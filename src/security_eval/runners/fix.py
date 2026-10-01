"""RQ8: a model proposes a fix and a regression test for a confirmed flaw.

One request per known vulnerability, each independent of the others, so the
cell batches cleanly. The model is told where the flaw is and its CWE -- RQ8
asks whether fixes work, not whether flaws are found, so detection is kept out
of it -- and gets the repository, its existing tests, and two true facts about
how its test will be run. Nothing else: no description from the answer key, so
a hand-written benchmark and a time-split one are asked the same way.

The answer is edits rather than a diff. A diff has to reproduce line numbers and
context exactly, and a fix lost to a malformed hunk would be scored as a fix
that does not work. An edit names the exact text to replace, which a model
copies reliably, and an edit that does not apply is still recorded as such.

Nothing is run here. The proposals are saved with the cell, and `security-eval
verify` checks them in a sandbox later, for free and as often as needed.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import time
from pathlib import Path
from typing import Any

from ..batch import BatchItem, BatchOutcome, custom_id, harness_body, read_outcome
from ..budget import Usage
from ..fixes import Edit, Proposal, materialise
from ..ledger import Outcome
from ..manifest import KnownIssue, Target
from .base import RunResult, effort_params
from .baseline import harness_complete, pack

FIX_TASK = (
    "The vulnerability below has been confirmed in this repository. Fix it with the smallest "
    "change that removes the vulnerability without changing the code's intended behaviour, and "
    "write a regression test: a unit test that fails on the current code because of the "
    "vulnerability and passes once your fix is applied. The test should check the safe "
    "behaviour, for example that unsafe input is rejected or neutralised; it must not depend on "
    "any new function or parameter your fix introduces. Give the fix as edits: for each, the "
    "file path, the exact current text to replace, copied verbatim without line numbers and "
    "long enough to occur exactly once in the file, and its replacement. Do not edit existing "
    "tests. Do not write exploits."
)

FIX_SYSTEM = (
    "You are a security engineer fixing a confirmed vulnerability in a repository the user is "
    "authorised to change. Answer with JSON only."
)

FIX_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "edits": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "old": {"type": "string",
                            "description": "exact current text; empty to create a new file"},
                    "new": {"type": "string"},
                },
                "required": ["path", "old", "new"],
            },
        },
        "test": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"],
        },
        "explanation": {"type": "string"},
    },
    "required": ["edits", "test", "explanation"],
}


class FixRunner:
    condition = "fix"
    kind = "fix"

    def __init__(self, max_chars: int = 400_000, max_tokens: int = 8_000) -> None:
        self.max_chars = max_chars
        self.max_tokens = max_tokens

    # -- live --------------------------------------------------------------------

    def run(self, target: Target, route: str, workdir: Path, task: str = FIX_TASK,
            effort: str = "") -> RunResult:
        prepared = self._prepare(target)
        if isinstance(prepared, RunResult):
            return prepared
        system = prepared
        params = effort_params(route, effort) or {}
        started = time.monotonic()
        replies = []
        for vuln in target.vulnerabilities:
            try:
                answer = asyncio.run(harness_complete(
                    route=route, system=system, user=describe(task, vuln),
                    json_schema=FIX_SCHEMA, max_tokens=self.max_tokens, params=params,
                    workdir=workdir,
                ))
            except Exception as exc:  # noqa: BLE001 - one provider failure is the cell's outcome
                return RunResult(Outcome.ERROR, detail=f"{type(exc).__name__}: {exc}"[:500])
            replies.append((answer.text, answer.finish, answer.refusal, answer.usage))
        return self._result(target, replies, time.monotonic() - started, route, effort)

    # -- batch -------------------------------------------------------------------

    def batch_items(self, target: Target, route: str, task: str, effort: str,
                    cell_id: str, workdir: Path) -> list[BatchItem] | RunResult:
        prepared = self._prepare(target)
        if isinstance(prepared, RunResult):
            return prepared
        extra = effort_params(route, effort) or {}
        return [
            BatchItem(custom_id(cell_id, i), harness_body(
                route=route, system=prepared, user=describe(task, vuln),
                json_schema=FIX_SCHEMA, max_tokens=self.max_tokens, extra=extra,
                workdir=workdir, cache_system=True,
            ))
            for i, vuln in enumerate(target.vulnerabilities)
        ]

    def from_batch(self, target: Target, route: str, outcomes: list[BatchOutcome],
                   effort: str = "") -> RunResult:
        replies = []
        errors = []
        for outcome in outcomes:
            reply = read_outcome(outcome)
            if reply.error:
                errors.append(reply.error)
            replies.append((reply.text, reply.finish, reply.refusal,
                            Usage(reply.input_tokens, reply.output_tokens,
                                  reply.cache_read_tokens, reply.cache_write_tokens)))
        usage = sum((r[3] for r in replies), Usage())
        if errors or len(replies) != len(target.vulnerabilities):
            first = errors[0] if errors else f"{len(replies)} result(s) for " \
                                             f"{len(target.vulnerabilities)} request(s)"
            return RunResult(Outcome.ERROR, usage=usage,
                             detail=f"batch: {len(errors)} request(s) did not run: {first}")
        result = self._result(target, replies, 0.0, route, effort)
        result.extra["batched"] = True
        return result

    # -- shared ------------------------------------------------------------------

    def _prepare(self, target: Target) -> str | RunResult:
        if target.open or not target.vulnerabilities:
            return RunResult(Outcome.ERROR, detail=f"{target.id} has no known vulnerability to "
                                                   "fix (open targets have no answer key)")
        if target.verify is None or target.verify.problems():
            problems = target.verify.problems() if target.verify else ["no verify section"]
            return RunResult(Outcome.ERROR, detail=f"{target.id}: fixes cannot be verified: "
                                                   + "; ".join(problems))
        with tempfile.TemporaryDirectory(prefix="security-eval-fix-") as tmp:
            code, _ = pack(materialise(target, Path(tmp) / "tree"))
        if len(code) > self.max_chars:
            return RunResult(Outcome.ERROR, detail=f"target is {len(code)} chars, over "
                                                   f"{self.max_chars}; not truncated")
        return (f"{FIX_SYSTEM}\n\n{how_tests_run(target)}\n\n"
                f"The repository, with its existing tests:\n\n{code}")

    def _result(self, target: Target, replies: list[tuple[str, str, str | None, Usage]],
                seconds: float, route: str, effort: str) -> RunResult:
        usage = Usage()
        proposals: list[Proposal] = []
        categories: set[str] = set()
        for vuln, (text, finish, refusal, spent) in zip(target.vulnerabilities, replies,
                                                        strict=True):
            usage = usage + spent
            if refusal is not None:
                proposals.append(Proposal(vuln.id, refusal=refusal))
                if refusal:
                    categories.add(refusal)
                continue
            proposal = parse_proposal(text, vuln.id)
            if proposal is None:
                truncated = finish in ("max_tokens", "length")
                proposal = Proposal(vuln.id, invalid=("answer truncated at the token limit"
                                                      if truncated else
                                                      "no answer in the shape asked for"))
            proposals.append(proposal)

        n = len(proposals)
        refused = sum(p.refusal is not None for p in proposals)
        invalid = sum(bool(p.invalid) for p in proposals)
        if n and refused == n:
            outcome = Outcome.REFUSED
        elif n and invalid == n:
            outcome = Outcome.INVALID_OUTPUT
        else:
            outcome = Outcome.OK
        return RunResult(outcome, [], usage, seconds,
                         extra={"vulnerabilities": n, "refused_items": refused,
                                "invalid_items": invalid,
                                "refusal_categories": sorted(categories),
                                "effort": effort if effort_params(route, effort) else ""},
                         artifacts={"proposals": [p.to_dict() for p in proposals]})


def how_tests_run(target: Target) -> str:
    """Two true facts about the test's run; the junit plumbing is ours, not the model's."""
    assert target.verify is not None  # noqa: S101 - checked by the caller
    command = " ".join(t for t in target.verify.test_command.split() if "{junit}" not in t)
    command = command.replace("{test}", "<test file>")
    return (f"Tests are run from the repository root with `{command}`, "
            f"without network access. Put your test in a new file under "
            f"`{target.verify.test_dir}/`.")


def describe(task: str, vuln: KnownIssue) -> str:
    where = [f"{loc.normalised_path}:{loc.start_line}-{loc.end_line}" for loc in vuln.locations]
    also = f" (the flaw can also be seen at {', '.join(where[1:])})" if len(where) > 1 else ""
    return (f"{task}\n\nThe vulnerability:\n- location: {where[0]}{also}\n"
            f"- CWE: {vuln.cwe or 'unknown'}")


def parse_proposal(text: str, vulnerability: str) -> Proposal | None:
    """The model's proposal, or ``None`` if the answer is not the JSON asked for."""
    body = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```")
    start, end = body.find("{"), body.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        data = json.loads(body[start:end + 1])
        edits = data["edits"]
        test = data["test"]
    except (json.JSONDecodeError, KeyError, TypeError):
        return None
    if not isinstance(edits, list) or not isinstance(test, dict):
        return None
    return Proposal(
        vulnerability=vulnerability,
        edits=[Edit(str(e.get("path", "")), str(e.get("old", "")), str(e.get("new", "")))
               for e in edits if isinstance(e, dict)],
        test_path=str(test.get("path", "")),
        test_content=str(test.get("content", "")),
        explanation=str(data.get("explanation", "")),
    )
