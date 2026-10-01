"""RQ3: a model triages what a scanner reported.

Each scanner finding is judged on its own -- real and reachable, not a real
issue in this code, or undecidable from the code -- with the whole repository in
view, as a human triager would have it. One request per finding, so each
judgement is independent of the order the scanner listed them in, and so the
cell batches cleanly.

The repository and instructions go in the system text, the finding in the user
message. Live, through the harness's provider layer, that is all. Batched, the
system text is also marked as a cache breakpoint, so a target with forty
findings pays for its source code roughly once rather than forty times. The
text the model reads is identical either way.

Ground truth comes from the answer key (`scanners.label`). What the company will
care about most is in the score: how much of the scanner's noise the model
dismisses, and how many real issues it keeps.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

from ..batch import BatchItem, BatchOutcome, custom_id, harness_body, read_outcome
from ..budget import Usage
from ..finding import SecurityFinding, Verdict, normalise_severity
from ..ledger import Outcome
from ..manifest import Target
from ..scanners import ScanError, scanner_findings
from .base import RunResult, effort_params
from .baseline import harness_complete, pack

TRIAGE_TASK = (
    "A static analysis tool reported the finding below in this repository. Decide whether "
    "it is a real vulnerability that untrusted input can reach (true_positive), not a real "
    "issue in this code (false_positive), or impossible to decide from the code alone "
    "(needs_info). Give your verdict, the severity if it is real, your confidence from 0 to "
    "1, your reasoning tied to specific lines, and a fix if it is real. Do not write exploits."
)

TRIAGE_SYSTEM = (
    "You are a security engineer triaging static analysis results for a repository the "
    "user is authorised to review. Answer with JSON only."
)

TRIAGE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": [v.value for v in Verdict]},
        "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
        "confidence": {"type": "number"},
        "reasoning": {"type": "string"},
        "fix": {"type": "string"},
    },
    "required": ["verdict", "confidence", "reasoning"],
}


class TriageRunner:
    condition = "triage"
    kind = "triage"

    def __init__(self, tool: str = "bandit", max_chars: int = 400_000,
                 max_tokens: int = 4_000) -> None:
        self.tool = tool
        self.max_chars = max_chars
        self.max_tokens = max_tokens

    # -- live --------------------------------------------------------------------

    def run(self, target: Target, route: str, workdir: Path, task: str = TRIAGE_TASK,
            effort: str = "") -> RunResult:
        prepared = self._prepare(target)
        if isinstance(prepared, RunResult):
            return prepared
        findings, system = prepared
        params = effort_params(route, effort) or {}
        started = time.monotonic()
        replies = []
        for finding in findings:
            try:
                answer = asyncio.run(harness_complete(
                    route=route, system=system, user=describe(task, finding, self.tool),
                    json_schema=TRIAGE_SCHEMA, max_tokens=self.max_tokens, params=params,
                    workdir=workdir,
                ))
            except Exception as exc:  # noqa: BLE001 - one provider failure is the cell's outcome
                return RunResult(Outcome.ERROR, detail=f"{type(exc).__name__}: {exc}"[:500])
            replies.append((answer.text, answer.finish, answer.refusal, answer.usage))
        return self._result(findings, replies, time.monotonic() - started, route, effort)

    # -- batch -------------------------------------------------------------------

    def batch_items(self, target: Target, route: str, task: str, effort: str,
                    cell_id: str, workdir: Path) -> list[BatchItem] | RunResult:
        prepared = self._prepare(target)
        if isinstance(prepared, RunResult):
            return prepared
        findings, system = prepared
        extra = effort_params(route, effort) or {}
        return [
            BatchItem(custom_id(cell_id, i), harness_body(
                route=route, system=system, user=describe(task, f, self.tool),
                json_schema=TRIAGE_SCHEMA, max_tokens=self.max_tokens, extra=extra,
                workdir=workdir, cache_system=True,
            ))
            for i, f in enumerate(findings)
        ]

    def from_batch(self, target: Target, route: str, outcomes: list[BatchOutcome],
                   effort: str = "") -> RunResult:
        prepared = self._prepare(target)
        if isinstance(prepared, RunResult):
            return prepared
        findings, _ = prepared
        replies = []
        errors = []
        for outcome in outcomes:
            reply = read_outcome(outcome)
            if reply.error:
                errors.append(reply.error)
            replies.append((reply.text, reply.finish, reply.refusal,
                            Usage(reply.input_tokens, reply.output_tokens,
                                  reply.cache_read_tokens, reply.cache_write_tokens)))
        if errors:
            usage = sum((r[3] for r in replies), Usage())
            return RunResult(Outcome.ERROR, usage=usage,
                             detail=f"batch: {len(errors)} request(s) did not run: {errors[0]}")
        result = self._result(findings, replies, 0.0, route, effort)
        result.extra["batched"] = True
        return result

    # -- shared ------------------------------------------------------------------

    def _prepare(self, target: Target) -> tuple[list[SecurityFinding], str] | RunResult:
        try:
            findings = scanner_findings(target, self.tool)
        except ScanError as exc:
            return RunResult(Outcome.ERROR, detail=str(exc))
        code, _ = pack(target.root)
        if len(code) > self.max_chars:
            return RunResult(Outcome.ERROR, detail=f"target is {len(code)} chars, over "
                                                   f"{self.max_chars}; not truncated")
        return findings, f"{TRIAGE_SYSTEM}\n\nThe repository:\n\n{code}"

    def _result(self, findings: list[SecurityFinding],
                replies: list[tuple[str, str, str | None, Usage]], seconds: float,
                route: str, effort: str) -> RunResult:
        usage = Usage()
        refused = invalid = 0
        categories: set[str] = set()
        judged: list[SecurityFinding] = []
        for finding, (text, _finish, refusal, spent) in zip(findings, replies, strict=True):
            usage = usage + spent
            judged_finding = SecurityFinding.from_dict(finding.to_dict())
            if refusal is not None:
                refused += 1
                if refusal:
                    categories.add(refusal)
            else:
                verdict = parse_verdict(text)
                if verdict is None:
                    invalid += 1
                else:
                    judged_finding.triage = verdict["verdict"]
                    judged_finding.confidence = verdict["confidence"]
                    judged_finding.triage_reason = verdict["reasoning"]
                    judged_finding.recommendation = verdict["fix"]
                    if verdict["severity"]:
                        judged_finding.severity = verdict["severity"]
            judged.append(judged_finding)

        n = len(findings)
        if n and refused == n:
            outcome = Outcome.REFUSED
        elif n and invalid == n:
            outcome = Outcome.INVALID_OUTPUT
        else:
            outcome = Outcome.OK
        return RunResult(outcome, judged, usage, seconds, extra={
            "tool": self.tool, "scanner_findings": n, "refused_items": refused,
            "invalid_items": invalid, "refusal_categories": sorted(categories),
            "effort": effort if effort_params(route, effort) else "",
        })


def describe(task: str, finding: SecurityFinding, tool: str) -> str:
    where = (f"{finding.location.normalised_path}:{finding.location.start_line}-"
             f"{finding.location.end_line}" if finding.location else "(no location given)")
    return (f"{task}\n\nThe finding:\n- tool: {tool}\n- rule: {finding.id}\n"
            f"- location: {where}\n- reported CWE: {finding.cwe or 'none'}\n"
            f"- message: {finding.detail or finding.title}")


def parse_verdict(text: str) -> dict[str, Any] | None:
    """The model's verdict, or ``None`` if the answer is not the JSON asked for."""
    body = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```")
    start, end = body.find("{"), body.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        data = json.loads(body[start:end + 1])
        verdict = Verdict(str(data["verdict"]).strip().lower())
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None
    try:
        confidence = min(1.0, max(0.0, float(data.get("confidence", 0.5))))
    except (TypeError, ValueError):
        confidence = 0.5
    return {
        "verdict": verdict, "confidence": confidence,
        "reasoning": str(data.get("reasoning", "")), "fix": str(data.get("fix", "")),
        "severity": normalise_severity(data["severity"]) if data.get("severity") else "",
    }
