"""The baseline condition: one model, one prompt, the whole target, one answer.

It calls the model through the harness's own provider layer, not through a
separate SDK client. That is deliberate. The research question is what the
*supervision* adds, so the harness should be the only thing that differs
between conditions -- not the HTTP client, the request defaults or the retry
policy. The price is that the baseline inherits the harness's provider
limitations too, including the one prerequisite P2 exists to fix.

The target is sent in full, with line numbers, or not at all. A target larger
than ``max_chars`` is an error for this condition rather than being truncated:
a silently truncated baseline would be scored as missing whatever was cut, and
look worse than it is.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..batch import BatchItem, BatchOutcome, Reply, custom_id, harness_body, read_outcome
from ..budget import Usage
from ..finding import SecurityFinding, locate, normalise_cwe, normalise_severity
from ..ledger import Outcome
from ..manifest import Target
from .base import TASK, RunResult, effort_params

# Extensions read into the prompt. Anything else is skipped and named in the
# result's detail, so a target whose vulnerable file is `.tpl` is noticed.
SOURCE_SUFFIXES = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".kt", ".go", ".rb", ".php", ".cs",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".rs", ".swift", ".scala", ".sql", ".sh",
    ".html", ".xml", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf",
}

FINDINGS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "cwe": {"type": "string"},
                    "location": {"type": "string",
                                 "description": "path/to/file.ext:start-end"},
                    "severity": {"type": "string",
                                 "enum": ["info", "low", "medium", "high", "critical"]},
                    "confidence": {"type": "number"},
                    "evidence": {"type": "string"},
                    "recommendation": {"type": "string"},
                },
                "required": ["title", "cwe", "location", "severity", "confidence"],
            },
        }
    },
    "required": ["findings"],
}

SYSTEM = (
    "You are a security code reviewer working on a benchmark repository the user owns. "
    "Answer with JSON only."
)


class BaselineRunner:
    condition = "baseline"

    def __init__(self, max_chars: int = 400_000, max_tokens: int = 16_000) -> None:
        self.max_chars = max_chars
        self.max_tokens = max_tokens

    def run(self, target: Target, route: str, workdir: Path, task: str = TASK,
            effort: str = "") -> RunResult:
        code, skipped = pack(target.root)
        if len(code) > self.max_chars:
            return RunResult(
                Outcome.ERROR,
                detail=f"target is {len(code)} chars, over the baseline's {self.max_chars}; "
                       "not truncated",
            )
        prompt = f"{task}\n\nThe repository:\n\n{code}"
        params = effort_params(route, effort)
        started = time.monotonic()
        try:
            answer = asyncio.run(self._complete(route, prompt, workdir, params or {}))
        except Exception as exc:  # noqa: BLE001 - every provider failure is one outcome
            return RunResult(Outcome.ERROR, detail=f"{type(exc).__name__}: {exc}"[:500])
        seconds = time.monotonic() - started

        extra: dict[str, Any] = {"finish_reason": answer.finish, "skipped": skipped[:50],
                                 "effort": effort if params else ""}
        detail = f"skipped {len(skipped)} non-source file(s)" if skipped else ""
        if answer.refusal is not None:
            extra["refusal_categories"] = [answer.refusal] if answer.refusal else []
            return RunResult(Outcome.REFUSED, usage=answer.usage, seconds=seconds,
                             detail=detail, extra=extra)
        findings = parse_findings(answer.text, route)
        if findings is None:
            truncated = answer.finish in ("max_tokens", "length")
            return RunResult(
                Outcome.INVALID_OUTPUT, usage=answer.usage, seconds=seconds, extra=extra,
                detail=("answer truncated at the token limit; " if truncated else "")
                       + f"finish={answer.finish}; {answer.text[:300]!r}",
            )
        return RunResult(Outcome.OK, findings, answer.usage, seconds, detail=detail, extra=extra)

    async def _complete(self, route: str, prompt: str, workdir: Path,
                        params: dict[str, Any]) -> Answer:
        return await harness_complete(route=route, system=SYSTEM, user=prompt,
                                      json_schema=FINDINGS_SCHEMA, max_tokens=self.max_tokens,
                                      params=params, workdir=workdir)

    # -- batch ---------------------------------------------------------------------------

    def batch_items(self, target: Target, route: str, task: str, effort: str,
                    cell_id: str, workdir: Path) -> list[BatchItem] | RunResult:
        """The one request this cell makes, built as the harness would send it.

        A ``RunResult`` instead when the cell cannot be batched at all -- a target
        too large to send whole is an error here exactly as it is live.
        """
        code, _skipped = pack(target.root)
        if len(code) > self.max_chars:
            return RunResult(Outcome.ERROR, detail=f"target is {len(code)} chars, over the "
                                                   f"baseline's {self.max_chars}; not truncated")
        body = harness_body(
            route=route, system=SYSTEM, user=f"{task}\n\nThe repository:\n\n{code}",
            json_schema=FINDINGS_SCHEMA, max_tokens=self.max_tokens,
            extra=effort_params(route, effort) or {}, workdir=workdir,
        )
        return [BatchItem(custom_id(cell_id, 0), body)]

    def from_batch(self, target: Target, route: str, outcomes: list[BatchOutcome],
                   effort: str = "") -> RunResult:
        reply = read_outcome(outcomes[0]) if outcomes else Reply(error="no result returned")
        usage = Usage(reply.input_tokens, reply.output_tokens,
                      reply.cache_read_tokens, reply.cache_write_tokens)
        extra: dict[str, Any] = {"finish_reason": reply.finish, "batched": True,
                                 "effort": effort if effort_params(route, effort) else ""}
        if reply.error:
            # Errored, canceled or expired: the request did not run, so it is
            # retried on the next run, like any other error.
            return RunResult(Outcome.ERROR, usage=usage, detail=f"batch: {reply.error}",
                             extra=extra)
        if reply.refusal is not None:
            extra["refusal_categories"] = [reply.refusal] if reply.refusal else []
            return RunResult(Outcome.REFUSED, usage=usage, extra=extra)
        findings = parse_findings(reply.text, route)
        if findings is None:
            truncated = reply.finish in ("max_tokens", "length")
            return RunResult(Outcome.INVALID_OUTPUT, usage=usage, extra=extra,
                             detail=("answer truncated at the token limit; " if truncated else "")
                                    + f"finish={reply.finish}; {reply.text[:300]!r}")
        return RunResult(Outcome.OK, findings, usage, extra=extra)


async def harness_complete(*, route: str, system: str, user: str,
                           json_schema: dict[str, Any] | None, max_tokens: int,
                           params: dict[str, Any], workdir: Path) -> Answer:
    """One live call through the harness's own provider layer -- the path every
    unbatched request in this study takes, whichever condition makes it."""
    from supervisor_harness.config import load_config
    from supervisor_harness.providers.base import (
        ChatMessage,
        CompletionRequest,
        ProviderRefusal,
    )
    from supervisor_harness.providers.router import ModelRouter

    config = load_config(workdir)
    config.routing = {"default": route}
    router = ModelRouter(config)
    try:
        response = await router.complete(
            "analysis",
            CompletionRequest(system=system, messages=[ChatMessage("user", user)],
                              json_schema=json_schema, max_tokens=max_tokens, timeout=900.0,
                              extra=params),
            retries=0,
        )
    except ProviderRefusal as exc:
        # A refusal is a result. The harness raises it rather than returning an
        # empty answer, and never retries it; neither does this.
        return Answer(finish="refusal", refusal=exc.category)
    finally:
        await router.aclose()
    u = response.usage
    return Answer(
        text=response.text, finish=response.finish_reason,
        usage=Usage(u.input_tokens, u.output_tokens,
                    getattr(u, "cache_read_tokens", 0), getattr(u, "cache_write_tokens", 0)),
    )


@dataclass
class Answer:
    text: str = ""
    finish: str = ""
    usage: Usage = field(default_factory=Usage)
    refusal: str | None = None     # the category, "" if none given; None if not refused


def pack(root: Path) -> tuple[str, list[str]]:
    """Every source file under ``root``, with a path header and line numbers."""
    parts: list[str] = []
    skipped: list[str] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        if any(part.startswith(".") for part in path.relative_to(root).parts):
            continue
        if path.suffix.lower() not in SOURCE_SUFFIXES:
            skipped.append(rel)
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        numbered = "\n".join(f"{n:>5}  {line}" for n, line in enumerate(lines, 1))
        parts.append(f"=== {rel} ===\n{numbered}")
    return "\n\n".join(parts), skipped


_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def parse_findings(text: str, route: str) -> list[SecurityFinding] | None:
    """The model's findings, or ``None`` if the answer is not the JSON asked for."""
    body = _FENCE.sub("", text.strip())
    start, end = body.find("{"), body.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        data = json.loads(body[start:end + 1])
        items = data["findings"]
    except (json.JSONDecodeError, KeyError, TypeError):
        return None
    if not isinstance(items, list):
        return None
    out = []
    for item in items:
        if not isinstance(item, dict):
            continue
        evidence = [str(item["evidence"])] if item.get("evidence") else []
        location, source = locate(str(item.get("location", "")), *evidence)
        out.append(SecurityFinding(
            title=str(item.get("title", "")),
            cwe=normalise_cwe(item.get("cwe")),
            location=location,
            location_source=source,
            severity=normalise_severity(item.get("severity")),
            confidence=_confidence(item.get("confidence")),
            evidence=evidence,
            recommendation=str(item.get("recommendation", "")),
            source=f"baseline:{route}",
        ))
    return out


def _confidence(raw: object) -> float:
    try:
        return min(1.0, max(0.0, float(raw)))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.5
