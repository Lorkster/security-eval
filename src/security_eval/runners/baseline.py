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
from pathlib import Path
from typing import Any

from ..budget import Usage
from ..finding import SecurityFinding, find_location, normalise_cwe, normalise_severity
from ..ledger import Outcome
from ..manifest import Target
from .base import TASK, RunResult

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

    def run(self, target: Target, route: str, workdir: Path, task: str = TASK) -> RunResult:
        code, skipped = pack(target.root)
        if len(code) > self.max_chars:
            return RunResult(
                Outcome.ERROR,
                detail=f"target is {len(code)} chars, over the baseline's {self.max_chars}; "
                       "not truncated",
            )
        prompt = f"{task}\n\nThe repository:\n\n{code}"
        started = time.monotonic()
        try:
            text, finish, usage = asyncio.run(self._complete(route, prompt, workdir))
        except Exception as exc:  # noqa: BLE001 - every provider failure is one outcome
            return RunResult(Outcome.ERROR, detail=f"{type(exc).__name__}: {exc}"[:500])
        seconds = time.monotonic() - started

        detail = f"skipped {len(skipped)} non-source file(s)" if skipped else ""
        if finish == "refusal":
            return RunResult(Outcome.REFUSED, usage=usage, seconds=seconds, detail=detail)
        findings = parse_findings(text, route)
        if findings is None:
            return RunResult(Outcome.INVALID_OUTPUT, usage=usage, seconds=seconds,
                             detail=f"finish={finish}; {text[:300]!r}")
        return RunResult(Outcome.OK, findings, usage, seconds, detail=detail,
                         extra={"finish_reason": finish, "skipped": skipped[:50]})

    async def _complete(self, route: str, prompt: str, workdir: Path) -> tuple[str, str, Usage]:
        from supervisor_harness.config import load_config
        from supervisor_harness.providers.base import ChatMessage, CompletionRequest
        from supervisor_harness.providers.router import ModelRouter

        config = load_config(workdir)
        config.routing = {"default": route}
        router = ModelRouter(config)
        try:
            response = await router.complete(
                "analysis",
                CompletionRequest(
                    system=SYSTEM,
                    messages=[ChatMessage("user", prompt)],
                    json_schema=FINDINGS_SCHEMA,
                    max_tokens=self.max_tokens,
                    timeout=900.0,
                ),
                retries=0,
            )
        finally:
            await router.aclose()
        u = response.usage
        return response.text, response.finish_reason, Usage(u.input_tokens, u.output_tokens)


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
        out.append(SecurityFinding(
            title=str(item.get("title", "")),
            cwe=normalise_cwe(item.get("cwe")),
            location=find_location(str(item.get("location", ""))),
            severity=normalise_severity(item.get("severity")),
            confidence=_confidence(item.get("confidence")),
            evidence=[str(item["evidence"])] if item.get("evidence") else [],
            recommendation=str(item.get("recommendation", "")),
            source=f"baseline:{route}",
        ))
    return out


def _confidence(raw: object) -> float:
    try:
        return min(1.0, max(0.0, float(raw)))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.5
