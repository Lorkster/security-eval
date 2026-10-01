"""The security finding every runner produces and the scorer consumes.

One shape for all sources -- a single-model baseline, a supervised harness run,
a scanner's SARIF -- so the scorer never needs to know where a finding came
from. ``source`` records it for the analysis instead.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

CWE_PATTERN = re.compile(r"\bCWE[-_ ]?(\d{1,4})\b", re.IGNORECASE)

# `path/to/file.py:12` or `path/to/file.py:12-18`, optionally backticked. The
# extension is required, so prose like "step 3:4" is not mistaken for a place.
LOCATION_PATTERN = re.compile(
    r"`?(?P<path>(?:[A-Za-z]:)?[\w./\\-]+\.[A-Za-z0-9]{1,8}):(?P<start>\d+)(?:[-:](?P<end>\d+))?`?"
)

SEVERITIES = ("info", "low", "medium", "high", "critical")


class Verdict(StrEnum):
    """A triage decision about one finding."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_INFO = "needs_info"


@dataclass(frozen=True)
class Location:
    path: str
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError(f"bad line range {self.start_line}-{self.end_line}")

    @property
    def normalised_path(self) -> str:
        return normalise_path(self.path)


@dataclass
class SecurityFinding:
    title: str
    cwe: str | None = None                  # "CWE-89"
    location: Location | None = None
    severity: str = "medium"
    confidence: float = 0.5
    detail: str = ""
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""
    triage: Verdict | None = None
    source: str = ""                        # "baseline:claude-sonnet-5-5", "harness:...", "semgrep"
    id: str = ""
    # How the location was obtained: "stated" -- the model filled in the
    # location field it was asked for; "recovered" -- it did not, and a
    # `path:line` was found in its evidence instead; "" -- no location. Both
    # conditions apply the same rule, and the scorer can be told to accept only
    # stated locations, so the leniency is visible rather than hidden.
    location_source: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["triage"] = self.triage.value if self.triage else None
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecurityFinding:
        loc = data.get("location")
        triage = data.get("triage")
        return cls(
            title=str(data.get("title", "")),
            cwe=normalise_cwe(data.get("cwe")),
            location=Location(**loc) if loc else None,
            severity=normalise_severity(data.get("severity")),
            confidence=float(data.get("confidence", 0.5)),
            detail=str(data.get("detail", "")),
            evidence=[str(e) for e in data.get("evidence") or []],
            recommendation=str(data.get("recommendation", "")),
            triage=Verdict(triage) if triage else None,
            source=str(data.get("source", "")),
            id=str(data.get("id", "")),
            location_source=str(data.get("location_source", "")),
        )


def normalise_path(path: str) -> str:
    """Compare paths the way people write them: forward slashes, no ``./``."""
    out = path.strip().replace("\\", "/")
    while out.startswith("./"):
        out = out[2:]
    return out.lstrip("/")


def normalise_cwe(raw: object) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, int):
        return f"CWE-{raw}"
    match = CWE_PATTERN.search(str(raw))
    if match:
        return f"CWE-{int(match.group(1))}"
    text = str(raw).strip()
    return f"CWE-{int(text)}" if text.isdigit() else None


def normalise_severity(raw: object) -> str:
    text = str(raw or "medium").strip().lower()
    return text if text in SEVERITIES else "medium"


def find_cwe(*texts: str) -> str | None:
    """The first CWE id mentioned anywhere in ``texts``."""
    for text in texts:
        match = CWE_PATTERN.search(text or "")
        if match:
            return f"CWE-{int(match.group(1))}"
    return None


def locate(stated: str, *fallback: str) -> tuple[Location | None, str]:
    """A finding's location and how it was obtained -- the one rule both conditions use.

    ``stated`` is the location field the model was asked to fill in; ``fallback``
    is its evidence and detail, searched only when the field gave nothing.
    """
    location = find_location(stated)
    if location is not None:
        return location, "stated"
    location = find_location(*fallback)
    return (location, "recovered") if location is not None else (None, "")


def find_location(*texts: str) -> Location | None:
    """The first ``file:line`` or ``file:start-end`` mentioned in ``texts``."""
    for text in texts:
        match = LOCATION_PATTERN.search(text or "")
        if not match:
            continue
        start = int(match.group("start"))
        end = int(match.group("end") or start)
        if start < 1 or end < start:
            continue
        return Location(normalise_path(match.group("path")), start, end)
    return None
