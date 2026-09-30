"""Deterministic scoring of findings against a target's answer key.

No model judges anything here. A finding matches a known vulnerability when it
names the same file and its line range overlaps the known one, allowing
``tolerance`` lines of slack either side. That is the *loose* match; the
*strict* match also requires the same CWE. Both are reported, because "found
the right place, called it the wrong thing" is a different result from a miss,
and the difference between them is itself worth measuring.

Matching is one-to-one and greedy by confidence: the most confident finding
claims a vulnerability first, and a second finding on the same vulnerability
is a duplicate, not a second true positive. Duplicates are counted separately
rather than as false positives -- a model that reports the same bug twice is
noisy, not wrong.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .finding import Location, SecurityFinding, Verdict
from .manifest import KnownIssue, Target

DEFAULT_TOLERANCE = 3


@dataclass
class Match:
    finding_index: int
    issue_id: str
    cwe_correct: bool


@dataclass
class Score:
    """One run's findings, scored against one target."""

    target: str
    findings: int
    vulnerabilities: int
    matches: list[Match] = field(default_factory=list)
    duplicates: int = 0
    decoy_hits: int = 0
    false_positives: int = 0      # located, but on no known issue (decoys included)
    unanchored: int = 0           # no usable location: cannot be a true positive
    missed: list[str] = field(default_factory=list)

    @property
    def tp_loose(self) -> int:
        return len(self.matches)

    @property
    def tp_strict(self) -> int:
        return sum(1 for m in self.matches if m.cwe_correct)

    def precision(self, strict: bool = False) -> float:
        tp = self.tp_strict if strict else self.tp_loose
        # A loose match with the wrong CWE is not a false positive under the
        # strict reading either -- it is a true positive that fails the bar --
        # so the denominator is the same in both readings.
        denominator = self.tp_loose + self.false_positives + self.unanchored
        return tp / denominator if denominator else 0.0

    def recall(self, strict: bool = False) -> float:
        tp = self.tp_strict if strict else self.tp_loose
        return tp / self.vulnerabilities if self.vulnerabilities else 0.0

    def f1(self, strict: bool = False) -> float:
        p, r = self.precision(strict), self.recall(strict)
        return 2 * p * r / (p + r) if p + r else 0.0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for strict in (False, True):
            key = "strict" if strict else "loose"
            data[key] = {
                "tp": self.tp_strict if strict else self.tp_loose,
                "precision": round(self.precision(strict), 4),
                "recall": round(self.recall(strict), 4),
                "f1": round(self.f1(strict), 4),
            }
        return data


def overlaps(a: Location, b: Location, tolerance: int = DEFAULT_TOLERANCE) -> bool:
    if a.normalised_path.lower() != b.normalised_path.lower():
        return False
    return a.start_line <= b.end_line + tolerance and b.start_line <= a.end_line + tolerance


def score(
    findings: list[SecurityFinding], target: Target, tolerance: int = DEFAULT_TOLERANCE
) -> Score:
    result = Score(target=target.id, findings=len(findings),
                   vulnerabilities=len(target.vulnerabilities))
    claimed: set[str] = set()

    order = sorted(range(len(findings)), key=lambda i: -findings[i].confidence)
    for index in order:
        finding = findings[index]
        if finding.location is None:
            result.unanchored += 1
            continue

        # Exact beats fuzzy: a finding squarely on a decoy is a decoy hit, even
        # when the decoy sits within `tolerance` lines of a real vulnerability --
        # which, in a benchmark built from look-alike pairs, it usually does.
        hit = _first_overlap(finding.location, target.vulnerabilities, 0)
        if hit is None and _first_overlap(finding.location, target.decoys, 0) is None:
            hit = _first_overlap(finding.location, target.vulnerabilities, tolerance)
        if hit is not None:
            if hit.id in claimed:
                result.duplicates += 1
            else:
                claimed.add(hit.id)
                result.matches.append(
                    Match(index, hit.id,
                          cwe_correct=finding.cwe is not None and finding.cwe == hit.cwe)
                )
            continue

        result.false_positives += 1
        if _first_overlap(finding.location, target.decoys, tolerance) is not None:
            result.decoy_hits += 1

    result.missed = [v.id for v in target.vulnerabilities if v.id not in claimed]
    return result


def _first_overlap(
    location: Location, issues: list[KnownIssue], tolerance: int
) -> KnownIssue | None:
    for issue in issues:
        if overlaps(location, issue.location, tolerance):
            return issue
    return None


# -- RQ3: triage ---------------------------------------------------------------


@dataclass
class TriageScore:
    total: int
    correct: int
    needs_info: int
    confusion: dict[str, dict[str, int]]   # label -> predicted -> count

    @property
    def accuracy(self) -> float:
        return self.correct / self.total if self.total else 0.0


def score_triage(predicted: list[Verdict | None], labels: list[bool]) -> TriageScore:
    """Verdicts against ground-truth labels (True = the finding is real).

    ``needs_info`` and a missing verdict are not counted as correct: a triage
    step that declines to decide has not done the job, and counting it as
    right would reward indecision.
    """
    if len(predicted) != len(labels):
        raise ValueError("one verdict per label")
    confusion: dict[str, dict[str, int]] = {"real": {}, "not_real": {}}
    correct = needs_info = 0
    for verdict, real in zip(predicted, labels, strict=True):
        label = "real" if real else "not_real"
        key = verdict.value if verdict else "none"
        confusion[label][key] = confusion[label].get(key, 0) + 1
        if verdict in (Verdict.NEEDS_INFO, None):
            needs_info += 1
        elif (verdict is Verdict.TRUE_POSITIVE) == real:
            correct += 1
    return TriageScore(len(labels), correct, needs_info, confusion)
