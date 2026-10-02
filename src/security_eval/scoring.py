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

import json
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
    findings: list[SecurityFinding], target: Target, tolerance: int = DEFAULT_TOLERANCE,
    *, stated_only: bool = False,
) -> Score:
    """Score ``findings`` against ``target``'s answer key.

    ``stated_only`` treats a location recovered from evidence -- rather than
    stated in the field the model was asked to fill -- as no location at all.
    Reporting both readings shows how much the recovery rule is doing.
    """
    result = Score(target=target.id, findings=len(findings),
                   vulnerabilities=len(target.vulnerabilities))
    claimed: set[str] = set()

    order = sorted(range(len(findings)), key=lambda i: -findings[i].confidence)
    for index in order:
        finding = findings[index]
        if finding.location is None or (stated_only
                                        and finding.location_source == "recovered"):
            result.unanchored += 1
            continue

        hit = matched_issue(finding.location, target, tolerance)
        if hit is not None:
            if hit.id in claimed:
                result.duplicates += 1
            else:
                claimed.add(hit.id)
                result.matches.append(
                    Match(index, hit.id,
                          cwe_correct=finding.cwe is not None and finding.cwe in hit.cwes)
                )
            continue

        result.false_positives += 1
        if _first_overlap(finding.location, target.decoys, tolerance) is not None:
            result.decoy_hits += 1

    result.missed = [v.id for v in target.vulnerabilities if v.id not in claimed]
    return result


def matched_issue(location: Location, target: Target,
                  tolerance: int = DEFAULT_TOLERANCE) -> KnownIssue | None:
    """The known vulnerability ``location`` points at, or ``None``.

    Exact beats fuzzy: a location squarely on a decoy is a decoy hit, even when
    the decoy sits within ``tolerance`` lines of a real vulnerability -- which,
    in a benchmark built from look-alike pairs, it usually does.
    """
    hit = _first_overlap(location, target.vulnerabilities, 0)
    if hit is None and _first_overlap(location, target.decoys, 0) is None:
        hit = _first_overlap(location, target.vulnerabilities, tolerance)
    return hit


def _first_overlap(
    location: Location, issues: list[KnownIssue], tolerance: int
) -> KnownIssue | None:
    for issue in issues:
        if any(overlaps(location, loc, tolerance) for loc in issue.locations):
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


# -- calibration: does the scorer score known answers as it should? ---------------

#: Beside a manifest: hand-written answers with a known score, in the shape of a
#: cell's findings.json. ``good.json`` must score full recall (strict) and full
#: precision; ``bad.json`` must score no true positive at all.
CALIBRATION_DIR = "calibration"


def calibrate(target: Target, tolerance: int = DEFAULT_TOLERANCE) -> list[str]:
    """What is wrong with scoring ``target``, found by scoring answers whose score is known.

    Results are only as trustworthy as the scorer that produced them, and a
    scorer can be wrong for one benchmark only: a decoy placed exactly on a
    vulnerability's lines, an ``also`` location that matches a different
    issue, a CWE list that excludes the CWE a correct answer gives. Each is a
    case where a perfect answer would not score perfectly, or a wrong one
    would score, and none shows in the numbers. So both are tried first:
    answers built from the key itself, then any hand-written ones beside it.
    """
    if target.open:
        return []
    out: list[str] = []

    def at(loc: Location, cwe: str | None, title: str = "calibration") -> SecurityFinding:
        return SecurityFinding(title=title, cwe=cwe, location=loc, confidence=0.9,
                               location_source="stated")

    perfect = [at(v.location, v.cwe) for v in target.vulnerabilities]
    s = score(perfect, target, tolerance)
    if s.tp_strict != len(target.vulnerabilities) or s.false_positives or s.duplicates:
        out.append(f"the answer key itself scores {s.tp_strict}/{len(target.vulnerabilities)} "
                   f"strict, {s.false_positives} false positive(s), {s.duplicates} duplicate(s); "
                   "a vulnerability's lines may overlap a decoy or another vulnerability")
    twice = score(perfect + perfect, target, tolerance)
    if twice.duplicates != len(target.vulnerabilities) or twice.false_positives:
        out.append(f"the key reported twice gives {twice.duplicates} duplicate(s) and "
                   f"{twice.false_positives} false positive(s), not "
                   f"{len(target.vulnerabilities)} and 0")

    for v in target.vulnerabilities:
        for loc in v.also:
            got = score([at(loc, v.cwe)], target, tolerance)
            if [m.issue_id for m in got.matches] != [v.id]:
                out.append(f"{v.id}: its also-location {loc.path}:{loc.start_line} does not "
                           f"match {v.id} alone")
        for cwe in v.also_cwes:
            got = score([at(v.location, cwe)], target, tolerance)
            if got.tp_strict != 1:
                out.append(f"{v.id}: the alternative {cwe} is not accepted as correct")
        wrong = score([at(v.location, "CWE-0")], target, tolerance)
        if wrong.tp_loose != 1 or wrong.tp_strict != 0:
            out.append(f"{v.id}: the right place with the wrong CWE scores "
                       f"{wrong.tp_loose} loose / {wrong.tp_strict} strict, not 1 / 0")

    for d in target.decoys:
        got = score([at(d.location, None)], target, tolerance)
        if got.tp_loose or got.decoy_hits != 1:
            out.append(f"{d.id}: a finding exactly on the decoy scores as "
                       + (f"a true positive ({got.matches[0].issue_id})" if got.tp_loose
                          else "something other than a decoy hit"))

    nowhere = [at(Location("no/such/calibration_file.py", 1, 1), None),
               SecurityFinding(title="no place named", confidence=0.9)]
    got = score(nowhere, target, tolerance)
    if got.tp_loose or got.false_positives != 1 or got.unanchored != 1:
        out.append("a finding in a file that does not exist, or with no location, scored "
                   "other than one false positive and one unanchored")

    out.extend(_calibration_files(target, tolerance))
    return out


def _calibration_files(target: Target, tolerance: int) -> list[str]:
    if target.manifest_path is None:
        return []
    folder = target.manifest_path.parent / CALIBRATION_DIR
    out: list[str] = []
    for name in ("good", "bad"):
        file = folder / f"{name}.json"
        if not file.is_file():
            continue
        try:
            findings = [SecurityFinding.from_dict(f)
                        for f in json.loads(file.read_text(encoding="utf-8"))]
        except (OSError, ValueError, TypeError, KeyError) as exc:
            out.append(f"{CALIBRATION_DIR}/{name}.json: unreadable ({exc})")
            continue
        s = score(findings, target, tolerance)
        if name == "good" and (s.recall(strict=True) != 1.0 or s.precision() != 1.0):
            out.append(f"{CALIBRATION_DIR}/good.json scores strict recall "
                       f"{s.recall(strict=True):.2f} and precision {s.precision():.2f}, "
                       f"not 1.00 and 1.00 (missed: {', '.join(s.missed) or 'none'})")
        if name == "bad" and s.tp_loose:
            out.append(f"{CALIBRATION_DIR}/bad.json scores {s.tp_loose} true positive(s) "
                       f"({', '.join(m.issue_id for m in s.matches)}), not 0")
    return out
