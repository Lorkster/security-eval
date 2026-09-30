"""The scorer is the instrument. If it is wrong, every number in the write-up is."""

from __future__ import annotations

import pytest

from security_eval.finding import Location, SecurityFinding, Verdict
from security_eval.manifest import Target
from security_eval.scoring import overlaps, score, score_triage


def f(path: str, start: int, end: int | None = None, cwe: str | None = None,
      confidence: float = 0.9) -> SecurityFinding:
    return SecurityFinding("x", cwe=cwe, location=Location(path, start, end or start),
                           confidence=confidence)


def test_a_perfect_answer_scores_one_in_both_readings(toy: Target) -> None:
    findings = [f(v.location.path, v.location.start_line, v.location.end_line, v.cwe)
                for v in toy.vulnerabilities]
    s = score(findings, toy)
    assert (s.precision(), s.recall(), s.precision(True), s.recall(True)) == (1, 1, 1, 1)
    assert s.missed == []


def test_right_place_wrong_cwe_is_loose_but_not_strict(toy: Target) -> None:
    s = score([f("app/db.py", 11, cwe="CWE-79")], toy)
    assert s.tp_loose == 1
    assert s.tp_strict == 0


def test_nothing_found_is_zero_not_an_error(toy: Target) -> None:
    s = score([], toy)
    assert (s.precision(), s.recall(), s.f1()) == (0, 0, 0)
    assert len(s.missed) == len(toy.vulnerabilities)


def test_a_second_finding_on_the_same_bug_is_a_duplicate_not_a_true_positive(
    toy: Target,
) -> None:
    s = score([f("app/db.py", 11, cwe="CWE-89"), f("app/db.py", 12, cwe="CWE-89",
                                                   confidence=0.5)], toy)
    assert s.tp_loose == 1
    assert s.duplicates == 1
    assert s.false_positives == 0


def test_a_finding_on_a_decoy_is_a_false_positive_even_within_tolerance_of_a_bug(
    toy: Target,
) -> None:
    """V4 is config.py:9 and its decoy D4 is config.py:11 -- inside the tolerance.

    Fuzzy matching alone would credit a finding on the decoy as finding V4.
    Exact beats fuzzy.
    """
    s = score([f("app/config.py", 11, cwe="CWE-798")], toy)
    assert s.tp_loose == 0
    assert s.decoy_hits == 1
    assert s.false_positives == 1


def test_a_near_miss_within_tolerance_still_counts(toy: Target) -> None:
    s = score([f("app/session.py", 7, cwe="CWE-502")], toy)   # V5 is line 9
    assert s.tp_strict == 1


def test_an_unlocated_finding_cannot_be_a_true_positive(toy: Target) -> None:
    s = score([SecurityFinding("SQL injection somewhere", cwe="CWE-89")], toy)
    assert s.unanchored == 1
    assert s.tp_loose == 0
    assert s.precision() == 0


def test_the_most_confident_finding_claims_the_bug(toy: Target) -> None:
    low = f("app/db.py", 11, cwe="CWE-79", confidence=0.2)
    high = f("app/db.py", 12, cwe="CWE-89", confidence=0.9)
    s = score([low, high], toy)
    assert s.tp_strict == 1, "the confident, correct finding should have been matched"


@pytest.mark.parametrize(("a", "b", "expected"), [
    (("app/x.py", 10, 12), ("app/x.py", 15, 15), True),     # 3 lines apart
    (("app/x.py", 10, 12), ("app/x.py", 16, 16), False),
    (("./app\\x.py", 10, 10), ("app/x.py", 10, 10), True),  # path spelling
    (("app/x.py", 10, 10), ("app/y.py", 10, 10), False),
])
def test_overlap(a: tuple[str, int, int], b: tuple[str, int, int], expected: bool) -> None:
    assert overlaps(Location(*a), Location(*b)) is expected


def test_triage_does_not_reward_indecision() -> None:
    s = score_triage(
        [Verdict.TRUE_POSITIVE, Verdict.FALSE_POSITIVE, Verdict.NEEDS_INFO, None],
        [True, False, True, False],
    )
    assert s.correct == 2
    assert s.needs_info == 2
    assert s.accuracy == 0.5
