"""`security-eval compare`: two runs side by side, and how much of what they found overlaps."""

from __future__ import annotations

from pathlib import Path

import pytest

from security_eval.budget import PriceTable, Usage
from security_eval.compare import compare, render
from security_eval.finding import Location, SecurityFinding, Verdict
from security_eval.ledger import Outcome
from security_eval.manifest import Target
from security_eval.matrix import Matrix, run_matrix
from security_eval.runners.base import RunResult

from .conftest import TOY


def reporting(*places: tuple[str, int]) -> object:
    class Reports:
        condition = "fake"

        def run(self, target: Target, route: str, workdir: Path, task: str = "",
                effort: str = "") -> RunResult:
            return RunResult(Outcome.OK, [
                SecurityFinding(f"at {p}:{n}", location=Location(p, n, n)) for p, n in places
            ], Usage(100, 10), seconds=5.0)
    return Reports()


def judging(*verdicts: Verdict) -> object:
    class Judges:
        condition = "fake"
        kind = "triage"

        def run(self, target: Target, route: str, workdir: Path, task: str = "",
                effort: str = "") -> RunResult:
            # Two findings share a rule id, as Bandit's do.
            found = [SecurityFinding("hardcoded", id="B105", location=Location("app/a.py", n, n),
                                     triage=v) for n, v in zip((10, 20, 30), verdicts,
                                                               strict=True)]
            return RunResult(Outcome.OK, found, Usage(100, 10))
    return Judges()


def run(tmp_path: Path, prices: PriceTable, name: str, detect: object, triage: object) -> Path:
    m = Matrix(name=name, targets=[TOY], conditions=["baseline", "triage"], models=["fake:m"],
               tokens_per_run={"baseline": (1, 1), "triage": (1, 1)})
    out = tmp_path / name
    run_matrix(m, {"baseline": detect, "triage": triage}, out, prices,  # type: ignore[dict-item]
               progress=lambda _: None)
    return out


def test_overlap_counts_places_both_runs_found(tmp_path: Path, prices: PriceTable) -> None:
    a = run(tmp_path, prices, "a",
            reporting(("app/db.py", 10), ("app/db.py", 12), ("app/x.py", 5), ("app/y.py", 1)),
            judging(Verdict.TRUE_POSITIVE, Verdict.FALSE_POSITIVE, Verdict.FALSE_POSITIVE))
    b = run(tmp_path, prices, "b",
            reporting(("app/db.py", 11), ("app/z.py", 7)),
            judging(Verdict.TRUE_POSITIVE, Verdict.TRUE_POSITIVE, Verdict.FALSE_POSITIVE))
    rows = {r["condition"]: r for r in compare(a, b)}

    places = rows["baseline"]["places"]
    assert (places["a"], places["b"], places["both"]) == (3, 2, 1), "db.py:10-12 is one place"
    assert places["overlap"] == pytest.approx(1 / 4)
    assert rows["baseline"]["a"]["findings"] == 4

    triage = rows["triage"]["triage"]
    assert (triage["judged_in_both"], triage["same_verdict"]) == (3, 2), "B105 twice, by line"
    assert triage["agreement"] == pytest.approx(2 / 3, abs=1e-3)

    text = render(list(rows.values()), "a", "b")
    assert "| 3 / 2 | 1 | 25% |" in text and "2 of 3" in text
