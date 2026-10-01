"""The budget guard, the ledger and resumption: the parts that protect the money."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from security_eval.budget import BudgetExceeded, BudgetGuard, PriceTable, Usage
from security_eval.cli import main
from security_eval.ledger import Ledger, Outcome
from security_eval.manifest import Target
from security_eval.matrix import Matrix, cells, estimate, run_matrix
from security_eval.runners.base import RunResult
from security_eval.runners.fake import FakeRunner

from .conftest import ROOT, TOY


class Paid:
    """A runner that pretends to spend, with a scripted outcome per call."""

    condition = "baseline"

    def __init__(self, outcomes: list[Outcome] | None = None,
                 usage: Usage | None = None) -> None:
        self.outcomes = list(outcomes or [])
        self.usage = usage or Usage(1_000_000, 0)
        self.calls = 0

    def run(self, target: Target, route: str, workdir: Path, task: str = "",
            effort: str = "") -> RunResult:
        self.calls += 1
        outcome = self.outcomes.pop(0) if self.outcomes else Outcome.OK
        return RunResult(outcome, usage=self.usage)


def matrix(**overrides: object) -> Matrix:
    base: dict[str, object] = dict(
        name="t", targets=[TOY], conditions=["baseline"],
        models=["anthropic:claude-sonnet-5-5"], repeats=3, budget_usd=100.0,
        tokens_per_run={"baseline": (1_000_000, 0), "harness": (1_000_000, 0)},
    )
    base.update(overrides)
    return Matrix(**base)  # type: ignore[arg-type]


def quiet(_: str) -> None:
    pass


def test_prices_come_from_the_table_and_an_unknown_model_is_an_error(prices: PriceTable) -> None:
    assert prices.cost("anthropic:claude-sonnet-5-5", Usage(1_000_000, 100_000)) == 3.0
    assert prices.cost("openrouter:anthropic/claude-sonnet-5-5", Usage(1_000_000, 0)) == 2.0
    assert prices.cost("ollama:qwen", Usage(10**9, 10**9)) == 0.0
    assert prices.cost("anthropic:claude-sonnet-5-5", Usage(1_000_000, 0), batch=True) == 1.0
    with pytest.raises(KeyError):
        prices.cost("anthropic:some-model-nobody-priced", Usage(1, 1))


def test_cache_reads_are_cheaper_than_input(prices: PriceTable) -> None:
    read = prices.cost("anthropic:claude-sonnet-5-5", Usage(cache_read_tokens=1_000_000))
    assert read == pytest.approx(0.2)


def test_the_guard_refuses_before_spending_not_after() -> None:
    guard = BudgetGuard(10.0, spent_usd=8.0)
    guard.check(2.0)
    with pytest.raises(BudgetExceeded):
        guard.check(2.01)


def test_cells_run_the_core_comparison_first(toy: Target) -> None:
    m = matrix(conditions=["baseline", "harness"], models=["a:x", "a:y"], repeats=2)
    order = cells(m, {TOY: toy})
    assert [(c.condition, c.model, c.repeat) for c in order[:4]] == [
        ("baseline", "a:x", 1), ("harness", "a:x", 1),
        ("baseline", "a:y", 1), ("harness", "a:y", 1),
    ], "every model's first repeat comes before anyone's second"
    repeats = [c.repeat for c in order]
    assert repeats == sorted(repeats)


def test_a_matrix_stops_at_the_budget_and_says_so(tmp_path: Path, prices: PriceTable) -> None:
    runner = Paid()   # $2 per cell on Sonnet
    ledger = run_matrix(matrix(budget_usd=5.0), {"baseline": runner}, tmp_path, prices,
                        progress=quiet)
    outcomes = [r.outcome for r in ledger.records()]
    assert outcomes == [Outcome.OK, Outcome.OK, Outcome.SKIPPED_BUDGET]
    assert runner.calls == 2
    assert ledger.spent() == pytest.approx(4.0)


def test_a_resumed_matrix_never_pays_twice_for_a_finished_cell(
    tmp_path: Path, prices: PriceTable
) -> None:
    first = Paid([Outcome.OK, Outcome.ERROR, Outcome.REFUSED])
    run_matrix(matrix(), {"baseline": first}, tmp_path, prices, progress=quiet)
    assert first.calls == 3

    second = Paid()
    ledger = run_matrix(matrix(), {"baseline": second}, tmp_path, prices, progress=quiet)
    assert second.calls == 1, "only the errored cell is retried; a refusal is a result"
    assert ledger.spent() == pytest.approx(8.0), "the retried attempt's cost is still counted"


def test_the_budget_counts_what_earlier_invocations_spent(
    tmp_path: Path, prices: PriceTable
) -> None:
    run_matrix(matrix(repeats=2, budget_usd=5.0), {"baseline": Paid()}, tmp_path, prices,
               progress=quiet)
    later = Paid()
    run_matrix(matrix(repeats=3, budget_usd=5.0), {"baseline": later}, tmp_path, prices,
               progress=quiet)
    assert later.calls == 0, "$4 of $5 was already spent; a $2 cell must not start"


def test_the_fake_runner_spends_nothing(tmp_path: Path, prices: PriceTable) -> None:
    ledger = run_matrix(matrix(), {"baseline": FakeRunner()}, tmp_path, prices, progress=quiet)
    assert ledger.spent() == 0.0
    assert all(r.outcome is Outcome.OK for r in ledger.records())


def test_estimate_matches_the_worked_example_in_the_docs(prices: PriceTable) -> None:
    """docs/models-and-budget.md: Sonnet 5.5, $0.20 a baseline run and $1.20 a harness run."""
    m = matrix(conditions=["baseline", "harness"], repeats=3,
               tokens_per_run={"baseline": (60_000, 8_000), "harness": (400_000, 40_000)})
    result = estimate(m, prices)
    assert result["by_condition_and_model"] == {
        "baseline / anthropic:claude-sonnet-5-5": 0.6,
        "harness / anthropic:claude-sonnet-5-5": 3.6,
    }


def test_the_fake_matrix_runs_end_to_end_from_the_command_line(tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert main(["run", str(ROOT / "configs" / "matrix.fake.json"), "--fake",
                 "--out", str(out)]) == 0
    records = Ledger(out / "ledger.jsonl").records()
    assert len(records) == 12
    score = json.loads(next((out / "cells").rglob("score.json")).read_text(encoding="utf-8"))
    assert score["vulnerabilities"] == 5


def test_a_runner_that_raises_is_recorded_and_the_matrix_carries_on(
    tmp_path: Path, prices: PriceTable
) -> None:
    class Broken(Paid):
        def run(self, target: Target, route: str, workdir: Path, task: str = "",
            effort: str = "") -> RunResult:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("bug in a runner")
            return super().run(target, route, workdir, task)

    runner = Broken()
    ledger = run_matrix(matrix(), {"baseline": runner}, tmp_path, prices, progress=quiet)
    outcomes = [r.outcome for r in ledger.records()]
    assert outcomes[0] is Outcome.ERROR
    assert "bug in a runner" in ledger.records()[0].detail
    assert outcomes[1:] == [Outcome.OK, Outcome.OK], "the other cells still ran"


def test_a_previous_attempt_with_read_only_files_is_cleared(tmp_path: Path) -> None:
    """Git writes its objects read-only; a harness cell's tree is a git repository."""
    import os
    import stat

    from security_eval.matrix import remove_tree

    locked = tmp_path / "cell" / "tree" / ".git" / "objects" / "ab"
    locked.mkdir(parents=True)
    (locked / "cdef").write_text("x", encoding="utf-8")
    os.chmod(locked / "cdef", stat.S_IREAD)

    remove_tree(tmp_path / "cell")

    assert not (tmp_path / "cell").exists()


def test_prompt_variants_are_cells_and_the_ledger_records_which_text_ran(
    tmp_path: Path, prices: PriceTable
) -> None:
    """Honest framing is an experimental factor, and a frozen one."""
    from security_eval.runners.base import load_prompts, prompt_hash

    seen: list[str] = []

    class Recording(Paid):
        def run(self, target: Target, route: str, workdir: Path, task: str = "",
            effort: str = "") -> RunResult:
            seen.append(task)
            return super().run(target, route, workdir, task)

    ledger = run_matrix(matrix(prompts=["plain", "context"], repeats=1), {"baseline": Recording()},
                        tmp_path, prices, progress=quiet)
    prompts = load_prompts()
    assert seen == [prompts["plain"], prompts["context"]]
    assert [(r.prompt, r.prompt_sha) for r in ledger.records()] == [
        ("plain", prompt_hash(prompts["plain"])), ("context", prompt_hash(prompts["context"]))]


def test_an_unknown_prompt_name_stops_the_matrix_before_anything_is_spent(
    tmp_path: Path, prices: PriceTable
) -> None:
    runner = Paid()
    with pytest.raises(KeyError, match="not in"):
        run_matrix(matrix(prompts=["plain", "persuasive"]), {"baseline": runner}, tmp_path,
                   prices, progress=quiet)
    assert runner.calls == 0


def test_effort_is_a_dimension_that_reaches_the_runner_and_the_ledger(
    tmp_path: Path, prices: PriceTable
) -> None:
    seen: list[str] = []

    class Recording(Paid):
        def run(self, target: Target, route: str, workdir: Path, task: str = "",
                effort: str = "") -> RunResult:
            seen.append(effort)
            return super().run(target, route, workdir, task)

    ledger = run_matrix(matrix(efforts=["low", "high"], repeats=1), {"baseline": Recording()},
                        tmp_path, prices, progress=quiet)

    assert seen == ["low", "high"]
    records = ledger.records()
    assert [r.effort for r in records] == ["low", "high"]
    assert len({r.cell for r in records}) == 2, "each effort level is its own cell"
