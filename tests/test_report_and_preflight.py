"""The report that turns a ledger into results, and the checks that run before spending."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from security_eval.budget import PriceTable, Usage
from security_eval.cli import main
from security_eval.finding import SecurityFinding
from security_eval.ledger import Outcome
from security_eval.manifest import Target
from security_eval.matrix import Matrix, run_matrix
from security_eval.preflight import run_checks
from security_eval.report import load_cells, render_markdown, summarise
from security_eval.runners.base import RunResult

from .conftest import ROOT, TOY


class Scripted:
    """Answers each cell from a script: outcome, findings and spend."""

    condition = "baseline"

    def __init__(self, script: list[tuple[Outcome, list[SecurityFinding]]]) -> None:
        self.script = list(script)

    def run(self, target: Target, route: str, workdir: Path, task: str = "",
            effort: str = "") -> RunResult:
        outcome, findings = self.script.pop(0)
        return RunResult(outcome, findings, Usage(1_000_000, 100_000))


def hit(target: Target, index: int, source: str = "stated") -> SecurityFinding:
    v = target.vulnerabilities[index]
    return SecurityFinding("x", cwe=v.cwe, location=v.location, confidence=0.9,
                           location_source=source)


def matrix(**overrides: object) -> Matrix:
    base: dict[str, object] = dict(
        name="t", targets=[TOY], conditions=["baseline"],
        models=["anthropic:claude-sonnet-5-5"], repeats=3, budget_usd=100.0,
        tokens_per_run={"baseline": (1_000_000, 100_000)},
    )
    base.update(overrides)
    return Matrix(**base)  # type: ignore[arg-type]


def ran(tmp_path: Path, prices: PriceTable, toy: Target,
        script: list[tuple[Outcome, list[SecurityFinding]]]) -> Path:
    run_matrix(matrix(repeats=len(script)), {"baseline": Scripted(script)}, tmp_path, prices,
               progress=lambda _: None)
    return tmp_path


# -- the report ----------------------------------------------------------------------


def test_ok_and_completed_are_reported_apart(
    tmp_path: Path, prices: PriceTable, toy: Target
) -> None:
    """A harness stop is the harness's outcome, so the headline is shown with and without it."""
    out = ran(tmp_path, prices, toy, [
        (Outcome.OK, [hit(toy, 0), hit(toy, 1)]),
        (Outcome.HARNESS_STOPPED, []),
        (Outcome.REFUSED, []),
    ])
    (group,) = summarise(load_cells(out))["groups"]

    assert group["ok"]["recall_loose"]["n"] == 1
    assert group["ok"]["recall_loose"]["median"] == 0.4
    assert group["completed"]["recall_loose"]["n"] == 2
    assert group["completed"]["recall_loose"]["median"] == 0.2
    assert group["refusal_rate"] == pytest.approx(1 / 3, abs=1e-3)
    assert group["harness_stopped_rate"] == pytest.approx(1 / 3, abs=1e-3)


def test_cost_per_true_positive_counts_the_runs_that_found_nothing(
    tmp_path: Path, prices: PriceTable, toy: Target
) -> None:
    out = ran(tmp_path, prices, toy, [(Outcome.OK, [hit(toy, 0)]), (Outcome.OK, [])])
    (group,) = summarise(load_cells(out))["groups"]

    # Two runs at $3 each ($2 input + $1 output), one true positive between them.
    assert group["ok"]["cost_per_true_positive"] == pytest.approx(6.0)


def test_stated_only_treats_a_recovered_location_as_none(
    tmp_path: Path, prices: PriceTable, toy: Target
) -> None:
    out = ran(tmp_path, prices, toy, [(Outcome.OK, [hit(toy, 0), hit(toy, 1, "recovered")])])

    lenient = summarise(load_cells(out))["groups"][0]["ok"]
    strict = summarise(load_cells(out, stated_only=True))["groups"][0]["ok"]

    assert lenient["true_positives"] == 2
    assert strict["true_positives"] == 1
    assert strict["unanchored"] == 1
    assert lenient["recovered_locations"] == 1


def test_scores_are_recomputed_so_a_scorer_fix_reaches_old_runs(
    tmp_path: Path, prices: PriceTable, toy: Target
) -> None:
    """The report reads findings and the manifest, not the score written at run time."""
    out = ran(tmp_path, prices, toy, [(Outcome.OK, [hit(toy, 0)])])
    for score_file in out.rglob("score.json"):
        score_file.write_text(json.dumps({"tampered": True}), encoding="utf-8")

    (group,) = summarise(load_cells(out))["groups"]
    assert group["ok"]["true_positives"] == 1


def test_recall_by_cwe_says_which_classes_are_missed(
    tmp_path: Path, prices: PriceTable, toy: Target
) -> None:
    out = ran(tmp_path, prices, toy, [(Outcome.OK, [hit(toy, 0)])])
    by_cwe = {r["cwe"]: (r["found"], r["total"]) for r in summarise(load_cells(out))["by_cwe"]}

    assert by_cwe[toy.vulnerabilities[0].cwe or ""] == (1, 1)
    assert sum(found for found, _ in by_cwe.values()) == 1


def test_measured_tokens_are_offered_back_for_the_next_estimate(
    tmp_path: Path, prices: PriceTable, toy: Target
) -> None:
    out = ran(tmp_path, prices, toy, [(Outcome.OK, []), (Outcome.REFUSED, [])])
    summary = summarise(load_cells(out))

    assert summary["tokens_per_run"] == {"baseline": [1_000_000, 100_000]}
    assert '"tokens_per_run"' in render_markdown(summary, title="t", stated_only=False)


def test_the_report_command_writes_markdown_json_and_csv(
    tmp_path: Path, prices: PriceTable, toy: Target
) -> None:
    out = ran(tmp_path, prices, toy, [(Outcome.OK, [hit(toy, 0)])])

    assert main(["report", str(out)]) == 0

    assert (out / "report.md").is_file()
    assert json.loads((out / "report.json").read_text(encoding="utf-8"))["groups"]
    with (out / "cells.csv").open(encoding="utf-8") as fh:
        (row,) = list(csv.DictReader(fh))
    assert row["tp_loose"] == "1"


# -- preflight -------------------------------------------------------------------------


def levels(m: Matrix, prices: PriceTable, **kwargs: object) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {"ok": [], "warn": [], "fail": []}
    for c in run_checks(m, prices, **kwargs):  # type: ignore[arg-type]
        out[c.level].append(c.message)
    return out


def test_a_sound_fake_matrix_passes(prices: PriceTable) -> None:
    result = levels(Matrix.load(ROOT / "configs" / "matrix.fake.json"), prices, fake=True)
    assert result["fail"] == []


@pytest.mark.parametrize(("overrides", "expected"), [
    ({"prompts": ["plain", "persuasive"]}, "persuasive"),
    ({"models": ["anthropic:unpriced-model"]}, "no price"),
    ({"budget_usd": 0.01}, "projected"),
    ({"efforts": ["extreme"]}, "effort"),
])
def test_each_problem_is_a_failure_before_anything_runs(
    prices: PriceTable, overrides: dict[str, object], expected: str
) -> None:
    result = levels(matrix(**overrides), prices, fake=True)
    # Its own check, not a side effect of another: the estimate also fails on an
    # unpriced model, with a message that mentions the price.
    assert any(f.startswith(expected) or (expected != "no price" and expected in f)
               for f in result["fail"]), result["fail"]


def test_a_missing_harness_cli_is_a_failure(prices: PriceTable) -> None:
    result = levels(matrix(conditions=["harness"]), prices, supervisor="no-such-cli-xyz")
    assert any("not on PATH" in f for f in result["fail"])


def test_one_repeat_and_effort_on_a_local_model_are_warnings(prices: PriceTable) -> None:
    result = levels(matrix(repeats=1, models=["ollama:qwen"], efforts=["high"]), prices,
                    fake=True)
    assert any("one repeat" in w for w in result["warn"])
    assert any("do not apply" in w for w in result["warn"])


def test_run_refuses_to_start_when_a_check_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "matrix.json"
    bad.write_text(json.dumps({
        "name": "bad", "targets": [str(TOY)], "conditions": ["baseline"],
        "models": ["anthropic:unpriced-model"], "repeats": 1, "budget_usd": 1,
        "tokens_per_run": {"baseline": [1, 1]},
    }), encoding="utf-8")

    assert main(["run", str(bad), "--fake", "--out", str(tmp_path / "out")]) == 1
    assert not (tmp_path / "out" / "ledger.jsonl").exists(), "nothing ran"
    assert "nothing was run" in capsys.readouterr().out
