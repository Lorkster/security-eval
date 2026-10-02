"""The baseline condition's handling of what the provider layer hands back.

Uses the harness's real provider layer with its router's `complete` replaced,
so what is tested is this runner's reading of real harness types -- including
`ProviderRefusal`, which the harness raises (since #70) where it used to return
an empty answer with `finish_reason: "refusal"`. A runner still checking the
old shape would record every refusal as an error, and a resumed matrix would
then retry it: exactly what the study must never do.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from security_eval.ledger import Outcome
from security_eval.manifest import Target
from security_eval.runners.baseline import BaselineRunner

try:
    from supervisor_harness.models import Usage as HarnessUsage
    from supervisor_harness.providers.base import CompletionResponse, ProviderRefusal
    from supervisor_harness.providers.router import ModelRouter
    HAVE = True
except ImportError:
    HAVE = False
needs_harness = pytest.mark.skipif(not HAVE, reason="supervisor-harness not installed")


def answering(monkeypatch: pytest.MonkeyPatch, outcome: Any, seen: list[Any]) -> None:
    async def complete(self: Any, stage: str, request: Any, **kwargs: Any) -> Any:
        seen.append(request)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(ModelRouter, "complete", complete)


@needs_harness
def test_a_refusal_is_recorded_as_refused_with_its_category(
    toy: Target, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    answering(monkeypatch, ProviderRefusal("anthropic", category="cyber"), [])

    result = BaselineRunner().run(toy, "anthropic:claude-sonnet-5-5", tmp_path)

    assert result.outcome is Outcome.REFUSED
    assert result.extra["refusal_categories"] == ["cyber"]


@needs_harness
def test_effort_reaches_the_request_only_for_models_that_take_one(
    toy: Target, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[Any] = []
    answer = CompletionResponse(text='{"findings": []}', usage=HarnessUsage(10, 5))
    answering(monkeypatch, answer, seen)

    BaselineRunner().run(toy, "anthropic:claude-sonnet-5-5", tmp_path, effort="high")
    BaselineRunner().run(toy, "ollama:qwen", tmp_path, effort="high")

    assert seen[0].extra == {"output_config": {"effort": "high"}}
    assert seen[1].extra == {}, "a local model is not sent a parameter it does not know"


@needs_harness
def test_cache_tokens_are_carried_into_the_cost(
    toy: Target, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    usage = HarnessUsage(10, 5, cache_read_tokens=900, cache_write_tokens=40)
    answering(monkeypatch, CompletionResponse(text='{"findings": []}', usage=usage), [])

    result = BaselineRunner().run(toy, "anthropic:claude-sonnet-5-5", tmp_path)

    assert (result.usage.cache_read_tokens, result.usage.cache_write_tokens) == (900, 40)


@needs_harness
def test_a_truncated_answer_says_so(
    toy: Target, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    answer = CompletionResponse(text='{"findings": [', finish_reason="max_tokens")
    answering(monkeypatch, answer, [])

    result = BaselineRunner().run(toy, "anthropic:claude-sonnet-5-5", tmp_path)

    assert result.outcome is Outcome.INVALID_OUTPUT
    assert "truncated" in result.detail


def test_a_bare_list_of_findings_is_accepted() -> None:
    """Seen from a local model without a format constraint: the list, fenced, no object."""
    from security_eval.runners.baseline import parse_findings

    text = ('```json\n[{"title": "a", "cwe": "CWE-89", "location": "app/db.py:10-12", '
            '"severity": "high", "confidence": 0.9},\n {"title": "b", "cwe": "CWE-79", '
            '"location": "app/x.py:3", "severity": "low", "confidence": 0.4}]\n```')
    found = parse_findings(text, "ollama:m")
    assert found is not None and [f.title for f in found] == ["a", "b"]
    assert found[0].location is not None and found[0].location.start_line == 10
    assert parse_findings('{"findings": []}', "ollama:m") == []
    assert parse_findings("[not json", "ollama:m") is None


def test_an_empty_answer_in_a_few_tokens_is_flagged_in_the_report(
    tmp_path: Path, prices: Any
) -> None:
    from security_eval.budget import Usage
    from security_eval.matrix import Matrix, run_matrix
    from security_eval.report import load_cells, render_markdown, summarise
    from security_eval.runners.base import RunResult

    from .conftest import TOY

    class Empty:
        condition = "baseline"

        def __init__(self, out: int) -> None:
            self.out = out

        def run(self, target: Target, route: str, workdir: Path, task: str = "",
                effort: str = "") -> RunResult:
            return RunResult(Outcome.OK, [], Usage(90_000, self.out))

    m = Matrix(name="e", targets=[TOY], conditions=["baseline"], models=["ollama:m"],
               tokens_per_run={"baseline": (1, 1)})
    run_matrix(m, {"baseline": Empty(11)}, tmp_path / "short", prices, progress=lambda _: None)
    summary = summarise(load_cells(tmp_path / "short"))
    assert len(summary["empty_answers"]) == 1
    assert "gave up" in render_markdown(summary, title="t", stated_only=False)

    run_matrix(m, {"baseline": Empty(900)}, tmp_path / "long", prices, progress=lambda _: None)
    assert summarise(load_cells(tmp_path / "long"))["empty_answers"] == [], \
        "a considered answer that found nothing is not flagged"
