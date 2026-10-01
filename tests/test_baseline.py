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
