"""The Batches API path, and RQ3's triage of scanner output."""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from security_eval.batch import (
    BatchItem,
    BatchOutcome,
    BatchStore,
    custom_id,
    harness_body,
    read_outcome,
    supports_batch,
)
from security_eval.budget import PriceTable, Usage
from security_eval.cli import main
from security_eval.finding import Location, Verdict
from security_eval.ledger import Outcome
from security_eval.manifest import Target, load_target
from security_eval.matrix import Matrix, run_matrix
from security_eval.preflight import run_checks
from security_eval.report import load_cells, summarise
from security_eval.runners.base import RunResult
from security_eval.runners.triage import TriageRunner, parse_verdict
from security_eval.scanners import label, run_scan, scanner_findings

from .conftest import ROOT, TOY

NOTES = ROOT / "benchmarks" / "notes-api" / "manifest.json"
SONNET = "anthropic:claude-sonnet-5-5"

try:
    import supervisor_harness  # noqa: F401
    HAVE_HARNESS = True
except ImportError:
    HAVE_HARNESS = False
needs_harness = pytest.mark.skipif(not HAVE_HARNESS, reason="supervisor-harness not installed")


def quiet(_: str) -> None:
    pass


# -- eligibility and ids ----------------------------------------------------------------


def test_only_anthropics_own_api_offers_batches() -> None:
    assert supports_batch("anthropic:claude-sonnet-5-5")
    for route in ("bedrock:anthropic.claude-sonnet-5-5", "openrouter:anthropic/claude-sonnet-5-5",
                  "ollama:qwen", "fake:m"):
        assert not supports_batch(route), route


def test_custom_ids_are_legal_and_distinct() -> None:
    import re

    ids = {custom_id(f"t/{c}/plain/anthropic_m@high/r{r}", i)
           for c in ("baseline", "triage") for r in (1, 2) for i in range(3)}
    assert len(ids) == 12
    assert all(re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", i) for i in ids)


# -- the body matches what the harness would send ---------------------------------------


@needs_harness
def test_a_batched_request_is_the_request_the_harness_would_send(tmp_path: Path) -> None:
    """Otherwise batched and live baseline cells would not be the same condition."""
    import httpx
    from supervisor_harness.providers.anthropic import AnthropicProvider
    from supervisor_harness.providers.base import ChatMessage, CompletionRequest

    from security_eval.runners.baseline import FINDINGS_SCHEMA

    sent: list[dict[str, Any]] = []

    def answer(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={"content": [], "model": "m", "stop_reason": "end_turn",
                                         "usage": {"input_tokens": 1, "output_tokens": 1}})

    provider = AnthropicProvider(api_key="k")
    provider._client = httpx.AsyncClient(transport=httpx.MockTransport(answer),
                                         base_url=provider.base_url)
    effort = {"output_config": {"effort": "high"}}
    asyncio.run(provider.complete(CompletionRequest(
        model="claude-sonnet-5-5", system="sys", messages=[ChatMessage("user", "the task")],
        json_schema=FINDINGS_SCHEMA, max_tokens=16_000, extra=effort)))

    ours = harness_body(route=SONNET, system="sys", user="the task",
                        json_schema=FINDINGS_SCHEMA, max_tokens=16_000, extra=effort,
                        workdir=tmp_path)

    assert ours == sent[0]


@needs_harness
def test_caching_the_system_text_changes_nothing_the_model_reads(tmp_path: Path) -> None:
    plain = harness_body(route=SONNET, system="sys", user="u", json_schema=None,
                         max_tokens=100, extra={}, workdir=tmp_path)
    cached = harness_body(route=SONNET, system="sys", user="u", json_schema=None,
                          max_tokens=100, extra={}, workdir=tmp_path, cache_system=True)
    assert cached["system"] == [{"type": "text", "text": plain["system"],
                                 "cache_control": {"type": "ephemeral"}}]
    assert {k: v for k, v in cached.items() if k != "system"} == \
        {k: v for k, v in plain.items() if k != "system"}


# -- reading results ---------------------------------------------------------------------


def message(text: str = '{"findings": []}', stop: str = "end_turn", **usage: int) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "stop_reason": stop,
            "usage": {"input_tokens": 10, "output_tokens": 5, **usage}}


def test_a_batched_refusal_is_read_as_a_refusal() -> None:
    m = message(text="", stop="refusal")
    m["stop_details"] = {"category": "cyber"}
    assert read_outcome(BatchOutcome("c", "succeeded", m)).refusal == "cyber"


def test_cache_tokens_and_failures_are_read() -> None:
    reply = read_outcome(BatchOutcome("c", "succeeded", message(cache_read_input_tokens=900)))
    assert reply.cache_read_tokens == 900
    assert read_outcome(BatchOutcome("c", "expired")).error == "expired"


def test_the_store_survives_a_restart(tmp_path: Path) -> None:
    store = BatchStore(tmp_path / "batches.json")
    store.record("b1", {"c0-0": {"cell": "x", "index": 0}}, {"x": {"projected": 1.5, "n": 1}})

    again = BatchStore(tmp_path / "batches.json")
    assert again.pending_cells() == {"x": 1.5}
    again.mark_collected("b1")
    assert BatchStore(tmp_path / "batches.json").pending_cells() == {}


# -- the matrix, batched -------------------------------------------------------------------


class FakeClient:
    def __init__(self) -> None:
        self.submitted: list[list[BatchItem]] = []
        self.state = "in_progress"
        self.kind = "succeeded"

    def submit(self, items: list[BatchItem]) -> str:
        self.submitted.append(items)
        return f"batch_{len(self.submitted)}"

    def status(self, batch_id: str) -> str:
        return self.state

    def results(self, batch_id: str) -> Iterator[BatchOutcome]:
        for item in self.submitted[int(batch_id.split("_")[1]) - 1]:
            yield BatchOutcome(item.custom_id, self.kind,
                               message(input_tokens=1_000_000, output_tokens=100_000)
                               if self.kind == "succeeded" else None)


class Batchable:
    """A baseline that can batch, and fails the test if it is ever run live."""

    condition = "baseline"

    def __init__(self) -> None:
        self.live = 0

    def run(self, target: Target, route: str, workdir: Path, task: str = "",
            effort: str = "") -> RunResult:
        self.live += 1
        return RunResult(Outcome.OK, usage=Usage(1_000_000, 100_000))

    def batch_items(self, target: Target, route: str, task: str, effort: str, cell_id: str,
                    workdir: Path) -> list[BatchItem]:
        return [BatchItem(custom_id(cell_id, 0), {"model": route})]

    def from_batch(self, target: Target, route: str, outcomes: list[BatchOutcome],
                   effort: str = "") -> RunResult:
        reply = read_outcome(outcomes[0])
        if reply.error:
            return RunResult(Outcome.ERROR, detail=reply.error)
        return RunResult(Outcome.OK, usage=Usage(reply.input_tokens, reply.output_tokens))


def matrix(**overrides: object) -> Matrix:
    base: dict[str, object] = dict(
        name="t", targets=[TOY], conditions=["baseline"], models=[SONNET], repeats=2,
        budget_usd=100.0, tokens_per_run={"baseline": (1_000_000, 100_000)}, batch=True,
    )
    base.update(overrides)
    return Matrix(**base)  # type: ignore[arg-type]


def test_a_batch_is_submitted_once_and_collected_at_half_price(
    tmp_path: Path, prices: PriceTable
) -> None:
    client, runner = FakeClient(), Batchable()

    ledger = run_matrix(matrix(), {"baseline": runner}, tmp_path, prices, progress=quiet,
                        batch_client=client)
    assert len(client.submitted) == 1 and len(client.submitted[0]) == 2
    assert ledger.records() == [], "nothing is recorded until the batch comes back"

    run_matrix(matrix(), {"baseline": runner}, tmp_path, prices, progress=quiet,
               batch_client=client)
    assert len(client.submitted) == 1, "an unfinished batch is never resubmitted"

    client.state = "ended"
    ledger = run_matrix(matrix(), {"baseline": runner}, tmp_path, prices, progress=quiet,
                        batch_client=client)
    records = ledger.records()
    assert [r.outcome for r in records] == [Outcome.OK, Outcome.OK]
    assert records[0].cost_usd == pytest.approx(1.5), "$3 live, half price batched"
    assert runner.live == 0
    assert len(client.submitted) == 1


def test_a_model_without_a_batch_api_runs_live(tmp_path: Path, prices: PriceTable) -> None:
    client, runner = FakeClient(), Batchable()
    prices.models["local-model"] = prices.models["claude-haiku-4-5"]
    run_matrix(matrix(models=["ollama:local-model"]), {"baseline": runner}, tmp_path, prices,
               progress=quiet, batch_client=client)
    assert client.submitted == []
    assert runner.live == 2


def test_in_flight_batches_count_against_the_budget(tmp_path: Path, prices: PriceTable) -> None:
    """$1.50 a cell batched: two in flight claim $3 of a $4 budget."""
    client = FakeClient()
    run_matrix(matrix(budget_usd=4.0), {"baseline": Batchable()}, tmp_path, prices,
               progress=quiet, batch_client=client)
    ledger = run_matrix(matrix(budget_usd=4.0, repeats=3), {"baseline": Batchable()}, tmp_path,
                        prices, progress=quiet, batch_client=client)
    assert [r.outcome for r in ledger.records()] == [Outcome.SKIPPED_BUDGET]


def test_a_request_that_did_not_run_is_retried_by_resubmitting(
    tmp_path: Path, prices: PriceTable
) -> None:
    client = FakeClient()
    client.state, client.kind = "ended", "expired"
    run_matrix(matrix(repeats=1), {"baseline": Batchable()}, tmp_path, prices, progress=quiet,
               batch_client=client)
    ledger = run_matrix(matrix(repeats=1), {"baseline": Batchable()}, tmp_path, prices,
                        progress=quiet, batch_client=client)
    assert ledger.records()[0].outcome is Outcome.ERROR
    assert len(client.submitted) == 2, "an expired request is an error, so it is retried"


def test_the_harness_condition_is_never_batched(tmp_path: Path, prices: PriceTable) -> None:
    client = FakeClient()
    harness = Batchable()
    harness.condition = "harness"
    run_matrix(matrix(conditions=["harness"], repeats=1,
                      tokens_per_run={"harness": (1, 1)}),
               {"harness": harness}, tmp_path, prices, progress=quiet, batch_client=client)
    assert client.submitted == []
    assert harness.live == 1


# -- triage -------------------------------------------------------------------------------


def test_scanner_findings_are_labelled_by_the_answer_key() -> None:
    notes = load_target(NOTES)
    findings = scanner_findings(notes, "bandit")
    labels = dict(zip(((f.location.normalised_path, f.location.start_line)
                       for f in findings if f.location), label(findings, notes), strict=True))
    assert labels[("notes/db.py", 15)] is True          # V1
    assert labels[("notes/render.py", 19)] is False     # D6: MD5 for an ETag


@pytest.mark.parametrize(("text", "verdict"), [
    ('{"verdict": "false_positive", "confidence": 0.9, "reasoning": "r"}', Verdict.FALSE_POSITIVE),
    ('```json\n{"verdict": "TRUE_POSITIVE", "confidence": 2, "reasoning": "r"}\n```',
     Verdict.TRUE_POSITIVE),
    ('{"verdict": "probably", "confidence": 1, "reasoning": "r"}', None),
    ("I think it is fine.", None),
])
def test_verdicts_are_parsed_or_rejected(text: str, verdict: Verdict | None) -> None:
    parsed = parse_verdict(text)
    assert (parsed["verdict"] if parsed else None) == verdict
    if parsed:
        assert 0.0 <= parsed["confidence"] <= 1.0


@needs_harness
def test_a_triage_cell_is_one_cached_request_per_finding(tmp_path: Path) -> None:
    notes = load_target(NOTES)
    items = TriageRunner("bandit").batch_items(notes, SONNET, "triage this", "", "cell", tmp_path)
    assert isinstance(items, list)
    assert len(items) == len(scanner_findings(notes, "bandit"))
    assert all(i.params["system"][0]["cache_control"] == {"type": "ephemeral"} for i in items)
    assert len({i.params["system"][0]["text"] for i in items}) == 1, \
        "the repository is the same prefix for every finding"
    for item, finding in zip(items, scanner_findings(notes, "bandit"), strict=True):
        assert finding.location is not None
        where = f"{finding.location.normalised_path}:{finding.location.start_line}"
        assert where in item.params["messages"][0]["content"], "each asks about its own finding"


def test_batched_verdicts_come_back_in_order_and_are_scored(tmp_path: Path) -> None:
    notes = load_target(NOTES)
    findings = scanner_findings(notes, "bandit")
    truth = label(findings, notes)
    outcomes = [
        BatchOutcome(custom_id("c", i), "succeeded", message(json.dumps({
            "verdict": "true_positive" if real else "false_positive", "confidence": 0.8,
            "reasoning": "r"})))
        for i, real in enumerate(truth)
    ]
    result = TriageRunner("bandit").from_batch(notes, SONNET, outcomes)

    assert result.outcome is Outcome.OK
    assert [f.triage for f in result.findings] == [
        Verdict.TRUE_POSITIVE if real else Verdict.FALSE_POSITIVE for real in truth]
    assert result.extra["batched"] is True


def test_a_triage_cell_whose_every_request_was_refused_is_refused() -> None:
    notes = load_target(NOTES)
    n = len(scanner_findings(notes, "bandit"))
    refused = message(text="", stop="refusal")
    result = TriageRunner("bandit").from_batch(
        notes, SONNET, [BatchOutcome(custom_id("c", i), "succeeded", refused) for i in range(n)])
    assert result.outcome is Outcome.REFUSED


class ScriptedTriage:
    """Dismisses every not-real finding, keeps half the real ones."""

    condition = "triage"
    kind = "triage"

    def run(self, target: Target, route: str, workdir: Path, task: str = "",
            effort: str = "") -> RunResult:
        findings = scanner_findings(target, "bandit")
        kept = 0
        for f, real in zip(findings, label(findings, target), strict=True):
            if not real:
                f.triage = Verdict.FALSE_POSITIVE
            else:
                f.triage = Verdict.TRUE_POSITIVE if kept % 2 == 0 else Verdict.NEEDS_INFO
                kept += 1
        return RunResult(Outcome.OK, findings, Usage(1_000_000, 0), extra={"tool": "bandit"})


def test_the_report_says_how_much_noise_went_and_how_many_real_issues_stayed(
    tmp_path: Path, prices: PriceTable
) -> None:
    m = matrix(targets=[NOTES], conditions=["triage"], repeats=1, batch=False,
               tokens_per_run={"triage": (1, 1)})
    run_matrix(m, {"triage": ScriptedTriage()}, tmp_path, prices, progress=quiet)

    (row,) = summarise(load_cells(tmp_path))["triage"]
    assert row["noise_dismissed"]["median"] == 1.0
    assert row["real_kept"]["median"] == pytest.approx(2 / 3, abs=1e-3)   # 3 real: kept 2


# -- preflight and scanning ------------------------------------------------------------------


def test_triage_without_a_scan_fails_preflight(tmp_path: Path, prices: PriceTable) -> None:
    copy = tmp_path / "toy"
    shutil.copytree(TOY.parent, copy, ignore=shutil.ignore_patterns("scans"))
    data = json.loads((copy / "manifest.json").read_text(encoding="utf-8"))
    data.pop("scans", None)
    (copy / "manifest.json").write_text(json.dumps(data), encoding="utf-8")

    checks = run_checks(matrix(targets=[copy / "manifest.json"], conditions=["triage"],
                               tokens_per_run={"triage": (1, 1)}), prices, fake=True)
    assert any(c.level == "fail" and "no bandit scan" in c.message for c in checks)


def test_preflight_says_which_cells_batch_and_which_run_live(prices: PriceTable) -> None:
    prices.models["local-model"] = prices.models["claude-haiku-4-5"]
    checks = run_checks(matrix(models=[SONNET, "ollama:local-model"]), prices, fake=True)
    messages = [(c.level, c.message) for c in checks]
    assert any(level == "ok" and "half price" in m and SONNET in m for level, m in messages)
    assert any(level == "warn" and "ollama:local-model" in m for level, m in messages)


def test_scan_records_any_tool_s_sarif_in_the_manifest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    copy = tmp_path / "toy"
    shutil.copytree(TOY.parent, copy)
    writer = tmp_path / "fake_scanner.py"
    writer.write_text(
        "import json, sys\n"
        "json.dump({'runs': [{'tool': {'driver': {'name': 'mine', 'rules': []}}, 'results': ["
        "{'ruleId': 'X1', 'message': {'text': 'looks bad'}, 'locations': [{'physicalLocation': "
        "{'artifactLocation': {'uri': 'app/db.py'}, 'region': {'startLine': 11}}}]}]}]}, "
        "open(sys.argv[1], 'w'))\n", encoding="utf-8")

    assert main(["scan", "mine", str(copy / "manifest.json"), "--command",
                 f"{sys.executable} {writer} {{out}}"]) == 0

    target = load_target(copy / "manifest.json")
    (finding,) = scanner_findings(target, "mine")
    assert finding.location == Location("app/db.py", 11, 11)
    assert label([finding], target) == [True]


def test_run_scan_reports_a_missing_tool(tmp_path: Path) -> None:
    from security_eval.scanners import ScanError

    with pytest.raises(ScanError, match="not on PATH"):
        run_scan(load_target(TOY), "x", tmp_path / "x.sarif", ["no-such-scanner-xyz", "{out}"])


def test_the_fake_triage_runner_spends_nothing_and_scores(tmp_path: Path) -> None:
    out = tmp_path / "out"
    m = tmp_path / "m.json"
    m.write_text(json.dumps({
        "name": "f", "targets": [str(NOTES)], "conditions": ["triage"], "models": ["fake:m"],
        "repeats": 1, "tokens_per_run": {"triage": [1, 1]}}), encoding="utf-8")
    assert main(["run", str(m), "--fake", "--out", str(out)]) == 0
    record = json.loads((out / "ledger.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert record["extra"]["kind"] == "triage"
    assert record["cost_usd"] == 0.0


def test_results_are_put_back_in_request_order(tmp_path: Path, prices: PriceTable) -> None:
    """The Batches API returns results in any order; a triage verdict must stay with its finding."""
    seen: list[list[str]] = []

    class ThreeRequests(Batchable):
        def batch_items(self, target: Target, route: str, task: str, effort: str,
                        cell_id: str, workdir: Path) -> list[BatchItem]:
            return [BatchItem(custom_id(cell_id, i), {"n": i}) for i in range(3)]

        def from_batch(self, target: Target, route: str, outcomes: list[BatchOutcome],
                       effort: str = "") -> RunResult:
            seen.append([o.custom_id for o in outcomes])
            return RunResult(Outcome.OK)

    class Shuffled(FakeClient):
        def results(self, batch_id: str) -> Iterator[BatchOutcome]:
            yield from reversed(list(super().results(batch_id)))

    client = Shuffled()
    client.state = "ended"
    runner = ThreeRequests()
    run_matrix(matrix(repeats=1), {"baseline": runner}, tmp_path, prices, progress=quiet,
               batch_client=client)
    run_matrix(matrix(repeats=1), {"baseline": runner}, tmp_path, prices, progress=quiet,
               batch_client=client)

    (order,) = seen
    assert order == [item.custom_id for item in client.submitted[0]]
