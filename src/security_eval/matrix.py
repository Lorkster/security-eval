"""Expand a matrix into cells, order them, cost them, run them.

A matrix file:

    {
      "name": "pilot",
      "targets": ["benchmarks/toy-webapp/manifest.json"],
      "conditions": ["baseline", "harness"],
      "models": ["anthropic:claude-sonnet-5-5"],
      "prompts": ["plain", "context"],        # optional: names in the prompts file
      "prompts_file": "prompts.json",         # optional: default configs/prompts.json
      "efforts": ["low", "high"],             # optional: effort levels, for models that take one
      "repeats": 3,
      "budget_usd": 25.0,
      "tokens_per_run": {                      # assumptions until the pilot measures them
        "baseline": [60000, 8000],
        "harness": [400000, 40000]
      }
    }

Cells run in *priority* order, not nested-loop order: every target's first
repeat on the first model, across every condition, before anything else. If the
budget runs out partway, what finished is still a complete comparison, not
three repeats of half the targets.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from .batch import (
    AnthropicBatchClient,
    BatchClient,
    BatchItem,
    BatchOutcome,
    BatchStore,
    supports_batch,
)
from .budget import BudgetExceeded, BudgetGuard, PriceTable, Usage
from .ledger import Ledger, Outcome, Record
from .manifest import Target, load_target
from .runners.base import DEFAULT_PROMPTS, Runner, RunResult, load_prompts, prompt_hash

DEFAULT_MODELS = Path(__file__).resolve().parents[2] / "configs" / "models.json"


def training_cutoff(models_file: Path, route: str) -> date | None:
    """A model's training cutoff from the models file, or ``None`` if it is not recorded."""
    if not models_file.is_file():
        return None
    models = json.loads(models_file.read_text(encoding="utf-8")).get("models", {})
    model = route.split(":", 1)[-1]
    for key in (model, model.rsplit("/", 1)[-1]):
        raw = (models.get(key) or {}).get("training_cutoff")
        if raw:
            return date.fromisoformat(str(raw))
    return None


@dataclass
class Matrix:
    name: str
    targets: list[Path]
    conditions: list[str]
    models: list[str]
    repeats: int = 1
    budget_usd: float = 0.0
    tokens_per_run: dict[str, tuple[int, int]] = field(default_factory=dict)
    prompts: list[str] = field(default_factory=lambda: ["plain"])
    prompts_file: Path = DEFAULT_PROMPTS
    #: "" is the provider's default. Only models that take an effort level
    #: (current Claude models) are affected; see `effort_params`.
    efforts: list[str] = field(default_factory=lambda: [""])
    #: Send eligible cells through the Message Batches API at half price. Only
    #: models on the `anthropic` route are eligible; everything else runs live.
    batch: bool = False
    #: The scanner whose output the triage condition judges.
    scanner: str = "bandit"
    #: The prompt the triage condition uses (from the prompts file). Triage has
    #: its own task, so the `prompts` dimension does not apply to it.
    triage_prompt: str = "triage"
    #: The prompt the fix condition (RQ8) uses. Like triage, it has its own task.
    fix_prompt: str = "fix"
    #: Models standing in for an unregulated attacker: legal open-weight models,
    #: run on the same defensive task. Adjudication reports how much of what
    #: they find the other models also find.
    attacker_proxies: list[str] = field(default_factory=list)
    models_file: Path = DEFAULT_MODELS

    @classmethod
    def load(cls, path: Path | str) -> Matrix:
        path = Path(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        base = path.parent
        return cls(
            name=str(data.get("name", path.stem)),
            targets=[_resolve(base, t) for t in data["targets"]],
            conditions=list(data["conditions"]),
            models=list(data["models"]),
            repeats=int(data.get("repeats", 1)),
            budget_usd=float(data.get("budget_usd", 0.0)),
            tokens_per_run={k: (int(v[0]), int(v[1]))
                            for k, v in data.get("tokens_per_run", {}).items()},
            prompts=list(data.get("prompts", ["plain"])),
            prompts_file=(_resolve(base, data["prompts_file"]) if "prompts_file" in data
                          else DEFAULT_PROMPTS),
            efforts=[str(e) for e in data.get("efforts", [""])] or [""],
            batch=bool(data.get("batch", False)),
            scanner=str(data.get("scanner", "bandit")),
            triage_prompt=str(data.get("triage_prompt", "triage")),
            fix_prompt=str(data.get("fix_prompt", "fix")),
            attacker_proxies=[str(m) for m in data.get("attacker_proxies", [])],
            models_file=(_resolve(base, data["models_file"]) if "models_file" in data
                         else DEFAULT_MODELS),
        )

    def prompts_for(self, condition: str) -> list[str]:
        own = {"triage": self.triage_prompt, "fix": self.fix_prompt}
        return [own[condition]] if condition in own else self.prompts

    def batched(self, cell: Cell) -> bool:
        """Whether this cell goes through the Batches API rather than live."""
        return self.batch and cell.condition in BATCHABLE and supports_batch(cell.model)


#: Conditions that can be batched: one-shot requests. The harness condition is a
#: conversation -- each turn depends on the last -- so it always runs live.
BATCHABLE = frozenset({"baseline", "triage", "fix"})


def _resolve(base: Path, raw: str) -> Path:
    """A target path relative to the matrix file, or to the working directory."""
    for candidate in (base / raw, Path(raw)):
        if candidate.exists():
            return candidate.resolve()
    return (base / raw).resolve()


@dataclass(frozen=True)
class Cell:
    target: str
    condition: str
    model: str
    repeat: int
    manifest: Path
    prompt: str = "plain"
    effort: str = ""

    @property
    def id(self) -> str:
        safe_model = self.model.replace(":", "_").replace("/", "_")
        effort = f"@{self.effort}" if self.effort else ""
        return f"{self.target}/{self.condition}/{self.prompt}/{safe_model}{effort}/r{self.repeat}"


def cells(matrix: Matrix, targets: Mapping[Path, Target]) -> list[Cell]:
    out = [
        Cell(targets[m].id, condition, model, repeat, m, prompt, effort)
        for m in matrix.targets
        for condition in matrix.conditions
        for prompt in matrix.prompts_for(condition)
        for effort in matrix.efforts
        for model in matrix.models
        for repeat in range(1, matrix.repeats + 1)
    ]
    # Priority order: repeat, model, prompt, target, condition -- so the first
    # repeat of the first model and prompt covers every target and condition
    # before anything else starts.
    model_rank = {m: i for i, m in enumerate(matrix.models)}
    prompt_rank = {p: i for i, p in enumerate([*matrix.prompts, matrix.triage_prompt,
                                               matrix.fix_prompt])}
    effort_rank = {e: i for i, e in enumerate(matrix.efforts)}
    target_rank = {targets[m].id: i for i, m in enumerate(matrix.targets)}
    cond_rank = {c: i for i, c in enumerate(matrix.conditions)}
    return sorted(out, key=lambda c: (c.repeat, model_rank[c.model], prompt_rank[c.prompt],
                                      effort_rank[c.effort], target_rank[c.target],
                                      cond_rank[c.condition]))


def projected_cost(cell: Cell, matrix: Matrix, prices: PriceTable, *,
                   batch: bool | None = None) -> float:
    tokens = matrix.tokens_per_run.get(cell.condition)
    if tokens is None:
        raise KeyError(f"tokens_per_run has no figure for condition {cell.condition!r}")
    batched = matrix.batched(cell) if batch is None else batch
    return prices.cost(cell.model, Usage(*tokens), batch=batched)


def estimate(matrix: Matrix, prices: PriceTable) -> dict[str, Any]:
    targets = {m: load_target(m) for m in matrix.targets}
    plan = cells(matrix, targets)
    by_block: dict[str, float] = {}
    for cell in plan:
        key = f"{cell.condition} / {cell.model}"
        if len(matrix.prompts) > 1:
            key += f" / {cell.prompt}"
        if cell.effort:
            key += f" @ {cell.effort}"
        by_block[key] = by_block.get(key, 0.0) + projected_cost(cell, matrix, prices)
    total = sum(by_block.values())
    return {
        "cells": len(plan),
        "total_usd": round(total, 2),
        "by_condition_and_model": {k: round(v, 2) for k, v in sorted(by_block.items())},
        "budget_usd": matrix.budget_usd,
        "fits": matrix.budget_usd <= 0 or total <= matrix.budget_usd,
        "prices_as_of": prices.as_of,
        "tokens_per_run": {k: list(v) for k, v in matrix.tokens_per_run.items()},
    }


def run_matrix(
    matrix: Matrix,
    runners: Mapping[str, Runner],
    out_dir: Path,
    prices: PriceTable,
    *,
    dry_run: bool = False,
    progress: Callable[[str], None] = print,
    batch_client: BatchClient | None = None,
    wait: bool = False,
    poll_seconds: float = 60.0,
) -> Ledger:
    """Run every cell not already finished, under the budget guard.

    With ``matrix.batch``, eligible cells are submitted as one batch instead of
    run live, and collected on a later invocation (or now, with ``wait``).
    Anything finished in a batch submitted earlier is collected first.
    """
    ledger = Ledger(out_dir / "ledger.jsonl")
    targets = {m: load_target(m) for m in matrix.targets}
    available = load_prompts(matrix.prompts_file)
    needed = {p for c in matrix.conditions for p in matrix.prompts_for(c)}
    unknown = sorted(needed - set(available))
    if unknown:
        raise KeyError(f"prompt(s) {unknown} are not in {matrix.prompts_file}")
    plan = cells(matrix, targets)
    by_id = {c.id: c for c in plan}
    store = BatchStore(out_dir / "batches.json")
    run = _Run(matrix, runners, out_dir, prices, ledger, targets, available, progress)

    if store.pending() and not dry_run:
        client = batch_client or AnthropicBatchClient(out_dir)
        _collect(store, client, run, by_id)

    done = ledger.finished()
    pending = store.pending_cells()
    # In flight is spent, as far as the budget is concerned: a re-run while a
    # batch is out must not start work the batch's cost has already claimed.
    guard = (BudgetGuard(matrix.budget_usd, ledger.spent() + sum(pending.values()))
             if matrix.budget_usd > 0 else None)

    to_batch: list[tuple[Cell, float]] = []
    for cell in plan:
        if cell.id in done or cell.id in pending:
            continue
        runner = runners.get(cell.condition)
        if runner is None:
            raise KeyError(f"no runner for condition {cell.condition!r}")
        target = targets[cell.manifest]
        if not target.allows(cell.model):
            # Enforced here as well as in preflight, so --skip-check cannot send
            # code somewhere its owner did not approve. Final: retrying will not
            # change the policy.
            ledger.append(_record(
                cell, Outcome.SKIPPED_POLICY, prompt_sha=prompt_hash(available[cell.prompt]),
                detail=f"{target.id} may only go to {', '.join(target.allowed_providers)}"))
            progress(f"skip  {cell.id}: data policy forbids {cell.model.split(':', 1)[0]}")
            continue
        # Only a runner that can build batch requests is batched; the fake runners
        # cannot, so a --fake matrix always runs live.
        batched = matrix.batched(cell) and hasattr(runner, "batch_items")
        projected = projected_cost(cell, matrix, prices, batch=batched)
        if guard is not None:
            try:
                guard.check(projected, cell.id)
            except BudgetExceeded as exc:
                ledger.append(_record(cell, Outcome.SKIPPED_BUDGET, detail=str(exc),
                                      prompt_sha=prompt_hash(available[cell.prompt])))
                progress(f"skip  {cell.id}: {exc}")
                continue
            if batched:
                guard.record(projected)     # claimed now; settled when collected
        if dry_run:
            progress(f"would {'batch' if batched else 'run'} {cell.id} (~${projected:.2f})")
            continue
        if batched:
            to_batch.append((cell, projected))
            continue

        workdir = run.fresh_workdir(cell)
        started, t0 = _now(), time.monotonic()
        try:
            result = runner.run(targets[cell.manifest], cell.model, workdir,
                                available[cell.prompt], cell.effort)
        except Exception as exc:  # noqa: BLE001 - one broken cell must not end the matrix
            # Recorded as an error, so a resumed matrix retries it. Whatever it
            # spent before failing is unknown and so unrecorded -- the one gap
            # in the ledger's accounting, and why runners return errors rather
            # than raise them.
            result = RunResult(Outcome.ERROR, detail=f"runner raised {type(exc).__name__}: "
                                                     f"{exc}"[:500])
        cost = run.finish(cell, runner, result, workdir, started, t0, batched=False)
        if guard is not None:
            guard.record(cost)

    if to_batch:
        client = batch_client or AnthropicBatchClient(out_dir)
        _submit(store, client, run, to_batch)

    while wait and store.pending() and not dry_run:
        client = batch_client or AnthropicBatchClient(out_dir)
        progress(f"waiting {poll_seconds:.0f}s for {len(store.pending())} batch(es)...")
        time.sleep(poll_seconds)
        _collect(store, client, run, by_id)
    for batch in store.pending():
        progress(f"batch {batch.batch_id}: {len(batch.cells)} cell(s) in flight; run again "
                 "to collect (most finish within an hour, all within 24)")
    return ledger


@dataclass
class _Run:
    """What finishing a cell needs, whether it ran live or came back from a batch."""

    matrix: Matrix
    runners: Mapping[str, Runner]
    out_dir: Path
    prices: PriceTable
    ledger: Ledger
    targets: Mapping[Path, Target]
    prompts: Mapping[str, str]
    progress: Callable[[str], None]

    def fresh_workdir(self, cell: Cell) -> Path:
        workdir = self.out_dir / "cells" / cell.id
        if workdir.exists():
            remove_tree(workdir)   # a previous attempt at a non-final cell
        workdir.mkdir(parents=True)
        return workdir

    def finish(self, cell: Cell, runner: Runner, result: RunResult, workdir: Path,
               started: str, t0: float, *, batched: bool) -> float:
        """Score, save and record one cell; return what it cost."""
        from .scoring import score, score_triage

        # The fake runner reports plausible token counts so projections can be
        # exercised, but no money moved, and the ledger must not say it did.
        cost = (0.0 if runner.condition == "fake"
                else self.prices.cost(cell.model, result.usage, batch=batched))
        findings_path = workdir / "findings.json"
        findings_path.write_text(
            json.dumps([f.to_dict() for f in result.findings], indent=2), encoding="utf-8")
        for name, data in result.artifacts.items():
            (workdir / f"{name}.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
        target = self.targets[cell.manifest]
        extra: dict[str, Any] = {**result.extra, "manifest": str(cell.manifest)}
        kind = getattr(runner, "kind", "detect")
        if kind == "fix":
            # Nothing to score yet: the proposals are checked in the sandbox by
            # `security-eval verify`, which costs nothing and can be re-run.
            extra["kind"] = "fix"
            n = len(result.artifacts.get("proposals", []))
            summary = f"{n} proposal(s) to verify"
        elif target.open:
            # No answer key: findings (or triage verdicts) are kept for blind
            # adjudication, and nothing is scored against an empty key, which
            # would call every finding a false positive.
            extra["open"] = True
            if kind == "triage":
                extra["kind"] = "triage"
            summary = f"{len(result.findings)} item(s) kept for adjudication"
        elif kind == "triage":
            from .scanners import label

            triaged = score_triage([f.triage for f in result.findings],
                                   label(result.findings, target))
            (workdir / "score.json").write_text(json.dumps(asdict(triaged), indent=2),
                                                encoding="utf-8")
            extra["kind"] = "triage"
            extra["triage_accuracy"] = round(triaged.accuracy, 4)
            summary = f"triage accuracy {triaged.accuracy:.2f} over {triaged.total}"
        else:
            scored = score(result.findings, target)
            (workdir / "score.json").write_text(json.dumps(scored.to_dict(), indent=2),
                                                encoding="utf-8")
            extra["recall_loose"] = round(scored.recall(), 4)
            extra["precision_loose"] = round(scored.precision(), 4)
            summary = f"recall {scored.recall():.2f}  precision {scored.precision():.2f}"
        self.ledger.append(_record(
            cell, result.outcome, prompt_sha=prompt_hash(self.prompts[cell.prompt]),
            cost=cost, usage=result.usage,
            seconds=result.seconds or (time.monotonic() - t0),
            findings_path=findings_path.relative_to(self.out_dir).as_posix(),
            detail=result.detail, started=started, extra=extra,
        ))
        self.progress(f"{result.outcome.value:<15} {cell.id}  ${cost:.3f}  {summary}"
                      + ("  [batch]" if batched else ""))
        return cost


def _submit(store: BatchStore, client: BatchClient, run: _Run,
            to_batch: list[tuple[Cell, float]]) -> None:
    items: list[BatchItem] = []
    index: dict[str, dict[str, Any]] = {}
    cells_info: dict[str, dict[str, Any]] = {}
    for cell, projected in to_batch:
        runner = run.runners[cell.condition]
        workdir = run.fresh_workdir(cell)
        built = runner.batch_items(run.targets[cell.manifest], cell.model,  # type: ignore[attr-defined]
                                   run.prompts[cell.prompt], cell.effort, cell.id, workdir)
        if isinstance(built, RunResult):
            # Cannot be sent at all (a target too large, a missing scan): an
            # error now, exactly as it would be live.
            run.finish(cell, runner, built, workdir, _now(), time.monotonic(), batched=True)
            continue
        if not built:
            run.finish(cell, runner, runner.from_batch(  # type: ignore[attr-defined]
                run.targets[cell.manifest], cell.model, [], cell.effort),
                workdir, _now(), time.monotonic(), batched=True)
            continue
        for i, item in enumerate(built):
            items.append(item)
            index[item.custom_id] = {"cell": cell.id, "index": i}
        cells_info[cell.id] = {"projected": projected, "n": len(built)}
    if not items:
        return
    batch_id = client.submit(items)
    store.record(batch_id, index, cells_info)
    run.progress(f"submitted batch {batch_id}: {len(cells_info)} cell(s), "
                 f"{len(items)} request(s), at the batch price")


def _collect(store: BatchStore, client: BatchClient, run: _Run, by_id: Mapping[str, Cell]) -> None:
    for batch in store.pending():
        status = client.status(batch.batch_id)
        if status != "ended":
            continue
        outcomes: dict[str, list[tuple[int, BatchOutcome]]] = {}
        for outcome in client.results(batch.batch_id):
            entry = batch.items.get(outcome.custom_id)
            if entry is None:
                continue
            outcomes.setdefault(entry["cell"], []).append((int(entry["index"]), outcome))
        for cell_id in batch.cells:
            cell = by_id.get(cell_id)
            if cell is None:
                continue        # no longer in this matrix; its spend is still in the batch
            ordered = [o for _, o in sorted(outcomes.get(cell_id, []), key=lambda p: p[0])]
            runner = run.runners[cell.condition]
            workdir = run.out_dir / "cells" / cell.id
            workdir.mkdir(parents=True, exist_ok=True)
            result = runner.from_batch(run.targets[cell.manifest], cell.model,  # type: ignore[attr-defined]
                                       ordered, cell.effort)
            result.extra["batch_id"] = batch.batch_id
            run.finish(cell, runner, result, workdir, batch.submitted, time.monotonic(),
                       batched=True)
        store.mark_collected(batch.batch_id)


def _record(cell: Cell, outcome: Outcome, *, cost: float = 0.0, usage: Usage | None = None,
            seconds: float = 0.0, findings_path: str = "", detail: str = "",
            started: str = "", extra: dict[str, Any] | None = None,
            prompt_sha: str = "") -> Record:
    u = usage or Usage()
    return Record(
        cell=cell.id, target=cell.target, condition=cell.condition, model=cell.model,
        repeat=cell.repeat, outcome=outcome, prompt=cell.prompt, prompt_sha=prompt_sha,
        effort=cell.effort,
        cost_usd=round(cost, 6),
        input_tokens=u.input_tokens, output_tokens=u.output_tokens,
        cache_read_tokens=u.cache_read_tokens, cache_write_tokens=u.cache_write_tokens,
        seconds=round(seconds, 2),
        findings_path=findings_path, detail=detail, started=started or _now(),
        finished=_now(), extra=extra or {},
    )


def remove_tree(path: Path) -> None:
    """``shutil.rmtree`` that also removes read-only files.

    A harness cell's tree is a git repository, and git writes its objects
    read-only; on Windows that makes a plain ``rmtree`` fail, which surfaced as
    a resumed matrix unable to clear the failed attempt it was about to retry.
    """
    def writable_then_retry(func: Callable[..., Any], target: str, _exc: object) -> None:
        os.chmod(target, stat.S_IWRITE)
        func(target)

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=writable_then_retry)
    else:
        shutil.rmtree(path, onerror=writable_then_retry)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")
