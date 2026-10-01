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
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .budget import BudgetExceeded, BudgetGuard, PriceTable, Usage
from .ledger import Ledger, Outcome, Record
from .manifest import Target, load_target
from .runners.base import DEFAULT_PROMPTS, Runner, RunResult, load_prompts, prompt_hash


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
        )


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
        for prompt in matrix.prompts
        for effort in matrix.efforts
        for model in matrix.models
        for repeat in range(1, matrix.repeats + 1)
    ]
    # Priority order: repeat, model, prompt, target, condition -- so the first
    # repeat of the first model and prompt covers every target and condition
    # before anything else starts.
    model_rank = {m: i for i, m in enumerate(matrix.models)}
    prompt_rank = {p: i for i, p in enumerate(matrix.prompts)}
    effort_rank = {e: i for i, e in enumerate(matrix.efforts)}
    target_rank = {targets[m].id: i for i, m in enumerate(matrix.targets)}
    cond_rank = {c: i for i, c in enumerate(matrix.conditions)}
    return sorted(out, key=lambda c: (c.repeat, model_rank[c.model], prompt_rank[c.prompt],
                                      effort_rank[c.effort], target_rank[c.target],
                                      cond_rank[c.condition]))


def projected_cost(cell: Cell, matrix: Matrix, prices: PriceTable) -> float:
    tokens = matrix.tokens_per_run.get(cell.condition)
    if tokens is None:
        raise KeyError(f"tokens_per_run has no figure for condition {cell.condition!r}")
    return prices.cost(cell.model, Usage(*tokens))


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
) -> Ledger:
    """Run every cell not already finished, under the budget guard."""
    from .scoring import score

    ledger = Ledger(out_dir / "ledger.jsonl")
    done = ledger.finished()
    guard = BudgetGuard(matrix.budget_usd, ledger.spent()) if matrix.budget_usd > 0 else None
    targets = {m: load_target(m) for m in matrix.targets}
    available = load_prompts(matrix.prompts_file)
    unknown = [p for p in matrix.prompts if p not in available]
    if unknown:
        raise KeyError(f"prompt(s) {unknown} are not in {matrix.prompts_file}")

    for cell in cells(matrix, targets):
        if cell.id in done:
            continue
        runner = runners.get(cell.condition)
        if runner is None:
            raise KeyError(f"no runner for condition {cell.condition!r}")
        projected = projected_cost(cell, matrix, prices)
        if guard is not None:
            try:
                guard.check(projected, cell.id)
            except BudgetExceeded as exc:
                ledger.append(_record(cell, Outcome.SKIPPED_BUDGET, detail=str(exc),
                                      prompt_sha=prompt_hash(available[cell.prompt])))
                progress(f"skip  {cell.id}: {exc}")
                continue
        if dry_run:
            progress(f"would run {cell.id} (~${projected:.2f})")
            continue

        workdir = out_dir / "cells" / cell.id
        if workdir.exists():
            remove_tree(workdir)   # a previous attempt at a non-final cell
        workdir.mkdir(parents=True)
        started = _now()
        t0 = time.monotonic()
        try:
            result = runner.run(targets[cell.manifest], cell.model, workdir,
                                available[cell.prompt], cell.effort)
        except Exception as exc:  # noqa: BLE001 - one broken cell must not end the matrix
            # Recorded as an error, so a resumed matrix retries it. Whatever it
            # spent before failing is unknown and so unrecorded -- the one gap
            # in the ledger's accounting, and why runners return errors rather
            # than raise them.
            detail = f"runner raised {type(exc).__name__}: {exc}"
            result = RunResult(Outcome.ERROR, detail=detail[:500])

        # The fake runner reports plausible token counts so projections can be
        # exercised, but no money moved, and the ledger must not say it did.
        cost = 0.0 if runner.condition == "fake" else prices.cost(cell.model, result.usage)
        if guard is not None:
            guard.record(cost)
        findings_path = workdir / "findings.json"
        findings_path.write_text(
            json.dumps([f.to_dict() for f in result.findings], indent=2), encoding="utf-8"
        )
        scored = score(result.findings, targets[cell.manifest])
        (workdir / "score.json").write_text(json.dumps(scored.to_dict(), indent=2),
                                            encoding="utf-8")
        ledger.append(_record(
            cell, result.outcome, prompt_sha=prompt_hash(available[cell.prompt]),
            cost=cost, usage=result.usage,
            seconds=result.seconds or (time.monotonic() - t0),
            findings_path=findings_path.relative_to(out_dir).as_posix(),
            detail=result.detail, started=started,
            extra={**result.extra, "manifest": str(cell.manifest),
                   "recall_loose": round(scored.recall(), 4),
                   "precision_loose": round(scored.precision(), 4)},
        ))
        progress(f"{result.outcome.value:<15} {cell.id}  ${cost:.3f}  "
                 f"recall {scored.recall():.2f}  precision {scored.precision():.2f}")
    return ledger


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
