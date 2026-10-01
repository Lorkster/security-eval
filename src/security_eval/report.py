"""Turn a matrix's ledger into the numbers the research questions ask for.

Every figure is recomputed from what each cell saved -- its findings, and the
manifest it was scored against -- rather than from the scores written at run
time. A fix to the scorer, or a different reading (`stated_only`, another
tolerance), therefore applies to every run already made, without spending
anything to repeat them.

Two populations are reported, because the proposal commits to both:

* **ok** -- runs that completed normally;
* **completed** -- ok plus runs the harness stopped an agent in. A harness
  stop is the harness's outcome, not the model's (RQ4), so the headline
  comparison is shown with and without them.

Repeats are summarised as median and range, never as a mean alone.
"""

from __future__ import annotations

import csv
import json
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .finding import SecurityFinding
from .ledger import Ledger, Outcome, Record
from .manifest import Target, load_target
from .scanners import label
from .scoring import DEFAULT_TOLERANCE, Score, TriageScore, score, score_triage

GroupKey = tuple[str, str, str, str]      # condition, model, prompt, effort


@dataclass
class CellResult:
    record: Record
    score: Score | None
    recovered: int = 0
    triage: TriageScore | None = None

    @property
    def is_triage(self) -> bool:
        return self.record.extra.get("kind") == "triage"


@dataclass
class Group:
    key: GroupKey
    cells: list[CellResult] = field(default_factory=list)

    def outcomes(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for c in self.cells:
            counts[c.record.outcome.value] += 1
        return dict(counts)

    def scored(self, population: str) -> list[CellResult]:
        allowed = {Outcome.OK} if population == "ok" else {Outcome.OK, Outcome.HARNESS_STOPPED}
        return [c for c in self.cells if c.record.outcome in allowed and c.score is not None]


def spread(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"median": None, "min": None, "max": None, "n": 0}
    return {"median": round(statistics.median(values), 4), "min": round(min(values), 4),
            "max": round(max(values), 4), "n": len(values)}


def _fmt(s: dict[str, float | None]) -> str:
    if not s["n"]:
        return "—"
    return f"{s['median']:.2f} [{s['min']:.2f} to {s['max']:.2f}]"


def load_cells(out_dir: Path, *, tolerance: int = DEFAULT_TOLERANCE,
               stated_only: bool = False) -> list[CellResult]:
    ledger = Ledger(out_dir / "ledger.jsonl")
    latest: dict[str, Record] = {}
    for record in ledger.records():
        latest[record.cell] = record
    targets: dict[str, Target] = {}
    cells = []
    for record in latest.values():
        manifest = record.extra.get("manifest")
        findings_file = out_dir / record.findings_path if record.findings_path else None
        if not manifest or findings_file is None or not findings_file.is_file():
            cells.append(CellResult(record, None))
            continue
        if manifest not in targets:
            targets[manifest] = load_target(manifest)
        findings = [SecurityFinding.from_dict(f)
                    for f in json.loads(findings_file.read_text(encoding="utf-8"))]
        if record.extra.get("open"):
            continue    # adjudicated, not scored: see `security-eval adjudicate`
        if record.extra.get("kind") == "triage":
            target = targets[manifest]
            cells.append(CellResult(record, None, triage=score_triage(
                [f.triage for f in findings], label(findings, target, tolerance))))
            continue
        cells.append(CellResult(
            record,
            score(findings, targets[manifest], tolerance, stated_only=stated_only),
            recovered=sum(1 for f in findings if f.location_source == "recovered"),
        ))
    return cells


def summarise(cells: list[CellResult]) -> dict[str, Any]:
    groups: dict[GroupKey, Group] = {}
    for c in cells:
        if c.is_triage:
            continue
        r = c.record
        key = (r.condition, r.model, r.prompt or "plain", r.effort or "default")
        groups.setdefault(key, Group(key)).cells.append(c)

    rows = []
    for key in sorted(groups):
        g = groups[key]
        n = len(g.cells)
        outcomes = g.outcomes()
        row: dict[str, Any] = {
            "condition": key[0], "model": key[1], "prompt": key[2], "effort": key[3],
            "cells": n, "outcomes": outcomes,
            "refusal_rate": round(outcomes.get("refused", 0) / n, 4) if n else 0.0,
            "harness_stopped_rate": round(outcomes.get("harness_stopped", 0) / n, 4) if n else 0.0,
            "agents_refused": sum(int(c.record.extra.get("agents_refused", 0)) for c in g.cells),
            "cost_usd": round(sum(c.record.cost_usd for c in g.cells), 4),
        }
        for population in ("ok", "completed"):
            done = g.scored(population)
            scores = [c.score for c in done if c.score is not None]
            tp = sum(s.tp_loose for s in scores)
            cost = sum(c.record.cost_usd for c in done)
            row[population] = {
                "recall_loose": spread([s.recall() for s in scores]),
                "recall_strict": spread([s.recall(True) for s in scores]),
                "precision_loose": spread([s.precision() for s in scores]),
                "precision_strict": spread([s.precision(True) for s in scores]),
                "f1_loose": spread([s.f1() for s in scores]),
                "true_positives": tp,
                "cost_per_true_positive": round(cost / tp, 4) if tp else None,
                "decoy_hits": sum(s.decoy_hits for s in scores),
                "duplicates": sum(s.duplicates for s in scores),
                "unanchored": sum(s.unanchored for s in scores),
                "recovered_locations": sum(c.recovered for c in done),
            }
        rows.append(row)

    return {"groups": rows, "by_cwe": _by_cwe(groups), "tokens_per_run": _tokens(cells),
            "triage": _triage(cells), "scanners": _scanners(cells)}


def _triage(cells: list[CellResult]) -> list[dict[str, Any]]:
    """RQ3, per model, prompt and effort: what the model did with the scanner's output.

    The two numbers that answer the company's question: of the findings that
    were *not* real, how many the model dismissed (noise removed), and of those
    that were, how many it kept (real issues not lost). Accuracy alone hides the
    trade between them.
    """
    grouped: dict[tuple[str, str, str, str], list[CellResult]] = defaultdict(list)
    for c in cells:
        if c.is_triage:
            r = c.record
            grouped[(r.model, r.prompt or "triage", r.effort or "default",
                     str(r.extra.get("tool", "")))].append(c)
    rows = []
    for key in sorted(grouped):
        group = grouped[key]
        scored = [c.triage for c in group
                  if c.triage is not None and c.record.outcome is Outcome.OK]
        triaged = sum(t.total for t in scored)
        cost = sum(c.record.cost_usd for c in group)
        rows.append({
            "model": key[0], "prompt": key[1], "effort": key[2], "scanner": key[3],
            "cells": len(group),
            "refusal_rate": round(sum(c.record.outcome is Outcome.REFUSED for c in group)
                                  / len(group), 4),
            "accuracy": spread([t.accuracy for t in scored]),
            "noise_dismissed": spread(_rate(scored, "not_real", "false_positive")),
            "real_kept": spread(_rate(scored, "real", "true_positive")),
            "needs_info": spread([t.needs_info / t.total for t in scored if t.total]),
            "findings_triaged": triaged,
            "cost_usd": round(cost, 4),
            "cost_per_finding": round(cost / triaged, 4) if triaged else None,
        })
    return rows


def _rate(scored: list[TriageScore], label_key: str, verdict: str) -> list[float]:
    """Per cell: the share of findings with this label that drew this verdict."""
    out = []
    for t in scored:
        row = t.confusion.get(label_key, {})
        total = sum(row.values())
        if total:
            out.append(row.get(verdict, 0) / total)
    return out


def _scanners(cells: list[CellResult]) -> list[dict[str, Any]]:
    """Each scan in the run's targets, scored on the same answer key as the models.

    Deterministic, so once per target and tool. Strict (CWE) figures are given
    only where the tool reports CWEs at all; Bandit, for one, does not.
    """
    from .scanners import ScanError, scanner_findings

    rows = []
    seen: set[str] = set()
    for c in cells:
        manifest = c.record.extra.get("manifest")
        if not manifest or manifest in seen:
            continue
        seen.add(manifest)
        target = load_target(manifest)
        for tool in sorted(target.scans):
            try:
                found = scanner_findings(target, tool)
            except ScanError:
                continue
            s = score(found, target)
            gives_cwe = any(f.cwe for f in found)
            rows.append({
                "tool": tool, "target": target.id, "findings": len(found),
                "recall_loose": round(s.recall(), 4), "precision_loose": round(s.precision(), 4),
                "recall_strict": round(s.recall(True), 4) if gives_cwe else None,
                "decoy_hits": s.decoy_hits, "missed": s.missed,
            })
    return rows


def _by_cwe(groups: dict[GroupKey, Group]) -> list[dict[str, Any]]:
    """Recall per CWE per group, over completed cells: which classes of flaw are missed."""
    out = []
    for key in sorted(groups):
        found: dict[str, int] = defaultdict(int)
        total: dict[str, int] = defaultdict(int)
        for c in groups[key].scored("completed"):
            manifest = c.record.extra.get("manifest")
            if not manifest or c.score is None:
                continue
            target = load_target(manifest)
            matched = {m.issue_id for m in c.score.matches}
            for v in target.vulnerabilities:
                cwe = v.cwe or "unknown"
                total[cwe] += 1
                found[cwe] += v.id in matched
        for cwe in sorted(total):
            out.append({"condition": key[0], "model": key[1], "prompt": key[2],
                        "effort": key[3], "cwe": cwe, "found": found[cwe],
                        "total": total[cwe]})
    return out


def _tokens(cells: list[CellResult]) -> dict[str, list[int]]:
    """Median measured tokens per condition: the figures to put in `tokens_per_run`."""
    by: dict[str, list[Record]] = defaultdict(list)
    for c in cells:
        if c.record.outcome in (Outcome.OK, Outcome.HARNESS_STOPPED):
            by[c.record.condition].append(c.record)
    return {
        condition: [int(statistics.median(r.input_tokens + r.cache_read_tokens
                                          + r.cache_write_tokens for r in records)),
                    int(statistics.median(r.output_tokens for r in records))]
        for condition, records in sorted(by.items())
    }


def render_markdown(summary: dict[str, Any], *, title: str, stated_only: bool) -> str:
    lines = [f"# {title}", ""]
    if stated_only:
        lines += ["*Stated locations only: a location recovered from evidence counts as none.*",
                  ""]
    lines += [
        "Median [min to max] over repeats. **ok** = completed normally; **completed** also "
        "includes runs in which the harness stopped an agent.", "",
        "| condition | model | prompt | effort | cells | refused | harness-stopped | "
        "recall (ok) | recall (completed) | strict recall (ok) | precision (ok) | "
        "$ / true positive | cost |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for g in summary["groups"]:
        cpt = g["ok"]["cost_per_true_positive"]
        lines.append(
            f"| {g['condition']} | {g['model']} | {g['prompt']} | {g['effort']} | {g['cells']} | "
            f"{g['refusal_rate']:.0%} | {g['harness_stopped_rate']:.0%} | "
            f"{_fmt(g['ok']['recall_loose'])} | {_fmt(g['completed']['recall_loose'])} | "
            f"{_fmt(g['ok']['recall_strict'])} | {_fmt(g['ok']['precision_loose'])} | "
            f"{'—' if cpt is None else f'${cpt:.2f}'} | ${g['cost_usd']:.2f} |"
        )
    lines += ["", "## Where precision went (completed runs)", "",
              "| condition | model | prompt | effort | decoy hits | duplicates | unanchored | "
              "recovered locations |",
              "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for g in summary["groups"]:
        c = g["completed"]
        lines.append(f"| {g['condition']} | {g['model']} | {g['prompt']} | {g['effort']} | "
                     f"{c['decoy_hits']} | {c['duplicates']} | {c['unanchored']} | "
                     f"{c['recovered_locations']} |")
    if summary["by_cwe"]:
        lines += ["", "## Recall by CWE (completed runs)", "",
                  "| condition | model | prompt | effort | CWE | found / total |",
                  "| --- | --- | --- | --- | --- | --- |"]
        for r in summary["by_cwe"]:
            lines.append(f"| {r['condition']} | {r['model']} | {r['prompt']} | {r['effort']} | "
                         f"{r['cwe']} | {r['found']} / {r['total']} |")
    if summary.get("scanners"):
        lines += ["", "## The scanners, on the same answer key", "",
                  "| tool | target | findings | recall | strict recall | precision | "
                  "decoy hits | missed |",
                  "| --- | --- | --- | --- | --- | --- | --- | --- |"]
        for r in summary["scanners"]:
            strict = "n/a (no CWEs)" if r["recall_strict"] is None else f"{r['recall_strict']:.2f}"
            lines.append(f"| {r['tool']} | {r['target']} | {r['findings']} | "
                         f"{r['recall_loose']:.2f} | {strict} | {r['precision_loose']:.2f} | "
                         f"{r['decoy_hits']} | {', '.join(r['missed']) or 'none'} |")
    if summary.get("triage"):
        lines += ["", "## Triage of scanner output (RQ3)", "",
                  "**Noise dismissed**: share of not-real findings judged false positive. "
                  "**Real kept**: share of real ones judged true positive. "
                  "*needs info* counts as neither.", "",
                  "| model | prompt | effort | scanner | cells | refused | accuracy | "
                  "noise dismissed | real kept | needs info | $ / finding |",
                  "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
        for r in summary["triage"]:
            cpf = r["cost_per_finding"]
            lines.append(
                f"| {r['model']} | {r['prompt']} | {r['effort']} | {r['scanner']} | "
                f"{r['cells']} | {r['refusal_rate']:.0%} | {_fmt(r['accuracy'])} | "
                f"{_fmt(r['noise_dismissed'])} | {_fmt(r['real_kept'])} | "
                f"{_fmt(r['needs_info'])} | {'—' if cpf is None else f'${cpf:.3f}'} |")
    if summary["tokens_per_run"]:
        lines += ["", "## Measured tokens per run (median, input incl. cache / output)", "",
                  "Put these in the matrix's `tokens_per_run` before estimating the next one:",
                  "", "```json",
                  json.dumps({"tokens_per_run": summary["tokens_per_run"]}, indent=2),
                  "```"]
    return "\n".join(lines) + "\n"


def write_cells_csv(cells: list[CellResult], path: Path) -> None:
    """One row per cell, for analysis in whatever the group prefers."""
    fields = ["cell", "target", "condition", "model", "prompt", "effort", "repeat", "outcome",
              "cost_usd", "input_tokens", "output_tokens", "cache_read_tokens",
              "cache_write_tokens", "seconds", "findings", "tp_loose", "tp_strict",
              "false_positives", "decoy_hits", "duplicates", "unanchored", "recall_loose",
              "recall_strict", "precision_loose", "precision_strict", "agents_refused",
              "agents_stopped", "stop_reasons", "prompt_sha"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for c in cells:
            r, s = c.record, c.score
            writer.writerow({
                "cell": r.cell, "target": r.target, "condition": r.condition, "model": r.model,
                "prompt": r.prompt, "effort": r.effort, "repeat": r.repeat,
                "outcome": r.outcome.value, "cost_usd": r.cost_usd,
                "input_tokens": r.input_tokens, "output_tokens": r.output_tokens,
                "cache_read_tokens": r.cache_read_tokens,
                "cache_write_tokens": r.cache_write_tokens, "seconds": r.seconds,
                "findings": s.findings if s else "", "tp_loose": s.tp_loose if s else "",
                "tp_strict": s.tp_strict if s else "",
                "false_positives": s.false_positives if s else "",
                "decoy_hits": s.decoy_hits if s else "", "duplicates": s.duplicates if s else "",
                "unanchored": s.unanchored if s else "",
                "recall_loose": round(s.recall(), 4) if s else "",
                "recall_strict": round(s.recall(True), 4) if s else "",
                "precision_loose": round(s.precision(), 4) if s else "",
                "precision_strict": round(s.precision(True), 4) if s else "",
                "agents_refused": r.extra.get("agents_refused", ""),
                "agents_stopped": r.extra.get("agents_stopped", ""),
                "stop_reasons": " | ".join(r.extra.get("stop_reasons") or []),
                "prompt_sha": r.prompt_sha,
            })
