"""Two runs side by side: did a change help, or is the difference noise?

The question after any change -- a harness fix, a new prompt, another model --
is whether the next run is better. Comparing two reports by eye misses the
part that matters most on real code: whether the two runs found the *same*
things. A local model given identical input twice can report almost entirely
different places, and a "better" second run may be no more than that.

So, per condition, model, prompt and effort: outcome, time and tokens for each
run, and the places reported -- with how many both runs found (places on
overlapping lines of the same file count as one), how many only one did, and
the overlap as a share of all places either found. For triage, how often the
two runs gave the same verdict on the same scanner finding.
"""

from __future__ import annotations

import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any

from .finding import Location, SecurityFinding
from .ledger import Ledger, Record
from .scoring import DEFAULT_TOLERANCE, overlaps

Key = tuple[str, str, str, str]


def _cells(run_dir: Path) -> dict[Key, list[tuple[Record, list[SecurityFinding]]]]:
    latest: dict[str, Record] = {}
    for record in Ledger(run_dir / "ledger.jsonl").records():
        latest[record.cell] = record
    out: dict[Key, list[tuple[Record, list[SecurityFinding]]]] = defaultdict(list)
    for r in latest.values():
        findings: list[SecurityFinding] = []
        file = run_dir / r.findings_path if r.findings_path else None
        if file is not None and file.is_file():
            findings = [SecurityFinding.from_dict(f)
                        for f in json.loads(file.read_text(encoding="utf-8"))]
        out[(r.condition, r.model, r.prompt or "plain", r.effort or "default")].append(
            (r, findings))
    return out


def places(findings: list[SecurityFinding], tolerance: int = DEFAULT_TOLERANCE) -> list[Location]:
    """Distinct places: findings on overlapping lines of one file count once."""
    seen: list[Location] = []
    for f in findings:
        if f.location is not None and not any(overlaps(f.location, s, tolerance) for s in seen):
            seen.append(f.location)
    return seen


def _median(values: list[float]) -> float | None:
    return round(statistics.median(values), 2) if values else None


def _side(cells: list[tuple[Record, list[SecurityFinding]]]) -> dict[str, Any]:
    outcomes: dict[str, int] = defaultdict(int)
    for r, _ in cells:
        outcomes[r.outcome.value] += 1
    return {
        "cells": len(cells), "outcomes": dict(outcomes),
        "seconds": _median([r.seconds for r, _ in cells]),
        "tokens_in": _median([float(r.input_tokens + r.cache_read_tokens
                                    + r.cache_write_tokens) for r, _ in cells]),
        "tokens_out": _median([float(r.output_tokens) for r, _ in cells]),
        "findings": sum(len(f) for _, f in cells),
        "stop_reasons": sorted({s for r, _ in cells for s in r.extra.get("stop_reasons") or []}),
        "harness": sorted({str(r.extra["harness"]) for r, _ in cells if r.extra.get("harness")}),
    }


def compare(run_a: Path, run_b: Path, tolerance: int = DEFAULT_TOLERANCE) -> list[dict[str, Any]]:
    a, b = _cells(run_a), _cells(run_b)
    rows = []
    for key in sorted(set(a) | set(b)):
        left, right = a.get(key, []), b.get(key, [])
        row: dict[str, Any] = {"condition": key[0], "model": key[1], "prompt": key[2],
                               "effort": key[3], "a": _side(left), "b": _side(right)}
        triage = any(f.triage is not None for _, fs in left + right for f in fs)
        if triage:
            row["triage"] = _verdicts(left, right)
        else:
            pa = places([f for _, fs in left for f in fs], tolerance)
            pb = places([f for _, fs in right for f in fs], tolerance)
            shared = sum(1 for p in pa if any(overlaps(p, q, tolerance) for q in pb))
            union = len(pa) + len(pb) - shared
            row["places"] = {"a": len(pa), "b": len(pb), "both": shared,
                             "only_a": len(pa) - shared, "only_b": len(pb) - shared,
                             "overlap": round(shared / union, 4) if union else None}
        rows.append(row)
    return rows


def _verdicts(left: list[tuple[Record, list[SecurityFinding]]],
              right: list[tuple[Record, list[SecurityFinding]]]) -> dict[str, Any]:
    def by_finding(cells: list[tuple[Record, list[SecurityFinding]]]) -> dict[str, str]:
        # Rule ids repeat (two B105s in one file), so the line is part of the key.
        return {(f"{f.id}@{f.location.normalised_path}:{f.location.start_line}"
                 if f.location else f.id): (f.triage.value if f.triage else "")
                for _, fs in cells for f in fs}

    va, vb = by_finding(left), by_finding(right)
    common = [k for k in va if k in vb]
    same = sum(va[k] == vb[k] for k in common)
    return {"judged_in_both": len(common), "same_verdict": same,
            "agreement": round(same / len(common), 4) if common else None}


def render(rows: list[dict[str, Any]], run_a: str, run_b: str) -> str:
    lines = [f"# {run_a} vs {run_b}", "",
             "Per condition: **a** is the first run, **b** the second. Places on overlapping "
             "lines of one file count once. *Overlap* is the places both runs found, as a "
             "share of all places either found: low overlap on unchanged input means the "
             "difference between runs is mostly noise.", "",
             "| condition | model | prompt | effort | outcomes a / b | seconds a / b | "
             "tokens in a / b | tokens out a / b | findings a / b | places a / b | both | "
             "overlap | triage agreement |",
             "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for r in rows:
        a, b = r["a"], r["b"]

        def outcomes(side: dict[str, Any]) -> str:
            return ", ".join(f"{k} {v}" for k, v in sorted(side["outcomes"].items())) or "—"

        p = r.get("places")
        t = r.get("triage")
        lines.append(
            f"| {r['condition']} | {r['model']} | {r['prompt']} | {r['effort']} | "
            f"{outcomes(a)} / {outcomes(b)} | {_n(a['seconds'])} / {_n(b['seconds'])} | "
            f"{_n(a['tokens_in'])} / {_n(b['tokens_in'])} | "
            f"{_n(a['tokens_out'])} / {_n(b['tokens_out'])} | {a['findings']} / {b['findings']} | "
            + (f"{p['a']} / {p['b']} | {p['both']} | {_pct(p['overlap'])} | — |" if p else
               f"— | — | — | {t['same_verdict']} of {t['judged_in_both']} |" if t else
               "— | — | — | — |"))
    va = sorted({v for r in rows for v in r["a"]["harness"]})
    vb = sorted({v for r in rows for v in r["b"]["harness"]})
    if va or vb:
        lines += ["", f"Harness: a {', '.join(va) or 'not recorded'}; "
                      f"b {', '.join(vb) or 'not recorded'}."]
    stops = [(side, r["condition"], s) for r in rows for side in ("a", "b")
             for s in r[side]["stop_reasons"]]
    if stops:
        lines += ["", "Why the harness stopped agents:", ""]
        lines += [f"- {side}, {condition}: {reason}" for side, condition, reason in stops]
    return "\n".join(lines) + "\n"


def _n(value: float | None) -> str:
    return "—" if value is None else f"{value:,.0f}" if value >= 100 else f"{value:g}"


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{value:.0%}"
