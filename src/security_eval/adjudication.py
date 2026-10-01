"""Blind human adjudication: scoring findings on real code, where no answer key exists.

On real code nobody knows the full list of flaws, so recall cannot be measured
against a key, and a finding outside the key is not automatically wrong. This
is the standard way through (pooling, as information-retrieval evaluations do
it):

1. **Pool.** Every candidate finding from every condition, model and scanner,
   with findings that point at the same place merged into one candidate.
   Included: everything on ``open`` targets, and on time-split targets
   everything that is *not* the known flaw -- real code can hold real bugs
   nobody has filed yet, and calling them false positives would be wrong.
2. **Judge, blind.** Two reviewers judge each candidate -- ``tp``, ``fp`` or
   ``unsure`` -- without being told who reported it. The order is shuffled. The
   key linking candidates to their sources is a separate file. ``review.html``
   (`review_page`) is where they read and judge; each downloads a sheet with
   their own column filled, and ``import`` merges them.
3. **Score.** Agreement between reviewers (Cohen's kappa); disagreements listed
   for resolution in the ``final`` column. Then per condition and model:
   precision, verified findings no scanner reported (*beyond the scanners*),
   recall relative to every verified finding in the pool, coverage of what an
   attacker proxy found, and triage accuracy against the verdicts.

A real vulnerability in someone else's project, once verified, goes through
that project's disclosure process before it appears in any write-up.
"""

from __future__ import annotations

import csv
import json
import random
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .finding import SecurityFinding
from .ledger import Ledger, Outcome, Record
from .manifest import Target, load_target
from .scanners import ScanError, scanner_findings
from .scoring import DEFAULT_TOLERANCE, matched_issue, overlaps, score_triage

VERDICTS = ("tp", "fp", "unsure")
#: The sheet is for the record and for `import`; reading a candidate happens on
#: the review page, so the sheet carries no code or report text.
SHEET_COLUMNS = ["candidate", "target", "location", "cwe_suggested", "reviewer_a",
                 "reviewer_b", "final", "notes"]
VERDICT_COLUMNS = ("reviewer_a", "reviewer_b", "final")


@dataclass
class Source:
    """One report of a candidate: which run, cell or scanner said it."""

    origin: str              # "model" | "scanner"
    group: str               # "baseline | anthropic:m | plain | default", or "scanner:bandit"
    cell: str = ""
    model: str = ""
    finding: int = -1        # index in the cell's findings, or in the scan's findings
    run: str = ""


@dataclass
class Candidate:
    target: str
    path: str
    start: int
    end: int
    findings: list[SecurityFinding] = field(default_factory=list)
    sources: list[Source] = field(default_factory=list)


def _group(record: Record) -> str:
    return " | ".join([record.condition, record.model, record.prompt or "plain",
                       record.effort or "default"])


def pool(run_dirs: list[Path], tolerance: int = DEFAULT_TOLERANCE) -> list[Candidate]:
    """Every candidate finding across ``run_dirs`` and the targets' scans, merged by place."""
    reports: list[tuple[Target, SecurityFinding, Source]] = []
    targets: dict[str, Target] = {}
    for run_dir in run_dirs:
        latest: dict[str, Record] = {}
        for record in Ledger(run_dir / "ledger.jsonl").records():
            latest[record.cell] = record
        for record in latest.values():
            manifest = record.extra.get("manifest")
            if not manifest:
                continue
            # Registered before any filtering: a target reached only by triage
            # runs still has scanner findings to pool, and its triage verdicts
            # are scored against what the reviewers decide about them.
            target = targets.setdefault(manifest, load_target(manifest))
            if (not _adjudicated(target) or record.extra.get("kind") == "triage"
                    or record.outcome not in (Outcome.OK, Outcome.HARNESS_STOPPED)
                    or not record.findings_path):
                continue
            findings = json.loads((run_dir / record.findings_path).read_text(encoding="utf-8"))
            for i, raw in enumerate(findings):
                f = SecurityFinding.from_dict(raw)
                if _needs_judging(f, target, tolerance):
                    reports.append((target, f, Source("model", _group(record), record.cell,
                                                      record.model, i, str(run_dir))))
    for target in targets.values():
        if not _adjudicated(target):
            continue
        for tool in sorted(target.scans):
            try:
                found = scanner_findings(target, tool)
            except ScanError:
                continue
            for i, f in enumerate(found):
                if _needs_judging(f, target, tolerance):
                    reports.append((target, f, Source("scanner", f"scanner:{tool}", finding=i)))
    return _merge(reports, tolerance)


def _adjudicated(target: Target) -> bool:
    """Real code: an open target, or a time-split one (its key covers one flaw, not all)."""
    return target.open or bool(target.source.get("published"))


def _needs_judging(f: SecurityFinding, target: Target, tolerance: int) -> bool:
    if target.open or f.location is None:
        return True
    return matched_issue(f.location, target, tolerance) is None


def _merge(reports: list[tuple[Target, SecurityFinding, Source]],
           tolerance: int) -> list[Candidate]:
    candidates: list[Candidate] = []
    for target, f, source in reports:
        home = None
        if f.location is not None:
            for c in candidates:
                if c.target == target.id and c.path and overlaps(
                        f.location, _as_location(c), tolerance):
                    home = c
                    break
        if home is None:
            loc = f.location
            home = Candidate(target.id, loc.normalised_path if loc else "",
                             loc.start_line if loc else 0, loc.end_line if loc else 0)
            candidates.append(home)
        elif f.location is not None:
            home.start = min(home.start, f.location.start_line)
            home.end = max(home.end, f.location.end_line)
        home.findings.append(f)
        home.sources.append(source)
    return candidates


def _as_location(c: Candidate) -> Any:
    from .finding import Location

    return Location(c.path, max(1, c.start), max(1, c.start, c.end))


def export(run_dirs: list[Path], sheet: Path, key: Path, *, seed: int = 0,
           tolerance: int = DEFAULT_TOLERANCE) -> int:
    """Write the blind sheet, its review page and the separate key; return the candidates.

    The page is ``review.html`` beside the sheet.
    """
    from . import review_page

    candidates = pool(run_dirs, tolerance)
    random.Random(seed).shuffle(candidates)   # noqa: S311 - order, not secrecy
    roots = _roots(run_dirs)
    sheet.parent.mkdir(parents=True, exist_ok=True)
    key_data: dict[str, Any] = {"created": datetime.now(UTC).isoformat(timespec="seconds"),
                                "seed": seed, "runs": [str(r) for r in run_dirs],
                                "candidates": {}}
    items: list[dict[str, Any]] = []
    with sheet.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=SHEET_COLUMNS)
        writer.writeheader()
        for n, c in enumerate(candidates, 1):
            cid = f"C{n:04d}"
            location = f"{c.path}:{c.start}-{c.end}" if c.path else "(no location given)"
            cwe = ", ".join(sorted({f.cwe for f in c.findings if f.cwe}))
            writer.writerow({"candidate": cid, "target": c.target, "location": location,
                             "cwe_suggested": cwe, "reviewer_a": "", "reviewer_b": "",
                             "final": "", "notes": ""})
            key_data["candidates"][cid] = {
                "target": c.target, "path": c.path, "start": c.start, "end": c.end,
                "sources": [s.__dict__ for s in c.sources],
            }
            first, lines = _excerpt(roots.get(c.target), c)
            items.append({"id": cid, "target": c.target, "location": location, "cwe": cwe,
                          "start": c.start, "end": c.end, "first": first, "lines": lines,
                          "reports": _reports(c.findings)})
    key.write_text(json.dumps(key_data, indent=2), encoding="utf-8")
    (sheet.parent / "review.html").write_text(review_page.render(
        items, title=f"Review: {len(items)} candidate(s)",
        sheet_id=f"{key_data['created']}:{seed}", columns=SHEET_COLUMNS,
        base_name=sheet.stem), encoding="utf-8")
    return len(candidates)


def _reports(findings: list[SecurityFinding]) -> list[dict[str, str]]:
    """What was said about a candidate, once per distinct report, with no source on it."""
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for f in findings:
        title = _strip_rule(f)
        detail = f.detail.strip() if f.detail.strip() != title else ""
        if (title, detail) in seen:
            continue
        seen.add((title, detail))
        out.append({"title": title, "detail": detail[:1500],
                    "evidence": " | ".join(e.strip() for e in f.evidence[:3])[:1500],
                    "recommendation": f.recommendation.strip()[:1000]})
    return out


def _roots(run_dirs: list[Path]) -> dict[str, Path]:
    roots: dict[str, Path] = {}
    for run_dir in run_dirs:
        for record in Ledger(run_dir / "ledger.jsonl").records():
            manifest = record.extra.get("manifest")
            if manifest and record.target not in roots:
                roots[record.target] = load_target(manifest).root
    return roots


def _strip_rule(f: SecurityFinding) -> str:
    """The report's words without a scanner rule id, so the sheet does not name its source."""
    text = (f.title or f.detail).strip()
    return text.split(":", 1)[1].strip() if text[:1].isupper() and text[1:5].isdigit() else text


def _excerpt(root: Path | None, c: Candidate, context: int = 4,
             limit: int = 80) -> tuple[int, list[str]]:
    """The flagged lines and a few around them: the first line's number, and the lines."""
    if root is None or not c.path:
        return 0, []
    file = root / c.path
    if not file.is_file():
        return 0, []
    lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
    first, last = max(1, c.start - context), min(len(lines), c.end + context)
    return first, lines[first - 1:min(last, first + limit - 1)]


# -- import --------------------------------------------------------------------------


def _verdict(raw: str) -> str | None:
    text = raw.strip().lower()
    if not text:
        return None
    if text in ("tp", "true", "true positive", "real", "yes", "y"):
        return "tp"
    if text in ("fp", "false", "false positive", "not real", "no", "n"):
        return "fp"
    if text in ("unsure", "?", "unknown", "needs info"):
        return "unsure"
    raise ValueError(f"unrecognised verdict {raw!r}: use tp, fp or unsure")


def cohens_kappa(pairs: list[tuple[str, str]]) -> float | None:
    """Agreement beyond chance between two reviewers; ``None`` with nothing to compare."""
    if not pairs:
        return None
    n = len(pairs)
    observed = sum(a == b for a, b in pairs) / n
    expected = sum((sum(a == k for a, _ in pairs) / n) * (sum(b == k for _, b in pairs) / n)
                   for k in VERDICTS)
    return 1.0 if expected == 1 else round((observed - expected) / (1 - expected), 4)


def merge_sheets(sheets: list[Path]) -> dict[str, dict[str, str]]:
    """The sheets' verdicts by candidate, one sheet per reviewer or all in one.

    A verdict column filled in two sheets with different answers is an error,
    not a silent choice between them. Notes are kept from every sheet.
    """
    merged: dict[str, dict[str, str]] = {}
    for sheet in sheets:
        with sheet.open(encoding="utf-8-sig") as fh:
            for line in csv.DictReader(fh):
                cid = (line.get("candidate") or "").strip()
                if not cid:
                    continue
                row = merged.setdefault(cid, {c: "" for c in (*VERDICT_COLUMNS, "notes")})
                for column in VERDICT_COLUMNS:
                    value = (line.get(column) or "").strip()
                    if not value:
                        continue
                    if row[column] and _verdict(row[column]) != _verdict(value):
                        raise ValueError(f"{cid}: {column} is {row[column]!r} in one sheet and "
                                         f"{value!r} in {sheet}")
                    row[column] = value
                note = (line.get("notes") or "").strip()
                if note and note not in row["notes"]:
                    row["notes"] = f"{row['notes']} | {note}" if row["notes"] else note
    return merged


def score_sheet(sheet: Path | list[Path], key: Path, *,
                attacker_proxies: list[str] | None = None) -> dict[str, Any]:
    key_data = json.loads(key.read_text(encoding="utf-8"))
    finals: dict[str, str] = {}
    pairs: list[tuple[str, str]] = []
    disputed: list[str] = []
    pending: list[str] = []
    rows = merge_sheets(sheet if isinstance(sheet, list) else [sheet])
    for cid in key_data["candidates"]:
        line = rows.get(cid, {})
        a, b = _verdict(line.get("reviewer_a", "")), _verdict(line.get("reviewer_b", ""))
        final = _verdict(line.get("final", ""))
        if a and b:
            pairs.append((a, b))
        if final:
            finals[cid] = final
        elif a and b and a == b:
            finals[cid] = a
        elif a and b:
            disputed.append(cid)
        else:
            pending.append(cid)

    candidates: dict[str, dict[str, Any]] = key_data["candidates"]
    reporters: dict[str, set[str]] = defaultdict(set)      # group -> candidate ids
    by_cell: dict[tuple[str, str], set[str]] = defaultdict(set)
    proxies = set(attacker_proxies or [])
    proxy_found: set[str] = set()
    scanner_found: set[str] = set()
    targets_of: dict[str, set[str]] = defaultdict(set)
    for cid, info in candidates.items():
        for s in info["sources"]:
            reporters[s["group"]].add(cid)
            targets_of[s["group"]].add(info["target"])
            if s["origin"] == "scanner":
                scanner_found.add(cid)
            else:
                by_cell[(s["group"], s["cell"])].add(cid)
                if s["model"] in proxies:
                    proxy_found.add(cid)
    verified = {cid for cid, v in finals.items() if v == "tp"}
    rejected = {cid for cid, v in finals.items() if v == "fp"}
    proxy_verified = proxy_found & verified

    groups = []
    for group in sorted(reporters):
        reported = reporters[group]
        pool_tp = {c for c in verified if candidates[c]["target"] in targets_of[group]}
        tp, fp = reported & verified, reported & rejected
        cells = [ids for (g, _cell), ids in by_cell.items() if g == group]
        row: dict[str, Any] = {
            "group": group, "candidates_reported": len(reported),
            "verified": len(tp), "rejected": len(fp),
            "precision": round(len(tp) / (len(tp) + len(fp)), 4) if tp or fp else None,
            "beyond_the_scanners": len(tp - scanner_found) if not group.startswith("scanner:")
            else None,
            "relative_recall": round(len(tp) / len(pool_tp), 4) if pool_tp else None,
            "relative_recall_per_run": (
                round(statistics.median(len(ids & pool_tp) / len(pool_tp) for ids in cells), 4)
                if cells and pool_tp else None),
        }
        model = group.split(" | ")[1] if " | " in group else ""
        if proxy_verified and model not in proxies and not group.startswith("scanner:"):
            row["attacker_proxy_coverage"] = round(len(tp & proxy_verified)
                                                   / len(proxy_verified), 4)
        groups.append(row)

    return {
        "candidates": len(candidates), "verified": len(verified), "rejected": len(rejected),
        "unsure": sum(v == "unsure" for v in finals.values()),
        "kappa": cohens_kappa(pairs), "pairs_compared": len(pairs),
        "disputed": disputed, "pending": pending,
        "attacker_proxies": sorted(proxies), "attacker_proxy_verified": len(proxy_verified),
        "groups": groups,
        "triage": _triage_on_open_targets(key_data, finals),
    }


def _triage_on_open_targets(key_data: dict[str, Any],
                            finals: dict[str, str]) -> list[dict[str, Any]]:
    """Triage verdicts on real code, scored against what the reviewers decided."""
    label_of: dict[tuple[str, str, int], bool] = {}
    for cid, info in key_data["candidates"].items():
        verdict = finals.get(cid)
        if verdict not in ("tp", "fp"):
            continue
        for s in info["sources"]:
            if s["origin"] == "scanner":
                label_of[(info["target"], s["group"].removeprefix("scanner:"), s["finding"])] = (
                    verdict == "tp")
    rows = []
    for run in key_data.get("runs", []):
        latest: dict[str, Record] = {}
        for record in Ledger(Path(run) / "ledger.jsonl").records():
            latest[record.cell] = record
        for record in latest.values():
            if record.extra.get("kind") != "triage" or not record.extra.get("open"):
                continue
            if record.outcome is not Outcome.OK or not record.findings_path:
                continue
            tool = str(record.extra.get("tool", ""))
            findings = json.loads((Path(run) / record.findings_path).read_text(encoding="utf-8"))
            preds, labels = [], []
            for i, raw in enumerate(findings):
                key = (record.target, tool, i)
                if key in label_of:
                    preds.append(SecurityFinding.from_dict(raw).triage)
                    labels.append(label_of[key])
            if labels:
                t = score_triage(preds, labels)
                rows.append({"cell": record.cell, "model": record.model, "judged": t.total,
                             "accuracy": round(t.accuracy, 4), "confusion": t.confusion})
    return rows


def render(result: dict[str, Any]) -> str:
    kappa = result["kappa"]
    lines = [
        "# Adjudication", "",
        f"{result['candidates']} candidates: {result['verified']} verified, "
        f"{result['rejected']} rejected, {result['unsure']} unsure. "
        f"Reviewer agreement (Cohen's kappa) over {result['pairs_compared']} pairs: "
        f"{'—' if kappa is None else f'{kappa:.2f}'}.", "",
    ]
    if result["disputed"] or result["pending"]:
        lines += [f"**Not final**: {len(result['disputed'])} disputed (fill `final`), "
                  f"{len(result['pending'])} not yet judged by both reviewers. The figures "
                  "below change when they are resolved.", ""]
    lines += ["| condition / model | reported | verified | precision | beyond the scanners | "
              "relative recall | per run (median) | attacker-proxy coverage |",
              "| --- | --- | --- | --- | --- | --- | --- | --- |"]

    def pct(v: float | None) -> str:
        return "—" if v is None else f"{v:.2f}"

    for g in result["groups"]:
        beyond = "—" if g["beyond_the_scanners"] is None else str(g["beyond_the_scanners"])
        lines.append(f"| {g['group']} | {g['candidates_reported']} | {g['verified']} | "
                     f"{pct(g['precision'])} | {beyond} | {pct(g['relative_recall'])} | "
                     f"{pct(g['relative_recall_per_run'])} | "
                     f"{pct(g.get('attacker_proxy_coverage'))} |")
    lines += ["", "*Relative recall* is against every finding the reviewers verified, from any "
              "source: real code has no complete list of its flaws, so this is a lower bound "
              "on how much was missed, not true recall."]
    if result["triage"]:
        lines += ["", "## Triage on real code, against the reviewers' verdicts", "",
                  "| cell | judged | accuracy |", "| --- | --- | --- |"]
        for t in result["triage"]:
            lines.append(f"| {t['cell']} | {t['judged']} | {t['accuracy']:.2f} |")
    return "\n".join(lines) + "\n"
