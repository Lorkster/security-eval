"""security-eval command line."""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from pathlib import Path

from .budget import DEFAULT_PRICES, PriceTable
from .finding import SecurityFinding
from .ledger import Ledger, Outcome
from .manifest import ManifestError, load_target
from .matrix import Matrix, estimate, run_matrix
from .preflight import render as render_checks
from .preflight import run_checks
from .report import load_cells, render_markdown, summarise, write_cells_csv
from .runners.base import Runner
from .runners.fake import FakeRunner, FakeTriageRunner
from .sarif import to_sarif
from .scanners import ScanError, run_scan, scanner_findings
from .scoring import score


def _runners(fake: bool, scanner: str = "bandit") -> dict[str, Runner]:
    if fake:
        # Every condition answered by a fake runner: the whole pipeline, for $0.
        return {"baseline": FakeRunner(), "harness": FakeRunner(recall=0.8),
                "triage": FakeTriageRunner(scanner), "fake": FakeRunner()}
    from .runners.baseline import BaselineRunner
    from .runners.harness import HarnessRunner
    from .runners.triage import TriageRunner

    return {"baseline": BaselineRunner(), "harness": HarnessRunner(),
            "triage": TriageRunner(scanner), "fake": FakeRunner()}


def cmd_validate(args: argparse.Namespace) -> int:
    status = 0
    for manifest in args.manifests:
        try:
            target = load_target(manifest)
        except ManifestError as exc:
            print(f"FAIL {exc}")
            status = 1
            continue
        print(f"ok   {target.id}: {len(target.vulnerabilities)} vulnerabilities, "
              f"{len(target.decoys)} decoys, public={target.public}")
    return status


def cmd_estimate(args: argparse.Namespace) -> int:
    result = estimate(Matrix.load(args.matrix), PriceTable.load(args.prices))
    print(json.dumps(result, indent=2))
    return 0 if result["fits"] else 1


def _preflight(matrix: Matrix, args: argparse.Namespace) -> bool:
    """Run the checks; print them; say whether the matrix may start."""
    if getattr(args, "skip_check", False):
        print("preflight skipped (--skip-check)")
        return True
    checks = run_checks(matrix, PriceTable.load(args.prices), fake=args.fake)
    print(render_checks(checks))
    failed = [c for c in checks if c.level == "fail"]
    if failed:
        print(f"\n{len(failed)} check(s) failed; nothing was run. Fix them, or pass "
              "--skip-check if you are sure.")
    return not failed


def cmd_check(args: argparse.Namespace) -> int:
    ok = _preflight(Matrix.load(args.matrix), args)
    return 0 if ok else 1


def cmd_run(args: argparse.Namespace) -> int:
    matrix = Matrix.load(args.matrix)
    if not _preflight(matrix, args):
        return 1
    out = Path(args.out or Path("runs") / matrix.name)
    if args.batch:
        matrix.batch = True
    ledger = run_matrix(matrix, _runners(args.fake, matrix.scanner), out,
                        PriceTable.load(args.prices), dry_run=args.dry_run,
                        wait=args.wait, poll_seconds=args.poll)
    _summary(ledger)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Run a scanner over a benchmark and record its SARIF in the manifest."""
    manifest = Path(args.manifest)
    target = load_target(manifest)
    out = manifest.parent / "scans" / f"{args.tool}.sarif"
    command = args.command.split() if args.command else None
    try:
        run_scan(target, args.tool, out, command)
    except ScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data.setdefault("scans", {})[args.tool] = out.relative_to(manifest.parent).as_posix()
    manifest.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    found = len(scanner_findings(load_target(manifest), args.tool))
    print(f"{args.tool}: {found} finding(s) -> {out}; recorded under \"scans\" in {manifest}")
    return 0


def cmd_adjudicate_export(args: argparse.Namespace) -> int:
    from .adjudication import export

    sheet, key = Path(args.sheet), Path(args.key)
    n = export([Path(r) for r in args.run_dirs], sheet, key, seed=args.seed)
    print(f"{n} candidate(s) -> {sheet} (blind: no source on it)")
    print(f"key -> {key}: keep it away from the reviewers until both have finished")
    return 0


def cmd_adjudicate_import(args: argparse.Namespace) -> int:
    from .adjudication import render, score_sheet

    proxies = list(args.proxy)
    if args.matrix:
        proxies += Matrix.load(args.matrix).attacker_proxies
    result = score_sheet(Path(args.sheet), Path(args.key), attacker_proxies=proxies)
    markdown = render(result)
    out = Path(args.sheet).with_suffix(".md")
    out.write_text(markdown, encoding="utf-8")
    out.with_suffix(".json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(markdown)
    print(f"written: {out}, {out.with_suffix('.json')}")
    return 0 if not (result["disputed"] or result["pending"]) else 3


def cmd_import_fix(args: argparse.Namespace) -> int:
    from .timesplit import TimeSplitError, import_fix

    try:
        manifest = import_fix(Path(args.repo), args.vulnerable, args.fixed, Path(args.dest),
                              published=args.published, cwes=list(args.cwe),
                              advisory=args.advisory, subdir=args.subdir, target_id=args.id)
    except TimeSplitError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    target = load_target(manifest)
    print(f"{target.id}: vulnerable version exported to {target.root} (no history); "
          f"{len(target.vulnerabilities[0].locations)} location(s) from the fix diff")
    print("next: fill the training cutoffs in configs/models.json, then "
          f"security-eval scan bandit {manifest}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    out_dir = Path(args.run_dir)
    if not (out_dir / "ledger.jsonl").is_file():
        print(f"no ledger in {out_dir}", file=sys.stderr)
        return 2
    cells = load_cells(out_dir, tolerance=args.tolerance, stated_only=args.stated_only)
    summary = summarise(cells)
    suffix = "-stated" if args.stated_only else ""
    markdown = render_markdown(summary, title=f"Results: {out_dir.name}",
                               stated_only=args.stated_only)
    (out_dir / f"report{suffix}.md").write_text(markdown, encoding="utf-8")
    (out_dir / f"report{suffix}.json").write_text(json.dumps(summary, indent=2),
                                                  encoding="utf-8")
    write_cells_csv(cells, out_dir / f"cells{suffix}.csv")
    print(markdown)
    print(f"written: report{suffix}.md, report{suffix}.json, cells{suffix}.csv in {out_dir}")
    return 0


def cmd_gate(args: argparse.Namespace) -> int:
    """Stage 1: a few baseline calls per candidate on the toy target."""
    matrix = Matrix(
        name="viability-gate",
        targets=[Path(args.target).resolve()],
        conditions=["baseline"],
        models=list(args.models),
        repeats=args.repeats,
        budget_usd=args.budget_usd,
        tokens_per_run={"baseline": (60_000, 8_000)},
    )
    if not _preflight(matrix, args):
        return 1
    out = Path(args.out or Path("runs") / "viability-gate")
    ledger = run_matrix(matrix, _runners(args.fake), out, PriceTable.load(args.prices),
                        dry_run=args.dry_run)
    _summary(ledger)
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    target = load_target(args.manifest)
    raw = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    findings = [SecurityFinding.from_dict(f) for f in raw]
    print(json.dumps(score(findings, target, args.tolerance).to_dict(), indent=2))
    return 0


def cmd_sarif(args: argparse.Namespace) -> int:
    raw = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    doc = to_sarif([SecurityFinding.from_dict(f) for f in raw])
    Path(args.output).write_text(json.dumps(doc, indent=2), encoding="utf-8")
    print(f"wrote {args.output}")
    return 0


def _summary(ledger: Ledger) -> None:
    latest = {r.cell: r for r in ledger.records()}
    if not latest:
        print("\nnothing recorded (a dry run records nothing)")
        return
    counts: dict[str, int] = {}
    for r in latest.values():
        counts[r.outcome.value] = counts.get(r.outcome.value, 0) + 1
    print(f"\n{len(latest)} cell(s): " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    print(f"spent ${ledger.spent():.2f} (every attempt, including retried ones)")
    if counts.get(Outcome.REFUSED.value):
        print("some cells were REFUSED: see docs/models-and-budget.md, stage 1")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="security-eval")
    parser.add_argument("--prices", default=str(DEFAULT_PRICES), help="price table JSON")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate", help="check benchmark manifests against their code")
    p.add_argument("manifests", nargs="+")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("estimate", help="project a matrix's cost before spending anything")
    p.add_argument("matrix")
    p.set_defaults(func=cmd_estimate)

    for name, func, text in (("run", cmd_run, "run a matrix, resumably, under its budget"),
                             ("gate", cmd_gate, "stage 1: viability gate for candidate models")):
        p = sub.add_parser(name, help=text)
        if name == "run":
            p.add_argument("matrix")
        else:
            p.add_argument("models", nargs="+", help="routes, e.g. anthropic:claude-sonnet-5-5")
            p.add_argument("--target", default="benchmarks/toy-webapp/manifest.json")
            p.add_argument("--repeats", type=int, default=3)
            p.add_argument("--budget-usd", type=float, default=5.0)
        p.add_argument("--out", help="output directory (default: runs/<name>)")
        p.add_argument("--fake", action="store_true",
                       help="answer every condition with the zero-cost fake runner")
        p.add_argument("--dry-run", action="store_true", help="say what would run")
        p.add_argument("--skip-check", action="store_true",
                       help="start without the preflight checks")
        if name == "run":
            p.add_argument("--batch", action="store_true",
                           help="batch eligible cells (models on the anthropic route) at "
                                "half price; same as \"batch\": true in the matrix")
            p.add_argument("--wait", action="store_true",
                           help="wait for submitted batches and collect them now")
            p.add_argument("--poll", type=float, default=60.0, metavar="SECONDS",
                           help="how often --wait checks a batch (default: 60)")
        p.set_defaults(func=func)

    p = sub.add_parser("scan", help="run a scanner over a benchmark and record its SARIF")
    p.add_argument("tool", help="bandit, semgrep, snyk, or a name for --command")
    p.add_argument("manifest")
    p.add_argument("--command", default="",
                   help="the command to run instead of a preset; must contain {out}")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("check", help="everything checkable about a matrix before spending")
    p.add_argument("matrix")
    p.add_argument("--fake", action="store_true",
                   help="skip the provider and tooling checks, as a --fake run would")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("adjudicate", help="blind human review of findings on real code")
    adj = p.add_subparsers(dest="step", required=True)
    q = adj.add_parser("export", help="pool candidates from runs into a blind review sheet")
    q.add_argument("run_dirs", nargs="+")
    q.add_argument("--sheet", default="adjudication/sheet.csv")
    q.add_argument("--key", default="adjudication/key.json")
    q.add_argument("--seed", type=int, default=0, help="shuffle seed for the sheet's order")
    q.set_defaults(func=cmd_adjudicate_export)
    q = adj.add_parser("import", help="score the reviewers' verdicts")
    q.add_argument("--sheet", default="adjudication/sheet.csv")
    q.add_argument("--key", default="adjudication/key.json")
    q.add_argument("--proxy", action="append", default=[],
                   help="a model route standing in for an attacker; repeatable")
    q.add_argument("--matrix", default="", help="take attacker_proxies from this matrix")
    q.set_defaults(func=cmd_adjudicate_import)

    p = sub.add_parser("import-fix",
                       help="a time-split target from a real fix: vulnerable version and key")
    p.add_argument("repo", help="a local clone")
    p.add_argument("--vulnerable", required=True, help="the commit before the fix")
    p.add_argument("--fixed", required=True, help="the commit that fixed it")
    p.add_argument("--published", required=True, help="disclosure date, YYYY-MM-DD")
    p.add_argument("--cwe", action="append", default=[], required=True,
                   help="a CWE describing it; repeatable")
    p.add_argument("--advisory", default="", help="advisory id, kept where no model sees it")
    p.add_argument("--subdir", default="", help="export and locate only under this path")
    p.add_argument("--id", default="", help="a neutral target id (default ts-<hash>)")
    p.add_argument("--dest", required=True, help="where to write the benchmark, e.g. "
                                                 "benchmarks/ts-001")
    p.set_defaults(func=cmd_import_fix)

    p = sub.add_parser("report", help="aggregate a matrix's results into the study's numbers")
    p.add_argument("run_dir", help="the matrix's output directory, e.g. runs/pilot")
    p.add_argument("--tolerance", type=int, default=3)
    p.add_argument("--stated-only", action="store_true",
                   help="count a location recovered from evidence as no location")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("score", help="score a findings file against a manifest")
    p.add_argument("manifest")
    p.add_argument("findings")
    p.add_argument("--tolerance", type=int, default=3)
    p.set_defaults(func=cmd_score)

    p = sub.add_parser("sarif", help="export a findings file as SARIF 2.1.0")
    p.add_argument("findings")
    p.add_argument("-o", "--output", default="findings.sarif")
    p.set_defaults(func=cmd_sarif)
    return parser


def _utf8_streams() -> None:
    """Write UTF-8 whatever the console's encoding: reports contain non-ASCII."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):
                reconfigure(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    _utf8_streams()
    args = build_parser().parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
