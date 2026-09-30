"""security-eval command line."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .budget import DEFAULT_PRICES, PriceTable
from .finding import SecurityFinding
from .ledger import Ledger, Outcome
from .manifest import ManifestError, load_target
from .matrix import Matrix, estimate, run_matrix
from .runners.base import Runner
from .runners.fake import FakeRunner
from .sarif import to_sarif
from .scoring import score


def _runners(fake: bool) -> dict[str, Runner]:
    if fake:
        # Every condition answered by the fake runner: the whole pipeline, for $0.
        return {"baseline": FakeRunner(), "harness": FakeRunner(recall=0.8), "fake": FakeRunner()}
    from .runners.baseline import BaselineRunner
    from .runners.harness import HarnessRunner

    return {"baseline": BaselineRunner(), "harness": HarnessRunner(), "fake": FakeRunner()}


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


def cmd_run(args: argparse.Namespace) -> int:
    matrix = Matrix.load(args.matrix)
    out = Path(args.out or Path("runs") / matrix.name)
    ledger = run_matrix(matrix, _runners(args.fake), out, PriceTable.load(args.prices),
                        dry_run=args.dry_run)
    _summary(ledger)
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
        p.set_defaults(func=func)

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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
