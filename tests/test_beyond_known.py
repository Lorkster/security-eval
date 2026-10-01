"""The tracks beyond known issues: time-split targets, adjudication, data policy."""

from __future__ import annotations

import csv
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from security_eval.adjudication import cohens_kappa, export, score_sheet
from security_eval.budget import PriceTable, Usage
from security_eval.finding import Location, SecurityFinding
from security_eval.ledger import Outcome
from security_eval.manifest import Target, load_target
from security_eval.matrix import Matrix, run_matrix
from security_eval.preflight import run_checks
from security_eval.report import load_cells, summarise
from security_eval.runners.base import RunResult
from security_eval.runners.harness import neutral_tree
from security_eval.timesplit import TimeSplitError, import_fix, looks_like_advisory

from .conftest import TOY

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def quiet(_: str) -> None:
    pass


# -- time-split targets ------------------------------------------------------------------


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t",
                           *args], capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def fixed_repo(tmp_path: Path) -> tuple[Path, str, str]:
    """A repository whose second commit fixes an injection and adds a regression test."""
    repo = tmp_path / "upstream"
    (repo / "pkg").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "pkg" / "db.py").write_text(
        "import sqlite3\n\n\ndef find(conn, name):\n"
        "    return conn.execute(f\"SELECT * FROM t WHERE n = '{name}'\").fetchall()\n",
        encoding="utf-8")
    (repo / "README.md").write_text("pkg\n", encoding="utf-8")
    git(repo, "init", "-q")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "initial")
    vulnerable = git(repo, "rev-parse", "HEAD")
    (repo / "pkg" / "db.py").write_text(
        "import sqlite3\n\n\ndef find(conn, name):\n"
        "    return conn.execute(\"SELECT * FROM t WHERE n = ?\", (name,)).fetchall()\n",
        encoding="utf-8")
    (repo / "tests" / "test_db.py").write_text("def test_quote():\n    pass\n", encoding="utf-8")
    (repo / "README.md").write_text("pkg\n\nFixed an injection.\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "fix injection in find (CVE-2099-0001)")
    return repo, vulnerable, git(repo, "rev-parse", "HEAD")


@needs_git
def test_a_fix_becomes_a_target_without_its_history_or_its_fix(
    fixed_repo: tuple[Path, str, str], tmp_path: Path
) -> None:
    repo, vulnerable, fixed = fixed_repo
    manifest = import_fix(repo, vulnerable, fixed, tmp_path / "bench", published="2099-01-01",
                          cwes=["CWE-89"], advisory="CVE-2099-0001")

    target = load_target(manifest)
    assert target.id.startswith("ts-") and not looks_like_advisory(target.id)
    (v,) = target.vulnerabilities
    assert v.location == Location("pkg/db.py", 5, 5), "the line the fix changed"
    assert all("test" not in loc.path and not loc.path.endswith(".md") for loc in v.locations)
    code = (target.root / "pkg" / "db.py").read_text(encoding="utf-8")
    assert "f\"SELECT" in code, "the vulnerable version, not the fixed one"
    assert not (target.root / ".git").exists()
    assert not (target.root / "tests" / "test_db.py").exists(), "the fix's test is not there yet"
    assert target.source["advisory"] == "CVE-2099-0001"
    assert "CVE" not in json.dumps({k: v for k, v in json.loads(
        manifest.read_text(encoding="utf-8")).items() if k != "source"})


@needs_git
def test_an_id_naming_the_advisory_is_refused(
    fixed_repo: tuple[Path, str, str], tmp_path: Path
) -> None:
    repo, vulnerable, fixed = fixed_repo
    with pytest.raises(TimeSplitError, match="advisory"):
        import_fix(repo, vulnerable, fixed, tmp_path / "b", published="2099-01-01",
                   cwes=["CWE-89"], target_id="cve-2099-0001")


def test_the_harness_never_works_under_a_path_naming_the_target(tmp_path: Path) -> None:
    workdir = tmp_path / "cells" / "cve-2099-0001" / "harness" / "plain" / "m" / "r1"
    tree = neutral_tree(workdir)
    assert "cve" not in str(tree).lower()
    assert neutral_tree(workdir) == tree, "stable for a cell"
    assert neutral_tree(workdir.parent / "r2") != tree, "distinct between cells"


# -- preflight -----------------------------------------------------------------------------


def time_split(tmp_path: Path, published: str, **extra: object) -> Path:
    copy = tmp_path / "ts"
    shutil.copytree(TOY.parent, copy)
    data = json.loads((copy / "manifest.json").read_text(encoding="utf-8"))
    data.update(id="ts-abc123", public=True, source={"published": published}, **extra)
    (copy / "manifest.json").write_text(json.dumps(data), encoding="utf-8")
    return copy / "manifest.json"


def models_file(tmp_path: Path, cutoff: str | None) -> Path:
    path = tmp_path / "models.json"
    path.write_text(json.dumps({"models": {"claude-sonnet-5-5": {"training_cutoff": cutoff}}}),
                    encoding="utf-8")
    return path


def checks(m: Matrix, prices: PriceTable) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {"ok": [], "warn": [], "fail": []}
    for c in run_checks(m, prices, fake=True):
        out[c.level].append(c.message)
    return out


def matrix(targets: list[Path], **overrides: object) -> Matrix:
    base: dict[str, object] = dict(
        name="t", targets=targets, conditions=["baseline"],
        models=["anthropic:claude-sonnet-5-5"], repeats=2, budget_usd=100.0,
        tokens_per_run={"baseline": (1000, 100), "harness": (1000, 100)})
    base.update(overrides)
    return Matrix(**base)  # type: ignore[arg-type]


@pytest.mark.parametrize(("cutoff", "level"), [
    ("2099-06-01", "fail"),      # disclosed before the cutoff: may have been trained on
    ("2098-12-31", "ok"),
    (None, "warn"),              # unknown: the check cannot run, and says so
])
def test_a_target_disclosed_before_a_models_cutoff_is_refused(
    tmp_path: Path, prices: PriceTable, cutoff: str | None, level: str
) -> None:
    m = matrix([time_split(tmp_path, "2099-01-01")], models_file=models_file(tmp_path, cutoff))
    assert any("ts-abc123" in msg and "2099-01-01" in msg for msg in checks(m, prices)[level])


def test_an_advisory_like_id_fails_preflight(tmp_path: Path, prices: PriceTable) -> None:
    manifest = time_split(tmp_path, "2099-01-01")
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["id"] = "GHSA-xxxx-yyyy"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    result = checks(matrix([manifest], models_file=models_file(tmp_path, "2098-01-01")), prices)
    assert any("advisory" in f for f in result["fail"])


def test_a_harness_that_can_run_commands_fails_for_time_split_targets(
    tmp_path: Path, prices: PriceTable, monkeypatch: pytest.MonkeyPatch
) -> None:
    import security_eval.preflight as preflight

    monkeypatch.setattr(preflight, "_harness_runs_commands", lambda: True)
    m = matrix([time_split(tmp_path, "2099-01-01")], conditions=["harness"],
               models_file=models_file(tmp_path, "2098-01-01"))
    assert any("command execution" in f for f in checks(m, prices)["fail"])


def test_code_is_not_sent_to_a_provider_its_owner_did_not_approve(
    tmp_path: Path, prices: PriceTable
) -> None:
    manifest = time_split(tmp_path, "2099-01-01", allowed_providers=["bedrock", "ollama"])
    m = matrix([manifest], models_file=models_file(tmp_path, "2098-01-01"))

    assert any("may only go to bedrock, ollama" in f for f in checks(m, prices)["fail"])

    class NeverRun:
        condition = "baseline"
        calls = 0

        def run(self, target: Target, route: str, workdir: Path, task: str = "",
                effort: str = "") -> RunResult:
            NeverRun.calls += 1
            return RunResult(Outcome.OK)

    ledger = run_matrix(m, {"baseline": NeverRun()}, tmp_path / "out", prices, progress=quiet)
    assert NeverRun.calls == 0, "refused at run time too, whatever preflight said"
    assert {r.outcome for r in ledger.records()} == {Outcome.SKIPPED_POLICY}
    assert Outcome.SKIPPED_POLICY.final


def test_an_attacker_proxy_must_be_one_of_the_models(tmp_path: Path, prices: PriceTable) -> None:
    result = checks(matrix([TOY], attacker_proxies=["ollama:open-model"]), prices)
    assert any("attacker proxies" in f for f in result["fail"])


# -- adjudication ---------------------------------------------------------------------------


def open_target(tmp_path: Path) -> Path:
    copy = tmp_path / "real"
    shutil.copytree(TOY.parent, copy)
    data = json.loads((copy / "manifest.json").read_text(encoding="utf-8"))
    data.update(id="real-1", open=True, vulnerabilities=[], decoys=[])
    (copy / "manifest.json").write_text(json.dumps(data), encoding="utf-8")
    return copy / "manifest.json"


def reporting(*places: tuple[str, int]) -> type:
    class Reports:
        condition = "baseline"

        def run(self, target: Target, route: str, workdir: Path, task: str = "",
                effort: str = "") -> RunResult:
            return RunResult(Outcome.OK, [
                SecurityFinding(f"issue at {p}:{line}", location=Location(p, line, line),
                                location_source="stated")
                for p, line in places], Usage(10, 1))
    return Reports


def fill(sheet: Path, verdicts: dict[str, tuple[str, str]]) -> dict[str, str]:
    """Fill reviewers by location; return candidate id per location."""
    rows = list(csv.DictReader(sheet.open(encoding="utf-8")))
    ids = {}
    for row in rows:
        loc = row["location"].split("-")[0]
        ids[loc] = row["candidate"]
        a, b = verdicts.get(loc, ("", ""))
        row["reviewer_a"], row["reviewer_b"] = a, b
    with sheet.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return ids


def test_adjudication_pools_blindly_and_scores_what_the_reviewers_decided(
    tmp_path: Path, prices: PriceTable
) -> None:
    real = open_target(tmp_path)
    m = matrix([real], models=["anthropic:claude-sonnet-5-5", "ollama:open-model"], repeats=1,
               attacker_proxies=["ollama:open-model"])
    prices.models["open-model"] = prices.models["claude-haiku-4-5"]

    class Both:
        condition = "baseline"

        def run(self, target: Target, route: str, workdir: Path, task: str = "",
                effort: str = "") -> RunResult:
            places = [("app/db.py", 11), ("app/files.py", 10)]
            if route.startswith("ollama"):
                places = [("app/db.py", 12), ("app/session.py", 9), ("app/config.py", 9)]
            return reporting(*places)().run(target, route, workdir)

    out = tmp_path / "out"
    ledger = run_matrix(m, {"baseline": Both()}, out, prices, progress=quiet)
    assert all(r.extra.get("open") for r in ledger.records()), "not scored against a key"
    assert summarise(load_cells(out))["groups"] == [], "the report leaves open targets alone"

    sheet, key = tmp_path / "adj" / "sheet.csv", tmp_path / "adj" / "key.json"
    export([out], sheet, key, seed=1)
    text = sheet.read_text(encoding="utf-8")
    assert "anthropic" not in text and "ollama" not in text and "baseline" not in text, "blind"
    ids = fill(sheet, {"app/db.py:11": ("tp", "tp"), "app/files.py:10": ("tp", "tp"),
                       "app/session.py:9": ("tp", "tp"), "app/config.py:9": ("tp", "fp")})
    assert "app/db.py:12" not in ids, "db.py:11 and :12 are one candidate"

    result = score_sheet(sheet, key, attacker_proxies=["ollama:open-model"])

    assert ids["app/config.py:9"] in result["disputed"]
    groups = {g["group"]: g for g in result["groups"]}
    claude = groups["baseline | anthropic:claude-sonnet-5-5 | plain | default"]
    proxy = groups["baseline | ollama:open-model | plain | default"]
    # Verified pool: db.py, files.py, session.py. config.py is disputed, so not yet in it.
    assert claude["verified"] == 2
    assert claude["relative_recall"] == pytest.approx(2 / 3, abs=1e-3)
    assert proxy["relative_recall"] == pytest.approx(2 / 3, abs=1e-3)
    # The proxy verified db.py and session.py; Claude found db.py only.
    assert claude["attacker_proxy_coverage"] == 0.5
    assert "attacker_proxy_coverage" not in proxy, "a proxy is not measured against itself"
    assert claude["beyond_the_scanners"] == 1, "files.py: Bandit did not report it"


def test_on_a_time_split_target_only_what_is_not_the_known_flaw_is_judged(
    tmp_path: Path, prices: PriceTable
) -> None:
    """The key covers one flaw. Everything else on real code is a candidate, not a mistake."""
    manifest = time_split(tmp_path, "2099-01-01")
    out = tmp_path / "out"
    run_matrix(matrix([manifest], repeats=1), {"baseline": reporting(
        ("app/db.py", 11), ("app/files.py", 10))()}, out, prices, progress=quiet)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["vulnerabilities"] = [v for v in data["vulnerabilities"] if v["id"] == "V1"]
    manifest.write_text(json.dumps(data), encoding="utf-8")

    sheet, key = tmp_path / "adj" / "sheet.csv", tmp_path / "adj" / "key.json"
    export([out], sheet, key)
    locations = {row["location"].split("-")[0]
                 for row in csv.DictReader(sheet.open(encoding="utf-8"))}

    assert "app/db.py:11" not in locations, "the known flaw is scored by the key"
    assert "app/files.py:10" in locations


def test_kappa() -> None:
    assert cohens_kappa([("tp", "tp"), ("fp", "fp")]) == 1.0
    assert cohens_kappa([("tp", "fp"), ("fp", "tp")]) == -1.0
    assert cohens_kappa([]) is None


def test_a_verdict_that_is_not_one_of_the_three_is_an_error() -> None:
    from security_eval.adjudication import _verdict

    assert _verdict(" TP ") == "tp"
    with pytest.raises(ValueError, match="unrecognised"):
        _verdict("maybe-ish")


def test_triage_on_real_code_is_scored_against_the_reviewers(
    tmp_path: Path, prices: PriceTable
) -> None:
    """No answer key on an open target: the reviewers' verdicts on the scanner's findings are it."""
    from security_eval.finding import Verdict
    from security_eval.scanners import scanner_findings

    real = open_target(tmp_path)

    class SaysEverythingIsReal:
        condition = "triage"
        kind = "triage"

        def run(self, target: Target, route: str, workdir: Path, task: str = "",
                effort: str = "") -> RunResult:
            findings = scanner_findings(target, "bandit")
            for f in findings:
                f.triage = Verdict.TRUE_POSITIVE
            return RunResult(Outcome.OK, findings, Usage(10, 1), extra={"tool": "bandit"})

    out = tmp_path / "out"
    run_matrix(matrix([real], conditions=["triage"], repeats=1,
                      tokens_per_run={"triage": (10, 1)}),
               {"triage": SaysEverythingIsReal()}, out, prices, progress=quiet)
    sheet, key = tmp_path / "adj" / "sheet.csv", tmp_path / "adj" / "key.json"
    export([out], sheet, key)
    # Bandit's db.py:11 finding is real; tools.py:3 (an import) is not.
    fill(sheet, {"app/db.py:11": ("tp", "tp"), "app/tools.py:3": ("fp", "fp")})

    (row,) = score_sheet(sheet, key)["triage"]
    assert row["judged"] == 2, "only what the reviewers decided"
    assert row["accuracy"] == 0.5, "right about db.py, wrong about the import"
