"""RQ8: proposed fixes and their regression tests, checked stage by stage.

The verdict logic runs against real pytest runs: `LocalSandbox` runs the
commands on the host, which is safe here only because every line of code it
runs -- the benchmark and each proposal -- is written by these tests. The
container itself is exercised by the last tests, where an engine is present.
"""

from __future__ import annotations

import dataclasses
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from security_eval.batch import BatchOutcome
from security_eval.budget import PriceTable, Usage
from security_eval.fixes import (
    Edit,
    FixVerdict,
    Proposal,
    TargetState,
    apply_edits,
    prepare_target,
    verify_proposal,
    verify_run,
)
from security_eval.ledger import Outcome
from security_eval.manifest import Target, VerifyConfig, load_target
from security_eval.matrix import BATCHABLE, Matrix, run_matrix
from security_eval.preflight import run_checks
from security_eval.report import load_cells, render_markdown, summarise
from security_eval.runners.base import RunResult
from security_eval.runners.fix import FixRunner, describe, parse_proposal
from security_eval.sandbox import ContainerSandbox, Execution, fill, find_engine, parse_junit
from security_eval.timesplit import import_fix

from .conftest import ROOT, TOY

NOTES = ROOT / "benchmarks" / "notes-api" / "manifest.json"
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def quiet(_: str) -> None:
    pass


class LocalSandbox:
    """Runs on the host, for tests only, on code the tests wrote themselves."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str]]] = []

    def run(self, tree: Path, command: str, tests: list[str], timeout: int) -> Execution:
        self.calls.append((tree.name, tests))
        junit = tree.parent / f"{tree.name}-junit.xml"
        junit.unlink(missing_ok=True)
        argv = shlex.split(fill(command, tests, str(junit)))
        if argv[0] == "python":
            argv[0] = sys.executable
        proc = subprocess.run(argv, cwd=tree, capture_output=True, text=True, timeout=timeout,
                              env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, check=False)
        return Execution(proc.returncode, (proc.stdout + proc.stderr)[-4000:],
                         junit=junit.read_text(encoding="utf-8") if junit.is_file() else None)


@pytest.fixture(scope="module")
def notes() -> Target:
    return load_target(NOTES)


@pytest.fixture(scope="module")
def notes_state(notes: Target, tmp_path_factory: pytest.TempPathFactory) -> TargetState:
    return prepare_target(notes, LocalSandbox(), tmp_path_factory.mktemp("state"))


SQL_LINE = '    sql = "SELECT id, title, created FROM notes WHERE owner_id = ? ORDER BY " + order'
ALLOW_LIST = ('    if order not in SORTABLE:\n'
              '        raise ValueError(f"cannot sort by {order!r}")\n' + SQL_LINE)
SORT_TEST = (
    "import pytest\n\nfrom notes import db\n\n\n"
    "def test_sort_order_must_be_an_allowed_column(conn):\n"
    "    with pytest.raises(ValueError):\n"
    "        db.list_notes(conn, 1, 'title DESC')\n"
)


def v1(edits: list[Edit] | None = None, test: str = SORT_TEST,
       path: str = "tests/test_sort_order.py") -> Proposal:
    return Proposal("V1", edits if edits is not None else [Edit("notes/db.py", SQL_LINE,
                                                                ALLOW_LIST)],
                    test_path=path, test_content=test)


def check(notes: Target, state: TargetState, proposal: Proposal, tmp_path: Path,
          sandbox: object | None = None) -> tuple[FixVerdict, str]:
    result = verify_proposal(notes, proposal, sandbox or LocalSandbox(), state,  # type: ignore[arg-type]
                             tmp_path)
    return result.verdict, result.detail


# -- the stages ----------------------------------------------------------------


def test_the_suite_runs_and_passes_on_the_vulnerable_code(notes_state: TargetState) -> None:
    assert notes_state.problem == ""
    assert notes_state.suite is not None
    counts = notes_state.suite.counts()
    assert counts["passed"] == 20 and counts["failed"] == counts["error"] == 0


def test_a_fix_whose_test_fails_before_and_passes_after_is_verified(
    notes: Target, notes_state: TargetState, tmp_path: Path
) -> None:
    sandbox = LocalSandbox()
    verdict, detail = check(notes, notes_state, v1(), tmp_path, sandbox)
    assert verdict is FixVerdict.VERIFIED, detail
    stages = [tree for tree, _ in sandbox.calls]
    assert stages == ["vulnerable", "patched", "patched-suite"], "in order, each on its own tree"
    assert (ROOT / "benchmarks" / "notes-api" / "src" / "notes" / "db.py").read_text(
        encoding="utf-8").count("SORTABLE") == 1, "the benchmark itself is never edited"


def test_the_suite_is_run_with_the_fix_but_without_the_new_test(
    notes: Target, notes_state: TargetState, tmp_path: Path
) -> None:
    result = verify_proposal(notes, v1(), LocalSandbox(), notes_state, tmp_path)
    suite = result.stages[-1]
    assert suite["stage"] == "suite with the fix"
    assert suite["counts"]["passed"] == 20, "the project's tests only"


def junit(status: str) -> str:
    inner = {"passed": "", "failed": '<failure message="assert False"/>'}[status]
    return f'<testsuite><testcase classname="t" name="a">{inner}</testcase></testsuite>'


class StageSandbox:
    """Answers each stage with a prepared execution, by tree name."""

    def __init__(self, runs: dict[str, Execution]) -> None:
        self.runs = runs

    def run(self, tree: Path, command: str, tests: list[str], timeout: int) -> Execution:
        return self.runs[tree.name]


@pytest.mark.parametrize(("runs", "verdict"), [
    ({"vulnerable": Execution(None, timed_out=True)}, FixVerdict.TEST_BROKEN),
    ({"vulnerable": Execution(1, junit=junit("failed")),
      "patched": Execution(None, timed_out=True)}, FixVerdict.NOT_FIXED),
    ({"vulnerable": Execution(1, junit=junit("failed")),
      "patched": Execution(0, junit=junit("passed")),
      "patched-suite": Execution(None, timed_out=True)}, FixVerdict.SUITE_REGRESSED),
])
def test_a_run_that_does_not_finish_counts_against_the_proposal(
    notes: Target, notes_state: TargetState, tmp_path: Path, runs: dict[str, Execution],
    verdict: FixVerdict,
) -> None:
    assert check(notes, notes_state, v1(), tmp_path, StageSandbox(runs))[0] is verdict


def test_a_test_that_passes_on_the_vulnerable_code_detects_nothing(
    notes: Target, notes_state: TargetState, tmp_path: Path
) -> None:
    test = ("from notes import db\n\n\ndef test_sorting(conn):\n"
            "    assert db.list_notes(conn, 1, 'title')\n")
    assert check(notes, notes_state, v1(test=test), tmp_path)[0] is FixVerdict.TEST_DID_NOT_FAIL


def test_a_test_that_fails_only_by_calling_what_the_fix_adds_is_the_wrong_reason(
    notes: Target, notes_state: TargetState, tmp_path: Path
) -> None:
    edits = [Edit("notes/db.py", SQL_LINE,
                  "    validate_order(order)\n" + SQL_LINE),
             Edit("notes/db.py", "def list_notes(",
                  "def validate_order(order):\n    if order not in SORTABLE:\n"
                  "        raise ValueError(order)\n\n\ndef list_notes(")]
    test = ("import pytest\n\nfrom notes import db\n\n\ndef test_validate():\n"
            "    with pytest.raises(ValueError):\n        db.validate_order('title DESC')\n")
    verdict, detail = check(notes, notes_state, v1(edits, test), tmp_path)
    assert verdict is FixVerdict.TEST_WRONG_REASON, detail
    assert "AttributeError" in detail


def test_a_test_that_cannot_even_be_collected_is_broken(
    notes: Target, notes_state: TargetState, tmp_path: Path
) -> None:
    verdict, _ = check(notes, notes_state, v1(test="def test_x(:\n    pass\n"), tmp_path)
    assert verdict is FixVerdict.TEST_BROKEN


def test_a_fix_that_leaves_the_test_failing_is_not_a_fix(
    notes: Target, notes_state: TargetState, tmp_path: Path
) -> None:
    edits = [Edit("notes/db.py", '"""Storage for notes."""', '"""Storage for notes (safe)."""')]
    verdict, detail = check(notes, notes_state, v1(edits), tmp_path)
    assert verdict is FixVerdict.NOT_FIXED
    assert "still fail" in detail and "DID NOT RAISE" in detail


def test_a_fix_that_breaks_what_worked_is_a_regression(
    notes: Target, notes_state: TargetState, tmp_path: Path
) -> None:
    edits = [Edit("notes/db.py", SQL_LINE,
                  '    if order != "title":\n        raise ValueError(order)\n' + SQL_LINE)]
    verdict, detail = check(notes, notes_state, v1(edits), tmp_path)
    assert verdict is FixVerdict.SUITE_REGRESSED, detail
    assert "test_list_notes_by_created" in detail or "passed before" in detail


@pytest.mark.parametrize(("proposal", "reason"), [
    (v1([Edit("tests/test_notes.py", "def test_get_note", "def _skip")]), "may not be edited"),
    (v1([Edit("tests/conftest.py", "import os", "import os")]), "may not be edited"),
    (v1([Edit("pyproject.toml", "", "[tool.pytest.ini_options]\n")]), "may not be edited"),
    (v1([Edit("../escape.py", "", "x = 1\n")]), "outside"),
    (v1([Edit("notes/db.py", "this text is not there", "x")]), "occurs 0 times"),
    (v1([Edit("notes/db.py", "conn", "c")]), "times"),
    (v1([]), "no edits"),
    (v1(path="notes/test_elsewhere.py"), "under tests/"),
    (v1(path="tests/test_notes.py"), "exists already"),
    (v1(path="tests/conftest.py"), "test configuration"),
    (v1(test=""), "no regression test"),
])
def test_a_proposal_may_not_change_what_it_is_measured_against(
    notes: Target, notes_state: TargetState, tmp_path: Path, proposal: Proposal, reason: str
) -> None:
    verdict, detail = check(notes, notes_state, proposal, tmp_path)
    assert verdict is FixVerdict.INVALID_PROPOSAL
    assert reason in detail


def test_refusals_and_unusable_answers_have_no_proposal(
    notes: Target, notes_state: TargetState, tmp_path: Path
) -> None:
    sandbox = LocalSandbox()
    assert check(notes, notes_state, Proposal("V1", refusal="cyber"), tmp_path,
                 sandbox) == (FixVerdict.NO_PROPOSAL, "refused (cyber)")
    assert check(notes, notes_state, Proposal("V1", invalid="truncated"), tmp_path / "b",
                 sandbox)[0] is FixVerdict.NO_PROPOSAL
    assert sandbox.calls == [], "nothing to run"


def test_a_sandbox_failure_says_nothing_about_the_proposal(
    notes: Target, notes_state: TargetState, tmp_path: Path
) -> None:
    class Broken:
        def run(self, tree: Path, command: str, tests: list[str], timeout: int) -> Execution:
            return Execution(125, infra_error="no such image")

    assert check(notes, notes_state, v1(), tmp_path, Broken())[0] is FixVerdict.SANDBOX_ERROR
    assert prepare_target(notes, Broken(), tmp_path / "s").problem  # type: ignore[arg-type]


def test_edits_match_whatever_line_endings_the_checkout_has(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_bytes(b"x = 1\r\ny = 2\r\n")
    config = VerifyConfig(test_dir="tests")
    assert apply_edits(tmp_path, [Edit("a.py", "x = 1\ny = 2", "x = 1\ny = 3")], config) == ""
    assert (tmp_path / "a.py").read_bytes() == b"x = 1\r\ny = 3\r\n"


# -- against a real fix (time-split) -------------------------------------------


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t",
                           "-c", "core.autocrlf=false", *args],
                          capture_output=True, text=True, check=True).stdout.strip()


VULNERABLE = "def safe_name(name):\n    return name\n"
FIXED = ("def safe_name(name):\n    if '/' in name or name.startswith('.'):\n"
         "        raise ValueError('bad name')\n    return name\n")
UPSTREAM_TEST = ("import pytest\n\nfrom pkg.names import safe_name\n\n\n"
                 "def test_traversal():\n    with pytest.raises(ValueError):\n"
                 "        safe_name('../x')\n\n\ndef test_absolute():\n"
                 "    with pytest.raises(ValueError):\n        safe_name('/etc/x')\n")


@pytest.fixture(scope="module")
def time_split(tmp_path_factory: pytest.TempPathFactory) -> Target:
    if shutil.which("git") is None:
        pytest.skip("git not installed")
    base = tmp_path_factory.mktemp("ts")
    repo = base / "upstream"
    (repo / "pkg").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "pkg" / "names.py").write_text(VULNERABLE, encoding="utf-8")
    (repo / "tests" / "test_names.py").write_text(
        "from pkg.names import safe_name\n\n\ndef test_plain():\n"
        "    assert safe_name('a.txt') == 'a.txt'\n", encoding="utf-8")
    git(repo, "init", "-q")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "initial")
    vulnerable = git(repo, "rev-parse", "HEAD")
    (repo / "pkg" / "names.py").write_text(FIXED, encoding="utf-8")
    (repo / "tests" / "test_traversal.py").write_text(UPSTREAM_TEST, encoding="utf-8")
    (repo / "CHANGELOG.md").write_text("fixed\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "fix")
    manifest = import_fix(repo, vulnerable, git(repo, "rev-parse", "HEAD"), base / "bench",
                          published="2099-01-01", cwes=["CWE-22"])
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["verify"].update(
        image="local", test_command="python -m pytest -q -p no:cacheprovider {test} "
                                    "--junitxml={junit}",
        suite_command="python -m pytest -q -p no:cacheprovider tests --junitxml={junit}")
    manifest.write_text(json.dumps(data), encoding="utf-8")
    return load_target(manifest)


def test_import_fix_keeps_the_real_fix_where_no_model_sees_it(time_split: Target) -> None:
    v = time_split.verify
    assert v is not None and v.reference_fix is not None and v.reference_tests is not None
    assert (v.reference_fix / "pkg" / "names.py").read_text(encoding="utf-8") == FIXED
    assert (v.reference_tests / "tests" / "test_traversal.py").is_file()
    assert not (v.reference_fix / "CHANGELOG.md").exists(), "notes are not part of the fix"
    assert not (time_split.root / "tests" / "test_traversal.py").exists()
    assert "raise" not in (time_split.root / "pkg" / "names.py").read_text(encoding="utf-8")
    assert not str(v.reference_fix).startswith(str(time_split.root)), "outside src/"


@pytest.fixture(scope="module")
def ts_state(time_split: Target, tmp_path_factory: pytest.TempPathFactory) -> TargetState:
    return prepare_target(time_split, LocalSandbox(), tmp_path_factory.mktemp("ts-state"))


def test_the_reference_is_checked_before_it_is_trusted(ts_state: TargetState) -> None:
    assert ts_state.reference_valid, ts_state.reference_detail
    assert ts_state.reference_tests == ["tests/test_traversal.py"]


def test_reference_tests_that_pass_on_the_vulnerable_code_are_not_trusted(
    time_split: Target, tmp_path: Path
) -> None:
    assert time_split.verify is not None
    weak = tmp_path / "weak" / "tests"
    weak.mkdir(parents=True)
    (weak / "test_weak.py").write_text("def test_nothing():\n    assert True\n",
                                       encoding="utf-8")
    target = dataclasses.replace(time_split, verify=dataclasses.replace(
        time_split.verify, reference_tests=weak.parent))
    state = prepare_target(target, LocalSandbox(), tmp_path / "s")
    assert not state.reference_valid
    assert "pass on the vulnerable code" in state.reference_detail
    result = verify_proposal(target, names_fix("'/' in name or name.startswith('.')", RAISES),
                             LocalSandbox(), state, tmp_path / "p")
    assert result.upstream is None and result.overfit is None, "no reference, no claims"


def names_fix(condition: str, test_body: str) -> Proposal:
    return Proposal(
        "V1",
        [Edit("pkg/names.py", "    return name",
              f"    if {condition}:\n        raise ValueError('name contains ..')\n"
              "    return name")],
        test_path="tests/test_model.py",
        test_content=("import pytest\n\nfrom pkg.names import safe_name\n\n\n"
                      f"def test_rejects():\n{test_body}"))


RAISES = "    with pytest.raises(ValueError):\n        safe_name('../x')\n"


def test_a_complete_fix_passes_the_real_fixs_own_tests(
    time_split: Target, ts_state: TargetState, tmp_path: Path
) -> None:
    result = verify_proposal(time_split, names_fix("'/' in name or name.startswith('.')", RAISES),
                             LocalSandbox(), ts_state, tmp_path)
    assert result.verdict is FixVerdict.VERIFIED, result.detail
    assert result.upstream == "pass"
    assert result.overfit is False


def test_an_incomplete_fix_can_pass_its_own_test_and_fail_upstream(
    time_split: Target, ts_state: TargetState, tmp_path: Path
) -> None:
    result = verify_proposal(time_split, names_fix("'..' in name", RAISES), LocalSandbox(),
                             ts_state, tmp_path)
    assert result.verdict is FixVerdict.VERIFIED, "its own test is satisfied"
    assert result.upstream == "fail", "the project's test of absolute paths is not"


def test_a_test_of_the_models_own_fix_rather_than_the_flaw_is_overfit(
    time_split: Target, ts_state: TargetState, tmp_path: Path
) -> None:
    body = "    with pytest.raises(ValueError, match='contains'):\n        safe_name('../x')\n"
    result = verify_proposal(time_split, names_fix("'/' in name or name.startswith('.')", body),
                             LocalSandbox(), ts_state, tmp_path)
    assert result.verdict is FixVerdict.VERIFIED
    assert result.overfit is True, "the real fix raises with another message"


# -- the runner ------------------------------------------------------------------


def test_the_model_is_told_where_and_what_but_not_the_answer_key(notes: Target) -> None:
    v = notes.vulnerabilities[0]
    text = describe("TASK", v)
    assert "notes/db.py:15-16" in text and "notes/handlers.py:7-8" in text and "CWE-89" in text
    assert v.description not in text and "SORTABLE" not in text


def test_the_model_sees_the_tests_and_how_they_run_but_not_the_plumbing(notes: Target) -> None:
    system = FixRunner()._prepare(notes)
    assert isinstance(system, str)
    assert "tests/test_notes.py" in system and "NOTES_SERVICE_TOKEN" in system
    assert "python -m pytest -q -p no:cacheprovider <test file>" in system
    assert "junit" not in system.lower() and "without network access" in system


def test_targets_whose_fixes_cannot_be_verified_are_not_asked(toy: Target, tmp_path: Path) -> None:
    result = FixRunner().run(toy, "anthropic:claude-sonnet-5-5", tmp_path)
    assert isinstance(result, RunResult) and result.outcome is Outcome.ERROR
    assert "verify" in result.detail


def test_proposals_are_parsed_and_unusable_answers_recorded(notes: Target) -> None:
    good = json.dumps({"edits": [{"path": "notes/db.py", "old": "a", "new": "b"}],
                       "test": {"path": "tests/test_x.py", "content": "x"},
                       "explanation": "why"})
    parsed = parse_proposal(f"```json\n{good}\n```", "V1")
    assert parsed is not None and parsed.edits == [Edit("notes/db.py", "a", "b")]
    assert parse_proposal("I would rather not.", "V1") is None

    usage = Usage(10, 5)
    replies = [(good, "end_turn", None, usage), ("prose", "max_tokens", None, usage),
               ("", "refusal", "cyber", usage)] + [(good, "end_turn", None, usage)] * 3
    result = FixRunner()._result(notes, replies, 1.0, "anthropic:claude-sonnet-5-5", "")
    proposals = result.artifacts["proposals"]
    assert result.outcome is Outcome.OK and len(proposals) == 6
    assert proposals[1]["invalid"] == "answer truncated at the token limit"
    assert proposals[2]["refusal"] == "cyber"
    assert [p["vulnerability"] for p in proposals] == [v.id for v in notes.vulnerabilities]
    assert result.usage == Usage(60, 30)

    refused = FixRunner()._result(notes, [("", "refusal", "", usage)] * 6, 1.0, "x:y", "")
    assert refused.outcome is Outcome.REFUSED


def test_fix_cells_batch_one_cached_request_per_flaw(notes: Target, tmp_path: Path) -> None:
    pytest.importorskip("supervisor_harness")
    assert "fix" in BATCHABLE
    items = FixRunner().batch_items(notes, "anthropic:claude-sonnet-5-5", "TASK", "",
                                    "cell", tmp_path)
    assert isinstance(items, list) and len(items) == len(notes.vulnerabilities)
    assert len({i.custom_id for i in items}) == len(items)
    assert all(i.params["system"][0].get("cache_control") for i in items)

    message = {
        "content": [{"type": "text", "text": json.dumps(
            {"edits": [], "test": {"path": "t", "content": "c"}, "explanation": ""})}],
        "stop_reason": "end_turn", "usage": {"input_tokens": 5, "output_tokens": 1}}
    outcomes = [BatchOutcome(i.custom_id, "succeeded", message) for i in items]
    result = FixRunner().from_batch(notes, "anthropic:claude-sonnet-5-5", outcomes)
    assert result.outcome is Outcome.OK and result.extra["batched"]
    short = FixRunner().from_batch(notes, "anthropic:claude-sonnet-5-5", outcomes[:2])
    assert short.outcome is Outcome.ERROR, "a missing result is not a missing proposal"


# -- end to end ------------------------------------------------------------------


class Scripted:
    condition = "fake"
    kind = "fix"

    def __init__(self, proposals: list[Proposal]) -> None:
        self.proposals = proposals

    def run(self, target: Target, route: str, workdir: Path, task: str = "",
            effort: str = "") -> RunResult:
        return RunResult(Outcome.OK, [], Usage(1000, 100),
                         artifacts={"proposals": [p.to_dict() for p in self.proposals]})


def test_a_run_is_verified_resumably_and_reported(tmp_path: Path, prices: PriceTable) -> None:
    matrix = Matrix(name="fix", targets=[NOTES], conditions=["fix"], models=["fake:m"],
                    tokens_per_run={"fix": (1000, 100)})
    out = tmp_path / "run"
    proposals = [v1(), Proposal("V2", refusal=""), v1(path="elsewhere.py")]
    run_matrix(matrix, {"fix": Scripted(proposals)}, out, prices, progress=quiet)
    cell = next((out / "cells").rglob("proposals.json")).parent

    (pending,) = summarise(load_cells(out))["fixes"]
    assert pending["unverified_cells"] == 1 and pending["flaws"] == 0

    sandbox = LocalSandbox()
    assert verify_run(out, lambda _: sandbox, progress=quiet) == 1
    verdicts = [r["verdict"] for r in json.loads(
        (cell / "verify.json").read_text(encoding="utf-8"))["results"]]
    assert verdicts == ["verified", "no_proposal", "invalid_proposal"]

    calls = len(sandbox.calls)
    assert verify_run(out, lambda _: sandbox, progress=quiet) == 0, "done is done"
    assert len(sandbox.calls) == calls

    (row,) = summarise(load_cells(out))["fixes"]
    assert row["verified"] == 1 and row["flaws"] == 3, "refusals count against the rate"
    assert row["verdicts"] == {"invalid_proposal": 1, "no_proposal": 1, "verified": 1}
    assert row["verified_rate"]["median"] == pytest.approx(1 / 3, abs=1e-3)
    summary = summarise(load_cells(out))
    assert not summary["groups"], "fix cells are not scored as detection"
    assert "Fix verification (RQ8)" in render_markdown(summary, title="t", stated_only=False)


def test_a_sandbox_error_is_verified_again(tmp_path: Path, prices: PriceTable) -> None:
    matrix = Matrix(name="fix", targets=[NOTES], conditions=["fix"], models=["fake:m"],
                    tokens_per_run={"fix": (1000, 100)})
    out = tmp_path / "run"
    run_matrix(matrix, {"fix": Scripted([v1()])}, out, prices, progress=quiet)

    class Broken:
        def run(self, tree: Path, command: str, tests: list[str], timeout: int) -> Execution:
            return Execution(None, infra_error="engine down")

    assert verify_run(out, lambda _: Broken(), progress=quiet) == 1
    assert verify_run(out, lambda _: LocalSandbox(), progress=quiet) == 1, "retried"
    (row,) = summarise(load_cells(out))["fixes"]
    assert row["verdicts"] == {"verified": 1}


def test_preflight_refuses_a_fix_matrix_whose_fixes_could_not_be_checked(
    prices: PriceTable,
) -> None:
    def levels(target: Path) -> dict[str, list[str]]:
        m = Matrix(name="f", targets=[target], conditions=["fix"],
                   models=["anthropic:claude-sonnet-5-5"], repeats=2, budget_usd=10.0,
                   tokens_per_run={"fix": (1000, 100)})
        out: dict[str, list[str]] = {"ok": [], "warn": [], "fail": []}
        for c in run_checks(m, prices, fake=True):
            out[c.level].append(c.message)
        return out

    assert any("no verify section" in m for m in levels(TOY)["fail"])
    notes = levels(NOTES)
    assert not notes["fail"], notes["fail"]
    assert any("security-eval/notes-api" in m for m in notes["ok"])


# -- the sandbox -----------------------------------------------------------------


def test_junit_tells_a_failure_from_an_error() -> None:
    report = parse_junit(
        '<testsuites><testsuite><testcase classname="t" name="a"/>'
        '<testcase classname="t" name="b"><failure message="assert 1 == 2">x</failure></testcase>'
        '<testcase classname="t" name="c"><error message="collection failure"/></testcase>'
        '<testcase classname="t" name="d"><skipped/></testcase></testsuite></testsuites>')
    assert report is not None
    assert report.counts() == {"passed": 1, "failed": 1, "error": 1, "skipped": 1}
    assert report.messages["t::b"] == "assert 1 == 2"
    assert parse_junit("not xml") is None and parse_junit(None) is None


def test_the_container_has_no_network_and_cannot_write_the_tree(tmp_path: Path) -> None:
    argv = ContainerSandbox("docker", "img").argv(tmp_path, tmp_path / "r", "n", "true")
    joined = " ".join(argv)
    assert "--network none" in joined and "--read-only" in joined
    assert "--cap-drop ALL" in joined and "no-new-privileges" in joined
    assert f"{tmp_path}:/work:ro" in joined and "--pids-limit" in joined
    assert argv[-4:] == ["img", "sh", "-c", "true"]


def test_a_missing_engine_is_a_sandbox_error_not_a_verdict(tmp_path: Path) -> None:
    run = ContainerSandbox("no-such-engine-here", "img").run(tmp_path, "true", [], 10)
    assert run.infra_error


def _linux_engine() -> str | None:
    engine = find_engine()
    if engine is None:
        return None
    proc = subprocess.run([engine, "info", "--format", "{{.OSType}}"],
                          capture_output=True, text=True, check=False)
    return engine if proc.stdout.strip() == "linux" else None


ENGINE = _linux_engine()
needs_containers = pytest.mark.skipif(ENGINE is None, reason="no Linux container engine")


@pytest.fixture(scope="module")
def built(notes: Target) -> str:
    assert ENGINE is not None and notes.verify is not None and notes.verify.dockerfile
    proc = subprocess.run([ENGINE, "build", "-q", "-t", notes.verify.image, "-f",
                           str(notes.verify.dockerfile), str(NOTES.parent)],
                          capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        pytest.skip(f"could not build the image: {proc.stderr[-300:]}")
    return ENGINE


@needs_containers
def test_in_the_container_a_good_fix_is_verified(
    built: str, notes: Target, tmp_path: Path
) -> None:
    assert notes.verify is not None
    sandbox = ContainerSandbox(built, notes.verify.image)
    state = prepare_target(notes, sandbox, tmp_path / "state")
    assert state.problem == "", state.problem
    result = verify_proposal(notes, v1(), sandbox, state, tmp_path / "p")
    assert result.verdict is FixVerdict.VERIFIED, (result.detail, result.stages)


@needs_containers
def test_in_the_container_nothing_is_reachable_and_the_tree_is_read_only(
    built: str, notes: Target, tmp_path: Path
) -> None:
    assert notes.verify is not None
    sandbox = ContainerSandbox(built, notes.verify.image)
    tree = tmp_path / "tree"
    tree.mkdir()
    net = sandbox.run(tree, "python -c \"import socket; socket.create_connection("
                            "('1.1.1.1', 53), timeout=3)\"", [], 60)
    assert net.exit_code not in (0, None) and not net.infra_error
    write = sandbox.run(tree, "touch /work/x", [], 60)
    assert write.exit_code != 0 and not (tree / "x").exists()
