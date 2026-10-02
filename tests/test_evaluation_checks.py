"""The checks beside the scores: calibration, evidence, coverage, consistency, identity.

Five ideas taken from how violin (Strategic-Automation/violin) evaluates its
own runs -- its evaluation method, not its tooling:

* the scorer is tried on answers whose score is known before any result is trusted;
* a finding's quoted code is checked against the file it names;
* a miss is told apart as "never read" or "read and missed";
* a vulnerability is reported as found in k of n repeats, not only as a median;
* each cell records a fingerprint of the code it ran on.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from security_eval.budget import Usage
from security_eval.checks import (
    attribute_misses,
    check_evidence,
    quoted_fragments,
    target_digest,
)
from security_eval.cli import main
from security_eval.finding import Location, SecurityFinding
from security_eval.ledger import Outcome
from security_eval.manifest import Target, load_target
from security_eval.matrix import Matrix, run_matrix
from security_eval.preflight import run_checks
from security_eval.report import load_cells, render_markdown, summarise
from security_eval.runners.base import RunResult
from security_eval.runners.baseline import BaselineRunner
from security_eval.runners.harness import files_read
from security_eval.scoring import calibrate

from .conftest import ROOT, TOY

NOTES = ROOT / "benchmarks" / "notes-api" / "manifest.json"


def quiet(_: str) -> None:
    pass


def at(path: str, start: int, end: int | None = None, *evidence: str,
       cwe: str | None = None) -> SecurityFinding:
    return SecurityFinding(title="t", cwe=cwe, location=Location(path, start, end or start),
                           evidence=list(evidence), location_source="stated")


@pytest.fixture
def toy_copy(tmp_path: Path) -> Path:
    """A writable copy of the toy benchmark: manifest, code and calibration."""
    dest = tmp_path / "toy"
    shutil.copytree(TOY.parent, dest)
    return dest / "manifest.json"


def edit_manifest(manifest: Path, change: Any) -> None:
    data = json.loads(manifest.read_text(encoding="utf-8"))
    change(data)
    manifest.write_text(json.dumps(data), encoding="utf-8")


# -- calibration -----------------------------------------------------------------


@pytest.mark.parametrize("manifest", [TOY, NOTES])
def test_the_bundled_benchmarks_calibrate_with_their_hand_written_answers(
    manifest: Path,
) -> None:
    assert (manifest.parent / "calibration" / "good.json").is_file()
    assert (manifest.parent / "calibration" / "bad.json").is_file()
    assert calibrate(load_target(manifest)) == []


def test_the_calibration_answers_are_outside_what_a_model_is_sent() -> None:
    """Answers with their scores beside the code would be the key, handed over."""
    for manifest in (TOY, NOTES):
        target = load_target(manifest)
        calibration = (manifest.parent / "calibration").resolve()
        assert not calibration.is_relative_to(target.root)


def test_a_decoy_on_a_vulnerability_s_lines_fails_calibration(toy_copy: Path) -> None:
    """The vulnerability wins the tie, so a correct report of the decoy would score."""
    edit_manifest(toy_copy, lambda d: d["decoys"][0].update(lines=[11, 12]))
    problems = calibrate(load_target(toy_copy))
    assert any("D1: a finding exactly on the decoy scores as a true positive" in p
               for p in problems), problems


def test_a_cwe_the_key_does_not_list_is_caught_by_the_good_answers(toy_copy: Path) -> None:
    edit_manifest(toy_copy, lambda d: d["vulnerabilities"][0].update(cwe="CWE-564"))
    problems = calibrate(load_target(toy_copy))
    assert any("good.json" in p for p in problems), problems


def test_a_bad_answer_that_scores_is_caught(toy_copy: Path) -> None:
    bad = toy_copy.parent / "calibration" / "bad.json"
    answers = json.loads(bad.read_text(encoding="utf-8"))
    answers.append(at("app/db.py", 11, 12, cwe="CWE-89").to_dict())
    bad.write_text(json.dumps(answers), encoding="utf-8")
    problems = calibrate(load_target(toy_copy))
    assert any("bad.json scores 1 true positive" in p for p in problems), problems


def test_an_also_location_another_issue_claims_fails_calibration(toy_copy: Path) -> None:
    def add_also(d: dict[str, Any]) -> None:
        # On V1's lines: a report there is credited to V1, never to V2.
        d["vulnerabilities"][1]["also"] = [{"path": "app/db.py", "lines": [11, 12]}]
    edit_manifest(toy_copy, add_also)
    problems = calibrate(load_target(toy_copy))
    assert any("V2: its also-location" in p for p in problems), problems


def test_preflight_and_validate_refuse_a_target_that_does_not_calibrate(
    toy_copy: Path, prices: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    edit_manifest(toy_copy, lambda d: d["decoys"][0].update(lines=[11, 12]))
    matrix = Matrix(name="c", targets=[toy_copy], conditions=["baseline"],
                    models=["fake:m"], tokens_per_run={"baseline": (1, 1)})
    checks = run_checks(matrix, prices, fake=True)
    assert any(c.level == "fail" and "calibration" in c.message for c in checks)

    assert main(["validate", str(toy_copy)]) == 1
    assert "scorer calibration" in capsys.readouterr().out


# -- the quoted code -----------------------------------------------------------------


@pytest.mark.parametrize(("finding", "verdict"), [
    (at("app/db.py", 11, 12, "`return conn.execute(query).fetchone()`"), "quoted_at_location"),
    # A line number copied along with the line.
    (at("app/session.py", 9, 9, "    9  return pickle.loads(base64.b64decode(cookie))"),
     "quoted_at_location"),
    (at("app/db.py", 11, 12, "`return conn.execute(query, (email,)).fetchone()`"),
     "quoted_elsewhere"),
    (at("app/db.py", 11, 12, "`cursor.executescript(user_supplied_sql)`"), "quote_not_in_file"),
    (at("app/db.py", 11, 12, "The username is interpolated into the query, which allows "
                             "an attacker to change it."), "nothing_quoted"),
    (at("app/models.py", 3, 3, "`query = build(username)`"), "no_such_file"),
    (at("../../outside.py", 1, 1, "`import os`"), "no_such_file"),
    # Outside the target's root, though the file exists: not part of the target.
    (at("../manifest.json", 2, 2, '`"id": "toy-webapp",`'), "no_such_file"),
    (at("app/db.py", 400, 401, "`query = build(username)`"), "past_end_of_file"),
    (SecurityFinding(title="t", evidence=["`pickle.loads(cookie)`"]), "no_location"),
])
def test_evidence_verdicts(toy: Target, finding: SecurityFinding, verdict: str) -> None:
    assert check_evidence(finding, toy.root) == verdict


def test_prose_is_not_mistaken_for_a_quote() -> None:
    assert quoted_fragments(["The function uses pickle.loads on a cookie the user controls."]) \
        == []
    assert quoted_fragments(["data = pickle.loads(base64.b64decode(cookie))"]) \
        == ["data = pickle.loads(base64.b64decode(cookie))"]
    assert quoted_fragments(["```python\n  12: x = eval(request.args['q'])\n```"]) \
        == ["x = eval(request.args['q'])"]


@pytest.mark.parametrize(("evidence", "fragments"), [
    # From the 18-file local run: evidence that names a place, then talks about it.
    ("tools.py:672-696 \u2014 run_command implementation with allow-list and metacharacter "
     "refusal but no OS-level isolation", []),
    ("config.py:111 (scope_envelope_forbidden field)", []),
    ("mcp_server.py - no authentication middleware or rate limiting visible in the server", []),
    ("tree_wide_git guard (prevents git state changes but not file overwrites)", []),
    # ... and evidence that names a place, then quotes it.
    ("src/pkg/tools.py:462: regex = re.compile(pattern, re.IGNORECASE)",
     ["regex = re.compile(pattern, re.IGNORECASE)"]),
    ("app\\files.py:10: path = os.path.join(UPLOADS, name)",
     ["path = os.path.join(UPLOADS, name)"]),
    # A quote the model shortened: both sides are still quotes.
    ("httpx.AsyncClient(base_url=self.base_url, headers={...})",
     ["httpx.AsyncClient(base_url=self.base_url, headers={"]),
    # A call is not a filename: nothing is taken off the front of this one.
    ("path = os.path.join(UPLOADS, name)", ["path = os.path.join(UPLOADS, name)"]),
])
def test_a_named_place_is_not_a_quote(evidence: str, fragments: list[str]) -> None:
    assert quoted_fragments([evidence]) == fragments


def test_a_reflowed_quote_is_still_a_quote(tmp_path: Path) -> None:
    """A statement that spans lines in the file, quoted on one line, as models do."""
    (tmp_path / "client.py").write_text(
        "class C:\n    def http(self):\n        return httpx.AsyncClient(\n"
        "            base_url=self.base_url,\n            headers={'a': 'b'}\n        )\n",
        encoding="utf-8")
    finding = at("client.py", 3, 6,
                 "`httpx.AsyncClient(base_url=self.base_url, headers={'a': 'b'})`")
    assert check_evidence(finding, tmp_path) == "quoted_at_location"


# -- which code -------------------------------------------------------------------


def test_the_digest_follows_content_not_line_endings_or_git(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_bytes(b"x = 1\ny = 2\n")
    first = target_digest(tmp_path)
    (tmp_path / "a.py").write_bytes(b"x = 1\r\ny = 2\r\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    assert target_digest(tmp_path) == first
    (tmp_path / "a.py").write_bytes(b"x = 1\ny = 3\n")
    assert target_digest(tmp_path) != first


# -- missed, or never read --------------------------------------------------------


def test_misses_are_split_by_whether_their_file_was_read() -> None:
    target = load_target(NOTES)
    split = attribute_misses(["V1", "V2", "V5"], target.vulnerabilities,
                             ["notes/handlers.py", "notes\\auth.py"])
    # V1 and V5 cross into handlers.py; reading either end counts as reading it.
    assert split == {"never_read": [], "read": ["V1", "V2", "V5"]}
    assert attribute_misses(["V2"], target.vulnerabilities, ["notes/db.py"]) \
        == {"never_read": ["V2"], "read": []}


def test_the_harness_coverage_is_read_from_its_measured_turns() -> None:
    def turn(read: list[str] | None) -> dict[str, Any]:
        body: dict[str, Any] = {"id": "t"}
        if read is not None:
            body["files_read"] = read
        return {"type": "turn_recorded", "payload": {"turn": body}}

    assert files_read([turn(["b.py", "a.py"]), turn(["a.py"]), turn([])]) == ["a.py", "b.py"]
    # A harness from before reads were measured: unknown, not zero.
    assert files_read([turn(None), turn(None)]) is None
    assert files_read([turn([])]) == []


def test_the_baseline_reads_every_source_file(toy: Target) -> None:
    assert BaselineRunner().files_sent(toy) == [
        "app/__init__.py", "app/config.py", "app/db.py", "app/files.py",
        "app/session.py", "app/tools.py",
    ]


# -- a matrix, end to end ---------------------------------------------------------


class Scripted:
    """Finds V1 and V3 every repeat, V2 on the first only; never reads config.py or session.py.

    The V3 finding quotes code that is not in tools.py, and still scores: on the
    right lines, with the right CWE. That is the case the evidence check is for.
    """

    condition = "harness"

    def __init__(self) -> None:
        self.calls = 0

    def run(self, target: Target, route: str, workdir: Path, task: str = "",
            effort: str = "") -> RunResult:
        self.calls += 1
        findings = [at("app/db.py", 11, 12, "`return conn.execute(query).fetchone()`",
                       cwe="CWE-89"),
                    at("app/tools.py", 7, 7, "`os.system(command_line)`", cwe="CWE-78")]
        if self.calls == 1:
            findings.append(at("app/files.py", 10, 11, cwe="CWE-22"))
        read = ["app/db.py", "app/files.py", "app/tools.py"]
        return RunResult(Outcome.OK, findings, Usage(1000, 500),
                         artifacts={"coverage": {"files_read": read}})


@pytest.fixture
def ran(tmp_path: Path, toy_copy: Path, prices: Any) -> Path:
    out = tmp_path / "out"
    matrix = Matrix(name="e", targets=[toy_copy], conditions=["harness"], models=["ollama:m"],
                    repeats=2, tokens_per_run={"harness": (1, 1)})
    run_matrix(matrix, {"harness": Scripted()}, out, prices, progress=quiet)
    return out


def test_each_cell_records_the_code_it_ran_on_and_what_it_read(ran: Path, toy_copy: Path) -> None:
    records = [json.loads(line) for line in
               (ran / "ledger.jsonl").read_text(encoding="utf-8").splitlines()]
    digest = target_digest(load_target(toy_copy).root)
    assert all(r["extra"]["target_digest"] == digest for r in records)
    assert all(r["extra"]["files_read"] == 3 for r in records)
    assert all((ran / Path(r["findings_path"]).parent / "coverage.json").is_file()
               for r in records)


def test_the_report_shows_consistency_evidence_and_coverage(ran: Path) -> None:
    summary = summarise(load_cells(ran))

    (consistency,) = summary["consistency"]
    assert consistency["every"] == ["V1", "V3"]
    assert consistency["some"] == ["V2"] and consistency["found"]["V2"] == 1
    assert consistency["never"] == ["V4", "V5"]

    (evidence,) = summary["evidence"]
    # Per repeat: db.py quoted at its lines, tools.py quoting code not in it;
    # the first repeat's files.py finding quotes nothing.
    assert evidence["verdicts"]["quoted_at_location"] == 2
    assert evidence["verdicts"]["quote_not_in_file"] == 2
    assert evidence["verdicts"]["nothing_quoted"] == 1

    (coverage,) = summary["coverage"]
    # V4 (config.py) and V5 (session.py) were never read, in either repeat.
    assert coverage["missed_never_read"] == 4
    assert coverage["missed_read"] == 1          # V2, on the repeat that did not report it
    assert coverage["files_read"]["median"] == 3

    text = render_markdown(summary, title="t", stated_only=False)
    assert "## Consistency across repeats" in text and "V2 (1/2)" in text
    assert "quote not in file" in text
    assert "## Missed, or never read?" in text
    assert "Warning:** the code of the target has changed" not in text


def test_the_report_warns_when_the_code_changed_after_the_cells_ran(
    ran: Path, toy_copy: Path
) -> None:
    db = toy_copy.parent / "src" / "app" / "db.py"
    db.write_text(db.read_text(encoding="utf-8") + "\n# edited after the run\n",
                  encoding="utf-8")
    summary = summarise(load_cells(ran))
    assert len(summary["changed_targets"]) == 2
    assert "the code of the target has changed" in render_markdown(
        summary, title="t", stated_only=False)


def test_a_baseline_cell_records_that_it_read_everything(
    tmp_path: Path, toy_copy: Path, prices: Any
) -> None:
    """Its coverage is what it sends, so every miss is a miss in a file it read."""

    class Silent(BaselineRunner):
        def run(self, target: Target, route: str, workdir: Path, task: str = "",
                effort: str = "") -> RunResult:
            return RunResult(Outcome.OK, [], Usage(1000, 500))

    out = tmp_path / "out"
    matrix = Matrix(name="b", targets=[toy_copy], conditions=["baseline"], models=["ollama:m"],
                    tokens_per_run={"baseline": (1, 1)})
    run_matrix(matrix, {"baseline": Silent()}, out, prices, progress=quiet)

    (coverage,) = summarise(load_cells(out))["coverage"]
    assert coverage["files_read"]["median"] == 6
    assert coverage["missed_never_read"] == 0 and coverage["missed_read"] == 5
