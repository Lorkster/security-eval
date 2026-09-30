"""Findings, manifests and SARIF."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from security_eval.finding import Location, SecurityFinding, Verdict, find_cwe, find_location
from security_eval.manifest import ManifestError, Target, load_target
from security_eval.runners.baseline import parse_findings
from security_eval.sarif import from_sarif, to_sarif


def test_the_toy_manifest_matches_its_code(toy: Target) -> None:
    assert len(toy.vulnerabilities) == 5
    assert len(toy.decoys) == 5


def test_nothing_in_the_toy_source_names_the_answers(toy: Target) -> None:
    """The model reads `src/`. A comment saying what is planted gives the answer away."""
    for path in toy.root.rglob("*.py"):
        text = path.read_text(encoding="utf-8").lower()
        for tell in ("vulnerab", "planted", "benchmark", "cwe", "decoy", "insecure"):
            assert tell not in text, f"{path.name} contains {tell!r}"


def test_a_manifest_pointing_past_the_end_of_a_file_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "manifest.json").write_text(json.dumps({
        "root": "src",
        "vulnerabilities": [{"id": "V1", "cwe": 89, "path": "a.py", "lines": [5, 6]}],
    }), encoding="utf-8")
    with pytest.raises(ManifestError, match="past the end"):
        load_target(tmp_path / "manifest.json")


def test_a_vulnerability_without_a_cwe_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "manifest.json").write_text(json.dumps({
        "vulnerabilities": [{"id": "V1", "path": "a.py", "lines": [1, 1]}],
    }), encoding="utf-8")
    with pytest.raises(ManifestError, match="needs a CWE"):
        load_target(tmp_path / "manifest.json")


@pytest.mark.parametrize(("text", "expected"), [
    ("see `app/db.py:11-12` for the query", Location("app/db.py", 11, 12)),
    ("app/tools.py:7", Location("app/tools.py", 7, 7)),
    ("C:\\x\\app\\files.py:10", Location("C:/x/app/files.py", 10, 10)),
    ("./app\\db.py:3", Location("app/db.py", 3, 3)),
    ("step 3:4 of the plan", None),
])
def test_location_recovery(text: str, expected: Location | None) -> None:
    assert find_location(text) == expected


def test_cwe_recovery() -> None:
    assert find_cwe("no id here", "this is cwe_89 territory") == "CWE-89"
    assert find_cwe("CWE-0798") == "CWE-798"
    assert find_cwe("nothing") is None


def test_findings_round_trip_through_json() -> None:
    original = SecurityFinding("t", cwe="CWE-22", location=Location("a.py", 1, 2),
                               triage=Verdict.NEEDS_INFO, evidence=["e"], source="s")
    assert SecurityFinding.from_dict(json.loads(json.dumps(original.to_dict()))) == original


def test_sarif_round_trip_keeps_what_the_scorer_needs() -> None:
    findings = [SecurityFinding("SQLi", cwe="CWE-89", location=Location("app/db.py", 11, 12),
                                severity="high"),
                SecurityFinding("no place", cwe=None)]
    back = from_sarif(to_sarif(findings))
    assert [(b.cwe, b.location, b.severity) for b in back] == [
        ("CWE-89", Location("app/db.py", 11, 12), "high"),
        (None, None, "medium"),
    ]


def test_sarif_import_reads_cwe_from_rule_tags() -> None:
    doc = {"runs": [{
        "tool": {"driver": {"name": "semgrep", "rules": [
            {"id": "py.sqli", "properties": {"tags": ["CWE-89: SQL Injection"]}}]}},
        "results": [{"ruleId": "py.sqli", "level": "error", "message": {"text": "tainted"},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": "app/db.py"},
                         "region": {"startLine": 11}}}]}],
    }]}
    (finding,) = from_sarif(doc)
    assert (finding.cwe, finding.location, finding.source) == (
        "CWE-89", Location("app/db.py", 11, 11), "semgrep")


def test_baseline_answers_are_parsed_or_rejected_never_guessed() -> None:
    good = '```json\n{"findings": [{"title": "t", "cwe": "89", "location": "a.py:3-4", ' \
           '"severity": "HIGH", "confidence": 3}]}\n```'
    (finding,) = parse_findings(good, "r") or []
    assert (finding.cwe, finding.location, finding.severity, finding.confidence) == (
        "CWE-89", Location("a.py", 3, 4), "high", 1.0)
    assert parse_findings("I could not find anything.", "r") is None
    assert parse_findings('{"results": []}', "r") is None
    assert parse_findings('{"findings": []}', "r") == []


def test_every_prompt_keeps_the_defensive_boundary() -> None:
    """Find, explain, fix. A prompt that drops this line changes what is being studied."""
    from security_eval.runners.base import TASK, load_prompts

    prompts = load_prompts()
    assert prompts["plain"] == TASK, "the default in code and the frozen file must agree"
    for name, text in prompts.items():
        assert "do not write exploits" in text.lower(), name
