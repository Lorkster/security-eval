"""The seam between the harness and us: its published command line, read back.

The pinning tests run the real `supervisor` CLI, so they skip where the harness
is not installed. Skipped per test, not per module: a module-level skip would
also skip the tests here that need nothing installed.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from security_eval.budget import Usage
from security_eval.finding import Location
from security_eval.runners.harness import (
    HarnessError,
    HarnessRunner,
    from_export,
    refusals,
    route_variable,
    stop_reasons,
    usage_from_events,
)

needs_cli = pytest.mark.skipif(shutil.which("supervisor") is None,
                               reason="supervisor-harness CLI not installed")


def record(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "fnd_1", "lens": "security", "severity": "high", "title": "SQL injection",
        "detail": "username reaches the query", "path": "app/db.py", "line_start": 11,
        "line_end": 12, "cwe": "CWE-89", "confidence": 0.8,
        "evidence": ["app/db.py:11 builds the query with an f-string"],
        "recommendation": "parameterise", "status": "open",
    }
    base.update(overrides)
    return base


# -- findings ----------------------------------------------------------------------


def test_a_stated_location_is_taken_from_the_export_fields() -> None:
    f = from_export(record(), "anthropic:m")
    assert f.location == Location("app/db.py", 11, 12)
    assert f.location_source == "stated"
    assert (f.cwe, f.severity, f.source) == ("CWE-89", "high", "harness:anthropic:m:security")


def test_with_no_stated_location_one_is_recovered_from_evidence_and_says_so() -> None:
    f = from_export(record(path="", line_start=0, line_end=0), "r")
    assert f.location == Location("app/db.py", 11, 11)
    assert f.location_source == "recovered"


def test_with_nothing_to_go_on_a_finding_is_kept_unanchored() -> None:
    f = from_export(record(path="", line_start=0, evidence=[], detail="auth is weak", cwe=""),
                    "r")
    assert f.location is None
    assert f.location_source == ""
    assert f.cwe is None


# -- the log ---------------------------------------------------------------------


def events(*items: dict[str, Any]) -> list[dict[str, Any]]:
    return list(items)


def turn(turn_id: str, **usage: int) -> dict[str, Any]:
    return {"type": "turn_recorded", "payload": {"turn": {"id": turn_id, "usage": usage}}}


def test_usage_counts_every_turn_once_and_every_supervisor_call() -> None:
    log = events(
        turn("t1", input_tokens=100, output_tokens=10, cache_read_tokens=50),
        turn("t1", input_tokens=100, output_tokens=10, cache_read_tokens=50),  # re-reported
        turn("t2", input_tokens=200, output_tokens=20, cache_write_tokens=5),
        {"type": "usage_recorded", "payload": {"stage": "synthesis",
                                                "usage": {"input_tokens": 1000,
                                                          "output_tokens": 100}}},
        {"type": "note", "payload": {"text": "tools called"}},
    )
    assert usage_from_events(log) == Usage(1300, 130, 50, 5)


def test_refusals_are_read_with_their_agent_and_category() -> None:
    log = events(
        {"type": "note", "actor": "agt_1",
         "payload": {"text": "agent refused by the model", "refusal": True, "category": "cyber"}},
        {"type": "note", "actor": "agt_2", "payload": {"text": "agent failed: HTTP 500"}},
    )
    assert refusals(log) == [{"actor": "agt_1", "category": "cyber"}]


def test_stop_reasons_are_kept_in_the_harness_s_own_words() -> None:
    log = events(
        {"type": "note", "payload": {"text": "agent `a1` finished (stop): drift score 0.86 "
                                              "after 1 correction(s); 0/4 objectives"}},
        {"type": "note", "payload": {"text": "agent `a2` finished (accept): objectives addressed"}},
    )
    assert stop_reasons(log) == ["drift score 0.86 after 1 correction(s); 0/4 objectives"]


def test_route_variables_are_named_as_the_harness_reads_them() -> None:
    assert route_variable("analysis.security") == "SUPERVISOR_ROUTE_ANALYSIS__SECURITY"
    assert route_variable("drift") == "SUPERVISOR_ROUTE_DRIFT"


# -- pinning, against the real CLI ---------------------------------------------------


@needs_cli
def test_a_lens_route_in_a_config_file_is_overridden_and_the_pin_verified(
    tmp_path: Path,
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "supervisor.config.json").write_text(
        json.dumps({"routing": {"analysis.security": "ollama:elsewhere"}}), encoding="utf-8")

    env = HarnessRunner().pinned_env("ollama:under-test", tmp_path / "home", tree)

    assert env["SUPERVISOR_ROUTE_ANALYSIS__SECURITY"] == "ollama:under-test"
    assert env["SUPERVISOR_HOME"] == str(tmp_path / "home")


def test_a_stage_that_will_not_pin_stops_the_cell_before_it_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = HarnessRunner()
    monkeypatch.setattr(runner, "_routing", lambda env, tree: {"drift": "ollama:elsewhere"})

    with pytest.raises(HarnessError, match="drift -> ollama:elsewhere"):
        runner.pinned_env("ollama:under-test", tmp_path, tmp_path)


def test_effort_is_written_to_the_cells_own_trusted_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Effort reaches every stage of the harness run, and only this one."""
    from security_eval.manifest import load_target

    from .conftest import TOY

    runner = HarnessRunner(supervisor="definitely-not-installed-xyz")
    monkeypatch.setattr(runner, "pinned_env", lambda route, home, tree: {})
    workdir = tmp_path / "cell"
    workdir.mkdir()

    result = runner.run(load_target(TOY), "anthropic:claude-sonnet-5-5", workdir, effort="high")

    written = json.loads((workdir / "home" / "config.json").read_text(encoding="utf-8"))
    assert written == {"providers": {"anthropic": {"params": {"output_config":
                                                              {"effort": "high"}}}}}
    assert result.outcome.value == "error", "the fake CLI is missing, so the run itself fails"

    from security_eval.runners.harness import neutral_tree

    assert neutral_tree(workdir).is_dir(), "the copy is made under the neutral path"
    assert not (workdir / "tree").exists(), "and not under the cell's own, target-named one"
