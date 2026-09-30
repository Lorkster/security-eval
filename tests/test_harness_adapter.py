"""The seam between the harness and us, tested against the real harness types.

Skipped per test, not per module, when the harness is not installed: a
module-level skip would also skip anything here that does not need it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from security_eval.finding import Location

try:
    import supervisor_harness  # noqa: F401
    HAVE_HARNESS = True
except ImportError:
    HAVE_HARNESS = False
needs_harness = pytest.mark.skipif(not HAVE_HARNESS, reason="supervisor-harness not installed")


@needs_harness
def test_a_harness_finding_keeps_its_place_and_cwe(tmp_path: Path) -> None:
    from supervisor_harness.models import Finding, Severity

    from security_eval.runners.harness import from_harness_finding

    tree = tmp_path / "tree"
    finding = Finding(
        lens="security", severity=Severity.HIGH, title="SQL injection in find_user",
        detail="username reaches the query unescaped",
        evidence=[f"{tree / 'app' / 'db.py'}:11-12 builds the query with an f-string"],
        tags=["injection", "cwe-89"], confidence=0.8,
    )
    ours = from_harness_finding(finding, tree, "anthropic:m")
    assert ours.location == Location("app/db.py", 11, 12), "the per-cell prefix is stripped"
    assert ours.cwe == "CWE-89"
    assert ours.severity == "high"
    assert ours.source == "harness:anthropic:m:security"


@needs_harness
def test_a_harness_finding_with_no_place_is_kept_unanchored(tmp_path: Path) -> None:
    from supervisor_harness.models import Finding

    from security_eval.runners.harness import from_harness_finding

    ours = from_harness_finding(Finding(title="auth is weak", detail="in general"),
                                tmp_path, "r")
    assert ours.location is None


@needs_harness
def test_every_known_stage_is_pinned_to_the_model_under_test(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from supervisor_harness.config import KNOWN_STAGES

    from security_eval.runners.harness import pinned_env, unpinned_stages

    monkeypatch.setenv("SUPERVISOR_ROUTE_DRIFT", "ollama:something-else")
    env = pinned_env("anthropic:m", tmp_path / "home")
    for stage in KNOWN_STAGES:
        assert env[f"SUPERVISOR_ROUTE_{stage.upper()}"] == "anthropic:m"
    assert env["SUPERVISOR_HOME"] == str(tmp_path / "home")

    # A workspace config that routes a lens elsewhere is caught, not ignored.
    (tmp_path / "supervisor.config.json").write_text(
        '{"routing": {"analysis.security": "ollama:elsewhere"}}', encoding="utf-8")
    assert unpinned_stages(tmp_path, env, "anthropic:m") == [
        "analysis.security -> ollama:elsewhere"]
