"""The harness condition: one supervised run of supervisor-harness, in report mode.

Each cell gets a fresh copy of the target and its own empty ``SUPERVISOR_HOME``.
The copy is so nothing the run writes can reach the next cell's tree. The empty
home is so the harness's cross-run lessons library -- a feature, in normal use
-- cannot carry what one cell learned into the next. That would be a leak
between supposedly independent samples.

Every stage is routed to the model under test through environment variables,
and the run refuses to start if any stage would still resolve elsewhere (for
instance a lens-specific route in your own ``~/.supervisor/config.json``). A
cell that silently ran part of its work on a different model would be
mislabelled data.

Findings are read by folding the run's event log through the harness's own
store (`_harness_findings`). That is the harness's internal state, not a
published interface, and it is the one place to change when prerequisite P3
(a structured findings export) lands.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from ..budget import Usage
from ..finding import SecurityFinding, find_cwe, find_location, normalise_severity
from ..ledger import Outcome
from ..manifest import Target
from .base import TASK, RunResult


class HarnessRunner:
    condition = "harness"

    def __init__(self, supervisor: str = "supervisor", timeout_seconds: float = 3600) -> None:
        self.supervisor = supervisor
        self.timeout = timeout_seconds

    def run(self, target: Target, route: str, workdir: Path, task: str = TASK) -> RunResult:
        tree = workdir / "tree"
        home = workdir / "home"
        shutil.copytree(target.root, tree)
        home.mkdir(parents=True)
        try:
            snapshot(tree)
        except subprocess.CalledProcessError as exc:
            return RunResult(Outcome.ERROR, detail=f"could not snapshot the tree: {exc}")

        env = pinned_env(route, home)
        unpinned = unpinned_stages(tree, env, route)
        if unpinned:
            return RunResult(
                Outcome.ERROR,
                detail="routing is not pinned to the model under test: " + ", ".join(unpinned),
            )

        started = time.monotonic()
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [self.supervisor, "run", task, "--mode", "report", "--backend", "autonomous",
                 "--yes", "--json", "-w", str(tree)],
                env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=self.timeout, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return RunResult(Outcome.ERROR, detail=f"supervisor did not complete: {exc}")
        seconds = time.monotonic() - started

        note = ""
        try:
            response = json.loads(proc.stdout)
            run_id = str(response["run_id"])
        except (json.JSONDecodeError, KeyError, TypeError):
            # The run is on disk even when the CLI failed to report it -- the
            # first real run here died printing its JSON on a cp1252 console,
            # after the work was done and paid for. Read it from the store
            # rather than discard it, and say so.
            runs = sorted(p.name for p in (home / "runs").glob("*") if p.is_dir())
            if len(runs) != 1:
                return RunResult(
                    Outcome.ERROR, seconds=seconds,
                    detail=f"exit {proc.returncode}; stderr: {proc.stderr[-500:]}",
                )
            run_id, response = runs[0], {}
            note = f"CLI output unreadable (exit {proc.returncode}), read from the store; "

        findings, usage, stopped, phase = _harness_findings(home, run_id, tree, route)
        if response.get("action") == "failed" or phase == "failed":
            outcome = Outcome.ERROR
        elif stopped:
            outcome = Outcome.HARNESS_STOPPED
        elif phase != "complete":
            outcome = Outcome.ERROR
            note += f"run ended in phase {phase!r}; "
        else:
            outcome = Outcome.OK
        summary = response.get("ledger") or response.get("message", "")
        return RunResult(
            outcome, findings, usage, seconds,
            detail=f"{note}run {run_id}: {summary}"[:500],
            extra={"run_id": run_id, "agents_stopped": stopped, "harness_home": str(home)},
        )


def snapshot(tree: Path) -> None:
    """Make the copy a one-commit repository: the harness measures against a baseline commit."""
    git = shutil.which("git")
    if git is None:
        return
    for argv in (["init", "-q"], ["add", "-A"],
                 ["-c", "user.name=security-eval", "-c", "user.email=security-eval@localhost",
                  "commit", "-q", "-m", "benchmark snapshot"]):
        subprocess.run([git, *argv], cwd=tree, check=True, capture_output=True)  # noqa: S603


def pinned_env(route: str, home: Path) -> dict[str, str]:
    from supervisor_harness.config import KNOWN_STAGES

    env = {k: v for k, v in os.environ.items() if not k.startswith("SUPERVISOR_ROUTE_")}
    env["SUPERVISOR_HOME"] = str(home)
    # The harness prints non-ASCII text; a Windows pipe defaults to cp1252 and
    # the CLI dies on the first arrow it prints.
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    for stage in KNOWN_STAGES:
        env[f"SUPERVISOR_ROUTE_{stage.upper()}"] = route
    return env


def unpinned_stages(tree: Path, env: dict[str, str], route: str) -> list[str]:
    """Every configured route that would not resolve to ``route`` under ``env``."""
    from supervisor_harness.config import load_config

    saved = dict(os.environ)
    try:
        os.environ.clear()
        os.environ.update(env)
        config = load_config(tree)
    finally:
        os.environ.clear()
        os.environ.update(saved)
    return sorted(f"{stage} -> {value}"
                  for stage, value in config.routing.items() if value != route)


def _harness_findings(
    home: Path, run_id: str, tree: Path, route: str
) -> tuple[list[SecurityFinding], Usage, int, str]:
    from supervisor_harness.models import AgentStatus
    from supervisor_harness.store.runstore import RunStore

    with RunStore(home) as store:
        state = store.open(run_id).state
    total = state.total_usage()
    stopped = sum(1 for a in state.agents.values() if a.status is AgentStatus.STOPPED)
    findings = [from_harness_finding(f, tree, route) for f in state.findings]
    return findings, Usage(total.input_tokens, total.output_tokens), stopped, str(state.phase)


def from_harness_finding(finding: Any, tree: Path, route: str) -> SecurityFinding:
    """Map one harness `Finding` onto ours.

    The harness keeps location and CWE only inside free text -- tags, title,
    detail, evidence -- so both are recovered by pattern. A finding whose place
    cannot be recovered is kept, unanchored; the scorer counts those
    separately, because "found something, could not say where" is a result.
    """
    evidence = [str(e) for e in finding.evidence]
    texts = [*evidence, str(finding.detail), str(finding.title)]
    location = find_location(*[_relative(t, tree) for t in texts])
    return SecurityFinding(
        title=str(finding.title),
        cwe=find_cwe(*[str(t) for t in finding.tags], *texts),
        location=location,
        severity=normalise_severity(str(finding.severity)),
        confidence=float(finding.confidence),
        detail=str(finding.detail),
        evidence=evidence,
        recommendation=str(finding.recommendation),
        source=f"harness:{route}:{finding.lens}",
        id=str(finding.id),
    )


def _relative(text: str, tree: Path) -> str:
    """Strip the per-cell tree prefix, so an absolute path compares as a relative one."""
    out = text
    for prefix in {str(tree), tree.as_posix(), str(tree.resolve()), tree.resolve().as_posix()}:
        out = out.replace(prefix + os.sep, "").replace(prefix + "/", "")
    return out
