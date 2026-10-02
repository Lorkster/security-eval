"""The harness condition: one supervised run of supervisor-harness, in report mode.

Everything here goes through the harness's published command line; nothing
imports its internals. The run is started with ``supervisor run --json``, and
read back with three commands whose output is documented:

* ``supervisor findings --json`` -- each finding with its location and CWE as
  fields, as the agent stated them;
* ``supervisor status --json`` -- the phase, and how each agent ended;
* ``supervisor events --json`` -- the log itself, for token usage (every turn,
  and every call the supervisor made on its own behalf) and refusal notes.

Each cell gets a fresh copy of the target and its own empty ``SUPERVISOR_HOME``.
The copy is so nothing the run writes can reach the next cell's tree. The empty
home is so the harness's cross-run lessons library -- a feature, in normal use
-- cannot carry what one cell learned into the next. That would be a leak
between supposedly independent samples.

Every stage is routed to the model under test through environment variables,
checked against ``supervisor providers --json``, and the run refuses to start
if any stage would still resolve elsewhere (a lens-specific route in your own
``~/.supervisor/config.json``, say). A cell that silently ran part of its work
on a different model would be mislabelled data.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from ..budget import Usage
from ..finding import SecurityFinding, locate, normalise_cwe, normalise_severity
from ..ledger import Outcome
from ..manifest import Target
from .base import TASK, RunResult, effort_params

#: Stages that always exist, whatever `supervisor providers` lists. A route set
#: for each makes the pin independent of which stages a given version reports.
BASE_STAGES = ("default", "supervisor", "planning", "analysis", "synthesis",
               "execution", "verification", "drift", "improvement")


class HarnessError(RuntimeError):
    pass


class HarnessRunner:
    condition = "harness"

    def __init__(self, supervisor: str = "supervisor", timeout_seconds: float = 3600) -> None:
        self.supervisor = supervisor
        self.timeout = timeout_seconds

    def run(self, target: Target, route: str, workdir: Path, task: str = TASK,
            effort: str = "") -> RunResult:
        tree = neutral_tree(workdir)
        home = workdir / "home"
        if tree.exists():
            shutil.rmtree(tree, ignore_errors=True)
        shutil.copytree(target.root, tree)
        home.mkdir(parents=True)
        try:
            snapshot(tree)
        except subprocess.CalledProcessError as exc:
            return RunResult(Outcome.ERROR, detail=f"could not snapshot the tree: {exc}")

        params = effort_params(route, effort)
        if params:
            # The cell's home is a trusted config location, so provider params
            # set here reach every stage of this run and no other.
            provider = route.split(":", 1)[0]
            (home / "config.json").write_text(
                json.dumps({"providers": {provider: {"params": params}}}), encoding="utf-8"
            )

        try:
            env = self.pinned_env(route, home, tree)
        except HarnessError as exc:
            return RunResult(Outcome.ERROR, detail=str(exc))

        started = time.monotonic()
        try:
            proc = self._cli(["run", task, "--mode", "report", "--backend", "autonomous",
                              "--yes", "--json", "-w", str(tree)], env, timeout=self.timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return RunResult(Outcome.ERROR, detail=f"supervisor did not complete: {exc}")
        seconds = time.monotonic() - started

        note = ""
        try:
            response: dict[str, Any] = json.loads(proc.stdout)
            run_id = str(response["run_id"])
        except (json.JSONDecodeError, KeyError, TypeError):
            # The run is on disk even when the CLI failed to report it. Read it
            # back rather than discard work that was done and paid for.
            runs = sorted(p.name for p in (home / "runs").glob("*") if p.is_dir())
            if len(runs) != 1:
                return RunResult(Outcome.ERROR, seconds=seconds,
                                 detail=f"exit {proc.returncode}; stderr: {proc.stderr[-500:]}")
            run_id, response = runs[0], {}
            note = f"CLI output unreadable (exit {proc.returncode}), read back by id; "

        try:
            exported = self._json(["findings", run_id, "--json", "-w", str(tree)], env)
            status = self._json(["status", run_id, "--json", "-w", str(tree)], env)
            events = self._json(["events", run_id, "--json", "-w", str(tree)], env)
        except HarnessError as exc:
            return RunResult(Outcome.ERROR, seconds=seconds, detail=f"{note}{exc}")

        findings = [from_export(f, route) for f in exported.get("findings", [])]
        usage = usage_from_events(events.get("events", []))
        refused = refusals(events.get("events", []))
        agents = status.get("agents", [])
        stopped = sum(1 for a in agents if a.get("status") == "stopped")
        analysis = [a for a in agents if a.get("kind") == "analysis"]
        phase = str(status.get("phase", ""))

        if analysis and len({r["actor"] for r in refused}) >= len(analysis):
            outcome = Outcome.REFUSED
        elif response.get("action") == "failed" or phase == "failed":
            outcome = Outcome.ERROR
        elif stopped:
            outcome = Outcome.HARNESS_STOPPED
        elif phase != "complete":
            outcome = Outcome.ERROR
            note += f"run ended in phase {phase!r}; "
        else:
            outcome = Outcome.OK
        summary = response.get("ledger") or response.get("message", "")
        read = files_read(events.get("events", []))
        return RunResult(
            outcome, findings, usage, seconds,
            artifacts={} if read is None else {"coverage": {"files_read": read}},
            detail=f"{note}run {run_id}: {summary}"[:500],
            extra={
                "run_id": run_id,
                "agents": len(agents),
                "agents_stopped": stopped,
                "agents_refused": len({r["actor"] for r in refused}),
                "refusal_categories": sorted({r["category"] for r in refused if r["category"]}),
                # Why each stopped agent was stopped, in the harness's own words:
                # "harness_stopped" alone cannot tell a supervisor stopping a model
                # that never answered from one stopping an agent that was working.
                "stop_reasons": stop_reasons(events.get("events", [])),
                "effort": effort if params else "",
                "harness_home": str(home),
                "harness_tree": str(tree),
            },
        )

    # -- the command line ------------------------------------------------------

    def _cli(self, args: list[str], env: dict[str, str],
             timeout: float = 120) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed argv, no shell
            [self.supervisor, *args], env=env, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, check=False,
        )

    def _json(self, args: list[str], env: dict[str, str]) -> dict[str, Any]:
        try:
            proc = self._cli(args, env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HarnessError(f"`supervisor {args[0]}` did not complete: {exc}") from exc
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise HarnessError(
                f"`supervisor {args[0]}` gave no JSON (exit {proc.returncode}): "
                f"{proc.stderr[-300:]}"
            ) from exc
        if not isinstance(data, dict):
            raise HarnessError(f"`supervisor {args[0]}` gave {type(data).__name__}, not an object")
        return data

    def pinned_env(self, route: str, home: Path, tree: Path) -> dict[str, str]:
        """An environment routing every stage to ``route``, checked by the harness itself."""
        env = {k: v for k, v in os.environ.items() if not k.startswith("SUPERVISOR_ROUTE_")}
        env["SUPERVISOR_HOME"] = str(home)
        # The harness prints non-ASCII; a Windows pipe defaults to cp1252.
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        for stage in BASE_STAGES:
            env[route_variable(stage)] = route

        # Any stage the harness still reports elsewhere -- a lens route from a
        # config file, a stage this list does not know -- gets its own variable,
        # and then the whole table is checked again.
        for stage, value in self._routing(env, tree).items():
            if value != route:
                env[route_variable(stage)] = route
        unpinned = sorted(f"{stage} -> {value}"
                          for stage, value in self._routing(env, tree).items() if value != route)
        if unpinned:
            raise HarnessError("routing is not pinned to the model under test: "
                               + ", ".join(unpinned))
        return env

    def _routing(self, env: dict[str, str], tree: Path) -> dict[str, str]:
        routing = self._json(["providers", "--json", "-w", str(tree)], env).get("routing", {})
        return {str(k): str(v) for k, v in routing.items()} if isinstance(routing, dict) else {}


def neutral_tree(workdir: Path) -> Path:
    """Where the target's copy goes: a path that says nothing about the target.

    The harness shows its agents the workspace path, and the cell's own
    directory is named after the target -- which for a time-split benchmark
    could carry an advisory id. Named by a hash instead, outside the run.
    """
    digest = hashlib.sha256(str(workdir.resolve()).encode("utf-8")).hexdigest()[:12]
    return Path(tempfile.gettempdir()) / "security-eval-work" / digest / "repo"


def route_variable(stage: str) -> str:
    """``analysis.security`` -> ``SUPERVISOR_ROUTE_ANALYSIS__SECURITY``, as the harness reads it."""
    return "SUPERVISOR_ROUTE_" + stage.upper().replace(".", "__")


def snapshot(tree: Path) -> None:
    """Make the copy a one-commit repository: the harness measures against a baseline commit."""
    git = shutil.which("git")
    if git is None:
        return
    for argv in (["init", "-q"], ["add", "-A"],
                 ["-c", "user.name=security-eval", "-c", "user.email=security-eval@localhost",
                  "commit", "-q", "-m", "benchmark snapshot"]):
        subprocess.run([git, *argv], cwd=tree, check=True, capture_output=True)  # noqa: S603


def from_export(record: dict[str, Any], route: str) -> SecurityFinding:
    """One record of ``supervisor findings --json``, as our finding.

    The export's ``path``/``line_start``/``line_end`` are the location the agent
    stated. Only when it stated none is one recovered from its evidence -- the
    same rule the baseline applies, recorded in ``location_source``.
    """
    stated = ""
    if record.get("path") and record.get("line_start"):
        start = int(record["line_start"])
        end = int(record.get("line_end") or start)
        stated = f"{record['path']}:{start}-{max(start, end)}"
    evidence = [str(e) for e in record.get("evidence") or []]
    location, source = locate(stated, *evidence, str(record.get("detail", "")))
    return SecurityFinding(
        title=str(record.get("title", "")),
        cwe=normalise_cwe(record.get("cwe")) if record.get("cwe") else None,
        location=location,
        location_source=source,
        severity=normalise_severity(record.get("severity")),
        confidence=float(record.get("confidence") or 0.5),
        detail=str(record.get("detail", "")),
        evidence=evidence,
        recommendation=str(record.get("recommendation", "")),
        source=f"harness:{route}:{record.get('lens', '')}",
        id=str(record.get("id", "")),
    )


def usage_from_events(events: list[dict[str, Any]]) -> Usage:
    """The whole run's spend, from the log: every turn, and every supervisor-side call.

    A turn re-reported under the same id is counted once, as the harness's own
    fold does.
    """
    total = Usage()
    seen_turns: set[str] = set()
    for event in events:
        payload = event.get("payload") or {}
        raw: Any = None
        if event.get("type") == "turn_recorded":
            turn = payload.get("turn") or {}
            if turn.get("id") in seen_turns:
                continue
            seen_turns.add(str(turn.get("id")))
            raw = turn.get("usage")
        elif event.get("type") == "usage_recorded":
            raw = payload.get("usage")
        if isinstance(raw, dict):
            total = total + Usage(
                int(raw.get("input_tokens") or 0), int(raw.get("output_tokens") or 0),
                int(raw.get("cache_read_tokens") or 0), int(raw.get("cache_write_tokens") or 0),
            )
    return total


def files_read(events: list[dict[str, Any]]) -> list[str] | None:
    """Every file any agent opened, as the harness measured it; ``None`` if it did not.

    ``files_read`` on a recorded turn is measured by the harness's tool loop,
    not reported by the agent. A harness from before it was measured has no
    such field on any turn, and its coverage is unknown -- not zero.
    """
    seen: set[str] = set()
    measured = False
    for event in events:
        if event.get("type") != "turn_recorded":
            continue
        turn = (event.get("payload") or {}).get("turn") or {}
        if "files_read" in turn:
            measured = True
            seen.update(str(p) for p in turn.get("files_read") or [])
    return sorted(seen) if measured else None


def stop_reasons(events: list[dict[str, Any]]) -> list[str]:
    """The reason the harness gave for each agent it stopped."""
    out = []
    for event in events:
        text = str((event.get("payload") or {}).get("text", ""))
        if event.get("type") == "note" and "finished (stop):" in text:
            out.append(text.split("finished (stop):", 1)[1].strip())
    return out


def refusals(events: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Every refusal the harness recorded: which agent, and the category given."""
    out = []
    for event in events:
        payload = event.get("payload") or {}
        if event.get("type") == "note" and payload.get("refusal"):
            out.append({"actor": str(event.get("actor", "")),
                        "category": str(payload.get("category") or "")})
    return out
