"""Running a target's tests where they cannot reach anything (RQ8).

Fix verification runs code: the target's own, a model's patch to it and a
model's test of it. None of that runs on the host. Each run is a fresh
container with:

* no network (``--network none``), so a test cannot fetch anything or reach
  anything;
* a read-only root filesystem and the target's tree mounted read-only, with
  only ``/tmp`` and the results directory writable;
* no capabilities, no privilege escalation, and caps on memory, CPU and the
  number of processes;
* a wall-clock timeout, after which the container is killed.

The tree is a copy made for this one run, so nothing a run does can reach the
benchmark or the next run. Results come back as a JUnit XML report, the one
format that separates a test that *failed* (an assertion did not hold) from one
that *errored* (it could not run) -- the difference between a regression test
that detects the flaw and one that is merely broken.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

#: JUnit reports larger than this are not read.
MAX_REPORT_BYTES = 5_000_000
#: Exit codes meaning the container itself failed, not the tests in it:
#: 125 the engine could not run it, 126/127 the command was not runnable.
ENGINE_FAILURES = frozenset({125, 126, 127})


@dataclass
class Execution:
    exit_code: int | None
    output: str = ""
    timed_out: bool = False
    junit: str | None = None
    #: Set when the run says nothing about the code: no engine, no image, a
    #: command missing from the image. Retried by the next `verify`.
    infra_error: str = ""


@dataclass
class TestReport:
    """What a JUnit report says, per test case."""

    #: test id -> "passed" | "failed" | "error" | "skipped"
    cases: dict[str, str] = field(default_factory=dict)
    messages: dict[str, str] = field(default_factory=dict)

    def with_status(self, status: str) -> list[str]:
        return [case for case, s in self.cases.items() if s == status]

    def counts(self) -> dict[str, int]:
        out = {"passed": 0, "failed": 0, "error": 0, "skipped": 0}
        for status in self.cases.values():
            out[status] += 1
        return out


def parse_junit(text: str | None) -> TestReport | None:
    """The report, or ``None`` if there is none or it is not JUnit XML."""
    if not text:
        return None
    try:
        # The sandbox's own report, size-capped by the reader.
        root = ET.fromstring(text)  # noqa: S314
    except ET.ParseError:
        return None
    report = TestReport()
    for case in root.iter("testcase"):
        case_id = f"{case.get('classname', '')}::{case.get('name', '')}"
        status, message = "passed", ""
        for child, name in (("failure", "failed"), ("error", "error"), ("skipped", "skipped")):
            element = case.find(child)
            if element is not None:
                status = name
                message = element.get("message") or (element.text or "").strip()
                break
        report.cases[case_id] = status
        if message:
            report.messages[case_id] = message.strip().splitlines()[0] if message.strip() else ""
    return report


class Sandbox(Protocol):
    def run(self, tree: Path, command: str, tests: list[str], timeout: int) -> Execution:
        """Run ``command`` in a copy-of-the-tree sandbox, ``{test}`` and ``{junit}`` filled in.

        ``tests`` are paths relative to the tree. ``tree`` is the sandbox's to
        use: callers pass a copy made for this one run.
        """
        ...


def find_engine(preferred: str = "") -> str | None:
    """A container engine on PATH: ``preferred``, ``$SECURITY_EVAL_ENGINE``, docker, podman."""
    for name in (preferred, os.environ.get("SECURITY_EVAL_ENGINE", ""), "docker", "podman"):
        if name and shutil.which(name):
            return name
    return None


def image_id(engine: str, image: str) -> str | None:
    """The image's id if it is present locally, so results can name exactly what ran them."""
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [engine, "image", "inspect", "--format", "{{.Id}}", image],
            capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def build_image(engine: str, image: str, dockerfile: Path, context: Path) -> int:
    """``docker build``: the one step that may use the network. No target code runs in it."""
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [engine, "build", "-t", image, "-f", str(dockerfile), str(context)], check=False,
    ).returncode


def fill(command: str, tests: list[str], junit: str) -> str:
    return (command.replace("{test}", " ".join(shlex.quote(t) for t in tests))
                   .replace("{junit}", shlex.quote(junit)))


class ContainerSandbox:
    def __init__(self, engine: str, image: str, *, memory: str = "1g", cpus: str = "1",
                 pids: int = 256, writable: bool = False) -> None:
        self.engine = engine
        self.image = image
        self.memory = memory
        self.cpus = cpus
        self.pids = pids
        self.writable = writable

    def argv(self, tree: Path, results: Path, name: str, script: str) -> list[str]:
        argv = [
            self.engine, "run", "--rm", "--name", name,
            "--network", "none",
            "--read-only", "--tmpfs", "/tmp:rw,exec,size=256m",  # noqa: S108 - in the container
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", str(self.pids), "--memory", self.memory, "--cpus", self.cpus,
            "-e", "HOME=/tmp", "-e", "PYTHONDONTWRITEBYTECODE=1",
            "-v", f"{tree}:/work:{'rw' if self.writable else 'ro'}",
            "-v", f"{results}:/results:rw",
            "-w", "/work",
        ]
        if sys.platform != "win32":
            # The host user, so the results directory is writable without
            # running as root. Rootless podman needs its id mapping kept.
            if Path(self.engine).name.startswith("podman"):
                argv += ["--userns=keep-id"]
            argv += ["--user", f"{os.getuid()}:{os.getgid()}"]
        return [*argv, self.image, "sh", "-c", script]

    def run(self, tree: Path, command: str, tests: list[str], timeout: int) -> Execution:
        results = Path(tempfile.mkdtemp(prefix="security-eval-results-"))
        name = f"security-eval-{uuid.uuid4().hex[:12]}"
        argv = self.argv(tree.resolve(), results, name, fill(command, tests, "/results/junit.xml"))
        try:
            try:
                proc = subprocess.run(argv, capture_output=True, timeout=timeout,  # noqa: S603
                                      check=False)
            except subprocess.TimeoutExpired as exc:
                # Killing the client leaves the container running; kill it by name.
                subprocess.run([self.engine, "kill", name], capture_output=True,  # noqa: S603
                               timeout=60, check=False)
                return Execution(None, _tail(exc.stdout, exc.stderr), timed_out=True,
                                 junit=_read_report(results))
            except OSError as exc:
                return Execution(None, infra_error=f"{self.engine}: {exc}")
            output = _tail(proc.stdout, proc.stderr)
            if proc.returncode in ENGINE_FAILURES:
                return Execution(proc.returncode, output,
                                 infra_error=f"exit {proc.returncode}: {output[-300:]}")
            return Execution(proc.returncode, output, junit=_read_report(results))
        finally:
            shutil.rmtree(results, ignore_errors=True)


def _read_report(results: Path) -> str | None:
    report = results / "junit.xml"
    if not report.is_file() or report.stat().st_size > MAX_REPORT_BYTES:
        return None
    return report.read_text(encoding="utf-8", errors="replace")


def _tail(*streams: bytes | str | None, limit: int = 4000) -> str:
    text = "".join(s.decode("utf-8", "replace") if isinstance(s, bytes) else (s or "")
                   for s in streams)
    return text[-limit:]
