"""Static analysis tools: run them, keep their SARIF, and label what they report.

Two jobs in the study need a scanner's output:

* **RQ3, triage.** The models judge each scanner finding: real, not real, or
  undecidable from the code. The company already runs such tools; what it
  lacks is time to sift their output.
* **A baseline for detection.** On the same answer key, how do the tools the
  company already pays for compare with the models? The report scores each
  target's scans beside the model conditions.

A scan is stored beside its benchmark (``benchmarks/<name>/scans/<tool>.sarif``)
and named in the manifest (``"scans": {"bandit": "scans/bandit.sarif"}``), so it
is part of the frozen material, not re-run on every cell.

Labelling uses the scorer's own rule, so triage and detection agree on what is
real: a finding that lands on a known vulnerability is real; one on a decoy, or
on nothing in the answer key, is not.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from .finding import SecurityFinding
from .manifest import Target
from .sarif import from_sarif
from .scoring import DEFAULT_TOLERANCE, matched_issue

#: Command templates. ``{out}`` is the SARIF file to write; each runs from the
#: target's root so the paths it reports are relative to it, as the manifest's are.
PRESETS: dict[str, list[str]] = {
    "bandit": ["bandit", "-r", ".", "-f", "sarif", "-o", "{out}", "-q"],
    # Not available natively on Windows; use WSL, Linux or macOS. Metrics off:
    # the code under study does not leave the machine because of a scanner.
    "semgrep": ["semgrep", "scan", "--config", "p/default", "--metrics", "off",
                "--sarif", "--output", "{out}", "."],
    # Needs `snyk auth`. This is the tool the company already uses, which makes
    # it the most relevant comparison of all.
    "snyk": ["snyk", "code", "test", "--sarif-file-output={out}"],
}


class ScanError(RuntimeError):
    pass


def run_scan(target: Target, tool: str, out: Path, command: list[str] | None = None) -> Path:
    """Run ``tool`` (a preset, or ``command`` with ``{out}``) over ``target``, writing SARIF."""
    template = command or PRESETS.get(tool)
    if not template:
        raise ScanError(f"no preset for {tool!r}; pass a command containing {{out}}")
    executable = find_tool(template[0])
    if executable is None:
        raise ScanError(f"`{template[0]}` is not on PATH, nor installed beside this Python")
    out.parent.mkdir(parents=True, exist_ok=True)
    argv = [executable, *(part.replace("{out}", str(out.resolve())) for part in template[1:])]
    # Scanners exit non-zero when they find something; only a missing file is failure.
    proc = subprocess.run(argv, cwd=target.root, capture_output=True, text=True,  # noqa: S603
                          check=False)
    if not out.is_file():
        raise ScanError(f"{tool} wrote no SARIF (exit {proc.returncode}): {proc.stderr[-300:]}")
    json.loads(out.read_text(encoding="utf-8"))   # fail now, not on the first triage cell
    return out


def find_tool(name: str) -> str | None:
    """``name`` on PATH, or else beside the running Python.

    ``pip install bandit`` into the project's virtual environment puts it next
    to the interpreter, which is not on PATH unless the environment is
    activated. Running ``.venv/Scripts/security-eval`` directly should still
    find it.
    """
    found = shutil.which(name)
    if found:
        return found
    return shutil.which(name, path=str(Path(sys.executable).parent))


def scanner_findings(target: Target, tool: str) -> list[SecurityFinding]:
    """What ``tool`` reported on ``target``, from the SARIF its manifest names."""
    path = target.scans.get(tool)
    if path is None:
        raise ScanError(f"target {target.id} has no {tool} scan; run `security-eval scan`")
    findings = from_sarif(json.loads(path.read_text(encoding="utf-8")))
    for i, f in enumerate(findings):
        f.source = f"scanner:{tool}"
        f.id = f.id or f"{tool}-{i}"
        f.location_source = "stated" if f.location else ""
    return findings


def label(findings: list[SecurityFinding], target: Target,
          tolerance: int = DEFAULT_TOLERANCE) -> list[bool]:
    """Whether each finding is real, by the answer key: the triage ground truth."""
    return [f.location is not None and matched_issue(f.location, target, tolerance) is not None
            for f in findings]
