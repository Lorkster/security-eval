"""Benchmark targets and their answer keys.

A manifest is a JSON file beside the target's code:

    {
      "id": "toy-webapp",
      "root": "src",                    # relative to the manifest
      "language": "python",
      "public": false,                  # could a model have trained on it?
      "vulnerabilities": [
        {"id": "V1", "cwe": "CWE-89", "path": "app/db.py", "lines": [10, 12],
         "description": "..."}
      ],
      "decoys": [
        {"id": "D1", "path": "app/db.py", "lines": [20, 22],
         "description": "parameterised query that looks like V1"}
      ]
    }

Decoys are safe code that resembles a vulnerability. A finding on a decoy is a
false positive the benchmark was designed to provoke, and is counted as such.

Two optional fields, for the cases where one answer would be unfair:

* ``"also": [{"path": ..., "lines": [...]}]`` -- further places a finding may
  fairly point at. A flaw that crosses files (input taken in a handler, used in
  a query two modules away) can be reported at either end, and a correct report
  at the other end must not be scored as a false positive.
* ``"cwe": ["CWE-916", "CWE-327", "CWE-328"]`` -- a list when several CWEs
  describe the flaw correctly. The first is the one reported; any of them
  passes the strict reading.

Three more, for the tracks beyond known issues (docs/beyond-known-issues.md):

* ``"open": true`` -- real code with no answer key. Nothing is scored against
  it automatically; its findings go to blind human adjudication instead.
* ``"source": {"repo", "vulnerable", "fixed", "published", "advisory"}`` --
  where a time-split target came from. ``published`` is the disclosure date the
  preflight check holds against each model's training cutoff. The advisory id
  lives here and nowhere the model can see.
* ``"allowed_providers": ["bedrock", "ollama"]`` -- where this target's code may
  be sent. Code goes to whichever provider serves the model -- Anthropic for
  ``anthropic:``, AWS for ``bedrock:``, a third party for ``openrouter:``,
  nowhere for ``ollama:`` -- so company code carries the list its owner
  approved, and a cell routed anywhere else is refused.

And one for RQ8, fix verification (docs/beyond-known-issues.md):

* ``"verify": {...}`` -- how to run the target's tests in a sandbox, so a
  proposed fix and its regression test can be checked. See `VerifyConfig`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from .finding import Location, normalise_cwe


@dataclass(frozen=True)
class KnownIssue:
    id: str
    location: Location
    cwe: str | None = None
    description: str = ""
    also: tuple[Location, ...] = ()
    also_cwes: tuple[str, ...] = ()

    @property
    def locations(self) -> tuple[Location, ...]:
        return (self.location, *self.also)

    @property
    def cwes(self) -> frozenset[str]:
        return frozenset(c for c in (self.cwe, *self.also_cwes) if c)


@dataclass(frozen=True)
class VerifyConfig:
    """How a target's tests run in the sandbox, for checking proposed fixes (RQ8).

    Paths are relative to the manifest. Commands run with ``sh -c`` in the
    container, from the root of the target's tree; ``{test}`` is replaced by the
    test file(s) to run and ``{junit}`` by where the JUnit XML report goes. The
    report is how a failure is told apart from an error, so it is required.

        "verify": {
          "image": "security-eval/notes-api:1",
          "dockerfile": "verify/Dockerfile",      # optional: `security-eval sandbox build`
          "overlay": "verify/overlay",            # optional: files laid over the tree
          "test_dir": "tests",                    # where a proposed test may go
          "test_command": "python -m pytest -q -p no:cacheprovider {test} --junitxml={junit}",
          "suite_command": "python -m pytest -q -p no:cacheprovider tests --junitxml={junit}",
          "timeout": 120,
          "reference_fix": "verify/fixed",        # time-split: the files as the fix left them
          "reference_tests": "verify/fixed_tests" # time-split: the tests the fix added
        }

The overlay is for a benchmark whose test suite must not be in ``src/``,
where a detection run would read it. Nothing under ``verify/`` is sent to a
model by a detection condition.
    """

    image: str = ""
    dockerfile: Path | None = None
    overlay: Path | None = None
    test_dir: str = "tests"
    test_command: str = ""
    suite_command: str = ""
    timeout: int = 300
    #: Mount the tree writable. Off by default: a test has /tmp to write to.
    writable: bool = False
    reference_fix: Path | None = None
    reference_tests: Path | None = None
    reference_deleted: tuple[str, ...] = ()
    #: Regexes over a failure's message that mean the test failed for the wrong
    #: reason (it calls something the fix adds); empty means the defaults.
    wrong_reasons: tuple[str, ...] = ()

    def problems(self) -> list[str]:
        """What is missing before fixes on this target can be verified."""
        out = []
        if not self.image:
            out.append("verify.image is not set")
        if "{test}" not in self.test_command or "{junit}" not in self.test_command:
            out.append("verify.test_command needs {test} and {junit}")
        if "{junit}" not in self.suite_command:
            out.append("verify.suite_command needs {junit}")
        if not self.test_dir.strip("/"):
            out.append("verify.test_dir is empty")
        return out


@dataclass
class Target:
    id: str
    root: Path
    language: str = ""
    public: bool = True
    vulnerabilities: list[KnownIssue] = field(default_factory=list)
    decoys: list[KnownIssue] = field(default_factory=list)
    manifest_path: Path | None = None
    #: Scanner output kept beside the benchmark: tool -> SARIF file.
    scans: dict[str, Path] = field(default_factory=dict)
    open: bool = False
    source: dict[str, str] = field(default_factory=dict)
    #: Providers this target's code may be sent to; empty means any.
    allowed_providers: list[str] = field(default_factory=list)
    verify: VerifyConfig | None = None

    def allows(self, route: str) -> bool:
        return not self.allowed_providers or route.split(":", 1)[0] in self.allowed_providers


class ManifestError(ValueError):
    pass


def load_target(manifest: Path | str) -> Target:
    path = Path(manifest)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"{path}: {exc}") from exc

    root = (path.parent / data.get("root", ".")).resolve()
    target = Target(
        id=str(data.get("id") or path.parent.name),
        root=root,
        language=str(data.get("language", "")),
        public=bool(data.get("public", True)),
        vulnerabilities=[_issue(v, path, "vulnerabilities")
                         for v in data.get("vulnerabilities", [])],
        decoys=[_issue(d, path, "decoys") for d in data.get("decoys", [])],
        manifest_path=path,
        scans={str(tool): (path.parent / str(rel)).resolve()
               for tool, rel in (data.get("scans") or {}).items()},
        open=bool(data.get("open", False)),
        source={str(k): str(v) for k, v in (data.get("source") or {}).items()},
        allowed_providers=[str(x) for x in data.get("allowed_providers") or []],
        verify=_verify(data.get("verify"), path),
    )
    problems = validate(target)
    if problems:
        raise ManifestError(f"{path}:\n  " + "\n  ".join(problems))
    return target


def _verify(raw: Any, path: Path) -> VerifyConfig | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ManifestError(f"{path}: verify must be an object")

    def rel(key: str) -> Path | None:
        return (path.parent / str(raw[key])).resolve() if raw.get(key) else None

    try:
        return VerifyConfig(
            image=str(raw.get("image", "")),
            dockerfile=rel("dockerfile"),
            overlay=rel("overlay"),
            test_dir=str(raw.get("test_dir", "tests")).strip().strip("/"),
            test_command=str(raw.get("test_command", "")),
            suite_command=str(raw.get("suite_command", "")),
            timeout=int(raw.get("timeout", 300)),
            writable=bool(raw.get("writable", False)),
            reference_fix=rel("reference_fix"),
            reference_tests=rel("reference_tests"),
            reference_deleted=tuple(str(x) for x in raw.get("reference_deleted") or []),
            wrong_reasons=tuple(str(x) for x in raw.get("wrong_reasons") or []),
        )
    except (TypeError, ValueError) as exc:
        raise ManifestError(f"{path}: bad verify section ({exc})") from exc


def _location(raw: dict[str, Any]) -> Location:
    lines = raw["lines"]
    if isinstance(lines, list):
        start, end = int(lines[0]), int(lines[-1])
    else:
        start = end = int(lines)
    return Location(str(raw["path"]), start, end)


def _issue(raw: dict[str, Any], path: Path, section: str) -> KnownIssue:
    try:
        cwe_raw = raw.get("cwe")
        cwes = [c for c in (normalise_cwe(x) for x in (
            cwe_raw if isinstance(cwe_raw, list) else [cwe_raw])) if c]
        return KnownIssue(
            id=str(raw["id"]),
            location=_location(raw),
            cwe=cwes[0] if cwes else None,
            description=str(raw.get("description", "")),
            also=tuple(_location(a) for a in raw.get("also", [])),
            also_cwes=tuple(cwes[1:]),
        )
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        raise ManifestError(f"{path}: bad entry in {section}: {raw!r} ({exc})") from exc


def validate(target: Target) -> list[str]:
    """What is wrong with a target, checked against the code on disk."""
    problems: list[str] = []
    if not target.root.is_dir():
        return [f"root {target.root} is not a directory"]

    seen: set[str] = set()
    for issue in [*target.vulnerabilities, *target.decoys]:
        if issue.id in seen:
            problems.append(f"{issue.id}: duplicate id")
        seen.add(issue.id)
        for loc in issue.locations:
            file = target.root / loc.path
            if not file.is_file():
                problems.append(f"{issue.id}: {loc.path} does not exist under the root")
                continue
            n_lines = len(file.read_text(encoding="utf-8", errors="replace").splitlines())
            if loc.end_line > n_lines:
                problems.append(
                    f"{issue.id}: lines {loc.start_line}-{loc.end_line} "
                    f"run past the end of {loc.path} ({n_lines} lines)"
                )
    for tool, scan in target.scans.items():
        if not scan.is_file():
            problems.append(f"scan {tool}: {scan} does not exist")
    for vuln in target.vulnerabilities:
        if vuln.cwe is None:
            problems.append(f"{vuln.id}: a vulnerability needs a CWE")
    if not target.vulnerabilities and not target.open:
        problems.append("no vulnerabilities: nothing to score recall against "
                        "(mark it \"open\": true if it is real code for adjudication)")
    if target.source.get("published"):
        try:
            date.fromisoformat(target.source["published"])
        except ValueError:
            problems.append(f"source.published {target.source['published']!r} is not YYYY-MM-DD")
    if target.verify is not None:
        v = target.verify
        if v.dockerfile is not None and not v.dockerfile.is_file():
            problems.append(f"verify.dockerfile: {v.dockerfile} does not exist")
        for name, folder in (("overlay", v.overlay), ("reference_fix", v.reference_fix),
                             ("reference_tests", v.reference_tests)):
            if folder is not None and not folder.is_dir():
                problems.append(f"verify.{name}: {folder} is not a directory")
        for pattern in v.wrong_reasons:
            try:
                re.compile(pattern)
            except re.error as exc:
                problems.append(f"verify.wrong_reasons: {pattern!r} ({exc})")
    return problems
