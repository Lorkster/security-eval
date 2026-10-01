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
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
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
    )
    problems = validate(target)
    if problems:
        raise ManifestError(f"{path}:\n  " + "\n  ".join(problems))
    return target


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
    if not target.vulnerabilities:
        problems.append("no vulnerabilities: nothing to score recall against")
    return problems
