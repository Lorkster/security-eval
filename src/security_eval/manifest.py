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


@dataclass
class Target:
    id: str
    root: Path
    language: str = ""
    public: bool = True
    vulnerabilities: list[KnownIssue] = field(default_factory=list)
    decoys: list[KnownIssue] = field(default_factory=list)
    manifest_path: Path | None = None


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
    )
    problems = validate(target)
    if problems:
        raise ManifestError(f"{path}:\n  " + "\n  ".join(problems))
    return target


def _issue(raw: dict[str, Any], path: Path, section: str) -> KnownIssue:
    try:
        lines = raw["lines"]
        if isinstance(lines, list):
            start, end = int(lines[0]), int(lines[-1])
        else:
            start = end = int(lines)
        return KnownIssue(
            id=str(raw["id"]),
            location=Location(str(raw["path"]), start, end),
            cwe=normalise_cwe(raw.get("cwe")),
            description=str(raw.get("description", "")),
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
        file = target.root / issue.location.path
        if not file.is_file():
            problems.append(f"{issue.id}: {issue.location.path} does not exist under the root")
            continue
        n_lines = len(file.read_text(encoding="utf-8", errors="replace").splitlines())
        if issue.location.end_line > n_lines:
            problems.append(
                f"{issue.id}: lines {issue.location.start_line}-{issue.location.end_line} "
                f"run past the end of {issue.location.path} ({n_lines} lines)"
            )
    for vuln in target.vulnerabilities:
        if vuln.cwe is None:
            problems.append(f"{vuln.id}: a vulnerability needs a CWE")
    if not target.vulnerabilities:
        problems.append("no vulnerabilities: nothing to score recall against")
    return problems
