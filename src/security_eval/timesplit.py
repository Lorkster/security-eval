"""Time-split targets: a real flaw, disclosed after the models' training cutoff.

The answer to "only known issues": known to us, unknown to the model. A target
is the vulnerable version of a real project, and the answer key is derived from
the commit that fixed it -- the lines the fix changed are where the flaw was.

What keeps the evaluation honest, and where each part is enforced:

* **The vulnerable version only, without history.** Exported with ``git
  archive``, so neither the fix commit nor any later commit is in the tree the
  model reads. (The harness re-initialises a one-commit repository on top.)
* **A neutral id.** The harness shows its agents the workspace path; the target
  id is part of the run's paths. An id like ``cve-2026-1234`` would hand the
  model the advisory's name. Ids default to ``ts-<hash>``, and preflight
  refuses an id that looks like an advisory.
* **Disclosure after every model's cutoff.** ``source.published`` is checked
  against ``configs/models.json`` before anything runs.
* **No way to look it up.** Baseline and triage have no tools; the harness's
  tools read only the workspace, and preflight refuses a harness config that
  allows running commands (which could fetch the advisory).

The advisory id, the fix commit and the disclosure date are kept in the
manifest's ``source``, which no model ever sees.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

#: Changes a fix makes that are not where the flaw was: its new tests, its notes.
_NOT_THE_FLAW = re.compile(
    r"(^|/)(tests?|testing|spec|specs|__tests__|docs?)/|(^|/)test_[^/]*$|_test\.[a-z]+$|"
    r"\.(md|rst|txt|adoc)$|(^|/)(changelog|changes|news|history|security)[^/]*$",
    re.IGNORECASE,
)
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@")
_ADVISORY_ID = re.compile(r"cve|ghsa|osv|pysec|rustsec", re.IGNORECASE)

LANGUAGES = {".py": "python", ".js": "javascript", ".ts": "typescript", ".go": "go",
             ".java": "java", ".rb": "ruby", ".php": "php", ".rs": "rust", ".c": "c",
             ".cc": "cpp", ".cpp": "cpp", ".cs": "csharp"}


class TimeSplitError(RuntimeError):
    pass


@dataclass(frozen=True)
class Hunk:
    path: str
    start: int
    end: int


def looks_like_advisory(target_id: str) -> bool:
    return bool(_ADVISORY_ID.search(target_id))


def fix_hunks(repo: Path, vulnerable: str, fixed: str, subdir: str = "") -> list[Hunk]:
    """The vulnerable-side line ranges the fix changed, in code that existed before it."""
    args = ["diff", "--unified=0", "--no-color", "--no-renames", vulnerable, fixed]
    if subdir:
        args += ["--", subdir]
    diff = _git(repo, args)
    hunks: list[Hunk] = []
    path: str | None = None
    for line in diff.splitlines():
        if line.startswith("--- "):
            old = line[4:].strip()
            path = None if old == "/dev/null" else old.removeprefix("a/")
            continue
        match = _HUNK.match(line)
        if not match or path is None or _NOT_THE_FLAW.search(path):
            continue
        start = int(match.group(1))
        count = int(match.group(2)) if match.group(2) is not None else 1
        # A pure insertion (count 0) -- the fix adds a missing check -- points
        # at the line it was inserted after: that is where the check was missing.
        first = max(start, 1)
        last = max(first, start + count - 1)
        hunks.append(Hunk(_relative(path, subdir), first, last))
    return hunks


def import_fix(repo: Path, vulnerable: str, fixed: str, dest: Path, *, published: str,
               cwes: list[str], advisory: str = "", subdir: str = "",
               target_id: str = "") -> Path:
    """Write ``dest/manifest.json`` and ``dest/src``: the vulnerable version and its key."""
    repo = repo.resolve()
    if not cwes:
        raise TimeSplitError("give at least one CWE: strict scoring needs one, and the "
                             "advisory usually names it")
    target_id = target_id or "ts-" + hashlib.sha256(
        f"{repo.name}:{fixed}".encode()).hexdigest()[:6]
    if looks_like_advisory(target_id):
        raise TimeSplitError(f"target id {target_id!r} looks like an advisory id; the model "
                           "would see it in its workspace path. Use a neutral one.")
    hunks = fix_hunks(repo, vulnerable, fixed, subdir)
    if not hunks:
        raise TimeSplitError("the fix changed no code that existed before it (only tests, docs "
                           "or new files); there is nothing to locate the flaw by")

    src = dest / "src"
    if src.exists():
        raise TimeSplitError(f"{src} already exists")
    _export(repo, vulnerable, subdir, src)

    suffixes = [PurePosixPath(h.path).suffix for h in hunks]
    language = max(set(suffixes), key=suffixes.count, default="")
    first, *rest = hunks
    manifest = {
        "id": target_id,
        "root": "src",
        "language": LANGUAGES.get(language, language.lstrip(".")),
        "public": True,
        "source": {"repo": str(repo), "vulnerable": vulnerable, "fixed": fixed,
                   "published": published, "advisory": advisory, "subdir": subdir},
        "vulnerabilities": [{
            "id": "V1", "cwe": cwes, "path": first.path,
            "lines": [first.start, first.end],
            "also": [{"path": h.path, "lines": [h.start, h.end]} for h in rest],
            "description": "derived from the lines the fix commit changed",
        }],
        "decoys": [],
    }
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n",
                                        encoding="utf-8")
    return dest / "manifest.json"


def _export(repo: Path, commit: str, subdir: str, dest: Path) -> None:
    """The tree at ``commit`` (under ``subdir``), without any git history."""
    args = ["archive", "--format=zip", commit]
    if subdir:
        args.append(subdir)
    data = subprocess.run(["git", "-C", str(repo), *args], capture_output=True,  # noqa: S603, S607
                          check=False)
    if data.returncode != 0:
        raise TimeSplitError(f"git archive failed: {data.stderr.decode(errors='replace')[-300:]}")
    with zipfile.ZipFile(io.BytesIO(data.stdout)) as archive:
        for member in archive.infolist():
            if member.is_dir():
                continue
            rel = _relative(member.filename, subdir)
            if not rel or rel.startswith("..") or PurePosixPath(rel).is_absolute():
                continue
            out = dest / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(archive.read(member))


def _relative(path: str, subdir: str) -> str:
    prefix = subdir.strip("/") + "/" if subdir else ""
    return path[len(prefix):] if prefix and path.startswith(prefix) else path


def _git(repo: Path, args: list[str]) -> str:
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True,  # noqa: S603, S607
                          text=True, encoding="utf-8", errors="replace", check=False)
    if proc.returncode != 0:
        raise TimeSplitError(f"git {args[0]} failed: {proc.stderr[-300:]}")
    return proc.stdout
