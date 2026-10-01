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

#: Test code: what a fix adds to prove itself, not where the flaw was. Also
#: what a proposed fix may not edit (`fixes.protected`).
TEST_PATH = re.compile(
    r"(^|/)(tests?|testing|spec|specs|__tests__)/|(^|/)test_[^/]*$|_test\.[a-z]+$|"
    r"(^|/)conftest\.py$",
    re.IGNORECASE,
)
_DOC_PATH = re.compile(
    r"(^|/)docs?/|\.(md|rst|txt|adoc)$|(^|/)(changelog|changes|news|history|security)[^/]*$",
    re.IGNORECASE,
)


def _not_the_flaw(path: str) -> bool:
    """Changes a fix makes that are not where the flaw was: its new tests, its notes."""
    return bool(TEST_PATH.search(path) or _DOC_PATH.search(path))


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
        if not match or path is None or _not_the_flaw(path):
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
    verify = _export_reference(repo, vulnerable, fixed, subdir, dest / "verify")
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
        # For RQ8. The group fills in the image and the commands for this
        # project; `security-eval sandbox check` says what is still missing.
        "verify": verify,
    }
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n",
                                        encoding="utf-8")
    return dest / "manifest.json"


def _export_reference(repo: Path, vulnerable: str, fixed: str, subdir: str,
                      dest: Path) -> dict[str, object]:
    """The fix as files, for checking proposed fixes against it (RQ8).

    ``fixed/`` holds each code file the fix changed or added, as the fix left
    it; ``fixed_tests/`` the test files. Whole files rather than a patch, so
    applying them is a copy and cannot fail on line endings or context. Neither
    is under ``src/``, so no model sees them.
    """
    args = ["diff", "--name-status", "--no-renames", vulnerable, fixed]
    if subdir:
        args += ["--", subdir]
    verify: dict[str, object] = {"image": "", "test_dir": "tests", "test_command": "",
                                 "suite_command": "", "timeout": 300}
    deleted: list[str] = []
    wrote = {"fixed": False, "fixed_tests": False}
    for line in _git(repo, args).splitlines():
        status, _, path = line.partition("\t")
        rel = _relative(path, subdir)
        if not rel or rel.startswith("..") or _DOC_PATH.search(rel):
            continue
        if status.startswith("D"):
            if not TEST_PATH.search(rel):
                deleted.append(rel)
            continue
        folder = "fixed_tests" if TEST_PATH.search(rel) else "fixed"
        out = dest / folder / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(_git_bytes(repo, ["show", f"{fixed}:{path}"]))
        wrote[folder] = True
    if wrote["fixed"]:
        verify["reference_fix"] = "verify/fixed"
    if wrote["fixed_tests"]:
        verify["reference_tests"] = "verify/fixed_tests"
    if deleted:
        verify["reference_deleted"] = deleted
    return verify


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


def _git_bytes(repo: Path, args: list[str]) -> bytes:
    """Raw output: a file's bytes exactly as committed, line endings included."""
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True,  # noqa: S603, S607
                          check=False)
    if proc.returncode != 0:
        raise TimeSplitError(f"git {args[0]} failed: {proc.stderr.decode(errors='replace')[-300:]}")
    return proc.stdout


def _git(repo: Path, args: list[str]) -> str:
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True,  # noqa: S603, S607
                          text=True, encoding="utf-8", errors="replace", check=False)
    if proc.returncode != 0:
        raise TimeSplitError(f"git {args[0]} failed: {proc.stderr[-300:]}")
    return proc.stdout
