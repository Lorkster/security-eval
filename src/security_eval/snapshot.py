"""Real code as a target: a frozen snapshot of files you own, for a trial run.

``security-eval import-code`` copies chosen files of a local repository, as
committed, into a target with no answer key (``"open": true``). Its findings go
to adjudication rather than a scorer. By default the code may go only to local
models (``"allowed_providers": ["ollama"]``), so a later edit to a matrix cannot
send it to an API by accident: preflight and the runner both refuse.

A snapshot rather than the live working tree, because the material must not
change between conditions, and because uncommitted work does not belong in a
study. See docs/local-trial-run.md.
"""

from __future__ import annotations

import io
import json
import re
import subprocess
import zipfile
from pathlib import Path, PurePosixPath

from .timesplit import LANGUAGES, TimeSplitError, _git


def import_code(repo: Path, paths: list[str], dest: Path, *, commit: str = "HEAD",
                target_id: str = "", allowed_providers: list[str] | None = None) -> Path:
    """Write ``dest/manifest.json`` and ``dest/code``: ``paths`` at ``commit``, no history.

    Files keep their paths in the repository, so a finding at
    ``src/pkg/x.py:12`` names the same place in the repository itself.
    """
    repo = repo.resolve()
    if not paths:
        raise TimeSplitError("name at least one file or directory to import")
    src = dest / "code"
    if src.exists():
        raise TimeSplitError(f"{src} already exists")
    resolved = _git(repo, ["rev-parse", commit]).strip()
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "-C", str(repo), "archive", "--format=zip", resolved, "--", *paths],  # noqa: S607
        capture_output=True, check=False)
    if proc.returncode != 0:
        raise TimeSplitError("git archive failed (is each path committed?): "
                             + proc.stderr.decode(errors="replace")[-300:])
    suffixes: list[str] = []
    with zipfile.ZipFile(io.BytesIO(proc.stdout)) as archive:
        for member in archive.infolist():
            rel = PurePosixPath(member.filename)
            if member.is_dir() or rel.is_absolute() or ".." in rel.parts:
                continue
            out = src / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(archive.read(member))
            suffixes.append(rel.suffix)
    if not suffixes:
        raise TimeSplitError("no files matched")
    manifest = {
        "id": target_id or dest.name,
        "root": "code",
        "language": LANGUAGES.get(max(set(suffixes), key=suffixes.count), ""),
        "public": False,
        "open": True,
        "allowed_providers": ["ollama"] if allowed_providers is None else allowed_providers,
        "source": {"repo": repo.name, "commit": resolved, "paths": " ".join(paths)},
    }
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return dest / "manifest.json"


_RELATIVE_IMPORT = re.compile(r"^\s*from\s+(\.+)([\w.]*)\s+import\s+(.+)$", re.MULTILINE)


def missing_imports(root: Path) -> list[str]:
    """Modules the snapshot's Python files import from their own package but did not include.

    A slice of a project reads like a whole one to a model, but the code it
    calls into is not there: in the first trial run, both harness lenses
    reported that they could not check claims depending on modules the snapshot
    left out. Better known when choosing the slice than found in the review.
    Relative imports only -- they are the ones that certainly name the project's
    own code.
    """
    missing: set[str] = set()
    for file in sorted(root.rglob("*.py")):
        package = file.parent
        text = file.read_text(encoding="utf-8", errors="replace")
        for dots, module, names in _RELATIVE_IMPORT.findall(text):
            base = package
            for _ in range(len(dots) - 1):
                base = base.parent
            if module:
                candidates = [base.joinpath(*module.split("."))]
            else:
                # `from . import a, b`: each name is a module of the package.
                candidates = [base / n.strip().split(" ")[0].strip("()")
                              for n in names.split(",") if n.strip().strip("()")]
            for target in candidates:
                if not (target.with_suffix(".py").is_file() or (target / "__init__.py").is_file()
                        or target.is_dir()):
                    try:
                        missing.add(target.relative_to(root).as_posix() + ".py")
                    except ValueError:
                        continue
    return sorted(missing)
