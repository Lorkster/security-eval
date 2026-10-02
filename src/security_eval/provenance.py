"""Which harness actually ran: recorded with every cell, checked against the pin.

``pyproject.toml`` pins the harness to a commit, because a moving dependency is
not one an evaluation can be reproduced against. But nothing made the pin true.
A developer's environment typically has the harness installed *editable*, from a
local checkout, and then whatever that checkout has -- another branch,
uncommitted edits -- is what runs. The first trial run on real code ran that
way, and nothing in its results said which harness produced them.

So the version is read from the installation itself (PEP 610's
``direct_url.json``): the commit a VCS install was built from, or, for an
editable install, the checkout's current commit and whether it has uncommitted
changes. Preflight compares it with the pin; every cell records it.
"""

from __future__ import annotations

import json
import re
import subprocess
import tomllib
from dataclasses import dataclass
from functools import lru_cache
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from urllib.parse import unquote, urlparse

PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"
_COMMIT = re.compile(r"@([0-9a-f]{7,40})\b")


@dataclass(frozen=True)
class HarnessVersion:
    commit: str = ""         # "" when it cannot be told
    how: str = "unknown"     # "pinned install" | "editable" | "unknown" | "missing"
    dirty: bool = False      # an editable checkout with uncommitted changes
    where: str = ""

    def label(self) -> str:
        """What a cell records: the commit, marked when it is not reproducible."""
        if not self.commit:
            return self.how
        return self.commit[:12] + (" +uncommitted" if self.dirty else "")


def pinned_commit(pyproject: Path = PYPROJECT) -> str:
    """The commit ``pyproject.toml`` pins the harness to, or "" if it pins none."""
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return ""
    for requirement in data.get("project", {}).get("optional-dependencies", {}).get(
            "harness", []):
        match = _COMMIT.search(str(requirement))
        if match:
            return match.group(1)
    return ""


@lru_cache(maxsize=1)
def installed() -> HarnessVersion:
    """The harness this environment would run, as far as the installation says."""
    try:
        dist = distribution("supervisor-harness")
    except PackageNotFoundError:
        return HarnessVersion(how="missing")
    try:
        direct = json.loads(dist.read_text("direct_url.json") or "{}")
    except json.JSONDecodeError:
        direct = {}
    vcs = direct.get("vcs_info") or {}
    if vcs.get("commit_id"):
        return HarnessVersion(str(vcs["commit_id"]), "pinned install", where=direct.get("url", ""))
    if (direct.get("dir_info") or {}).get("editable"):
        path = _local_path(str(direct.get("url", "")))
        commit = _git(path, "rev-parse", "HEAD")
        dirty = bool(_git(path, "status", "--porcelain", "--untracked-files=no"))
        return HarnessVersion(commit, "editable", dirty=dirty, where=str(path))
    return HarnessVersion(where=direct.get("url", ""))


def _local_path(url: str) -> Path:
    parsed = urlparse(url)
    path = unquote(parsed.path)
    # file:///C:/x on Windows parses to "/C:/x"
    if re.match(r"^/[A-Za-z]:/", path):
        path = path[1:]
    return Path(path)


def _git(path: Path, *args: str) -> str:
    try:
        proc = subprocess.run(["git", "-C", str(path), *args],  # noqa: S603, S607
                              capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""
