"""Real code as a target for a trial run: `security-eval import-code`."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from security_eval.cli import main
from security_eval.manifest import load_target
from security_eval.snapshot import import_code
from security_eval.timesplit import TimeSplitError

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t",
                           *args], capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    repo = tmp_path / "mine"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "pkg" / "b.py").write_text("y = 2\n", encoding="utf-8")
    (repo / "notes.md").write_text("private\n", encoding="utf-8")
    git(repo, "init", "-q")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "one")
    return repo


def test_only_the_named_files_as_committed_and_local_models_only(
    repo: Path, tmp_path: Path
) -> None:
    (repo / "pkg" / "a.py").write_text("x = 'uncommitted work'\n", encoding="utf-8")
    target = load_target(import_code(repo, ["pkg"], tmp_path / "t"))
    files = sorted(p.relative_to(target.root).as_posix() for p in target.root.rglob("*")
                   if p.is_file())
    assert files == ["pkg/a.py", "pkg/b.py"], "repository paths kept; notes.md not named"
    assert (target.root / "pkg" / "a.py").read_text(encoding="utf-8") == "x = 1\n"
    assert target.open and not target.public and target.language == "python"
    assert target.allowed_providers == ["ollama"]
    assert not target.allows("anthropic:claude-sonnet-5-5")
    assert target.source["commit"] == git(repo, "rev-parse", "HEAD")


def test_nothing_matched_is_an_error(repo: Path, tmp_path: Path) -> None:
    with pytest.raises(TimeSplitError):
        import_code(repo, ["no/such/path.py"], tmp_path / "t")


def test_the_command_reports_size_and_where_the_code_may_go(
    repo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = tmp_path / "t"
    assert main(["import-code", str(repo), "pkg/a.py", "--dest", str(dest),
                 "--allow", "bedrock", "--allow", "ollama"]) == 0
    out = capsys.readouterr().out
    assert "characters" in out and "may go to: bedrock, ollama" in out
    data = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
    assert data["allowed_providers"] == ["bedrock", "ollama"]
    assert main(["import-code", str(repo), "pkg/b.py", "--dest", str(tmp_path / "u"),
                 "--allow", "any"]) == 0
    assert load_target(tmp_path / "u" / "manifest.json").allowed_providers == []


def test_modules_the_slice_imports_but_leaves_out_are_named(repo: Path, tmp_path: Path) -> None:
    from security_eval.snapshot import missing_imports

    (repo / "pkg" / "a.py").write_text(
        "from .b import y\nfrom . import c\nfrom ..top import z\nimport os\n", encoding="utf-8")
    (repo / "pkg" / "c.py").write_text("", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "imports")

    alone = load_target(import_code(repo, ["pkg/a.py"], tmp_path / "one"))
    assert missing_imports(alone.root) == ["pkg/b.py", "pkg/c.py", "top.py"]

    with_b = load_target(import_code(repo, ["pkg/a.py", "pkg/b.py", "pkg/c.py"], tmp_path / "two"))
    assert missing_imports(with_b.root) == ["top.py"], "os is not the project's"
