"""Which harness actually ran: read from the installation, checked against the pin, recorded."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from security_eval import preflight, provenance
from security_eval.budget import PriceTable, Usage
from security_eval.ledger import Outcome
from security_eval.matrix import Matrix, run_matrix
from security_eval.provenance import HarnessVersion, installed, pinned_commit
from security_eval.report import load_cells, render_markdown, summarise
from security_eval.runners.base import RunResult

from .conftest import TOY

PIN = "bb5c8b7c2499d5a5aa8e355ba87afb376ecae215"


class FakeDist:
    def __init__(self, direct: dict[str, Any] | None) -> None:
        self.direct = direct

    def read_text(self, name: str) -> str | None:
        return json.dumps(self.direct) if self.direct is not None else None


@pytest.fixture(autouse=True)
def fresh() -> Any:
    installed.cache_clear()
    yield
    installed.cache_clear()


def test_the_pin_is_read_from_pyproject(tmp_path: Path) -> None:
    assert len(pinned_commit()) == 40, "the real pyproject pins a full commit"
    toml = tmp_path / "pyproject.toml"
    toml.write_text('[project.optional-dependencies]\nharness = ["supervisor-harness @ '
                    f'git+https://example.org/h@{PIN}"]\n', encoding="utf-8")
    assert pinned_commit(toml) == PIN
    toml.write_text('[project.optional-dependencies]\nharness = ["supervisor-harness"]\n',
                    encoding="utf-8")
    assert pinned_commit(toml) == ""


def test_a_vcs_install_reports_the_commit_it_was_built_from(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(provenance, "distribution", lambda _: FakeDist(
        {"url": "https://example.org/h", "vcs_info": {"vcs": "git", "commit_id": PIN}}))
    assert installed() == HarnessVersion(PIN, "pinned install", where="https://example.org/h")


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_an_editable_install_reports_its_checkout_and_whether_it_is_clean(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    repo = tmp_path / "harness"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    run = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run([*run, "init", "-q"], check=True)
    subprocess.run([*run, "add", "-A"], check=True)
    subprocess.run([*run, "commit", "-q", "-m", "one"], check=True)
    head = subprocess.run([*run, "rev-parse", "HEAD"], capture_output=True, text=True,
                          check=True).stdout.strip()
    monkeypatch.setattr(provenance, "distribution", lambda _: FakeDist(
        {"url": repo.as_uri(), "dir_info": {"editable": True}}))

    clean = installed()
    assert (clean.commit, clean.how, clean.dirty) == (head, "editable", False)
    assert clean.label() == head[:12]

    (repo / "a.py").write_text("x = 2\n", encoding="utf-8")
    installed.cache_clear()
    assert installed().dirty and installed().label().endswith("+uncommitted")


def test_preflight_says_whether_the_pinned_harness_will_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(provenance, "pinned_commit", lambda *a: PIN)

    def check(version: HarnessVersion) -> str:
        monkeypatch.setattr(provenance, "installed", lambda: version)
        (c,) = preflight._harness_version()
        return c.level

    assert check(HarnessVersion(PIN, "pinned install")) == "ok"
    assert check(HarnessVersion(PIN, "editable")) == "ok"
    assert check(HarnessVersion(PIN, "editable", dirty=True)) == "warn"
    assert check(HarnessVersion("0" * 40, "editable")) == "warn"
    assert check(HarnessVersion()) == "warn", "an unidentifiable harness is not the pin"


class Real:
    """Not the fake condition, so the cell records a harness version."""

    condition = "baseline"

    def run(self, target: Any, route: str, workdir: Path, task: str = "",
            effort: str = "") -> RunResult:
        return RunResult(Outcome.OK, [], Usage(10, 1))


def test_every_cell_records_the_harness_and_the_report_flags_a_mix(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prices: PriceTable,
) -> None:
    m = Matrix(name="p", targets=[TOY], conditions=["baseline"], models=["ollama:m"],
               repeats=2, tokens_per_run={"baseline": (10, 1)})
    out = tmp_path / "out"
    monkeypatch.setattr(provenance, "installed", lambda: HarnessVersion(PIN, "editable"))
    run_matrix(m, {"baseline": Real()}, out, prices, progress=lambda _: None)
    summary = summarise(load_cells(out))
    assert summary["harness"] == [PIN[:12]]
    text = render_markdown(summary, title="t", stated_only=False)
    assert f"Harness: {PIN[:12]}." in text
    assert "did not all run on one committed harness" not in text

    m.repeats = 3
    monkeypatch.setattr(provenance, "installed",
                        lambda: HarnessVersion(PIN, "editable", dirty=True))
    run_matrix(m, {"baseline": Real()}, out, prices, progress=lambda _: None)
    summary = summarise(load_cells(out))
    assert len(summary["harness"]) == 2
    assert "did not all run on one committed harness" in render_markdown(
        summary, title="t", stated_only=False)
