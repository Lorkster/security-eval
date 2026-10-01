"""The review page and the reviewers' sheets: readable, blind, safe, and merged on import."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from security_eval.adjudication import SHEET_COLUMNS, export, merge_sheets, score_sheet
from security_eval.budget import PriceTable, Usage
from security_eval.cli import main
from security_eval.finding import Location, SecurityFinding
from security_eval.ledger import Outcome
from security_eval.manifest import Target
from security_eval.matrix import run_matrix
from security_eval.runners.base import RunResult

from .test_beyond_known import matrix, open_target, quiet

HOSTILE_CODE = 'x = "</script><script>alert(1)</script>"'
HOSTILE_TITLE = "<img src=x onerror=alert(1)> in the query"


class Reports:
    condition = "baseline"

    def run(self, target: Target, route: str, workdir: Path, task: str = "",
            effort: str = "") -> RunResult:
        return RunResult(Outcome.OK, [
            SecurityFinding(HOSTILE_TITLE, cwe="CWE-89", location=Location("app/db.py", 11, 11),
                            detail="the order reaches SQL", evidence=["db.py:11"],
                            recommendation="use an allow-list", location_source="stated"),
            SecurityFinding("path built from input", location=Location("app/files.py", 10, 10),
                            location_source="stated"),
        ], Usage(10, 1))


@pytest.fixture
def exported(tmp_path: Path, prices: PriceTable) -> tuple[Path, Path, Path]:
    real = open_target(tmp_path)
    db = real.parent / "src" / "app" / "db.py"
    lines = db.read_text(encoding="utf-8").splitlines()
    lines[10] = HOSTILE_CODE
    db.write_text("\n".join(lines) + "\n", encoding="utf-8")
    prices.models["open-model"] = prices.models["claude-haiku-4-5"]
    out = tmp_path / "out"
    run_matrix(matrix([real], models=["anthropic:claude-sonnet-5-5", "ollama:open-model"],
                      repeats=1), {"baseline": Reports()}, out, prices, progress=quiet)
    sheet, key = tmp_path / "adj" / "sheet.csv", tmp_path / "adj" / "key.json"
    export([out], sheet, key, seed=3)
    return sheet, key, sheet.parent / "review.html"


def embedded(page: str) -> dict:
    start = page.index('<script type="application/json" id="data">')
    body = page[page.index(">", start) + 1:page.index("</script>", start)]
    return json.loads(body)


def test_the_sheet_is_a_short_record_and_the_page_holds_the_reading(
    exported: tuple[Path, Path, Path],
) -> None:
    sheet, _, page = exported
    rows = list(csv.DictReader(sheet.open(encoding="utf-8")))
    assert list(rows[0]) == SHEET_COLUMNS
    assert all(len(row["location"]) < 80 for row in rows), "no code or reports in cells"
    text = page.read_text(encoding="utf-8")
    for meaning in ("True positive.", "False positive.", "Unsure.", "key.json",
                    "Download my verdicts"):
        assert meaning in text


def test_the_page_says_nothing_about_who_reported_what(
    exported: tuple[Path, Path, Path],
) -> None:
    text = exported[2].read_text(encoding="utf-8").lower()
    for source in ("anthropic", "ollama", "sonnet", "open-model", "baseline", "bandit"):
        assert source not in text, source


def test_untrusted_code_and_reports_are_shown_as_text_never_run(
    exported: tuple[Path, Path, Path],
) -> None:
    text = exported[2].read_text(encoding="utf-8")
    assert "</script><script>alert(1)" not in text, "could close the data element early"
    assert "innerHTML" not in text and "insertAdjacentHTML" not in text
    items = {i["location"].split(":")[0] + ":" + str(i["start"]): i
             for i in embedded(text)["items"]}
    db = items["app/db.py:11"]
    assert HOSTILE_CODE in db["lines"], "intact, as text, for the reviewer to read"
    assert db["first"] <= 11 <= db["first"] + len(db["lines"]) - 1
    assert db["reports"][0]["title"] == HOSTILE_TITLE
    assert db["reports"][0]["recommendation"] == "use an allow-list"
    titles = [r["title"] for r in db["reports"]]
    assert titles.count(HOSTILE_TITLE) == 1, "two models said the same thing: shown once"
    assert len(titles) == 2, "and the scanner's report on the same line beside it"


def reviewer_sheet(sheet: Path, column: str, verdicts: dict[str, str], out: Path,
                   notes: dict[str, str] | None = None) -> Path:
    """What the page downloads: the sheet, with one reviewer's column filled."""
    rows = list(csv.DictReader(sheet.open(encoding="utf-8")))
    for row in rows:
        place = row["location"].split("-")[0]
        row[column] = verdicts.get(place, "")
        row["notes"] = (notes or {}).get(place, "")
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=SHEET_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return out


def test_each_reviewers_file_is_merged_on_import(
    exported: tuple[Path, Path, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sheet, key, _ = exported
    a = reviewer_sheet(sheet, "reviewer_a", {"app/db.py:11": "tp", "app/files.py:10": "tp"},
                       tmp_path / "a.csv", {"app/db.py:11": "order reaches SQL"})
    b = reviewer_sheet(sheet, "reviewer_b", {"app/db.py:11": "tp", "app/files.py:10": "fp"},
                       tmp_path / "b.csv", {"app/db.py:11": "agree"})
    merged = merge_sheets([a, b])
    assert any(r["notes"] == "order reaches SQL | agree" for r in merged.values())

    result = score_sheet([a, b], key)
    assert result["pairs_compared"] == 2 and result["verified"] == 1
    assert len(result["disputed"]) == 1

    assert main(["adjudicate", "import", "--sheet", str(a), "--sheet", str(b),
                 "--key", str(key)]) == 3, "a dispute is still open"
    assert (key.parent / "results.md").is_file()

    final = reviewer_sheet(sheet, "final", {"app/files.py:10": "fp"}, tmp_path / "f.csv")
    assert score_sheet([a, b, final], key)["disputed"] == []
    capsys.readouterr()


def test_two_files_disagreeing_on_one_column_is_an_error_not_a_choice(
    exported: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    sheet, key, _ = exported
    one = reviewer_sheet(sheet, "reviewer_a", {"app/db.py:11": "tp"}, tmp_path / "1.csv")
    two = reviewer_sheet(sheet, "reviewer_a", {"app/db.py:11": "fp"}, tmp_path / "2.csv")
    with pytest.raises(ValueError, match="reviewer_a"):
        score_sheet([one, two], key)
    assert main(["adjudicate", "import", "--sheet", str(one), "--sheet", str(two),
                 "--key", str(key)]) == 2
