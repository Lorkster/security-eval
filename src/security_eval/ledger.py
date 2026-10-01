"""The append-only record of every cell a matrix has run, or refused to run.

One JSON line per attempt, written and flushed before the driver moves on. It
is what makes a matrix resumable without paying twice: a cell with a finished
record is skipped on the next invocation. It is also the dataset -- every
analysis in the write-up should be reproducible from the ledger plus the
per-cell findings files it points at.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class Outcome(StrEnum):
    OK = "ok"
    REFUSED = "refused"                    # the model declined (RQ4: model)
    INVALID_OUTPUT = "invalid_output"      # no parseable findings (RQ4: model)
    HARNESS_STOPPED = "harness_stopped"    # drift control stopped an agent (RQ4: harness)
    ERROR = "error"                        # provider, network, crash: retry later
    SKIPPED_BUDGET = "skipped_budget"      # the budget guard refused to start it
    SKIPPED_POLICY = "skipped_policy"      # the target's data policy forbids this provider

    @property
    def final(self) -> bool:
        """Whether a resumed matrix should leave this cell alone.

        An error or a budget skip is worth another attempt; a refusal or an
        invalid answer is a result, and retrying it until it goes away would be
        both expensive and a way of hiding it.
        """
        return self not in (Outcome.ERROR, Outcome.SKIPPED_BUDGET)


@dataclass
class Record:
    cell: str
    target: str
    condition: str
    model: str
    repeat: int
    outcome: Outcome
    prompt: str = ""
    prompt_sha: str = ""
    effort: str = ""
    cost_usd: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    seconds: float = 0.0
    findings_path: str = ""
    detail: str = ""
    started: str = ""
    finished: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        data = asdict(self)
        data["outcome"] = self.outcome.value
        return json.dumps(data, sort_keys=True)


class Ledger:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def records(self) -> list[Record]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            data = json.loads(line)
            data["outcome"] = Outcome(data["outcome"])
            out.append(Record(**data))
        return out

    def append(self, record: Record) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(record.to_json() + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def finished(self) -> set[str]:
        """Cells whose latest record is final."""
        latest: dict[str, Record] = {}
        for record in self.records():
            latest[record.cell] = record
        return {cell for cell, r in latest.items() if r.outcome.final}

    def spent(self) -> float:
        """Every dollar recorded, including attempts that later had to be retried."""
        return sum(r.cost_usd for r in self.records())
