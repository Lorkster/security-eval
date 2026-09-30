"""What every runner takes and returns."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ..budget import Usage
from ..finding import SecurityFinding
from ..ledger import Outcome
from ..manifest import Target

DEFAULT_PROMPTS = Path(__file__).resolve().parents[3] / "configs" / "prompts.json"

# The default task statement: `plain` in configs/prompts.json, and what a runner
# uses when it is given no other. The same text goes to every condition, so the
# prompt is held constant across baseline and harness. Defensive by
# construction: find, explain, fix -- never exploit. See docs/proposal.md
# section 1 and docs/working-with-regulated-models.md.
TASK = (
    "Review the code in this repository for security vulnerabilities. For each one, "
    "report: a short title; the CWE id; the file and line range, written as "
    "`path/to/file.ext:start-end` relative to the repository root; severity "
    "(info, low, medium, high, critical); your confidence from 0 to 1; the evidence "
    "in the code; and a recommended fix. Report only issues you can point to in the "
    "code. Do not write exploits."
)


def load_prompts(path: Path | str = DEFAULT_PROMPTS) -> dict[str, str]:
    """Named task prompts. Keys starting with ``_`` are comments."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {k: str(v) for k, v in data.items() if not k.startswith("_")}


def prompt_hash(text: str) -> str:
    """A short, stable fingerprint of a prompt, recorded with every cell.

    Prompts are meant to be frozen before the pilot's results are seen. The hash
    in the ledger is how anyone can check afterwards that they were.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


@dataclass
class RunResult:
    outcome: Outcome
    findings: list[SecurityFinding] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    seconds: float = 0.0
    detail: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


class Runner(Protocol):
    #: The condition this runner implements: "baseline", "harness", "fake".
    condition: str

    def run(self, target: Target, route: str, workdir: Path, task: str = TASK) -> RunResult:
        """Run ``task`` on ``target`` with the model at ``route``.

        ``workdir`` is empty and belongs to this cell alone. A runner must not
        write into ``target.root``: targets are shared by every cell.
        """
        ...
