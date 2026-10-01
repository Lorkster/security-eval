"""A runner that costs nothing, for exercising everything around the model.

It answers from the answer key, with a configurable recall and a configurable
number of invented false positives, deterministically per (target, repeat
seed). The scorer, ledger, budget guard and reports can all be developed and
tested against it before a single paid call is made -- which is stage 0 of
docs/models-and-budget.md.
"""

from __future__ import annotations

import random
from pathlib import Path

from ..budget import Usage
from ..finding import Location, SecurityFinding
from ..ledger import Outcome
from ..manifest import Target
from .base import TASK, RunResult


class FakeRunner:
    condition = "fake"

    def __init__(
        self,
        recall: float = 0.7,
        false_positives: int = 1,
        tokens: tuple[int, int] = (50_000, 5_000),
        seed: int = 0,
    ) -> None:
        self.recall = recall
        self.false_positives = false_positives
        self.tokens = tokens
        self.seed = seed

    def run(self, target: Target, route: str, workdir: Path, task: str = TASK,
            effort: str = "") -> RunResult:
        # Reproducible, not secret: the same cell always gets the same answer.
        rng = random.Random(f"{self.seed}:{target.id}:{route}:{workdir.name}")  # noqa: S311
        findings = [
            SecurityFinding(
                title=f"known issue {v.id}",
                cwe=v.cwe,
                location=v.location,
                severity="high",
                confidence=round(rng.uniform(0.5, 1.0), 2),
                source=f"fake:{route}",
            )
            for v in target.vulnerabilities
            if rng.random() < self.recall
        ]
        for n in range(self.false_positives):
            findings.append(SecurityFinding(
                title=f"invented issue {n}",
                cwe="CWE-20",
                location=Location("not/a/real/file.py", 1, 1),
                confidence=round(rng.uniform(0.1, 0.6), 2),
                source=f"fake:{route}",
            ))
        return RunResult(
            outcome=Outcome.OK,
            findings=findings,
            usage=Usage(*self.tokens),
            detail="fake runner: answered from the manifest",
        )


class FakeTriageRunner:
    """Triage for free: judges each scanner finding from the answer key, mostly right.

    Correct with probability ``accuracy``, deterministically per cell, and
    ``needs_info`` otherwise -- so the triage scoring, report and batch plumbing
    can be exercised without a model.
    """

    condition = "fake"
    kind = "triage"

    def __init__(self, tool: str = "bandit", accuracy: float = 0.8, seed: int = 0) -> None:
        self.tool = tool
        self.accuracy = accuracy
        self.seed = seed

    def run(self, target: Target, route: str, workdir: Path, task: str = TASK,
            effort: str = "") -> RunResult:
        from ..finding import Verdict
        from ..scanners import ScanError, label, scanner_findings

        try:
            findings = scanner_findings(target, self.tool)
        except ScanError as exc:
            return RunResult(Outcome.ERROR, detail=str(exc))
        rng = random.Random(f"{self.seed}:{target.id}:{route}:{workdir.name}")  # noqa: S311
        for finding, real in zip(findings, label(findings, target), strict=True):
            right = Verdict.TRUE_POSITIVE if real else Verdict.FALSE_POSITIVE
            finding.triage = right if rng.random() < self.accuracy else Verdict.NEEDS_INFO
        return RunResult(Outcome.OK, findings, Usage(20_000 * max(1, len(findings)), 500),
                         detail="fake triage: answered from the manifest",
                         extra={"tool": self.tool, "scanner_findings": len(findings)})


class FakeFixRunner:
    """The fix condition for free: one empty proposal per known vulnerability.

    No fake can write a real fix, so each proposal is marked as having none.
    That exercises the ledger, the proposal files, `verify` and the report; the
    sandbox itself is exercised by the tests, with proposals written by hand.
    """

    condition = "fake"
    kind = "fix"

    def run(self, target: Target, route: str, workdir: Path, task: str = TASK,
            effort: str = "") -> RunResult:
        proposals = [{"vulnerability": v.id, "invalid": "fake runner: no proposal"}
                     for v in target.vulnerabilities]
        return RunResult(Outcome.OK, [], Usage(30_000 * max(1, len(proposals)), 2_000),
                         detail="fake fix: no proposals",
                         extra={"vulnerabilities": len(proposals)},
                         artifacts={"proposals": proposals})
