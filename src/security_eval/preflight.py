"""Everything that can be checked about a matrix before a single token is paid for.

A missing API key, an unpriced model, a typo in a prompt name or a manifest that
points past the end of a file all fail the same way if they are found late: on
the first cell, after the budget guard has already let it start, or worse, on
the fortieth. This finds them first. `security-eval run` calls it and stops on
any failure; `security-eval check` runs it on its own.

Provider availability is checked the way each harness cell will see it: with an
empty ``SUPERVISOR_HOME``, so a key that only exists in a home config the cells
will not read is reported as missing here rather than there.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .batch import supports_batch
from .budget import PriceTable
from .manifest import ManifestError, load_target
from .matrix import BATCHABLE, Matrix, estimate
from .runners.base import EFFORT_LEVELS, EFFORT_PROVIDERS, load_prompts, prompt_hash

LOCAL_PROVIDERS = frozenset({"fake", "ollama"})


@dataclass
class Check:
    level: str        # "ok" | "warn" | "fail"
    message: str


def run_checks(matrix: Matrix, prices: PriceTable, *, fake: bool = False,
               supervisor: str = "supervisor") -> list[Check]:
    out: list[Check] = []

    targets = []
    for manifest in matrix.targets:
        try:
            target = load_target(manifest)
        except ManifestError as exc:
            out.append(Check("fail", f"manifest: {exc}"))
            continue
        targets.append(target)
        out.append(Check("ok", f"target {target.id}: {len(target.vulnerabilities)} "
                               f"vulnerabilities, {len(target.decoys)} decoys"))
    public = [t.id for t in targets if t.public]
    if public:
        out.append(Check("warn", f"public target(s) {', '.join(public)}: may be in the models' "
                                 "training data; keep at least one private target for headline "
                                 "numbers"))

    try:
        prompts = load_prompts(matrix.prompts_file)
    except (OSError, json.JSONDecodeError) as exc:
        out.append(Check("fail", f"prompts file {matrix.prompts_file}: {exc}"))
        prompts = {}
    for name in sorted({p for c in matrix.conditions for p in matrix.prompts_for(c)}):
        if name in prompts:
            out.append(Check("ok", f"prompt {name!r} sha {prompt_hash(prompts[name])}"))
        elif prompts:
            out.append(Check("fail", f"prompt {name!r} is not in {matrix.prompts_file}"))

    if "triage" in matrix.conditions:
        for target in targets:
            if matrix.scanner in target.scans:
                out.append(Check("ok", f"target {target.id}: {matrix.scanner} scan present"))
            else:
                out.append(Check("fail", f"target {target.id} has no {matrix.scanner} scan for "
                                         f"triage: security-eval scan {matrix.scanner} "
                                         f"{target.manifest_path}"))

    if matrix.batch:
        out.extend(_batching(matrix))

    for effort in matrix.efforts:
        if effort and effort not in EFFORT_LEVELS:
            out.append(Check("fail", f"effort {effort!r}: use one of {', '.join(EFFORT_LEVELS)}"))
    if any(matrix.efforts):
        ignored = [m for m in matrix.models if m.split(":", 1)[0] not in EFFORT_PROVIDERS]
        if ignored:
            out.append(Check("warn", f"effort levels do not apply to {', '.join(ignored)}; "
                                     "those cells run at the provider's default"))

    for model in matrix.models:
        try:
            prices.price(model)
        except KeyError as exc:
            out.append(Check("fail", str(exc).strip("'\"")))
    try:
        projected = estimate(matrix, prices)
        level = "ok" if projected["fits"] else "fail"
        out.append(Check(level, f"projected ${projected['total_usd']:.2f} for "
                                f"{projected['cells']} cells against a budget of "
                                f"${matrix.budget_usd:.2f} (token figures: "
                                f"{projected['tokens_per_run']})"))
    except (KeyError, ManifestError) as exc:
        out.append(Check("fail", f"estimate: {exc}"))
    if matrix.repeats < 2:
        out.append(Check("warn", "one repeat: no variance can be reported"))

    if not fake:
        out.extend(_environment(matrix, supervisor))
    return out


def _batching(matrix: Matrix) -> list[Check]:
    """Which cells the Batches API will take, and which will run live at full price."""
    out: list[Check] = []
    one_shot = [c for c in matrix.conditions if c in BATCHABLE]
    if not one_shot:
        return [Check("warn", "batch is on, but no condition can be batched (the harness "
                              "condition always runs live)")]
    eligible = [m for m in matrix.models if supports_batch(m)]
    live = [m for m in matrix.models if not supports_batch(m)]
    if eligible:
        out.append(Check("ok", f"batched at half price: {', '.join(one_shot)} on "
                               f"{', '.join(eligible)}"))
        try:
            import anthropic  # noqa: F401
        except ImportError:
            out.append(Check("fail", "batching needs the Anthropic SDK: "
                                     "pip install -e \".[batch]\""))
    if live:
        out.append(Check("warn", f"no Batches API for {', '.join(live)}: those cells run live "
                                 "at full price (only Anthropic's own API offers batches)"))
    if "harness" in matrix.conditions:
        out.append(Check("ok", "the harness condition runs live: a supervised run is a "
                               "conversation, not a batch of independent requests"))
    return out


def _environment(matrix: Matrix, supervisor: str) -> list[Check]:
    out: list[Check] = []
    if "baseline" in matrix.conditions:
        try:
            import supervisor_harness  # noqa: F401
            out.append(Check("ok", "supervisor-harness importable (baseline condition)"))
        except ImportError:
            out.append(Check("fail", "baseline needs supervisor-harness: "
                                     "pip install -e \".[harness]\""))
    if "harness" in matrix.conditions and shutil.which("git") is None:
        out.append(Check("fail", "harness condition needs git on PATH"))
    if shutil.which(supervisor) is None:
        out.append(Check("fail", f"`{supervisor}` is not on PATH"))
        return out

    remote = sorted({m.split(":", 1)[0] for m in matrix.models} - LOCAL_PROVIDERS)
    local = sorted({m.split(":", 1)[0] for m in matrix.models} & {"ollama"})
    providers = _providers(supervisor)
    if providers is None:
        out.append(Check("fail", "`supervisor providers --json` did not answer"))
        return out
    for name in remote + local:
        info = providers.get(name) or {}
        if info.get("available"):
            out.append(Check("ok", f"provider {name} available"))
        else:
            out.append(Check("fail", f"provider {name} not available: "
                                     f"{info.get('error') or 'missing credentials or unreachable'}"
                                     " (checked as a cell sees it: empty SUPERVISOR_HOME)"))
    return out


def _providers(supervisor: str) -> dict[str, Any] | None:
    with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as ws:
        env = {k: v for k, v in os.environ.items() if not k.startswith("SUPERVISOR_ROUTE_")}
        env.update(SUPERVISOR_HOME=home, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [supervisor, "providers", "--json", "-w", str(Path(ws))], env=env,
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=120, check=False,
            )
            data = json.loads(proc.stdout)
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            return None
    providers = data.get("providers") if isinstance(data, dict) else None
    return providers if isinstance(providers, dict) else None


def render(checks: list[Check]) -> str:
    mark = {"ok": "ok  ", "warn": "WARN", "fail": "FAIL"}
    return "\n".join(f"{mark[c.level]}  {c.message}" for c in checks)
