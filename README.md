# security-eval

Measure how well language models find and triage known vulnerabilities when
they run unattended — on their own, and supervised by
[supervisor-harness](https://github.com/Lorkster/supervisor-harness). Every
finding is scored against ground truth, and every dollar is recorded.

**Start with [`docs/proposal.md`](docs/proposal.md)**, then:

- [`docs/models-and-budget.md`](docs/models-and-budget.md), before spending anything;
- [`docs/working-with-regulated-models.md`](docs/working-with-regulated-models.md),
  on getting the best legitimate results and treating refusals as data;
- [`docs/preregistration.md`](docs/preregistration.md), filled in and
  committed before the pilot.

> **Status: skeleton.** The scorer, SARIF, budget guard, ledger, matrix driver
> and fake runner are complete and tested. The baseline runner has run for real
> against a local Ollama model. The harness runner is wired to the harness, but
> it cannot run on current Claude models until harness prerequisite **P2** is
> merged (proposal §3).

## Quick start (costs nothing)

```bash
python -m venv .venv
.venv/Scripts/activate            # Windows; `source .venv/bin/activate` elsewhere
pip install -e ".[dev,harness]"

security-eval validate benchmarks/toy-webapp/manifest.json
security-eval run configs/matrix.fake.json --fake
security-eval estimate configs/matrix.example.json
```

`--fake` answers every condition from the answer key, so the whole pipeline —
matrix, ledger, budget guard, scorer — runs for $0. Try every change there
first.

With [Ollama](https://ollama.com) running, a real model call is still free:

```bash
security-eval gate ollama:qwen3.8-code:latest --repeats 1
```

## The stages of spending

| Stage | Command | Cost |
| --- | --- | --- |
| 0. plumbing | `run configs/matrix.fake.json --fake`, then `gate ollama:...` | $0 |
| 1. viability gate | `gate anthropic:claude-sonnet-5-5 anthropic:claude-opus-5-5 ...` | cents to a few dollars |
| 2. pilot | `run configs/matrix.pilot.json` | ~5% of the budget |
| 3. matrix | `estimate` → then `run` your matrix | the rest, capped by `budget_usd` |

Every `run` is resumable: re-running the same matrix skips finished cells and
retries only errors. A refusal or invalid output is a *result* and is not
retried. See `docs/models-and-budget.md` for why.

## Layout

```
docs/                proposal, models and budget
configs/             price table (dated), matrices, frozen prompts
benchmarks/          targets and their answer keys (manifest.json)
  toy-webapp/        five seeded vulnerabilities, five decoys; for plumbing
src/security_eval/
  finding.py         the finding format: CWE, file:line, severity, triage verdict
  manifest.py        benchmark targets, validated against their code
  scoring.py         deterministic matching; precision/recall, loose and strict
  sarif.py           SARIF 2.1.0 in (scanner output) and out
  budget.py          prices, cost, the budget guard
  ledger.py          append-only record of every cell; resumption
  matrix.py          cells, priority order, estimate, run
  runners/
    fake.py          zero-cost runner answering from the manifest
    baseline.py      one model, one prompt, via the harness's provider layer
    harness.py       one supervised harness run, isolated per cell
  cli.py
tests/
```

## Output

`runs/<matrix>/ledger.jsonl` has one line per attempt: cell, model, outcome,
tokens, cost, seconds. Each cell's `findings.json` and `score.json` sit under
`runs/<matrix>/cells/`. `runs/` is git-ignored; share results deliberately.

## Adding a benchmark

1. Put the code under `benchmarks/<name>/src/`. **Nothing in it may hint at the
   answers**, because the model reads it all. No comments saying what is
   planted, no telling names.
2. Write `benchmarks/<name>/manifest.json` (format in `src/security_eval/manifest.py`).
   Include decoys.
3. `security-eval validate benchmarks/<name>/manifest.json`
4. Have someone else review the manifest against the code.

The toy target is too easy to tell models apart: a local 27B code model scored
5/5 on it, CWE included. It proves the plumbing works. Real benchmarks have to
be harder.

## Rules

- Only intentionally vulnerable code, or code the group owns. No live systems.
- Find, explain, fix. No exploit generation.
- If a real vulnerability turns up in a public project, stop and follow that
  project's disclosure policy.
- API keys come from the environment or `~/.supervisor/config.json`. Never commit them.
