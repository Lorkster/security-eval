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

> **Status: ready for the pilot.** Every harness prerequisite is merged, and
> the dependency is pinned to that commit. Both conditions have run end to end
> against a local Ollama model. The harness condition reads its results only
> through the harness's published command line (`findings`, `status`, `events`).
> No paid model has been called yet. That is stage 1, below.

## Quick start (costs nothing)

```bash
python -m venv .venv
.venv/Scripts/activate            # Windows; `source .venv/bin/activate` elsewhere
pip install -e ".[dev,harness]"

security-eval validate benchmarks/*/manifest.json
security-eval run configs/matrix.fake.json --fake
security-eval report runs/fake
security-eval check configs/matrix.example.json
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
| 2. pilot | `run configs/matrix.pilot.json`, then `report runs/pilot` | ~5% of the budget |
| 3. matrix | put the pilot's measured `tokens_per_run` in, `estimate`, then `run` | the rest, capped by `budget_usd` |

`run` and `gate` run `check` first and start nothing if it fails. It checks
manifests, prompts, effort levels and prices, whether the budget fits, whether
the harness CLI and git are present, and whether each model's provider answers,
tested the way a cell will see it. Every `run` is resumable: re-running the
same matrix skips finished cells and retries only errors. A refusal or invalid
output is a *result* and is not retried. See `docs/models-and-budget.md` for
why.

## Results

`security-eval report runs/<matrix>` writes `report.md`, `report.json` and
`cells.csv` beside the ledger:

- recall and precision, loose (right place) and strict (right place and CWE),
  as median and range over repeats;
- **ok** runs and **completed** runs (ok plus harness-stopped) side by side,
  since a harness stop is the harness's outcome, not the model's;
- cost per true positive, refusal rate, harness-stopped rate, and why each
  stopped agent was stopped;
- where precision went: decoy hits, duplicates, unanchored findings, and
  locations recovered from evidence rather than stated;
- recall per CWE, showing which classes of flaw each condition misses;
- the median tokens per run measured, ready to replace the budget assumptions.

Scores are recomputed from each cell's saved findings, so a scoring fix reaches
runs already made. `--stated-only` counts a location recovered from evidence as
none, which shows how much that leniency is doing.

## Layout

```
docs/                proposal, models and budget
configs/             price table (dated), matrices, frozen prompts
benchmarks/          targets and their answer keys (manifest.json)
  toy-webapp/        five seeded vulnerabilities, five decoys; for plumbing only
  notes-api/         six flaws across five files, incl. cross-file and authorisation
src/security_eval/
  finding.py         the finding format: CWE, file:line, severity, triage verdict
  manifest.py        benchmark targets, validated against their code
  scoring.py         deterministic matching; precision/recall, loose and strict
  sarif.py           SARIF 2.1.0 in (scanner output) and out
  budget.py          prices, cost, the budget guard
  ledger.py          append-only record of every cell; resumption
  matrix.py          cells, priority order, estimate, run
  preflight.py       everything checkable before a token is paid for
  report.py          the ledger, aggregated into the study's numbers
  runners/
    fake.py          zero-cost runner answering from the manifest
    baseline.py      one model, one prompt, via the harness's provider layer
    harness.py       one supervised harness run, isolated per cell, read back
                     through the harness's published CLI
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
   Include decoys. Where a flaw can fairly be reported in more than one place,
   list the others under `also`; where several CWEs describe it correctly, give
   `cwe` as a list. Otherwise a correct finding is scored as wrong.
3. `security-eval validate benchmarks/<name>/manifest.json`
4. Have someone else review the manifest against the code.

The toy target is too easy to tell models apart: a local 27B code model scored
5/5 on it, CWE included. It proves the plumbing works. `notes-api` is the
pattern to follow. The same model found 5 of its 6 flaws and missed the
authorisation one, which no single line gives away. Real benchmarks have to be
at least that hard.

## Rules

- Only intentionally vulnerable code, or code the group owns. No live systems.
- Find, explain, fix. No exploit generation.
- If a real vulnerability turns up in a public project, stop and follow that
  project's disclosure policy.
- API keys come from the environment or `~/.supervisor/config.json`. Never commit them.
