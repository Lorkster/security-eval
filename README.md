# security-eval

Measure how well language models find, triage and fix vulnerabilities when
they run unattended — on their own, and supervised by
[supervisor-harness](https://github.com/Lorkster/supervisor-harness). Every
finding is scored against ground truth, and every dollar is recorded.

**Start with [`docs/proposal.md`](docs/proposal.md)**, then:

- [`docs/models-and-budget.md`](docs/models-and-budget.md), before spending anything;
- [`docs/working-with-regulated-models.md`](docs/working-with-regulated-models.md),
  on getting the best legitimate results and treating refusals as data;
- [`docs/preregistration.md`](docs/preregistration.md), filled in and
  committed before the pilot;
- [`docs/local-trial-run.md`](docs/local-trial-run.md), to try everything on
  your own code with a local model, for free.

> **Status: ready for the pilot.** Every harness prerequisite is merged, and
> the dependency is pinned to that commit. Both conditions have run end to end
> against a local Ollama model. The harness condition reads its results only
> through the harness's published command line (`findings`, `status`, `events`).
> No paid model has been called yet. That is stage 1, below.

## Quick start (costs nothing)

```bash
python -m venv .venv
.venv/Scripts/activate            # Windows; `source .venv/bin/activate` elsewhere
pip install -e ".[dev,harness,batch]"

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

**Try it on your own code, for free, before paying for anything:**
[`docs/local-trial-run.md`](docs/local-trial-run.md). It covers snapshotting
files you own (`security-eval import-code`, local models only by default),
running every condition on a local model, reading the report, and judging the
findings. You come away with the measured token figures the budget needs.

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

## Triage of scanner output (RQ3)

The company already runs scanners. RQ3 asks whether a model can sift their
output: dismiss the noise, keep the real issues.

```bash
security-eval scan bandit benchmarks/notes-api/manifest.json    # or semgrep, snyk, --command
```

The scan's SARIF is stored beside the benchmark and named in its manifest, so it
is frozen material like the code. A matrix with the `triage` condition then asks
the model about each scanner finding on its own, with the whole repository in
view. Each finding is labelled real or not by the answer key, using the scorer's
own rule. The report gives **noise dismissed** (not-real findings judged false
positive), **real kept** (real ones judged true positive) and accuracy. It also
scores each scanner on the same answer key as the models, so the company's own
tools are part of the comparison.

## Beyond known issues

Known-issue benchmarks are calibration. The study's headline is what lies past
them. See [`docs/beyond-known-issues.md`](docs/beyond-known-issues.md).

```bash
security-eval import-fix REPO --vulnerable SHA --fixed SHA --published DATE --cwe CWE-79 \
    --dest benchmarks/ts-001                        # RQ5: disclosed after the cutoff
security-eval adjudicate export runs/real           # RQ6/RQ7: blind sheet for two reviewers
security-eval adjudicate import --matrix configs/matrix.real.json
```

- **Time-split targets** export the vulnerable version without history and take
  the answer key from the fix commit. Preflight refuses one disclosed before a
  model's training cutoff (`configs/models.json`), an id that names the
  advisory, or a harness config that could reach the network.
- **Real code** (`"open": true`) has no key. Its findings, with the scanners',
  are pooled, merged by place, and judged blind by two reviewers.
  `adjudicate import` gives kappa, precision, findings beyond the scanners,
  relative recall and attacker-proxy coverage, and scores triage against the
  verdicts.
- **Where code goes** depends on the route (Anthropic, AWS, a third party, or
  nowhere for Ollama). A manifest's `allowed_providers` holds the owner's
  approval. Preflight and the runner both refuse anything else.

### Fix verification (RQ8)

```bash
security-eval sandbox build benchmarks/notes-api/manifest.json   # needs docker or podman
security-eval sandbox check benchmarks/notes-api/manifest.json
security-eval run configs/matrix.fix.json
security-eval verify runs/fix
```

The `fix` condition asks for edits and a new regression test for each known
flaw. `verify` runs them in a container with no network. The test must fail on
the vulnerable code, for a real reason and not because it calls something the
fix adds. It must pass with the fix, and the project's suite must lose nothing.
On time-split targets, the real fix's own tests are run against the proposal
too. Target code and model-written tests only ever run inside the container.

## Batching (half price)

`"batch": true` in a matrix (or `run --batch`) sends eligible cells through the
Message Batches API at half price. **Only Anthropic's own API offers it.**
Bedrock, Vertex, OpenRouter and Ollama do not, and their cells run live at full
price; `check` says which is which. The harness condition always runs live,
because a supervised run is a conversation, not a batch of independent requests.

A batch usually finishes within an hour and always within 24. `run` submits it
and returns; running it again collects the results (`--wait` stays until they
are back). The batch id is written to `batches.json` as soon as it is accepted,
so a crash or a re-run never pays for the same requests twice. While a batch is
out, its projected cost counts against the budget. A batched request is the same
request the harness would send live, and a test holds the two equal. In triage,
the repository text is prompt-cached across a target's findings.

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
  notes-api/         six flaws across five files, incl. cross-file and authorisation;
                     verify/ holds its sandbox and test suite, never sent to a model
src/security_eval/
  finding.py         the finding format: CWE, file:line, severity, triage verdict
  manifest.py        benchmark targets, validated against their code
  scoring.py         deterministic matching; precision/recall, loose and strict
  sarif.py           SARIF 2.1.0 in (scanner output) and out
  budget.py          prices, cost, the budget guard
  ledger.py          append-only record of every cell; resumption
  matrix.py          cells, priority order, estimate, run
  preflight.py       everything checkable before a token is paid for
  batch.py           the Message Batches API: eligibility, requests, the in-flight record
  scanners.py        run scanners, keep their SARIF, label findings by the answer key
  sandbox.py         the container fix verification runs in; JUnit reports
  fixes.py           RQ8: apply a proposal, check it stage by stage
  timesplit.py       time-split targets from a real fix commit
  snapshot.py        real code you own as a target, for a free trial run
  adjudication.py    blind pooling, review sheets, kappa and the open-world metrics
  report.py          the ledger, aggregated into the study's numbers
  runners/
    fake.py          zero-cost runner answering from the manifest
    baseline.py      one model, one prompt, via the harness's provider layer
    harness.py       one supervised harness run, isolated per cell, read back
                     through the harness's published CLI
    triage.py        RQ3: a model's verdict on each scanner finding
    fix.py           RQ8: a fix and a regression test for each known flaw
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
