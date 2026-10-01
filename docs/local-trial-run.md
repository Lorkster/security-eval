# A free trial run on real code

*Run the whole pipeline on code you own, with a model on your own machine,
before spending anything on paid models.*

A local run costs nothing, and no code leaves the machine. It shows four
things the paid stages depend on:

- the pipeline works on real code, not just the benchmarks;
- how long each condition takes;
- how many tokens each condition uses: the figures `estimate` needs;
- whether a model's output holds its format.

It also gives you a first set of findings to practise adjudication on.

It does **not** tell you how good Claude is. A local open-weight model is
weaker and different. Its numbers are not study results, unless the
pre-registration names it as an attacker proxy (RQ7).

---

## 1. What you need

- The project installed with the harness and Bandit:

  ```bash
  pip install -e ".[dev,harness,scanners]"
  ```

- [Ollama](https://ollama.com), running, with a code model pulled. Check its
  context window with `ollama show <model>`, under *context length* and
  *num_ctx*. The trial run below used `qwen3.8-code` (27B, 4-bit, about
  17 GB, 128k context). Any code model works for checking the plumbing, and a
  7–9B model is much faster if your GPU is small.
- No API keys.

## 2. Choose code you own

- Use **code you own or are allowed to analyse**. Company code is fine to run
  locally, since nothing leaves the machine, but whatever you find in it goes
  to the company.
- **Choose a slice, not a whole repository.** The baseline sends everything in
  one request, at most 400,000 characters. Allow about four characters per
  token, and stay well inside your model's context window. Choose the files
  where trust is decided: input handling, authentication, file access, running
  commands, configuration.
- **Only committed files.** The snapshot is taken at a commit, so uncommitted
  work is never included and every condition sees the same code.

## 3. Snapshot it

```bash
security-eval import-code ../myproject src/myproject/auth.py src/myproject/files.py --dest runs/_targets/mycode
```

This writes `runs/_targets/mycode/` with:

- **`code/`**: the files at `HEAD` (or `--commit`), with no git history, at
  their repository paths. A finding at `src/myproject/auth.py:42` names the
  same line in your repository.
- **`manifest.json`**: `"open": true`, meaning real code with no answer key,
  and `"allowed_providers": ["ollama"]`. The code may go **only to local
  models**. If a matrix names any other model, preflight fails, and the runner
  refuses it even with `--skip-check`. Use `--allow` to approve others
  deliberately.

It also prints the size, so you know before running whether it fits.

**Keep it under `runs/`.** `runs/` is git-ignored, and this repository is
public. Never put private code under `benchmarks/`.

## 4. Scan it

```bash
security-eval scan bandit runs/_targets/mycode/manifest.json
```

Bandit's output is what the triage condition judges. On real code most of it
is usually noise, which is exactly what triage is for.

## 5. The matrix

Copy `configs/matrix.local.json` and edit the target path and the model:

```json
{
  "name": "local",
  "targets": ["../runs/_targets/mycode/manifest.json"],
  "conditions": ["baseline", "triage", "harness"],
  "models": ["ollama:qwen3.8-code:latest"],
  "repeats": 1,
  "budget_usd": 0,
  "tokens_per_run": { "baseline": [30000, 8000], "triage": [30000, 2000], "harness": [150000, 15000] }
}
```

Ollama costs nothing, so `budget_usd: 0` (no cap) is fine. `tokens_per_run`
is only used by `estimate`. The run replaces it with measured figures.

## 6. Check, then run

```bash
security-eval check configs/matrix.local.json
```

```bash
security-eval run configs/matrix.local.json --out runs/local
```

`check` confirms that Ollama answers, the scan is present and the target is
allowed to go to the models you named. The run is resumable: run it again and
it continues where it stopped. The harness condition is the slow one: several
agents, several turns each.

## 7. Read the results

```bash
security-eval report runs/local
```

Real code has no answer key, so nothing is scored. The report's section
**Real code, awaiting adjudication** gives, per condition:

- **findings and places**: places count findings on the same lines once, so
  more findings than places means repeats;
- **triage verdicts**;
- **time**;
- **why the harness stopped any agent**.

Below that are the **measured tokens per run**, ready to paste into a real
matrix.

Each cell's raw output is in `runs/local/cells/.../findings.json`.

## 8. Judge the findings

```bash
security-eval adjudicate export runs/local --sheet runs/local/adjudication/sheet.csv --key runs/local/adjudication/key.json
```

The sheet pools every condition's findings and the scanner's, merged by place
and shuffled, with nothing saying who reported what. Mark each one `tp`, `fp`
or `unsure` in the `reviewer_a` column, then:

```bash
security-eval adjudicate import --sheet runs/local/adjudication/sheet.csv --key runs/local/adjudication/key.json
```

One reviewer is enough for a trial. The study itself needs two, blind
(`docs/beyond-known-issues.md`), and kappa needs both columns filled.

## 9. From trial to budget

Turn the measured tokens into a price before choosing a paid model:

```bash
security-eval estimate configs/matrix.pilot.json
```

Two cautions:

- Claude's tokenizer counts the same text differently from an open model's,
  and Claude models may write longer answers. Treat the conversion as rough,
  and let the pilot (stage 2) replace it.
- Triage sends the repository once for each scanner finding. That is why
  batching and prompt caching matter for it on Claude: the cached repository
  is billed at a fraction of the input price after the first request.

---

## The trial this guide was written from

Four files (about 98,000 characters) at the trust boundary of a private
Python project. Model: `qwen3.8-code`, local. One repeat. All of it free.

| condition | outcome | time | tokens in / out | findings (places) |
| --- | --- | --- | --- | --- |
| baseline | ok | 42 s | 30,296 / 1,047 | 4 (4) |
| triage of Bandit's 4 | ok | 28 s | 121,410 / 1,177 | all 4 judged false positives |
| harness | harness_stopped | 2 min | 142,714 / 11,264 | 9 (4) |

- **The tokens are the point.** At Sonnet 5.5 list prices, the same three cells
  would cost roughly $0.07, $0.25 and $0.40 live, and much less for the first
  two with batching and caching.
- **Triage** dismissed Bandit's four findings: two "hardcoded passwords" that
  were the strings `-` and `--`, a `subprocess` import, and a `subprocess`
  call. Whether that was right is the reviewers' call, not the model's.
- **Harness.** It stopped one agent because its turn repeated the previous one
  exactly. The repeated turn's findings were still stored, so there were 9
  findings in 4 places. The *places* column exists to make that visible.
- **Ten candidates** went onto the review sheet.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `bandit` not found | install the `scanners` extra; it is found inside the virtual environment even when that is not activated |
| `provider ollama not available` | start Ollama (`ollama serve`) and check `ollama list` |
| `too large for the baseline` | import fewer files |
| a cell ends `invalid_output` | the model's answer was not the JSON asked for; the detail shows the start of it. Common with small models; a result, not a bug |
| `harness_stopped` | not an error: drift control stopped an agent, and the report says why |
| `data policy forbids anthropic` | working as intended: the target is local-only. Approve other providers with `import-code --allow` only if the code may go there |
