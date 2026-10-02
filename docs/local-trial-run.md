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

- [Ollama](https://ollama.com), running, with a code model pulled. The trial
  run below used `qwen3.8-code` (27B, 4-bit, about 17 GB, 128k context). Any
  code model works for checking the plumbing, and a 7–9B model is much faster
  if your GPU is small.
- **Check the context window Ollama will actually use.** `ollama show <model>`
  lists the model's *context length* and, under *Parameters*, a `num_ctx` if
  the model sets one. Without `num_ctx`, Ollama uses its own small default
  (a few thousand tokens). A longer prompt is then cut off at the start,
  without any error, and the model reviews only the end of your code. A
  30,000-token baseline needs `num_ctx` well above that. If it is missing,
  make a variant that sets it:

  ```bash
  ollama create mymodel-64k -f Modelfile
  ```

  with a `Modelfile` of two lines: `FROM <model>` and `PARAMETER num_ctx 65536`.
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
  "repeats": 2,
  "budget_usd": 0,
  "tokens_per_run": { "baseline": [30000, 8000], "triage": [30000, 2000], "harness": [150000, 15000] }
}
```

Ollama costs nothing, so `budget_usd: 0` (no cap) is fine. `tokens_per_run`
is only used by `estimate`. The run replaces it with measured figures.

**Use at least two repeats, even here.** A model given the same code twice
does not report the same things. In the trial below, two baseline runs on
identical input shared one place out of six. With one repeat you cannot tell a
finding from luck, or a change that helped from one that didn't.

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

Then two checks that need no answer key:

- **Is the quoted code where the finding says?** For each finding, whether the
  code it quotes is at the lines it names, elsewhere in the file, or nowhere in
  it. *Quote not in file* is worth a reviewer's first look: it is the clearest
  sign of a made-up finding.
- **Missed, or never read?** How many files each cell read. The baseline is sent
  every source file. The harness records what its agents opened, so a low
  number here means the harness ran over code it never looked at.

Below that are the **measured tokens per run**, ready to paste into a real
matrix.

Each cell's raw output is in `runs/local/cells/.../findings.json`.

## 8. Judge the findings

```bash
security-eval adjudicate export runs/local --sheet runs/local/adjudication/sheet.csv --key runs/local/adjudication/key.json
```

This pools every condition's findings and the scanner's, merged by place and
shuffled, with nothing saying who reported what. It writes three files:

- **`review.html`**: open it in a browser. It works offline, needs nothing
  installed, and is where you read and judge. Choose *Reviewer A*, then for
  each candidate read what was reported and the code (flagged lines marked),
  and pick a verdict.
- **`sheet.csv`**: the record `import` reads, one short row per candidate.
- **`key.json`**: who reported what. Don't open it until you've judged
  everything.

What the verdicts mean (the page shows this too):

| Verdict | Meaning |
| --- | --- |
| `tp` | A real vulnerability in this code. You can point to the line, the untrusted input that reaches it, and what an attacker would gain. Ideally you could write a unit test that fails because of it. Never write an exploit. |
| `fp` | Not a vulnerability here: the input is not attacker-controlled, it is already validated, or the code is safe as used (MD5 for a cache key, say). A real bug that is not a security issue is also `fp`; say so in the notes. |
| `unsure` | You cannot decide from the code with reasonable effort, for example because it depends on how the code is deployed. Say in the notes what would settle it. |

Judge whether the issue is real, not whether the report is well written. Right
place but wrong CWE is still `tp` if the issue described is real; note the
right CWE.

Your answers are kept in the browser as you go. When done, press **Download my
verdicts**, which saves `sheet-reviewer_a.csv` to your downloads folder, then:

```bash
security-eval adjudicate import --sheet ~/Downloads/sheet-reviewer_a.csv --key runs/local/adjudication/key.json
```

One reviewer is enough for a trial. The study itself needs two, blind
(`docs/beyond-known-issues.md`): each downloads their own file, and `import`
takes both (`--sheet` twice), which is what kappa needs.

## 9. Did a change help?

After changing something (a prompt, a model, a harness version), run again into
a new folder and compare:

```bash
security-eval compare runs/local runs/local-2
```

Per condition it shows both runs' outcomes, time, tokens and findings. It also
shows how many places **both** runs found and the overlap as a share of all
places either found, plus how often triage gave the same verdict twice. Low
overlap on unchanged input is the noise floor: a difference smaller than that
is not a result. Each cell also records the harness commit it ran on, and the
report and the comparison show it.

## 10. From trial to budget

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

## The trial runs this guide was written from

Four files (about 98,000 characters) at the trust boundary of
[supervisor-harness](https://github.com/Lorkster/supervisor-harness): `core/tools.py`,
`core/paths.py`, `config.py` and `install.py`, at a fixed commit. Model:
`qwen3.8-code`, local, one repeat per run. The same snapshot and matrix were run three
times, changing only the harness:

| | run 1 | run 2 | run 3 |
| --- | --- | --- | --- |
| harness | `c8d0a47` | `bb5c8b7` (first scope fix) | `1f99b30`, merged as `163a965` (both scope routes, readable tool results) |
| baseline | 4 findings, 42 s | 3 findings, 41 s | 4 findings, 39 s |
| triage of Bandit's 4 | all false positive | all false positive | all false positive |
| harness outcome | stopped one agent | stopped its only agent | **ok**, no agent stopped |
| harness findings (places) | 9 (4) | 0 | 8 (7) |
| harness time, tokens in / out | 2 min, 143k / 11k | 38 s, 81k / 2k | 2 min 18 s, 213k / 11k |

What the runs showed, in order:

- **Two harness bugs that only real code exposed.** The planner wrote the workspace's
  absolute path as each agent's scope (run 1), and also as the run-wide envelope that
  agents inherit (run 2). Agents report relative paths, so every file they read counted
  as "outside the declared scope". Drift control stopped them, and in run 2 the
  correction persuaded the model that the files in front of it were not the code it had
  been asked to review.
- **A third harness bug: silently cut tool results.** Each round's results were sliced
  to 8,000 characters. An agent asking for four files saw part of the first, with no
  sign that anything was missing. It said it had not reached two of the files.
- **Run 3, with all three fixed:** both agents read all four files in their first turn,
  were accepted with a drift score of 0, and reported more specific issues.
- **Same input, different answers.** The baseline got the same 30,296-token prompt every
  time. Runs 1 and 2 shared one place out of six, and runs 2 and 3 shared two out of
  five. Triage gave the same verdicts every time. That's why section 5 says to repeat.
- **The tokens are the point.** At Sonnet 5.5 list prices, run 3's three cells would cost
  roughly $0.07, $0.25 and $0.53 live, and less for the first two with batching and caching.
- **The snapshot left context out.** Both agents in run 3 noted that `tools.py` calls into
  modules that weren't in the snapshot. `import-code` now lists them when it takes one.

Run 3's review page, with its 11 unjudged candidates, is in
[`examples/review/`](../examples/review/).

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `bandit` not found | install the `scanners` extra; it is found inside the virtual environment even when that is not activated |
| `provider ollama not available` | start Ollama (`ollama serve`) and check `ollama list` |
| `too large for the baseline` | import fewer files |
| a cell ends `invalid_output` | the model's answer was not the JSON asked for; the detail shows the start of it. Common with small models; a result, not a bug |
| the report warns of answers with no findings in a few tokens | the model gave up rather than finding nothing. With Ollama this was its JSON-schema grammar collapsing on a long prompt: a 90,000-token review came back as `{"findings": []}` in 11 tokens. Harness [#77](https://github.com/Lorkster/supervisor-harness/pull/77) switches long prompts to JSON mode. Otherwise check `num_ctx` (section 1) and try a smaller slice |
| `harness_stopped` | not an error: drift control stopped an agent, and the report says why |
| `data policy forbids anthropic` | working as intended: the target is local-only. Approve other providers with `import-code --allow` only if the code may go there |
