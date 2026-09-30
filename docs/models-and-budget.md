# Models and budget

*Prices are Anthropic first-party API rates as of 2026-09-25. Bedrock and
Vertex bill separately and differently. Check the provider's pricing page
before committing a budget; `configs/prices.json` is the copy the budget guard
reads, and it must be updated to match.*

The constraint this document is written around: **a student budget cannot pay
to discover that a path was never viable.** So money is spent in stages, each
of which can kill a path cheaply before the next one spends more.

---

## The four stages of spending

| Stage | What it answers | Models | Rough cost |
| --- | --- | --- | --- |
| **0. Plumbing** | does the pipeline run end to end? | the fake runner; a local Ollama model | **$0** |
| **1. Viability gate** | does this model refuse the work, break the output format, or find nothing? | each candidate, ~10 calls on the toy target | cents to a few dollars in total |
| **2. Pilot** | what does one run of each condition actually cost? | the survivors, one target, one repeat | ~5% of the budget |
| **3. Matrix** | the research questions | the plan below | the rest, under the budget guard |

Never skip a stage to save time. Stage 0 is where most bugs are found, and a
bug found at stage 3 is paid for once per cell.

### Stage 1 is the important one

For every candidate, before it goes anywhere near the matrix, measure three
things on `benchmarks/toy-webapp`:

1. **Refusal rate.** Current Claude models run safety classifiers, and `cyber`
   is one of the categories they decline in. Defensive code review of your own
   code is ordinary work for them, but false positives happen, and they are
   more likely the closer a prompt gets to asking for an exploit. A model that
   refuses a meaningful share of *this* task is not viable, however good it is
   elsewhere. Keep prompts to find, explain and fix.
2. **Output validity.** Does it return findings in the required structure, with
   a file and a line? A model that needs retries to produce parseable output
   costs a multiple of its list price.
3. **Any signal at all.** Does it find at least the obvious seeded
   vulnerabilities? If not, drop it. Don't run it across the matrix to confirm
   the zero.

`security-eval gate` runs this (it is the matrix driver pointed at the toy
target, with the baseline condition only).

---

## Which models, for what

| Role | Model | $ in / out per 1M tokens | Why this one |
| --- | --- | --- | --- |
| **Workhorse** — every cell of the matrix | Claude Sonnet 5.5 (`claude-sonnet-5-5`) | $2 / $10 | the best capability for the price for reading code; the model the headline numbers come from |
| **Ceiling** — a subset of targets, one repeat | Claude Opus 5.5 (`claude-opus-5-5`) | $4 / $20 | only 2× the workhorse. Shows how much headroom a stronger model has, without paying for it on every cell |
| **Cheap tier** — triage of scanner findings (RQ3), harness drift checks | Claude Haiku 4.5 (`claude-haiku-4-5`) | $1 / $5 | high-volume, simple judgements |
| **Free tier** — plumbing, and an optional open-weight comparison | a code model on local Ollama | $0 (your hardware) | nothing leaves the machine; slow and weaker, which is fine for stage 0 |

**Not recommended:** Claude Fable 5.1 ($10 / $50). It is 5× the workhorse, and a
student budget is better spent on repeats and targets than on one very capable
data point. The same goes for fast mode (2× price for speed nobody needs in a
batch study).

**Open-weight models through OpenRouter** are a reasonable additional arm if the
group wants a "small / open versus frontier" comparison. Put them through
stage 1 exactly like the others. Their prices change often, so check the
current listing rather than trusting a number written here.

### How to call them

These settings matter as much as the choice of model:

- **Effort, not model, is the first dial.** Current Claude models take an effort
  level (`low` … `max`). Start triage at `low` and analysis at `medium`, and
  raise it only if the pilot shows it helps. Opus 5.5 defaults to `medium`;
  set it explicitly either way so it is recorded. A lower effort on the
  workhorse often beats a cheaper model, and costs one config line to test.
- **Thinking stays on.** Opus 5.5 and Sonnet 5.5 do not allow it to be
  disabled. Thinking tokens bill as output, so budget output generously.
- **Give responses room.** Truncated output is a failed run you paid for. Keep
  `max_tokens` well above the expected answer (16k for a structured findings
  list is not excessive).
- **Prompt caching.** The fixed part of every prompt — instructions, schema,
  and in the baseline, the target's code — is identical across repeats. Cached
  reads cost about a tenth of input. The harness does not cache yet
  (prerequisite P2); the baseline runner should.
- **Batch API: half price** for anything that is one independent request: the
  baseline condition and RQ3 triage. Results arrive within hours, not seconds,
  which is fine for a study. The harness's multi-turn runs cannot use it.
- **Pin model IDs.** Always the exact ID in the table, recorded in the ledger
  for every cell.

### Prerequisite: the harness has to be able to call these models

Today the harness's Anthropic and Bedrock providers send `temperature` on every
request. Current Claude models reject sampling parameters, so the harness
condition **cannot run on Sonnet 5.5 or Opus 5.5 until prerequisite P2 in the
proposal is merged**. Haiku 4.5 works. The baseline condition hits the same
wall, because it deliberately goes through the same provider layer. Don't spend
the viability gate discovering this; it fails with an HTTP 400 on the first
call.

---

## First measurements (one run each, local model, toy target)

Both conditions were run once on `benchmarks/toy-webapp` with a local
`qwen3.8-code` through Ollama, on 2026-09-30. **n = 1, on a model nobody will use
for the headline numbers, on a target too easy to tell models apart.** These
numbers illustrate the shape of the trade-off. They don't measure it.

| | baseline | harness |
| --- | --- | --- |
| findings | 5 | 26 (12 duplicates across lenses, 4 unanchored) |
| recall, loose / strict | 1.00 / 1.00 | 1.00 / 0.80 |
| precision, loose | 1.00 | 0.36 (4 of the 5 false positives were on decoys) |
| tokens in / out | ~1k / ~0.8k | ~42k / ~33k |
| wall clock | 76 s | 8 min |
| outcome | ok | `harness_stopped`: the security lens was refocused four times for "no progress" while it was still reading files, and ran out of turns |

What it already shows:

- **The harness multiplies tokens far more than the 6× assumed below** on a tiny
  target. Part of that is fixed overhead (briefs, schemas, several lenses), so
  the ratio should fall as targets grow, but only the pilot can say how far.
  Treat the worked budget's harness figures as optimistic until then.
- **Duplicates and decoys are where the harness loses precision.** Several
  lenses report the same bug, and the extra reporting surface catches more
  look-alikes. The scorer counts duplicates separately, so the write-up can
  report both readings.
- **Harness-stopped runs are real, and on the lens that matters most.** Every
  refocus is a paid turn. RQ4 needs this outcome recorded, and the pilot should
  check how often it happens on Claude models before the matrix is sized.

## A worked budget

**The token figures below are assumptions, not measurements.** The pilot's job is
to replace them. They are here so the group can see how the arithmetic works
and choose a budget with its eyes open.

Assumed per run, on a small target:

| Condition | Input tokens | Output tokens |
| --- | --- | --- |
| baseline | 60k | 8k |
| harness (≈4 lenses × a few turns, synthesis, drift checks) | 400k | 40k |

Cost of one run:

| Model | baseline | harness |
| --- | --- | --- |
| Sonnet 5.5 | 0.06×2 + 0.008×10 = **$0.20** | 0.4×2 + 0.04×10 = **$1.20** |
| Opus 5.5 | **$0.40** | **$2.40** |
| Haiku 4.5 | **$0.10** | **$0.60** |

A matrix sized for the research questions:

| Block | Cells | Cost |
| --- | --- | --- |
| Sonnet 5.5, 20 targets × 2 conditions × 3 repeats | 120 | 60 × $0.20 + 60 × $1.20 = **$84** |
| Opus 5.5 ceiling, 10 targets × 2 conditions × 1 repeat | 20 | 10 × $0.40 + 10 × $2.40 = **$28** |
| RQ3 triage, 500 scanner findings on Haiku 4.5 via Batch (≈3k in / 500 out each) | 500 | ≈ **$1.40** |
| Viability gate and pilot | — | ≈ **$10** |
| **Subtotal** | | **≈ $123** |
| Contingency (the assumptions are probably optimistic about the harness) | +40% | **≈ $170** |

Using Batch for the baseline cells halves their share. Prompt caching in the
harness (once P2 lands) should cut its input cost noticeably, though by how much
is a pilot measurement, not a promise.

**What moves the total most**, in order: the number of harness cells (each is
~6× a baseline cell), target size (tokens scale with the code read), repeats,
and only then the model.

### If the budget is smaller

Cut in this order. Each step keeps a publishable comparison:

1. Drop the Opus ceiling to 5 targets.
2. Drop repeats from 3 to 2 on the harness condition only.
3. Drop to 10 targets.
4. Run the baseline on Batch.

Don't cut the viability gate or the pilot. They are what keep the rest of the
money from being wasted.

---

## Keeping to the budget

- `security-eval estimate` projects a matrix's cost from `configs/prices.json`
  and per-run token figures: assumptions at first, the pilot's measurements
  after.
- `security-eval run` refuses to start a cell whose projected cost would take
  total spend past `budget_usd`. It records the refusal in the ledger as
  `skipped_budget`, so it is visible, not silent.
- The ledger is append-only. A matrix stopped by a crash, a refusal or the
  budget resumes where it stopped, and never pays for a finished cell twice.
- Cells run core comparison first (workhorse × both conditions × first repeat
  across all targets), so if the money runs out, what is finished is still a
  complete comparison.
