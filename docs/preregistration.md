# Pre-registration

*Fill in and commit **before** the pilot's results are seen. After that, this
file only gains dated amendments at the bottom, each with its reason. Nothing
above the amendments line is edited.*

Why: see [`working-with-regulated-models.md`](working-with-regulated-models.md),
"Keeping the study honest".

---

**Date frozen:** YYYY-MM-DD  **Commit:** (hash of the commit that freezes this file)

## Hypotheses

Stated so each can come out either way.

- **H1** (RQ1): regulated model *M* reaches recall ≥ ___ (loose) on the held-out targets.
- **H2** (RQ2): the harness condition differs from the baseline by ≥ ___ in F1, at a cost per true positive of ___.
- **H3** (RQ3): triage accuracy ≥ ___ against labels.
- **H4** (refusals): the refusal rate on defensive tasks is ≤ ___ for the `plain` prompt; `context` changes it by ___.

## Primary metrics

- Recall and precision, loose and strict (`src/security_eval/scoring.py`), tolerance ___ lines.
- Cost per true positive, from the ledger.
- Refusal rate, per model and prompt.
- Harness-stopped rate (RQ4).

Which one is **primary** for each hypothesis: ___

## Frozen configuration

| | Value |
| --- | --- |
| models (exact IDs) | |
| effort per stage | |
| prompts (names, and `prompt_sha` from a dry run) | |
| repeats | |
| budget cap | |
| harness version (commit) | |
| security-eval version (commit) | |

## Targets

- **Development set** (tuning allowed): ___
- **Held-out set** (headline numbers, no tuning): ___
- How the split was made (before looking at any results): ___

## Tracks beyond known issues

- Time-split targets, their disclosure dates, and the cutoff **margin** required: ___
- Training cutoffs used (`configs/models.json`, with the source of each): ___
- Real-code targets, and which may go to which providers (`allowed_providers`): ___
- Attacker proxies: ___
- Adjudication: reviewers (two, named), how disagreements are resolved, maximum
  candidates (random sample if over), and what evidence a `tp` needs: ___
- Fix verification: targets with a `verify` section, their images (by id, from
  `verify.json`), any `wrong_reasons` beyond the defaults, and how many verified
  proposals a reviewer reads by hand: ___

## Exclusion rules

A run, target or model is excluded only if: ___

(For example: target manifest found to be wrong on review, fixed, and *all*
conditions re-run on it; provider outage recorded as `error`.)

## Stopping rule

The matrix stops when: ___ (all cells complete, or budget exhausted; if the
budget runs out, the core comparison is what gets reported, per the cell order).

## Analysis plan

The report also shows, beside the scores, consistency across repeats, whether a
finding's quoted code is where it says, and whether a miss was in a file the
condition read (`src/security_eval/checks.py`). None of them changes a score.
They are exploratory unless named here as primary.

- How repeats are summarised (median and range, not mean alone): ___
- Comparisons and how uncertainty is shown: ___
- What would count as "no difference": ___

---

## Amendments

*Dated, with reasons. Never edit above this line.*
