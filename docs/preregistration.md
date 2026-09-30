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

## Exclusion rules

A run, target or model is excluded only if: ___

(For example: target manifest found to be wrong on review, fixed, and *all*
conditions re-run on it; provider outage recorded as `error`.)

## Stopping rule

The matrix stops when: ___ (all cells complete, or budget exhausted; if the
budget runs out, the core comparison is what gets reported, per the cell order).

## Analysis plan

- How repeats are summarised (median and range, not mean alone): ___
- Comparisons and how uncertainty is shown: ___
- What would count as "no difference": ___

---

## Amendments

*Dated, with reasons. Never edit above this line.*
