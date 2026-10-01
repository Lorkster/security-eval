# security-eval — project proposal

*Draft for the student group, 2026-09-30. It is written to be argued with: every
section names what it assumes, and the places we have not measured anything yet
say so.*

## In one paragraph

We want to measure how well language models find and triage security
vulnerabilities when they run unattended, and whether wrapping them in a
supervising harness makes them better, worse, or just more expensive. We will
run models against code whose vulnerabilities are already known, score what
they report against that ground truth, and record what every run cost. The
harness is [supervisor-harness](https://github.com/Lorkster/supervisor-harness)
(MIT); this repository is the evaluation around it, and depends on it rather
than forking it.

---

## 1. Research questions

| | Question | Measured as |
| --- | --- | --- |
| **RQ1** | How well does a model find known vulnerabilities on its own? | precision, recall and F1 against ground truth, in two strictness levels: right place, and right place *and* right CWE |
| **RQ2** | Does a supervised, multi-lens harness change that, and at what price? | the RQ1 metrics for the harness condition beside the baseline, and **cost per true positive** in dollars and tokens |
| **RQ3** | How well does a model triage scanner output? | accuracy and confusion matrix of true-positive / false-positive verdicts against labels; severity agreement |
| **RQ4** | When a run fails, whose failure is it? | outcome counts by cause: model (refused, malformed output, missed) versus harness (agent stopped by drift control, agent abandoned, phase failed) |
| **RQ5** | Do models find real flaws disclosed after their training cutoff? | recall and precision against the fix commit, with the contamination controls of `beyond-known-issues.md` |
| **RQ6** | What do models find in real code that the company's own scanners miss? | blind two-reviewer adjudication: precision, verified findings no scanner reported, relative recall, Cohen's kappa |
| **RQ7** | Of what an unregulated model finds, how much do the regulated ones also find? | attacker-proxy coverage, from the same adjudication |
| **RQ8** | Do the proposed fixes work? | the share of flaws whose proposed fix is verified in a sandbox: its regression test fails before the fix for a real reason, passes after, and the suite loses nothing; on time-split targets, also the real fix's own tests |

**Known issues are calibration, not the result.** Tools like Snyk already find
known patterns, and the company already runs them. RQ1–RQ3 on seeded benchmarks
show whether a condition works at all, and they are the only place recall can
be measured exactly. The headline is RQ5–RQ8: flaws the models cannot have
seen, findings beyond the company's own tools, and coverage of what an
attacker's model would find. How each is measured without fooling ourselves,
including why looking a CVE up online would be cheating and how the study
prevents it, is in [`beyond-known-issues.md`](beyond-known-issues.md).

RQ2 is the one that makes this project different from a model leaderboard, and
it is the one that is easiest to get wrong — see §4.

**On the group's scenario** (attackers with unregulated models, defenders with
regulated ones): these questions measure what regulated models achieve on
*defence*, which is where they are designed to help. The study reports that
result whichever way it points. It is not designed to rule a conclusion out;
a study designed that way would not be evidence. How to give regulated models
every legitimate advantage, and why the data could not support "only
unregulated models can defend" in any case, is in
[`working-with-regulated-models.md`](working-with-regulated-models.md).
Hypotheses and thresholds are frozen in [`preregistration.md`](preregistration.md)
before the pilot.

**Deliberately out of scope:** generating working exploits, testing anything
we do not own or have not been given, and live systems of any kind. The models
are asked to *find, explain and propose a fix*. That keeps the work defensive,
keeps it within what the providers' usage policies are built for, and — as a
budget matter — avoids the requests most likely to be refused (§6).

## 2. What we build on, and what we build

The harness already provides, and we reuse as is:

- **per-stage model routing** across Anthropic, Bedrock, OpenRouter and Ollama,
  so the model under test is a configuration value;
- **unattended runs** — `supervisor run --mode report --backend autonomous --yes`;
- **a security lens** it can be forced to include on every run;
- **an append-only event log and trajectory export** with token usage per call,
  which is what makes RQ4 answerable at all;
- **findings with severity, evidence, recommendation and confidence**, and a
  refusal to keep a finding that has no evidence.

What does not exist anywhere yet, and is this repository:

| Component | Purpose | Status |
| --- | --- | --- |
| benchmark manifests | a target plus its answer key: which CWE, which file, which lines; and *decoys*, safe code that looks vulnerable | format with alternative locations and CWEs; a toy target for plumbing and `notes-api`, a harder one |
| a security finding format | CWE, file:line location, severity, confidence, triage verdict | done |
| SARIF in and out | read scanner output (Semgrep, CodeQL) for RQ3; write ours for tooling | minimal 2.1.0 |
| runners | *baseline* (one model, one prompt), *harness* (supervised run), *fake* (zero-cost, for plumbing) | all three complete; baseline and harness have both run end to end on a local model; the harness is read only through its published CLI |
| a scorer | deterministic matching of findings to ground truth; no LLM judge | done |
| a matrix driver | targets × conditions × models × repeats, resumable from a ledger | done |
| a budget guard | refuses to start a run the remaining budget cannot cover | done |
| triage runner (RQ3) | each scanner finding judged by a model; labelled by the answer key; scanners scored beside the models | done; Bandit scans of both benchmarks included |
| batching | half-price Message Batches for baseline and triage, Anthropic's own API only; never resubmits, budget counts what is in flight | done |
| preflight checks | everything checkable before a token is paid for: manifests, prompts, prices, budget, tooling, provider credentials | done |
| a report | the ledger aggregated into the research questions' numbers, re-scored from saved findings | done |

## 3. Prerequisites in the harness

Six things in supervisor-harness should be looked at before this project spends
money on it. They were found while writing this proposal and running its first
cells; each is a pull request against the harness, not a workaround here.

| | What | Why it matters to us | State |
| --- | --- | --- | --- |
| **P1** | `supervisor uninstall` | anything used as a dependency needs a clean way out | **done**: [PR #69](https://github.com/Lorkster/supervisor-harness/pull/69), merged 2026-09-30 |
| **P2** | provider compatibility with current Claude models | the Anthropic and Bedrock providers always send `temperature: 0.2`. Current Claude models reject sampling parameters with HTTP 400, so **every call to Opus 5.5, Sonnet 5.5 or Sonnet 5 fails** — only Haiku 4.5 and the 4.6 generation work today. The same change should (a) treat a `refusal` stop reason as its own non-retried outcome instead of an empty answer the drift checks then send back for another paid attempt, (b) cache the fixed part of every brief, and record cache tokens in usage, and (c) raise the 4096-token default so thinking models are not truncated into retries | **done**: [PR #70](https://github.com/Lorkster/supervisor-harness/pull/70), merged 2026-10-01 |
| **P3** | a structured findings export (`supervisor findings RUN --json`) with location and CWE as fields | today findings carry location only inside free-text evidence, and the only way to read them is by folding the harness's internal state; our adapter does that behind one function so it can be swapped | **done**: [PR #73](https://github.com/Lorkster/supervisor-harness/pull/73), merged 2026-10-01 |
| **P4** | `config.roles` is declared but never read | defining narrower security lenses (injection, authn/authz, secrets, dependencies) by configuration does not work; it needs wiring or removing. Until then the harness runs its one built-in security lens | **done**: [PR #74](https://github.com/Lorkster/supervisor-harness/pull/74), merged 2026-10-01 |
| **P5** | `supervisor run --json` crashes when stdout is a Windows pipe | the CLI prints non-ASCII to a cp1252 stream and dies *after* the run completes. Found in the first real harness cell. The runner here works around it (forces UTF-8, and falls back to reading the run from its store), but the fix belongs in the CLI | **done**: [PR #71](https://github.com/Lorkster/supervisor-harness/pull/71), merged 2026-10-01 |
| **P6** | the drift check stops a lens that is reading, not drifting | in the first real harness cell, the security lens was refocused four times for `no_progress` on turns where it was reading files. The drift model's second opinion called those turns on-brief (0.26) and was not followed. It overlaps an open harness investigation ([#67](https://github.com/Lorkster/supervisor-harness/issues/67)). One run on a local model is a data point, not a diagnosis | **done**: [PR #72](https://github.com/Lorkster/supervisor-harness/pull/72), merged 2026-10-01 |

All six are merged as of 2026-10-01, and `pyproject.toml` pins the harness to that commit
(`c8d0a47`). Moving the pin mid-study changes a condition, so it belongs in the
pre-registration.

## 4. Experimental design

### Conditions

| Condition | What runs | Varies |
| --- | --- | --- |
| **baseline** | one model, one prompt, the whole target in context, one structured answer | the model |
| **harness** | the same model on every stage of a supervised run, security lens forced | the model |
| *harness-mixed* (optional) | the model under test on analysis, a cheaper one on drift and synthesis | the routing |

The baseline goes through **the harness's own provider layer**, not a separate
SDK client. That way the harness is the only thing that differs between the two
conditions — not the HTTP client, the retry policy or the request defaults.

### Controls against the obvious confounds

- **Harness failures are the harness's.** A run where the drift rule stopped an
  agent is recorded with outcome `harness_stopped`, and RQ1 and RQ2 are reported
  both with and without those runs. This is not hypothetical: an open harness
  issue ([#67](https://github.com/Lorkster/supervisor-harness/issues/67)) is a
  run in which two agents were stopped with turns to spare.
- **Pristine targets.** Each run gets a fresh copy of the target and its own
  harness store, so no lesson or fact from one run leaks into the next. The
  harness's lessons library is exactly such a leak, and is switched off by
  giving every run an empty `SUPERVISOR_HOME`.
- **Repeats.** Models are not deterministic. Core cells run three times; the
  variance is reported, not averaged away.
- **No LLM judge.** A finding matches a known vulnerability by file and line
  overlap, and optionally CWE. A judge model would add a second model's errors
  and a second bill.
- **Decoys.** Every target should contain safe code that resembles a
  vulnerability, so false positives are measured rather than inferred.
- **Contamination.** Famous benchmarks may be in the models' training data. We
  note which targets are public, and prefer a few private or freshly-written
  targets for the headline numbers.

### Benchmarks to consider

Check each one's licence and label quality before adopting it.

| Candidate | Good for | Caveat |
| --- | --- | --- |
| OWASP Benchmark (Java) | RQ3: every test case is labelled true or false positive | synthetic, and very likely seen in training |
| NIST SARD / Juliet | RQ1: CWE-labelled, many languages | synthetic, small functions |
| OWASP Juice Shop, DVWA | RQ1 on realistic web apps | vulnerability lists are prose, not line numbers; the manifest has to be written by hand |
| CVE fix commits (e.g. CVEfixes) | RQ1 on real code: the parent of a fix commit is the vulnerable version | labelling lines needs care; contamination is likely |
| our own seeded targets | the headline numbers | effort to write, but uncontaminated |

`benchmarks/toy-webapp` in this repository is a seeded target of the last kind,
small enough to run for cents, and it is what every plumbing test uses. It is
**too easy to tell models apart**: a local 27B code model scored 5 of 5 on it,
CWE included, in the first real run. The benchmarks that carry the research
questions have to be larger and subtler: vulnerabilities that cross files,
need data-flow reasoning, or sit beside convincing decoys.

## 5. Plan and milestones

| Week | Milestone | Money spent |
| --- | --- | --- |
| 1 | everyone runs the fake-runner matrix and `report` locally (the harness prerequisites are merged) | none |
| 2 | two or three benchmark manifests written and validated; scorer checked by hand against a sample | none |
| 3 | **pre-registration committed**; then the **viability gate** (§6): every candidate model, a handful of calls each on the toy target | a few dollars |
| 4 | **pilot**: one target, every condition, one repeat; real token counts replace the estimates | ~5% of the budget |
| 5–7 | measurement matrix, resumable, under the budget guard | the bulk |
| 8 | analysis and write-up; RQ4 from the event logs | none |

The order matters more than the dates: nothing costs money until the plumbing
has run end to end for free, and nothing large runs until a pilot has measured
what a run costs.

## 6. Models and budget

Covered in full in [`models-and-budget.md`](models-and-budget.md). In short:

- **Develop for free.** The fake runner and a local Ollama model exercise the
  whole pipeline. No paid call is made to debug plumbing.
- **Gate viability before choosing.** A few cheap calls per candidate find out
  whether it refuses this kind of work, whether it can produce the structured
  output, and whether it finds anything at all. Models that fail are dropped
  before they cost more.
- **One workhorse, one ceiling, one cheap tier.** Claude Sonnet 5.5 for the full
  matrix; Claude Opus 5.5 on a subset, to show the headroom; Claude Haiku 4.5
  for high-volume triage and the harness's drift checks.
- **Measure, then extrapolate.** The budget guard projects every cell's cost from
  the pilot's measured tokens and refuses to start one the budget cannot cover.

## 7. Risks

| Risk | Mitigation |
| --- | --- |
| Refusals on security prompts make a model unusable | the viability gate finds this for a few cents; prompts stay defensive; refusals are an outcome, not an error to retry |
| The harness fails in ways that look like model failures | outcome classification from the event log (RQ4); results reported with and without harness-stopped runs |
| Budget runs out halfway through the matrix | the budget guard; the ledger makes a stopped matrix resumable without re-spending; cells are ordered so the core comparison finishes first |
| Ground truth is wrong | manifests reviewed by two people; decoys; spot-check of scorer decisions |
| Benchmark contamination | at least one private target for the headline numbers |
| Source code sent to a provider | only intentionally-vulnerable or owned code; Ollama for anything that must stay local |
| Finding a real vulnerability in a public project | stop, tell the supervisor, follow the project's disclosure policy |

## 8. What we need from the group

1. Agreement on the research questions, especially whether RQ3 is in scope.
2. A budget figure. The plan in `models-and-budget.md` has a worked example.
3. Two people for each benchmark manifest (one writes it, one reviews it).
4. One person to own the harness prerequisites (P2 first).
