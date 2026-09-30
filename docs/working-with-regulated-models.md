# Working with regulated models

*How to get the best legitimate results from Claude Opus, Sonnet and their
peers on defensive security work, and how to keep the study honest while doing
it.*

## The scenario, and the trap in it

The group's scenario: in the near future, attackers use unregulated models,
and defenders only have the regulated ones. The natural question is whether the
regulated models are enough to defend legitimate systems.

It's tempting to want a particular answer. A result suggesting that only
unregulated, possibly illegal, models can protect legitimate systems would be
uncomfortable. But a study that is steered to avoid that result is no longer
evidence of anything, and a reviewer who finds the steering will discard the
results that were fine too. So this document gives regulated models every
*legitimate* advantage, and makes the study report whatever happens.

Two points take most of the discomfort out of it.

**The asymmetry sits mostly on offence, and this study is about defence.**
What regulated models restrict is mainly *offensive* help: working exploits,
attack payloads, operational intrusion. Finding a vulnerability in code you are
authorised to review, explaining it and fixing it is exactly the work they are
built to support. The study measures that directly. It doesn't need an
attacker model at all: the benchmark's answer key *is* the attacker, because
it lists every flaw an adversary could use. Recall against it is the
defender's coverage.

**The data will not support "only unregulated models can defend" anyway.** That
claim needs an unregulated arm doing the same defensive task, and a
demonstration that it succeeds where regulated models fail, for reasons of
regulation rather than capability. What the study *can* support is narrower
and more useful: *under these conditions, regulated models find this share of
these vulnerabilities, at this cost, with this refusal rate.* If that share is
low, the finding is a measured capability gap: which classes of flaw, which
configurations, how much refusals cost. Providers, policy-makers and defenders
can act on that. It is not an argument for illegal tools.

The study does not use illegal models, and does not obtain models from
anywhere it shouldn't. If the group wants a contrast arm, open-weight models
run locally are legal and legitimate. The comparison is then *open-weight
versus hosted frontier*, and it should be written up as that.

---

## Getting the best legitimate results

In rough order of how much they matter.

### 1. Say truthfully who you are and what the work is for

Regulated models do better, and refuse less, when they understand the task is
defensive. Tell them, truthfully:

- this is a defensive code review for a research project;
- the code is a benchmark the group wrote, or is authorised to analyse;
- nothing in it is deployed;
- the goal is to find and fix, not to attack.

Every sentence has to be true of every target it is used on. **Invented
context — claiming a pentest contract you don't have, a role you don't hold,
an emergency that isn't happening — is a jailbreak by another name.** It breaks
the provider's terms. It also breaks the study: a regulated model talked out
of its safeguards is no longer the regulated condition, so the result would
describe a model that doesn't exist in the scenario.

`configs/prompts.json` has two frozen variants: `plain` (no context) and
`context` (honest context, plus a request for data flow and a regression test).
Run both. The difference between them is a result in its own right: *how much
does honest framing change refusals and quality?*

### 2. Ask for what a defender needs, not what an attacker needs

| Ask for | Not |
| --- | --- |
| where the flaw is: file and line range | a working exploit |
| the root cause, and the data flow from untrusted input to the dangerous use | an attack payload or proof-of-concept string |
| the CWE | how to evade detection |
| a fix | steps to use it against a running system |
| **a unit test that fails on the vulnerable code and passes on the fixed code** | |

The last row is the defensive substitute for a proof of concept. It shows the
flaw is real, and it guards the fix, without producing anything usable against
someone else's system. Both prompts end with *"Do not write exploits"*, and a
test fails if a prompt ever loses that line.

### 3. Give the whole picture

Send whole files, not fragments. A model shown ten lines out of context can
neither see that input is sanitised two calls earlier nor tell that the
snippet is from a review rather than an attack. The baseline sends the full
target; the harness gives the model tools to read the repository itself.
Fragments cause false positives and suspicious-looking requests at once.

### 4. Structure the answer

Ask for structured output against a schema: one finding per item, with
location, CWE, severity and confidence as fields. This is what the scorer
needs, and it stops paying for prose that has to be parsed back out.

### 5. Spend reasoning where it pays

Current Claude models take an `effort` level. Analysis over a whole repository
benefits from `high`; triaging one finding at a time often doesn't need more
than `low`. Tune it in the pilot, per stage, and record it. It is cheaper than
changing model and often better.

### 6. Decompose, then verify

Two structures consistently help on this kind of work:

- **Decompose:** separate passes per vulnerability class or per component,
  rather than "find everything" in one breath. The harness's lenses are one
  form of this.
- **Verify:** a second pass whose only job is to try to *refute* each finding
  against the code. This is where most false positives die, and it is RQ3's
  triage step turned on the model's own output.

Both cost tokens, so both should be conditions measured against the plain
baseline rather than assumed to help. The first local-model run found the
harness *lowering* precision through duplicates and decoy hits.

### 7. Use access routes that exist for defenders

Regulated providers already run restricted-access routes that differ from the
public defaults. Anthropic, for example, offers Claude Mythos 5.1 only through
Project Glasswing, and the safeguards on it depend on the access programme. A
student group is unlikely to qualify. Before citing any such programme, check
what it is actually for and who it admits; don't rely on this paragraph. But
these routes matter to the scenario: the real choice for defenders is not only
"restricted public model or unregulated model". Mentioning this in the
write-up, accurately, points the conclusions somewhere constructive.

---

## Refusals are data

A refusal is a result, not an error to engineer around.

- **Record it.** The ledger has an outcome for it (`refused`). The harness
  needs prerequisite P2 to report it properly; the baseline already does.
- **Don't retry it into success.** Rephrasing until a refused request goes
  through is circumventing a safeguard. It is also p-hacking: the reported
  refusal rate would be whatever the rephrasing budget allowed. The matrix
  deliberately never retries a refusal.
- **Measure framing honestly instead.** Differences between the frozen `plain`
  and `context` prompts are legitimate evidence about how honest framing
  interacts with safeguards.
- **Report the rate, with categories.** For the scenario, the refusal rate on
  defensive work is one of the most relevant numbers the study produces: it is
  the measured cost of regulation to a defender. If it is low, say so. If it is
  high, say that, and on which tasks.
- **Read a sample.** Some refusals are reasonable given the request. Some are
  false positives. The difference matters for the write-up, and only reading
  them shows it.

---

## Keeping the study honest

The practices that let a result stand, whichever way it points:

1. **Pre-register before the pilot's results are seen.** Hypotheses, metrics,
   thresholds, prompts, targets, models and the stopping rule go into
   [`preregistration.md`](preregistration.md), and are committed. The ledger
   stores each prompt's hash, so any later change shows.
2. **Separate tuning from measuring.** Prompts, effort and configuration may be
   tuned on a *development* set of targets. The headline numbers come only from
   a *held-out* set that no tuning ever looked at. Tuning on the evaluation set
   produces numbers that measure the tuning.
3. **No dropping after the fact.** A target, model or run is excluded only by a
   rule written before the results existed. Every exclusion is listed in the
   write-up.
4. **Report the unflattering numbers.** Negative results, high refusal rates
   and conditions that didn't help go in the write-up with the same prominence
   as the rest.
5. **Score blind.** The scorer is deterministic and never sees which condition
   produced a finding. Hand-checks of its decisions should be done without the
   condition label too.
6. **Claim what was measured.** "Regulated models found 62% of seeded
   injection flaws at $0.40 per true positive" is a finding. "Regulated models
   cannot protect systems" is not one, unless the study measured that. Neither
   is "unregulated models are required".
