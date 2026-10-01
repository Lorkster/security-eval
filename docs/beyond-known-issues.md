# Beyond known issues

*Why the study does not stop at known vulnerabilities, and how it measures what
lies past them without fooling itself.*

## The objection, and why it is right

The company runs Snyk. Tools like it already find known vulnerability patterns,
quickly and cheaply. A study that only shows a language model finding the
flaws seeded in a benchmark tells the company what it already has. And in the
group's own scenario, attackers with unregulated models are not limited to
known patterns: the threat is flaws nobody has catalogued yet.

So known-issue benchmarks stay, but as **calibration**: they are the only place
recall can be measured exactly, so they show whether a condition works at all.
The headline questions move past them.

## Four tracks

| | Question | Ground truth | What it gives the company |
| --- | --- | --- | --- |
| **RQ5. Post-cutoff vulnerabilities** | Do models find real flaws they cannot have seen? | the fix commit of a flaw disclosed after every model's training cutoff | evidence about *unknown* flaws, with an answer key |
| **RQ6. Beyond the scanners** | What do models find in real code that the company's own tools miss? | blind adjudication by two reviewers | the marginal value over Snyk, measured on their terms |
| **RQ7. Attacker-proxy coverage** | Of what an unregulated model finds, how much do the regulated ones also find? | blind adjudication | the scenario's question, measured directly |
| **RQ8. Fix verification** | Do the proposed fixes work? | each fix's own regression test, run in a sandbox | from finding to fixed, not just to flagged |

RQ1–RQ4 (detection on known issues, harness vs baseline, triage, failure
attribution) remain, and RQ3's triage carries over to real code, scored against
the reviewers' verdicts.

---

## RQ5: post-cutoff vulnerabilities

```bash
security-eval import-fix ~/src/someproject --vulnerable <commit> --fixed <commit> \
    --published 2026-08-14 --cwe CWE-79 --advisory GHSA-... --dest benchmarks/ts-001
```

The target is the vulnerable version of a real project. The answer key is the
code the fix commit changed. Changes to tests, documentation and changelogs are
excluded, because a fix usually adds its own test, and that test is not where
the flaw was. A fix that only *inserts* a missing check points at the line
where the check belonged. Several changed hunks become alternative locations, so
any of them counts.

### Would finding the advisory online be cheating?

Yes. A model that retrieves the advisory, or the fix, has looked the answer up,
not found the flaw. The study has to show this cannot happen, not just intend
it:

| Way the answer could leak | What stops it | Enforced by |
| --- | --- | --- |
| The model searches the web | Baseline and triage have no tools. The harness's tools read only the workspace; its one command tool, which could run `curl`, is off by default | preflight fails a time-split matrix if the harness config allows command execution |
| The fix is in the repository's history | The vulnerable version is exported with `git archive`, no history; the harness re-initialises a one-commit repository on top | `import-fix`; a test checks the tree holds the vulnerable code and no `.git` |
| The target's name gives it away | The harness shows its agents the workspace path, and run paths contain the target id | ids default to `ts-<hash>`; `import-fix` and preflight refuse ids that look like advisories; the harness copies the code to a neutral, hash-named path |
| The flaw was in training data | Disclosed after the model's training cutoff | preflight compares `source.published` with `configs/models.json` and fails any model whose cutoff is on or after it, warning where a cutoff is unrecorded |
| The answer key reaches the model | The manifest, which holds the advisory id and fix commit, is never sent | by construction: runners send only the target's `src/` |

Two honest limits to state in the write-up. A model may well have seen the
*vulnerable code itself* before its cutoff. That is fine and realistic: so has
any attacker. What it cannot have seen is the disclosure. And a training cutoff
is approximate, so leave a margin: prefer flaws disclosed some months after the
cutoff, and record the margin in the pre-registration.

Also: a time-split target's key covers *one* flaw. Real code can hold others, so
a finding elsewhere is not automatically a false positive. It goes to
adjudication with everything else.

---

## RQ6: beyond the scanners

Run the models and the company's own tools on real code, then have people
judge every candidate:

```bash
security-eval scan snyk benchmarks/real-1/manifest.json      # the company's tool
security-eval run configs/matrix.real.json
security-eval adjudicate export runs/real --sheet adjudication/sheet.csv --key adjudication/key.json
#   ... two reviewers fill in reviewer_a / reviewer_b, independently ...
security-eval adjudicate import --sheet adjudication/sheet.csv --key adjudication/key.json \
    --matrix configs/matrix.real.json
```

A real-code target is a manifest with `"open": true` and no answer key.

### The adjudication protocol

1. **Pool.** Every candidate from every condition, model and scanner. Findings
   at the same place (same file, overlapping lines) become one candidate.
2. **Blind.** The sheet shows the location, the code, and what was reported,
   with scanner rule ids stripped. It does not show who reported it. The order
   is shuffled. The key that maps candidates to sources is a separate file the
   reviewers do not open until both have finished.
3. **Two reviewers, independently.** Each marks every candidate `tp`, `fp` or
   `unsure`. A `tp` should be backed by something checkable: the line, the input
   that reaches it, and ideally a failing unit test. Never an exploit.
4. **Resolve disagreements.** Candidates where the reviewers differ are listed;
   they discuss and fill `final`. Report how many there were.
5. **Score.** `adjudicate import` reports:
   - **agreement**: Cohen's kappa;
   - per condition and model: **precision** (verified / decided);
   - **beyond the scanners**: verified findings no scanner reported;
   - **relative recall**: share of all verified findings in the pool. This is a
     lower bound on what was missed, not true recall, because real code has no
     complete list of its flaws. Say so wherever the number appears.

Budget the reviewers' time like money. At roughly five to ten minutes a
candidate per reviewer, 300 candidates is 25 to 50 hours each. Cap the pool if
needed, by sampling candidates at random rather than choosing them.

### Where the code goes

Code goes to whichever provider serves the model:

| Route | Code goes to |
| --- | --- |
| `anthropic:` | Anthropic's API |
| `bedrock:` | AWS (Amazon Bedrock), inside the company's own AWS account if that is where it runs |
| `openrouter:` | OpenRouter, a third party, and on to the model's provider |
| `ollama:` | nowhere: the model runs locally |

For company code, the owner decides which routes are acceptable, and the
manifest records it: `"allowed_providers": ["bedrock", "ollama"]`. Preflight
fails a matrix that would route it elsewhere, and the runner refuses such a cell
even with `--skip-check`. Note the trade-off: Bedrock has no Batches API, so
company code on Bedrock costs twice what the same cells would through
`anthropic:` batched.

Company results may not be publishable. The open-source results carry the
published numbers. The company appendix stays with the company.

---

## RQ7: attacker-proxy coverage

The scenario is attackers with unregulated models. The study cannot and should
not build attacks. What it can measure is **discovery**: run a legal
open-weight model, locally, on the *same defensive task* as the others, and ask
how much of what it finds the regulated models also find.

```json
"models": ["anthropic:claude-sonnet-5-5", "ollama:<open-weight model>"],
"attacker_proxies": ["ollama:<open-weight model>"]
```

Adjudication reports, for each regulated condition, **attacker-proxy coverage**:
the share of the proxy's verified findings that condition also found. A
coverage near 1 means defenders using regulated models see what the attacker's
tool sees. A low one names the flaws they would miss.

Two limits. An open-weight model on a defensive prompt is a proxy, not an
attacker; it shows what is discoverable, not what would be exploited. And only
legal, openly licensed models; nothing obtained from anywhere it should not be.

---

## RQ8: fix verification

Each finding's recommendation becomes a patch and a regression test. In a
sandbox, the test must fail on the vulnerable code, pass with the patch, and
the project's own suite must not get worse. That runs code from the target, so
it is built separately with its own isolation (containers), in its own pull
request, and comes after this one.

---

## Disclosure

A verified vulnerability in a project the group does not own is reported to
that project, following its security policy, before it appears in any
write-up, slide or repository. The supervisor is told first. Findings in company
code go to the company only.
