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
#   ... each reviewer opens adjudication/review.html, judges, downloads their file ...
security-eval adjudicate import --sheet sheet-reviewer_a.csv --sheet sheet-reviewer_b.csv \
    --key adjudication/key.json --matrix configs/matrix.real.json
```

A real-code target is a manifest with `"open": true` and no answer key.

### The adjudication protocol

1. **Pool.** Every candidate from every condition, model and scanner. Findings
   at the same place (same file, overlapping lines) become one candidate.
2. **Blind.** `export` writes `review.html`, a page that opens offline in any
   browser. It shows each candidate's location, the code with the flagged lines
   marked, and what was reported, with scanner rule ids stripped. It does not
   show who reported it, and the order is shuffled. The key that maps
   candidates to sources is a separate file the reviewers do not open until
   both have finished.
3. **Two reviewers, independently.** Each opens the page, chooses *Reviewer A*
   or *Reviewer B*, and marks every candidate:

   | Verdict | Meaning |
   | --- | --- |
   | `tp` | A real vulnerability in this code. You can point to the line, the untrusted input that reaches it, and what an attacker would gain. Ideally you could write a unit test that fails because of it. Never write an exploit. |
   | `fp` | Not a vulnerability here: the input is not attacker-controlled, it is already validated, or the code is safe as used (MD5 for a cache key, say). A real bug that is not a security issue is also `fp`; say so in the notes. |
   | `unsure` | You cannot decide from the code with reasonable effort, for example because it depends on how the code is deployed. Say in the notes what would settle it. |

   Judge whether the issue is real, not whether the report is well written. Right
   place but wrong CWE is still `tp` if the issue described is real; note the
   right CWE.

   Answers are kept in the browser as they go. **Download my verdicts** saves a
   copy of the sheet with only that reviewer's column filled
   (`sheet-reviewer_a.csv`), so neither sees the other's answers and nobody edits
   a shared file. A reviewer who prefers a spreadsheet can fill their column of
   `sheet.csv` directly instead.
4. **Resolve disagreements.** `import` lists candidates where the reviewers
   differ. They discuss, and one of them chooses *Final* on the page, judges
   only those, and downloads `sheet-final.csv`, which goes to `import` with the
   other two. Report how many disagreements there were.
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

Finding a flaw is half the job. The other half is a fix that works, and the
company will ask whether a model's fixes can be trusted.

```bash
security-eval sandbox build benchmarks/notes-api/manifest.json   # once; the only step with network
security-eval sandbox check benchmarks/notes-api/manifest.json   # the suite runs, before paying
security-eval run configs/matrix.fix.json                        # proposals, batched
security-eval verify runs/fix                                    # every proposal, in the sandbox
security-eval report runs/fix
```

The `fix` condition gives the model a confirmed flaw: its location and CWE,
not the answer key's description. RQ8 asks whether fixes work, not whether
flaws are found, so detection is kept out of it. The model sees the repository
and its existing tests, and is told how its test will be run. It answers with
**edits** (exact text to replace) and **one new test file**. Edits, not a diff:
a diff must reproduce line numbers and context exactly, and a good fix lost to
a malformed hunk would be scored as one that does not work.

Nothing runs while the model is being asked. `verify` checks the saved
proposals afterwards, which costs nothing and can be repeated.

### The stages

Each proposal is checked in order, and stops at the first stage it fails:

| Stage | Must hold | Otherwise |
| --- | --- | --- |
| the proposal applies | edits match exactly once; no test or test configuration is edited; the test is a new file under the target's test directory | `invalid_proposal` |
| the test detects the flaw | on the vulnerable code it **fails**: an assertion that does not hold | `test_did_not_fail` if it passes; `test_broken` if it only errors or nothing ran; `test_wrong_reason` if it fails only by calling what the fix adds |
| the fix fixes it | with the edits, the same test passes | `not_fixed` |
| nothing else breaks | the project's suite, with the edits and without the new test, loses no test that passed before | `suite_regressed` |

All four is **verified**. A refusal or an unusable answer is `no_proposal` and
counts against the rate, so a model that declines half the work does not look
better for it. A failure of the sandbox itself is `sandbox_error`, says
nothing about the proposal, and is retried by the next `verify`.

`test_wrong_reason` closes a loophole. A test that imports the helper the fix
is about to add fails before the fix and passes after it, yet shows nothing
about the flaw. Failures that are only `ImportError`, `AttributeError`,
`NameError` or a call with the wrong arguments are therefore not detection.
A target can set its own patterns in `verify.wrong_reasons`.

### Against the real fix

A time-split target also has the fix that actually shipped. `import-fix`
saves it under `verify/fixed/`, and the tests it added under
`verify/fixed_tests/`. Both are outside `src/`, so no model sees them. Two more
checks are recorded beside each verdict:

- **upstream**: do the project's own tests from the real fix pass on the
  proposed fix? This is an oracle the model did not write. A fix can satisfy
  its own narrow test and still fail here.
- **overfit**: does the model's test fail on the real fix? If so, it tests the
  model's fix rather than the flaw.

Both are used only once the reference has been checked: its tests must fail on
the vulnerable code and pass on the real fix. `sandbox check` reports this.

### The sandbox

Every run is a fresh container with:

- no network;
- a read-only root filesystem and a read-only copy of the tree;
- no capabilities and no privilege escalation;
- limits on memory, CPU, process count and time.

Results come back as JUnit XML, the one format that tells a failed assertion
from an error. Each target says how its tests run (`verify` in its manifest).
`notes-api` is the example: a Dockerfile that installs pytest, and a functional
test suite under `verify/overlay/`. The suite sits outside `src/`, so detection
runs never read it.

For a real project, the group writes the Dockerfile with the project's
dependencies, then runs `sandbox check`. A time-split manifest arrives with
`verify` started and the image and commands left blank.

Limits to state in the write-up:

- "The suite loses nothing" is only as strong as the suite.
- A verified fix is not proof of a correct fix; *upstream* is the stronger
  evidence where it exists.
- The verifier trusts the test runner's report, and a proposal's code runs in
  the same process. Reviewers should read a sample of verified proposals.
- Regression tests check safe behaviour (unsafe input is rejected or
  neutralised). They are unit tests, not exploits, and the prompt says so.

---

## Disclosure

A verified vulnerability in a project the group does not own is reported to
that project, following its security policy, before it appears in any
write-up, slide or repository. The supervisor is told first. Findings in company
code go to the company only.
