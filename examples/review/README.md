# Example review page

[`review.html`](review.html) is the page `security-eval adjudicate export`
writes for reviewers. Download it and open it in a browser; it works offline.
Choose a reviewer, mark a few candidates, and press **Download my verdicts** to
see the file `adjudicate import` reads.

## Where it came from

It's real output, not a mock-up: a free local trial run
([`docs/local-trial-run.md`](../../docs/local-trial-run.md)) on four files of
[supervisor-harness](https://github.com/Lorkster/supervisor-harness) at commit
`c8d0a47`:

- `core/tools.py`
- `core/paths.py`
- `config.py`
- `install.py`

Every condition used `qwen3.8-code` on local Ollama: the baseline, triage of
Bandit's output, and the supervised harness on commit `1f99b30`. The page pools
11 candidates from all of them, merged by place and shuffled, with nothing
saying who reported which.

**Nothing on it has been judged.** Each candidate is a claim by a local model
or a scanner about that code, and is unverified until reviewers decide. Many
will be false positives; sorting that out is what the page is for.
