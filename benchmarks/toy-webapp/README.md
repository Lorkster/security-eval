# toy-webapp

A deliberately vulnerable toy application, written for this benchmark. **Never
deploy it.** Every credential in it is invented.

It exists so the whole pipeline can be exercised for cents: five seeded
vulnerabilities, five decoys (safe code written to look like the vulnerability
next to it), and nothing else. It is small enough that the baseline sends it in
full.

Nothing under `src/` may hint at the answers -- no comments saying what is
planted, no names like `vulnerable_`. The runners send `src/` to the model;
the answer key is `manifest.json`, which they never do.

| id | CWE | where | decoy beside it |
| --- | --- | --- | --- |
| V1 | CWE-89 SQL injection | `app/db.py` | D1, parameterised query |
| V2 | CWE-22 path traversal | `app/files.py` | D2, resolved and contained |
| V3 | CWE-78 OS command injection | `app/tools.py` | D3, argv list, no shell |
| V4 | CWE-798 hard-coded credential | `app/config.py` | D4, secret from the environment |
| V5 | CWE-502 unsafe deserialisation | `app/session.py` | D5, JSON |

## Calibration

`calibration/good.json` must score full strict recall and full precision, and
`calibration/bad.json` no true positive; `security-eval validate` checks both,
with answers built from the key itself. They are written the way a model writes
findings, and sit beside `src/`, so no model is sent them.
