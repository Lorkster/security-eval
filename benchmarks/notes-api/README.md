# notes-api

A deliberately flawed notes service, written for this study. **Never deploy
it.** Harder than `toy-webapp` on purpose: the flaws the toy target cannot
test.

- **Cross-file flow.** The sort order enters in `handlers.py` and reaches SQL in
  `db.py`, where an allow-list (`SORTABLE`) exists and is never used. Either end
  is a fair place to report it, and the manifest accepts both (`also`).
- **Authorisation, not injection.** `show_note` returns any note by id. Nothing
  in the line itself is wrong; the check that `delete_note` makes is missing.
- **Subtle crypto.** A salted MD5 password hash, and a token compared with `==`.
  Several CWEs describe each correctly, and the manifest lists them.
- **Decoys that look like the real thing.** A parameterised `LIKE`,
  `hmac.compare_digest`, an ownership check, a fixed-host fetch, escaped titles,
  and MD5 used for an ETag, which is not a security use.

| id | CWE (first listed) | where | decoy |
| --- | --- | --- | --- |
| V1 | CWE-89 | `db.py:15`, or `handlers.py:7` | D1 |
| V2 | CWE-916 | `auth.py:12` | D6 (MD5, but for an ETag) |
| V3 | CWE-208 | `auth.py:16` | D2 |
| V4 | CWE-639 | `handlers.py:18-21` | D3 |
| V5 | CWE-918 | `fetch.py:8-10`, or `handlers.py:33` | D4 |
| V6 | CWE-79 | `render.py:8-10` | D5 |

As with every target: nothing under `src/` may hint at the answers. It still
needs a second person's review before it counts toward results.
