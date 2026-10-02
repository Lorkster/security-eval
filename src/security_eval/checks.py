"""Checks on a cell's result that the scores alone do not make.

Three, each answering a question a recall figure cannot:

* **Which code was this?** -- :func:`target_digest`, a fingerprint of the target's
  files, recorded with every cell. The report rescores every cell against the
  manifest as it stands today; if the code under it has changed since a cell
  ran, that cell's score is about code that no longer exists, and the report
  says so.
* **Is the quoted code really there?** -- :func:`check_evidence`. A finding
  quotes code and names a place. Whether the quote is at that place is
  checkable without a model, and a quote found nowhere in the file is the
  clearest sign of a finding the model made up -- one that can still land on
  the right lines by chance and score as a true positive.
* **Missed, or never looked?** -- :func:`attribute_misses`. A vulnerability in a
  file the condition never read is a different failure from one in a file it
  read and passed over. The baseline is sent every source file; the harness
  reads what its agents choose to, and records which.

None of these changes a score. They are reported beside the scores, as their
own dimensions, and are exploratory: the preregistered metrics are the ones in
docs/preregistration.md.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from pathlib import Path

from .finding import SecurityFinding, normalise_path
from .manifest import KnownIssue

# -- which code ------------------------------------------------------------------

#: Not part of the target: version-control state and caches a run may leave.
_IGNORED_PARTS = frozenset({".git", "__pycache__", ".pytest_cache", ".mypy_cache",
                            ".supervisor"})


def target_digest(root: Path) -> str:
    """A fingerprint of every file under ``root``: its path and its bytes.

    Line endings are normalised first, so a checkout on Windows and one on
    Linux of the same commit agree; nothing else is.
    """
    h = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root)
        if _IGNORED_PARTS.intersection(rel.parts):
            continue
        h.update(rel.as_posix().encode("utf-8") + b"\0")
        h.update(path.read_bytes().replace(b"\r\n", b"\n") + b"\0")
    return h.hexdigest()[:16]


# -- the quoted code --------------------------------------------------------------

#: The verdicts, in the order the report shows them.
EVIDENCE_VERDICTS = (
    "quoted_at_location",   # a quoted line is at the stated lines (within the tolerance)
    "quoted_elsewhere",     # it is in the file, but not near the stated lines
    "quote_not_in_file",    # code was quoted, and none of it is in the file
    "nothing_quoted",       # the evidence is prose: there is nothing to look for
    "no_such_file",         # the stated file is not in the target
    "past_end_of_file",     # the stated lines run past the end of the file
    "no_location",          # the finding names no place
)

_BACKTICKED = re.compile(r"`([^`\n]{4,})`")
_FENCE = re.compile(r"```[\w+-]*\n?(.*?)```", re.DOTALL)
# "12:", "12 |", "  12  " -- a line number a model copied along with the line.
_LINE_PREFIX = re.compile(r"^\s*(?:L?\d+\s*[:|]\s*|\d+\s{2,})")
# An identifier followed by a call, an index, an assignment or an attribute.
_CODE_SHAPE = re.compile(r"[A-Za-z_][\w]*\s*(?:\(|\[|=[^=]|\.[A-Za-z_])")
_PROSE_WORDS = frozenset({"the", "is", "a", "an", "of", "to", "which", "this", "that",
                          "uses", "with", "without", "be", "are", "was", "it", "allows",
                          "because", "can", "could", "user", "attacker"})
#: Shorter fragments match too much by accident (``id = x`` is everywhere).
MIN_FRAGMENT_CHARS = 10


def _squash(text: str) -> str:
    return " ".join(text.split())


def _looks_like_code(line: str) -> bool:
    if not _CODE_SHAPE.search(line):
        return False
    words = re.findall(r"[A-Za-z]+", line.lower())
    return sum(w in _PROSE_WORDS for w in words) < 3 and not line.rstrip().endswith(".")


def quoted_fragments(evidence: Iterable[str]) -> list[str]:
    """The lines of code a finding's evidence quotes, whitespace-squashed.

    Backticked spans and fenced blocks always count; a bare line counts only if
    it looks like code rather than a sentence about code. When unsure, a line
    is left out: an unquoted finding is reported as "nothing quoted", never as
    a fabrication.
    """
    out: list[str] = []
    for text in evidence:
        quoted: list[str] = []
        for block in _FENCE.findall(text):
            quoted.extend(block.splitlines())
        text = _FENCE.sub(" ", text)
        quoted.extend(_BACKTICKED.findall(text))
        if not quoted:
            quoted = [line for line in text.splitlines() if _looks_like_code(line)]
        for line in quoted:
            fragment = _squash(_LINE_PREFIX.sub("", line))
            if len(fragment) >= MIN_FRAGMENT_CHARS and fragment not in out:
                out.append(fragment)
    return out


def check_evidence(finding: SecurityFinding, root: Path, tolerance: int = 3) -> str:
    """Whether the code ``finding`` quotes is at the place it names. One of EVIDENCE_VERDICTS."""
    loc = finding.location
    if loc is None:
        return "no_location"
    file = root / loc.normalised_path
    try:
        inside = file.resolve().is_relative_to(root.resolve())
    except OSError:
        inside = False
    if not inside or not file.is_file():
        return "no_such_file"
    lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
    if loc.start_line > len(lines):
        return "past_end_of_file"
    fragments = quoted_fragments([*finding.evidence, finding.detail])
    if not fragments:
        return "nothing_quoted"
    lo = max(0, loc.start_line - 1 - tolerance)
    hi = min(len(lines), loc.end_line + tolerance)
    near = _squash("\n".join(lines[lo:hi]))
    whole = _squash("\n".join(lines))
    if any(f in near for f in fragments):
        return "quoted_at_location"
    if any(f in whole for f in fragments):
        return "quoted_elsewhere"
    return "quote_not_in_file"


# -- missed, or never looked -------------------------------------------------------


def attribute_misses(missed: Iterable[str], issues: Iterable[KnownIssue],
                     files_read: Iterable[str]) -> dict[str, list[str]]:
    """Split missed vulnerabilities by whether any file they are in was read.

    A vulnerability with ``also`` locations counts as read if any of its files
    was: reading either end of a cross-file flaw was a chance to find it.
    """
    read = {normalise_path(p).lower() for p in files_read}
    by_id = {i.id: i for i in issues}
    out: dict[str, list[str]] = {"never_read": [], "read": []}
    for issue_id in missed:
        issue = by_id.get(issue_id)
        if issue is None:
            continue
        seen = any(loc.normalised_path.lower() in read for loc in issue.locations)
        out["read" if seen else "never_read"].append(issue_id)
    return out


__all__ = [
    "EVIDENCE_VERDICTS",
    "attribute_misses",
    "check_evidence",
    "quoted_fragments",
    "target_digest",
]
