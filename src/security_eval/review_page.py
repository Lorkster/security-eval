"""The page reviewers judge candidates on: one self-contained HTML file, offline.

The CSV sheet is what `adjudicate import` reads. It is a poor place to *read* a
candidate: a spreadsheet cell holding forty lines of code and three reports
cannot be read in any spreadsheet. The page shows each candidate as a card --
what was reported, the code with the flagged lines marked -- with the
instructions and the meaning of each verdict at the top, where a reviewer
needs them. Verdicts are kept in the browser as you go and downloaded as a CSV
in the sheet's own format, one file per reviewer, so two reviewers never edit
the same file and neither sees the other's answers.

Blind by construction: the page is built from the sheet's candidates only, never
from the key, so nothing on it says which model, condition or scanner reported
what. Everything shown is inserted as text, never as HTML: the code under
review and the reports about it are untrusted, and a page that rendered them
could be made to run whatever they contained.
"""

from __future__ import annotations

import json
from typing import Any

VERDICT_HELP = [
    ("tp", "True positive",
     "A real vulnerability in this code. You can point to the line, the untrusted input "
     "that reaches it, and what an attacker would gain. Ideally you could write a unit "
     "test that fails because of it. Never write an exploit."),
    ("fp", "False positive",
     "Not a vulnerability here: the input is not attacker-controlled, it is already "
     "validated, or the code is safe as used (MD5 for a cache key, say). A real bug "
     "that is not a security issue is also fp; say so in the notes."),
    ("unsure", "Unsure",
     "You cannot decide from the code with reasonable effort, for example because it "
     "depends on how the code is deployed. Say in the notes what would settle it."),
]

ROLES = [("reviewer_a", "Reviewer A"), ("reviewer_b", "Reviewer B"),
         ("final", "Final (resolving disagreements)")]


def render(items: list[dict[str, Any]], *, title: str, sheet_id: str, columns: list[str],
           base_name: str) -> str:
    """The page, with ``items`` (one per candidate) embedded as data."""
    data = json.dumps({"items": items, "sheetId": sheet_id, "columns": columns,
                       "baseName": base_name, "roles": ROLES}, ensure_ascii=False)
    # Inside <script>, only "</" can end the element early; escape it.
    data = data.replace("</", "<\\/")
    verdicts = "".join(
        f"<div class='help'><span class='tag {code}'>{code}</span><div><strong>{name}.</strong> "
        f"{text}</div></div>" for code, name, text in VERDICT_HELP)
    return (_TEMPLATE.replace("__TITLE__", _escape(title))
                     .replace("__VERDICTS__", verdicts)
                     .replace("__DATA__", data))


def _escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace('"', "&quot;"))


_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root {
  --bg: #f7f7f5; --card: #ffffff; --text: #1d1d1b; --muted: #6b6b66; --line: #e2e1dc;
  --code-bg: #f1f0ec; --mark: #fff1b8; --accent: #2f5fd0;
  --tp: #1f7a3a; --fp: #a33a2a; --unsure: #8a6a00;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #161615; --card: #1f1f1d; --text: #ecebe6; --muted: #a09f98; --line: #34332f;
    --code-bg: #262623; --mark: #4a4120; --accent: #8fb0ff;
    --tp: #6fcf8a; --fp: #ff8f7a; --unsure: #e6c35c;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 980px; margin: 0 auto; padding: 24px 16px 96px; }
h1 { font-size: 22px; margin: 0 0 4px; }
.sub { color: var(--muted); margin: 0 0 20px; }
section.box { background: var(--card); border: 1px solid var(--line); border-radius: 10px;
  padding: 16px; margin-bottom: 16px; }
section.box h2 { font-size: 16px; margin: 0 0 10px; }
ol.steps { margin: 0; padding-left: 20px; }
.help { display: flex; gap: 10px; align-items: flex-start; margin: 8px 0; }
.tag { display: inline-block; min-width: 58px; text-align: center; font-weight: 600;
  border-radius: 6px; padding: 1px 8px; border: 1px solid currentColor; }
.tag.tp { color: var(--tp); } .tag.fp { color: var(--fp); } .tag.unsure { color: var(--unsure); }
.bar { position: sticky; top: 0; z-index: 2; background: var(--bg); padding: 10px 0;
  display: flex; flex-wrap: wrap; gap: 12px; align-items: center;
  border-bottom: 1px solid var(--line); margin-bottom: 16px; }
#roles { display: flex; flex-wrap: wrap; gap: 4px 12px; }
.bar label { white-space: nowrap; }
main { overflow-wrap: anywhere; }
button { font: inherit; border: 1px solid var(--line); background: var(--card); color: var(--text);
  border-radius: 8px; padding: 6px 12px; cursor: pointer; }
button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 10px;
  padding: 16px; margin-bottom: 16px; }
.card.done { border-left: 4px solid var(--accent); }
.card h3 { font-size: 15px; margin: 0 0 6px; display: flex; flex-wrap: wrap; gap: 8px; }
.loc { font-family: ui-monospace, Consolas, monospace; font-size: 13px; color: var(--muted);
  overflow-wrap: anywhere; }
.reports { margin: 8px 0; padding-left: 18px; }
.reports li { margin-bottom: 6px; }
.reports .detail { color: var(--muted); font-size: 14px; }
pre { background: var(--code-bg); border-radius: 8px; padding: 8px 0; overflow-x: auto;
  font: 12.5px/1.45 ui-monospace, Consolas, monospace; margin: 8px 0; }
pre .ln { display: block; padding: 0 12px; white-space: pre; }
pre .ln.hit { background: var(--mark); }
pre .num { display: inline-block; width: 4.5em; color: var(--muted); user-select: none; }
.choices { display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0 6px; }
.choices label { border: 1px solid var(--line); border-radius: 8px; padding: 4px 12px;
  cursor: pointer; }
.choices input { margin-right: 6px; }
textarea { width: 100%; min-height: 54px; font: inherit; color: var(--text);
  background: var(--bg); border: 1px solid var(--line); border-radius: 8px; padding: 6px 8px; }
.muted { color: var(--muted); }
.hidden { display: none; }
</style>
</head>
<body>
<main>
<h1>__TITLE__</h1>
<p class="sub">Blind review: nothing here says which model, condition or scanner reported a
candidate, and the order is shuffled.</p>

<section class="box">
<h2>How to review</h2>
<ol class="steps">
<li>Choose who you are below. Each reviewer works on their own, and nobody opens
<code>key.json</code> until every reviewer has finished.</li>
<li>For each candidate, read what was reported and the code (flagged lines are marked).
Open the file in your editor if you need more context. Then pick a verdict.</li>
<li>Your answers are kept in this browser as you go. When done, press
<strong>Download my verdicts</strong> and hand the file to whoever runs
<code>security-eval adjudicate import</code>.</li>
<li>Judge whether the issue is real, not whether the report is well written. Right
place but wrong CWE is still tp if the issue described is real; note the right CWE.</li>
</ol>
</section>

<section class="box">
<h2>What the verdicts mean</h2>
__VERDICTS__
</section>

<div class="bar">
  <span>I am:</span>
  <span id="roles"></span>
  <span id="progress" class="muted"></span>
  <label><input type="checkbox" id="only-open"> show only unjudged</label>
  <button class="primary" id="download">Download my verdicts</button>
</div>
<p id="pick-role" class="muted">Choose who you are to start.</p>
<div id="cards"></div>
</main>

<script type="application/json" id="data">__DATA__</script>
<script>
(function () {
  "use strict";
  var DATA = JSON.parse(document.getElementById("data").textContent);
  var role = "";
  var answers = {};

  function storageKey() { return "security-eval-review:" + DATA.sheetId + ":" + role; }
  function load() {
    try { answers = JSON.parse(localStorage.getItem(storageKey()) || "{}") || {}; }
    catch (e) { answers = {}; }
  }
  function save() {
    try { localStorage.setItem(storageKey(), JSON.stringify(answers)); }
    catch (e) { /* kept in memory only */ }
  }
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  var rolesBox = document.getElementById("roles");
  DATA.roles.forEach(function (pair) {
    var label = el("label");
    var input = el("input");
    input.type = "radio"; input.name = "role"; input.value = pair[0];
    input.addEventListener("change", function () { role = pair[0]; load(); draw(); });
    label.appendChild(input);
    label.appendChild(document.createTextNode(" " + pair[1] + " "));
    rolesBox.appendChild(label);
  });

  function judged() {
    return DATA.items.filter(function (it) {
      return answers[it.id] && answers[it.id].verdict;
    }).length;
  }

  function draw() {
    var cards = document.getElementById("cards");
    cards.textContent = "";
    document.getElementById("pick-role").classList.toggle("hidden", !!role);
    document.getElementById("progress").textContent =
      role ? judged() + " of " + DATA.items.length + " judged" : "";
    if (!role) return;
    var onlyOpen = document.getElementById("only-open").checked;
    DATA.items.forEach(function (it) {
      var answer = answers[it.id] || {};
      if (onlyOpen && answer.verdict) return;
      var card = el("article", "card" + (answer.verdict ? " done" : ""));
      var head = el("h3");
      head.appendChild(el("span", "", it.id));
      head.appendChild(el("span", "loc", it.location));
      if (it.cwe) head.appendChild(el("span", "muted", "suggested: " + it.cwe));
      card.appendChild(head);

      card.appendChild(el("div", "muted", "What was reported (" + it.reports.length +
        (it.reports.length === 1 ? " report)" : " reports)") + ":"));
      var list = el("ul", "reports");
      it.reports.forEach(function (r) {
        var li = el("li");
        li.appendChild(el("div", "", r.title));
        if (r.detail) li.appendChild(el("div", "detail", r.detail));
        if (r.evidence) li.appendChild(el("div", "detail", "Evidence: " + r.evidence));
        if (r.recommendation) {
          li.appendChild(el("div", "detail", "Suggested fix: " + r.recommendation));
        }
        list.appendChild(li);
      });
      card.appendChild(list);

      if (it.lines.length) {
        var pre = el("pre");
        it.lines.forEach(function (line, i) {
          var n = it.first + i;
          var row = el("span", "ln" + (n >= it.start && n <= it.end ? " hit" : ""));
          row.appendChild(el("span", "num", String(n)));
          row.appendChild(document.createTextNode(line));
          pre.appendChild(row);
        });
        card.appendChild(pre);
      } else {
        card.appendChild(el("p", "muted", "No code excerpt: no location was given, " +
          "or the file is not in the snapshot."));
      }

      var choices = el("div", "choices");
      ["tp", "fp", "unsure"].forEach(function (v) {
        var label = el("label");
        var input = el("input");
        input.type = "radio"; input.name = "v-" + it.id; input.value = v;
        input.checked = answer.verdict === v;
        input.addEventListener("change", function () {
          answers[it.id] = answers[it.id] || {};
          answers[it.id].verdict = v;
          save();
          card.classList.add("done");
          document.getElementById("progress").textContent =
            judged() + " of " + DATA.items.length + " judged";
        });
        label.appendChild(input);
        label.appendChild(el("span", "tag " + v, v));
        choices.appendChild(label);
      });
      card.appendChild(choices);
      var notes = el("textarea");
      notes.placeholder = "Notes: why, the right CWE, what would settle it (optional)";
      notes.value = answer.notes || "";
      notes.addEventListener("input", function () {
        answers[it.id] = answers[it.id] || {};
        answers[it.id].notes = notes.value;
        save();
      });
      card.appendChild(notes);
      cards.appendChild(card);
    });
  }

  document.getElementById("only-open").addEventListener("change", draw);

  function csvField(value) {
    var s = String(value == null ? "" : value);
    return /[",\\r\\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }

  document.getElementById("download").addEventListener("click", function () {
    if (!role) { alert("Choose who you are first."); return; }
    var open = DATA.items.length - judged();
    if (open && !confirm(open + " candidate(s) not judged yet. Download anyway?")) return;
    var rows = [DATA.columns.join(",")];
    DATA.items.forEach(function (it) {
      var answer = answers[it.id] || {};
      var values = { candidate: it.id, target: it.target, location: it.location,
                     cwe_suggested: it.cwe, notes: answer.notes || "" };
      values[role] = answer.verdict || "";
      rows.push(DATA.columns.map(function (c) { return csvField(values[c]); }).join(","));
    });
    var blob = new Blob([rows.join("\\r\\n") + "\\r\\n"], { type: "text/csv" });
    var link = el("a");
    link.href = URL.createObjectURL(blob);
    link.download = DATA.baseName + "-" + role + ".csv";
    document.body.appendChild(link);
    link.click();
    link.remove();
  });

  draw();
})();
</script>
</body>
</html>
"""
