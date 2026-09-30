"""SARIF 2.1.0 in and out -- the minimal subset scanners and viewers agree on.

In: scanner output (Semgrep, CodeQL, Bandit...) becomes the input to RQ3, where
a model triages each result. Out: our findings in a form code-scanning tools
and IDE viewers can display, which makes spot-checking the scorer much faster.

Only ``results[].ruleId``, ``message``, ``level``, the first physical location,
and CWE tags on rules or results are read. Anything else is carried through
untouched on export and ignored on import.
"""

from __future__ import annotations

from typing import Any

from .finding import Location, SecurityFinding, find_cwe, normalise_cwe

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL_TO_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
_SEVERITY_TO_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                      "low": "note", "info": "none"}


def to_sarif(findings: list[SecurityFinding], tool: str = "security-eval") -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for finding in findings:
        rule_id = finding.cwe or "unclassified"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "properties": {"tags": [finding.cwe]} if finding.cwe else {},
        })
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
            "message": {"text": finding.title
                        + (f"\n\n{finding.detail}" if finding.detail else "")},
            "properties": {
                "confidence": finding.confidence,
                "source": finding.source,
                "recommendation": finding.recommendation,
                **({"triage": finding.triage.value} if finding.triage else {}),
            },
        }
        if finding.location:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.location.normalised_path},
                    "region": {"startLine": finding.location.start_line,
                               "endLine": finding.location.end_line},
                }
            }]
        results.append(result)
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": tool, "rules": list(rules.values())}},
                  "results": results}],
    }


def from_sarif(doc: dict[str, Any]) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    for run in doc.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        tool = str(driver.get("name", "sarif"))
        rule_cwe = {
            str(rule.get("id")): _cwe_from_tags(rule.get("properties", {}).get("tags", []))
            for rule in driver.get("rules", [])
        }
        for result in run.get("results", []):
            rule_id = str(result.get("ruleId", ""))
            message = str(result.get("message", {}).get("text", ""))
            cwe = (
                _cwe_from_tags(result.get("properties", {}).get("tags", []))
                or rule_cwe.get(rule_id)
                or find_cwe(rule_id, message)
            )
            findings.append(SecurityFinding(
                title=message.splitlines()[0] if message else rule_id,
                detail=message,
                cwe=cwe,
                location=_location(result),
                severity=_LEVEL_TO_SEVERITY.get(str(result.get("level", "warning")), "medium"),
                source=tool,
                id=rule_id,
            ))
    return findings


def _cwe_from_tags(tags: list[Any]) -> str | None:
    for tag in tags:
        cwe = normalise_cwe(tag) if "cwe" in str(tag).lower() else None
        if cwe:
            return cwe
    return None


def _location(result: dict[str, Any]) -> Location | None:
    for loc in result.get("locations", []):
        physical = loc.get("physicalLocation", {})
        uri = physical.get("artifactLocation", {}).get("uri")
        start = physical.get("region", {}).get("startLine")
        if uri and start:
            end = physical.get("region", {}).get("endLine", start)
            return Location(str(uri).removeprefix("file://"), int(start), max(int(end), int(start)))
    return None
