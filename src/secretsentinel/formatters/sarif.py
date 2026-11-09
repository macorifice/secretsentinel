"""SARIF 2.1.0 output for CI integrations such as GitHub code scanning."""

from __future__ import annotations

import json
from typing import Dict, List

from .. import __version__
from ..engine.models import Finding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _rule_entry(rule_id: str, description: str, severity: str, cwe: str) -> Dict:
    return {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": description},
        "defaultConfiguration": {"level": LEVEL.get(severity, "warning")},
        "properties": {"tags": ["security", "secrets", cwe], "security-severity": _score(severity)},
    }


def _score(severity: str) -> str:
    return {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}.get(severity, "5.0")


def render_sarif(findings: List[Finding]) -> str:
    rules: Dict[str, Dict] = {}
    results = []
    for f in findings:
        rules.setdefault(f.rule_id, _rule_entry(f.rule_id, f.description, f.severity, f.cwe))
        message = f"Possible {f.description.lower()} ({f.redacted})"
        if f.commit:
            message += f" introduced in commit {f.commit}"
        results.append(
            {
                "ruleId": f.rule_id,
                "level": LEVEL.get(f.severity, "warning"),
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.path.replace("\\", "/")},
                            "region": {"startLine": f.line, "startColumn": f.column},
                        }
                    }
                ],
                # Stable across runs: a secret keeps the same fingerprint even if its line moves.
                "partialFingerprints": {"secretDigest/v1": f"{f.rule_id}:{f.digest}"},
            }
        )

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secretsentinel",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"
