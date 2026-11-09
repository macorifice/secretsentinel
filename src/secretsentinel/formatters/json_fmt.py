"""JSON output formatter."""

from __future__ import annotations

import json
from typing import List

from .. import __version__
from ..engine.models import Finding

SCHEMA_VERSION = 1


def render_json(findings: List[Finding]) -> str:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "secretsentinel", "version": __version__},
        "count": len(findings),
        "findings": [
            {
                "rule_id": f.rule_id,
                "description": f.description,
                "severity": f.severity,
                "cwe": f.cwe,
                "path": f.path,
                "line": f.line,
                "column": f.column,
                "commit": f.commit,
                "redacted": f.redacted,
                "entropy": f.entropy,
                "digest": f.digest,
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
