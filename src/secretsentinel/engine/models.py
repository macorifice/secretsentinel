"""Core data types shared by the engine, filters and formatters."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

SEVERITIES = ("low", "medium", "high", "critical")


@dataclass(frozen=True)
class Rule:
    """A detection rule loaded from YAML.

    If ``pattern`` contains a capture group, the first group is the candidate
    secret used for entropy scoring; otherwise the whole match is used.
    """

    id: str
    description: str
    pattern: "re.Pattern[str]"
    severity: str = "high"
    cwe: str = "CWE-798"
    min_entropy: float = 0.0


@dataclass(frozen=True)
class Finding:
    """A single suspected secret."""

    rule_id: str
    description: str
    severity: str
    cwe: str
    path: str
    line: int
    column: int
    redacted: str
    entropy: float
    commit: Optional[str] = None
    digest: str = ""  # SHA-256 of the secret; lets allowlists match without storing it
    extra: dict = field(default_factory=dict)
