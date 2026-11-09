"""False-positive management: ignore files and YAML allowlists."""

from __future__ import annotations

from typing import Iterable, List, Sequence

from ..engine.models import Finding
from .allowlist import AllowEntry
from .ignore import IgnoreRules


def apply_filters(
    findings: Iterable[Finding],
    ignore: IgnoreRules,
    allowlist: Sequence[AllowEntry] = (),
) -> List[Finding]:
    """Drop findings on ignored paths and findings matched by the allowlist."""
    kept: List[Finding] = []
    for finding in findings:
        if ignore.is_ignored(finding.path):
            continue
        if any(entry.matches(finding) for entry in allowlist):
            continue
        kept.append(finding)
    return kept
