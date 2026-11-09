"""YAML allowlist of accepted findings.

Example ``.secretsentinel-allow.yaml``::

    allow:
      - sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
        reason: Example key used in documentation
      - rule: generic-password-assignment
        path: tests/fixtures/*
        reason: Test fixtures contain fake passwords

An entry matches when every field it sets matches. ``sha256`` matches the exact
secret; ``rule`` matches the rule id; ``path`` is a glob on the relative path.
An entry must set at least one of these fields, and should set a ``reason``.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import yaml

from ..engine.models import Finding

ALLOWLIST_FILE_NAME = ".secretsentinel-allow.yaml"


class AllowlistError(ValueError):
    pass


@dataclass(frozen=True)
class AllowEntry:
    rule: Optional[str] = None
    path: Optional[str] = None
    sha256: Optional[str] = None
    reason: str = ""

    def matches(self, finding: Finding) -> bool:
        if self.rule is not None and finding.rule_id != self.rule:
            return False
        if self.path is not None and not fnmatch.fnmatchcase(finding.path, self.path):
            return False
        if self.sha256 is not None and finding.digest != self.sha256:
            return False
        return True


def parse_allowlist(text: str, source: str = "<string>") -> List[AllowEntry]:
    data = yaml.safe_load(text) or {}
    raw_entries = data.get("allow") or []
    if not isinstance(raw_entries, list):
        raise AllowlistError(f"{source}: 'allow' must be a list")

    entries: List[AllowEntry] = []
    for index, raw in enumerate(raw_entries, start=1):
        if not isinstance(raw, dict):
            raise AllowlistError(f"{source}: entry {index} must be a mapping")
        entry = AllowEntry(
            rule=raw.get("rule"),
            path=raw.get("path"),
            sha256=raw.get("sha256"),
            reason=str(raw.get("reason", "")),
        )
        if entry.rule is None and entry.path is None and entry.sha256 is None:
            raise AllowlistError(
                f"{source}: entry {index} must set at least one of rule, path or sha256"
            )
        entries.append(entry)
    return entries


def load_allowlist(path: Path) -> List[AllowEntry]:
    if not path.is_file():
        return []
    try:
        return parse_allowlist(path.read_text(encoding="utf-8"), source=str(path))
    except yaml.YAMLError as exc:
        raise AllowlistError(f"{path}: invalid YAML: {exc}") from exc
