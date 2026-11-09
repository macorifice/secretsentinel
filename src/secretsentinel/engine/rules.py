"""Loads detection rules from YAML files."""

from __future__ import annotations

import re
from importlib import resources
from pathlib import Path
from typing import Iterable, List

import yaml

from .models import SEVERITIES, Rule


class RuleError(ValueError):
    """Raised when a rules file is malformed."""


def _compile_rule(raw: dict, source: str) -> Rule:
    try:
        rule_id = str(raw["id"])
        pattern_text = str(raw["regex"])
    except KeyError as exc:
        raise RuleError(f"{source}: rule is missing required key {exc}") from exc

    severity = str(raw.get("severity", "high")).lower()
    if severity not in SEVERITIES:
        raise RuleError(f"{source}: rule {rule_id!r} has invalid severity {severity!r}")

    try:
        pattern = re.compile(pattern_text)
    except re.error as exc:
        raise RuleError(f"{source}: rule {rule_id!r} has invalid regex: {exc}") from exc

    return Rule(
        id=rule_id,
        description=str(raw.get("description", rule_id)),
        pattern=pattern,
        severity=severity,
        cwe=str(raw.get("cwe", "CWE-798")),
        min_entropy=float(raw.get("min_entropy", 0.0)),
    )


def parse_rules(text: str, source: str = "<string>") -> List[Rule]:
    """Parse a YAML document of the form ``{"rules": [ {...}, ... ]}``."""
    data = yaml.safe_load(text) or {}
    raw_rules = data.get("rules") or []
    if not isinstance(raw_rules, list):
        raise RuleError(f"{source}: 'rules' must be a list")
    return [_compile_rule(item, source) for item in raw_rules]


def load_default_rules() -> List[Rule]:
    """Load the rules bundled with the package."""
    text = resources.files("secretsentinel").joinpath("rules/default.yaml").read_text(
        encoding="utf-8"
    )
    return parse_rules(text, source="default.yaml")


def load_rules(extra_files: Iterable[Path] = ()) -> List[Rule]:
    """Return default rules plus any rules from user-supplied YAML files.

    A custom rule with the same id as a default rule replaces it.
    """
    rules = {rule.id: rule for rule in load_default_rules()}
    for path in extra_files:
        for rule in parse_rules(Path(path).read_text(encoding="utf-8"), source=str(path)):
            rules[rule.id] = rule
    return list(rules.values())
