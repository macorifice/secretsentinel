"""Unit tests for entropy, rule loading and the scanning engine.

Secrets are assembled at runtime so that the repository itself never contains
strings that look like real credentials.
"""

from __future__ import annotations

import pytest

from secretsentinel.engine.entropy import shannon_entropy
from secretsentinel.engine.rules import RuleError, load_default_rules, parse_rules
from secretsentinel.engine.scanner import redact, scan_text

AWS_KEY = "AKIA" + "X7Q2M9ZP4LRT8WVB"
GITHUB_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
STRIPE_KEY = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"


@pytest.fixture(scope="module")
def rules():
    return load_default_rules()


def test_entropy_of_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_entropy_of_repeated_char_is_zero():
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_increases_with_variety():
    assert shannon_entropy("abcdefgh") > shannon_entropy("abababab")
    assert shannon_entropy("abcdefgh") == pytest.approx(3.0)


def test_default_rules_load_and_have_unique_ids(rules):
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))
    assert "aws-access-key-id" in ids


def test_aws_key_is_detected(rules):
    findings = scan_text(f"aws_key = {AWS_KEY}", rules, path="app.py")
    assert [f.rule_id for f in findings] == ["aws-access-key-id"]
    assert findings[0].line == 1
    assert findings[0].cwe == "CWE-798"
    assert AWS_KEY not in findings[0].redacted


def test_github_token_and_stripe_key_detected(rules):
    text = f"token={GITHUB_TOKEN}\nstripe={STRIPE_KEY}\n"
    ids = {f.rule_id for f in scan_text(text, rules)}
    assert {"github-token", "stripe-live-key"} <= ids


def test_line_numbers_are_correct(rules):
    text = "a = 1\nb = 2\n" + f"key = {AWS_KEY}\n"
    findings = scan_text(text, rules)
    assert findings[0].line == 3


def test_password_assignment_detected_with_entropy_check(rules):
    strong = scan_text('password = "Xk9#mQ2vLp7!"', rules)
    weak = scan_text('password = "password"', rules)
    assert any(f.rule_id == "generic-password-assignment" for f in strong)
    assert not any(f.rule_id == "generic-password-assignment" for f in weak)


def test_private_key_header_detected(rules):
    header = "-----BEGIN " + "RSA PRIVATE KEY-----"
    findings = scan_text(header, rules)
    assert findings and findings[0].rule_id == "private-key-block"


def test_clean_text_has_no_findings(rules):
    text = "def add(a, b):\n    return a + b\n"
    assert scan_text(text, rules) == []


def test_redact_never_returns_full_secret():
    assert redact("short") == "*****"
    preview = redact(AWS_KEY)
    assert AWS_KEY not in preview
    assert preview.startswith("AKIA")


def test_parse_rules_rejects_bad_regex():
    bad = "rules:\n  - id: broken\n    regex: '('\n"
    with pytest.raises(RuleError, match="invalid regex"):
        parse_rules(bad, source="test")


def test_parse_rules_rejects_bad_severity():
    bad = "rules:\n  - id: x\n    regex: 'a'\n    severity: extreme\n"
    with pytest.raises(RuleError, match="invalid severity"):
        parse_rules(bad, source="test")


def test_parse_rules_requires_id_and_regex():
    with pytest.raises(RuleError, match="missing required key"):
        parse_rules("rules:\n  - regex: 'a'\n", source="test")


def test_custom_rule_overrides_default_by_id(rules):
    custom = parse_rules(
        "rules:\n  - id: aws-access-key-id\n    regex: 'NOPE'\n", source="custom"
    )
    merged = {r.id: r for r in rules}
    merged.update({r.id: r for r in custom})
    assert merged["aws-access-key-id"].pattern.pattern == "NOPE"
