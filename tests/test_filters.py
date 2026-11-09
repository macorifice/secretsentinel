"""Tests for .secretsentinelignore, the YAML allowlist and CLI integration."""

from __future__ import annotations

import hashlib

import pytest
from click.testing import CliRunner

from secretsentinel.cli import main
from secretsentinel.engine.models import Finding
from secretsentinel.filters import apply_filters
from secretsentinel.filters.allowlist import AllowlistError, parse_allowlist
from secretsentinel.filters.ignore import IgnoreRules

AWS_KEY = "AKIA" + "X7Q2M9ZP4LRT8WVB"
DIGEST = hashlib.sha256(AWS_KEY.encode()).hexdigest()


def make_finding(path="app/config.py", rule="aws-access-key-id", digest=DIGEST):
    return Finding(
        rule_id=rule,
        description="",
        severity="critical",
        cwe="CWE-798",
        path=path,
        line=1,
        column=1,
        redacted="AKIA...VB",
        entropy=4.0,
        digest=digest,
    )


# --- ignore -------------------------------------------------------------------

@pytest.mark.parametrize(
    "pattern, path, expected",
    [
        ("tests/fixtures/*", "tests/fixtures/a.env", True),
        ("tests/fixtures/*", "tests/fixtures/deep/b.env", True),
        ("tests/fixtures/*", "src/tests/fixtures/a.env", False),
        ("*.min.js", "web/app.min.js", True),
        ("*.min.js", "web/app.js", False),
        ("vendor/", "vendor/lib/x.py", True),
        ("vendor/", "src/vendor/x.py", False),
        (".env", ".env", True),
        ("/docs/secret.md", "docs/secret.md", True),
    ],
)
def test_ignore_patterns(pattern, path, expected):
    assert IgnoreRules([pattern]).is_ignored(path) is expected


def test_ignore_file_skips_comments_and_blank_lines(tmp_path):
    ignore_file = tmp_path / ".secretsentinelignore"
    ignore_file.write_text("# comment\n\n   \n*.md\n")
    rules = IgnoreRules.from_file(ignore_file)
    assert rules.patterns == ["*.md"]


def test_missing_ignore_file_ignores_nothing(tmp_path):
    rules = IgnoreRules.from_file(tmp_path / "nope")
    assert rules.is_ignored("anything.py") is False


# --- allowlist ----------------------------------------------------------------

def test_allowlist_entry_by_digest_matches_exact_secret():
    entries = parse_allowlist(f"allow:\n  - sha256: {DIGEST}\n    reason: docs\n")
    assert entries[0].matches(make_finding())
    assert not entries[0].matches(make_finding(digest="0" * 64))


def test_allowlist_entry_requires_all_set_fields_to_match():
    entries = parse_allowlist(
        "allow:\n  - rule: aws-access-key-id\n    path: tests/*\n"
    )
    assert not entries[0].matches(make_finding(path="app/config.py"))
    assert entries[0].matches(make_finding(path="tests/x.py"))
    assert not entries[0].matches(make_finding(path="tests/x.py", rule="github-token"))


def test_allowlist_entry_without_selectors_is_rejected():
    with pytest.raises(AllowlistError, match="at least one"):
        parse_allowlist("allow:\n  - reason: too broad\n")


def test_allowlist_must_be_a_list():
    with pytest.raises(AllowlistError, match="must be a list"):
        parse_allowlist("allow: nope\n")


def test_apply_filters_combines_ignore_and_allowlist():
    findings = [
        make_finding(path="vendor/x.py"),
        make_finding(path="app/allowed.py", digest=DIGEST),
        make_finding(path="app/real.py", digest="1" * 64),
    ]
    allow = parse_allowlist(f"allow:\n  - sha256: {DIGEST}\n")
    kept = apply_filters(findings, IgnoreRules(["vendor/"]), allow)
    assert [f.path for f in kept] == ["app/real.py"]


# --- CLI ----------------------------------------------------------------------

def test_cli_respects_ignore_file(tmp_path):
    (tmp_path / ".secretsentinelignore").write_text("fixtures/*\n")
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "a.py").write_text(f"KEY = '{AWS_KEY}'\n")
    result = CliRunner().invoke(main, ["scan", str(tmp_path)])
    assert result.exit_code == 0


def test_cli_respects_allowlist_by_digest(tmp_path):
    (tmp_path / "a.py").write_text(f"KEY = '{AWS_KEY}'\n")
    (tmp_path / ".secretsentinel-allow.yaml").write_text(
        f"allow:\n  - sha256: {DIGEST}\n    reason: known test key\n"
    )
    result = CliRunner().invoke(main, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert AWS_KEY not in result.output


def test_cli_explicit_allowlist_path(tmp_path):
    (tmp_path / "a.py").write_text(f"KEY = '{AWS_KEY}'\n")
    allow = tmp_path / "custom.yaml"
    allow.write_text(f"allow:\n  - rule: aws-access-key-id\n")
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--allowlist", str(allow)]
    )
    assert result.exit_code == 0


def test_cli_invalid_allowlist_exits_two(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / ".secretsentinel-allow.yaml").write_text("allow: [unclosed\n")
    result = CliRunner().invoke(main, ["scan", str(tmp_path)])
    assert result.exit_code == 2
