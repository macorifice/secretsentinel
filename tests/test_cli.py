"""End-to-end tests for the CLI on the working tree (week 1-2 scope)."""

from __future__ import annotations

from click.testing import CliRunner

from secretsentinel.cli import main

AWS_KEY = "AKIA" + "X7Q2M9ZP4LRT8WVB"


def test_clean_directory_exits_zero(tmp_path):
    (tmp_path / "ok.py").write_text("print('hello')\n")
    result = CliRunner().invoke(main, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "No secrets found" in result.output


def test_directory_with_secret_exits_one(tmp_path):
    (tmp_path / "config.py").write_text(f"KEY = '{AWS_KEY}'\n")
    result = CliRunner().invoke(main, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    assert "config.py:1:" in result.output
    assert "aws-access-key-id" in result.output
    assert AWS_KEY not in result.output


def test_skips_git_and_binary_files(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "leak.txt").write_text(AWS_KEY)
    (tmp_path / "image.bin").write_bytes(b"\x00\x01" + AWS_KEY.encode())
    result = CliRunner().invoke(main, ["scan", str(tmp_path)])
    assert result.exit_code == 0


def test_invalid_rules_file_exits_two(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules:\n  - id: x\n    regex: '('\n")
    target = tmp_path / "a.txt"
    target.write_text("hello")
    result = CliRunner().invoke(
        main, ["scan", str(target), "--rules-file", str(rules)]
    )
    assert result.exit_code == 2
    assert "invalid regex" in result.output


def test_custom_rules_file_adds_detection(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n  - id: internal-token\n    regex: 'INT-[0-9]{6}'\n    severity: low\n"
    )
    target = tmp_path / "a.txt"
    target.write_text("ref INT-123456")
    result = CliRunner().invoke(
        main, ["scan", str(target), "--rules-file", str(rules)]
    )
    assert result.exit_code == 1
    assert "internal-token" in result.output
