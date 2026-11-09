"""Tests for the console, JSON and SARIF output formats."""

from __future__ import annotations

import json

from click.testing import CliRunner

from secretsentinel.cli import main
from secretsentinel.engine.models import Finding
from secretsentinel.formatters.json_fmt import SCHEMA_VERSION, render_json
from secretsentinel.formatters.sarif import render_sarif

AWS_KEY = "AKIA" + "X7Q2M9ZP4LRT8WVB"


def sample_findings():
    base = dict(
        description="AWS access key ID",
        severity="critical",
        cwe="CWE-798",
        redacted="AKIA...VB (20 chars)",
        entropy=4.0,
        digest="ab" * 32,
    )
    return [
        Finding(rule_id="aws-access-key-id", path="src/a.py", line=3, column=7, **base),
        Finding(
            rule_id="aws-access-key-id",
            path="old/b.py",
            line=1,
            column=1,
            commit="deadbeef1234",
            **base,
        ),
    ]


def test_json_structure_and_counts():
    data = json.loads(render_json(sample_findings()))
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["count"] == 2
    first = data["findings"][0]
    assert first["path"] == "src/a.py"
    assert first["line"] == 3
    assert first["redacted"].startswith("AKIA")
    assert data["findings"][1]["commit"] == "deadbeef1234"


def test_json_empty_report():
    data = json.loads(render_json([]))
    assert data["count"] == 0
    assert data["findings"] == []


def test_sarif_is_valid_2_1_0_shape():
    sarif = json.loads(render_sarif(sample_findings()))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "secretsentinel"
    # One rule entry, even though two findings share it.
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["aws-access-key-id"]
    assert len(run["results"]) == 2
    result = run["results"][0]
    assert result["level"] == "error"
    region = result["locations"][0]["physicalLocation"]["region"]
    assert region == {"startLine": 3, "startColumn": 7}
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/a.py"


def test_sarif_level_mapping():
    findings = sample_findings()
    findings[0] = Finding(**{**findings[0].__dict__, "severity": "low"})
    sarif = json.loads(render_sarif(findings))
    assert sarif["runs"][0]["results"][0]["level"] == "note"


def test_sarif_fingerprint_does_not_contain_secret_preview():
    sarif_text = render_sarif(sample_findings())
    assert "partialFingerprints" in sarif_text
    assert AWS_KEY not in sarif_text


def test_cli_json_to_stdout(tmp_path):
    (tmp_path / "a.py").write_text(f"KEY = '{AWS_KEY}'\n")
    result = CliRunner().invoke(main, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["count"] == 1
    assert AWS_KEY not in result.output


def test_cli_sarif_to_file(tmp_path):
    (tmp_path / "a.py").write_text(f"KEY = '{AWS_KEY}'\n")
    out = tmp_path / "out.sarif"
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--format", "sarif", "--output", str(out)]
    )
    assert result.exit_code == 1
    sarif = json.loads(out.read_text())
    assert sarif["runs"][0]["results"][0]["ruleId"] == "aws-access-key-id"


def test_cli_console_with_output_file_is_rejected(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--output", str(tmp_path / "x.txt")]
    )
    assert result.exit_code == 2


def test_cli_console_clean_run(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    result = CliRunner().invoke(main, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "No secrets found" in result.output
