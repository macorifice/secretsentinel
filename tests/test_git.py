"""Tests for git integration: working tree, staged changes and history."""

from __future__ import annotations

import subprocess

import pytest
from click.testing import CliRunner

from secretsentinel.cli import main
from secretsentinel.git.patch import iter_added_lines

AWS_KEY = "AKIA" + "X7Q2M9ZP4LRT8WVB"
CLEAN = "print('hello')"


def git(repo, *args):
    env = {
        "GIT_AUTHOR_NAME": "test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "HOME": str(repo),
    }
    return subprocess.run(
        ["git", "-c", "commit.gpgsign=false", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.email", "test@example.com")
    git(tmp_path, "config", "user.name", "test")
    (tmp_path / "README.md").write_text("# demo\n")
    git(tmp_path, "add", "README.md")
    git(tmp_path, "commit", "-q", "-m", "init")
    return tmp_path


def run(args, cwd):
    runner = CliRunner()
    # The CLI resolves paths relative to the current directory, so pass absolute paths.
    return runner.invoke(main, args)


# --- patch parser -------------------------------------------------------------

def test_patch_parser_reports_new_line_numbers():
    patch = [
        "diff --git a/app.py b/app.py",
        "--- a/app.py",
        "+++ b/app.py",
        "@@ -2,0 +3,2 @@",
        "+x = 1",
        "+y = 2",
    ]
    added = list(iter_added_lines(patch))
    assert [(a.path, a.line, a.text) for a in added] == [
        ("app.py", 3, "x = 1"),
        ("app.py", 4, "y = 2"),
    ]


def test_patch_parser_ignores_deleted_files():
    patch = [
        "--- a/gone.py",
        "+++ /dev/null",
        "@@ -1 +0,0 @@",
        "-secret",
    ]
    assert list(iter_added_lines(patch)) == []


# --- working tree -------------------------------------------------------------

def test_untracked_secret_is_found(repo, monkeypatch):
    monkeypatch.chdir(repo)
    (repo / "config.py").write_text(f"KEY = '{AWS_KEY}'\n")
    result = run(["scan", str(repo)], repo)
    assert result.exit_code == 1
    assert "config.py:1" in result.output


def test_gitignored_file_is_skipped(repo, monkeypatch):
    monkeypatch.chdir(repo)
    (repo / ".gitignore").write_text("local.env\n")
    git(repo, "add", ".gitignore")
    git(repo, "commit", "-q", "-m", "ignore")
    (repo / "local.env").write_text(f"KEY={AWS_KEY}\n")
    result = run(["scan", str(repo)], repo)
    assert result.exit_code == 0


# --- staged -------------------------------------------------------------------

def test_staged_secret_is_found_with_line_number(repo, monkeypatch):
    monkeypatch.chdir(repo)
    (repo / "app.py").write_text(f"ok = 1\nkey = '{AWS_KEY}'\n")
    git(repo, "add", "app.py")
    result = run(["scan", "--staged", str(repo)], repo)
    assert result.exit_code == 1
    assert "app.py:2" in result.output


def test_unstaged_secret_is_not_reported_by_staged_scan(repo, monkeypatch):
    monkeypatch.chdir(repo)
    (repo / "app.py").write_text(f"key = '{AWS_KEY}'\n")
    result = run(["scan", "--staged", str(repo)], repo)
    assert result.exit_code == 0


# --- history ------------------------------------------------------------------

def test_deleted_secret_is_still_found_in_history(repo, monkeypatch):
    monkeypatch.chdir(repo)
    (repo / "secrets.py").write_text(f"KEY = '{AWS_KEY}'\n")
    git(repo, "add", "secrets.py")
    git(repo, "commit", "-q", "-m", "add key")
    git(repo, "rm", "-q", "secrets.py")
    git(repo, "commit", "-q", "-m", "remove key")

    # Working tree is clean...
    assert run(["scan", str(repo)], repo).exit_code == 0
    # ...but history still contains the secret.
    result = run(["scan", "--history", str(repo)], repo)
    assert result.exit_code == 1
    assert "secrets.py" in result.output
    assert "(commit " in result.output


def test_history_with_clean_repo_exits_zero(repo, monkeypatch):
    monkeypatch.chdir(repo)
    result = run(["scan", "--history", str(repo)], repo)
    assert result.exit_code == 0


def test_flags_cannot_be_combined(repo, monkeypatch):
    monkeypatch.chdir(repo)
    result = run(["scan", "--staged", "--history", str(repo)], repo)
    assert result.exit_code == 2


def test_git_flags_outside_repo_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = run(["scan", "--staged", str(tmp_path)], tmp_path)
    assert result.exit_code == 2
    assert "not inside a git repository" in result.output
