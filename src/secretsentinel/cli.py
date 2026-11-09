"""Command-line entry point."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional

import click
import git

from . import __version__
from .engine.models import Finding
from .engine.rules import RuleError, load_rules
from .engine.scanner import scan_directory, scan_file
from .filters import apply_filters
from .filters.allowlist import ALLOWLIST_FILE_NAME, AllowlistError, load_allowlist
from .filters.ignore import IGNORE_FILE_NAME, IgnoreRules
from .formatters.console import render_console
from .formatters.json_fmt import render_json
from .formatters.sarif import render_sarif
from .git.history import scan_history
from .git.working_tree import iter_repo_files, open_repo, scan_staged

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

FORMATTERS = {"json": render_json, "sarif": render_sarif}


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="secretsentinel")
def main() -> None:
    """SecretSentinel: find hard-coded secrets in your code."""


def _scan_repo_working_tree(path: Path, repo: git.Repo, rules) -> List[Finding]:
    """Scan files git knows about (tracked or not ignored) under ``path``."""
    root = Path(repo.working_tree_dir)
    scope = path.resolve()
    findings: List[Finding] = []
    for file_path in iter_repo_files(repo):
        if scope == file_path or scope in file_path.parents:
            findings.extend(scan_file(file_path, rules, root=root))
    return findings


def _fail(message: str) -> None:
    click.echo(f"error: {message}", err=True)
    sys.exit(EXIT_ERROR)


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
@click.option(
    "--rules-file",
    "rules_files",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Extra YAML rules file. Repeatable. Same id overrides a default rule.",
)
@click.option(
    "--allowlist",
    "allowlist_file",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help=f"YAML allowlist. Default: {ALLOWLIST_FILE_NAME} at the scan root, if present.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["console", *sorted(FORMATTERS)]),
    default="console",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output",
    "output_file",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write the report to this file instead of stdout (json or sarif only).",
)
@click.option("--staged", is_flag=True, help="Scan only lines staged for commit (git index).")
@click.option("--history", is_flag=True, help="Scan every added line in the commit history.")
@click.option(
    "--max-commits",
    type=click.IntRange(min=1),
    default=None,
    help="With --history, limit how many commits are scanned.",
)
def scan(
    path: Path,
    rules_files: tuple,
    allowlist_file: Optional[Path],
    output_format: str,
    output_file: Optional[Path],
    staged: bool,
    history: bool,
    max_commits: Optional[int],
) -> None:
    """Scan PATH (a file or directory) for secrets.

    Inside a git repository, the default scan covers tracked files and
    untracked files that are not ignored. Use --staged or --history for git-specific scans.
    """
    if staged and history:
        _fail("--staged and --history cannot be used together")
    if max_commits and not history:
        _fail("--max-commits requires --history")

    try:
        rules = load_rules(rules_files)
    except (RuleError, OSError) as exc:
        _fail(str(exc))

    try:
        repo: Optional[git.Repo] = open_repo(path)
    except git.InvalidGitRepositoryError:
        repo = None
    if (staged or history) and repo is None:
        _fail(f"{path} is not inside a git repository")

    # Base directory: paths in findings and ignore patterns are relative to it.
    if repo is not None:
        base = Path(repo.working_tree_dir)
    elif path.is_dir():
        base = path
    else:
        base = path.parent

    try:
        ignore = IgnoreRules.from_file(base / IGNORE_FILE_NAME)
        allow_path = allowlist_file or (base / ALLOWLIST_FILE_NAME)
        allowlist = load_allowlist(allow_path)
    except (AllowlistError, OSError) as exc:
        _fail(str(exc))

    findings: List[Finding]
    if staged and repo is not None:
        findings = scan_staged(repo, rules)
    elif history and repo is not None:
        findings = scan_history(repo, rules, max_commits=max_commits)
    elif path.is_file():
        findings = scan_file(path, rules, root=base)
    elif repo is not None:
        findings = _scan_repo_working_tree(path, repo, rules)
    else:
        findings = scan_directory(path, rules)

    findings = apply_filters(findings, ignore, allowlist)

    if output_file is not None:
        if output_format == "console":
            _fail("--output is not supported with --format console; use json or sarif")
        output_file.write_text(FORMATTERS[output_format](findings), encoding="utf-8")
        click.echo(f"Report written to {output_file}", err=True)
    elif output_format == "console":
        render_console(findings)
    else:
        click.echo(FORMATTERS[output_format](findings), nl=False)

    sys.exit(EXIT_FINDINGS if findings else EXIT_CLEAN)


if __name__ == "__main__":
    main()
