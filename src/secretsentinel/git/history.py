"""Scans lines added across the commit history of a repository."""

from __future__ import annotations

from dataclasses import replace
from typing import Iterator, List, Optional, Tuple

import git

from ..engine.models import Finding, Rule
from ..engine.scanner import scan_text
from .patch import iter_added_lines

COMMIT_MARKER = "@@COMMIT@@"
SHORT_SHA_LEN = 12


def history_patch(repo: git.Repo, max_commits: Optional[int] = None) -> List[str]:
    """Patch of every commit reachable from any ref, with no context lines.

    Merge commits are skipped by git's default ``-p`` behaviour. The output is
    held in memory, so very large repositories should use ``max_commits``.
    """
    args = [
        "--all",
        "-p",
        "--unified=0",
        "--no-color",
        "--no-ext-diff",
        f"--format={COMMIT_MARKER}%H",
    ]
    if max_commits:
        args.append(f"--max-count={max_commits}")
    return repo.git.log(*args).splitlines()


def _split_by_commit(lines: List[str]) -> Iterator[Tuple[str, List[str]]]:
    """Group patch lines into ``(commit_sha, lines)`` blocks."""
    current: Optional[str] = None
    block: List[str] = []
    for line in lines:
        if line.startswith(COMMIT_MARKER):
            if current is not None:
                yield current, block
            current = line[len(COMMIT_MARKER):].strip()
            block = []
        else:
            block.append(line)
    if current is not None:
        yield current, block


def scan_history(
    repo: git.Repo,
    rules: List[Rule],
    max_commits: Optional[int] = None,
) -> List[Finding]:
    """Scan every added line in the history. Findings carry the short commit SHA."""
    findings: List[Finding] = []
    for sha, block in _split_by_commit(history_patch(repo, max_commits)):
        short = sha[:SHORT_SHA_LEN]
        for added in iter_added_lines(block, commit=short):
            for f in scan_text(added.text, rules, path=added.path, commit=short):
                findings.append(replace(f, line=added.line))
    return findings
