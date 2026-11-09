"""Working-tree and staged-change scanning for git repositories."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Iterator, List

import git

from ..engine.models import Finding, Rule
from ..engine.scanner import scan_text
from .patch import iter_added_lines


def open_repo(path: Path) -> git.Repo:
    """Open the git repository containing ``path``.

    Raises ``git.InvalidGitRepositoryError`` if there is none.
    """
    return git.Repo(path, search_parent_directories=True)


def iter_repo_files(repo: git.Repo) -> Iterator[Path]:
    """Yield tracked and untracked (not ignored) files of the repository."""
    root = Path(repo.working_tree_dir)
    output = repo.git.ls_files("--cached", "--others", "--exclude-standard", "-z")
    for name in output.split("\0"):
        if not name:
            continue
        full = root / name
        if full.is_file() and not full.is_symlink():
            yield full


def staged_patch(repo: git.Repo) -> List[str]:
    """Unified diff of the index against HEAD, with no context lines."""
    text = repo.git.diff("--cached", "--unified=0", "--no-color", "--no-ext-diff")
    return text.splitlines()


def scan_staged(repo: git.Repo, rules: List[Rule]) -> List[Finding]:
    """Scan only the lines being added to the index, reporting their real line numbers."""
    findings: List[Finding] = []
    for added in iter_added_lines(staged_patch(repo)):
        for f in scan_text(added.text, rules, path=added.path):
            findings.append(replace(f, line=added.line))
    return findings
