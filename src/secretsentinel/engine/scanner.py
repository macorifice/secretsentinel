"""Applies loaded rules to text content and yields findings."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Iterable, Iterator, List, Optional

from .entropy import shannon_entropy
from .models import Finding, Rule

MAX_FILE_BYTES = 1_000_000  # files larger than this are skipped
BINARY_PROBE_BYTES = 8000
SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__", ".tox"}


def redact(secret: str) -> str:
    """Return a non-reversible preview of a secret, safe to print or store."""
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}...{secret[-2:]} ({len(secret)} chars)"


def scan_text(
    text: str,
    rules: Iterable[Rule],
    path: str = "<stdin>",
    commit: Optional[str] = None,
) -> List[Finding]:
    """Scan ``text`` line by line and return every finding that passes the entropy check."""
    rules = list(rules)
    findings: List[Finding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for rule in rules:
            for match in rule.pattern.finditer(line):
                if rule.pattern.groups >= 1 and match.group(1) is not None:
                    secret = match.group(1)
                    column = match.start(1) + 1
                else:
                    secret = match.group(0)
                    column = match.start() + 1
                entropy = shannon_entropy(secret)
                if entropy < rule.min_entropy:
                    continue
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        description=rule.description,
                        severity=rule.severity,
                        cwe=rule.cwe,
                        path=path,
                        line=line_no,
                        column=column,
                        redacted=redact(secret),
                        entropy=round(entropy, 2),
                        commit=commit,
                        digest=hashlib.sha256(secret.encode("utf-8")).hexdigest(),
                    )
                )
    return findings


def is_probably_binary(data: bytes) -> bool:
    return b"\x00" in data[:BINARY_PROBE_BYTES]


def scan_file(path: Path, rules: Iterable[Rule], root: Optional[Path] = None) -> List[Finding]:
    """Scan one file on disk. Binary and oversized files are skipped."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return []
        data = path.read_bytes()
    except OSError:
        return []
    if is_probably_binary(data):
        return []
    text = data.decode("utf-8", errors="replace")
    display = str(path.relative_to(root)) if root else str(path)
    return scan_text(text, rules, path=display)


def iter_files(root: Path) -> Iterator[Path]:
    """Yield regular files under ``root``, skipping VCS and dependency directories."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            full = Path(dirpath) / name
            if full.is_file() and not full.is_symlink():
                yield full


def scan_directory(root: Path, rules: Iterable[Rule]) -> List[Finding]:
    """Scan every file under ``root``."""
    rules = list(rules)
    findings: List[Finding] = []
    for file_path in iter_files(root):
        findings.extend(scan_file(file_path, rules, root=root))
    return findings
