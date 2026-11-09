"""Parses .secretsentinelignore files and decides which paths to skip.

Format: one pattern per line, ``#`` starts a comment, blank lines are ignored.

- ``tests/fixtures/*``  glob matched against the path relative to the root
  (``*`` also matches ``/`` here, so it covers nested files)
- ``*.min.js``          a pattern without ``/`` matches the file name at any depth
- ``vendor/``           a trailing slash matches everything under that directory
"""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Iterable, List

IGNORE_FILE_NAME = ".secretsentinelignore"


class IgnoreRules:
    def __init__(self, patterns: Iterable[str] = ()) -> None:
        self.patterns: List[str] = [p for p in (_clean(x) for x in patterns) if p]

    @classmethod
    def from_file(cls, path: Path) -> "IgnoreRules":
        if not path.is_file():
            return cls()
        return cls(path.read_text(encoding="utf-8").splitlines())

    def is_ignored(self, rel_path: str) -> bool:
        rel = rel_path.replace("\\", "/")
        if rel.startswith("./"):
            rel = rel[2:]
        name = rel.rsplit("/", 1)[-1]
        for pattern in self.patterns:
            if pattern.endswith("/"):
                if f"/{rel}".startswith(f"/{pattern}"):
                    return True
            elif "/" not in pattern:
                if fnmatch.fnmatchcase(name, pattern):
                    return True
            elif fnmatch.fnmatchcase(rel, pattern):
                return True
        return False


def _clean(line: str) -> str:
    line = line.strip()
    if not line or line.startswith("#"):
        return ""
    return line.lstrip("/")
