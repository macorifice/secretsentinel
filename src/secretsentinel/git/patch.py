"""Parser for unified diffs produced by git. Yields only added lines."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Iterator, Optional

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


@dataclass(frozen=True)
class AddedLine:
    path: str
    line: int
    text: str
    commit: Optional[str] = None


def iter_added_lines(patch_lines: Iterable[str], commit: Optional[str] = None) -> Iterator[AddedLine]:
    """Yield every added line with its path and line number in the new file.

    Deleted files (``+++ /dev/null``) contribute nothing. Lines are expected
    without trailing newlines.
    """
    path: Optional[str] = None
    new_line = 0
    in_hunk = False
    for raw in patch_lines:
        if raw.startswith("+++ "):
            target = raw[4:].strip()
            if target == "/dev/null":
                path = None
            else:
                path = target[2:] if target.startswith("b/") else target
            in_hunk = False
            continue
        if raw.startswith("--- ") and not in_hunk:
            continue
        match = HUNK_RE.match(raw)
        if match:
            new_line = int(match.group(1))
            in_hunk = True
            continue
        if not in_hunk or path is None:
            continue
        if raw.startswith("+"):
            yield AddedLine(path=path, line=new_line, text=raw[1:], commit=commit)
            new_line += 1
        elif raw.startswith("-"):
            continue
        elif raw.startswith("\\"):
            # "\ No newline at end of file"
            continue
        else:
            new_line += 1
