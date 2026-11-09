"""Shannon entropy calculation used to score candidate secrets."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy of ``value`` in bits per character.

    Random secrets (API keys, tokens) score high; words and placeholders such as
    ``"changeme"`` or ``"xxxxxxxx"`` score low. An empty string scores 0.0.
    """
    if not value:
        return 0.0
    length = len(value)
    counts = Counter(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())
