from __future__ import annotations
from typing import Iterable, List, Tuple
from collections import defaultdict
from .parser import LogRecord

def compute_top_talkers(records: Iterable[LogRecord], limit: int = 5) -> List[Tuple[str, int, int, int]]:
    """
    Returns list of (host, total, fourxx, fivexx), sorted by total desc.
    """
    counts = defaultdict(lambda: [0, 0, 0])  # total, 4xx, 5xx
    for r in records:
        row = counts[r.host]
        row[0] += 1
        if 400 <= r.status <= 499:
            row[1] += 1
        if 500 <= r.status <= 599:
            row[2] += 1

    ranked = sorted(((h, *vals) for h, vals in counts.items()), key=lambda t: t[1], reverse=True)
    return ranked[:limit]
