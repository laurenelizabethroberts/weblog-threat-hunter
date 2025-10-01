from __future__ import annotations
from datetime import datetime, timezone
from typing import Iterable, Dict, Tuple
from collections import defaultdict

def to_epoch_seconds(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())

def bucketize_per_host(
    rows: Iterable[Tuple[str, int]], window_seconds: int
) -> Dict[str, Dict[int, int]]:
    """
    rows: iterable of (host, epoch_seconds)
    returns: host -> { bucket_start_epoch: count }
    """
    res: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
    for host, t in rows:
        bstart = (t // window_seconds) * window_seconds
        res[host][bstart] += 1
    return res
