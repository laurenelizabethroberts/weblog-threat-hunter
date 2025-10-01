from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
import re
from typing import Iterator, Optional

# Regex for Apache Common/Combined
_APACHE_RE = re.compile(
    r'^(?P<host>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+))"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    r'\s*$'
)

_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"

@dataclass(frozen=True)
class LogRecord:
    raw: str
    host: str
    ident: Optional[str]
    user: Optional[str]
    time: datetime
    method: str
    path: str
    protocol: str
    status: int
    bytes: int
    referer: Optional[str]
    user_agent: Optional[str]

def _normalize_dash(value: str) -> Optional[str]:
    return None if value == "-" else value

def parse_line(line: str) -> LogRecord:
    m = _APACHE_RE.match(line.rstrip("\n"))
    if not m:
        raise ValueError(f"Unrecognized log format: {line!r}")
    gd = m.groupdict()
    byte_str = gd["bytes"]
    return LogRecord(
        raw=line,
        host=gd["host"],
        ident=_normalize_dash(gd["ident"]),
        user=_normalize_dash(gd["user"]),
        time=datetime.strptime(gd["time"], _TIME_FMT),
        method=gd["method"],
        path=gd["path"],
        protocol=gd["protocol"],
        status=int(gd["status"]),
        bytes=0 if byte_str == "-" else int(byte_str),
        referer=_normalize_dash(gd.get("referer") if gd.get("referer") is not None else "-"),
        user_agent=_normalize_dash(gd.get("ua") if gd.get("ua") is not None else "-"),
    )

def parse_file(path: str) -> Iterator[LogRecord]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            s = line.strip()
            if not s:
                continue
            try:
                yield parse_line(s)
            except ValueError as e:
                raise ValueError(f"{path}:{lineno}: {e}") from e
