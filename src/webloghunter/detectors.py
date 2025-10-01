from __future__ import annotations
from dataclasses import dataclass
from collections import defaultdict, Counter
from typing import Iterable, List, Dict
import re

from .parser import LogRecord
from .timebucket import to_epoch_seconds, bucketize_per_host
from .config import Config

_RE_SQLI = re.compile(r"(?i)(\bunion(?:\s+all)?\s+select\b|\bor\s+1=1\b|\bsleep\s*\()", re.I)
_RE_LFI  = re.compile(r"(\.\./){2,}|/etc/passwd", re.I)
_RE_RFI  = re.compile(r"https?://[^/\s]+/.*", re.I)
_RE_SHELLSHOCK = re.compile(r"\(\)\s*\{\s*:\s*;\s*\}")

_BAD_UA_HINTS = re.compile(r"(sqlmap|nikto|dirbuster|gobuster|wpscan|nmap|curl|wget)", re.I)

@dataclass(frozen=True)
class Finding:
    type: str
    host: str
    count: int
    severity: str
    evidence: str

def analyze(records: Iterable[LogRecord], cfg: Config) -> List[Finding]:
    recs = list(records)

    by_host_status = defaultdict(Counter)
    by_host_login401 = Counter()
    sqli_hits: Dict[str, int] = Counter()
    lfi_hits: Dict[str, int] = Counter()
    rfi_hits: Dict[str, int] = Counter()
    shellshock_hits: Dict[str, int] = Counter()
    badua_hits: Dict[str, int] = Counter()

    # For time-windowed buckets
    dirbust_rows = []   # (host, epoch_seconds) for 404s
    brute_rows   = []   # (host, epoch_seconds) for 401s on login-ish paths

    for r in recs:
        by_host_status[r.host][r.status] += 1
        path_lower = r.path.lower()
        tsec = to_epoch_seconds(r.time)

        # brute force signals
        if r.status == 401 and any(h in path_lower for h in cfg.login_hints):
            by_host_login401[r.host] += 1
            brute_rows.append((r.host, tsec))

        # dirbusting windows (lots of 404s)
        if r.status == 404:
            dirbust_rows.append((r.host, tsec))

        # content signatures
        if _RE_SQLI.search(path_lower):
            sqli_hits[r.host] += 1
        if _RE_LFI.search(path_lower):
            lfi_hits[r.host] += 1
        if _RE_RFI.search(r.path):
            rfi_hits[r.host] += 1
        if r.user_agent and _RE_SHELLSHOCK.search(r.user_agent):
            shellshock_hits[r.host] += 1
        if (not r.user_agent) or _BAD_UA_HINTS.search(r.user_agent):
            badua_hits[r.host] += 1

    findings: List[Finding] = []

    # --- rate-windowed dirbusting ---
    dirbust_buckets = bucketize_per_host(dirbust_rows, cfg.window_seconds)
    for host, buckets in dirbust_buckets.items():
        worst = max(buckets.values()) if buckets else 0
        if worst >= cfg.dirbust_threshold:
            sev = "med" if worst < 50 else "high"
            findings.append(Finding(
                type="DIRBUST",
                host=host,
                count=worst,
                severity=sev,
                evidence=f"peak {worst} x 404 within {cfg.window_seconds}s"
            ))

    # --- rate-windowed brute force ---
    brute_buckets = bucketize_per_host(brute_rows, cfg.window_seconds)
    for host, buckets in brute_buckets.items():
        worst = max(buckets.values()) if buckets else 0
        if worst >= cfg.bruteforce_threshold:
            sev = "med" if worst < 20 else "high"
            findings.append(Finding(
                type="BRUTE_FORCE",
                host=host,
                count=worst,
                severity=sev,
                evidence=f"peak {worst} x 401 on login paths within {cfg.window_seconds}s"
            ))

    # simple signature severities
    def add_sig(sig_counts: Dict[str, int], ftype: str):
        for host, c in sig_counts.items():
            findings.append(Finding(
                type=ftype, host=host, count=c,
                severity=("low" if c == 1 else "med" if c < 10 else "high"),
                evidence=f"{c} matching pattern(s)"
            ))

    add_sig(sqli_hits, "SQLI")
    add_sig(lfi_hits, "LFI")
    add_sig(rfi_hits, "RFI")
    add_sig(shellshock_hits, "SHELLSHOCK")
    add_sig(badua_hits, "UA_ABUSE")

    severity_rank = {"high": 2, "med": 1, "low": 0}
    findings.sort(key=lambda f: (severity_rank[f.severity], f.count), reverse=True)
    return findings
