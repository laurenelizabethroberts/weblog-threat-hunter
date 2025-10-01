from __future__ import annotations
from typing import Dict, Optional

# Demo-only mappings for documentation/test networks (RFC 5737)
_FAKE_GEO = {
    "203.0.113.": {"cc": "EX", "city": "Exampleville"},
    "198.51.100.": {"cc": "EX", "city": "Example City"},
    "192.0.2.": {"cc": "EX", "city": "Demo Town"},
    "127.0.0.": {"cc": "LO", "city": "Loopback"},
}

def enrich_ip(ip: str) -> Optional[Dict[str, str]]:
    for prefix, meta in _FAKE_GEO.items():
        if ip.startswith(prefix):
            return {"ip": ip, **meta}
    return None  # unknown; in a real system, call a provider here
