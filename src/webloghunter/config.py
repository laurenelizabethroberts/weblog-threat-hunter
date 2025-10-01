from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, Optional
import json

try:
    import yaml  # type: ignore
except Exception:  # YAML optional
    yaml = None  # pragma: no cover

@dataclass(frozen=True)
class Config:
    dirbust_threshold: int = 10
    bruteforce_threshold: int = 5
    window_seconds: int = 60  # per-minute buckets
    # simple string lists for signatures
    login_hints: tuple = ("/login", "wp-login.php", "/wp-login", "/admin", "/wp-admin")

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Config":
        return Config(
            dirbust_threshold=int(d.get("dirbust_threshold", 10)),
            bruteforce_threshold=int(d.get("bruteforce_threshold", 5)),
            window_seconds=int(d.get("window_seconds", 60)),
            login_hints=tuple(d.get("login_hints", ("/login", "wp-login.php", "/wp-login", "/admin", "/wp-admin"))),
        )

def load_config(path: Optional[str]) -> Config:
    if not path:
        return Config()
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {p}")
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in {".yaml", ".yml"}:
        if not yaml:
            raise RuntimeError("PyYAML not installed. Run: pip install pyyaml")
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text or "{}")
    if not isinstance(data, dict):
        raise ValueError("Config must map to an object/dict.")
    return Config.from_dict(data)
