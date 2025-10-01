from __future__ import annotations
from typing import List, Tuple, Optional
from pathlib import Path
import csv

from .detectors import Finding
from .enrich import enrich_ip

def write_csv(findings: List[Finding], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["type", "host", "count", "severity", "evidence"])
        for fnd in findings:
            w.writerow([fnd.type, fnd.host, fnd.count, fnd.severity, fnd.evidence])

def write_markdown(findings: List[Finding], out_path: Path, meta: Tuple[str, str],
                   top_talkers: Optional[List[Tuple[str,int,int,int]]] = None) -> None:
    input_path, generated_at = meta
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        f.write("# Web Log Threat Hunter — Findings\n\n")
        f.write(f"- **Input**: `{input_path}`\n")
        f.write(f"- **Generated**: `{generated_at}`\n\n")

        if top_talkers:
            f.write("## Top Talkers\n\n")
            f.write("| Host | Total | 4xx | 5xx | Enrichment |\n")
            f.write("|---|---:|---:|---:|---|\n")
            for host, total, fourxx, fivexx in top_talkers:
                meta = enrich_ip(host) or {}
                enr = f"{meta.get('cc','-')} {meta.get('city','')}".strip()
                f.write(f"| `{host}` | {total} | {fourxx} | {fivexx} | {enr or '-'} |\n")
            f.write("\n")

        if not findings:
            f.write("> No suspicious patterns detected with default heuristics.\n")
            return

        f.write("## Summary\n\n")
        f.write("| Type | Host | Count | Severity | Evidence |\n")
        f.write("|---|---:|---:|---|---|\n")
        for fnd in findings:
            f.write(f"| {fnd.type} | `{fnd.host}` | {fnd.count} | {fnd.severity} | {fnd.evidence} |\n")

        f.write("\n## Narrative by Category\n")
        by_type = {}
        for fnd in findings:
            by_type.setdefault(fnd.type, []).append(fnd)
        for t, arr in by_type.items():
            f.write(f"\n### {t}\n")
            for fnd in arr:
                f.write(f"- `{fnd.host}` → {fnd.count} events · {fnd.severity} · {fnd.evidence}\n")
