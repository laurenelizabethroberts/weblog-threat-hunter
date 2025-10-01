from __future__ import annotations
from typing import List, Tuple, Optional
from pathlib import Path
from html import escape

from .detectors import Finding
from .enrich import enrich_ip

CSS = """
body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:24px}
h1{font-size:24px;margin-bottom:8px}
.meta{color:#555;margin-bottom:20px}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:8px}
th{background:#f5f5f5;text-align:left}
.badge{padding:2px 8px;border-radius:12px;font-size:12px;display:inline-block}
.badge.low{background:#e6f4ea}
.badge.med{background:#fff4e5}
.badge.high{background:#fdecea}
.code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#f6f8fa;padding:0 6px;border-radius:6px}
.section{margin-top:24px}
"""

def write_html(findings: List[Finding], out_path: Path, meta: Tuple[str, str],
               top_talkers: Optional[List[Tuple[str,int,int,int]]] = None) -> None:
    inp, generated = meta
    out_path.parent.mkdir(parents=True, exist_ok=True)

    def sev_badge(s: str) -> str:
        return f'<span class="badge {escape(s)}">{escape(s.upper())}</span>'

    rows = []
    for f in findings:
        rows.append(
            "<tr>"
            f"<td>{escape(f.type)}</td>"
            f"<td><span class='code'>{escape(f.host)}</span></td>"
            f"<td style='text-align:right'>{f.count}</td>"
            f"<td>{sev_badge(f.severity)}</td>"
            f"<td>{escape(f.evidence)}</td>"
            "</tr>"
        )
    table = "\n".join(rows) if rows else (
        "<tr><td colspan='5'><em>No suspicious patterns with default heuristics.</em></td></tr>"
    )

    html = f"""<!doctype html>
<html lang="en"><meta charset="utf-8"><title>Web Log Threat Hunter — Findings</title>
<style>{CSS}</style>
<body>
  <h1>Web Log Threat Hunter — Findings</h1>
  <div class="meta">
    <div><strong>Input:</strong> <span class="code">{escape(inp)}</span></div>
    <div><strong>Generated:</strong> <span class="code">{escape(generated)}</span></div>
  </div>
  <div class="section">
    <h2>Top Talkers</h2>
    <table>
      <thead><tr><th>Host</th><th>Total</th><th>4xx</th><th>5xx</th><th>Enrichment</th></tr></thead>
      <tbody>
        {render_top_talkers(top_talkers)}
      </tbody>
    </table>
  </div>
  <div class="section">
    <h2>Summary</h2>
    <table>
      <thead><tr><th>Type</th><th>Host</th><th>Count</th><th>Severity</th><th>Evidence</th></tr></thead>
      <tbody>
        {table}
      </tbody>
    </table>
  </div>
</body></html>
"""
    out_path.write_text(html, encoding="utf-8")

def render_top_talkers(rows: Optional[List[Tuple[str,int,int,int]]]) -> str:
    if not rows:
        return "<tr><td colspan='5'><em>No data.</em></td></tr>"
    out = []
    for host, total, fourxx, fivexx in rows:
        meta = enrich_ip(host) or {}
        enr = (meta.get("cc","-") + " " + meta.get("city","")).strip()
        out.append(
            "<tr>"
            f"<td><span class='code'>{host}</span></td>"
            f"<td style='text-align:right'>{total}</td>"
            f"<td style='text-align:right'>{fourxx}</td>"
            f"<td style='text-align:right'>{fivexx}</td>"
            f"<td>{enr or '-'}</td>"
            "</tr>"
        )
    return "\n".join(out)
