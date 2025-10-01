import argparse
from pathlib import Path
from datetime import datetime

from .parser import parse_file
from .config import load_config
from .detectors import analyze
from .report import write_csv, write_markdown
from .report_html import write_html
from .stats import compute_top_talkers

def main():
    ap = argparse.ArgumentParser(description="Web Log Threat Hunter")
    ap.add_argument("--input", "-i", required=True, help="Path to Apache access.log")
    ap.add_argument("--report-dir", "-o", default="reports", help="Directory for CSV/Markdown/HTML reports")
    ap.add_argument("--config", "-c", help="Path to YAML or JSON config")
    ap.add_argument("--dirbust-threshold", type=int, help="Min 404s per host within window to flag dirbusting")
    ap.add_argument("--bruteforce-threshold", type=int, help="Min 401s on login paths within window to flag brute force")
    ap.add_argument("--window-seconds", type=int, help="Time window size for rate checks (default 60)")
    ap.add_argument("--top-talkers", type=int, default=5, help="How many top talkers to show in reports")
    args = ap.parse_args()

    cfg = load_config(args.config)
    # CLI overrides
    if args.dirbust_threshold is not None:
        cfg = type(cfg)(**{**cfg.__dict__, "dirbust_threshold": args.dirbust_threshold})
    if args.bruteforce_threshold is not None:
        cfg = type(cfg)(**{**cfg.__dict__, "bruteforce_threshold": args.bruteforce_threshold})
    if args.window_seconds is not None:
        cfg = type(cfg)(**{**cfg.__dict__, "window_seconds": args.window_seconds})

    input_path = Path(args.input)
    records = list(parse_file(str(input_path)))
    findings = analyze(records, cfg=cfg)
    top = compute_top_talkers(records, limit=args.top_talkers)

    stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    outdir = Path(args.report_dir)
    csv_path  = outdir / f"webloghunter_{stamp}.csv"
    md_path   = outdir / f"webloghunter_{stamp}.md"
    html_path = outdir / f"webloghunter_{stamp}.html"

    write_csv(findings, csv_path)
    write_markdown(findings, md_path, meta=(str(input_path), stamp), top_talkers=top)
    write_html(findings, html_path, meta=(str(input_path), stamp), top_talkers=top)

    print(f"Parsed {len(records)} lines from {input_path}")
    print(f"Findings: {len(findings)}")
    print(f"Wrote: {csv_path}")
    print(f"Wrote: {md_path}")
    print(f"Wrote: {html_path}")

if __name__ == "__main__":
    main()
