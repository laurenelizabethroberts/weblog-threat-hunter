#!/usr/bin/env bash
set -euo pipefail

# Find newest HTML report
LATEST=$(ls -t reports/webloghunter_*.html | head -n1)
OUT="assets/report_preview.png"

# Some distros call it chromium, others google-chrome-stable
BROWSER="${BROWSER_BIN:-chromium}"

# Use headless mode to capture a screenshot
# --window-size controls the viewport (WxH) for nicer layout
$BROWSER --headless=new --disable-gpu \
  --screenshot="$OUT" \
  --window-size=1400,1000 \
  "file://$(pwd)/$LATEST"

echo "Saved screenshot to $OUT"
