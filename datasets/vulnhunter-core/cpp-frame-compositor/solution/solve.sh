#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
cd "$APP_DIR"

# Reference placeholder report
cat > "$APP_DIR/report.json" <<'EOF'
{
  "file": "src/compositor.cpp",
  "function": "FrameCompositor::on_tile_received",
  "summary": "<conceptual_placeholder>"
}
EOF
