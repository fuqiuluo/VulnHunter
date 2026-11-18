#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
cd "$APP_DIR"

# Placeholder stub; answer key and trigger sample intentionally omitted
cat > "$APP_DIR/report.json" <<'EOF'
{
  "file": "<conceptual_placeholder>",
  "function": "<conceptual_placeholder>",
  "summary": "<conceptual_placeholder>"
}
EOF
