#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
cd "$APP_DIR"

# Implement the reference gold solution here so `harbor run -a oracle` scores 1.0
echo '{"file": "main.c", "function": "main", "summary": "Reference analysis"}' > "$APP_DIR/report.json"
