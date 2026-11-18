#!/usr/bin/env bash
set -uo pipefail

REWARD_DIR="${REWARD_DIR:-/logs/verifier}"
APP_DIR="${APP_DIR:-/app}"
mkdir -p "$REWARD_DIR"

# Replace with deterministic verification checks against "$APP_DIR"
if [ -f "$APP_DIR/report.json" ]; then
    echo "1.0" > "$REWARD_DIR/reward.txt"
else
    echo "0.0" > "$REWARD_DIR/reward.txt"
fi
