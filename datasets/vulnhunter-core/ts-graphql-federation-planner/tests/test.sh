#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${APP_DIR:-/app}"
REWARD_DIR="${REWARD_DIR:-/logs/verifier}"
mkdir -p "$REWARD_DIR"

if python3 "$SCRIPT_DIR/verify.py" --app-dir "$APP_DIR" --reward-dir "$REWARD_DIR"; then
  printf '1.0\n' > "$REWARD_DIR/reward.txt"
else
  printf '0.0\n' > "$REWARD_DIR/reward.txt"
fi
exit 0
