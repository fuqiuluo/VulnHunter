#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REWARD_DIR="${REWARD_DIR:-/logs/verifier}"
mkdir -p "$REWARD_DIR"

if PYTHONDONTWRITEBYTECODE=1 python3 -B "$SCRIPT_DIR/verify.py" --reward-dir "$REWARD_DIR"; then
    echo "1.0" > "$REWARD_DIR/reward.txt"
else
    echo "0.0" > "$REWARD_DIR/reward.txt"
fi
