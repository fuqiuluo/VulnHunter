#!/usr/bin/env bash
# Load .env, sync extra allowed URLs/hosts into task.toml, and invoke harbor.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT_DIR/.env}"
export PYTHONPATH="${ROOT_DIR}${PYTHONPATH:+:$PYTHONPATH}"
if [[ -d "$ROOT_DIR/.venv/bin" ]]; then
    export PATH="$ROOT_DIR/.venv/bin:$PATH"
fi

if [[ -f "$ENV_FILE" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
fi

python3 "$ROOT_DIR/scripts/network_policy.py" --env-file "$ENV_FILE"

exec harbor "$@"
