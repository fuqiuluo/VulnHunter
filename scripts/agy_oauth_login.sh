#!/usr/bin/env bash
# Perform one-time Antigravity CLI Google OAuth login into an isolated file-backed
# profile so Docker evaluation containers can reuse your local subscription quota
# without needing a host D-Bus / GNOME Keyring daemon.
set -euo pipefail

AGY_BIN="${AGY_BIN:-$HOME/.local/bin/agy}"
OAUTH_HOME="${AGY_OAUTH_HOME:-$HOME/.agy-eval}"
TOKEN_FILE="$OAUTH_HOME/.gemini/antigravity-cli/antigravity-oauth-token"

if [[ ! -x "$AGY_BIN" ]]; then
    if command -v agy >/dev/null 2>&1; then
        AGY_BIN="$(command -v agy)"
    else
        echo "Error: agy CLI binary not found (checked $AGY_BIN and PATH)." >&2
        exit 1
    fi
fi

mkdir -p "$OAUTH_HOME"
chmod 700 "$OAUTH_HOME"

echo "[1/2] Starting official Antigravity OAuth login (file-backed profile: $OAUTH_HOME)..."
echo "      Please complete Google sign-in in your browser."
HOME="$OAUTH_HOME" DBUS_SESSION_BUS_ADDRESS="unix:path=/nonexistent" "$AGY_BIN" acp --login

if [[ ! -f "$TOKEN_FILE" ]]; then
    echo "Error: Expected fallback OAuth token file was not created at $TOKEN_FILE" >&2
    exit 1
fi
chmod 600 "$TOKEN_FILE"

echo "[2/2] Verifying headless file-backed OAuth login (without keyring)..."
HOME="$OAUTH_HOME" DBUS_SESSION_BUS_ADDRESS="unix:path=/nonexistent" "$AGY_BIN" models </dev/null

echo ""
echo "Success! File-backed OAuth profile is ready at: $OAUTH_HOME"
echo "You can now run Harbor with harnesses.custom_antigravity:CustomAntigravityCli (oauth_home: $OAUTH_HOME)."
