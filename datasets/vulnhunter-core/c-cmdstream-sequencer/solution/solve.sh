#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
cd "$APP_DIR"

make -C "$APP_DIR" clean all

# 1. Write technical analysis report
cat > "$APP_DIR/report.json" <<'EOF'
{
  "file": "firmware/sequencer.fw",
  "function": "sub_127a",
  "summary": "Ring-0 stream depth check in @sub_127a masks CREG_STREAM_STATUS with 0x0003 instead of 0x0007, wrapping depth 4 (IB1 -> IB2 -> IB3 -> StateGroup) to 0."
}
EOF

# 2. Disassemble firmware, widen depth bitmask in @sub_127a to 0x0007, and reassemble
TMP_UC="$(mktemp)"
trap 'rm -f "$TMP_UC"' EXIT

"$APP_DIR/build/sqe_disasm" "$APP_DIR/firmware/sequencer.fw" "$TMP_UC"

python3 - "$TMP_UC" <<'PY'
import sys

uc_path = sys.argv[1]
with open(uc_path, "r", encoding="utf-8") as f:
    text = f.read()

marker = "@sub_127a:"
idx = text.find(marker)
assert idx != -1, "Target routine @sub_127a not found"

end_idx = text.find("@L_1284:", idx)
assert end_idx != -1, "Target block end not found"

block = text[idx:end_idx]
assert "andi     $r02, $r18, 0x0003" in block, "Expected mask instruction not found"
patched_block = block.replace("andi     $r02, $r18, 0x0003", "andi     $r02, $r18, 0x0007", 1)

text = text[:idx] + patched_block + text[end_idx:]
with open(uc_path, "w", encoding="utf-8") as f:
    f.write(text)
PY

"$APP_DIR/build/sqe_asm" "$TMP_UC" "$APP_DIR/firmware/sequencer.fw"
