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

# 2. Generate depth-4 verification bundle (/app/sample.bin)
python3 - "$APP_DIR/sample.bin" <<'PY'
import struct
import sys

out_path = sys.argv[1]
csb_magic = 0x43534231

def pkt7(opc, *words):
    hdr = 0x70000000 | ((opc & 0x3F) << 16) | (len(words) & 0xFFFF)
    return [hdr, *words]

# State Group slice executed at stream_depth == 4 when triggered from IB3
sg0 = pkt7(0x38, 0x00004000, 0x00000000, 0x0002BEEF)
ib3 = pkt7(0x0A, (0x01 << 16) | 0, 0x00103000, len(sg0)) + pkt7(0x2A, 6)
ib2 = pkt7(0x02, 0x00102000, len(ib3))
ib1 = pkt7(0x02, 0x00101000, len(ib2))

segs = [
    (0x00100000, ib1),
    (0x00101000, ib2),
    (0x00102000, ib3),
    (0x00103000, sg0),
]

parts = [struct.pack("<IIIIII", csb_magic, 77, 0x00100000, len(ib1), len(segs), 0)]
for va, words in segs:
    raw = struct.pack(f"<{len(words)}I", *words)
    parts.append(struct.pack("<II", va, len(raw)))
    parts.append(raw)

with open(out_path, "wb") as f:
    f.write(b"".join(parts))
PY

# 3. Disassemble firmware, widen depth bitmask in @sub_127a to 0x0007, and reassemble
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
