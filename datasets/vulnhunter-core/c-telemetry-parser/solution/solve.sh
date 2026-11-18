#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
cd "$APP_DIR"

# 1. Write analysis report
cat > "$APP_DIR/report.json" <<'EOF'
{
  "file": "src/pkt_parser.c",
  "function": "pkt_parse_bundle",
  "summary": "16-bit integer truncation in alloc_bytes (uint16_t) when PKT_META_SIZE + chunk_count * chunk_size >= 65536 causes undersized malloc followed by heap-based buffer overflow."
}
EOF

# 2. Generate reproduction sample (chunk_count=1024, chunk_size=256 => payload=262144)
python3 - "$APP_DIR/sample.bin" <<'PY'
import struct
import sys

out_path = sys.argv[1]
magic = 0x5648504B
session_id = 42
flags = 0
chunk_count = 1024
chunk_size = 256

parts = [struct.pack("<IIIHH", magic, session_id, flags, chunk_count, chunk_size)]
payload_chunk = b"A" * chunk_size
for seq in range(chunk_count):
    parts.append(struct.pack("<H", seq))
    parts.append(payload_chunk)

with open(out_path, "wb") as f:
    f.write(b"".join(parts))
PY

# 3. Update src/pkt_parser.c to use size_t and safe bounds checks
python3 - "$APP_DIR/src/pkt_parser.c" <<'PY'
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    src = f.read()

target = "uint16_t alloc_bytes = (uint16_t)(PKT_META_SIZE + chunk_count * chunk_size);"
replacement = """if (expected_payload > SIZE_MAX - PKT_META_SIZE) {
        return PKT_ERR_OVERFLOW;
    }
    size_t alloc_bytes = (size_t)PKT_META_SIZE + expected_payload;"""

assert target in src, "Expected allocation line not found"
src = src.replace(target, replacement, 1)

with open(path, "w", encoding="utf-8") as f:
    f.write(src)
PY

make -C "$APP_DIR" clean all
