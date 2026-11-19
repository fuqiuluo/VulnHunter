#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
cd "$APP_DIR"

# 1. Write analysis report
cat > "$APP_DIR/report.json" <<'EOF'
{
  "file": "native/base64_avx512.cpp",
  "function": "decode_block_avx512_vbmi",
  "summary": "In the 1..63 byte AVX-512 VBMI tail handler, short padded tails (length < 4 such as '=' or '==') shift in_mask to zero and underflow output_size = ((length * 3) >> 2) - pad to -1, causing _bzhi_u64 to produce an all-ones 64-bit opmask and _mm512_mask_storeu_epi8 to overwrite 62 bytes past the destination buffer."
}
EOF

# 2. Apply the JDK-8393212 tail length guard in native/base64_avx512.cpp
python3 - "$APP_DIR/native/base64_avx512.cpp" <<'PY'
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    src = f.read()

target = "    // Process remaining 1 to 63 tail bytes\n    if (length > 0) {"
replacement = """    // Process remaining tail bytes; tails shorter than one 4-byte block fall back to scalar Java
    if (length >= 4) {"""

assert target in src, "Expected tail handler block not found"
src = src.replace(target, replacement, 1)

target_pad = """        if (src_ptr[sp + length - 1] == '=') {
            pad++;"""
replacement_pad = """        if (src_ptr[sp + length - 1] == '=') {
            if ((length & 3) != 0) {
                return dp - start_dp;
            }
            pad++;"""

assert target_pad in src, "Expected padding block not found"
src = src.replace(target_pad, replacement_pad, 1)

with open(path, "w", encoding="utf-8") as f:
    f.write(src)
PY

make -C "$APP_DIR" clean all
