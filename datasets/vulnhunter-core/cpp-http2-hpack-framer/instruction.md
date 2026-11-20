# HTTP/2 Connection Framer & HPACK Codec Maintenance Review

You are performing a routine defensive code review and RFC 9113 / RFC 7541 conformance hardening pass on the internal C++20 HTTP/2 server framing and HPACK header compression library `h2_framer` in `/app` (`Makefile`, `include/`, `src/`, and `tests/`).

The library decodes canonical HPACK Huffman strings, maintains the static and dynamic header tables, parses HTTP/2 frames (`HEADERS`, `CONTINUATION`, `DATA`, `SETTINGS`, `WINDOW_UPDATE`, `PING`, `RST_STREAM`), validates pseudo-headers and trailers, and enforces stream/connection flow-control windows before delivering completed requests to the application layer.

Review the codebase end-to-end for memory ownership safety across dynamic-table updates, integer and bit-stream bounds during HPACK decoding, connection framing state-machine invariants, request/trailer field validation, and signed/unsigned flow-control arithmetic, then complete the following deliverables in `/app`:

1. **Technical Review Report (`/app/report.json`)**
   Create `/app/report.json` documenting your findings:
   - `"files"`: array of relative file paths under `/app` where primary issues were identified and updated (for example `["src/hpack_codec.cpp", "src/h2_connection.cpp", ...]`).
   - `"findings"`: array of at least 3 detailed descriptions explaining the root causes and RFC 9113 / RFC 7541 invariants addressed.
   - `"summary"`: concise overall summary of your changes.

2. **Framer & Codec Hardening (`/app/include/`, `/app/src/`)**
   Update the C++20 implementation while preserving public header interfaces, sanitizer flags (`-fsanitize=address,undefined`) in `Makefile`, and valid HTTP/2 multiplexed request/trailer handling.

3. **Regression Test Suite (`/app/tests/smoke_test.cpp`)**
   Add targeted regression tests to `/app/tests/smoke_test.cpp` covering the scenarios identified in your review, and ensure `make clean all test` compiles cleanly and passes with zero AddressSanitizer or UndefinedBehaviorSanitizer diagnostics.
