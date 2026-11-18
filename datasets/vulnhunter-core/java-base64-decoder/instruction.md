# Base64 Codec Module Review

Examine the Java and native C++ project in `/app` (`src/codec/`, `native/`, and `Makefile`), which builds `/app/build/libb64avx512.so` and `/app/build/b64_cli`. The module implements standard, URL-safe, and MIME Base64 encoding and decoding with an x86-64 AVX-512 VBMI JNI fast path, exiting with `0` on valid Base64 input and `1` on invalid Base64 input.

Analyze the implementation across both the Java and native layers thoroughly on your own and complete the following inside `/app`:

1. **Analysis Report (`/app/report.json`)**
   Record your technical findings in `/app/report.json` using this schema:
   ```json
   {
     "file": "relative/path/from/app",
     "function": "...",
     "summary": "Concise technical explanation of your analysis"
   }
   ```

2. **Test Sample (`/app/sample.txt`)**
   Save an ASCII Base64 test input at `/app/sample.txt` (at most 64 KiB) that demonstrates the critical edge case identified in your analysis when passed to the original `/app/build/b64_cli`.

3. **Implementation Update (`/app/` & `/app/build/b64_cli`)**
   Apply the necessary code changes while keeping AVX-512 VBMI block acceleration active and preserving `codec.Base64Codec` public API compatibility with `java.util.Base64`, then rebuild via `make`.
