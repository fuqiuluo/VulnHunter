# Tiled Frame Compositor Review

Examine the C++ project in `/app` (`include/`, `src/`, and `Makefile`), which builds `/app/build/frame_cli`. The utility decodes tiled YUV420 frame streams (`FDEC`) onto an RGBA8888 canvas and prints the canvas FNV-1a digest, exiting with `0` on valid streams and `1` on invalid streams.

Analyze the implementation across `/app` thoroughly on your own and complete the following inside `/app`:

1. **Analysis Report (`/app/report.json`)**
   Record your technical findings in `/app/report.json`:
   ```json
   {
     "file": "src/...",
     "function": "...",
     "summary": "Concise technical explanation of your analysis"
   }
   ```
   *(Use paths relative to `/app`.)*

2. **Test Sample (`/app/sample.bin`)**
   Generate a binary `FDEC` stream `/app/sample.bin` (at most 512 KiB) that demonstrates the critical edge case identified in your analysis when passed to the original `/app/build/frame_cli`.

3. **Implementation Update (`/app/src/` & `/app/build/frame_cli`)**
   Apply the necessary boundary and validation updates in `/app/src/` and rebuild `/app/build/frame_cli` via `make`, keeping the public declarations in `include/compositor.hpp` compatible.
