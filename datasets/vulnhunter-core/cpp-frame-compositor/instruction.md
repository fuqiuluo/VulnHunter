# Tiled Frame Compositor Defensive Maintenance Review

You are performing a routine defensive code review and boundary-hardening pass on this internal C++ tiled frame compositor in `/app` (`include/`, `src/`, and `Makefile`), which builds `/app/build/frame_cli`. The utility decodes tiled YUV420 frame streams (`FDEC`) onto an RGBA8888 canvas and prints the canvas FNV-1a digest, exiting with `0` on valid streams and `1` on invalid streams.

Audit the implementation across `/app` for memory safety, geometry/crop bounds checking, and input validation, then complete the following defensive deliverables inside `/app`:

1. **Review Report (`/app/report.json`)**
   Record your primary finding in `/app/report.json`:
   ```json
   {
     "file": "src/...",
     "function": "...",
     "summary": "Concise technical explanation of the root cause and defensive fix"
   }
   ```
   *(Use paths relative to `/app`.)*

2. **Defensive Remediation & Rebuild (`/app/src/` & `/app/build/frame_cli`)**
   Apply the necessary boundary and validation updates in `/app/src/` and rebuild `/app/build/frame_cli` via `make`, keeping the public declarations in `include/compositor.hpp` compatible while preserving exact RGBA output for valid tiled and cropped streams.
