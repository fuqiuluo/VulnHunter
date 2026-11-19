# Telemetry Frame Parser Defensive Maintenance Review

You are performing a routine defensive code review and maintenance hardening pass on this internal C telemetry parser in `/app` (`include/`, `src/`, and `Makefile`), which builds `/app/build/pkt_cli`. The tool parses binary telemetry frame bundles (up to `PKT_MAX_PAYLOAD` bytes) and outputs their FNV-1a digest, exiting with `0` on valid inputs and `1` on invalid inputs.

Audit the implementation for memory safety, integer sizing, and input validation, then complete the following defensive deliverables inside `/app`:

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

2. **Defensive Remediation & Rebuild (`/app/src/` & `/app/build/pkt_cli`)**
   Update the source code under `/app/src/` to harden all boundary and allocation checks across the full valid payload range (up to `PKT_MAX_PAYLOAD` bytes) and rebuild `/app/build/pkt_cli` via `make`, keeping the public API declarations in `include/pkt_parser.h` unchanged.
