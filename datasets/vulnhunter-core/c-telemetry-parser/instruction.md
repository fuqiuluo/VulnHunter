# Telemetry Frame Parser Review

Examine the C project in `/app` (`include/`, `src/`, and `Makefile`), which builds `/app/build/pkt_cli`. The tool parses binary telemetry frame bundles (up to `PKT_MAX_PAYLOAD` bytes) and outputs their FNV-1a digest, exiting with `0` on valid inputs and `1` on invalid inputs.

Analyze the implementation thoroughly on your own and complete the following inside `/app`:

1. **Analysis Report (`/app/report.json`)**
   Record your findings in `/app/report.json` using this schema:
   ```json
   {
     "file": "src/...",
     "function": "...",
     "summary": "Concise technical explanation of your analysis"
   }
   ```
   *(Use paths relative to `/app`.)*

2. **Test Sample (`/app/sample.bin`)**
   Generate a binary input file `/app/sample.bin` (at most 512 KiB) that demonstrates the critical case identified in your analysis when run against the original `pkt_cli`.

3. **Implementation Update (`/app/src/` & `/app/build/pkt_cli`)**
   Update the source code under `/app/src/` as needed and rebuild `/app/build/pkt_cli` via `make`, keeping the public API declarations in `include/pkt_parser.h` unchanged.
