# Session Negotiation Broker Review

Examine the C project in `/app` (`include/`, `src/`, and `Makefile`), which builds `/app/build/broker_cli`. The utility processes binary session-handshake streams (`SBRK`), expands the configured login command template, and dispatches session authorization checks, exiting with `0` on accepted sessions and `1` on rejected inputs.

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
   Generate a binary `SBRK` handshake stream `/app/sample.bin` (at most 512 KiB) that demonstrates the critical edge case identified in your analysis when executed against the original `/app/build/broker_cli`.

3. **Implementation Update (`/app/src/` & `/app/build/broker_cli`)**
   Apply the necessary validation updates under `/app/src/` (and headers if needed) and rebuild `/app/build/broker_cli` via `make`, keeping all public type definitions and function signatures in `include/session_broker.h` compatible.
