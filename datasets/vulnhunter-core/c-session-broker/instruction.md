# Session Negotiation Broker Review

Examine the C project in `/app` (`include/`, `src/`, and `Makefile`), which builds `/app/build/broker_cli`. The utility processes binary session-handshake streams, expands the configured login command template, and dispatches session authorization checks, exiting with `0` on accepted sessions and `1` on rejected inputs.

Analyze the implementation across `/app` on your own and complete the following inside `/app`:

1. **Analysis Report (`/app/report.json`)**
   Record your technical findings in `/app/report.json`:
   ```json
   {
     "file": "<conceptual_placeholder>",
     "function": "<conceptual_placeholder>",
     "summary": "<conceptual_placeholder>"
   }
   ```

2. **Verification Sample (`/app/sample.bin`)**
   Provide a binary handshake stream `/app/sample.bin` (at most 512 KiB) exercising the critical edge cases identified in your analysis.

3. **Implementation Update (`/app/src/` & `/app/build/broker_cli`)**
   Apply the necessary validation updates under `/app/src/` and rebuild `/app/build/broker_cli` via `make`, keeping the public declarations in `include/session_broker.h` compatible.
