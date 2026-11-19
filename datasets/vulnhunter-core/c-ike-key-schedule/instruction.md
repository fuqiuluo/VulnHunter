# Key-Exchange State Engine Defensive Maintenance Review

You are performing a routine defensive code review and protocol-hardening pass on this internal C11 key-exchange and security association (SA) engine in `/app` (`include/`, `src/`, and `Makefile`), which builds `/app/build/kex_cli`. Running `/app/build/kex_cli <trace.bin>` executes a binary `KEX1` session trace across `KEX_SA_INIT`, optional and mandatory hybrid `KEX_INTERMEDIATE` exchanges, `KEX_AUTH`, encrypted fragmentation, Child SA rekeying, and `INFORMATIONAL` session control, printing probe telemetry and final digests while exiting with `0` on valid traces and `1` on rejected traces.

Audit the implementation across `/app` for cryptographic key-schedule consistency, wire framing and fragment reassembly invariants, handshake state transitions, and SA lifecycle management, then complete the following defensive deliverables inside `/app`:

1. **Review Report (`/app/report.json`)**
   Record your findings and remediations in `/app/report.json`:
   ```json
   {
     "files": [
       "src/..."
     ],
     "findings": [
       {
         "file": "src/...",
         "function": "...",
         "description": "Concise technical explanation of the root cause and fix"
       }
     ],
     "summary": "Overall technical summary of the protocol and lifecycle remediations applied"
   }
   ```
   *(Use paths relative to `/app`.)*

2. **Defensive Remediation & Rebuild (`/app/src/` & `/app/build/kex_cli`)**
   Apply the necessary source updates in `/app/src/` and rebuild `/app/build/kex_cli` via `make`, keeping public type definitions in `include/` and CLI trace interfaces compatible while preserving deterministic digests across compliant classic, hybrid, fragmented, and concurrent-rekey sessions.
