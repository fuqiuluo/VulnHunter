# Multiplexed Stream Transport Engine Maintenance Review

You are conducting a routine defensive code review and protocol-conformance maintenance pass on the internal C++20 multiplexed stream transport engine in `/app` (`include/`, `src/`, and `Makefile`), which compiles `/app/build/mux_cli`.

The engine processes binary `QMUX` frame scripts (`STREAM`, `RESET_STREAM`, `STOP_SENDING`, `MAX_DATA`, `MAX_STREAMS`, `STREAM_DATA_BLOCKED`, `TICK_TIMER`, and `CONN_CLOSE`) across bidirectional and unidirectional client/server streams, performing byte-interval reassembly, connection and per-stream credit accounting, application stream admission control, and drain timer management. On valid sessions, `/app/build/mux_cli <script_path>` prints deterministic session counters and the 64-bit FNV-1a digest of completed streams with exit status `0`; on protocol or state violations, it prints an error diagnostic and exits with status `1`.

Review the codebase across `/app` for RFC 9000 stream lifecycle invariants, interval reassembly accuracy, credit and range accounting, and object lifetime management, then provide the following deliverables in `/app`:

1. **Maintenance Report (`/app/report.json`)**
   Record your review results in `/app/report.json` using paths relative to `/app`:
   ```json
   {
     "files": [
       "src/..."
     ],
     "findings": [
       "..."
     ],
     "summary": "Concise technical summary of root causes and defensive updates"
   }
   ```

2. **In-Place C++ Remediation & Rebuild (`/app` & `/app/build/mux_cli`)**
   Update the C++ implementation in `/app` and rebuild `/app/build/mux_cli` via `make` while preserving exact CLI behavior and FNV-1a stream digests for valid multiplexed sessions.
