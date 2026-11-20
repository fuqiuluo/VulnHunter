# MVCC Serializable Snapshot Isolation Engine Review

You are performing a routine formal isolation review and maintenance pass on the internal Rust storage crate `mvcc_ssi` in `/app` (`Cargo.toml`, `src/`, and `tests/`). The crate implements `SsiEngine`, an embedded multi-version concurrency control (MVCC) ordered key-value and range engine providing Serializable Snapshot Isolation (SSI) with `rw-antidependency` tracking, point and range `SIRead` predicate locks, nested transaction savepoints (`savepoint` / `rollback_to_savepoint`), and multi-version garbage collection (`vacuum`).

Review the crate end-to-end against its documented serializability, snapshot visibility, savepoint rollback, and reclamation invariants across concurrent transaction schedules, then complete the following deliverables inside `/app`:

1. **Review Report (`/app/report.json`)**
   Create `/app/report.json` documenting the consistency and isolation issues identified during your review:
   - `"files"`: array of relative file paths under `/app` where the primary issues reside (for example `["src/version_store.rs", "src/predicate.rs", ...]`).
   - `"findings"`: array of at least 2 concise descriptions explaining each distinct root cause and invariant violation discovered.
   - `"summary"`: overall summary of your remediation approach.

2. **Crate Remediation & Regression Tests**
   - Update the Rust implementation under `/app/src/` so all safe public operations enforce strict serializable snapshot isolation without introducing false-positive aborts on valid concurrent or serializable schedules, preserve exact snapshot visibility across active horizons and tombstones during `vacuum()`, and maintain multi-module architecture and public signatures (`SsiEngine`, `ScheduleStep`, `StepResult`, `VacuumStats`, `IsolationError`, `TxId`, `SeqNo`, `SavepointId`, `TxStatus`, `KeyRange`).
   - Expand `/app/tests/smoke.rs` (or add integration test files under `/app/tests/`) with deterministic regression tests covering the concurrency, savepoint, predicate-range, and garbage-collection scenarios you addressed, and ensure `cargo test --offline` passes cleanly with zero external crate dependencies.
