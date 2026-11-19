# Chunked Deque Crate Defensive Maintenance Review

You are performing a routine defensive code review and maintenance hardening pass on the internal Rust collection crate `chunked_deque` in `/app` (`Cargo.toml`, `src/`, and `tests/`). The crate implements `ChunkedDeque<T>`, a generic segmented ring-buffer deque backed by manually managed chunk allocations, along with iterators (`Iter`, `IterMut`, `IntoIter`), range draining (`Drain`), chunked cursors (`ChunkCursor`), and binary snapshot helpers.

Review the crate for memory lifecycle soundness, unwind/exception safety across user-supplied trait hooks (`Clone`, `Drop`, predicates), type-layout edge cases, and ring-index invariants, then complete the following deliverables inside `/app`:

1. **Review Report (`/app/report.json`)**
   Create `/app/report.json` documenting the issues identified during your review:
   - `"files"`: array of relative file paths under `/app` where the primary issues reside (for example `["src/raw_chunk.rs", "src/deque.rs", ...]`).
   - `"findings"`: array of at least 2 concise descriptions explaining each distinct root cause and invariant violation discovered.
   - `"summary"`: overall summary of your remediation approach.

2. **Crate Remediation & Regression Tests**
   - Update the Rust implementation under `/app/src/` so all safe public APIs uphold Rust's memory and drop-lifecycle guarantees across arbitrary element types, ring wrap states, and unwinding callbacks, while preserving the segmented multi-chunk architecture and public API signatures (`ChunkedDeque`, `ChunkStats`, `IntoIter`, `Drain`, `ChunkCursor`, and `wire` helpers).
   - Expand `/app/tests/smoke.rs` (or add integration test files under `/app/tests/`) with unit tests covering the edge cases you fixed, and ensure `cargo test --offline` passes cleanly without external dependencies.
