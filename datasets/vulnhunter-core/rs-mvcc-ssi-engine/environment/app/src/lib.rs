//! `mvcc_ssi` — Embedded Multi-Version Concurrency Control (MVCC) Ordered Key-Value Engine
//! with Serializable Snapshot Isolation (SSI), Nested Savepoints, and Version Garbage Collection.
//!
//! # Formal Isolation & Consistency Guarantees
//!
//! 1. **Strict Serializable Snapshot Isolation (SSI)**:
//!    Every schedule of committed transactions produced by [`SsiEngine`] must be conflict-equivalent
//!    (and observationally equivalent on all point reads, range scans, and final committed state)
//!    to at least one strict serial execution order of those committed transactions.
//!
//! 2. **Snapshot Visibility & Write-Write Conflict Detection**:
//!    Each transaction `T` captures a monotonic `snapshot_seq` at [`SsiEngine::begin`]. Point
//!    lookups ([`SsiEngine::get`]) and ordered scans ([`SsiEngine::scan_range`]) observe `T`'s own
//!    uncommitted writes overlaid atop the newest committed version with `commit_seq <= snapshot_seq`.
//!    Concurrent writes to the same key enforce First-Updater-Wins and First-Committer-Wins,
//!    returning [`IsolationError::WriteWriteConflict`] without corrupting staged state.
//!
//! 3. **Cahill-Style `rw-antidependency` & Predicate `SIRead` Tracking**:
//!    Point reads and range scans acquire `SIRead` predicate locks across exact keys and key
//!    intervals. Read-write antidependencies (`T_reader --rw--> T_writer`) are tracked across
//!    concurrent transactions whenever a reader observes a state preceding a concurrent writer's
//!    modification (including phantom key insertions into scanned ranges). Dangerous structures
//!    (`T_in --rw--> T_pivot --rw--> T_out`) abort the offending transaction at commit with
//!    [`IsolationError::SerializationFailure`] and roll back its uncommitted writes.
//!
//! 4. **Nested Savepoints (`savepoint` / `rollback_to_savepoint`)**:
//!    Transactions may create nested savepoints and roll back uncommitted writes staged after a
//!    savepoint while invalidating inner savepoints. Because application code executing after
//!    `rollback_to_savepoint` can branch on values read inside the rolled-back savepoint scope,
//!    read-dependency tracking (`SIRead` locks and outbound read-write antidependencies) acquired
//!    during the rolled-back scope remains active for the outer transaction, whereas rolled-back
//!    uncommitted writes release their staged versions and must not induce false conflicts.
//!
//! 5. **MVCC Garbage Collection (`vacuum`)**:
//!    [`SsiEngine::vacuum`] computes the active snapshot horizon (`min_active_snapshot`) and
//!    reclaims obsolete version-chain entries, tombstones, and finished transaction tracking state
//!    that can no longer affect visibility or serialization conflict detection for any active or
//!    future snapshot.

pub mod engine;
pub mod gc;
pub mod predicate;
pub mod ssi;
pub mod txn;
pub mod types;
pub mod version_store;

pub use engine::{EngineStats, ScheduleStep, SsiEngine, StepResult};
pub use gc::VacuumStats;
pub use txn::TxnHandle;
pub use types::{IsolationError, Key, KeyRange, SavepointId, SeqNo, TxId, TxStatus, Value};
