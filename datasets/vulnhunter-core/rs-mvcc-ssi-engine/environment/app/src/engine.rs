use std::collections::BTreeMap;
use std::ops::Bound;

use crate::gc::{run_vacuum, VacuumStats};
use crate::predicate::PredicateTable;
use crate::ssi::SsiTable;
use crate::txn::{
    exec_abort, exec_begin, exec_commit, exec_get, exec_rollback_to_savepoint, exec_savepoint,
    exec_scan_range, exec_write, ActiveTxn, TxnHandle,
};
use crate::types::{IsolationError, Key, KeyRange, SavepointId, SeqNo, TxId, TxStatus, Value};
use crate::version_store::{VersionKind, VersionStore};

/// Structural metrics describing the live state of an [`SsiEngine`].
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct EngineStats {
    pub active_tx_count: usize,
    pub latest_commit_seq: SeqNo,
    pub key_count: usize,
    pub total_committed_versions: usize,
    pub uncommitted_key_count: usize,
    pub predicate_lock_count: usize,
    pub ssi_record_count: usize,
}

/// Deterministic scripted operation step executed by [`SsiEngine::run_schedule`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScheduleStep {
    Begin { slot: usize },
    Get { slot: usize, key: Key },
    ScanRange { slot: usize, start: Bound<Key>, end: Bound<Key> },
    Put { slot: usize, key: Key, value: Value },
    Delete { slot: usize, key: Key },
    Savepoint { slot: usize, sp_slot: usize },
    RollbackTo { slot: usize, sp_slot: usize },
    Commit { slot: usize },
    Abort { slot: usize },
    Vacuum,
}

/// Outcome recorded for a corresponding [`ScheduleStep`] in [`SsiEngine::run_schedule`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepResult {
    Begun(TxId),
    Got(Result<Option<Value>, IsolationError>),
    Scanned(Result<Vec<(Key, Value)>, IsolationError>),
    Written(Result<(), IsolationError>),
    Savepointed(Result<SavepointId, IsolationError>),
    RolledBack(Result<(), IsolationError>),
    Committed(Result<SeqNo, IsolationError>),
    Aborted(Result<(), IsolationError>),
    Vacuumed(VacuumStats),
}

/// Embedded ordered MVCC key-value engine implementing Serializable Snapshot Isolation (SSI).
#[derive(Debug)]
pub struct SsiEngine {
    next_tx_raw: u64,
    next_savepoint_raw: u64,
    latest_commit_seq: SeqNo,
    version_store: VersionStore,
    predicate_table: PredicateTable,
    ssi_table: SsiTable,
    active_txns: BTreeMap<TxId, ActiveTxn>,
}

impl Default for SsiEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SsiEngine {
    /// Constructs a new empty [`SsiEngine`] starting at `SeqNo(0)`.
    pub fn new() -> Self {
        Self {
            next_tx_raw: 0,
            next_savepoint_raw: 0,
            latest_commit_seq: SeqNo::ZERO,
            version_store: VersionStore::new(),
            predicate_table: PredicateTable::new(),
            ssi_table: SsiTable::new(),
            active_txns: BTreeMap::new(),
        }
    }

    /// Starts a new transaction capturing the current `latest_commit_seq` as its snapshot.
    pub fn begin(&mut self) -> TxId {
        self.next_tx_raw += 1;
        let tx_id = TxId::new(self.next_tx_raw);
        exec_begin(tx_id, self.latest_commit_seq, &mut self.ssi_table, &mut self.active_txns)
    }

    /// Starts a new transaction and returns an ergonomic [`TxnHandle`] bound to `self`.
    pub fn transaction(&mut self) -> TxnHandle<'_> {
        let tx_id = self.begin();
        TxnHandle::new(self, tx_id)
    }

    /// Wraps an existing `tx_id` in a [`TxnHandle`].
    #[inline]
    pub fn handle(&mut self, tx_id: TxId) -> TxnHandle<'_> {
        TxnHandle::new(self, tx_id)
    }

    /// Looks up `key` under `tx_id`'s snapshot and records a point `SIRead` lock.
    pub fn get(&mut self, tx_id: TxId, key: impl AsRef<[u8]>) -> Result<Option<Value>, IsolationError> {
        exec_get(
            tx_id,
            key.as_ref(),
            &self.version_store,
            &mut self.predicate_table,
            &mut self.ssi_table,
            &mut self.active_txns,
        )
    }

    /// Scans visible `(Key, Value)` pairs within `range` and records a range `SIRead` lock.
    pub fn scan_range<R: KeyRange>(
        &mut self,
        tx_id: TxId,
        range: R,
    ) -> Result<Vec<(Key, Value)>, IsolationError> {
        let (start, end) = range.into_bounds();
        exec_scan_range(
            tx_id,
            start,
            end,
            &self.version_store,
            &mut self.predicate_table,
            &mut self.ssi_table,
            &mut self.active_txns,
        )
    }

    /// Stages `(key, value)` in `tx_id`'s uncommitted write set.
    pub fn put(
        &mut self,
        tx_id: TxId,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<(), IsolationError> {
        exec_write(
            tx_id,
            key.as_ref().to_vec(),
            VersionKind::Value(value.as_ref().to_vec()),
            &mut self.version_store,
            &self.predicate_table,
            &mut self.ssi_table,
            &mut self.active_txns,
        )
    }

    /// Stages a deletion tombstone on `key` in `tx_id`'s uncommitted write set.
    pub fn delete(&mut self, tx_id: TxId, key: impl AsRef<[u8]>) -> Result<(), IsolationError> {
        exec_write(
            tx_id,
            key.as_ref().to_vec(),
            VersionKind::Tombstone,
            &mut self.version_store,
            &self.predicate_table,
            &mut self.ssi_table,
            &mut self.active_txns,
        )
    }

    /// Creates a nested intra-transaction savepoint on `tx_id`.
    pub fn savepoint(&mut self, tx_id: TxId) -> Result<SavepointId, IsolationError> {
        if !self.active_txns.contains_key(&tx_id) {
            return Err(IsolationError::TxNotActive);
        }
        self.next_savepoint_raw += 1;
        exec_savepoint(tx_id, SavepointId::new(self.next_savepoint_raw), &mut self.active_txns)
    }

    /// Rolls back uncommitted writes staged after `savepoint_id` on `tx_id`.
    pub fn rollback_to_savepoint(
        &mut self,
        tx_id: TxId,
        savepoint_id: SavepointId,
    ) -> Result<(), IsolationError> {
        exec_rollback_to_savepoint(
            tx_id,
            savepoint_id,
            &mut self.version_store,
            &mut self.predicate_table,
            &mut self.ssi_table,
            &mut self.active_txns,
        )
    }

    /// Validates SSI invariants and commits `tx_id`, aborting automatically on `SerializationFailure`.
    pub fn commit(&mut self, tx_id: TxId) -> Result<SeqNo, IsolationError> {
        exec_commit(
            tx_id,
            &mut self.latest_commit_seq,
            &mut self.version_store,
            &mut self.predicate_table,
            &mut self.ssi_table,
            &mut self.active_txns,
        )
    }

    /// Explicitly aborts `tx_id` and rolls back all of its uncommitted writes.
    pub fn abort(&mut self, tx_id: TxId) -> Result<(), IsolationError> {
        exec_abort(
            tx_id,
            &mut self.version_store,
            &mut self.predicate_table,
            &mut self.ssi_table,
            &mut self.active_txns,
        )
    }

    /// Reclaims obsolete MVCC versions, tombstones, and finished SSI tracking records.
    pub fn vacuum(&mut self) -> VacuumStats {
        run_vacuum(
            &mut self.version_store,
            &mut self.predicate_table,
            &mut self.ssi_table,
            self.latest_commit_seq,
        )
    }

    #[inline]
    pub const fn latest_commit_seq(&self) -> SeqNo {
        self.latest_commit_seq
    }

    #[inline]
    pub fn tx_status(&self, tx_id: TxId) -> Option<TxStatus> {
        self.ssi_table.status(tx_id)
    }

    #[inline]
    pub fn tx_snapshot(&self, tx_id: TxId) -> Option<SeqNo> {
        self.active_txns
            .get(&tx_id)
            .map(|t| t.snapshot_seq)
            .or_else(|| self.ssi_table.snapshot_seq(tx_id))
    }

    pub fn stats(&self) -> EngineStats {
        EngineStats {
            active_tx_count: self.active_txns.len(),
            latest_commit_seq: self.latest_commit_seq,
            key_count: self.version_store.key_count(),
            total_committed_versions: self.version_store.total_committed_versions(),
            uncommitted_key_count: self.version_store.uncommitted_key_count(),
            predicate_lock_count: self.predicate_table.lock_count(),
            ssi_record_count: self.ssi_table.record_count(),
        }
    }

    pub fn export_committed_snapshot(&self) -> Vec<(Key, Value)> {
        self.version_store
            .scan_range(TxId::new(u64::MAX), self.latest_commit_seq, &Bound::Unbounded, &Bound::Unbounded)
            .rows
    }

    /// Executes a deterministic multi-transaction schedule and collects step-by-step outcomes.
    pub fn run_schedule(&mut self, steps: &[ScheduleStep]) -> Vec<StepResult> {
        let mut tx_slots: BTreeMap<usize, TxId> = BTreeMap::new();
        let mut sp_slots: BTreeMap<usize, SavepointId> = BTreeMap::new();
        let mut out = Vec::with_capacity(steps.len());

        for step in steps {
            let res = match step {
                ScheduleStep::Begin { slot } => {
                    let tx = self.begin();
                    tx_slots.insert(*slot, tx);
                    StepResult::Begun(tx)
                }
                ScheduleStep::Get { slot, key } => StepResult::Got(
                    tx_slots.get(slot).map_or(Err(IsolationError::TxNotActive), |&tx| self.get(tx, key)),
                ),
                ScheduleStep::ScanRange { slot, start, end } => StepResult::Scanned(
                    tx_slots.get(slot).map_or(Err(IsolationError::TxNotActive), |&tx| {
                        self.scan_range(tx, (start.clone(), end.clone()))
                    }),
                ),
                ScheduleStep::Put { slot, key, value } => StepResult::Written(
                    tx_slots.get(slot).map_or(Err(IsolationError::TxNotActive), |&tx| self.put(tx, key, value)),
                ),
                ScheduleStep::Delete { slot, key } => StepResult::Written(
                    tx_slots.get(slot).map_or(Err(IsolationError::TxNotActive), |&tx| self.delete(tx, key)),
                ),
                ScheduleStep::Savepoint { slot, sp_slot } => StepResult::Savepointed(
                    tx_slots.get(slot).map_or(Err(IsolationError::TxNotActive), |&tx| {
                        let r = self.savepoint(tx);
                        if let Ok(sp) = r {
                            sp_slots.insert(*sp_slot, sp);
                        }
                        r
                    }),
                ),
                ScheduleStep::RollbackTo { slot, sp_slot } => match (tx_slots.get(slot), sp_slots.get(sp_slot)) {
                    (Some(&tx), Some(&sp)) => StepResult::RolledBack(self.rollback_to_savepoint(tx, sp)),
                    (Some(_), None) => StepResult::RolledBack(Err(IsolationError::InvalidSavepoint)),
                    (None, _) => StepResult::RolledBack(Err(IsolationError::TxNotActive)),
                },
                ScheduleStep::Commit { slot } => StepResult::Committed(
                    tx_slots.get(slot).map_or(Err(IsolationError::TxNotActive), |&tx| self.commit(tx)),
                ),
                ScheduleStep::Abort { slot } => StepResult::Aborted(
                    tx_slots.get(slot).map_or(Err(IsolationError::TxNotActive), |&tx| self.abort(tx)),
                ),
                ScheduleStep::Vacuum => StepResult::Vacuumed(self.vacuum()),
            };
            out.push(res);
        }
        out
    }
}
