use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

use crate::engine::SsiEngine;
use crate::predicate::{PredicateLockId, PredicateTable};
use crate::ssi::{RwAntidependency, SsiTable};
use crate::types::{IsolationError, Key, KeyRange, SavepointId, SeqNo, TxId, Value};
use crate::version_store::{VersionKind, VersionStore};

/// Undo log record allowing nested savepoint rollback to restore intra-transaction state.
#[derive(Clone, Debug)]
pub struct UndoRecord {
    pub key: Key,
    pub prev_own_uncommitted: Option<VersionKind>,
    pub inserted_into_write_set: bool,
}

/// Snapshot of transaction-local log offsets captured at `savepoint()`.
#[derive(Copy, Clone, Debug)]
pub struct SavepointFrame {
    pub id: SavepointId,
    pub undo_len: usize,
    pub siread_len: usize,
    pub conflict_len: usize,
}

/// Mutable runtime context owned by an active transaction.
#[derive(Clone, Debug)]
pub struct ActiveTxn {
    pub tx_id: TxId,
    pub snapshot_seq: SeqNo,
    pub write_set: BTreeSet<Key>,
    pub undo_log: Vec<UndoRecord>,
    pub siread_log: Vec<PredicateLockId>,
    pub conflict_log: Vec<RwAntidependency>,
    pub savepoints: Vec<SavepointFrame>,
}

impl ActiveTxn {
    /// Creates a fresh [`ActiveTxn`] descriptor at `snapshot_seq`.
    pub fn new(tx_id: TxId, snapshot_seq: SeqNo) -> Self {
        Self {
            tx_id,
            snapshot_seq,
            write_set: BTreeSet::new(),
            undo_log: Vec::new(),
            siread_log: Vec::new(),
            conflict_log: Vec::new(),
            savepoints: Vec::new(),
        }
    }
}

/// Borrowed ergonomic handle binding a [`TxId`] to an [`SsiEngine`] reference.
pub struct TxnHandle<'a> {
    engine: &'a mut SsiEngine,
    tx_id: TxId,
}

impl<'a> TxnHandle<'a> {
    pub(crate) fn new(engine: &'a mut SsiEngine, tx_id: TxId) -> Self {
        Self { engine, tx_id }
    }

    /// Returns this transaction's [`TxId`].
    #[inline]
    pub const fn id(&self) -> TxId {
        self.tx_id
    }

    /// Returns the snapshot sequence number captured when this transaction began.
    pub fn snapshot_seq(&self) -> Result<SeqNo, IsolationError> {
        self.engine
            .tx_snapshot(self.tx_id)
            .ok_or(IsolationError::TxNotActive)
    }

    /// Reads a single key under SSI, recording an `SIRead` point predicate lock.
    pub fn get(&mut self, key: impl AsRef<[u8]>) -> Result<Option<Value>, IsolationError> {
        self.engine.get(self.tx_id, key)
    }

    /// Performs an ordered range scan under SSI, recording an `SIRead` range predicate lock.
    pub fn scan_range<R: KeyRange>(&mut self, range: R) -> Result<Vec<(Key, Value)>, IsolationError> {
        self.engine.scan_range(self.tx_id, range)
    }

    /// Stages an uncommitted write `(key, value)`.
    pub fn put(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<(), IsolationError> {
        self.engine.put(self.tx_id, key, value)
    }

    /// Stages an uncommitted key deletion (tombstone).
    pub fn delete(&mut self, key: impl AsRef<[u8]>) -> Result<(), IsolationError> {
        self.engine.delete(self.tx_id, key)
    }

    /// Creates a nested savepoint within this transaction.
    pub fn savepoint(&mut self) -> Result<SavepointId, IsolationError> {
        self.engine.savepoint(self.tx_id)
    }

    /// Rolls back uncommitted modifications staged after `sp`, invalidating inner savepoints.
    pub fn rollback_to_savepoint(&mut self, sp: SavepointId) -> Result<(), IsolationError> {
        self.engine.rollback_to_savepoint(self.tx_id, sp)
    }

    /// Validates SSI invariants and commits this transaction, returning its `commit_seq`.
    pub fn commit(self) -> Result<SeqNo, IsolationError> {
        self.engine.commit(self.tx_id)
    }

    /// Aborts this transaction and discards all uncommitted writes.
    pub fn abort(self) -> Result<(), IsolationError> {
        self.engine.abort(self.tx_id)
    }
}

/// Begins a new active transaction at `snapshot_seq`.
pub(crate) fn exec_begin(
    tx_id: TxId,
    snapshot_seq: SeqNo,
    ssi_table: &mut SsiTable,
    active_txns: &mut BTreeMap<TxId, ActiveTxn>,
) -> TxId {
    ssi_table.register_tx(tx_id, snapshot_seq);
    active_txns.insert(tx_id, ActiveTxn::new(tx_id, snapshot_seq));
    tx_id
}

/// Executes a point read with `SIRead` locking and write-before-read `rw` edge detection.
pub(crate) fn exec_get(
    tx_id: TxId,
    key: &[u8],
    version_store: &VersionStore,
    predicate_table: &mut PredicateTable,
    ssi_table: &mut SsiTable,
    active_txns: &mut BTreeMap<TxId, ActiveTxn>,
) -> Result<Option<Value>, IsolationError> {
    let Some(txn) = active_txns.get_mut(&tx_id) else {
        return Err(IsolationError::TxNotActive);
    };
    let snapshot_seq = txn.snapshot_seq;

    let lock_id = predicate_table.record_point_read(tx_id, key);
    txn.siread_log.push(lock_id);

    let read_out = version_store.read_point(tx_id, snapshot_seq, key);
    if let Some(unc_writer) = read_out.uncommitted_conflict {
        if ssi_table.record_rw_conflict(tx_id, unc_writer) {
            txn.conflict_log.push(RwAntidependency {
                reader: tx_id,
                writer: unc_writer,
            });
        }
    }
    for (comm_writer, _seq) in read_out.committed_conflicts {
        if ssi_table.record_rw_conflict(tx_id, comm_writer) {
            txn.conflict_log.push(RwAntidependency {
                reader: tx_id,
                writer: comm_writer,
            });
        }
    }

    Ok(read_out.value)
}

/// Executes an ordered range scan with interval `SIRead` locking and `rw` edge detection.
pub(crate) fn exec_scan_range(
    tx_id: TxId,
    start: Bound<Key>,
    end: Bound<Key>,
    version_store: &VersionStore,
    predicate_table: &mut PredicateTable,
    ssi_table: &mut SsiTable,
    active_txns: &mut BTreeMap<TxId, ActiveTxn>,
) -> Result<Vec<(Key, Value)>, IsolationError> {
    let Some(txn) = active_txns.get_mut(&tx_id) else {
        return Err(IsolationError::TxNotActive);
    };
    let snapshot_seq = txn.snapshot_seq;

    let scan_out = version_store.scan_range(tx_id, snapshot_seq, &start, &end);
    if let Some(lock_id) = predicate_table.record_range_read(tx_id, start, end) {
        txn.siread_log.push(lock_id);
    }

    for (unc_writer, _key) in scan_out.uncommitted_conflicts {
        if ssi_table.record_rw_conflict(tx_id, unc_writer) {
            txn.conflict_log.push(RwAntidependency {
                reader: tx_id,
                writer: unc_writer,
            });
        }
    }
    for (comm_writer, _seq) in scan_out.committed_conflicts {
        if ssi_table.record_rw_conflict(tx_id, comm_writer) {
            txn.conflict_log.push(RwAntidependency {
                reader: tx_id,
                writer: comm_writer,
            });
        }
    }

    Ok(scan_out.rows)
}

/// Stages a `put` or `delete` and records read-before-write `rw` conflicts against `SIRead` holders.
pub(crate) fn exec_write(
    tx_id: TxId,
    key: Key,
    kind: VersionKind,
    version_store: &mut VersionStore,
    predicate_table: &PredicateTable,
    ssi_table: &mut SsiTable,
    active_txns: &mut BTreeMap<TxId, ActiveTxn>,
) -> Result<(), IsolationError> {
    let Some(txn) = active_txns.get_mut(&tx_id) else {
        return Err(IsolationError::TxNotActive);
    };
    let snapshot_seq = txn.snapshot_seq;

    let staged = version_store.stage_write(tx_id, snapshot_seq, key.clone(), kind)?;

    // Fast path for brand-new keys that had no version chain in `version_store`:
    // check exact-key point `SIRead` holders; existing keys also consult range locks.
    let conflicting_readers = if staged.is_new_key {
        predicate_table.conflicting_point_readers(&key)
    } else {
        predicate_table.conflicting_readers(&key)
    };

    for reader_tx in conflicting_readers {
        if reader_tx != tx_id && ssi_table.record_rw_conflict(reader_tx, tx_id) {
            txn.conflict_log.push(RwAntidependency {
                reader: reader_tx,
                writer: tx_id,
            });
        }
    }

    let inserted_into_write_set = txn.write_set.insert(key.clone());
    txn.undo_log.push(UndoRecord {
        key,
        prev_own_uncommitted: staged.prev_own_uncommitted,
        inserted_into_write_set,
    });

    Ok(())
}

/// Creates a nested savepoint on `tx_id`.
pub(crate) fn exec_savepoint(
    tx_id: TxId,
    savepoint_id: SavepointId,
    active_txns: &mut BTreeMap<TxId, ActiveTxn>,
) -> Result<SavepointId, IsolationError> {
    let Some(txn) = active_txns.get_mut(&tx_id) else {
        return Err(IsolationError::TxNotActive);
    };

    txn.savepoints.push(SavepointFrame {
        id: savepoint_id,
        undo_len: txn.undo_log.len(),
        siread_len: txn.siread_log.len(),
        conflict_len: txn.conflict_log.len(),
    });
    Ok(savepoint_id)
}

/// Rolls back transaction changes recorded after `savepoint_id`.
pub(crate) fn exec_rollback_to_savepoint(
    tx_id: TxId,
    savepoint_id: SavepointId,
    version_store: &mut VersionStore,
    predicate_table: &mut PredicateTable,
    ssi_table: &mut SsiTable,
    active_txns: &mut BTreeMap<TxId, ActiveTxn>,
) -> Result<(), IsolationError> {
    let Some(txn) = active_txns.get_mut(&tx_id) else {
        return Err(IsolationError::TxNotActive);
    };

    let Some(sp_index) = txn.savepoints.iter().rposition(|sp| sp.id == savepoint_id) else {
        return Err(IsolationError::InvalidSavepoint);
    };
    let frame = txn.savepoints[sp_index];
    txn.savepoints.truncate(sp_index + 1);

    while txn.undo_log.len() > frame.undo_len {
        let undo = txn.undo_log.pop().expect("checked non-empty");
        version_store.restore_uncommitted(tx_id, &undo.key, undo.prev_own_uncommitted);
        if undo.inserted_into_write_set {
            txn.write_set.remove(&undo.key);
        }
    }

    while txn.siread_log.len() > frame.siread_len {
        let lock_id = txn.siread_log.pop().expect("checked non-empty");
        predicate_table.remove_lock(lock_id);
    }

    while txn.conflict_log.len() > frame.conflict_len {
        let edge = txn.conflict_log.pop().expect("checked non-empty");
        ssi_table.remove_rw_conflict(edge.reader, edge.writer);
    }

    Ok(())
}

/// Validates SSI invariants and commits `tx_id`; automatically aborts `tx_id` on `SerializationFailure`.
pub(crate) fn exec_commit(
    tx_id: TxId,
    latest_commit_seq: &mut SeqNo,
    version_store: &mut VersionStore,
    predicate_table: &mut PredicateTable,
    ssi_table: &mut SsiTable,
    active_txns: &mut BTreeMap<TxId, ActiveTxn>,
) -> Result<SeqNo, IsolationError> {
    if !active_txns.contains_key(&tx_id) {
        return Err(IsolationError::TxNotActive);
    }

    if let Err(err) = ssi_table.validate_commit(tx_id) {
        let _ = exec_abort(tx_id, version_store, predicate_table, ssi_table, active_txns);
        return Err(err);
    }

    let txn = active_txns.remove(&tx_id).expect("checked active");
    let commit_seq = latest_commit_seq.next();
    *latest_commit_seq = commit_seq;

    version_store.commit_write_set(tx_id, commit_seq, &txn.write_set);
    ssi_table.mark_committed(tx_id, commit_seq);

    Ok(commit_seq)
}

/// Aborts `tx_id`, rolling back all uncommitted versions and releasing its `SIRead` locks.
pub(crate) fn exec_abort(
    tx_id: TxId,
    version_store: &mut VersionStore,
    predicate_table: &mut PredicateTable,
    ssi_table: &mut SsiTable,
    active_txns: &mut BTreeMap<TxId, ActiveTxn>,
) -> Result<(), IsolationError> {
    let Some(txn) = active_txns.remove(&tx_id) else {
        return Err(IsolationError::TxNotActive);
    };

    version_store.abort_write_set(tx_id, &txn.write_set);
    predicate_table.remove_tx(tx_id);
    ssi_table.mark_aborted(tx_id);

    Ok(())
}
