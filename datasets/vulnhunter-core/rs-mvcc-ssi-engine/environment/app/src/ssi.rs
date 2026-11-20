use std::collections::{BTreeMap, BTreeSet};

use crate::types::{IsolationError, SeqNo, TxId, TxStatus};

/// Directed read-write antidependency `reader --rw--> writer`, signifying that `reader`
/// observed a key/range state preceding `writer`'s concurrent modification.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RwAntidependency {
    pub reader: TxId,
    pub writer: TxId,
}

/// Per-transaction serialization graph node tracked by [`SsiTable`].
#[derive(Clone, Debug)]
pub struct SsiTxRecord {
    pub tx_id: TxId,
    pub snapshot_seq: SeqNo,
    pub status: TxStatus,
    pub in_conflicts: BTreeSet<TxId>,
    pub out_conflicts: BTreeSet<TxId>,
}

impl SsiTxRecord {
    fn new(tx_id: TxId, snapshot_seq: SeqNo) -> Self {
        Self {
            tx_id,
            snapshot_seq,
            status: TxStatus::Active,
            in_conflicts: BTreeSet::new(),
            out_conflicts: BTreeSet::new(),
        }
    }
}

/// Serialization graph manager tracking concurrent `rw-antidependency` edges and
/// detecting Cahill dangerous structures (`T_in --rw--> T_pivot --rw--> T_out`).
#[derive(Debug, Default)]
pub struct SsiTable {
    records: BTreeMap<TxId, SsiTxRecord>,
}

impl SsiTable {
    /// Creates an empty [`SsiTable`].
    pub fn new() -> Self {
        Self {
            records: BTreeMap::new(),
        }
    }

    /// Registers a newly started transaction with `snapshot_seq`.
    pub fn register_tx(&mut self, tx_id: TxId, snapshot_seq: SeqNo) {
        self.records
            .insert(tx_id, SsiTxRecord::new(tx_id, snapshot_seq));
    }

    /// Returns the lifecycle status of `tx_id`, if still retained in the table.
    #[inline]
    pub fn status(&self, tx_id: TxId) -> Option<TxStatus> {
        self.records.get(&tx_id).map(|r| r.status)
    }

    /// Returns `snapshot_seq` for `tx_id`, if still retained in the table.
    #[inline]
    pub fn snapshot_seq(&self, tx_id: TxId) -> Option<SeqNo> {
        self.records.get(&tx_id).map(|r| r.snapshot_seq)
    }

    /// Determines whether `reader_tx` and `writer_tx` execute with overlapping snapshots
    /// such that an `rw-antidependency` between them is concurrency-relevant.
    pub fn are_concurrent(&self, reader_tx: TxId, writer_tx: TxId) -> bool {
        if reader_tx == writer_tx {
            return false;
        }
        let (Some(reader), Some(writer)) =
            (self.records.get(&reader_tx), self.records.get(&writer_tx))
        else {
            return false;
        };

        if reader.status.is_aborted() || writer.status.is_aborted() {
            return false;
        }
        if let Some(r_commit) = reader.status.commit_seq() {
            if r_commit <= writer.snapshot_seq {
                return false;
            }
        }
        if let Some(w_commit) = writer.status.commit_seq() {
            if w_commit <= reader.snapshot_seq {
                return false;
            }
        }
        true
    }

    /// Records a concurrent `reader_tx --rw--> writer_tx` edge.
    /// Returns `true` iff this edge was not previously present.
    pub fn record_rw_conflict(&mut self, reader_tx: TxId, writer_tx: TxId) -> bool {
        if !self.are_concurrent(reader_tx, writer_tx) {
            return false;
        }
        let mut inserted = false;
        if let Some(r_rec) = self.records.get_mut(&reader_tx) {
            inserted |= r_rec.out_conflicts.insert(writer_tx);
        }
        if let Some(w_rec) = self.records.get_mut(&writer_tx) {
            inserted |= w_rec.in_conflicts.insert(reader_tx);
        }
        inserted
    }

    /// Removes a previously recorded `reader_tx --rw--> writer_tx` edge.
    pub fn remove_rw_conflict(&mut self, reader_tx: TxId, writer_tx: TxId) {
        if let Some(r_rec) = self.records.get_mut(&reader_tx) {
            r_rec.out_conflicts.remove(&writer_tx);
        }
        if let Some(w_rec) = self.records.get_mut(&writer_tx) {
            w_rec.in_conflicts.remove(&reader_tx);
        }
    }

    /// Checks whether `tx_id` can safely commit without completing a dangerous SSI structure.
    pub fn validate_commit(&self, tx_id: TxId) -> Result<(), IsolationError> {
        let Some(rec) = self.records.get(&tx_id) else {
            return Err(IsolationError::TxNotActive);
        };
        if !rec.status.is_active() {
            return Err(IsolationError::TxNotActive);
        }

        let has_in_conflict = rec.in_conflicts.iter().any(|in_id| {
            self.records
                .get(in_id)
                .map_or(false, |in_rec| !in_rec.status.is_aborted())
        });

        let has_committed_out_conflict = rec.out_conflicts.iter().any(|out_id| {
            self.records
                .get(out_id)
                .map_or(false, |out_rec| out_rec.status.is_committed())
        });

        if has_in_conflict && has_committed_out_conflict {
            return Err(IsolationError::SerializationFailure);
        }

        Ok(())
    }

    /// Transitions `tx_id` from `Active` to `Committed { commit_seq }`.
    pub fn mark_committed(&mut self, tx_id: TxId, commit_seq: SeqNo) {
        if let Some(rec) = self.records.get_mut(&tx_id) {
            rec.status = TxStatus::Committed { commit_seq };
        }
    }

    /// Transitions `tx_id` to `Aborted` and detaches all incident `rw` edges, since
    /// aborted transactions cannot participate in committed dependency cycles.
    pub fn mark_aborted(&mut self, tx_id: TxId) {
        let (in_peers, out_peers) = match self.records.get_mut(&tx_id) {
            Some(rec) => {
                rec.status = TxStatus::Aborted;
                let ins: Vec<TxId> = rec.in_conflicts.iter().copied().collect();
                let outs: Vec<TxId> = rec.out_conflicts.iter().copied().collect();
                rec.in_conflicts.clear();
                rec.out_conflicts.clear();
                (ins, outs)
            }
            None => return,
        };

        for reader_id in in_peers {
            if let Some(r_rec) = self.records.get_mut(&reader_id) {
                r_rec.out_conflicts.remove(&tx_id);
            }
        }
        for writer_id in out_peers {
            if let Some(w_rec) = self.records.get_mut(&writer_id) {
                w_rec.in_conflicts.remove(&tx_id);
            }
        }
    }

    /// Evicts a finished transaction record and scrubs its ID from neighbor conflict sets.
    pub fn evict_tx(&mut self, tx_id: TxId) -> bool {
        let Some(removed) = self.records.remove(&tx_id) else {
            return false;
        };

        for reader_id in removed.in_conflicts {
            if let Some(r_rec) = self.records.get_mut(&reader_id) {
                r_rec.out_conflicts.remove(&tx_id);
            }
        }
        for writer_id in removed.out_conflicts {
            if let Some(w_rec) = self.records.get_mut(&writer_id) {
                w_rec.in_conflicts.remove(&tx_id);
            }
        }
        true
    }

    /// Lists all non-active (`Committed` or `Aborted`) transactions currently retained.
    pub fn finished_txs(&self) -> Vec<(TxId, TxStatus)> {
        self.records
            .iter()
            .filter_map(|(&id, rec)| {
                if rec.status.is_active() {
                    None
                } else {
                    Some((id, rec.status))
                }
            })
            .collect()
    }

    /// Computes the minimum `snapshot_seq` across all currently `Active` transactions,
    /// or `None` when no transactions are active.
    pub fn min_active_snapshot(&self) -> Option<SeqNo> {
        self.records
            .values()
            .filter(|rec| rec.status.is_active())
            .map(|rec| rec.snapshot_seq)
            .min()
    }

    /// Count of currently active transactions.
    pub fn active_count(&self) -> usize {
        self.records
            .values()
            .filter(|rec| rec.status.is_active())
            .count()
    }

    /// Total number of transaction records currently stored in the table.
    #[inline]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Returns a snapshot of `in_conflicts` recorded on `tx_id`.
    pub fn in_conflicts(&self, tx_id: TxId) -> BTreeSet<TxId> {
        self.records
            .get(&tx_id)
            .map(|r| r.in_conflicts.clone())
            .unwrap_or_default()
    }

    /// Returns a snapshot of `out_conflicts` recorded on `tx_id`.
    pub fn out_conflicts(&self, tx_id: TxId) -> BTreeSet<TxId> {
        self.records
            .get(&tx_id)
            .map(|r| r.out_conflicts.clone())
            .unwrap_or_default()
    }
}
