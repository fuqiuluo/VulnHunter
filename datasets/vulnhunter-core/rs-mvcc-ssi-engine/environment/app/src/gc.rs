use crate::predicate::PredicateTable;
use crate::ssi::SsiTable;
use crate::types::SeqNo;
use crate::version_store::VersionStore;

/// Diagnostic counters returned by [`crate::SsiEngine::vacuum`].
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct VacuumStats {
    /// Snapshot horizon used during this reclamation pass.
    pub horizon_seq: SeqNo,
    /// Number of committed version entries pruned from version chains.
    pub versions_reclaimed: usize,
    /// Number of deletion tombstones reclaimed across all keys.
    pub tombstones_reclaimed: usize,
    /// Number of completely empty key chains removed from the store.
    pub keys_removed: usize,
    /// Number of finished SSI transaction records evicted.
    pub ssi_records_reclaimed: usize,
    /// Number of `SIRead` predicate lock entries reclaimed.
    pub predicate_locks_reclaimed: usize,
}

impl VacuumStats {
    /// Returns `true` if `vacuum()` reclaimed at least one version, key, lock, or SSI record.
    #[inline]
    pub const fn did_reclaim_any(&self) -> bool {
        self.versions_reclaimed > 0
            || self.keys_removed > 0
            || self.ssi_records_reclaimed > 0
            || self.predicate_locks_reclaimed > 0
    }
}

/// Computes the oldest snapshot sequence number still visible to active transactions,
/// falling back to `latest_commit_seq` when the system is quiescent.
#[inline]
pub fn compute_vacuum_horizon(ssi_table: &SsiTable, latest_commit_seq: SeqNo) -> SeqNo {
    ssi_table
        .min_active_snapshot()
        .unwrap_or(latest_commit_seq)
}

/// Runs a synchronous MVCC + SSI garbage-collection pass across version chains,
/// `SIRead` predicate locks, and finished serialization-graph nodes.
pub fn run_vacuum(
    version_store: &mut VersionStore,
    predicate_table: &mut PredicateTable,
    ssi_table: &mut SsiTable,
    latest_commit_seq: SeqNo,
) -> VacuumStats {
    let horizon_seq = compute_vacuum_horizon(ssi_table, latest_commit_seq);
    let ver_report = version_store.gc_versions(horizon_seq);

    let mut ssi_records_reclaimed = 0;
    let mut predicate_locks_reclaimed = 0;

    // Reclaim finished (`Committed` and `Aborted`) transaction metadata.
    for (tx_id, _status) in ssi_table.finished_txs() {
        predicate_locks_reclaimed += predicate_table.remove_tx(tx_id);
        if ssi_table.evict_tx(tx_id) {
            ssi_records_reclaimed += 1;
        }
    }

    VacuumStats {
        horizon_seq,
        versions_reclaimed: ver_report.versions_reclaimed,
        tombstones_reclaimed: ver_report.tombstones_reclaimed,
        keys_removed: ver_report.keys_removed,
        ssi_records_reclaimed,
        predicate_locks_reclaimed,
    }
}
