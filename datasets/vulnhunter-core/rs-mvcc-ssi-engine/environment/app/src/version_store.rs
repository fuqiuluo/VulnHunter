use std::collections::BTreeMap;
use std::ops::Bound;

use crate::types::{
    bounds_can_match_any, clone_key_bound, IsolationError, Key, SeqNo, TxId, Value,
};

/// Payload state of a single committed or uncommitted key version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionKind {
    /// Live key payload containing `Value`.
    Value(Value),
    /// Deletion marker masking all older versions of the same key.
    Tombstone,
}

impl VersionKind {
    /// Returns `true` if this version is a [`VersionKind::Tombstone`].
    #[inline]
    pub const fn is_tombstone(&self) -> bool {
        matches!(self, Self::Tombstone)
    }

    /// Clones out `Some(Value)` for live entries or returns `None` for tombstones.
    #[inline]
    pub fn to_visible_value(&self) -> Option<Value> {
        match self {
            Self::Value(v) => Some(v.clone()),
            Self::Tombstone => None,
        }
    }
}

/// Immutable version finalized when `writer_tx` committed at `commit_seq`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedVersion {
    pub commit_seq: SeqNo,
    pub writer_tx: TxId,
    pub kind: VersionKind,
}

/// Staged write held by at most one active transaction under First-Updater-Wins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UncommittedVersion {
    pub tx_id: TxId,
    pub kind: VersionKind,
}

/// Per-key multi-version chain ordered chronologically (`committed` ascending by `commit_seq`).
#[derive(Clone, Debug, Default)]
pub struct VersionChain {
    pub committed: Vec<CommittedVersion>,
    pub uncommitted: Option<UncommittedVersion>,
}

impl VersionChain {
    /// Returns `true` when the chain has neither committed history nor staged writes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.committed.is_empty() && self.uncommitted.is_none()
    }

    /// Resolves snapshot visibility for `(reader_tx, snapshot_seq)` and collects concurrent writers
    /// whose versions are newer than `reader_tx`'s visible state.
    pub fn inspect_for_read(
        &self,
        reader_tx: TxId,
        snapshot_seq: SeqNo,
    ) -> (Option<Value>, Option<TxId>, Vec<(TxId, SeqNo)>) {
        let mut uncommitted_conflict = None;
        let mut committed_conflicts = Vec::new();

        for ver in self.committed.iter().rev() {
            if ver.commit_seq > snapshot_seq {
                if ver.writer_tx != reader_tx {
                    committed_conflicts.push((ver.writer_tx, ver.commit_seq));
                }
            } else {
                break;
            }
        }

        if let Some(ref unc) = self.uncommitted {
            if unc.tx_id == reader_tx {
                return (
                    unc.kind.to_visible_value(),
                    uncommitted_conflict,
                    committed_conflicts,
                );
            }
            uncommitted_conflict = Some(unc.tx_id);
        }

        let visible = self
            .committed
            .iter()
            .rev()
            .find(|ver| ver.commit_seq <= snapshot_seq)
            .and_then(|ver| ver.kind.to_visible_value());

        (visible, uncommitted_conflict, committed_conflicts)
    }
}

/// Result of a point read on `VersionStore`, bundling visible payload and invisible writers.
#[derive(Clone, Debug, Default)]
pub struct PointReadOutcome {
    pub value: Option<Value>,
    pub uncommitted_conflict: Option<TxId>,
    pub committed_conflicts: Vec<(TxId, SeqNo)>,
}

/// Result of an ordered range scan on `VersionStore`, bundling visible `(Key, Value)` pairs
/// alongside concurrent invisible writers encountered within the scanned key interval.
#[derive(Clone, Debug, Default)]
pub struct RangeScanOutcome {
    pub rows: Vec<(Key, Value)>,
    pub uncommitted_conflicts: Vec<(TxId, Key)>,
    pub committed_conflicts: Vec<(TxId, SeqNo)>,
}

/// Metadata returned when staging a `put` or `delete` into `VersionStore`.
#[derive(Clone, Debug)]
pub struct StagedWrite {
    /// True when the key had no prior committed or uncommitted versions in the store.
    pub is_new_key: bool,
    /// Previous uncommitted payload owned by the same transaction, if overwriting within one tx.
    pub prev_own_uncommitted: Option<VersionKind>,
}

/// Summary counters produced by version-chain reclamation during `vacuum()`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct VersionGcReport {
    pub versions_reclaimed: usize,
    pub tombstones_reclaimed: usize,
    pub keys_removed: usize,
}

/// Ordered `BTreeMap`-backed multi-version key-value store.
#[derive(Debug, Default)]
pub struct VersionStore {
    entries: BTreeMap<Key, VersionChain>,
}

impl VersionStore {
    /// Creates an empty [`VersionStore`].
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Number of distinct keys currently tracked in the version map.
    #[inline]
    pub fn key_count(&self) -> usize {
        self.entries.len()
    }

    /// Total number of committed version records across all key chains.
    pub fn total_committed_versions(&self) -> usize {
        self.entries.values().map(|c| c.committed.len()).sum()
    }

    /// Number of keys currently holding an uncommitted write lock.
    pub fn uncommitted_key_count(&self) -> usize {
        self.entries
            .values()
            .filter(|c| c.uncommitted.is_some())
            .count()
    }

    /// Returns `true` if `key` currently has a chain in the store.
    #[inline]
    pub fn contains_key(&self, key: &[u8]) -> bool {
        self.entries.contains_key(key)
    }

    /// Reads a single key at `(reader_tx, snapshot_seq)` and reports invisible concurrent writers.
    pub fn read_point(
        &self,
        reader_tx: TxId,
        snapshot_seq: SeqNo,
        key: &[u8],
    ) -> PointReadOutcome {
        let Some(chain) = self.entries.get(key) else {
            return PointReadOutcome::default();
        };
        let (value, uncommitted_conflict, committed_conflicts) =
            chain.inspect_for_read(reader_tx, snapshot_seq);
        PointReadOutcome {
            value,
            uncommitted_conflict,
            committed_conflicts,
        }
    }

    /// Scans keys matching `(start, end)` in ascending lexicographical order at `(reader_tx, snapshot_seq)`.
    pub fn scan_range(
        &self,
        reader_tx: TxId,
        snapshot_seq: SeqNo,
        start: &Bound<Key>,
        end: &Bound<Key>,
    ) -> RangeScanOutcome {
        if !bounds_can_match_any(start, end) {
            return RangeScanOutcome::default();
        }

        let mut outcome = RangeScanOutcome::default();
        for (key, chain) in self
            .entries
            .range((clone_key_bound(start), clone_key_bound(end)))
        {
            let (visible, unc_writer, comm_writers) =
                chain.inspect_for_read(reader_tx, snapshot_seq);
            if let Some(writer_tx) = unc_writer {
                outcome
                    .uncommitted_conflicts
                    .push((writer_tx, key.clone()));
            }
            outcome.committed_conflicts.extend(comm_writers);
            if let Some(val) = visible {
                outcome.rows.push((key.clone(), val));
            }
        }
        outcome
    }

    /// Stages an uncommitted `put` or `delete` after verifying First-Updater-Wins and
    /// First-Committer-Wins against concurrent transactions.
    pub fn stage_write(
        &mut self,
        writer_tx: TxId,
        snapshot_seq: SeqNo,
        key: Key,
        kind: VersionKind,
    ) -> Result<StagedWrite, IsolationError> {
        if let Some(chain) = self.entries.get_mut(&key) {
            if let Some(ref unc) = chain.uncommitted {
                if unc.tx_id != writer_tx {
                    return Err(IsolationError::WriteWriteConflict);
                }
            }
            if let Some(newest) = chain.committed.last() {
                if newest.commit_seq > snapshot_seq {
                    return Err(IsolationError::WriteWriteConflict);
                }
            }

            let is_new_key = chain.is_empty();
            let prev_own_uncommitted = chain
                .uncommitted
                .replace(UncommittedVersion {
                    tx_id: writer_tx,
                    kind,
                })
                .map(|prev| prev.kind);

            Ok(StagedWrite {
                is_new_key,
                prev_own_uncommitted,
            })
        } else {
            let mut chain = VersionChain::default();
            chain.uncommitted = Some(UncommittedVersion {
                tx_id: writer_tx,
                kind,
            });
            self.entries.insert(key, chain);
            Ok(StagedWrite {
                is_new_key: true,
                prev_own_uncommitted: None,
            })
        }
    }

    /// Restores a key's uncommitted slot for `tx_id` during savepoint rollback, pruning the
    /// chain entry if rolling back a brand-new key leaves no versions behind.
    pub fn restore_uncommitted(
        &mut self,
        tx_id: TxId,
        key: &[u8],
        prev_own: Option<VersionKind>,
    ) {
        let mut remove_entry = false;
        if let Some(chain) = self.entries.get_mut(key) {
            let owned_by_tx = chain
                .uncommitted
                .as_ref()
                .map_or(false, |u| u.tx_id == tx_id);
            if owned_by_tx || prev_own.is_some() {
                chain.uncommitted = prev_own.map(|kind| UncommittedVersion { tx_id, kind });
            }
            remove_entry = chain.is_empty();
        }
        if remove_entry {
            self.entries.remove(key);
        }
    }

    /// Finalizes all staged writes owned by `tx_id` into committed versions stamped with `commit_seq`.
    pub fn commit_write_set<'a, I>(&mut self, tx_id: TxId, commit_seq: SeqNo, keys: I)
    where
        I: IntoIterator<Item = &'a Key>,
    {
        for key in keys {
            if let Some(chain) = self.entries.get_mut(key) {
                if chain
                    .uncommitted
                    .as_ref()
                    .map_or(false, |u| u.tx_id == tx_id)
                {
                    let unc = chain.uncommitted.take().expect("checked Some");
                    chain.committed.push(CommittedVersion {
                        commit_seq,
                        writer_tx: tx_id,
                        kind: unc.kind,
                    });
                }
            }
        }
    }

    /// Discards all staged writes owned by `tx_id` and removes any empty chains.
    pub fn abort_write_set<'a, I>(&mut self, tx_id: TxId, keys: I)
    where
        I: IntoIterator<Item = &'a Key>,
    {
        for key in keys {
            let mut remove_entry = false;
            if let Some(chain) = self.entries.get_mut(key) {
                if chain
                    .uncommitted
                    .as_ref()
                    .map_or(false, |u| u.tx_id == tx_id)
                {
                    chain.uncommitted = None;
                }
                remove_entry = chain.is_empty();
            }
            if remove_entry {
                self.entries.remove(key);
            }
        }
    }

    /// Reclaims obsolete committed versions and tombstones older than `horizon`.
    pub fn gc_versions(&mut self, horizon: SeqNo) -> VersionGcReport {
        let mut report = VersionGcReport::default();

        self.entries.retain(|_key, chain| {
            if chain.uncommitted.is_none() {
                if let Some(newest) = chain.committed.last() {
                    if newest.kind.is_tombstone() && newest.commit_seq < horizon {
                        chain.committed.pop();
                        report.versions_reclaimed += 1;
                        report.tombstones_reclaimed += 1;
                    }
                }
            }

            if chain.committed.len() > 1 {
                let newest_seq = chain
                    .committed
                    .last()
                    .map(|v| v.commit_seq)
                    .unwrap_or(SeqNo::ZERO);
                let mut kept = Vec::with_capacity(chain.committed.len());
                for ver in chain.committed.drain(..) {
                    if ver.commit_seq == newest_seq || ver.commit_seq >= horizon {
                        kept.push(ver);
                    } else {
                        report.versions_reclaimed += 1;
                        if ver.kind.is_tombstone() {
                            report.tombstones_reclaimed += 1;
                        }
                    }
                }
                chain.committed = kept;
            }

            if chain.is_empty() {
                report.keys_removed += 1;
                false
            } else {
                true
            }
        });

        report
    }
}
