#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"
APP_DIR="${APP_DIR:-/app}"

cat > "$APP_DIR/src/predicate.rs" << 'EOF'
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

use crate::types::{bounds_can_match_any, Key, TxId};

/// Unique handle identifying a single `SIRead` predicate lock registration.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PredicateLockId(pub u64);

/// Range `SIRead` predicate lock acquired by a `scan_range` call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangePredicate {
    pub id: PredicateLockId,
    pub tx_id: TxId,
    pub start: Bound<Key>,
    pub end: Bound<Key>,
}

impl RangePredicate {
    /// Checks whether `key` falls inside this predicate's exact lower and upper bounds.
    pub fn matches(&self, key: &[u8]) -> bool {
        let lower_ok = match &self.start {
            Bound::Included(s) => key >= s.as_slice(),
            Bound::Excluded(s) => key > s.as_slice(),
            Bound::Unbounded => true,
        };
        let upper_ok = match &self.end {
            Bound::Included(e) => key <= e.as_slice(),
            Bound::Excluded(e) => key < e.as_slice(),
            Bound::Unbounded => true,
        };
        lower_ok && upper_ok
    }
}

#[derive(Clone, Debug)]
enum LockKind {
    Point { key: Key, tx_id: TxId },
    Range { tx_id: TxId },
}

/// Table of point-granularity and range-granularity `SIRead` predicate locks.
#[derive(Debug, Default)]
pub struct PredicateTable {
    next_lock_id: u64,
    point_locks: BTreeMap<Key, BTreeSet<(TxId, PredicateLockId)>>,
    range_locks: Vec<RangePredicate>,
    by_id: BTreeMap<PredicateLockId, LockKind>,
}

impl PredicateTable {
    /// Creates an empty [`PredicateTable`].
    pub fn new() -> Self {
        Self::default()
    }

    fn alloc_id(&mut self) -> PredicateLockId {
        self.next_lock_id += 1;
        PredicateLockId(self.next_lock_id)
    }

    /// Records a point-read `SIRead` lock for `(tx_id, key)`.
    pub fn record_point_read(&mut self, tx_id: TxId, key: &[u8]) -> PredicateLockId {
        let id = self.alloc_id();
        let owned = key.to_vec();
        self.point_locks
            .entry(owned.clone())
            .or_default()
            .insert((tx_id, id));
        self.by_id
            .insert(id, LockKind::Point { key: owned, tx_id });
        id
    }

    /// Records an interval `SIRead` lock for `(tx_id, start..end)`.
    /// Returns `None` if `(start, end)` cannot match any key.
    pub fn record_range_read(
        &mut self,
        tx_id: TxId,
        start: Bound<Key>,
        end: Bound<Key>,
    ) -> Option<PredicateLockId> {
        if !bounds_can_match_any(&start, &end) {
            return None;
        }
        let id = self.alloc_id();
        self.range_locks.push(RangePredicate {
            id,
            tx_id,
            start,
            end,
        });
        self.by_id.insert(id, LockKind::Range { tx_id });
        Some(id)
    }

    /// Returns all transactions holding an exact point `SIRead` lock on `key`.
    pub fn conflicting_point_readers(&self, key: &[u8]) -> BTreeSet<TxId> {
        let mut out = BTreeSet::new();
        if let Some(holders) = self.point_locks.get(key) {
            for &(tx_id, _) in holders {
                out.insert(tx_id);
            }
        }
        out
    }

    /// Returns all transactions holding a range `SIRead` lock whose interval covers `key`.
    pub fn conflicting_range_readers(&self, key: &[u8]) -> BTreeSet<TxId> {
        let mut out = BTreeSet::new();
        for pred in &self.range_locks {
            if pred.matches(key) {
                out.insert(pred.tx_id);
            }
        }
        out
    }

    /// Returns all transactions holding either a point or range `SIRead` lock covering `key`.
    pub fn conflicting_readers(&self, key: &[u8]) -> BTreeSet<TxId> {
        let mut out = self.conflicting_point_readers(key);
        for pred in &self.range_locks {
            if pred.matches(key) {
                out.insert(pred.tx_id);
            }
        }
        out
    }

    /// Removes a specific `SIRead` lock handle if still present.
    pub fn remove_lock(&mut self, lock_id: PredicateLockId) -> bool {
        let Some(kind) = self.by_id.remove(&lock_id) else {
            return false;
        };
        match kind {
            LockKind::Point { key, tx_id } => {
                let mut empty = false;
                if let Some(set) = self.point_locks.get_mut(&key) {
                    set.remove(&(tx_id, lock_id));
                    empty = set.is_empty();
                }
                if empty {
                    self.point_locks.remove(&key);
                }
            }
            LockKind::Range { .. } => {
                self.range_locks.retain(|r| r.id != lock_id);
            }
        }
        true
    }

    /// Removes all point and range `SIRead` locks owned by `tx_id`, returning the count removed.
    pub fn remove_tx(&mut self, tx_id: TxId) -> usize {
        let ids_to_remove: Vec<PredicateLockId> = self
            .by_id
            .iter()
            .filter_map(|(&id, kind)| {
                let owner = match kind {
                    LockKind::Point { tx_id: owner, .. } => *owner,
                    LockKind::Range { tx_id: owner } => *owner,
                };
                if owner == tx_id {
                    Some(id)
                } else {
                    None
                }
            })
            .collect();

        let mut removed = 0;
        for id in ids_to_remove {
            if self.remove_lock(id) {
                removed += 1;
            }
        }
        removed
    }

    #[inline]
    pub fn lock_count(&self) -> usize {
        self.by_id.len()
    }

    #[inline]
    pub fn point_lock_key_count(&self) -> usize {
        self.point_locks.len()
    }

    #[inline]
    pub fn range_lock_count(&self) -> usize {
        self.range_locks.len()
    }

    pub fn locks_held_by(&self, tx_id: TxId) -> usize {
        self.by_id
            .values()
            .filter(|kind| match kind {
                LockKind::Point { tx_id: owner, .. } => *owner == tx_id,
                LockKind::Range { tx_id: owner } => *owner == tx_id,
            })
            .count()
    }
}
EOF

cat > "$APP_DIR/src/version_store.rs" << 'EOF'
use std::collections::BTreeMap;
use std::ops::Bound;

use crate::types::{
    bounds_can_match_any, clone_key_bound, IsolationError, Key, SeqNo, TxId, Value,
};

/// Payload state of a single committed or uncommitted key version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionKind {
    Value(Value),
    Tombstone,
}

impl VersionKind {
    #[inline]
    pub const fn is_tombstone(&self) -> bool {
        matches!(self, Self::Tombstone)
    }

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
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.committed.is_empty() && self.uncommitted.is_none()
    }

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

#[derive(Clone, Debug, Default)]
pub struct PointReadOutcome {
    pub value: Option<Value>,
    pub uncommitted_conflict: Option<TxId>,
    pub committed_conflicts: Vec<(TxId, SeqNo)>,
}

#[derive(Clone, Debug, Default)]
pub struct RangeScanOutcome {
    pub rows: Vec<(Key, Value)>,
    pub uncommitted_conflicts: Vec<(TxId, Key)>,
    pub committed_conflicts: Vec<(TxId, SeqNo)>,
}

#[derive(Clone, Debug)]
pub struct StagedWrite {
    pub is_new_key: bool,
    pub prev_own_uncommitted: Option<VersionKind>,
}

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
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    #[inline]
    pub fn key_count(&self) -> usize {
        self.entries.len()
    }

    pub fn total_committed_versions(&self) -> usize {
        self.entries.values().map(|c| c.committed.len()).sum()
    }

    pub fn uncommitted_key_count(&self) -> usize {
        self.entries
            .values()
            .filter(|c| c.uncommitted.is_some())
            .count()
    }

    #[inline]
    pub fn contains_key(&self, key: &[u8]) -> bool {
        self.entries.contains_key(key)
    }

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

    /// Reclaims committed versions superseded at or before `horizon` without dropping
    /// the visibility anchor needed by snapshots `>= horizon` or resurrecting older versions
    /// underneath tombstones.
    pub fn gc_versions(&mut self, horizon: SeqNo) -> VersionGcReport {
        let mut report = VersionGcReport::default();

        self.entries.retain(|_key, chain| {
            if let Some(anchor_idx) = chain
                .committed
                .iter()
                .rposition(|ver| ver.commit_seq <= horizon)
            {
                let drop_end = if chain.committed[anchor_idx].kind.is_tombstone() {
                    // Anchor at <= horizon is a tombstone: both the tombstone and every
                    // older version (< anchor_idx) evaluate to None for all snapshots >= horizon.
                    anchor_idx + 1
                } else {
                    // Anchor is a live value still visible to snapshots in [horizon, next_ver);
                    // only versions strictly older than anchor_idx are obsolete.
                    anchor_idx
                };

                for removed in chain.committed.drain(0..drop_end) {
                    report.versions_reclaimed += 1;
                    if removed.kind.is_tombstone() {
                        report.tombstones_reclaimed += 1;
                    }
                }
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
EOF

cat > "$APP_DIR/src/ssi.rs" << 'EOF'
use std::collections::{BTreeMap, BTreeSet};

use crate::types::{IsolationError, Key, SeqNo, TxId, TxStatus};

/// Directed read-write antidependency `reader --rw--> writer`.
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
    /// Keys backing inbound `reader --rw--> self` edges while `self` is still uncommitted.
    uncommitted_in_keys: BTreeMap<TxId, BTreeSet<Key>>,
    /// Latched when a committed inbound peer is evicted by GC while this tx still depends on it.
    has_committed_in_conflict: bool,
    /// Minimum effective `commit_seq` across committed transactions reachable via outbound `rw` edges.
    min_committed_out_seq: Option<SeqNo>,
    /// Snapshot of `min_committed_out_seq` frozen at the instant this transaction commits.
    committed_out_seq_at_commit: Option<SeqNo>,
    /// Latched if a dangerous committed pivot in `out_conflicts` was evicted.
    has_dangerous_committed_pivot_out: bool,
}

impl SsiTxRecord {
    fn new(tx_id: TxId, snapshot_seq: SeqNo) -> Self {
        Self {
            tx_id,
            snapshot_seq,
            status: TxStatus::Active,
            in_conflicts: BTreeSet::new(),
            out_conflicts: BTreeSet::new(),
            uncommitted_in_keys: BTreeMap::new(),
            has_committed_in_conflict: false,
            min_committed_out_seq: None,
            committed_out_seq_at_commit: None,
            has_dangerous_committed_pivot_out: false,
        }
    }

    #[inline]
    fn latch_committed_out(&mut self, seq: SeqNo) {
        self.min_committed_out_seq = Some(match self.min_committed_out_seq {
            Some(existing) => existing.min(seq),
            None => seq,
        });
    }
}

/// Serialization graph manager tracking concurrent `rw-antidependency` edges and
/// detecting Cahill dangerous structures (`T_in --rw--> T_pivot --rw--> T_out`).
#[derive(Debug, Default)]
pub struct SsiTable {
    records: BTreeMap<TxId, SsiTxRecord>,
}

impl SsiTable {
    pub fn new() -> Self {
        Self {
            records: BTreeMap::new(),
        }
    }

    pub fn register_tx(&mut self, tx_id: TxId, snapshot_seq: SeqNo) {
        self.records
            .insert(tx_id, SsiTxRecord::new(tx_id, snapshot_seq));
    }

    #[inline]
    pub fn status(&self, tx_id: TxId) -> Option<TxStatus> {
        self.records.get(&tx_id).map(|r| r.status)
    }

    #[inline]
    pub fn snapshot_seq(&self, tx_id: TxId) -> Option<SeqNo> {
        self.records.get(&tx_id).map(|r| r.snapshot_seq)
    }

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

    /// Records a concurrent `reader_tx --rw--> writer_tx` edge caused by an uncommitted write
    /// of `writer_tx` on `key`.
    pub fn record_uncommitted_rw_conflict(
        &mut self,
        reader_tx: TxId,
        writer_tx: TxId,
        key: &[u8],
    ) -> bool {
        if !self.are_concurrent(reader_tx, writer_tx) {
            return false;
        }
        let mut inserted = false;
        if let Some(r_rec) = self.records.get_mut(&reader_tx) {
            inserted |= r_rec.out_conflicts.insert(writer_tx);
        }
        if let Some(w_rec) = self.records.get_mut(&writer_tx) {
            inserted |= w_rec.in_conflicts.insert(reader_tx);
            w_rec
                .uncommitted_in_keys
                .entry(reader_tx)
                .or_default()
                .insert(key.to_vec());
        }
        inserted
    }

    /// Records a concurrent `reader_tx --rw--> writer_tx` edge where `writer_tx` has already committed.
    pub fn record_committed_rw_conflict(&mut self, reader_tx: TxId, writer_tx: TxId) -> bool {
        if !self.are_concurrent(reader_tx, writer_tx) {
            return false;
        }
        let writer_tail_seq = self.records.get(&writer_tx).and_then(|w_rec| {
            w_rec.status.commit_seq().map(|c_seq| {
                w_rec
                    .committed_out_seq_at_commit
                    .map_or(c_seq, |tail| tail.min(c_seq))
            })
        });

        let mut inserted = false;
        if let Some(r_rec) = self.records.get_mut(&reader_tx) {
            inserted |= r_rec.out_conflicts.insert(writer_tx);
            if let Some(seq) = writer_tail_seq {
                r_rec.latch_committed_out(seq);
            }
        }
        if let Some(w_rec) = self.records.get_mut(&writer_tx) {
            inserted |= w_rec.in_conflicts.insert(reader_tx);
        }
        inserted
    }

    /// Legacy general entry point recording a permanent `reader_tx --rw--> writer_tx` conflict.
    pub fn record_rw_conflict(&mut self, reader_tx: TxId, writer_tx: TxId) -> bool {
        self.record_committed_rw_conflict(reader_tx, writer_tx)
    }

    /// Retracts uncommitted inbound conflicts on `writer_tx` that were solely attributable to
    /// `key` when `writer_tx` rolls back all modifications to `key` via savepoint rollback.
    pub fn retract_uncommitted_write_key(&mut self, writer_tx: TxId, key: &[u8]) {
        let mut detached_readers = Vec::new();
        if let Some(w_rec) = self.records.get_mut(&writer_tx) {
            if !w_rec.status.is_active() {
                return;
            }
            w_rec.uncommitted_in_keys.retain(|&reader_id, keys| {
                keys.remove(key);
                if keys.is_empty() {
                    detached_readers.push(reader_id);
                    false
                } else {
                    true
                }
            });
            for &reader_id in &detached_readers {
                w_rec.in_conflicts.remove(&reader_id);
            }
        }

        for reader_id in detached_readers {
            if let Some(r_rec) = self.records.get_mut(&reader_id) {
                r_rec.out_conflicts.remove(&writer_tx);
            }
        }
    }

    pub fn remove_rw_conflict(&mut self, reader_tx: TxId, writer_tx: TxId) {
        if let Some(r_rec) = self.records.get_mut(&reader_tx) {
            r_rec.out_conflicts.remove(&writer_tx);
        }
        if let Some(w_rec) = self.records.get_mut(&writer_tx) {
            w_rec.in_conflicts.remove(&reader_tx);
            w_rec.uncommitted_in_keys.remove(&reader_tx);
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

        // Condition 1: `tx_id` is T_pivot (`T_in --rw--> tx_id --rw--> T_out` with T_out committed).
        let has_in_conflict = rec.has_committed_in_conflict
            || rec.in_conflicts.iter().any(|in_id| {
                self.records
                    .get(in_id)
                    .map_or(false, |in_rec| !in_rec.status.is_aborted())
            });

        let has_committed_out_conflict = rec.min_committed_out_seq.is_some()
            || rec.out_conflicts.iter().any(|out_id| {
                self.records
                    .get(out_id)
                    .map_or(false, |out_rec| out_rec.status.is_committed())
            });

        if has_in_conflict && has_committed_out_conflict {
            return Err(IsolationError::SerializationFailure);
        }

        // Condition 2: `tx_id` is late-reading / read-only T_in (`tx_id --rw--> T_pivot --rw--> T_out`)
        // where both T_out and T_pivot already committed and `T_out.commit_seq <= tx_id.snapshot_seq`.
        if rec.has_dangerous_committed_pivot_out {
            return Err(IsolationError::SerializationFailure);
        }
        let hits_committed_pivot = rec.out_conflicts.iter().any(|out_id| {
            self.records.get(out_id).map_or(false, |piv| {
                piv.status.is_committed()
                    && piv
                        .committed_out_seq_at_commit
                        .map_or(false, |tail_seq| tail_seq <= rec.snapshot_seq)
            })
        });
        if hits_committed_pivot {
            return Err(IsolationError::SerializationFailure);
        }

        Ok(())
    }

    /// Transitions `tx_id` to `Committed { commit_seq }` and latches outbound conflict metadata
    /// onto every transaction with an inbound `rw` edge into `tx_id`.
    pub fn mark_committed(&mut self, tx_id: TxId, commit_seq: SeqNo) {
        let (in_peers, propagated_seq) = match self.records.get_mut(&tx_id) {
            Some(rec) => {
                rec.status = TxStatus::Committed { commit_seq };
                rec.uncommitted_in_keys.clear();
                rec.committed_out_seq_at_commit = rec.min_committed_out_seq;
                let tail = rec
                    .committed_out_seq_at_commit
                    .map_or(commit_seq, |t| t.min(commit_seq));
                let peers: Vec<TxId> = rec.in_conflicts.iter().copied().collect();
                (peers, tail)
            }
            None => return,
        };

        for reader_id in in_peers {
            if let Some(r_rec) = self.records.get_mut(&reader_id) {
                r_rec.latch_committed_out(propagated_seq);
            }
        }
    }

    /// Transitions `tx_id` to `Aborted` and detaches all incident `rw` edges.
    pub fn mark_aborted(&mut self, tx_id: TxId) {
        let (in_peers, out_peers) = match self.records.get_mut(&tx_id) {
            Some(rec) => {
                rec.status = TxStatus::Aborted;
                let ins: Vec<TxId> = rec.in_conflicts.iter().copied().collect();
                let outs: Vec<TxId> = rec.out_conflicts.iter().copied().collect();
                rec.in_conflicts.clear();
                rec.out_conflicts.clear();
                rec.uncommitted_in_keys.clear();
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
                w_rec.uncommitted_in_keys.remove(&tx_id);
            }
        }
    }

    /// Evicts a finished transaction record while preserving latched summary conflict state
    /// on any surviving neighbor transactions.
    pub fn evict_tx(&mut self, tx_id: TxId) -> bool {
        let Some(removed) = self.records.remove(&tx_id) else {
            return false;
        };

        let committed_info = removed.status.commit_seq().map(|c_seq| {
            let tail = removed
                .committed_out_seq_at_commit
                .map_or(c_seq, |t| t.min(c_seq));
            (tail, removed.committed_out_seq_at_commit)
        });

        for reader_id in removed.in_conflicts {
            if let Some(r_rec) = self.records.get_mut(&reader_id) {
                r_rec.out_conflicts.remove(&tx_id);
                if let Some((tail, piv_tail_opt)) = committed_info {
                    r_rec.latch_committed_out(tail);
                    if let Some(piv_tail) = piv_tail_opt {
                        if piv_tail <= r_rec.snapshot_seq {
                            r_rec.has_dangerous_committed_pivot_out = true;
                        }
                    }
                }
            }
        }

        for writer_id in removed.out_conflicts {
            if let Some(w_rec) = self.records.get_mut(&writer_id) {
                w_rec.in_conflicts.remove(&tx_id);
                w_rec.uncommitted_in_keys.remove(&tx_id);
                if committed_info.is_some() {
                    w_rec.has_committed_in_conflict = true;
                }
            }
        }
        true
    }

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

    pub fn min_active_snapshot(&self) -> Option<SeqNo> {
        self.records
            .values()
            .filter(|rec| rec.status.is_active())
            .map(|rec| rec.snapshot_seq)
            .min()
    }

    pub fn active_count(&self) -> usize {
        self.records
            .values()
            .filter(|rec| rec.status.is_active())
            .count()
    }

    #[inline]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn in_conflicts(&self, tx_id: TxId) -> BTreeSet<TxId> {
        self.records
            .get(&tx_id)
            .map(|r| r.in_conflicts.clone())
            .unwrap_or_default()
    }

    pub fn out_conflicts(&self, tx_id: TxId) -> BTreeSet<TxId> {
        self.records
            .get(&tx_id)
            .map(|r| r.out_conflicts.clone())
            .unwrap_or_default()
    }
}
EOF

cat > "$APP_DIR/src/txn.rs" << 'EOF'
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

use crate::engine::SsiEngine;
use crate::predicate::PredicateTable;
use crate::ssi::SsiTable;
use crate::types::{IsolationError, Key, KeyRange, SavepointId, SeqNo, TxId, Value};
use crate::version_store::{VersionKind, VersionStore};

/// Undo log record allowing nested savepoint rollback to restore intra-transaction writes.
#[derive(Clone, Debug)]
pub struct UndoRecord {
    pub key: Key,
    pub prev_own_uncommitted: Option<VersionKind>,
    pub inserted_into_write_set: bool,
}

/// Snapshot of transaction write-undo offset captured at `savepoint()`.
/// Read dependencies (`SIRead` locks and outbound `rw` edges) are intentionally preserved
/// across savepoint rollbacks because outer control flow can branch on values read prior to rollback.
#[derive(Copy, Clone, Debug)]
pub struct SavepointFrame {
    pub id: SavepointId,
    pub undo_len: usize,
}

/// Mutable runtime context owned by an active transaction.
#[derive(Clone, Debug)]
pub struct ActiveTxn {
    pub tx_id: TxId,
    pub snapshot_seq: SeqNo,
    pub write_set: BTreeSet<Key>,
    pub undo_log: Vec<UndoRecord>,
    pub savepoints: Vec<SavepointFrame>,
}

impl ActiveTxn {
    pub fn new(tx_id: TxId, snapshot_seq: SeqNo) -> Self {
        Self {
            tx_id,
            snapshot_seq,
            write_set: BTreeSet::new(),
            undo_log: Vec::new(),
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

    #[inline]
    pub const fn id(&self) -> TxId {
        self.tx_id
    }

    pub fn snapshot_seq(&self) -> Result<SeqNo, IsolationError> {
        self.engine
            .tx_snapshot(self.tx_id)
            .ok_or(IsolationError::TxNotActive)
    }

    pub fn get(&mut self, key: impl AsRef<[u8]>) -> Result<Option<Value>, IsolationError> {
        self.engine.get(self.tx_id, key)
    }

    pub fn scan_range<R: KeyRange>(&mut self, range: R) -> Result<Vec<(Key, Value)>, IsolationError> {
        self.engine.scan_range(self.tx_id, range)
    }

    pub fn put(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<(), IsolationError> {
        self.engine.put(self.tx_id, key, value)
    }

    pub fn delete(&mut self, key: impl AsRef<[u8]>) -> Result<(), IsolationError> {
        self.engine.delete(self.tx_id, key)
    }

    pub fn savepoint(&mut self) -> Result<SavepointId, IsolationError> {
        self.engine.savepoint(self.tx_id)
    }

    pub fn rollback_to_savepoint(&mut self, sp: SavepointId) -> Result<(), IsolationError> {
        self.engine.rollback_to_savepoint(self.tx_id, sp)
    }

    pub fn commit(self) -> Result<SeqNo, IsolationError> {
        self.engine.commit(self.tx_id)
    }

    pub fn abort(self) -> Result<(), IsolationError> {
        self.engine.abort(self.tx_id)
    }
}

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

pub(crate) fn exec_get(
    tx_id: TxId,
    key: &[u8],
    version_store: &VersionStore,
    predicate_table: &mut PredicateTable,
    ssi_table: &mut SsiTable,
    active_txns: &mut BTreeMap<TxId, ActiveTxn>,
) -> Result<Option<Value>, IsolationError> {
    let Some(txn) = active_txns.get(&tx_id) else {
        return Err(IsolationError::TxNotActive);
    };
    let snapshot_seq = txn.snapshot_seq;

    predicate_table.record_point_read(tx_id, key);

    let read_out = version_store.read_point(tx_id, snapshot_seq, key);
    if let Some(unc_writer) = read_out.uncommitted_conflict {
        ssi_table.record_uncommitted_rw_conflict(tx_id, unc_writer, key);
    }
    for (comm_writer, _seq) in read_out.committed_conflicts {
        ssi_table.record_committed_rw_conflict(tx_id, comm_writer);
    }

    Ok(read_out.value)
}

pub(crate) fn exec_scan_range(
    tx_id: TxId,
    start: Bound<Key>,
    end: Bound<Key>,
    version_store: &VersionStore,
    predicate_table: &mut PredicateTable,
    ssi_table: &mut SsiTable,
    active_txns: &mut BTreeMap<TxId, ActiveTxn>,
) -> Result<Vec<(Key, Value)>, IsolationError> {
    let Some(txn) = active_txns.get(&tx_id) else {
        return Err(IsolationError::TxNotActive);
    };
    let snapshot_seq = txn.snapshot_seq;

    let scan_out = version_store.scan_range(tx_id, snapshot_seq, &start, &end);
    let _ = predicate_table.record_range_read(tx_id, start, end);

    for (unc_writer, unc_key) in scan_out.uncommitted_conflicts {
        ssi_table.record_uncommitted_rw_conflict(tx_id, unc_writer, &unc_key);
    }
    for (comm_writer, _seq) in scan_out.committed_conflicts {
        ssi_table.record_committed_rw_conflict(tx_id, comm_writer);
    }

    Ok(scan_out.rows)
}

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

    // Always inspect BOTH point and range `SIRead` predicate locks, including for brand-new
    // key insertions that may fall into a concurrent transaction's scanned range!
    let conflicting_readers = predicate_table.conflicting_readers(&key);
    for reader_tx in conflicting_readers {
        if reader_tx != tx_id {
            ssi_table.record_uncommitted_rw_conflict(reader_tx, tx_id, &key);
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
    });
    Ok(savepoint_id)
}

pub(crate) fn exec_rollback_to_savepoint(
    tx_id: TxId,
    savepoint_id: SavepointId,
    version_store: &mut VersionStore,
    _predicate_table: &mut PredicateTable,
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
            ssi_table.retract_uncommitted_write_key(tx_id, &undo.key);
        }
    }

    Ok(())
}

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
EOF

cat > "$APP_DIR/src/gc.rs" << 'EOF'
use crate::predicate::PredicateTable;
use crate::ssi::SsiTable;
use crate::types::{SeqNo, TxStatus};
use crate::version_store::VersionStore;

/// Diagnostic counters returned by [`crate::SsiEngine::vacuum`].
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct VacuumStats {
    pub horizon_seq: SeqNo,
    pub versions_reclaimed: usize,
    pub tombstones_reclaimed: usize,
    pub keys_removed: usize,
    pub ssi_records_reclaimed: usize,
    pub predicate_locks_reclaimed: usize,
}

impl VacuumStats {
    #[inline]
    pub const fn did_reclaim_any(&self) -> bool {
        self.versions_reclaimed > 0
            || self.keys_removed > 0
            || self.ssi_records_reclaimed > 0
            || self.predicate_locks_reclaimed > 0
    }
}

#[inline]
pub fn compute_vacuum_horizon(ssi_table: &SsiTable, latest_commit_seq: SeqNo) -> SeqNo {
    ssi_table
        .min_active_snapshot()
        .unwrap_or(latest_commit_seq)
}

/// Runs a synchronous MVCC + SSI garbage-collection pass while retaining committed
/// SSI/predicate records that remain concurrent with any active snapshot (`commit_seq > min_active_snapshot`).
pub fn run_vacuum(
    version_store: &mut VersionStore,
    predicate_table: &mut PredicateTable,
    ssi_table: &mut SsiTable,
    latest_commit_seq: SeqNo,
) -> VacuumStats {
    let min_active = ssi_table.min_active_snapshot();
    let horizon_seq = min_active.unwrap_or(latest_commit_seq);
    let ver_report = version_store.gc_versions(horizon_seq);

    let mut ssi_records_reclaimed = 0;
    let mut predicate_locks_reclaimed = 0;

    for (tx_id, status) in ssi_table.finished_txs() {
        let can_reclaim = match status {
            TxStatus::Aborted => true,
            TxStatus::Committed { commit_seq } => match min_active {
                None => true,
                Some(min_snap) => commit_seq <= min_snap,
            },
            TxStatus::Active => false,
        };

        if can_reclaim {
            predicate_locks_reclaimed += predicate_table.remove_tx(tx_id);
            if ssi_table.evict_tx(tx_id) {
                ssi_records_reclaimed += 1;
            }
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
EOF

cat >> "$APP_DIR/tests/smoke.rs" << 'EOF'

#[test]
fn phantom_insert_range_write_skew_and_unbounded_bounds_regression() {
    let mut eng = SsiEngine::new();
    let t1 = eng.begin();
    let t2 = eng.begin();

    assert!(eng.scan_range(t1, b"dept:eng:"..b"dept:eng;").unwrap().is_empty());
    assert!(eng.scan_range(t2, b"dept:eng:"..b"dept:eng;").unwrap().is_empty());

    eng.put(t1, b"dept:eng:alice", b"oncall").unwrap();
    eng.put(t2, b"dept:eng:bob", b"oncall").unwrap();

    eng.commit(t1).unwrap();
    assert_eq!(eng.commit(t2), Err(IsolationError::SerializationFailure));

    // Unbounded upper range (`start..`) and inclusive upper bound (`..=end`)
    let mut eng2 = SsiEngine::new();
    let u1 = eng2.begin();
    let u2 = eng2.begin();
    assert!(eng2.scan_range(u1, &b"ev:"[..]..).unwrap().is_empty());
    assert!(eng2.scan_range(u2, ..=&b"ev:9"[..]).unwrap().is_empty());
    eng2.put(u1, b"ev:9", b"a").unwrap();
    eng2.put(u2, b"ev:5", b"b").unwrap();
    eng2.commit(u1).unwrap();
    assert_eq!(eng2.commit(u2), Err(IsolationError::SerializationFailure));
}

#[test]
fn savepoint_rollback_retains_read_dependencies_without_false_write_conflicts() {
    let mut eng = SsiEngine::new();
    let t1 = eng.begin();
    let t2 = eng.begin();

    let sp1 = eng.savepoint(t1).unwrap();
    let v1 = eng.get(t1, b"slot:a").unwrap();
    eng.put(t1, b"tmp:1", b"rolled_back").unwrap();
    eng.rollback_to_savepoint(t1, sp1).unwrap();
    if v1.is_none() {
        eng.put(t1, b"slot:b", b"t1").unwrap();
    }

    let sp2 = eng.savepoint(t2).unwrap();
    let v2 = eng.get(t2, b"slot:b").unwrap();
    eng.rollback_to_savepoint(t2, sp2).unwrap();
    if v2.is_none() {
        eng.put(t2, b"slot:a", b"t2").unwrap();
    }

    eng.commit(t1).unwrap();
    assert_eq!(eng.commit(t2), Err(IsolationError::SerializationFailure));
}

#[test]
fn three_tx_dangerous_structure_and_mvcc_vacuum_horizon_regression() {
    // 1. 3-tx T1 --rw--> T2 --rw--> T3 where T3 commits first + vacuum()
    let mut eng = SsiEngine::new();
    let s = eng.begin();
    eng.put(s, b"x", b"0").unwrap();
    eng.put(s, b"y", b"0").unwrap();
    eng.put(s, b"z", b"0").unwrap();
    eng.commit(s).unwrap();

    let t1 = eng.begin();
    let t2 = eng.begin();
    let t3 = eng.begin();
    let _ = eng.get(t1, b"x").unwrap();
    let _ = eng.get(t2, b"y").unwrap();
    let _ = eng.get(t3, b"z").unwrap();

    eng.put(t3, b"y", b"1").unwrap();
    eng.commit(t3).unwrap();
    let _ = eng.vacuum();

    eng.put(t2, b"x", b"1").unwrap();
    eng.put(t1, b"z", b"1").unwrap();
    assert_eq!(eng.commit(t2), Err(IsolationError::SerializationFailure));
    eng.commit(t1).unwrap();

    // 2. MVCC horizon anchor preservation + tombstone non-resurrection
    let mut eng2 = SsiEngine::new();
    let w1 = eng2.begin();
    eng2.put(w1, b"live", b"v1").unwrap();
    eng2.put(w1, b"deleted", b"v0").unwrap();
    eng2.commit(w1).unwrap();

    let w_del = eng2.begin();
    eng2.delete(w_del, b"deleted").unwrap();
    eng2.commit(w_del).unwrap();

    let snap = eng2.begin();
    let w2 = eng2.begin();
    eng2.put(w2, b"live", b"v2").unwrap();
    eng2.commit(w2).unwrap();

    let _ = eng2.vacuum();
    assert_eq!(eng2.get(snap, b"live").unwrap(), Some(b"v1".to_vec()));
    assert_eq!(eng2.get(snap, b"deleted").unwrap(), None);
    eng2.commit(snap).unwrap();
}
EOF

cat > "$APP_DIR/report.json" << 'EOF'
{
  "files": [
    "src/txn.rs",
    "src/predicate.rs",
    "src/ssi.rs",
    "src/gc.rs",
    "src/version_store.rs"
  ],
  "findings": [
    "Brand-new key insertions in src/txn.rs skipped range SIRead predicate checks via conflicting_point_readers, and RangePredicate::matches in src/predicate.rs mishandled unbounded upper bounds and inclusive/excluded endpoints, permitting phantom write-skew anomalies.",
    "Savepoint rollback in src/txn.rs removed SIRead locks and outbound rw-antidependency edges acquired inside the rolled-back scope while failing to retract uncommitted write-side inbound edges keyed to rolled-back writes.",
    "Garbage collection in src/gc.rs evicted committed transactions from PredicateTable and SsiTable even while overlapping active snapshots remained live, and src/ssi.rs neither latched committed outbound/inbound conflict flags across eviction nor checked read-only T_in dangerous structures against committed pivots.",
    "VersionStore::gc_versions in src/version_store.rs pruned pre-horizon versions that were still the newest visible anchor for active snapshots when newer post-horizon versions existed, and popped pre-horizon head tombstones before pruning older versions underneath them, resurrecting deleted values."
  ],
  "summary": "Consulted full point+range SIRead predicates on all writes with exact Bound semantics, preserved SIRead locks and outbound rw edges across savepoint rollbacks while retracting rolled-back uncommitted write keys, retained committed SSI/predicate state until min_active_snapshot advances while latching transitive committed out-conflict horizons, and anchored MVCC version/tombstone reclamation at the newest version <= horizon."
}
EOF

cargo test --offline --manifest-path "$APP_DIR/Cargo.toml"
