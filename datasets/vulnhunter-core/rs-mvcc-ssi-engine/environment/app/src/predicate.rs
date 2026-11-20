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
    /// Checks whether `key` falls inside this predicate's key interval.
    pub fn matches(&self, key: &[u8]) -> bool {
        let start_slice: &[u8] = match &self.start {
            Bound::Included(s) | Bound::Excluded(s) => s.as_slice(),
            Bound::Unbounded => b"",
        };
        let end_slice: &[u8] = match &self.end {
            Bound::Included(e) | Bound::Excluded(e) => e.as_slice(),
            Bound::Unbounded => b"",
        };

        let lower_ok = key >= start_slice;
        let upper_ok = !end_slice.is_empty() && key < end_slice;
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

    /// Total number of individual `SIRead` lock registrations currently stored.
    #[inline]
    pub fn lock_count(&self) -> usize {
        self.by_id.len()
    }

    /// Number of distinct keys currently holding at least one point `SIRead` lock.
    #[inline]
    pub fn point_lock_key_count(&self) -> usize {
        self.point_locks.len()
    }

    /// Number of active range `SIRead` predicate entries.
    #[inline]
    pub fn range_lock_count(&self) -> usize {
        self.range_locks.len()
    }

    /// Counts how many `SIRead` locks are currently held by `tx_id`.
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
