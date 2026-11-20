use std::error::Error;
use std::fmt;
use std::ops::{
    Bound, Range, RangeFrom, RangeFull, RangeInclusive, RangeTo, RangeToInclusive,
};

/// Monotonically increasing identifier uniquely naming a transaction instance.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TxId(pub u64);

impl TxId {
    #[inline]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl From<u64> for TxId {
    #[inline]
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Display for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "T{}", self.0)
    }
}

/// Monotonic commit sequence number defining MVCC snapshot visibility order.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SeqNo(pub u64);

impl SeqNo {
    pub const ZERO: Self = Self(0);

    #[inline]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl From<u64> for SeqNo {
    #[inline]
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Display for SeqNo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{}", self.0)
    }
}

/// Identifier of an intra-transaction savepoint created by `savepoint()`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SavepointId(pub u64);

impl SavepointId {
    #[inline]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl fmt::Display for SavepointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SP{}", self.0)
    }
}

/// Owned byte-string key stored in lexicographical order inside the engine.
pub type Key = Vec<u8>;
/// Owned byte-string payload associated with a key version.
pub type Value = Vec<u8>;

/// Lifecycle state of a transaction registered with the engine.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TxStatus {
    Active,
    Committed { commit_seq: SeqNo },
    Aborted,
}

impl TxStatus {
    #[inline]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    #[inline]
    pub const fn is_committed(self) -> bool {
        matches!(self, Self::Committed { .. })
    }

    #[inline]
    pub const fn is_aborted(self) -> bool {
        matches!(self, Self::Aborted)
    }

    #[inline]
    pub const fn commit_seq(self) -> Option<SeqNo> {
        match self {
            Self::Committed { commit_seq } => Some(commit_seq),
            Self::Active | Self::Aborted => None,
        }
    }
}

/// Concurrency control and lifecycle errors returned by transactional operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IsolationError {
    WriteWriteConflict,
    SerializationFailure,
    InvalidSavepoint,
    TxNotActive,
}

impl fmt::Display for IsolationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WriteWriteConflict => f.write_str("write-write conflict under snapshot isolation"),
            Self::SerializationFailure => f.write_str("serialization failure (dangerous rw cycle)"),
            Self::InvalidSavepoint => f.write_str("invalid or invalidated savepoint identifier"),
            Self::TxNotActive => f.write_str("transaction is not active"),
        }
    }
}

impl Error for IsolationError {}

/// Conversion trait allowing ergonomic byte-slice, string, and owned-key range expressions.
pub trait KeyRange {
    fn into_bounds(self) -> (Bound<Key>, Bound<Key>);
}

impl KeyRange for RangeFull {
    fn into_bounds(self) -> (Bound<Key>, Bound<Key>) {
        (Bound::Unbounded, Bound::Unbounded)
    }
}

impl<K: AsRef<[u8]>> KeyRange for Range<K> {
    fn into_bounds(self) -> (Bound<Key>, Bound<Key>) {
        (
            Bound::Included(self.start.as_ref().to_vec()),
            Bound::Excluded(self.end.as_ref().to_vec()),
        )
    }
}

impl<K: AsRef<[u8]>> KeyRange for RangeInclusive<K> {
    fn into_bounds(self) -> (Bound<Key>, Bound<Key>) {
        let (s, e) = self.into_inner();
        (Bound::Included(s.as_ref().to_vec()), Bound::Included(e.as_ref().to_vec()))
    }
}

impl<K: AsRef<[u8]>> KeyRange for RangeFrom<K> {
    fn into_bounds(self) -> (Bound<Key>, Bound<Key>) {
        (Bound::Included(self.start.as_ref().to_vec()), Bound::Unbounded)
    }
}

impl<K: AsRef<[u8]>> KeyRange for RangeTo<K> {
    fn into_bounds(self) -> (Bound<Key>, Bound<Key>) {
        (Bound::Unbounded, Bound::Excluded(self.end.as_ref().to_vec()))
    }
}

impl<K: AsRef<[u8]>> KeyRange for RangeToInclusive<K> {
    fn into_bounds(self) -> (Bound<Key>, Bound<Key>) {
        (Bound::Unbounded, Bound::Included(self.end.as_ref().to_vec()))
    }
}

impl KeyRange for (Bound<Key>, Bound<Key>) {
    fn into_bounds(self) -> (Bound<Key>, Bound<Key>) {
        self
    }
}

#[inline]
pub fn clone_key_bound(bound: &Bound<Key>) -> Bound<Key> {
    match bound {
        Bound::Included(k) => Bound::Included(k.clone()),
        Bound::Excluded(k) => Bound::Excluded(k.clone()),
        Bound::Unbounded => Bound::Unbounded,
    }
}

#[inline]
pub fn bounds_can_match_any(start: &Bound<Key>, end: &Bound<Key>) -> bool {
    match (start, end) {
        (Bound::Included(s), Bound::Included(e)) => s <= e,
        (Bound::Included(s), Bound::Excluded(e))
        | (Bound::Excluded(s), Bound::Included(e))
        | (Bound::Excluded(s), Bound::Excluded(e)) => s < e,
        _ => true,
    }
}
