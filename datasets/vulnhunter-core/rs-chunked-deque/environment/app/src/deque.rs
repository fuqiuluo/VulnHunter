use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::iter::FromIterator;
use std::ops::{Index, IndexMut, RangeBounds};
use std::ptr;

use crate::cursor::ChunkCursor;
use crate::drain::{normalize_range, Drain};
use crate::iter::{IntoIter, Iter, IterMut};
use crate::raw_chunk::{default_chunk_capacity, live_chunk_allocations, RawChunk};

/// Telemetry snapshot describing the internal segment layout of a `ChunkedDeque`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkStats {
    pub total_len: usize,
    pub chunk_count: usize,
    pub chunk_capacity: usize,
    pub total_slot_capacity: usize,
    pub global_live_chunks: usize,
}

/// A double-ended queue backed by a sequence of fixed-capacity circular chunks.
pub struct ChunkedDeque<T> {
    pub(crate) chunks: Vec<RawChunk<T>>,
    pub(crate) chunk_cap: usize,
    pub(crate) total_len: usize,
}

impl<T> ChunkedDeque<T> {
    /// Creates an empty `ChunkedDeque<T>` using the default segment capacity for `T`.
    pub fn new() -> Self {
        Self::with_chunk_capacity(default_chunk_capacity::<T>())
    }

    /// Creates an empty `ChunkedDeque<T>` where each allocated segment holds `chunk_cap` items.
    pub fn with_chunk_capacity(chunk_cap: usize) -> Self {
        assert!(chunk_cap > 0, "chunk_cap must be greater than zero");
        Self {
            chunks: Vec::new(),
            chunk_cap,
            total_len: 0,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.total_len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.total_len == 0
    }

    #[inline]
    pub fn chunk_capacity(&self) -> usize {
        self.chunk_cap
    }

    #[inline]
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Returns a structural telemetry snapshot of this deque's segmented storage.
    pub fn stats(&self) -> ChunkStats {
        ChunkStats {
            total_len: self.total_len,
            chunk_count: self.chunks.len(),
            chunk_capacity: self.chunk_cap,
            total_slot_capacity: self.chunks.len() * self.chunk_cap,
            global_live_chunks: live_chunk_allocations(),
        }
    }

    /// Maps a global logical index `0..len` to `(chunk_index, intra_chunk_index)`.
    pub(crate) fn locate(&self, index: usize) -> Option<(usize, usize)> {
        if index >= self.total_len {
            return None;
        }
        let mut rem = index;
        for (c_idx, chunk) in self.chunks.iter().enumerate() {
            let clen = chunk.len();
            if rem < clen {
                return Some((c_idx, rem));
            }
            rem -= clen;
        }
        None
    }

    /// Appends an element to the back of the deque.
    pub fn push_back(&mut self, value: T) {
        let need_new = match self.chunks.last() {
            Some(last) => last.is_full(),
            None => true,
        };
        if need_new {
            self.chunks.push(RawChunk::with_capacity(self.chunk_cap));
        }
        self.chunks.last_mut().unwrap().push_back(value);
        self.total_len += 1;
    }

    /// Prepends an element to the front of the deque.
    pub fn push_front(&mut self, value: T) {
        let need_new = match self.chunks.first() {
            Some(first) => first.is_full(),
            None => true,
        };
        if need_new {
            self.chunks.insert(0, RawChunk::with_capacity(self.chunk_cap));
        }
        self.chunks.first_mut().unwrap().push_front(value);
        self.total_len += 1;
    }

    /// Removes the last element from the deque and returns it, or `None` if empty.
    pub fn pop_back(&mut self) -> Option<T> {
        if self.total_len == 0 {
            return None;
        }
        let item = self.chunks.last_mut()?.pop_back()?;
        self.total_len -= 1;
        if self.chunks.last().is_some_and(|c| c.is_empty()) {
            self.chunks.pop();
        }
        Some(item)
    }

    /// Removes the first element from the deque and returns it, or `None` if empty.
    pub fn pop_front(&mut self) -> Option<T> {
        if self.total_len == 0 {
            return None;
        }
        let item = self.chunks.first_mut()?.pop_front()?;
        self.total_len -= 1;
        if self.chunks.first().is_some_and(|c| c.is_empty()) {
            self.chunks.remove(0);
        }
        Some(item)
    }

    pub fn front(&self) -> Option<&T> {
        self.get(0)
    }

    pub fn back(&self) -> Option<&T> {
        if self.total_len == 0 {
            None
        } else {
            self.get(self.total_len - 1)
        }
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        let (c_idx, inner) = self.locate(index)?;
        self.chunks[c_idx].get(inner)
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        let (c_idx, inner) = self.locate(index)?;
        self.chunks[c_idx].get_mut(inner)
    }

    /// Inserts an element at `index` within the deque, shifting subsequent elements in that
    /// segment (spilling at most one item into a neighbor/new chunk if the target chunk is full).
    pub fn insert(&mut self, index: usize, value: T) {
        assert!(index <= self.total_len, "insert index out of bounds");
        if index == self.total_len {
            self.push_back(value);
            return;
        }
        if index == 0 {
            self.push_front(value);
            return;
        }
        let (c_idx, inner) = self.locate(index).expect("valid interior index");
        if !self.chunks[c_idx].is_full() {
            self.chunks[c_idx].insert_within(inner, value);
            self.total_len += 1;
            return;
        }

        // Spill the tail item of `c_idx` into the front of `c_idx + 1` (or a newly inserted chunk).
        let spilled = self.chunks[c_idx].pop_back().expect("full chunk has back");
        self.chunks[c_idx].insert_within(inner, value);
        let can_push_next = self
            .chunks
            .get(c_idx + 1)
            .is_some_and(|next| !next.is_full());
        if can_push_next {
            self.chunks[c_idx + 1].push_front(spilled);
        } else {
            let mut fresh = RawChunk::with_capacity(self.chunk_cap);
            fresh.push_back(spilled);
            self.chunks.insert(c_idx + 1, fresh);
        }
        self.total_len += 1;
    }

    /// Removes and returns the element at `index`. Panics if `index >= len()`.
    pub fn remove(&mut self, index: usize) -> Option<T> {
        let (c_idx, inner) = self.locate(index)?;
        let val = self.chunks[c_idx].remove_within(inner);
        self.total_len -= 1;
        if self.chunks[c_idx].is_empty() {
            self.chunks.remove(c_idx);
        }
        Some(val)
    }

    /// Clones and appends all elements from `slice` to the back of the deque.
    pub fn extend_from_slice(&mut self, slice: &[T])
    where
        T: Clone,
    {
        if slice.is_empty() {
            return;
        }
        let mut cursor = 0;
        self.total_len += slice.len();
        if let Some(last) = self.chunks.last_mut() {
            if !last.is_full() {
                cursor += last.extend_cloning(&slice[cursor..]);
            }
        }
        while cursor < slice.len() {
            let mut chunk = RawChunk::with_capacity(self.chunk_cap);
            cursor += chunk.extend_cloning(&slice[cursor..]);
            self.chunks.push(chunk);
        }
    }

    /// Splits the deque into two at the given index, returning a new `ChunkedDeque` containing
    /// elements `[at, len)`. After the call, `self` contains `[0, at)`.
    pub fn split_off(&mut self, at: usize) -> Self {
        assert!(at <= self.total_len, "split_off index out of bounds");
        let mut right = Self::with_chunk_capacity(self.chunk_cap);
        if at == self.total_len {
            return right;
        }
        if at == 0 {
            std::mem::swap(&mut self.chunks, &mut right.chunks);
            std::mem::swap(&mut self.total_len, &mut right.total_len);
            return right;
        }

        let (c_idx, inner) = self.locate(at).expect("at < total_len");
        let right_len = self.total_len - at;

        if inner == 0 {
            right.chunks = self.chunks.split_off(c_idx);
            right.total_len = right_len;
            self.total_len = at;
            return right;
        }

        // Split `c_idx` into [0..inner) kept in `self` and [inner..chunk_len) moved to `right`.
        let tail_chunks = self.chunks.split_off(c_idx + 1);
        let pivot = &mut self.chunks[c_idx];
        let move_cnt = pivot.len() - inner;
        let mut first_right = RawChunk::with_capacity(self.chunk_cap);
        unsafe {
            ptr::copy_nonoverlapping(
                pivot.base_ptr().add(inner),
                first_right.base_ptr(),
                move_cnt,
            );
            first_right.set_head(0);
            first_right.set_len(move_cnt);
            pivot.set_len(inner);
        }

        right.chunks.push(first_right);
        right.chunks.extend(tail_chunks);
        right.total_len = right_len;
        self.total_len = at;
        right
    }

    /// Retains only the elements specified by the predicate, passing a mutable reference to each.
    pub fn retain_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut T) -> bool,
    {
        let mut idx = 0;
        while idx < self.total_len {
            let keep = {
                let elem = self.get_mut(idx).expect("valid index during retain_mut");
                f(elem)
            };
            if keep {
                idx += 1;
            } else {
                self.remove(idx);
            }
        }
    }

    /// Retains only the elements specified by the predicate.
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&T) -> bool,
    {
        self.retain_mut(|elem| f(elem));
    }

    /// Compacts internal chunks so every chunk except possibly the last is filled to `chunk_cap`.
    pub fn compact(&mut self) {
        if self.chunks.len() <= 1 {
            return;
        }
        let mut rebuilt = Self::with_chunk_capacity(self.chunk_cap);
        while let Some(item) = self.pop_front() {
            rebuilt.push_back(item);
        }
        *self = rebuilt;
    }

    /// Clears the deque, dropping all values and releasing all chunk allocations.
    pub fn clear(&mut self) {
        for chunk in &mut self.chunks {
            chunk.clear_elements();
        }
        self.chunks.clear();
        self.total_len = 0;
    }

    /// Removes the specified range from the deque in bulk, returning all removed elements as an iterator.
    pub fn drain<R>(&mut self, range: R) -> Drain<'_, T>
    where
        R: RangeBounds<usize>,
    {
        let (start, end) = normalize_range(range, self.total_len);
        Drain::new(self, start, end)
    }

    pub fn iter(&self) -> Iter<'_, T> {
        Iter::new(self)
    }

    pub fn iter_mut(&mut self) -> IterMut<'_, T> {
        IterMut::new(self)
    }

    pub fn cursor(&self) -> ChunkCursor<'_, T> {
        ChunkCursor::new(self)
    }
}

impl<T> Default for ChunkedDeque<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone> Clone for ChunkedDeque<T> {
    fn clone(&self) -> Self {
        let mut out = Self::with_chunk_capacity(self.chunk_cap);
        for chunk in &self.chunks {
            let (s1, s2) = chunk.as_slices();
            out.extend_from_slice(s1);
            out.extend_from_slice(s2);
        }
        out
    }
}

impl<T: PartialEq> PartialEq for ChunkedDeque<T> {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}

impl<T: Eq> Eq for ChunkedDeque<T> {}

impl<T: PartialOrd> PartialOrd for ChunkedDeque<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.iter().partial_cmp(other.iter())
    }
}

impl<T: Ord> Ord for ChunkedDeque<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.iter().cmp(other.iter())
    }
}

impl<T: Hash> Hash for ChunkedDeque<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_usize(self.total_len);
        for item in self.iter() {
            item.hash(state);
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for ChunkedDeque<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<T> Index<usize> for ChunkedDeque<T> {
    type Output = T;
    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("ChunkedDeque index out of bounds")
    }
}

impl<T> IndexMut<usize> for ChunkedDeque<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        self.get_mut(index)
            .expect("ChunkedDeque index out of bounds")
    }
}

impl<T> FromIterator<T> for ChunkedDeque<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut deque = Self::new();
        for item in iter {
            deque.push_back(item);
        }
        deque
    }
}

impl<T> Extend<T> for ChunkedDeque<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        for item in iter {
            self.push_back(item);
        }
    }
}

impl<T> IntoIterator for ChunkedDeque<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter::new(self)
    }
}

impl<'a, T> IntoIterator for &'a ChunkedDeque<T> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut ChunkedDeque<T> {
    type Item = &'a mut T;
    type IntoIter = IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}
