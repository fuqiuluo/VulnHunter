#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"
APP_DIR="${APP_DIR:-/app}"

cat > "$APP_DIR/src/raw_chunk.rs" << 'EOF'
use std::alloc::{alloc, dealloc, handle_alloc_error, Layout};
use std::mem;
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicUsize, Ordering};

static LIVE_CHUNK_ALLOCS: AtomicUsize = AtomicUsize::new(0);

/// Target byte footprint when choosing a default per-chunk capacity.
pub const TARGET_CHUNK_BYTES: usize = 1024;
pub const MIN_CHUNK_CAPACITY: usize = 4;
pub const DEFAULT_ZST_CHUNK_CAPACITY: usize = 64;

/// Number of currently live heap-allocated chunk buffers across the process.
pub fn live_chunk_allocations() -> usize {
    LIVE_CHUNK_ALLOCS.load(Ordering::Acquire)
}

/// Computes a sensible default element capacity per chunk for type `T`.
#[inline]
pub fn default_chunk_capacity<T>() -> usize {
    let elem_size = mem::size_of::<T>();
    if elem_size == 0 {
        return DEFAULT_ZST_CHUNK_CAPACITY;
    }
    let target = TARGET_CHUNK_BYTES / elem_size;
    if target < MIN_CHUNK_CAPACITY {
        MIN_CHUNK_CAPACITY
    } else {
        target.next_power_of_two()
    }
}

/// Low-level fixed-capacity circular buffer storing `0..=cap` initialized elements of `T`.
pub struct RawChunk<T> {
    ptr: NonNull<T>,
    cap: usize,
    head: usize,
    len: usize,
}

unsafe impl<T: Send> Send for RawChunk<T> {}
unsafe impl<T: Sync> Sync for RawChunk<T> {}

impl<T> RawChunk<T> {
    /// Allocates a new uninitialized circular chunk capable of holding `cap` elements.
    pub fn with_capacity(cap: usize) -> Self {
        assert!(cap > 0, "chunk capacity must be non-zero");
        if mem::size_of::<T>() == 0 {
            return Self {
                ptr: NonNull::dangling(),
                cap,
                head: 0,
                len: 0,
            };
        }
        let layout = Layout::array::<T>(cap).expect("chunk layout overflow");
        let raw = unsafe { alloc(layout) };
        let Some(nn_u8) = NonNull::new(raw) else {
            handle_alloc_error(layout);
        };
        unsafe {
            ptr::write_bytes(nn_u8.as_ptr(), 0xA5, layout.size());
        }
        LIVE_CHUNK_ALLOCS.fetch_add(1, Ordering::AcqRel);
        Self {
            ptr: nn_u8.cast::<T>(),
            cap,
            head: 0,
            len: 0,
        }
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.cap
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn is_full(&self) -> bool {
        self.len == self.cap
    }

    #[inline]
    pub fn head(&self) -> usize {
        self.head
    }

    #[inline]
    pub(crate) fn base_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }

    #[inline]
    pub(crate) fn phys_index(&self, logical_idx: usize) -> usize {
        debug_assert!(logical_idx < self.cap);
        let sum = self.head + logical_idx;
        if sum >= self.cap {
            sum - self.cap
        } else {
            sum
        }
    }

    #[inline]
    pub(crate) unsafe fn slot_ptr(&self, logical_idx: usize) -> *const T {
        if mem::size_of::<T>() == 0 {
            return self.ptr.as_ptr();
        }
        let phys = self.phys_index(logical_idx);
        self.ptr.as_ptr().add(phys)
    }

    #[inline]
    pub(crate) unsafe fn slot_mut_ptr(&mut self, logical_idx: usize) -> *mut T {
        if mem::size_of::<T>() == 0 {
            return self.ptr.as_ptr();
        }
        let phys = self.phys_index(logical_idx);
        self.ptr.as_ptr().add(phys)
    }

    /// Pushes an element onto the back of this chunk. Panics if full.
    pub fn push_back(&mut self, value: T) {
        assert!(!self.is_full(), "push_back on full RawChunk");
        let idx = self.len;
        unsafe {
            let dst = self.slot_mut_ptr(idx);
            ptr::write(dst, value);
        }
        self.len += 1;
    }

    /// Pushes an element onto the front of this chunk. Panics if full.
    pub fn push_front(&mut self, value: T) {
        assert!(!self.is_full(), "push_front on full RawChunk");
        let new_head = if self.head == 0 {
            self.cap - 1
        } else {
            self.head - 1
        };
        unsafe {
            let dst = if mem::size_of::<T>() == 0 {
                self.ptr.as_ptr()
            } else {
                self.ptr.as_ptr().add(new_head)
            };
            ptr::write(dst, value);
        }
        self.head = new_head;
        self.len += 1;
    }

    /// Pops an element from the back of this chunk, or returns `None` if empty.
    pub fn pop_back(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let last_idx = self.len - 1;
        let ptr_to_read = unsafe { self.slot_ptr(last_idx) };
        self.len = last_idx;
        if self.len == 0 {
            self.head = 0;
        }
        unsafe { Some(ptr::read(ptr_to_read)) }
    }

    /// Pops an element from the front of this chunk, or returns `None` if empty.
    pub fn pop_front(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let ptr_to_read = unsafe { self.slot_ptr(0) };
        self.len -= 1;
        if self.len == 0 {
            self.head = 0;
        } else {
            self.head = if self.head + 1 == self.cap {
                0
            } else {
                self.head + 1
            };
        }
        unsafe { Some(ptr::read(ptr_to_read)) }
    }

    #[inline]
    pub fn get(&self, logical_idx: usize) -> Option<&T> {
        if logical_idx >= self.len {
            return None;
        }
        unsafe { Some(&*self.slot_ptr(logical_idx)) }
    }

    #[inline]
    pub fn get_mut(&mut self, logical_idx: usize) -> Option<&mut T> {
        if logical_idx >= self.len {
            return None;
        }
        unsafe { Some(&mut *self.slot_mut_ptr(logical_idx)) }
    }

    /// Inserts `value` at `logical_idx` (`0..=len`), shifting elements to the right.
    pub fn insert_within(&mut self, logical_idx: usize, value: T) {
        assert!(!self.is_full(), "insert_within on full RawChunk");
        assert!(logical_idx <= self.len, "insert_within index out of bounds");
        for i in (logical_idx..self.len).rev() {
            unsafe {
                let val = ptr::read(self.slot_ptr(i));
                ptr::write(self.slot_mut_ptr(i + 1), val);
            }
        }
        unsafe {
            ptr::write(self.slot_mut_ptr(logical_idx), value);
        }
        self.len += 1;
    }

    /// Removes and returns the element at `logical_idx` (`0..len`), shifting tail elements left.
    pub fn remove_within(&mut self, logical_idx: usize) -> T {
        assert!(logical_idx < self.len, "remove_within index out of bounds");
        let removed = unsafe { ptr::read(self.slot_ptr(logical_idx)) };
        for i in logical_idx..(self.len - 1) {
            unsafe {
                let next_val = ptr::read(self.slot_ptr(i + 1));
                ptr::write(self.slot_mut_ptr(i), next_val);
            }
        }
        self.len -= 1;
        if self.len == 0 {
            self.head = 0;
        }
        removed
    }

    /// Appends up to `items.len()` cloned items into spare capacity at the back of this chunk,
    /// advancing `self.len` incrementally as each clone succeeds for unwind safety.
    pub fn extend_cloning(&mut self, items: &[T]) -> usize
    where
        T: Clone,
    {
        let spare = self.cap - self.len;
        let count = items.len().min(spare);
        for item in &items[..count] {
            let cloned = item.clone();
            let dst_idx = self.len;
            unsafe {
                ptr::write(self.slot_mut_ptr(dst_idx), cloned);
            }
            self.len = dst_idx + 1;
        }
        count
    }

    /// Returns up to two contiguous slices representing the initialized elements in logical order.
    pub fn as_slices(&self) -> (&[T], &[T]) {
        if self.len == 0 {
            return (&[], &[]);
        }
        if mem::size_of::<T>() == 0 {
            unsafe {
                return (std::slice::from_raw_parts(self.ptr.as_ptr(), self.len), &[]);
            }
        }
        if self.head + self.len <= self.cap {
            unsafe {
                let first = std::slice::from_raw_parts(self.ptr.as_ptr().add(self.head), self.len);
                (first, &[])
            }
        } else {
            let first_len = self.cap - self.head;
            let second_len = self.len - first_len;
            unsafe {
                let first = std::slice::from_raw_parts(self.ptr.as_ptr().add(self.head), first_len);
                let second = std::slice::from_raw_parts(self.ptr.as_ptr(), second_len);
                (first, second)
            }
        }
    }

    /// Drops all initialized elements in logical order, advancing `head`/`len` BEFORE each drop
    /// and ensuring remaining elements in this chunk are still dropped if a destructor unwinds.
    pub fn clear_elements(&mut self) {
        struct RestDropGuard<'a, T>(&'a mut RawChunk<T>);
        impl<'a, T> Drop for RestDropGuard<'a, T> {
            fn drop(&mut self) {
                while let Some(elem) = self.0.pop_front() {
                    drop(elem);
                }
            }
        }
        let guard = RestDropGuard(self);
        while let Some(elem) = guard.0.pop_front() {
            drop(elem);
        }
    }
}

impl<T: Clone> Clone for RawChunk<T> {
    fn clone(&self) -> Self {
        let mut out = Self::with_capacity(self.cap);
        let (s1, s2) = self.as_slices();
        out.extend_cloning(s1);
        out.extend_cloning(s2);
        out
    }
}

impl<T> Drop for RawChunk<T> {
    fn drop(&mut self) {
        struct DeallocGuard<T> {
            ptr: NonNull<T>,
            cap: usize,
        }
        impl<T> Drop for DeallocGuard<T> {
            fn drop(&mut self) {
                if mem::size_of::<T>() > 0 {
                    let layout = Layout::array::<T>(self.cap).expect("chunk layout overflow");
                    unsafe {
                        dealloc(self.ptr.as_ptr().cast::<u8>(), layout);
                    }
                    LIVE_CHUNK_ALLOCS.fetch_sub(1, Ordering::AcqRel);
                }
            }
        }

        let _dealloc_guard = DeallocGuard {
            ptr: self.ptr,
            cap: self.cap,
        };
        self.clear_elements();
    }
}
EOF

cat > "$APP_DIR/src/deque.rs" << 'EOF'
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::iter::FromIterator;
use std::ops::{Index, IndexMut, RangeBounds};

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
    pub fn new() -> Self {
        Self::with_chunk_capacity(default_chunk_capacity::<T>())
    }

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

    pub fn stats(&self) -> ChunkStats {
        ChunkStats {
            total_len: self.total_len,
            chunk_count: self.chunks.len(),
            chunk_capacity: self.chunk_cap,
            total_slot_capacity: self.chunks.len() * self.chunk_cap,
            global_live_chunks: live_chunk_allocations(),
        }
    }

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

    pub fn remove(&mut self, index: usize) -> Option<T> {
        let (c_idx, inner) = self.locate(index)?;
        let val = self.chunks[c_idx].remove_within(inner);
        self.total_len -= 1;
        if self.chunks[c_idx].is_empty() {
            self.chunks.remove(c_idx);
        }
        Some(val)
    }

    /// Clones and appends all elements from `slice` to the back of the deque while keeping
    /// `total_len` synchronized with actual initialized elements even if `T::clone` panics.
    pub fn extend_from_slice(&mut self, slice: &[T])
    where
        T: Clone,
    {
        if slice.is_empty() {
            return;
        }
        struct LenSyncGuard<'a, T>(&'a mut ChunkedDeque<T>);
        impl<'a, T> Drop for LenSyncGuard<'a, T> {
            fn drop(&mut self) {
                self.0.total_len = self.0.chunks.iter().map(|c| c.len()).sum();
            }
        }

        let guard = LenSyncGuard(self);
        let mut cursor = 0;
        if let Some(last) = guard.0.chunks.last_mut() {
            if !last.is_full() {
                cursor += last.extend_cloning(&slice[cursor..]);
            }
        }
        while cursor < slice.len() {
            let chunk = RawChunk::with_capacity(guard.0.chunk_cap);
            let take = (slice.len() - cursor).min(guard.0.chunk_cap);
            guard.0.chunks.push(chunk);
            let pushed_ref = guard.0.chunks.last_mut().unwrap();
            let added = pushed_ref.extend_cloning(&slice[cursor..cursor + take]);
            cursor += added;
        }
    }

    /// Splits the deque into two at `at`, respecting circular ring offsets inside wrapped chunks.
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

        let tail_chunks = self.chunks.split_off(c_idx + 1);
        let pivot = &mut self.chunks[c_idx];
        let move_cnt = pivot.len() - inner;
        let mut temp_rev = Vec::with_capacity(move_cnt);
        for _ in 0..move_cnt {
            temp_rev.push(pivot.pop_back().expect("pivot has tail element"));
        }
        let mut first_right = RawChunk::with_capacity(self.chunk_cap);
        for item in temp_rev.into_iter().rev() {
            first_right.push_back(item);
        }

        right.chunks.push(first_right);
        right.chunks.extend(tail_chunks);
        right.total_len = right_len;
        self.total_len = at;
        right
    }

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

    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&T) -> bool,
    {
        self.retain_mut(|elem| f(elem));
    }

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

    pub fn clear(&mut self) {
        let chunks = std::mem::take(&mut self.chunks);
        self.total_len = 0;
        drop(chunks);
    }

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
EOF

cat > "$APP_DIR/src/iter.rs" << 'EOF'
use std::collections::VecDeque;
use std::iter::FusedIterator;
use std::marker::PhantomData;
use std::mem;

use crate::deque::ChunkedDeque;
use crate::raw_chunk::RawChunk;

pub struct Iter<'a, T> {
    deque: &'a ChunkedDeque<T>,
    front: usize,
    back: usize,
}

impl<'a, T> Iter<'a, T> {
    pub(crate) fn new(deque: &'a ChunkedDeque<T>) -> Self {
        Self {
            deque,
            front: 0,
            back: deque.len(),
        }
    }
}

impl<'a, T> Clone for Iter<'a, T> {
    fn clone(&self) -> Self {
        Self {
            deque: self.deque,
            front: self.front,
            back: self.back,
        }
    }
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.front >= self.back {
            return None;
        }
        let idx = self.front;
        self.front += 1;
        self.deque.get(idx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = self.back.saturating_sub(self.front);
        (rem, Some(rem))
    }
}

impl<'a, T> DoubleEndedIterator for Iter<'a, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.front >= self.back {
            return None;
        }
        self.back -= 1;
        self.deque.get(self.back)
    }
}

impl<'a, T> ExactSizeIterator for Iter<'a, T> {}
impl<'a, T> FusedIterator for Iter<'a, T> {}

pub struct IterMut<'a, T> {
    chunks: std::slice::IterMut<'a, RawChunk<T>>,
    cur_front_slice: &'a mut [T],
    cur_back_slice: &'a mut [T],
    tail_front_slice: &'a mut [T],
    tail_back_slice: &'a mut [T],
    remaining: usize,
    _marker: PhantomData<&'a mut T>,
}

fn chunk_as_mut_slices<T>(chunk: &mut RawChunk<T>) -> (&mut [T], &mut [T]) {
    let len = chunk.len();
    if len == 0 {
        return (&mut [], &mut []);
    }
    let base = chunk.base_ptr();
    if mem::size_of::<T>() == 0 {
        unsafe { return (std::slice::from_raw_parts_mut(base, len), &mut []) }
    }
    let cap = chunk.capacity();
    let head = chunk.head();
    if head + len <= cap {
        unsafe { (std::slice::from_raw_parts_mut(base.add(head), len), &mut []) }
    } else {
        let first_len = cap - head;
        let second_len = len - first_len;
        unsafe {
            (
                std::slice::from_raw_parts_mut(base.add(head), first_len),
                std::slice::from_raw_parts_mut(base, second_len),
            )
        }
    }
}

impl<'a, T> IterMut<'a, T> {
    pub(crate) fn new(deque: &'a mut ChunkedDeque<T>) -> Self {
        let remaining = deque.total_len;
        Self {
            chunks: deque.chunks.iter_mut(),
            cur_front_slice: &mut [],
            cur_back_slice: &mut [],
            tail_front_slice: &mut [],
            tail_back_slice: &mut [],
            remaining,
            _marker: PhantomData,
        }
    }
}

impl<'a, T> Iterator for IterMut<'a, T> {
    type Item = &'a mut T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        loop {
            if !self.cur_front_slice.is_empty() {
                let slice = std::mem::take(&mut self.cur_front_slice);
                let (first, rest) = slice.split_first_mut().unwrap();
                self.cur_front_slice = rest;
                self.remaining -= 1;
                return Some(first);
            }
            if !self.cur_back_slice.is_empty() {
                let slice = std::mem::take(&mut self.cur_back_slice);
                let (first, rest) = slice.split_first_mut().unwrap();
                self.cur_back_slice = rest;
                self.remaining -= 1;
                return Some(first);
            }
            if let Some(next_chunk) = self.chunks.next() {
                let (s1, s2) = chunk_as_mut_slices(next_chunk);
                self.cur_front_slice = s1;
                self.cur_back_slice = s2;
                continue;
            }
            if !self.tail_front_slice.is_empty() {
                let slice = std::mem::take(&mut self.tail_front_slice);
                let (first, rest) = slice.split_first_mut().unwrap();
                self.tail_front_slice = rest;
                self.remaining -= 1;
                return Some(first);
            }
            if !self.tail_back_slice.is_empty() {
                let slice = std::mem::take(&mut self.tail_back_slice);
                let (first, rest) = slice.split_first_mut().unwrap();
                self.tail_back_slice = rest;
                self.remaining -= 1;
                return Some(first);
            }
            return None;
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<'a, T> DoubleEndedIterator for IterMut<'a, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        loop {
            if !self.tail_back_slice.is_empty() {
                let slice = std::mem::take(&mut self.tail_back_slice);
                let (last, rest) = slice.split_last_mut().unwrap();
                self.tail_back_slice = rest;
                self.remaining -= 1;
                return Some(last);
            }
            if !self.tail_front_slice.is_empty() {
                let slice = std::mem::take(&mut self.tail_front_slice);
                let (last, rest) = slice.split_last_mut().unwrap();
                self.tail_front_slice = rest;
                self.remaining -= 1;
                return Some(last);
            }
            if let Some(back_chunk) = self.chunks.next_back() {
                let (s1, s2) = chunk_as_mut_slices(back_chunk);
                self.tail_front_slice = s1;
                self.tail_back_slice = s2;
                continue;
            }
            if !self.cur_back_slice.is_empty() {
                let slice = std::mem::take(&mut self.cur_back_slice);
                let (last, rest) = slice.split_last_mut().unwrap();
                self.cur_back_slice = rest;
                self.remaining -= 1;
                return Some(last);
            }
            if !self.cur_front_slice.is_empty() {
                let slice = std::mem::take(&mut self.cur_front_slice);
                let (last, rest) = slice.split_last_mut().unwrap();
                self.cur_front_slice = rest;
                self.remaining -= 1;
                return Some(last);
            }
            return None;
        }
    }
}

impl<'a, T> ExactSizeIterator for IterMut<'a, T> {}
impl<'a, T> FusedIterator for IterMut<'a, T> {}

pub struct IntoIter<T> {
    chunks: VecDeque<RawChunk<T>>,
    remaining: usize,
}

impl<T> IntoIter<T> {
    pub(crate) fn new(mut deque: ChunkedDeque<T>) -> Self {
        let remaining = deque.total_len;
        let chunks: VecDeque<RawChunk<T>> = std::mem::take(&mut deque.chunks).into();
        deque.total_len = 0;
        Self { chunks, remaining }
    }
}

impl<T> Iterator for IntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(front_chunk) = self.chunks.front_mut() {
            if let Some(val) = front_chunk.pop_front() {
                self.remaining -= 1;
                if front_chunk.is_empty() {
                    self.chunks.pop_front();
                }
                return Some(val);
            }
            self.chunks.pop_front();
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<T> DoubleEndedIterator for IntoIter<T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        while let Some(back_chunk) = self.chunks.back_mut() {
            if let Some(val) = back_chunk.pop_back() {
                self.remaining -= 1;
                if back_chunk.is_empty() {
                    self.chunks.pop_back();
                }
                return Some(val);
            }
            self.chunks.pop_back();
        }
        None
    }
}

impl<T> ExactSizeIterator for IntoIter<T> {}
impl<T> FusedIterator for IntoIter<T> {}
EOF

cat > "$APP_DIR/src/drain.rs" << 'EOF'
use std::collections::VecDeque;
use std::iter::FusedIterator;
use std::ops::{Bound, RangeBounds};

use crate::deque::ChunkedDeque;

pub(crate) fn normalize_range<R: RangeBounds<usize>>(range: R, len: usize) -> (usize, usize) {
    let start = match range.start_bound() {
        Bound::Included(&s) => s,
        Bound::Excluded(&s) => s.checked_add(1).expect("range start overflow"),
        Bound::Unbounded => 0,
    };
    let end = match range.end_bound() {
        Bound::Included(&e) => e.checked_add(1).expect("range end overflow"),
        Bound::Excluded(&e) => e,
        Bound::Unbounded => len,
    };
    assert!(start <= end, "drain range start ({start}) > end ({end})");
    assert!(end <= len, "drain range end ({end}) > len ({len})");
    (start, end)
}

/// Panic-safe and leak-safe draining iterator over `[start..end)` of a `ChunkedDeque<T>`.
pub struct Drain<'a, T> {
    deque: &'a mut ChunkedDeque<T>,
    drained: VecDeque<T>,
    tail_rev: Vec<T>,
}

impl<'a, T> Drain<'a, T> {
    pub(crate) fn new(deque: &'a mut ChunkedDeque<T>, start: usize, end: usize) -> Self {
        let orig_len = deque.len();
        let suffix_cnt = orig_len - end;
        let drain_cnt = end - start;

        let mut tail_rev = Vec::with_capacity(suffix_cnt);
        for _ in 0..suffix_cnt {
            tail_rev.push(deque.pop_back().expect("suffix element present"));
        }

        let mut drained = VecDeque::with_capacity(drain_cnt);
        for _ in 0..drain_cnt {
            drained.push_front(deque.pop_back().expect("drained element present"));
        }

        Self {
            deque,
            drained,
            tail_rev,
        }
    }
}

impl<'a, T> Iterator for Drain<'a, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.drained.pop_front()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = self.drained.len();
        (rem, Some(rem))
    }
}

impl<'a, T> DoubleEndedIterator for Drain<'a, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.drained.pop_back()
    }
}

impl<'a, T> ExactSizeIterator for Drain<'a, T> {}
impl<'a, T> FusedIterator for Drain<'a, T> {}

impl<'a, T> Drop for Drain<'a, T> {
    fn drop(&mut self) {
        struct TailRestoreGuard<'b, T> {
            deque: &'b mut ChunkedDeque<T>,
            tail_rev: Vec<T>,
        }
        impl<'b, T> Drop for TailRestoreGuard<'b, T> {
            fn drop(&mut self) {
                while let Some(item) = self.tail_rev.pop() {
                    self.deque.push_back(item);
                }
            }
        }

        let tail_rev = std::mem::take(&mut self.tail_rev);
        let _restore_guard = TailRestoreGuard {
            deque: self.deque,
            tail_rev,
        };

        while let Some(unconsumed) = self.drained.pop_front() {
            drop(unconsumed);
        }
    }
}
EOF

cat >> "$APP_DIR/tests/smoke.rs" << 'EOF'

#[test]
fn zst_and_wrapped_split_off_and_unwind_regression() {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ZstMarker;

    let mut zq = ChunkedDeque::<ZstMarker>::new();
    for _ in 0..25 {
        zq.push_back(ZstMarker);
    }
    let zright = zq.split_off(10);
    assert_eq!(zq.len(), 10);
    assert_eq!(zright.len(), 15);

    // Wrapped ring split_off
    let mut wrapped = ChunkedDeque::with_chunk_capacity(4);
    for x in 0..4 {
        wrapped.push_back(x);
    }
    assert_eq!(wrapped.pop_front(), Some(0));
    assert_eq!(wrapped.pop_front(), Some(1));
    wrapped.push_back(4);
    wrapped.push_back(5);
    let wr = wrapped.split_off(2);
    assert_eq!(wrapped.iter().copied().collect::<Vec<_>>(), vec![2, 3]);
    assert_eq!(wr.iter().copied().collect::<Vec<_>>(), vec![4, 5]);

    // Unwind safety on panicking Drop and panicking Clone
    let drops = Arc::new(AtomicUsize::new(0));
    struct DropProbe {
        panic_on_drop: bool,
        drops: Arc<AtomicUsize>,
    }
    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
            if self.panic_on_drop && !std::thread::panicking() {
                panic!("scheduled drop unwind");
            }
        }
    }

    let mut pdq = ChunkedDeque::with_chunk_capacity(4);
    for i in 0..6 {
        pdq.push_back(DropProbe {
            panic_on_drop: i == 2,
            drops: Arc::clone(&drops),
        });
    }
    let res = catch_unwind(AssertUnwindSafe(|| {
        let mut it = pdq.into_iter();
        let _ = it.next();
    }));
    assert!(res.is_err());
    assert_eq!(drops.load(Ordering::SeqCst), 6);
}
EOF

cat > "$APP_DIR/report.json" << 'EOF'
{
  "files": [
    "src/raw_chunk.rs",
    "src/deque.rs",
    "src/drain.rs",
    "src/iter.rs"
  ],
  "findings": [
    "RawChunk::clear_elements and Drain::drop invoked drop_in_place across elements before advancing head/len cursors, causing double-drops when an element destructor panicked during IntoIter, Drain, or clear.",
    "RawChunk::extend_cloning and ChunkedDeque::extend_from_slice incremented chunk and deque lengths prior to fallible Clone::clone calls, dropping uninitialized slots upon panic unwinding.",
    "default_chunk_capacity divided by zero on zero-sized types (size_of::<T>() == 0), RawChunk::with_capacity/Drop passed zero-sized layouts to alloc/dealloc, and ChunkedDeque::split_off copied from base_ptr + offset without accounting for circular ring head wrap."
  ],
  "summary": "Made RawChunk, ChunkedDeque, IntoIter, IterMut, and Drain unwind-safe, leak-safe, ZST-compliant, and circular-offset aware via incremental length commits, pop-before-drop cleanup, RAII restore/dealloc guards, and dangling pointers for zero-sized types."
}
EOF

cargo test --offline --manifest-path "$APP_DIR/Cargo.toml"
