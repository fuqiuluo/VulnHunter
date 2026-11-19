use std::alloc::{alloc, dealloc, handle_alloc_error, Layout};
use std::mem;
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicUsize, Ordering};

static LIVE_CHUNK_ALLOCS: AtomicUsize = AtomicUsize::new(0);

/// Target byte footprint when choosing a default per-chunk capacity.
pub const TARGET_CHUNK_BYTES: usize = 1024;
pub const MIN_CHUNK_CAPACITY: usize = 4;

/// Number of currently live heap-allocated chunk buffers across the process.
pub fn live_chunk_allocations() -> usize {
    LIVE_CHUNK_ALLOCS.load(Ordering::Acquire)
}

/// Computes a sensible default element capacity per chunk for type `T`.
#[inline]
pub fn default_chunk_capacity<T>() -> usize {
    let elem_size = mem::size_of::<T>();
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
        let layout = Layout::array::<T>(cap).expect("chunk layout overflow");
        // Scrub freshly allocated backing memory so diagnostic tools can distinguish untouched slots.
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
        let phys = self.phys_index(logical_idx);
        self.ptr.as_ptr().add(phys)
    }

    #[inline]
    pub(crate) unsafe fn slot_mut_ptr(&mut self, logical_idx: usize) -> *mut T {
        let phys = self.phys_index(logical_idx);
        self.ptr.as_ptr().add(phys)
    }

    #[inline]
    pub(crate) unsafe fn set_len(&mut self, new_len: usize) {
        debug_assert!(new_len <= self.cap);
        self.len = new_len;
    }

    #[inline]
    pub(crate) unsafe fn set_head(&mut self, new_head: usize) {
        debug_assert!(new_head < self.cap);
        self.head = new_head;
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
            let dst = self.ptr.as_ptr().add(new_head);
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
        self.len = last_idx;
        unsafe { Some(ptr::read(self.slot_ptr(last_idx))) }
    }

    /// Pops an element from the front of this chunk, or returns `None` if empty.
    pub fn pop_front(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let old_head = self.head;
        self.head = if old_head + 1 == self.cap {
            0
        } else {
            old_head + 1
        };
        self.len -= 1;
        unsafe { Some(ptr::read(self.ptr.as_ptr().add(old_head))) }
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

    /// Appends up to `items.len()` cloned items into spare capacity at the back of this chunk.
    pub fn extend_cloning(&mut self, items: &[T]) -> usize
    where
        T: Clone,
    {
        let spare = self.cap - self.len;
        let count = items.len().min(spare);
        if count == 0 {
            return 0;
        }
        let base_len = self.len;
        self.len = base_len + count;
        for (offset, item) in items[..count].iter().enumerate() {
            let cloned = item.clone();
            unsafe {
                ptr::write(self.slot_mut_ptr(base_len + offset), cloned);
            }
        }
        count
    }

    /// Returns up to two contiguous slices representing the initialized elements in logical order.
    pub fn as_slices(&self) -> (&[T], &[T]) {
        if self.len == 0 {
            return (&[], &[]);
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

    /// Drops all initialized elements in logical order and resets the chunk to empty.
    pub fn clear_elements(&mut self) {
        let count = self.len;
        for idx in 0..count {
            unsafe {
                let elem_ptr = self.slot_mut_ptr(idx);
                ptr::drop_in_place(elem_ptr);
            }
        }
        self.len = 0;
        self.head = 0;
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
        self.clear_elements();
        let layout = Layout::array::<T>(self.cap).expect("chunk layout overflow");
        unsafe {
            dealloc(self.ptr.as_ptr().cast::<u8>(), layout);
        }
        LIVE_CHUNK_ALLOCS.fetch_sub(1, Ordering::AcqRel);
    }
}
