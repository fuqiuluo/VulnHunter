use std::iter::FusedIterator;
use std::ops::{Bound, RangeBounds};
use std::ptr;

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

/// Draining iterator removing elements in `[orig_start..orig_end)` from a `ChunkedDeque<T>`.
pub struct Drain<'a, T> {
    deque: &'a mut ChunkedDeque<T>,
    orig_start: usize,
    orig_end: usize,
    orig_total_len: usize,
    cur_front: usize,
    cur_back: usize,
}

impl<'a, T> Drain<'a, T> {
    pub(crate) fn new(deque: &'a mut ChunkedDeque<T>, start: usize, end: usize) -> Self {
        let orig_total_len = deque.total_len;
        Self {
            deque,
            orig_start: start,
            orig_end: end,
            orig_total_len,
            cur_front: start,
            cur_back: end,
        }
    }

    unsafe fn read_logical(&self, global_idx: usize) -> T {
        let mut rem = global_idx;
        for chunk in &self.deque.chunks {
            let clen = chunk.len();
            if rem < clen {
                return ptr::read(chunk.slot_ptr(rem));
            }
            rem -= clen;
        }
        unreachable!("global_idx out of bounds in Drain")
    }

    unsafe fn write_logical(&mut self, global_idx: usize, val: T) {
        let mut rem = global_idx;
        for chunk in &mut self.deque.chunks {
            let clen = chunk.len();
            if rem < clen {
                ptr::write(chunk.slot_mut_ptr(rem), val);
                return;
            }
            rem -= clen;
        }
        unreachable!("global_idx out of bounds in Drain::write_logical")
    }

    unsafe fn drop_logical(&mut self, global_idx: usize) {
        let mut rem = global_idx;
        for chunk in &mut self.deque.chunks {
            let clen = chunk.len();
            if rem < clen {
                ptr::drop_in_place(chunk.slot_mut_ptr(rem));
                return;
            }
            rem -= clen;
        }
        unreachable!("global_idx out of bounds in Drain::drop_logical")
    }
}

impl<'a, T> Iterator for Drain<'a, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cur_front >= self.cur_back {
            return None;
        }
        let idx = self.cur_front;
        self.cur_front += 1;
        unsafe { Some(self.read_logical(idx)) }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = self.cur_back.saturating_sub(self.cur_front);
        (rem, Some(rem))
    }
}

impl<'a, T> DoubleEndedIterator for Drain<'a, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.cur_front >= self.cur_back {
            return None;
        }
        self.cur_back -= 1;
        unsafe { Some(self.read_logical(self.cur_back)) }
    }
}

impl<'a, T> ExactSizeIterator for Drain<'a, T> {}
impl<'a, T> FusedIterator for Drain<'a, T> {}

impl<'a, T> Drop for Drain<'a, T> {
    fn drop(&mut self) {
        let drained_count = self.orig_end - self.orig_start;
        if drained_count == 0 {
            return;
        }

        // 1. Drop any remaining elements in [cur_front..cur_back) not yet consumed by caller.
        for idx in self.cur_front..self.cur_back {
            unsafe {
                self.drop_logical(idx);
            }
        }

        // 2. Shift suffix [orig_end..orig_total_len) down into [orig_start..new_len).
        let suffix_len = self.orig_total_len - self.orig_end;
        for offset in 0..suffix_len {
            unsafe {
                let moved = self.read_logical(self.orig_end + offset);
                self.write_logical(self.orig_start + offset, moved);
            }
        }

        // 3. Truncate trailing unowned slots from the back chunks without re-dropping them.
        let new_len = self.orig_total_len - drained_count;
        let mut to_trim = drained_count;
        while to_trim > 0 {
            let last = self.deque.chunks.last_mut().expect("chunks non-empty");
            let clen = last.len();
            if clen <= to_trim {
                unsafe {
                    last.set_len(0);
                    last.set_head(0);
                }
                self.deque.chunks.pop();
                to_trim -= clen;
            } else {
                unsafe {
                    last.set_len(clen - to_trim);
                }
                to_trim = 0;
            }
        }
        self.deque.total_len = new_len;
    }
}
