use std::collections::VecDeque;
use std::iter::FusedIterator;
use std::marker::PhantomData;

use crate::deque::ChunkedDeque;
use crate::raw_chunk::RawChunk;

/// Immutable element iterator over a `ChunkedDeque<T>`.
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

/// Mutable element iterator over a `ChunkedDeque<T>`.
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
    let cap = chunk.capacity();
    let head = chunk.head();
    let base = chunk.base_ptr();
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

/// Owning iterator over a `ChunkedDeque<T>`.
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
