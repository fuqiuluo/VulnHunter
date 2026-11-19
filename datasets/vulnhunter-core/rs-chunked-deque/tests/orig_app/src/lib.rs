//! `chunked_deque`: A segmented ring-buffer double-ended queue with bounded per-chunk allocations.
//!
//! Unlike a contiguous ring buffer that must reallocate and copy the entire buffer upon growth,
//! `ChunkedDeque<T>` stores elements across fixed-capacity ring chunks (`RawChunk<T>`), keeping
//! worst-case push latency predictable while preserving cache locality within each segment.

pub mod cursor;
pub mod deque;
pub mod drain;
pub mod iter;
pub mod raw_chunk;

pub use cursor::{wire, ChunkCursor};
pub use deque::{ChunkStats, ChunkedDeque};
pub use drain::Drain;
pub use iter::{ IntoIter, Iter, IterMut };
