use crate::deque::ChunkedDeque;

/// Read-only segment cursor iterating contiguous slices across `ChunkedDeque` chunks.
pub struct ChunkCursor<'a, T> {
    deque: &'a ChunkedDeque<T>,
    chunk_idx: usize,
    second_half: bool,
}

impl<'a, T> ChunkCursor<'a, T> {
    pub(crate) fn new(deque: &'a ChunkedDeque<T>) -> Self {
        Self {
            deque,
            chunk_idx: 0,
            second_half: false,
        }
    }

    /// Returns the next non-empty contiguous slice in logical order, or `None` at the end.
    pub fn next_contiguous_slice(&mut self) -> Option<&'a [T]> {
        while self.chunk_idx < self.deque.chunks.len() {
            let (s1, s2) = self.deque.chunks[self.chunk_idx].as_slices();
            if !self.second_half {
                self.second_half = true;
                if !s1.is_empty() {
                    return Some(s1);
                }
            }
            self.chunk_idx += 1;
            self.second_half = false;
            if !s2.is_empty() {
                return Some(s2);
            }
        }
        None
    }

    /// Resets the cursor back to the beginning of the deque.
    pub fn rewind(&mut self) {
        self.chunk_idx = 0;
        self.second_half = false;
    }
}

/// Wire snapshot helpers for serializing and restoring `ChunkedDeque<Vec<u8>>` frames.
pub mod wire {
    use crate::deque::ChunkedDeque;

    const MAGIC: &[u8; 4] = b"CDQ1";

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum WireError {
        Truncated,
        BadMagic,
        InvalidChunkCap,
        TrailingBytes,
        ChecksumMismatch,
    }

    fn fnv1a64(bytes: &[u8]) -> u64 {
        let mut hash: u64 = 0xcbf29ce484222325;
        for &b in bytes {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }

    /// Encodes a `ChunkedDeque<Vec<u8>>` into a self-checksummed binary frame.
    pub fn encode_records(deque: &ChunkedDeque<Vec<u8>>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(deque.chunk_capacity() as u32).to_le_bytes());
        out.extend_from_slice(&(deque.len() as u32).to_le_bytes());
        for record in deque.iter() {
            out.extend_from_slice(&(record.len() as u32).to_le_bytes());
            out.extend_from_slice(record);
        }
        let digest = fnv1a64(&out);
        out.extend_from_slice(&digest.to_le_bytes());
        out
    }

    /// Decodes a binary frame produced by `encode_records` back into a `ChunkedDeque<Vec<u8>>`.
    pub fn decode_records(frame: &[u8]) -> Result<ChunkedDeque<Vec<u8>>, WireError> {
        if frame.len() < 20 {
            return Err(WireError::Truncated);
        }
        if &frame[0..4] != MAGIC {
            return Err(WireError::BadMagic);
        }
        let body_end = frame.len() - 8;
        let expected_digest = u64::from_le_bytes(frame[body_end..].try_into().unwrap());
        if fnv1a64(&frame[..body_end]) != expected_digest {
            return Err(WireError::ChecksumMismatch);
        }

        let chunk_cap = u32::from_le_bytes(frame[4..8].try_into().unwrap()) as usize;
        if chunk_cap == 0 || chunk_cap > (1 << 20) {
            return Err(WireError::InvalidChunkCap);
        }
        let count = u32::from_le_bytes(frame[8..12].try_into().unwrap()) as usize;
        let mut pos = 12;
        let mut deque = ChunkedDeque::with_chunk_capacity(chunk_cap);
        for _ in 0..count {
            if pos + 4 > body_end {
                return Err(WireError::Truncated);
            }
            let rlen = u32::from_le_bytes(frame[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + rlen > body_end {
                return Err(WireError::Truncated);
            }
            deque.push_back(frame[pos..pos + rlen].to_vec());
            pos += rlen;
        }
        if pos != body_end {
            return Err(WireError::TrailingBytes);
        }
        Ok(deque)
    }
}
