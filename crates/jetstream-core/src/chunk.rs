//! Chunk arithmetic and the have/need bitmap.
//!
//! Files are divided into fixed 1 MiB chunks. Fixed rather than content-defined
//! on purpose: content-defined chunking earns its keep when re-syncing a file
//! that was *edited in the middle*, and pays for itself in complexity and a
//! rolling-hash pass over every byte. Jetstream's job is moving files that
//! the receiver either lacks entirely or holds a prefix of, and for that, fixed
//! offsets are simpler and strictly faster.
//!
//! [`ChunkMap`] is the state that makes resume work. It records which chunks of
//! a file have landed and been verified. Persisted next to the partial file, it
//! survives not just a dropped connection but a power cut — on restart the
//! receiver reloads it and asks only for what is still missing.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Chunk size.
///
/// 1 MiB balances three pressures: small enough that losing an in-flight chunk
/// to a disconnect wastes little work, large enough that per-chunk overhead
/// (a frame header, a hash, a bitmap update) disappears against the payload,
/// and a clean multiple of every filesystem block size we will meet.
pub const CHUNK_SIZE: u64 = 1 << 20;

/// Largest file we can describe, given a `u32` chunk index.
pub const MAX_FILE_SIZE: u64 = (u32::MAX as u64) * CHUNK_SIZE;

/// How many chunks a file of `size` bytes occupies.
///
/// A zero-byte file has zero chunks — it is created by the manifest entry
/// alone and needs no data transferred.
pub fn chunk_count(size: u64) -> Result<u32> {
    if size > MAX_FILE_SIZE {
        return Err(Error::Protocol(format!(
            "file of {size} bytes exceeds the {MAX_FILE_SIZE} byte maximum"
        )));
    }
    Ok(size.div_ceil(CHUNK_SIZE) as u32)
}

/// Byte offset and length of one chunk.
///
/// The final chunk is short whenever the file is not a whole number of chunks.
pub fn chunk_span(index: u32, size: u64) -> Result<(u64, usize)> {
    let count = chunk_count(size)?;
    if index >= count {
        return Err(Error::Protocol(format!(
            "chunk {index} is out of range for a {size} byte file ({count} chunks)"
        )));
    }

    let offset = index as u64 * CHUNK_SIZE;
    let len = CHUNK_SIZE.min(size - offset) as usize;
    Ok((offset, len))
}

/// A half-open run of chunk indices, `start..end`.
///
/// Runs rather than individual indices because a need-set is overwhelmingly
/// contiguous: "I have the first 4,000 chunks, send me 4,000 onward" is one
/// range instead of thousands of integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRange {
    pub start: u32,
    pub end: u32,
}

impl ChunkRange {
    pub fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }

    pub fn len(&self) -> u32 {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    pub fn contains(&self, index: u32) -> bool {
        index >= self.start && index < self.end
    }

    pub fn iter(&self) -> impl Iterator<Item = u32> + use<> {
        self.start..self.end
    }
}

/// Which chunks of a file are present and verified.
///
/// One bit per chunk: a 100 GB file costs 12.5 KB of bitmap, so tracking every
/// chunk of a very large transfer is free compared with the data itself.
#[derive(Clone, PartialEq, Eq)]
pub struct ChunkMap {
    bits: Vec<u8>,
    len: u32,
    present: u32,
}

impl ChunkMap {
    /// An empty map for a file of `len` chunks — nothing received yet.
    pub fn empty(len: u32) -> Self {
        Self {
            bits: vec![0; len.div_ceil(8) as usize],
            len,
            present: 0,
        }
    }

    /// A map with every chunk marked present.
    pub fn complete(len: u32) -> Self {
        let mut map = Self::empty(len);
        for index in 0..len {
            map.insert(index);
        }
        map
    }

    pub fn len(&self) -> u32 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn contains(&self, index: u32) -> bool {
        if index >= self.len {
            return false;
        }
        let (byte, bit) = locate(index);
        self.bits[byte] & bit != 0
    }

    /// Mark a chunk present. Returns `true` if this changed anything, so a
    /// caller can tell a fresh chunk from a duplicate retransmission.
    pub fn insert(&mut self, index: u32) -> bool {
        if index >= self.len || self.contains(index) {
            return false;
        }
        let (byte, bit) = locate(index);
        self.bits[byte] |= bit;
        self.present += 1;
        true
    }

    /// Mark a chunk missing again — used when verification fails and the chunk
    /// has to be re-requested.
    pub fn remove(&mut self, index: u32) -> bool {
        if !self.contains(index) {
            return false;
        }
        let (byte, bit) = locate(index);
        self.bits[byte] &= !bit;
        self.present -= 1;
        true
    }

    pub fn present_count(&self) -> u32 {
        self.present
    }

    pub fn missing_count(&self) -> u32 {
        self.len - self.present
    }

    pub fn is_complete(&self) -> bool {
        self.present == self.len
    }

    /// Bytes of this file already on disk, given its total size.
    ///
    /// Exact rather than `present * CHUNK_SIZE`, because the last chunk is
    /// usually short and a progress bar that overshoots looks broken.
    pub fn bytes_present(&self, size: u64) -> u64 {
        let full_chunks = if self.len > 0 && self.contains(self.len - 1) {
            self.present - 1
        } else {
            self.present
        };

        let mut total = full_chunks as u64 * CHUNK_SIZE;
        if self.len > 0 && self.contains(self.len - 1) {
            let last_offset = (self.len - 1) as u64 * CHUNK_SIZE;
            total += size - last_offset;
        }
        total
    }

    /// The chunks still needed, coalesced into contiguous runs.
    pub fn missing_ranges(&self) -> Vec<ChunkRange> {
        let mut ranges = Vec::new();
        let mut run_start: Option<u32> = None;

        for index in 0..self.len {
            match (self.contains(index), run_start) {
                (false, None) => run_start = Some(index),
                (true, Some(start)) => {
                    ranges.push(ChunkRange::new(start, index));
                    run_start = None;
                }
                _ => {}
            }
        }
        if let Some(start) = run_start {
            ranges.push(ChunkRange::new(start, self.len));
        }
        ranges
    }

    /// Serialize for persistence alongside the partial file.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bits
    }

    /// Restore a persisted map.
    ///
    /// `len` comes from the manifest, not the file, so a truncated or padded
    /// bitmap is caught here instead of silently mis-describing the download.
    /// Bits past `len` are treated as corruption rather than ignored: they mean
    /// the bitmap and the manifest disagree, and continuing would produce a
    /// wrong `present` count.
    pub fn from_bytes(len: u32, bytes: &[u8]) -> Result<Self> {
        let expected = len.div_ceil(8) as usize;
        if bytes.len() != expected {
            return Err(Error::Protocol(format!(
                "chunk bitmap is {} bytes but {len} chunks need {expected}",
                bytes.len()
            )));
        }

        // Bits in the final byte beyond `len` must be zero.
        if !len.is_multiple_of(8)
            && let Some(&last) = bytes.last()
        {
            let valid_mask = (1u16 << (len % 8)) as u8 - 1;
            if last & !valid_mask != 0 {
                return Err(Error::Protocol(
                    "chunk bitmap has bits set past the end of the file".into(),
                ));
            }
        }

        let present = bytes.iter().map(|b| b.count_ones()).sum();
        Ok(Self {
            bits: bytes.to_vec(),
            len,
            present,
        })
    }
}

impl std::fmt::Debug for ChunkMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChunkMap({}/{} chunks)", self.present, self.len)
    }
}

/// Bit `index` lives in byte `index / 8`, least significant bit first.
const fn locate(index: u32) -> (usize, u8) {
    ((index / 8) as usize, 1u8 << (index % 8))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_counts_round_up_and_zero_is_chunkless() {
        assert_eq!(chunk_count(0).unwrap(), 0);
        assert_eq!(chunk_count(1).unwrap(), 1);
        assert_eq!(chunk_count(CHUNK_SIZE).unwrap(), 1);
        assert_eq!(chunk_count(CHUNK_SIZE + 1).unwrap(), 2);
        assert_eq!(chunk_count(CHUNK_SIZE * 10).unwrap(), 10);
        assert_eq!(chunk_count(CHUNK_SIZE * 10 - 1).unwrap(), 10);
    }

    #[test]
    fn spans_tile_the_file_exactly() {
        // The property that matters: chunk spans must cover every byte once,
        // with no gap and no overlap, including a short final chunk.
        for size in [1, 1023, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, CHUNK_SIZE * 3 + 7] {
            let count = chunk_count(size).unwrap();
            let mut covered = 0u64;

            for index in 0..count {
                let (offset, len) = chunk_span(index, size).unwrap();
                assert_eq!(offset, covered, "gap or overlap at chunk {index} of {size}");
                covered += len as u64;
            }
            assert_eq!(covered, size, "spans did not cover all of a {size} byte file");
        }
    }

    #[test]
    fn spans_reject_out_of_range_indices() {
        assert!(chunk_span(0, 0).is_err(), "a zero-byte file has no chunk 0");
        assert!(chunk_span(1, CHUNK_SIZE).is_err());
        assert!(chunk_span(u32::MAX, 100).is_err());
    }

    #[test]
    fn oversized_files_are_refused_rather_than_wrapping() {
        assert!(chunk_count(MAX_FILE_SIZE).is_ok());
        assert!(chunk_count(MAX_FILE_SIZE + 1).is_err());
    }

    #[test]
    fn bitmap_tracks_presence() {
        let mut map = ChunkMap::empty(10);
        assert_eq!(map.present_count(), 0);
        assert_eq!(map.missing_count(), 10);
        assert!(!map.is_complete());

        assert!(map.insert(3));
        assert!(!map.insert(3), "re-inserting is a no-op");
        assert!(map.contains(3));
        assert!(!map.contains(4));
        assert_eq!(map.present_count(), 1);

        assert!(map.remove(3));
        assert!(!map.remove(3));
        assert_eq!(map.present_count(), 0);
    }

    #[test]
    fn out_of_range_indices_are_ignored_not_panics() {
        let mut map = ChunkMap::empty(4);
        assert!(!map.contains(99));
        assert!(!map.insert(99));
        assert!(!map.remove(99));
        assert_eq!(map.present_count(), 0);
    }

    #[test]
    fn complete_map_is_complete() {
        let map = ChunkMap::complete(17);
        assert!(map.is_complete());
        assert_eq!(map.present_count(), 17);
        assert!(map.missing_ranges().is_empty());
    }

    #[test]
    fn missing_ranges_coalesce_into_runs() {
        let mut map = ChunkMap::empty(10);
        for index in [0, 1, 2, 5, 9] {
            map.insert(index);
        }

        assert_eq!(
            map.missing_ranges(),
            vec![ChunkRange::new(3, 5), ChunkRange::new(6, 9)]
        );
    }

    #[test]
    fn missing_ranges_cover_the_whole_file_when_empty() {
        assert_eq!(
            ChunkMap::empty(5).missing_ranges(),
            vec![ChunkRange::new(0, 5)]
        );
        assert!(ChunkMap::empty(0).missing_ranges().is_empty());
    }

    #[test]
    fn resume_after_an_interruption_asks_only_for_the_tail() {
        // The core resume scenario: a transfer died partway, and the map must
        // describe exactly the remainder.
        let total = 1000;
        let mut map = ChunkMap::empty(total);
        for index in 0..600 {
            map.insert(index);
        }

        assert_eq!(map.missing_ranges(), vec![ChunkRange::new(600, 1000)]);
        assert_eq!(map.missing_count(), 400);
    }

    #[test]
    fn byte_progress_accounts_for_a_short_final_chunk() {
        let size = CHUNK_SIZE * 2 + 500;
        let mut map = ChunkMap::empty(chunk_count(size).unwrap());

        assert_eq!(map.bytes_present(size), 0);
        map.insert(0);
        assert_eq!(map.bytes_present(size), CHUNK_SIZE);
        map.insert(2); // the 500-byte tail
        assert_eq!(map.bytes_present(size), CHUNK_SIZE + 500);
        map.insert(1);
        assert_eq!(map.bytes_present(size), size, "a complete map reports the full size");
    }

    #[test]
    fn bitmap_survives_a_persistence_round_trip() {
        let mut original = ChunkMap::empty(100);
        for index in [0, 7, 8, 63, 64, 99] {
            original.insert(index);
        }

        let restored = ChunkMap::from_bytes(100, original.to_bytes()).unwrap();
        assert_eq!(restored, original);
        assert_eq!(restored.present_count(), 6);
        assert_eq!(restored.missing_ranges(), original.missing_ranges());
    }

    #[test]
    fn corrupt_bitmaps_are_rejected() {
        let map = ChunkMap::empty(100);

        assert!(
            ChunkMap::from_bytes(100, &map.to_bytes()[..5]).is_err(),
            "truncated bitmap"
        );
        assert!(
            ChunkMap::from_bytes(200, map.to_bytes()).is_err(),
            "bitmap that disagrees with the manifest's chunk count"
        );

        // 12 chunks occupy 2 bytes; bits 12..16 must be zero.
        assert!(ChunkMap::from_bytes(12, &[0xFF, 0x0F]).is_ok());
        assert!(
            ChunkMap::from_bytes(12, &[0xFF, 0xFF]).is_err(),
            "bits past the end of the file must be rejected"
        );
    }

    #[test]
    fn ranges_behave() {
        let range = ChunkRange::new(5, 9);
        assert_eq!(range.len(), 4);
        assert!(!range.is_empty());
        assert!(range.contains(5) && range.contains(8));
        assert!(!range.contains(4) && !range.contains(9));
        assert_eq!(range.iter().collect::<Vec<_>>(), vec![5, 6, 7, 8]);

        let empty = ChunkRange::new(7, 7);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(ChunkRange::new(9, 5).len(), 0, "inverted ranges are empty, not negative");
    }
}
