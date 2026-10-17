//! Crash-safe staging for an in-progress receive.
//!
//! Incoming data lands in `<destination>/.jetstream/<transfer-id>/` and only
//! moves into place once a file is complete and its hash checks out. Staging
//! lives *inside* the destination on purpose: the final move is then a rename
//! within one volume, which is atomic and instant, rather than a copy across
//! filesystems that could itself be interrupted.
//!
//! # What survives a power cut
//!
//! Each partial file has a chunk bitmap beside it. The invariant that makes
//! resume trustworthy is **the bitmap never claims more than the data file
//! holds** — so a checkpoint always flushes file data before the bitmap that
//! describes it. Crashing between the two loses a little progress, which is
//! re-requested. Crashing in the other order would silently skip chunks, and
//! the corruption would only surface as a whole-file hash failure at the very
//! end.
//!
//! Bitmaps are checkpointed every [`CHECKPOINT_INTERVAL`] chunks rather than on
//! every chunk: flushing a 12 KB bitmap after each 1 MiB chunk would add
//! measurable write amplification to buy back a second of re-transfer.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::chunk::{self, ChunkMap, ChunkRange};
use crate::error::{Error, Result};
use crate::manifest::{Entry, EntryKind, Manifest, system_time_from_unix};
use crate::path::to_extended_length;

/// Directory created inside the destination to hold in-progress work.
pub const STAGING_DIR: &str = ".jetstream";

/// Chunks written between bitmap checkpoints.
///
/// 64 MiB of re-transfer is the worst case after an unclean shutdown.
const CHECKPOINT_INTERVAL: u32 = 64;

/// Files smaller than this get no persisted chunk bitmap.
///
/// A bitmap exists to avoid re-sending data after an interruption, and every
/// checkpoint costs an `fsync` of the data plus an atomic write of the bitmap.
/// For a file this small the trade is backwards: the fsyncs cost more than the
/// re-transfer they save.
///
/// Measured, not guessed. Transferring 2,000 files of 131 KiB ran at 6.3 MB/s —
/// 20 ms per file — and almost all of it was fsync latency, not network or
/// bandwidth. Small files are the shape Dukto handles worst, so this is the
/// case worth getting right.
///
/// The effect on resume is that a small file's granularity becomes the whole
/// file rather than a chunk, which is the correct granularity for something
/// that re-transfers in a few milliseconds. Completed files are still recorded
/// as delivered, so an interrupted transfer of many small files only loses the
/// few that were in flight.
const BITMAP_THRESHOLD: u64 = 8 * 1024 * 1024;

/// Open file handles kept warm.
///
/// Small on purpose: the receiver works through files roughly in order, so a
/// handful of handles catches nearly every write while leaving plenty of
/// headroom under the process handle limit on a 50,000-file transfer.
const HANDLE_CACHE: usize = 8;

/// What to do when a file already exists at the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConflictPolicy {
    /// Keep both, adding ` (2)` before the extension. The safe default: a
    /// transfer should never destroy something the user already had.
    #[default]
    Rename,
    Overwrite,
    Skip,
}

/// Outcome of placing one completed file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    Created(PathBuf),
    Renamed(PathBuf),
    Overwritten(PathBuf),
    Skipped(PathBuf),
}

/// Counts of what a transfer did, for reporting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PlacementTally {
    pub created: usize,
    pub renamed: usize,
    pub overwritten: usize,
    pub skipped: usize,
}

impl PlacementTally {
    pub fn of(placements: &[Placement]) -> Self {
        let mut tally = Self::default();
        for placement in placements {
            match placement {
                Placement::Created(_) => tally.created += 1,
                Placement::Renamed(_) => tally.renamed += 1,
                Placement::Overwritten(_) => tally.overwritten += 1,
                Placement::Skipped(_) => tally.skipped += 1,
            }
        }
        tally
    }

    /// One line saying what actually happened.
    ///
    /// Worth spelling out rather than reporting a single total. A recovery run
    /// over a folder that is mostly already there places almost nothing and skips
    /// almost everything, and "128,773 items saved" would be a lie about both —
    /// it counted skipped files as saved. The breakdown is also the confirmation
    /// a user wants: that the files they already had were left alone.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        let plural = |n: usize| if n == 1 { "" } else { "s" };

        if self.created > 0 {
            parts.push(format!("{} file{} saved", self.created, plural(self.created)));
        }
        if self.renamed > 0 {
            parts.push(format!("{} kept as a second copy", self.renamed));
        }
        if self.overwritten > 0 {
            parts.push(format!("{} replaced", self.overwritten));
        }
        if self.skipped > 0 {
            parts.push(format!(
                "{} already present, left alone",
                self.skipped
            ));
        }

        if parts.is_empty() {
            "nothing to save".to_string()
        } else {
            parts.join(" · ")
        }
    }
}

/// An in-progress receive.
pub struct Staging {
    root: PathBuf,
    destination: PathBuf,
    manifest: Manifest,
    /// Bitmap per manifest entry index. Non-file entries get an empty map.
    maps: Vec<ChunkMap>,
    /// Chunks written since each file's last bitmap checkpoint.
    pending: Vec<u32>,
    /// Entries already verified and moved into the destination.
    ///
    /// Persisted, and that matters: a file's chunk bitmap is deleted once it is
    /// delivered, so without this record a resumed transfer would see no
    /// bitmap, conclude the file was never received, fetch it again, and — with
    /// the default rename policy — deliver a second copy beside the first.
    placed: ChunkMap,
    /// Entries the destination already has, under [`ConflictPolicy::Skip`].
    ///
    /// Computed once when staging opens, and the whole point is *when*. The skip
    /// used to be applied at delivery: every byte was pulled across the network,
    /// hashed, verified — and then the finished file was deleted because
    /// something was already there. "Skip the incoming file" cost exactly as much
    /// as accepting it.
    ///
    /// Deciding up front instead turns Skip into what it reads like, and makes it
    /// a way to recover a transfer whose staging directory is gone but whose
    /// delivered files are not: everything already present is simply not asked
    /// for.
    ///
    /// **Not persisted**, unlike `placed`. This is an observation about the
    /// destination right now, not a record of something we did, and it must be
    /// recomputed on each attempt in case the user changed the policy or the
    /// files.
    skipped: ChunkMap,
    /// Hash of the single chunk, for files that fit in one.
    ///
    /// Lets delivery skip re-reading the file to compute a whole-file hash it
    /// already knows. See [`Staging::finish_single_chunk_file`].
    single_chunk_hashes: Vec<Option<[u8; 32]>>,
    handles: HashMap<u32, File>,
    handle_order: Vec<u32>,
    conflict: ConflictPolicy,
    /// Size at or above which a file's progress is persisted.
    ///
    /// Adjustable because the trade differs sharply by transport. On a LAN,
    /// re-sending a few megabytes is faster than the fsyncs that would have
    /// saved it. Over a phone's uplink it is not, so the browser path lowers
    /// this to zero and accepts the write cost.
    bitmap_threshold: u64,
}

impl Staging {
    /// Open the staging area for `manifest` under `destination`, resuming any
    /// work already there.
    ///
    /// The transfer id is the manifest digest, so re-offering an unchanged tree
    /// finds the same directory and picks up where it stopped.
    pub fn open(destination: &Path, manifest: Manifest, conflict: ConflictPolicy) -> Result<Self> {
        Self::open_with(destination, manifest, conflict, BITMAP_THRESHOLD)
    }

    /// Open with progress persisted for **every** file, however small.
    ///
    /// For transports where re-sending is expensive — a phone uploading over a
    /// slow, flaky link — chunk-level resume is worth an fsync per checkpoint.
    /// The native LAN path uses [`Staging::open`] instead, where re-sending a few
    /// megabytes is faster than the fsyncs that would have saved it.
    ///
    /// A constructor rather than a setter because the threshold decides which
    /// bitmaps are read at open time; changing it afterwards would silently do
    /// nothing on a resumed transfer.
    pub fn open_tracking_all(
        destination: &Path,
        manifest: Manifest,
        conflict: ConflictPolicy,
    ) -> Result<Self> {
        Self::open_with(destination, manifest, conflict, 0)
    }

    fn open_with(
        destination: &Path,
        manifest: Manifest,
        conflict: ConflictPolicy,
        bitmap_threshold: u64,
    ) -> Result<Self> {
        manifest.validate()?;

        let transfer_id = hex::encode(manifest.digest());
        let root = destination.join(STAGING_DIR).join(&transfer_id);

        fs::create_dir_all(root.join("p"))?;
        fs::create_dir_all(root.join("m"))?;

        let entry_count = manifest.entries.len();
        let placed_path = root.join("placed");
        let placed = match fs::read(to_extended_length(&placed_path)) {
            Ok(bytes) => decode_map(&bytes, entry_count as u32).unwrap_or_else(|e| {
                // Losing this record is not dangerous, only wasteful: files
                // already delivered would be fetched again.
                tracing::warn!(error = %e, "delivery record unreadable; some files may be re-fetched");
                ChunkMap::empty(entry_count as u32)
            }),
            Err(_) => ChunkMap::empty(entry_count as u32),
        };

        let mut staging = Self {
            root,
            destination: destination.to_path_buf(),
            manifest,
            maps: Vec::with_capacity(entry_count),
            pending: vec![0; entry_count],
            placed,
            skipped: ChunkMap::empty(entry_count as u32),
            single_chunk_hashes: vec![None; entry_count],
            handles: HashMap::new(),
            handle_order: Vec::new(),
            conflict,
            bitmap_threshold,
        };

        staging.load_or_create_maps()?;
        staging.note_existing_to_skip();
        Ok(staging)
    }

    /// Under `Skip`, mark every entry the destination already has.
    ///
    /// Uses the same test as delivery — plain existence — so the plan and the
    /// placement can never disagree about what would have been skipped.
    fn note_existing_to_skip(&mut self) {
        if self.conflict != ConflictPolicy::Skip {
            return;
        }

        for (index, entry) in self.manifest.entries.iter().enumerate() {
            if !entry.is_file() {
                continue;
            }
            let target = to_extended_length(&entry.path.resolve_in(&self.destination));
            if target.exists() {
                self.skipped.insert(index as u32);
            }
        }

        // `present_count`, not `len` — `ChunkMap::len` is the map's capacity, and
        // using it here reported every entry as skipped.
        let count = self.skipped.present_count();
        if count > 0 {
            tracing::info!(count, "files already at the destination will not be requested");
        }
    }

    /// Whether this entry is being skipped because the destination has it.
    pub fn is_skipped(&self, index: u32) -> bool {
        self.skipped.contains(index)
    }

    /// How many entries are being skipped.
    pub fn skipped_count(&self) -> u64 {
        self.skipped.present_count() as u64
    }

    /// Record that an entry has been delivered, durably.
    ///
    /// Written straight after the rename rather than batched, so the window in
    /// which a crash could cause a duplicate delivery is a single file
    /// operation wide.
    fn mark_placed(&mut self, index: u32) -> Result<()> {
        if !self.placed.insert(index) {
            return Ok(());
        }
        write_atomically(&self.root.join("placed"), &encode_map(&self.placed))
    }

    fn load_or_create_maps(&mut self) -> Result<()> {
        for index in 0..self.manifest.entries.len() {
            let entry = &self.manifest.entries[index];
            let chunks = entry.chunk_count()?;

            let map = match self.read_map(index as u32, chunks) {
                Ok(Some(map)) => map,
                Ok(None) => ChunkMap::empty(chunks),
                Err(e) => {
                    // A corrupt bitmap is recoverable: forget it and re-fetch
                    // the file. Far better than trusting it and producing a
                    // file that only fails verification at the end.
                    tracing::warn!(
                        index,
                        path = %entry.path,
                        error = %e,
                        "discarding an unreadable chunk bitmap; this file will restart"
                    );
                    let _ = fs::remove_file(self.map_path(index as u32));
                    let _ = fs::remove_file(self.part_path(index as u32));
                    ChunkMap::empty(chunks)
                }
            };
            self.maps.push(map);
        }
        Ok(())
    }

    fn read_map(&self, index: u32, chunks: u32) -> Result<Option<ChunkMap>> {
        // Small files never persist one, so there is nothing to look for.
        if !self.tracks_progress(index) {
            return Ok(None);
        }

        let bytes = match fs::read(to_extended_length(&self.map_path(index))) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        decode_map(&bytes, chunks).map(Some)
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn transfer_id(&self) -> String {
        hex::encode(self.manifest.digest())
    }

    pub fn chunk_map(&self, index: u32) -> Option<&ChunkMap> {
        self.maps.get(index as usize)
    }

    /// Whether this file is fully staged (all chunks present) but not yet
    /// verified and moved.
    pub fn is_file_complete(&self, index: u32) -> bool {
        self.maps
            .get(index as usize)
            .is_some_and(ChunkMap::is_complete)
    }

    pub fn is_placed(&self, index: u32) -> bool {
        self.placed.contains(index)
    }

    /// Bytes already staged across the whole transfer — what a progress bar
    /// should show on resume, before a single new byte arrives.
    pub fn bytes_present(&self) -> u64 {
        self.manifest
            .entries
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                // A skipped file counts as fully here — it is, just not because
                // we put it there. Without this a Skip run would report 0%
                // throughout while correctly transferring nothing.
                //
                // Likewise a file already delivered by an earlier attempt. Its
                // bitmap is deleted once it is placed, so the map alone says
                // nothing is here — and a resumed transfer started from far below
                // where it really was, then finished well short of 100%.
                if self.skipped.contains(i as u32) || self.placed.contains(i as u32) {
                    return entry.size();
                }
                self.maps
                    .get(i)
                    .map(|map| map.bytes_present(entry.size()))
                    .unwrap_or(0)
            })
            .sum()
    }

    /// Files already complete on disk, staged or delivered.
    ///
    /// The file-count equivalent of [`Staging::bytes_present`], so a resumed
    /// transfer can report "199 of 128773 already here" instead of starting its
    /// counter at zero.
    pub fn files_present(&self) -> u64 {
        self.manifest
            .entries
            .iter()
            .enumerate()
            .filter(|(i, entry)| {
                if !entry.is_file() {
                    return false;
                }
                if self.skipped.contains(*i as u32) || self.placed.contains(*i as u32) {
                    return true;
                }
                let size = entry.size();
                self.maps
                    .get(*i)
                    .map(|map| map.bytes_present(size) == size)
                    .unwrap_or(false)
            })
            .count() as u64
    }

    /// What still needs to be fetched, as `(entry index, chunk range)` pairs.
    ///
    /// This *is* the resume computation: the receiver's entire request plan,
    /// derived from what is on disk rather than from anything remembered
    /// in memory or trusted from the sender.
    pub fn outstanding(&self) -> Vec<(u32, ChunkRange)> {
        let mut work = Vec::new();
        for &index in &self.manifest.transfer_order() {
            // Nothing to ask for: already delivered, or already at the
            // destination and the policy says leave it alone.
            if self.is_placed(index) || self.is_skipped(index) {
                continue;
            }
            if let Some(map) = self.maps.get(index as usize) {
                work.extend(map.missing_ranges().into_iter().map(|range| (index, range)));
            }
        }
        work
    }

    pub fn is_complete(&self) -> bool {
        self.manifest.entries.iter().enumerate().all(|(i, entry)| {
            !entry.is_file()
                || self.placed.contains(i as u32)
                || self.skipped.contains(i as u32)
                || self.maps[i].is_complete()
        })
    }

    /// Verify and store one chunk.
    ///
    /// The hash is checked *before* the write, so a corrupt chunk never touches
    /// the partial file — the bitmap and the data can therefore never disagree
    /// about content, only about how much of it is there.
    pub fn write_chunk(&mut self, index: u32, chunk_index: u32, data: &[u8], hash: &[u8; 32]) -> Result<bool> {
        let entry = self
            .manifest
            .entries
            .get(index as usize)
            .ok_or_else(|| Error::Protocol(format!("chunk for unknown entry {index}")))?;

        if !entry.is_file() {
            return Err(Error::Protocol(format!(
                "peer sent chunk data for non-file entry {:?}",
                entry.path.as_str()
            )));
        }

        let size = entry.size();
        let (offset, expected_len) = chunk::chunk_span(chunk_index, size)?;
        if data.len() != expected_len {
            return Err(Error::Protocol(format!(
                "chunk {chunk_index} of {:?} should be {expected_len} bytes, got {}",
                entry.path.as_str(),
                data.len()
            )));
        }

        let actual = blake3::hash(data);
        if actual.as_bytes() != hash {
            return Err(Error::Protocol(format!(
                "chunk {chunk_index} of {:?} failed its hash check",
                entry.path.as_str()
            )));
        }

        if self.maps[index as usize].contains(chunk_index) {
            // A duplicate from an overlapping re-request. Harmless, and worth
            // reporting so the caller does not double-count progress.
            return Ok(false);
        }

        let file = self.handle(index, size)?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)?;

        self.maps[index as usize].insert(chunk_index);
        self.pending[index as usize] += 1;

        // A file of one chunk needs no separate whole-file hash.
        if self.maps[index as usize].len() == 1 {
            self.single_chunk_hashes[index as usize] = Some(*hash);
        }

        if self.pending[index as usize] >= CHECKPOINT_INTERVAL {
            self.checkpoint(index)?;
        }

        Ok(true)
    }

    /// Whether this file's progress is worth persisting. See
    /// [`BITMAP_THRESHOLD`].
    fn tracks_progress(&self, index: u32) -> bool {
        self.manifest
            .entries
            .get(index as usize)
            .is_some_and(|entry| entry.size() >= self.bitmap_threshold)
    }

    /// Flush a file's data and then its bitmap, in that order.
    ///
    /// A no-op for small files, whose resume granularity is the whole file.
    pub fn checkpoint(&mut self, index: u32) -> Result<()> {
        if !self.tracks_progress(index) {
            self.pending[index as usize] = 0;
            return Ok(());
        }

        if let Some(file) = self.handles.get_mut(&index) {
            // Durability before the bitmap that claims it. Reversing these two
            // is the difference between "lost a little progress" and "silently
            // skipped a chunk".
            file.sync_data()?;
        }

        let encoded = encode_map(&self.maps[index as usize]);
        write_durably(&self.map_path(index), &encoded)?;
        self.pending[index as usize] = 0;
        Ok(())
    }

    /// Checkpoint every file with chunks written since its last checkpoint.
    ///
    /// For a receive that stops early. Periodic checkpoints only happen every
    /// [`CHECKPOINT_INTERVAL`] chunks, so without this an interruption threw away
    /// up to 64 MiB per file — for any file smaller than that, everything it had
    /// received — and the resume fetched it all again.
    pub fn checkpoint_all(&mut self) -> Result<()> {
        let dirty: Vec<u32> = self
            .pending
            .iter()
            .enumerate()
            .filter(|(_, pending)| **pending > 0)
            .map(|(index, _)| index as u32)
            .collect();

        for index in dirty {
            self.checkpoint(index)?;
        }
        Ok(())
    }

    /// Deliver a file that occupies exactly one chunk, without re-reading it.
    ///
    /// For a file no larger than one chunk, the whole-file BLAKE3 *is* the hash
    /// of that single chunk — same bytes, same hash. The chunk was already
    /// verified against the sender's hash on arrival, so the file is already
    /// proven and re-reading it to hash again proves nothing.
    ///
    /// This is not a shortcut around verification; it is the observation that
    /// the verification already happened. The whole-file hash exists to catch
    /// *assembly* errors — chunks written in the wrong order, a gap, a
    /// duplicate — and a file made of one chunk has no assembly to get wrong.
    ///
    /// It removes, per small file: one whole-file read here, one on the sender,
    /// and one network round trip. On a transfer of thousands of small files
    /// that is most of the cost.
    ///
    /// Fails if no verified chunk was recorded for this entry in this session,
    /// which is the caller's cue to use [`Staging::finish_file`] with a real
    /// whole-file hash instead.
    pub fn finish_single_chunk_file(&mut self, index: u32) -> Result<Placement> {
        if self.single_chunk_hashes.get(index as usize).copied().flatten().is_none() {
            return Err(Error::Protocol(format!(
                "entry {index} has no verified chunk recorded in this session"
            )));
        }

        self.close_handle(index);
        let part = self.part_path(index);
        let placement = self.place(index, &part)?;
        self.mark_placed(index)?;
        Ok(placement)
    }

    /// Verify a completed file against its whole-file hash and move it into
    /// the destination.
    ///
    /// On mismatch the staged data is discarded and the bitmap cleared, so the
    /// file is re-requested from scratch rather than left as plausible-looking
    /// corruption.
    pub fn finish_file(&mut self, index: u32, expected_hash: &[u8; 32]) -> Result<Placement> {
        let actual = self.hash_staged_file(index, &mut |_| {})?;
        self.place_verified(index, &actual, expected_hash)
    }

    /// Read a fully staged file back and hash it, reporting bytes read as it goes.
    ///
    /// The first half of [`Staging::finish_file`], split out so the slow part -
    /// reading the whole file - can overlap with the other device reading its
    /// copy, and can report progress instead of looking like a stall.
    pub fn hash_staged_file(&mut self, index: u32, on_read: &mut dyn FnMut(u64)) -> Result<[u8; 32]> {
        if !self.is_file_complete(index) {
            return Err(Error::Protocol(format!(
                "entry {index} is not fully staged yet"
            )));
        }

        self.checkpoint(index)?;
        self.close_handle(index);
        hash_file_reporting(&self.part_path(index), on_read)
    }

    /// The second half of [`Staging::finish_file`]: compare, then deliver or
    /// discard. Takes the hash [`Staging::hash_staged_file`] computed.
    pub fn place_verified(
        &mut self,
        index: u32,
        actual: &[u8; 32],
        expected_hash: &[u8; 32],
    ) -> Result<Placement> {
        let part = self.part_path(index);
        if actual != expected_hash {
            tracing::warn!(
                index,
                path = %self.manifest.entries[index as usize].path,
                "whole-file hash mismatch; discarding and re-requesting"
            );
            self.reset_file(index)?;
            return Err(Error::Protocol(format!(
                "{:?} failed verification after reassembly",
                self.manifest.entries[index as usize].path.as_str()
            )));
        }

        let placement = self.place(index, &part)?;
        self.mark_placed(index)?;
        let _ = fs::remove_file(self.map_path(index));
        Ok(placement)
    }

    /// Deliver a file that was verified chunk by chunk but has no whole-file
    /// digest to check against.
    ///
    /// **Weaker than [`Staging::finish_file`], and only for the browser upload
    /// path.** A page served over plain HTTP cannot compute BLAKE3: there is no
    /// secure context, so `crypto.subtle` is unavailable, and it only offers
    /// SHA-2 anyway. Browser uploads therefore carry a per-chunk CRC-32
    /// computed in JavaScript, which catches transmission corruption end to end
    /// but gives no cryptographic guarantee and no check that the reassembled
    /// whole matches the original.
    ///
    /// Native transfers must never use this. The distinction is a separate
    /// method rather than an `Option` argument precisely so that using the weak
    /// path is a visible, deliberate choice at the call site.
    pub fn finish_file_chunkwise(&mut self, index: u32) -> Result<Placement> {
        if !self.is_file_complete(index) {
            return Err(Error::Protocol(format!(
                "entry {index} is not fully staged yet"
            )));
        }

        self.checkpoint(index)?;
        self.close_handle(index);

        let part = self.part_path(index);
        let placement = self.place(index, &part)?;
        self.mark_placed(index)?;
        let _ = fs::remove_file(self.map_path(index));
        Ok(placement)
    }

    /// Throw away everything staged for one file.
    pub fn reset_file(&mut self, index: u32) -> Result<()> {
        self.close_handle(index);
        let _ = fs::remove_file(self.part_path(index));
        let _ = fs::remove_file(self.map_path(index));

        let chunks = self.manifest.entries[index as usize].chunk_count()?;
        self.maps[index as usize] = ChunkMap::empty(chunks);
        self.pending[index as usize] = 0;
        Ok(())
    }

    /// Move a verified file into the destination, applying the conflict policy.
    fn place(&mut self, index: u32, part: &Path) -> Result<Placement> {
        let entry = &self.manifest.entries[index as usize];
        let target = entry.path.resolve_in(&self.destination);

        if let Some(parent) = target.parent() {
            fs::create_dir_all(to_extended_length(parent))?;
        }

        let long_target = to_extended_length(&target);
        let exists = long_target.exists();

        let (final_path, placement) = match (exists, self.conflict) {
            (false, _) => (long_target.clone(), Placement::Created(target.clone())),
            (true, ConflictPolicy::Skip) => {
                let _ = fs::remove_file(part);
                return Ok(Placement::Skipped(target));
            }
            (true, ConflictPolicy::Overwrite) => {
                (long_target.clone(), Placement::Overwritten(target.clone()))
            }
            (true, ConflictPolicy::Rename) => {
                let renamed = next_available_name(&target)?;
                (to_extended_length(&renamed), Placement::Renamed(renamed))
            }
        };

        // Same volume, so this is atomic: the file appears complete or not at
        // all, never half-written.
        fs::rename(to_extended_length(part), &final_path)?;
        apply_metadata(&final_path, entry);

        Ok(placement)
    }

    /// Create directories, restore modification times, and remove the staging
    /// area.
    ///
    /// Directory mtimes are set last because moving files into a directory
    /// updates it.
    pub fn finish(mut self) -> Result<Vec<Placement>> {
        // A placeholder has nothing to do and no directories to remove.
        if self.root.as_os_str().is_empty() {
            return Ok(Vec::new());
        }

        let mut placements = Vec::new();

        // Directories first, so empty ones survive and files have somewhere to
        // land. Manifest order guarantees a parent precedes its children.
        for entry in &self.manifest.entries {
            if matches!(entry.kind, EntryKind::Directory) {
                let path = entry.path.resolve_in(&self.destination);
                fs::create_dir_all(to_extended_length(&path))?;
            }
        }

        // Zero-byte files carry no chunks, so they are created here rather
        // than arriving through the data path.
        for index in 0..self.manifest.entries.len() as u32 {
            let entry = &self.manifest.entries[index as usize];
            if entry.is_file() && entry.size() == 0 && !self.placed.contains(index) {
                let target = entry.path.resolve_in(&self.destination);
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(to_extended_length(parent))?;
                }
                let long_target = to_extended_length(&target);
                if !long_target.exists() || self.conflict == ConflictPolicy::Overwrite {
                    File::create(&long_target)?;
                    apply_metadata(&long_target, entry);
                    placements.push(Placement::Created(target));
                }
                self.mark_placed(index)?;
            }
        }

        // Report what was left alone. Returning nothing for a skipped file would
        // make a transfer that skipped a thousand of them look like it did
        // nothing at all, and the caller could not tell success from silence.
        for index in 0..self.manifest.entries.len() as u32 {
            if self.skipped.contains(index) {
                let entry = &self.manifest.entries[index as usize];
                placements.push(Placement::Skipped(entry.path.resolve_in(&self.destination)));
            }
        }

        for entry in &self.manifest.entries {
            if matches!(entry.kind, EntryKind::Directory) {
                let path = to_extended_length(&entry.path.resolve_in(&self.destination));
                apply_metadata(&path, entry);
            }
        }

        self.handles.clear();
        self.handle_order.clear();

        // Best effort: leaving an empty staging directory behind is untidy but
        // never wrong, and failing the whole transfer over it would be absurd.
        let _ = fs::remove_dir_all(&self.root);
        let _ = fs::remove_dir(self.destination.join(STAGING_DIR));

        Ok(placements)
    }

    /// An inert `Staging` used only to move a real one out of a `&mut` slot.
    ///
    /// `finish` consumes `self`, and the writer thread holds staging in a
    /// mutable binding, so there has to be something to leave behind. This never
    /// touches the disk: it has no entries, so every operation on it is a no-op.
    pub(crate) fn placeholder() -> Self {
        Self {
            root: PathBuf::new(),
            destination: PathBuf::new(),
            manifest: Manifest::default(),
            maps: Vec::new(),
            pending: Vec::new(),
            placed: ChunkMap::empty(0),
            skipped: ChunkMap::empty(0),
            single_chunk_hashes: Vec::new(),
            handles: HashMap::new(),
            handle_order: Vec::new(),
            conflict: ConflictPolicy::Skip,
            bitmap_threshold: BITMAP_THRESHOLD,
        }
    }


    /// Abandon this transfer and delete everything staged for it.
    pub fn discard(self) -> Result<()> {
        fs::remove_dir_all(&self.root)?;
        let _ = fs::remove_dir(self.destination.join(STAGING_DIR));
        Ok(())
    }

    fn handle(&mut self, index: u32, size: u64) -> Result<&mut File> {
        if !self.handles.contains_key(&index) {
            if self.handle_order.len() >= HANDLE_CACHE
                && let Some(evict) = self.handle_order.first().copied()
            {
                // Record what this file has before letting go of its handle. The
                // checkpoint's flush needs the handle, and a bitmap written later
                // without one could claim data that never reached the disk.
                if let Err(e) = self.checkpoint(evict) {
                    tracing::debug!(index = evict, error = %e, "could not checkpoint before closing a file");
                }
                self.close_handle(evict);
            }

            let path = to_extended_length(&self.part_path(index));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)?;

            // Preallocate so the filesystem can lay the file out contiguously
            // and so a disk-full condition surfaces now rather than at 99%.
            if file.metadata()?.len() != size {
                file.set_len(size)?;
            }

            self.handles.insert(index, file);
            self.handle_order.push(index);
        }

        Ok(self.handles.get_mut(&index).expect("just inserted"))
    }

    /// Close a file, setting its modification time on the way out.
    ///
    /// Done through the handle we already have rather than by reopening the
    /// placed file: on NTFS an open is one of the more expensive operations, and
    /// on a transfer of thousands of files those add up to seconds.
    fn close_handle(&mut self, index: u32) {
        if let Some(file) = self.handles.remove(&index) {
            if let Some(mtime) = self.manifest.entries.get(index as usize).and_then(|e| e.mtime) {
                let _ = file.set_modified(system_time_from_unix(mtime));
            }
            drop(file);
        }
        self.handle_order.retain(|&i| i != index);
    }

    fn part_path(&self, index: u32) -> PathBuf {
        self.root.join("p").join(index.to_string())
    }

    fn map_path(&self, index: u32) -> PathBuf {
        self.root.join("m").join(index.to_string())
    }
}

/// On-disk bitmap format: magic, chunk count, checksum, then the bits.
///
/// The checksum is the point. Partial files are preallocated to their full
/// size, so there is no way to cross-check a bitmap against the length of the
/// data it describes — a bitmap claiming chunks that never arrived looks
/// exactly like a correct one. Since the file is written atomically, a torn
/// write is already impossible; what remains is bit-rot and outside meddling,
/// and a checksum catches both.
///
/// It is not the last line of defence. Even a bitmap that is internally
/// consistent but wrong gets caught by the whole-file hash at the end, which
/// discards the file and re-fetches it.
const MAP_MAGIC: &[u8; 8] = b"JETMAP01";
const MAP_HEADER: usize = 8 + 4 + 32;

fn encode_map(map: &ChunkMap) -> Vec<u8> {
    let bits = map.to_bytes();
    let mut out = Vec::with_capacity(MAP_HEADER + bits.len());

    out.extend_from_slice(MAP_MAGIC);
    out.extend_from_slice(&map.len().to_le_bytes());
    out.extend_from_slice(blake3::hash(bits).as_bytes());
    out.extend_from_slice(bits);
    out
}

fn decode_map(bytes: &[u8], expected_chunks: u32) -> Result<ChunkMap> {
    if bytes.len() < MAP_HEADER || &bytes[..8] != MAP_MAGIC {
        return Err(Error::Protocol("chunk bitmap has a bad header".into()));
    }

    let len = u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes"));
    if len != expected_chunks {
        return Err(Error::Protocol(format!(
            "chunk bitmap is for {len} chunks but the manifest says {expected_chunks}"
        )));
    }

    let (checksum, bits) = bytes[12..].split_at(32);
    if blake3::hash(bits).as_bytes() != checksum {
        return Err(Error::Protocol("chunk bitmap failed its checksum".into()));
    }

    ChunkMap::from_bytes(len, bits)
}

/// Write a small file atomically **and durably** — survives a power cut.
///
/// Used for chunk bitmaps, where the ordering guarantee (data flushed before the
/// bitmap that claims it) is what makes resume trustworthy. The `fsync` is the
/// whole point and cannot be dropped.
fn write_durably(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = path.with_extension("tmp");
    {
        let mut file = File::create(to_extended_length(&temp))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(to_extended_length(&temp), to_extended_length(path))?;
    Ok(())
}

/// Write a small file atomically but **without** forcing it to disk.
///
/// All-or-nothing against a process crash, because the rename is atomic, but a
/// power cut can still lose the most recent update.
///
/// Used for the delivery record, where that is the right trade. Losing it costs
/// a duplicate file on the next resume — untidy, never destructive, since the
/// conflict policy keeps whatever was already there. Paying an `fsync` per
/// delivered file to avoid that made a 2,000-file transfer three times slower
/// than the network, which is a much worse outcome than a possible duplicate
/// after a power failure.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = path.with_extension("tmp");
    fs::write(to_extended_length(&temp), bytes)?;
    fs::rename(to_extended_length(&temp), to_extended_length(path))?;
    Ok(())
}

/// BLAKE3 of a whole file, calling `on_read` with the size of each block read.
fn hash_file_reporting(path: &Path, on_read: &mut dyn FnMut(u64)) -> Result<[u8; 32]> {
    let mut file = File::open(to_extended_length(path))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; 256 * 1024];

    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        on_read(read as u64);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Restore mtime and, on Unix, permissions.
///
/// Best effort: a file that arrived intact should not be reported as failed
/// because its timestamp could not be set.
fn apply_metadata(path: &Path, entry: &Entry) {
    if let Some(mtime) = entry.mtime
        && let Ok(file) = OpenOptions::new().write(true).open(path)
    {
        let _ = file.set_modified(system_time_from_unix(mtime));
    }

    #[cfg(unix)]
    if let Some(mode) = entry.mode {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
    }
}

/// `report.pdf` -> `report (2).pdf`, skipping names already taken.
fn next_available_name(target: &Path) -> Result<PathBuf> {
    let parent = target.parent().unwrap_or(Path::new("."));
    let stem = target
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let extension = target.extension().map(|e| e.to_string_lossy().to_string());

    for counter in 2..10_000u32 {
        let name = match &extension {
            Some(ext) => format!("{stem} ({counter}).{ext}"),
            None => format!("{stem} ({counter})"),
        };
        let candidate = parent.join(name);
        if !to_extended_length(&candidate).exists() {
            return Ok(candidate);
        }
    }

    Err(Error::Io(std::io::Error::other(format!(
        "could not find an unused name for {}",
        target.display()
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::CHUNK_SIZE;
    use crate::manifest::EntryKind;
    use crate::path::RelPath;

    fn entry(path: &str, size: u64) -> Entry {
        Entry {
            path: RelPath::parse(path).unwrap(),
            kind: EntryKind::File { size },
            mtime: Some(1_700_000_000),
            mode: None,
        }
    }

    fn directory(path: &str) -> Entry {
        Entry {
            path: RelPath::parse(path).unwrap(),
            kind: EntryKind::Directory,
            mtime: Some(1_700_000_000),
            mode: None,
        }
    }

    /// Deterministic pseudo-random bytes, so tests exercise real hashing
    /// without depending on a random source.
    fn payload(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
    }

    /// Feed an entire file through staging, chunk by chunk.
    fn send_all(staging: &mut Staging, index: u32, data: &[u8]) {
        let size = data.len() as u64;
        for chunk_index in 0..chunk::chunk_count(size).unwrap() {
            let (offset, len) = chunk::chunk_span(chunk_index, size).unwrap();
            let slice = &data[offset as usize..offset as usize + len];
            let hash = blake3::hash(slice);
            staging
                .write_chunk(index, chunk_index, slice, hash.as_bytes())
                .unwrap();
        }
    }

    /// Regression: a file delivered by an earlier attempt counted as nothing on
    /// resume, because its bitmap is deleted once it is placed. A resumed
    /// transfer then showed far less progress than it had made, told the sender
    /// the same, and finished short of 100%.
    #[test]
    fn files_delivered_before_an_interruption_count_on_resume() {
        let dir = tempfile::tempdir().unwrap();
        let big = payload(9 * 1024 * 1024, 3);
        let small = payload(5000, 4);
        let manifest = Manifest {
            entries: vec![
                entry("big.bin", big.len() as u64),
                entry("small.bin", small.len() as u64),
            ],
        };

        {
            let mut staging =
                Staging::open(dir.path(), manifest.clone(), ConflictPolicy::Rename).unwrap();
            send_all(&mut staging, 0, &big);
            staging.finish_file(0, blake3::hash(&big).as_bytes()).unwrap();
        }

        let resumed = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();
        assert!(resumed.is_placed(0));
        assert_eq!(resumed.bytes_present(), big.len() as u64);
        assert_eq!(resumed.files_present(), 1);
        assert!(
            resumed.outstanding().iter().all(|(index, _)| *index != 0),
            "a delivered file must not be requested again"
        );
    }

    #[test]
    fn stopping_early_keeps_every_chunk_that_was_written() {
        let dir = tempfile::tempdir().unwrap();
        // Ten chunks: well under the periodic checkpoint interval, so before
        // `checkpoint_all` none of this survived an interruption.
        let data = payload(10 * chunk::CHUNK_SIZE as usize, 5);
        let manifest = Manifest {
            entries: vec![entry("medium.bin", data.len() as u64)],
        };

        {
            let mut staging =
                Staging::open(dir.path(), manifest.clone(), ConflictPolicy::Rename).unwrap();
            for chunk_index in 0..6u32 {
                let (offset, len) = chunk::chunk_span(chunk_index, data.len() as u64).unwrap();
                let slice = &data[offset as usize..offset as usize + len];
                staging
                    .write_chunk(0, chunk_index, slice, blake3::hash(slice).as_bytes())
                    .unwrap();
            }
            staging.checkpoint_all().unwrap();
        }

        let resumed = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();
        assert_eq!(resumed.bytes_present(), 6 * chunk::CHUNK_SIZE);
        assert_eq!(resumed.outstanding(), vec![(0, ChunkRange::new(6, 10))]);
    }

    #[test]
    fn a_complete_transfer_lands_in_the_destination() {
        let dir = tempfile::tempdir().unwrap();
        let data = payload(5000, 1);

        let manifest = Manifest {
            entries: vec![directory("folder"), entry("folder/file.bin", data.len() as u64)],
        };
        let mut staging = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();

        send_all(&mut staging, 1, &data);
        assert!(staging.is_file_complete(1));

        staging.finish_file(1, blake3::hash(&data).as_bytes()).unwrap();
        staging.finish().unwrap();

        assert_eq!(fs::read(dir.path().join("folder/file.bin")).unwrap(), data);
        assert!(
            !dir.path().join(STAGING_DIR).exists(),
            "staging directory should be cleaned up"
        );
    }

    /// The headline feature. Half a file arrives, the process dies, a new
    /// `Staging` opens the same destination and must ask only for the rest.
    #[test]
    fn an_interrupted_transfer_resumes_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        // Above BITMAP_THRESHOLD: chunk-level resume is only tracked for files
        // large enough for it to be worth an fsync.
        let size = CHUNK_SIZE * 12 + 1234;
        let data = payload(size as usize, 7);
        let manifest = Manifest {
            entries: vec![entry("big.bin", size)],
        };

        // First attempt: two of five chunks, then the process vanishes.
        {
            let mut staging =
                Staging::open(dir.path(), manifest.clone(), ConflictPolicy::Rename).unwrap();
            for chunk_index in 0..8 {
                let (offset, len) = chunk::chunk_span(chunk_index, size).unwrap();
                let slice = &data[offset as usize..offset as usize + len];
                staging
                    .write_chunk(0, chunk_index, slice, blake3::hash(slice).as_bytes())
                    .unwrap();
            }
            staging.checkpoint(0).unwrap();
            // No `finish`: simulates an abrupt exit.
        }

        // Second attempt: a fresh Staging over the same destination.
        let mut resumed = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();

        assert_eq!(
            resumed.outstanding(),
            vec![(0, ChunkRange::new(8, 13))],
            "resume must ask only for the missing tail"
        );
        assert_eq!(resumed.bytes_present(), CHUNK_SIZE * 8);

        for chunk_index in 8..13 {
            let (offset, len) = chunk::chunk_span(chunk_index, size).unwrap();
            let slice = &data[offset as usize..offset as usize + len];
            resumed
                .write_chunk(0, chunk_index, slice, blake3::hash(slice).as_bytes())
                .unwrap();
        }

        resumed.finish_file(0, blake3::hash(&data).as_bytes()).unwrap();
        resumed.finish().unwrap();

        assert_eq!(
            fs::read(dir.path().join("big.bin")).unwrap(),
            data,
            "the resumed file must be byte-identical to the original"
        );
    }

    #[test]
    fn a_corrupt_chunk_is_refused_before_it_touches_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let data = payload(2000, 3);
        let manifest = Manifest {
            entries: vec![entry("f.bin", data.len() as u64)],
        };
        let mut staging = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();

        let mut corrupted = data.clone();
        corrupted[10] ^= 0xFF;

        let err = staging
            .write_chunk(0, 0, &corrupted, blake3::hash(&data).as_bytes())
            .unwrap_err();
        assert!(err.to_string().contains("hash check"), "got {err}");

        assert_eq!(staging.chunk_map(0).unwrap().present_count(), 0);
        assert_eq!(
            staging.outstanding(),
            vec![(0, ChunkRange::new(0, 1))],
            "the rejected chunk must still be outstanding"
        );
    }

    #[test]
    fn a_file_that_fails_final_verification_is_discarded_not_delivered() {
        let dir = tempfile::tempdir().unwrap();
        let data = payload(3000, 5);
        let manifest = Manifest {
            entries: vec![entry("f.bin", data.len() as u64)],
        };
        let mut staging = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();

        send_all(&mut staging, 0, &data);

        // Every chunk verified individually, but the whole-file hash we were
        // promised is different — the sender's file changed underneath it.
        let wrong = [0u8; 32];
        assert!(staging.finish_file(0, &wrong).is_err());

        assert!(
            !dir.path().join("f.bin").exists(),
            "a file failing verification must never appear in the destination"
        );
        assert_eq!(
            staging.outstanding(),
            vec![(0, ChunkRange::new(0, 1))],
            "the file should be queued to fetch again"
        );
    }

    #[test]
    fn a_tally_says_what_happened_rather_than_a_bare_total() {
        let p = |n: &str| PathBuf::from(n);
        let tally = PlacementTally::of(&[
            Placement::Created(p("a")),
            Placement::Created(p("b")),
            Placement::Skipped(p("c")),
            Placement::Renamed(p("d")),
            Placement::Overwritten(p("e")),
        ]);

        assert_eq!(tally.created, 2);
        assert_eq!(tally.skipped, 1);

        let text = tally.describe();
        assert!(text.contains("2 files saved"), "got {text}");
        assert!(text.contains("1 already present"), "got {text}");
    }

    #[test]
    fn a_recovery_run_does_not_claim_to_have_saved_what_it_skipped() {
        // The bug this replaces: `placements.len()` counted skipped files as
        // saved, so a run that placed 3 and skipped 1000 reported "1003 saved".
        let mut placements = vec![Placement::Created(PathBuf::from("new"))];
        placements.extend((0..1000).map(|i| Placement::Skipped(PathBuf::from(format!("old{i}")))));

        let text = PlacementTally::of(&placements).describe();
        assert!(text.contains("1 file saved"), "got {text}");
        assert!(text.contains("1000 already present"), "got {text}");
        assert!(!text.contains("1001"), "must not report a combined total: {text}");
    }

    #[test]
    fn a_transfer_that_placed_nothing_says_so() {
        assert_eq!(PlacementTally::of(&[]).describe(), "nothing to save");
    }

    /// The whole point of the fix: Skip must cost nothing.
    ///
    /// It used to be applied at delivery, so every byte of a file that was going
    /// to be skipped was still pulled across the network and hashed first. On a
    /// 138 GB folder already sitting at the destination, "skip" was as expensive
    /// as accepting it.
    #[test]
    fn skip_asks_for_nothing_when_the_destination_already_has_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let data = payload(CHUNK_SIZE as usize * 3, 11);

        // Something is already there, as if a previous run delivered it.
        fs::write(dir.path().join("game.dat"), &data).unwrap();

        let manifest = Manifest {
            entries: vec![entry("game.dat", data.len() as u64)],
        };
        let staging = Staging::open(dir.path(), manifest, ConflictPolicy::Skip).unwrap();

        assert!(
            staging.outstanding().is_empty(),
            "not one chunk should be requested for a file that is already there"
        );
        assert!(staging.is_complete(), "there is nothing left to do");
        assert_eq!(staging.skipped_count(), 1);

        // And it must read as progress, or the transfer would show 0% while
        // correctly doing nothing.
        assert_eq!(staging.bytes_present(), data.len() as u64);
        assert_eq!(staging.files_present(), 1);

        // The file is reported, not silently omitted.
        let placements = staging.finish().unwrap();
        assert!(
            placements
                .iter()
                .any(|p| matches!(p, Placement::Skipped(path) if path.ends_with("game.dat"))),
            "skipping must be visible to the caller, got {placements:?}"
        );

        // Untouched.
        assert_eq!(fs::read(dir.path().join("game.dat")).unwrap(), data);
    }

    #[test]
    fn the_other_policies_still_ask_for_the_file() {
        // Only Skip may shortcut the transfer. Rename and Overwrite both have to
        // receive the data before they can decide what to do with it.
        for policy in [ConflictPolicy::Rename, ConflictPolicy::Overwrite] {
            let dir = tempfile::tempdir().unwrap();
            let data = payload(CHUNK_SIZE as usize, 12);
            fs::write(dir.path().join("game.dat"), &data).unwrap();

            let manifest = Manifest {
                entries: vec![entry("game.dat", data.len() as u64)],
            };
            let staging = Staging::open(dir.path(), manifest, policy).unwrap();

            assert!(
                !staging.outstanding().is_empty(),
                "{policy:?} must still fetch the file"
            );
            assert_eq!(staging.skipped_count(), 0);
        }
    }

    #[test]
    fn skip_still_fetches_files_the_destination_lacks() {
        // A partly-finished transfer recovered with Skip must fill in the gaps.
        let dir = tempfile::tempdir().unwrap();
        let present = payload(CHUNK_SIZE as usize, 13);
        fs::write(dir.path().join("have.dat"), &present).unwrap();

        let manifest = Manifest {
            entries: vec![
                entry("have.dat", present.len() as u64),
                entry("missing.dat", CHUNK_SIZE),
            ],
        };
        let staging = Staging::open(dir.path(), manifest, ConflictPolicy::Skip).unwrap();

        let work = staging.outstanding();
        assert!(
            work.iter().all(|(index, _)| *index == 1),
            "only the missing file should be requested, got {work:?}"
        );
        assert!(!work.is_empty(), "the missing file must still be fetched");
        assert!(!staging.is_complete());
    }

    #[test]
    fn chunks_with_the_wrong_length_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = Manifest {
            entries: vec![entry("f.bin", 1000)],
        };
        let mut staging = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();

        let short = payload(999, 1);
        assert!(
            staging.write_chunk(0, 0, &short, blake3::hash(&short).as_bytes()).is_err(),
            "a chunk shorter than its span must be refused"
        );
    }

    #[test]
    fn duplicate_chunks_are_absorbed_without_double_counting() {
        let dir = tempfile::tempdir().unwrap();
        let data = payload(500, 9);
        let manifest = Manifest {
            entries: vec![entry("f.bin", data.len() as u64)],
        };
        let mut staging = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();

        let hash = blake3::hash(&data);
        assert!(staging.write_chunk(0, 0, &data, hash.as_bytes()).unwrap());
        assert!(
            !staging.write_chunk(0, 0, &data, hash.as_bytes()).unwrap(),
            "a repeat of a chunk we already hold reports no progress"
        );
        assert_eq!(staging.chunk_map(0).unwrap().present_count(), 1);
    }

    #[test]
    fn existing_files_are_renamed_rather_than_clobbered() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("notes.txt"), b"the original").unwrap();

        let data = payload(100, 2);
        let manifest = Manifest {
            entries: vec![entry("notes.txt", data.len() as u64)],
        };
        let mut staging = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();
        send_all(&mut staging, 0, &data);

        let placement = staging.finish_file(0, blake3::hash(&data).as_bytes()).unwrap();
        staging.finish().unwrap();

        assert!(matches!(placement, Placement::Renamed(_)), "got {placement:?}");
        assert_eq!(
            fs::read(dir.path().join("notes.txt")).unwrap(),
            b"the original",
            "the user's existing file must be untouched"
        );
        assert_eq!(fs::read(dir.path().join("notes (2).txt")).unwrap(), data);
    }

    #[test]
    fn overwrite_and_skip_policies_are_honoured() {
        for (policy, expect_original) in [
            (ConflictPolicy::Overwrite, false),
            (ConflictPolicy::Skip, true),
        ] {
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join("f.bin"), b"original").unwrap();

            let data = payload(100, 4);
            let manifest = Manifest {
                entries: vec![entry("f.bin", data.len() as u64)],
            };
            let mut staging = Staging::open(dir.path(), manifest, policy).unwrap();
            send_all(&mut staging, 0, &data);
            staging.finish_file(0, blake3::hash(&data).as_bytes()).unwrap();
            staging.finish().unwrap();

            let landed = fs::read(dir.path().join("f.bin")).unwrap();
            if expect_original {
                assert_eq!(landed, b"original", "{policy:?} should leave the file alone");
            } else {
                assert_eq!(landed, data, "{policy:?} should replace the file");
            }
        }
    }

    #[test]
    fn empty_files_and_directories_are_created() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = Manifest {
            entries: vec![
                directory("tree"),
                directory("tree/empty-dir"),
                entry("tree/empty-file.txt", 0),
            ],
        };

        let staging = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();
        assert!(staging.is_complete(), "nothing to fetch");
        staging.finish().unwrap();

        assert!(dir.path().join("tree/empty-dir").is_dir());
        assert!(dir.path().join("tree/empty-file.txt").is_file());
        assert_eq!(fs::metadata(dir.path().join("tree/empty-file.txt")).unwrap().len(), 0);
    }

    #[test]
    fn hashing_then_placing_delivers_a_matching_file_and_reports_every_byte() {
        let dir = tempfile::tempdir().unwrap();
        let data = payload(CHUNK_SIZE as usize * 3 + 77, 21);
        let manifest = Manifest {
            entries: vec![entry("big.bin", data.len() as u64)],
        };
        let mut staging = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();
        send_all(&mut staging, 0, &data);

        let mut reported = 0u64;
        let local = staging.hash_staged_file(0, &mut |n| reported += n).unwrap();
        assert_eq!(reported, data.len() as u64, "progress must account for the whole file");

        staging
            .place_verified(0, &local, blake3::hash(&data).as_bytes())
            .unwrap();
        assert_eq!(fs::read(dir.path().join("big.bin")).unwrap(), data);
    }

    #[test]
    fn a_mismatch_after_a_split_verify_is_refused_and_fetched_again() {
        // The split must keep the old guarantee: a file whose hash does not match
        // never reaches the destination, and is queued to be fetched again.
        let dir = tempfile::tempdir().unwrap();
        let data = payload(CHUNK_SIZE as usize * 2, 22);
        let manifest = Manifest {
            entries: vec![entry("big.bin", data.len() as u64)],
        };
        let mut staging = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();
        send_all(&mut staging, 0, &data);

        let local = staging.hash_staged_file(0, &mut |_| {}).unwrap();
        let wrong = [7u8; 32];
        assert!(staging.place_verified(0, &local, &wrong).is_err());
        assert!(!dir.path().join("big.bin").exists(), "must never be delivered");
        assert!(!staging.outstanding().is_empty(), "must be fetched again");
    }

    #[test]
    fn a_corrupt_bitmap_restarts_that_file_instead_of_trusting_it() {
        let dir = tempfile::tempdir().unwrap();
        let size = CHUNK_SIZE * 12;
        let data = payload(size as usize, 11);
        let manifest = Manifest {
            entries: vec![entry("f.bin", size)],
        };

        {
            let mut staging =
                Staging::open(dir.path(), manifest.clone(), ConflictPolicy::Rename).unwrap();
            let slice = &data[..CHUNK_SIZE as usize];
            staging
                .write_chunk(0, 0, slice, blake3::hash(slice).as_bytes())
                .unwrap();
            staging.checkpoint(0).unwrap();
        }

        // Flip a bit in the persisted bitmap, as bit-rot or an editor would.
        let transfer_id = hex::encode(manifest.digest());
        let map_path = dir.path().join(STAGING_DIR).join(&transfer_id).join("m").join("0");
        let mut raw = fs::read(&map_path).unwrap();
        *raw.last_mut().unwrap() ^= 0b0000_0010;
        fs::write(&map_path, &raw).unwrap();

        let resumed = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();
        assert_eq!(
            resumed.outstanding(),
            vec![(0, ChunkRange::new(0, 12))],
            "a bitmap failing its checksum must be discarded, not believed"
        );
    }

    /// The optimisation that made a 2,000-file transfer 15x faster: small files
    /// skip bitmap persistence entirely, so their resume granularity is the
    /// whole file rather than a chunk.
    #[test]
    fn small_files_skip_bitmap_persistence_and_restart_wholesale() {
        let dir = tempfile::tempdir().unwrap();
        let size = CHUNK_SIZE * 2; // comfortably under BITMAP_THRESHOLD
        let data = payload(size as usize, 21);
        let manifest = Manifest {
            entries: vec![entry("small.bin", size)],
        };

        {
            let mut staging =
                Staging::open(dir.path(), manifest.clone(), ConflictPolicy::Rename).unwrap();
            let slice = &data[..CHUNK_SIZE as usize];
            staging
                .write_chunk(0, 0, slice, blake3::hash(slice).as_bytes())
                .unwrap();
            staging.checkpoint(0).unwrap();
        }

        // No bitmap was written, so nothing had to be fsynced.
        let transfer_id = hex::encode(manifest.digest());
        let map = dir.path().join(STAGING_DIR).join(&transfer_id).join("m").join("0");
        assert!(!map.exists(), "a small file should not persist a bitmap");

        // And the resumed transfer simply asks for the whole thing again.
        let resumed = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();
        assert_eq!(resumed.outstanding(), vec![(0, ChunkRange::new(0, 2))]);
    }

    #[test]
    fn a_delivered_small_file_is_still_remembered() {
        // Skipping bitmaps must not skip the delivery record — that is what
        // stops a resume from producing duplicates.
        let dir = tempfile::tempdir().unwrap();
        let data = payload(4096, 22);
        let manifest = Manifest {
            entries: vec![entry("small.bin", data.len() as u64)],
        };

        {
            let mut staging =
                Staging::open(dir.path(), manifest.clone(), ConflictPolicy::Rename).unwrap();
            send_all(&mut staging, 0, &data);
            staging.finish_file(0, blake3::hash(&data).as_bytes()).unwrap();
        }

        let resumed = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();
        assert!(resumed.is_placed(0), "delivery must survive a restart");
        assert!(resumed.outstanding().is_empty());
        assert!(!dir.path().join("small (2).bin").exists());
    }

    #[test]
    fn bitmap_encoding_detects_tampering_and_mismatched_lengths() {
        let mut map = ChunkMap::empty(20);
        map.insert(0);
        map.insert(19);
        let encoded = encode_map(&map);

        assert_eq!(decode_map(&encoded, 20).unwrap(), map);

        assert!(decode_map(&encoded, 21).is_err(), "chunk count must agree");
        assert!(decode_map(b"too short", 20).is_err());

        let mut bad_magic = encoded.clone();
        bad_magic[0] = b'X';
        assert!(decode_map(&bad_magic, 20).is_err());

        let mut flipped = encoded.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(decode_map(&flipped, 20).is_err(), "checksum must catch a flipped bit");
    }

    #[test]
    fn modification_times_are_restored() {
        let dir = tempfile::tempdir().unwrap();
        let data = payload(64, 6);
        let mtime = 1_600_000_000;

        let manifest = Manifest {
            entries: vec![Entry {
                path: RelPath::parse("dated.bin").unwrap(),
                kind: EntryKind::File {
                    size: data.len() as u64,
                },
                mtime: Some(mtime),
                mode: None,
            }],
        };

        let mut staging = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();
        send_all(&mut staging, 0, &data);
        staging.finish_file(0, blake3::hash(&data).as_bytes()).unwrap();
        staging.finish().unwrap();

        let landed = fs::metadata(dir.path().join("dated.bin")).unwrap().modified().unwrap();
        let seconds = landed
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert_eq!(seconds, mtime, "mtime should survive the transfer");
    }

    /// Regression: resuming a transfer whose files were already delivered used
    /// to fetch them all over again and, under the rename policy, leave a
    /// second copy of every one. Found by interrupting a real 300 MB transfer
    /// after most files had landed.
    #[test]
    fn resuming_does_not_redeliver_files_already_placed() {
        let dir = tempfile::tempdir().unwrap();
        let first_data = payload(500, 1);
        let second_data = payload(700, 2);

        let manifest = Manifest {
            entries: vec![
                entry("done.bin", first_data.len() as u64),
                entry("pending.bin", second_data.len() as u64),
            ],
        };

        // First session delivers one file, then the process dies.
        {
            let mut staging =
                Staging::open(dir.path(), manifest.clone(), ConflictPolicy::Rename).unwrap();
            send_all(&mut staging, 0, &first_data);
            staging
                .finish_file(0, blake3::hash(&first_data).as_bytes())
                .unwrap();
        }

        // Second session must remember the delivery.
        let mut resumed = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();
        assert!(resumed.is_placed(0), "the delivery record must survive a restart");
        assert_eq!(
            resumed.outstanding(),
            vec![(1, ChunkRange::new(0, 1))],
            "only the undelivered file should be outstanding"
        );

        send_all(&mut resumed, 1, &second_data);
        resumed
            .finish_file(1, blake3::hash(&second_data).as_bytes())
            .unwrap();
        resumed.finish().unwrap();

        assert_eq!(fs::read(dir.path().join("done.bin")).unwrap(), first_data);
        assert_eq!(fs::read(dir.path().join("pending.bin")).unwrap(), second_data);
        assert!(
            !dir.path().join("done (2).bin").exists(),
            "the already-delivered file must not be duplicated"
        );
    }

    /// The single-chunk shortcut must be a shortcut past *redundant* work, never
    /// past verification. It is only valid when a chunk was actually verified in
    /// this session; without that it has to refuse so the caller falls back to
    /// fetching and checking a real whole-file hash.
    #[test]
    fn the_single_chunk_shortcut_refuses_without_a_verified_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = Manifest {
            entries: vec![entry("small.bin", 4096)],
        };
        let mut staging = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();

        // Nothing has arrived, so there is nothing proven.
        assert!(staging.finish_single_chunk_file(0).is_err());
        assert!(!dir.path().join("small.bin").exists());
    }

    #[test]
    fn the_single_chunk_shortcut_delivers_a_verified_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let data = payload(4096, 31);
        let manifest = Manifest {
            entries: vec![entry("small.bin", data.len() as u64)],
        };
        let mut staging = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();

        send_all(&mut staging, 0, &data);
        staging.finish_single_chunk_file(0).unwrap();
        staging.finish().unwrap();

        assert_eq!(fs::read(dir.path().join("small.bin")).unwrap(), data);
    }

    /// A tampered single chunk is still caught — by the per-chunk hash, before
    /// it ever reaches the file. The shortcut does not weaken this.
    #[test]
    fn a_corrupt_single_chunk_never_reaches_the_shortcut() {
        let dir = tempfile::tempdir().unwrap();
        let data = payload(4096, 32);
        let manifest = Manifest {
            entries: vec![entry("small.bin", data.len() as u64)],
        };
        let mut staging = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();

        let mut corrupt = data.clone();
        corrupt[7] ^= 0xFF;

        assert!(
            staging
                .write_chunk(0, 0, &corrupt, blake3::hash(&data).as_bytes())
                .is_err(),
            "the chunk hash must reject tampered bytes"
        );
        // And with nothing recorded, the shortcut refuses too.
        assert!(staging.finish_single_chunk_file(0).is_err());
    }

    #[test]
    fn discarding_removes_every_trace() {
        let dir = tempfile::tempdir().unwrap();
        let data = payload(2000, 8);
        let manifest = Manifest {
            entries: vec![entry("f.bin", data.len() as u64)],
        };

        let mut staging = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();
        send_all(&mut staging, 0, &data);
        staging.discard().unwrap();

        assert!(!dir.path().join(STAGING_DIR).exists());
        assert!(!dir.path().join("f.bin").exists());
    }

    #[test]
    fn chunk_data_for_a_directory_entry_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = Manifest {
            entries: vec![directory("folder")],
        };
        let mut staging = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();

        let data = payload(10, 1);
        assert!(
            staging.write_chunk(0, 0, &data, blake3::hash(&data).as_bytes()).is_err(),
            "a peer must not be able to write data through a directory entry"
        );
    }

    #[test]
    fn many_open_files_do_not_exhaust_the_handle_cache() {
        let dir = tempfile::tempdir().unwrap();
        let count = HANDLE_CACHE * 4;

        let entries: Vec<Entry> = (0..count).map(|i| entry(&format!("f{i}.bin"), 100)).collect();
        let manifest = Manifest { entries };
        let mut staging = Staging::open(dir.path(), manifest, ConflictPolicy::Rename).unwrap();

        for index in 0..count as u32 {
            let data = payload(100, index as u8);
            send_all(&mut staging, index, &data);
            staging.finish_file(index, blake3::hash(&data).as_bytes()).unwrap();
        }
        staging.finish().unwrap();

        for index in 0..count {
            assert!(dir.path().join(format!("f{index}.bin")).exists());
        }
    }
}
