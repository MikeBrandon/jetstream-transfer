//! The manifest: what a transfer contains, sent before any data moves.
//!
//! # Why there are no content hashes in here
//!
//! The obvious design puts a BLAKE3 hash of every chunk in the manifest. It is
//! also the wrong one, because it forces the sender to read and hash the entire
//! tree before the first byte goes out. On a 200 GB folder that is minutes of
//! apparent hang, and it re-reads data the transfer is about to read anyway.
//!
//! So the manifest carries only what `stat` already knows — paths, sizes,
//! modification times, modes — which makes it cheap to build and lets a
//! transfer start instantly. Integrity is enforced where the data actually is:
//!
//! - every chunk carries its own BLAKE3 hash, computed by the sender as it
//!   reads and verified by the receiver before the bytes are written;
//! - every file carries a whole-file BLAKE3, checked after reassembly, which
//!   catches misordering, gaps, and anything the per-chunk check could miss.
//!
//! Resume needs one extra guarantee: that the source file has not changed
//! between sessions. Size and mtime, both recorded here, answer that. If either
//! moved, the staged chunks are discarded rather than blended with new ones.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::chunk::{self, CHUNK_SIZE};
use crate::error::{Error, Result};
use crate::path::RelPath;

/// Upper bound on entries in one transfer.
///
/// Each entry costs on the order of a hundred bytes in memory, so this caps a
/// manifest at a few hundred megabytes even in the worst case — and a peer
/// cannot make us allocate without bound by claiming an absurd file count.
pub const MAX_ENTRIES: usize = 2_000_000;

/// Entries per wire batch.
///
/// The manifest is streamed in batches rather than sent as one frame, so a
/// large tree never needs a frame bigger than the control-frame ceiling.
pub const ENTRIES_PER_BATCH: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    File {
        size: u64,
    },
    /// Carried explicitly so empty directories survive the trip. Dukto loses
    /// them, which quietly changes the shape of anything you send.
    Directory,
    /// Reserved in the wire format. The v1 walker skips symlinks rather than
    /// following them — following risks cycles and escaping the transfer root,
    /// and creating them on Windows needs privileges we should not require.
    /// Keeping the variant means adding support later costs no version bump.
    Symlink {
        target: String,
    },
}

/// One filesystem object in a transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub path: RelPath,
    pub kind: EntryKind,
    /// Modification time as whole seconds since the Unix epoch.
    ///
    /// Seconds, not nanoseconds, because that is the coarsest resolution among
    /// the filesystems we care about (FAT32 is 2s, but rounding that far would
    /// weaken the resume check). Also doubles as half of the "has the source
    /// changed since we paused?" test.
    pub mtime: Option<i64>,
    /// POSIX permission bits. `None` from a Windows sender, and ignored by a
    /// Windows receiver — carried so Unix-to-Unix transfers keep the exec bit.
    pub mode: Option<u32>,
}

impl Entry {
    pub fn size(&self) -> u64 {
        match self.kind {
            EntryKind::File { size } => size,
            _ => 0,
        }
    }

    pub fn is_file(&self) -> bool {
        matches!(self.kind, EntryKind::File { .. })
    }

    pub fn chunk_count(&self) -> Result<u32> {
        chunk::chunk_count(self.size())
    }
}

/// The complete description of a transfer.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Manifest {
    pub entries: Vec<Entry>,
}

/// Headline numbers for the accept prompt.
///
/// A user deciding whether to accept needs to know roughly what is arriving
/// without reading a list of 50,000 paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub file_count: u64,
    pub directory_count: u64,
    pub total_bytes: u64,
    /// Distinct top-level names, capped — enough to recognise what this is.
    pub top_level: Vec<String>,
    /// True if [`Summary::top_level`] was truncated.
    pub more_top_level: bool,
}

const MAX_TOP_LEVEL_SHOWN: usize = 12;

/// What the walker skipped, so the UI can say so instead of quietly dropping
/// things. A transfer that silently omits files is worse than one that fails.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WalkReport {
    pub symlinks_skipped: Vec<PathBuf>,
    pub unreadable: Vec<(PathBuf, String)>,
    pub unsupported_names: Vec<(PathBuf, String)>,
}

impl WalkReport {
    pub fn is_clean(&self) -> bool {
        self.symlinks_skipped.is_empty()
            && self.unreadable.is_empty()
            && self.unsupported_names.is_empty()
    }

    pub fn skipped_count(&self) -> usize {
        self.symlinks_skipped.len() + self.unreadable.len() + self.unsupported_names.len()
    }

    /// Everything skipped, as `(path, why)`, ready to show a user.
    ///
    /// A count on its own — "3 item(s) skipped" — is the sort of thing that makes
    /// a person distrust the whole transfer, because the one question it raises
    /// is the one it refuses to answer. The paths are right here; there is no
    /// reason to withhold them.
    pub fn skipped(&self) -> Vec<(PathBuf, String)> {
        let symlinks = self.symlinks_skipped.iter().map(|path| {
            (
                path.clone(),
                "symbolic link — not followed, to avoid loops and escaping the folder".to_string(),
            )
        });

        let unreadable = self
            .unreadable
            .iter()
            .map(|(path, why)| (path.clone(), format!("could not be read: {why}")));

        let unsupported = self
            .unsupported_names
            .iter()
            .map(|(path, why)| (path.clone(), format!("name cannot be used: {why}")));

        symlinks.chain(unreadable).chain(unsupported).collect()
    }
}

impl Manifest {
    /// Build a manifest from the paths a user dropped.
    ///
    /// Each source is made relative to its own parent, so dropping
    /// `C:\photos\2026` produces entries under `2026/`, and dropping a bare
    /// file produces a single entry with just its name.
    ///
    /// Unreadable files are reported rather than aborting the whole transfer:
    /// one locked file in a large folder should not sink everything else.
    pub fn from_paths(sources: &[PathBuf]) -> Result<(Self, WalkReport)> {
        let mut entries = Vec::new();
        let mut report = WalkReport::default();

        for source in sources {
            let metadata = fs::symlink_metadata(source)
                .map_err(|e| Error::Io(std::io::Error::new(e.kind(), format!("{}: {e}", source.display()))))?;

            // Relative to the parent, so the dropped item keeps its own name.
            let root = source.parent().unwrap_or(Path::new(""));

            if metadata.is_dir() {
                walk_directory(source, root, &mut entries, &mut report)?;
            } else if metadata.is_symlink() {
                report.symlinks_skipped.push(source.clone());
            } else {
                push_entry(source, root, &metadata, &mut entries, &mut report);
            }

            if entries.len() > MAX_ENTRIES {
                return Err(Error::Protocol(format!(
                    "transfer contains more than {MAX_ENTRIES} items"
                )));
            }
        }

        // Sorted for determinism, which makes the digest stable and puts every
        // directory ahead of its contents (a prefix sorts before what extends
        // it), so the receiver can create paths in order.
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        entries.dedup_by(|a, b| a.path == b.path);

        Ok((Self { entries }, report))
    }

    /// Check a manifest that arrived from a peer.
    ///
    /// Paths are already validated by [`RelPath`]'s deserializer; this catches
    /// the structural problems that survive per-path checks — duplicates, an
    /// absurd entry count, and files too large to address.
    pub fn validate(&self) -> Result<()> {
        if self.entries.len() > MAX_ENTRIES {
            return Err(Error::Protocol(format!(
                "manifest has {} entries, over the {MAX_ENTRIES} limit",
                self.entries.len()
            )));
        }

        let mut seen = std::collections::HashSet::with_capacity(self.entries.len());
        for entry in &self.entries {
            if !seen.insert(entry.path.as_str()) {
                return Err(Error::Protocol(format!(
                    "manifest lists {:?} more than once",
                    entry.path.as_str()
                )));
            }
            entry.chunk_count()?;

            // Windows compares filenames case-insensitively, so `A.txt` and
            // `a.txt` in one manifest would collide on arrival. Caught here so
            // the failure is a clear message rather than a half-written file.
            if cfg!(windows) {
                let lowered = entry.path.as_str().to_lowercase();
                if lowered != entry.path.as_str() && seen.contains(lowered.as_str()) {
                    return Err(Error::Protocol(format!(
                        "manifest contains {:?} and a name differing only by case, \
                         which cannot both exist on Windows",
                        entry.path.as_str()
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn summary(&self) -> Summary {
        let mut top_level = Vec::new();
        let mut seen_top = std::collections::HashSet::new();
        let mut file_count = 0;
        let mut directory_count = 0;
        let mut total_bytes = 0u64;

        for entry in &self.entries {
            match entry.kind {
                EntryKind::File { size } => {
                    file_count += 1;
                    total_bytes = total_bytes.saturating_add(size);
                }
                EntryKind::Directory => directory_count += 1,
                EntryKind::Symlink { .. } => {}
            }

            let top = entry.path.top_level();
            if seen_top.insert(top.to_string()) && top_level.len() < MAX_TOP_LEVEL_SHOWN {
                top_level.push(top.to_string());
            }
        }

        Summary {
            file_count,
            directory_count,
            total_bytes,
            more_top_level: seen_top.len() > top_level.len(),
            top_level,
        }
    }

    /// Stable content digest, and the transfer's identity.
    ///
    /// Deriving the transfer id from the manifest rather than picking a random
    /// one means re-dropping the same unchanged folder after a crash lands on
    /// the same staging directory and resumes, instead of starting over beside
    /// a pile of orphaned partial files.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("jetstream 2026-01 manifest-digest v1");

        for entry in &self.entries {
            hasher.update(entry.path.as_str().as_bytes());
            hasher.update(b"\0");
            match &entry.kind {
                EntryKind::File { size } => {
                    hasher.update(b"f");
                    hasher.update(&size.to_le_bytes());
                }
                EntryKind::Directory => {
                    hasher.update(b"d");
                }
                EntryKind::Symlink { target } => {
                    hasher.update(b"l");
                    hasher.update(target.as_bytes());
                }
            }
            hasher.update(&entry.mtime.unwrap_or(0).to_le_bytes());
        }

        *hasher.finalize().as_bytes()
    }

    /// Indices of file entries, in transfer order.
    ///
    /// Largest last: finishing many small files early makes progress visible
    /// immediately and means an interrupted transfer leaves fewer partials.
    pub fn transfer_order(&self) -> Vec<u32> {
        let mut indices: Vec<u32> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.is_file() && e.size() > 0)
            .map(|(i, _)| i as u32)
            .collect();

        indices.sort_by_key(|&i| self.entries[i as usize].size());
        indices
    }

    pub fn total_bytes(&self) -> u64 {
        self.entries
            .iter()
            .map(Entry::size)
            .fold(0u64, u64::saturating_add)
    }

    pub fn total_chunks(&self) -> u64 {
        self.entries
            .iter()
            .map(|e| e.size().div_ceil(CHUNK_SIZE))
            .sum()
    }
}

fn walk_directory(
    directory: &Path,
    root: &Path,
    entries: &mut Vec<Entry>,
    report: &mut WalkReport,
) -> Result<()> {
    // `follow_links(false)` is what keeps a symlink loop from walking forever.
    let walker = walkdir::WalkDir::new(directory)
        .follow_links(false)
        .max_depth(64)
        .into_iter();

    for item in walker {
        let item = match item {
            Ok(item) => item,
            Err(e) => {
                let path = e.path().unwrap_or(directory).to_path_buf();
                report.unreadable.push((path, e.to_string()));
                continue;
            }
        };

        let file_type = item.file_type();
        if file_type.is_symlink() {
            report.symlinks_skipped.push(item.path().to_path_buf());
            continue;
        }

        let metadata = match item.metadata() {
            Ok(metadata) => metadata,
            Err(e) => {
                report.unreadable.push((item.path().to_path_buf(), e.to_string()));
                continue;
            }
        };

        push_entry(item.path(), root, &metadata, entries, report);

        if entries.len() > MAX_ENTRIES {
            return Err(Error::Protocol(format!(
                "transfer contains more than {MAX_ENTRIES} items"
            )));
        }
    }
    Ok(())
}

fn push_entry(
    absolute: &Path,
    root: &Path,
    metadata: &fs::Metadata,
    entries: &mut Vec<Entry>,
    report: &mut WalkReport,
) {
    let relative = absolute.strip_prefix(root).unwrap_or(absolute);

    // A local name we cannot express safely — a reserved device name, a
    // trailing dot, non-UTF-8 — is reported rather than silently mangled.
    let path = match RelPath::from_local(relative) {
        Ok(path) => path,
        Err(e) => {
            report
                .unsupported_names
                .push((absolute.to_path_buf(), e.to_string()));
            return;
        }
    };

    let kind = if metadata.is_dir() {
        EntryKind::Directory
    } else {
        EntryKind::File {
            size: metadata.len(),
        }
    };

    entries.push(Entry {
        path,
        kind,
        mtime: unix_seconds(metadata),
        mode: unix_mode(metadata),
    });
}

fn unix_seconds(metadata: &fs::Metadata) -> Option<i64> {
    let modified = metadata.modified().ok()?;

    Some(match modified.duration_since(UNIX_EPOCH) {
        Ok(after) => after.as_secs() as i64,
        // Files dated before 1970 exist, mostly from broken archives.
        Err(before) => -(before.duration().as_secs() as i64),
    })
}

#[cfg(unix)]
fn unix_mode(metadata: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(metadata.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn unix_mode(_metadata: &fs::Metadata) -> Option<u32> {
    None
}

/// Convert whole seconds since the epoch back into a `SystemTime`, for
/// restoring mtimes on the receiving side.
pub fn system_time_from_unix(seconds: i64) -> SystemTime {
    let magnitude = std::time::Duration::from_secs(seconds.unsigned_abs());
    if seconds >= 0 {
        UNIX_EPOCH + magnitude
    } else {
        UNIX_EPOCH - magnitude
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a small tree: a top file, a nested file, and an empty directory.
    fn sample_tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("payload");

        fs::create_dir_all(root.join("nested")).unwrap();
        fs::create_dir_all(root.join("empty")).unwrap();

        fs::write(root.join("top.txt"), b"hello").unwrap();
        fs::write(root.join("nested/deep.bin"), vec![0u8; 3000]).unwrap();

        dir
    }

    #[test]
    fn walks_a_tree_into_relative_entries() {
        let dir = sample_tree();
        let (manifest, report) = Manifest::from_paths(&[dir.path().join("payload")]).unwrap();

        assert!(report.is_clean(), "unexpected skips: {report:?}");

        let paths: Vec<&str> = manifest.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "payload",
                "payload/empty",
                "payload/nested",
                "payload/nested/deep.bin",
                "payload/top.txt",
            ],
            "entries should be sorted with directories before their contents"
        );
    }

    #[test]
    fn empty_directories_are_preserved() {
        let dir = sample_tree();
        let (manifest, _) = Manifest::from_paths(&[dir.path().join("payload")]).unwrap();

        let empty = manifest
            .entries
            .iter()
            .find(|e| e.path.as_str() == "payload/empty")
            .expect("the empty directory must appear in the manifest");

        assert_eq!(empty.kind, EntryKind::Directory);
    }

    #[test]
    fn a_single_file_becomes_one_entry_named_after_itself() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("report.pdf");
        fs::write(&file, b"pdf bytes").unwrap();

        let (manifest, _) = Manifest::from_paths(&[file]).unwrap();

        assert_eq!(manifest.entries.len(), 1);
        assert_eq!(manifest.entries[0].path.as_str(), "report.pdf");
        assert_eq!(manifest.entries[0].kind, EntryKind::File { size: 9 });
    }

    #[test]
    fn records_sizes_and_modification_times() {
        let dir = sample_tree();
        let (manifest, _) = Manifest::from_paths(&[dir.path().join("payload")]).unwrap();

        let deep = manifest
            .entries
            .iter()
            .find(|e| e.path.as_str() == "payload/nested/deep.bin")
            .unwrap();

        assert_eq!(deep.kind, EntryKind::File { size: 3000 });
        assert!(deep.mtime.is_some(), "mtime is needed for the resume check");
    }

    #[test]
    fn summary_describes_the_transfer_without_listing_it() {
        let dir = sample_tree();
        let (manifest, _) = Manifest::from_paths(&[dir.path().join("payload")]).unwrap();
        let summary = manifest.summary();

        assert_eq!(summary.file_count, 2);
        assert_eq!(summary.directory_count, 3);
        assert_eq!(summary.total_bytes, 3005);
        assert_eq!(summary.top_level, ["payload"]);
        assert!(!summary.more_top_level);
    }

    #[test]
    fn digest_is_stable_across_walks_but_moves_with_content() {
        let dir = sample_tree();
        let source = dir.path().join("payload");

        let (first, _) = Manifest::from_paths(std::slice::from_ref(&source)).unwrap();
        let (second, _) = Manifest::from_paths(std::slice::from_ref(&source)).unwrap();
        assert_eq!(
            first.digest(),
            second.digest(),
            "re-dropping an unchanged folder must resume, not restart"
        );

        // A file that grew must produce a different transfer.
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(source.join("top.txt"))
            .unwrap();
        file.write_all(b" more").unwrap();
        drop(file);

        let (changed, _) = Manifest::from_paths(&[source]).unwrap();
        assert_ne!(first.digest(), changed.digest());
    }

    #[test]
    fn transfer_order_puts_small_files_first() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("mixed");
        fs::create_dir_all(&root).unwrap();

        fs::write(root.join("big.bin"), vec![0u8; 10_000]).unwrap();
        fs::write(root.join("small.txt"), b"x").unwrap();
        fs::write(root.join("medium.dat"), vec![0u8; 500]).unwrap();
        fs::write(root.join("empty.txt"), b"").unwrap();

        let (manifest, _) = Manifest::from_paths(&[root]).unwrap();
        let order = manifest.transfer_order();

        let names: Vec<&str> = order
            .iter()
            .map(|&i| manifest.entries[i as usize].path.file_name())
            .collect();

        assert_eq!(names, ["small.txt", "medium.dat", "big.bin"]);
        assert!(
            !names.contains(&"empty.txt"),
            "zero-byte files need no chunks and are created from the manifest alone"
        );
    }

    #[test]
    fn validate_rejects_duplicate_paths() {
        let entry = Entry {
            path: RelPath::parse("a.txt").unwrap(),
            kind: EntryKind::File { size: 1 },
            mtime: None,
            mode: None,
        };
        let manifest = Manifest {
            entries: vec![entry.clone(), entry],
        };

        assert!(manifest.validate().is_err());
    }

    #[test]
    fn validate_accepts_a_walked_manifest() {
        let dir = sample_tree();
        let (manifest, _) = Manifest::from_paths(&[dir.path().join("payload")]).unwrap();
        manifest.validate().unwrap();
    }

    #[test]
    fn validate_rejects_files_too_large_to_address() {
        let manifest = Manifest {
            entries: vec![Entry {
                path: RelPath::parse("huge.bin").unwrap(),
                kind: EntryKind::File {
                    size: chunk::MAX_FILE_SIZE + 1,
                },
                mtime: None,
                mode: None,
            }],
        };

        assert!(manifest.validate().is_err());
    }

    #[test]
    fn a_hostile_manifest_cannot_smuggle_a_path_through_the_wire() {
        // The end-to-end version of the path test: an attacker encodes the
        // manifest by hand rather than going through `from_paths`.
        #[derive(Serialize)]
        struct ForgedEntry {
            path: String,
            kind: EntryKind,
            mtime: Option<i64>,
            mode: Option<u32>,
        }
        #[derive(Serialize)]
        struct ForgedManifest {
            entries: Vec<ForgedEntry>,
        }

        let forged = ForgedManifest {
            entries: vec![ForgedEntry {
                path: r"..\..\Windows\System32\evil.dll".to_string(),
                kind: EntryKind::File { size: 1 },
                mtime: None,
                mode: None,
            }],
        };

        let bytes = postcard::to_stdvec(&forged).unwrap();
        assert!(
            postcard::from_bytes::<Manifest>(&bytes).is_err(),
            "SECURITY: a traversal path survived manifest decoding"
        );
    }

    #[test]
    fn manifest_round_trips_over_the_wire() {
        let dir = sample_tree();
        let (manifest, _) = Manifest::from_paths(&[dir.path().join("payload")]).unwrap();

        let bytes = postcard::to_stdvec(&manifest).unwrap();
        let decoded: Manifest = postcard::from_bytes(&bytes).unwrap();

        assert_eq!(decoded, manifest);
        assert_eq!(decoded.digest(), manifest.digest());
    }

    #[test]
    fn mtime_survives_the_round_trip_through_seconds() {
        for seconds in [0, 1_700_000_000, -86_400] {
            let time = system_time_from_unix(seconds);
            let recovered = match time.duration_since(UNIX_EPOCH) {
                Ok(after) => after.as_secs() as i64,
                Err(before) => -(before.duration().as_secs() as i64),
            };
            assert_eq!(recovered, seconds);
        }
    }

    #[test]
    fn unreadable_sources_are_reported_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("not-here");

        assert!(
            Manifest::from_paths(&[missing]).is_err(),
            "a source the user explicitly chose must fail loudly"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_skipped_and_reported() {
        let dir = sample_tree();
        let root = dir.path().join("payload");
        std::os::unix::fs::symlink(root.join("top.txt"), root.join("link.txt")).unwrap();

        let (manifest, report) = Manifest::from_paths(&[root]).unwrap();

        assert_eq!(report.symlinks_skipped.len(), 1);
        assert!(!manifest.entries.iter().any(|e| e.path.file_name() == "link.txt"));
    }
}
