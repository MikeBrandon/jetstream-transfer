//! Resumable uploads from a browser.
//!
//! The browser slices each file client-side and PUTs the pieces, which is what
//! makes this resumable: a phone that loses signal at 80% asks what is missing
//! and sends only that. A plain `<form>` upload cannot do it — losing the
//! connection means starting the whole file again, which is precisely the Dukto
//! failure this project exists to fix.
//!
//! Chunks land in exactly the same [`Staging`] area the native path uses, with
//! the same bitmaps and the same crash safety. The only difference is the
//! integrity check: a CRC-32 from JavaScript instead of a BLAKE3 from a peer.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use jetstream_core::chunk::CHUNK_SIZE;
use jetstream_core::manifest::{Entry, EntryKind, Manifest};
use jetstream_core::path::RelPath;
use jetstream_core::staging::{ConflictPolicy, Staging};
use jetstream_core::transfer::Progress;
use serde::{Deserialize, Serialize};

/// Largest number of files one browser upload may declare.
///
/// A browser folder selection can be large, but nothing like a native transfer.
/// Bounded so a hostile request cannot make us build an enormous manifest.
pub const MAX_FILES: usize = 20_000;

/// What the browser declares before sending anything.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadRequest {
    pub files: Vec<UploadFile>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadFile {
    /// Relative path as the browser reports it. Fully untrusted: validated
    /// through [`RelPath`] exactly as a native manifest entry is, so a
    /// `../../` cannot escape the destination.
    pub path: String,
    pub size: u64,
}

/// What the browser needs in order to send, or resume.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadPlan {
    pub transfer_id: String,
    pub chunk_size: u64,
    /// Per-file list of chunk ranges still wanted, as `[start, end)` pairs.
    /// Empty for a file that is already complete — which is how resume works
    /// without the browser having to remember anything.
    pub needed: Vec<FileNeed>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileNeed {
    pub index: u32,
    pub path: String,
    pub size: u64,
    pub ranges: Vec<[u32; 2]>,
}

/// An accepted upload in progress.
pub struct Upload {
    pub staging: Staging,
    pub progress: Arc<Progress>,
    pub placed: Vec<String>,
}

/// Every upload currently accepted, keyed by transfer id.
pub struct Uploads {
    inner: Mutex<HashMap<String, Arc<tokio::sync::Mutex<Upload>>>>,
}

#[derive(Debug, thiserror::Error)]
pub enum UploadError {
    #[error("no such upload — it may have finished or the app may have restarted")]
    Unknown,

    #[error("chunk failed its checksum, so it was not written")]
    BadChecksum,

    #[error("{0}")]
    Invalid(String),

    /// The person at the computer stopped this upload.
    #[error("stopped on the other device — what already arrived was kept")]
    Stopped,
}

impl Uploads {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Turn a browser's declared file list into a manifest and open staging.
    ///
    /// Returns the plan the browser should follow, which for a resumed upload
    /// names only the missing chunks.
    pub fn begin(
        &self,
        request: &UploadRequest,
        destination: PathBuf,
        conflict: ConflictPolicy,
        progress: Arc<Progress>,
    ) -> Result<UploadPlan, UploadError> {
        if request.files.is_empty() {
            return Err(UploadError::Invalid("nothing to upload".into()));
        }
        if request.files.len() > MAX_FILES {
            return Err(UploadError::Invalid(format!(
                "too many files in one upload (limit {MAX_FILES})"
            )));
        }

        // Same validation as a native manifest: every path goes through
        // `RelPath`, so traversal, drive letters, reserved device names and
        // trailing dots are all refused before anything touches the disk.
        let mut entries = Vec::with_capacity(request.files.len());
        for file in &request.files {
            let path = RelPath::parse(&file.path)
                .map_err(|e| UploadError::Invalid(format!("unsafe path: {e}")))?;

            entries.push(Entry {
                path,
                kind: EntryKind::File { size: file.size },
                // A browser cannot report a reliable mtime for a file the user
                // picked, so we do not invent one. The file gets its arrival
                // time, which is honest.
                mtime: None,
                mode: None,
            });
        }

        entries.sort_by(|a, b| a.path.cmp(&b.path));
        entries.dedup_by(|a, b| a.path == b.path);

        let manifest = Manifest { entries };
        manifest
            .validate()
            .map_err(|e| UploadError::Invalid(e.to_string()))?;

        std::fs::create_dir_all(&destination)
            .map_err(|e| UploadError::Invalid(format!("cannot use the download folder: {e}")))?;

        // Progress is persisted for every file regardless of size. The native
        // path skips this for small files because re-sending over a LAN is
        // cheaper than the fsyncs — but a phone uploading over patchy Wi-Fi is
        // the opposite case, and losing a 5 MB upload at 80% is exactly the
        // failure this project exists to prevent.
        let staging = Staging::open_tracking_all(&destination, manifest, conflict)
            .map_err(|e| UploadError::Invalid(e.to_string()))?;

        let transfer_id = staging.transfer_id();
        progress
            .bytes_total
            .store(staging.manifest().total_bytes(), std::sync::atomic::Ordering::Relaxed);
        progress
            .bytes_done
            .store(staging.bytes_present(), std::sync::atomic::Ordering::Relaxed);
        progress.files_total.store(
            staging.manifest().summary().file_count,
            std::sync::atomic::Ordering::Relaxed,
        );
        progress.files_done.store(
            staging.files_present(),
            std::sync::atomic::Ordering::Relaxed,
        );

        let plan = plan_for(&staging, &transfer_id);

        self.inner.lock().expect("uploads poisoned").insert(
            transfer_id.clone(),
            Arc::new(tokio::sync::Mutex::new(Upload {
                staging,
                progress,
                placed: Vec::new(),
            })),
        );

        Ok(plan)
    }

    fn get(&self, transfer_id: &str) -> Result<Arc<tokio::sync::Mutex<Upload>>, UploadError> {
        self.inner
            .lock()
            .expect("uploads poisoned")
            .get(transfer_id)
            .cloned()
            .ok_or(UploadError::Unknown)
    }

    /// Store one chunk.
    pub async fn write_chunk(
        &self,
        transfer_id: &str,
        entry: u32,
        chunk_index: u32,
        expected_crc: u32,
        data: &[u8],
    ) -> Result<(), UploadError> {
        if data.len() as u64 > CHUNK_SIZE {
            return Err(UploadError::Invalid("chunk larger than the agreed size".into()));
        }

        // Resolve the transfer before checking the payload, so an unknown
        // transfer reports as unknown rather than as a checksum failure. The
        // browser reacts differently to the two — one means "ask what you still
        // need", the other means "send that chunk again".
        let upload = self.get(transfer_id)?;

        // Checked before the data is written, so a corrupt chunk never reaches
        // the partial file — the same ordering the native path uses.
        if crate::crc32(data) != expected_crc {
            return Err(UploadError::BadChecksum);
        }

        let mut upload = upload.lock().await;

        // Cancelled from the computer's transfer list. Nothing else would stop a
        // browser, which simply keeps sending until it is told no.
        if upload.progress.cancelled() || upload.progress.paused() {
            return Err(UploadError::Stopped);
        }

        // The staging layer requires a BLAKE3 per chunk. Computing it here makes
        // that check a formality for this path — the end-to-end guarantee came
        // from the CRC above — but it keeps the on-disk format identical to a
        // native transfer, so bitmaps, resume, and crash recovery all behave
        // exactly the same.
        let hash = blake3_of(data);

        let fresh = upload
            .staging
            .write_chunk(entry, chunk_index, data, &hash)
            .map_err(|e| UploadError::Invalid(e.to_string()))?;

        if fresh {
            // Through `advance` so it counts towards the speed shown, not only
            // towards the bar — browser uploads used to show no speed at all.
            upload.progress.advance(data.len() as u64);

            // Persist the bitmap after **every** chunk, unlike the native path
            // which batches checkpoints.
            //
            // A browser can disappear between any two requests — the tab closes,
            // the phone locks, the user walks out of Wi-Fi range — and there is
            // no connection whose loss we could react to. Anything not
            // checkpointed is simply gone, which would make resume, the whole
            // point of this path, silently useless. An fsync per megabyte is a
            // cheap price on a link that will not exceed a few tens of MB/s.
            if let Err(e) = upload.staging.checkpoint(entry) {
                tracing::warn!(entry, error = %e, "could not checkpoint an upload");
            }
        }

        // Deliver as soon as a file is whole, rather than batching to the end,
        // so an upload abandoned halfway still leaves usable files.
        if upload.staging.is_file_complete(entry) && !upload.staging.is_placed(entry) {
            match upload.staging.finish_file_chunkwise(entry) {
                Ok(placement) => {
                    upload
                        .progress
                        .files_done
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    upload.placed.push(describe_placement(&placement));
                }
                Err(e) => tracing::warn!(entry, error = %e, "could not place an uploaded file"),
            }
        }

        Ok(())
    }

    /// What is still missing, so a resumed upload can ask.
    pub async fn status(&self, transfer_id: &str) -> Result<UploadPlan, UploadError> {
        let upload = self.get(transfer_id)?;
        let upload = upload.lock().await;
        Ok(plan_for(&upload.staging, transfer_id))
    }

    /// Complete the upload, creating any empty files and cleaning up staging.
    pub async fn finish(&self, transfer_id: &str) -> Result<Vec<String>, UploadError> {
        let upload = self
            .inner
            .lock()
            .expect("uploads poisoned")
            .remove(transfer_id)
            .ok_or(UploadError::Unknown)?;

        let mut upload = upload.lock().await;
        let mut placed = std::mem::take(&mut upload.placed);

        // `Staging::finish` consumes self, so swap in a throwaway to move the
        // real one out of the guard.
        let staging = std::mem::replace(
            &mut upload.staging,
            Staging::open(
                &std::env::temp_dir().join("jetstream-discarded"),
                Manifest::default(),
                ConflictPolicy::Skip,
            )
            .map_err(|e| UploadError::Invalid(e.to_string()))?,
        );

        for placement in staging.finish().map_err(|e| UploadError::Invalid(e.to_string()))? {
            placed.push(describe_placement(&placement));
        }

        Ok(placed)
    }

}

fn plan_for(staging: &Staging, transfer_id: &str) -> UploadPlan {
    let mut needed = Vec::new();

    for (index, entry) in staging.manifest().entries.iter().enumerate() {
        if !entry.is_file() {
            continue;
        }
        let index = index as u32;

        let ranges = if staging.is_placed(index) {
            Vec::new()
        } else {
            staging
                .chunk_map(index)
                .map(|map| {
                    map.missing_ranges()
                        .into_iter()
                        .map(|range| [range.start, range.end])
                        .collect()
                })
                .unwrap_or_default()
        };

        needed.push(FileNeed {
            index,
            path: entry.path.as_str().to_string(),
            size: entry.size(),
            ranges,
        });
    }

    UploadPlan {
        transfer_id: transfer_id.to_string(),
        chunk_size: CHUNK_SIZE,
        needed,
    }
}

fn blake3_of(data: &[u8]) -> [u8; 32] {
    // `Staging::write_chunk` wants a BLAKE3; jetstream-core re-exports nothing
    // for this, so hash directly through the same crate it uses.
    *blake3_hasher(data).as_bytes()
}

fn blake3_hasher(data: &[u8]) -> blake3::Hash {
    blake3::hash(data)
}

fn describe_placement(placement: &jetstream_core::staging::Placement) -> String {
    use jetstream_core::staging::Placement;

    match placement {
        Placement::Created(path)
        | Placement::Renamed(path)
        | Placement::Overwritten(path)
        | Placement::Skipped(path) => path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| path.display().to_string()),
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use jetstream_core::chunk;

    fn request(files: &[(&str, u64)]) -> UploadRequest {
        UploadRequest {
            files: files
                .iter()
                .map(|(path, size)| UploadFile {
                    path: (*path).to_string(),
                    size: *size,
                })
                .collect(),
        }
    }

    fn payload(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed)).collect()
    }

    /// Cancelling a browser upload on the computer used to change nothing: the
    /// phone kept sending and the files kept landing.
    #[tokio::test]
    async fn a_cancelled_upload_refuses_further_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let uploads = Uploads::new();
        let progress = Arc::new(Progress::default());
        let data = payload(3000, 2);

        let plan = uploads
            .begin(
                &request(&[("photo.jpg", data.len() as u64)]),
                dir.path().to_path_buf(),
                ConflictPolicy::Rename,
                Arc::clone(&progress),
            )
            .unwrap();

        progress.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        let refused = uploads
            .write_chunk(&plan.transfer_id, 0, 0, crate::crc32(&data), &data)
            .await;
        assert!(matches!(refused, Err(UploadError::Stopped)), "got {refused:?}");
        assert!(!dir.path().join("photo.jpg").exists());
    }

    #[tokio::test]
    async fn uploaded_bytes_count_towards_the_speed_shown() {
        let dir = tempfile::tempdir().unwrap();
        let uploads = Uploads::new();
        let progress = Arc::new(Progress::default());
        let data = payload(3000, 3);

        let plan = uploads
            .begin(
                &request(&[("photo.jpg", data.len() as u64)]),
                dir.path().to_path_buf(),
                ConflictPolicy::Rename,
                Arc::clone(&progress),
            )
            .unwrap();
        uploads
            .write_chunk(&plan.transfer_id, 0, 0, crate::crc32(&data), &data)
            .await
            .unwrap();

        assert_eq!(
            progress.bytes_moved.load(std::sync::atomic::Ordering::Relaxed),
            data.len() as u64
        );
    }

    #[tokio::test]
    async fn a_browser_upload_lands_in_the_destination() {
        let dir = tempfile::tempdir().unwrap();
        let uploads = Uploads::new();
        let data = payload(3000, 1);

        let plan = uploads
            .begin(
                &request(&[("photo.jpg", data.len() as u64)]),
                dir.path().to_path_buf(),
                ConflictPolicy::Rename,
                Arc::new(Progress::default()),
            )
            .unwrap();

        assert_eq!(plan.needed.len(), 1);
        assert_eq!(plan.needed[0].ranges, vec![[0, 1]]);

        uploads
            .write_chunk(&plan.transfer_id, 0, 0, crate::crc32(&data), &data)
            .await
            .unwrap();

        let placed = uploads.finish(&plan.transfer_id).await.unwrap();
        assert_eq!(placed, vec!["photo.jpg"]);
        assert_eq!(std::fs::read(dir.path().join("photo.jpg")).unwrap(), data);
    }

    #[tokio::test]
    async fn a_corrupt_chunk_is_refused_and_stays_outstanding() {
        let dir = tempfile::tempdir().unwrap();
        let uploads = Uploads::new();
        let data = payload(2000, 2);

        let plan = uploads
            .begin(
                &request(&[("f.bin", data.len() as u64)]),
                dir.path().to_path_buf(),
                ConflictPolicy::Rename,
                Arc::new(Progress::default()),
            )
            .unwrap();

        let mut corrupt = data.clone();
        corrupt[10] ^= 0xFF;

        let error = uploads
            .write_chunk(&plan.transfer_id, 0, 0, crate::crc32(&data), &corrupt)
            .await
            .unwrap_err();
        assert!(matches!(error, UploadError::BadChecksum));

        // Still wanted, so the browser will send it again.
        let status = uploads.status(&plan.transfer_id).await.unwrap();
        assert_eq!(status.needed[0].ranges, vec![[0, 1]]);
    }

    /// The headline feature of this path: a phone that dropped off mid-upload
    /// asks what is missing and sends only that.
    #[tokio::test]
    async fn an_interrupted_upload_resumes_from_what_is_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let size = CHUNK_SIZE * 3 + 500;
        let data = payload(size as usize, 3);
        let files = request(&[("video.mp4", size)]);

        // First attempt: two of four chunks, then the browser vanishes.
        let first_id = {
            let uploads = Uploads::new();
            let plan = uploads
                .begin(
                    &files,
                    dir.path().to_path_buf(),
                    ConflictPolicy::Rename,
                    Arc::new(Progress::default()),
                )
                .unwrap();

            for index in 0..2u32 {
                let (offset, len) = chunk::chunk_span(index, size).unwrap();
                let slice = &data[offset as usize..offset as usize + len];
                uploads
                    .write_chunk(&plan.transfer_id, 0, index, crate::crc32(slice), slice)
                    .await
                    .unwrap();
            }
            plan.transfer_id
        };

        // Second attempt: a brand-new server, same destination and file list.
        let uploads = Uploads::new();
        let plan = uploads
            .begin(
                &files,
                dir.path().to_path_buf(),
                ConflictPolicy::Rename,
                Arc::new(Progress::default()),
            )
            .unwrap();

        assert_eq!(
            plan.transfer_id, first_id,
            "the same file list must resume the same transfer, not start a new one"
        );
        assert_eq!(
            plan.needed[0].ranges,
            vec![[2, 4]],
            "only the missing tail should be requested"
        );

        for index in 2..4u32 {
            let (offset, len) = chunk::chunk_span(index, size).unwrap();
            let slice = &data[offset as usize..offset as usize + len];
            uploads
                .write_chunk(&plan.transfer_id, 0, index, crate::crc32(slice), slice)
                .await
                .unwrap();
        }
        uploads.finish(&plan.transfer_id).await.unwrap();

        assert_eq!(
            std::fs::read(dir.path().join("video.mp4")).unwrap(),
            data,
            "the resumed upload must be byte-identical"
        );
    }

    #[tokio::test]
    async fn files_are_delivered_as_they_complete() {
        let dir = tempfile::tempdir().unwrap();
        let uploads = Uploads::new();
        let small = payload(100, 4);

        let plan = uploads
            .begin(
                &request(&[("a.txt", small.len() as u64), ("b.txt", CHUNK_SIZE * 2)]),
                dir.path().to_path_buf(),
                ConflictPolicy::Rename,
                Arc::new(Progress::default()),
            )
            .unwrap();

        let a = plan.needed.iter().find(|f| f.path == "a.txt").unwrap().index;
        uploads
            .write_chunk(&plan.transfer_id, a, 0, crate::crc32(&small), &small)
            .await
            .unwrap();

        // Delivered already, without waiting for the large file or `finish`.
        assert!(dir.path().join("a.txt").exists());
        assert!(!dir.path().join("b.txt").exists());
    }

    /// The security check that matters most on this path: a browser is fully
    /// untrusted, and a crafted request must not be able to write outside the
    /// download folder.
    #[tokio::test]
    async fn hostile_paths_are_refused_before_anything_is_created() {
        let dir = tempfile::tempdir().unwrap();
        let uploads = Uploads::new();

        for hostile in [
            "../escaped.txt",
            "..\\..\\Windows\\System32\\evil.dll",
            "C:\\Windows\\evil.dll",
            "/etc/passwd",
            "CON",
            "trailing.",
            "nul.txt",
        ] {
            let error = uploads
                .begin(
                    &request(&[(hostile, 10)]),
                    dir.path().to_path_buf(),
                    ConflictPolicy::Rename,
                    Arc::new(Progress::default()),
                )
                .unwrap_err();

            assert!(
                matches!(error, UploadError::Invalid(_)),
                "SECURITY: {hostile:?} was accepted"
            );
        }

        // Nothing at all should have been created by the rejected attempts.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn absurd_requests_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let uploads = Uploads::new();
        let destination = dir.path().to_path_buf();

        assert!(
            uploads
                .begin(
                    &request(&[]),
                    destination.clone(),
                    ConflictPolicy::Rename,
                    Arc::new(Progress::default())
                )
                .is_err(),
            "an empty upload"
        );

        let many: Vec<(String, u64)> = (0..MAX_FILES + 1)
            .map(|i| (format!("f{i}.bin"), 1))
            .collect();
        let borrowed: Vec<(&str, u64)> = many.iter().map(|(p, s)| (p.as_str(), *s)).collect();

        assert!(
            uploads
                .begin(
                    &request(&borrowed),
                    destination,
                    ConflictPolicy::Rename,
                    Arc::new(Progress::default())
                )
                .is_err(),
            "more files than the limit"
        );
    }

    #[tokio::test]
    async fn an_oversized_chunk_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let uploads = Uploads::new();

        let plan = uploads
            .begin(
                &request(&[("f.bin", 100)]),
                dir.path().to_path_buf(),
                ConflictPolicy::Rename,
                Arc::new(Progress::default()),
            )
            .unwrap();

        let huge = vec![0u8; CHUNK_SIZE as usize + 1];
        assert!(
            uploads
                .write_chunk(&plan.transfer_id, 0, 0, crate::crc32(&huge), &huge)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn writing_to_an_unknown_transfer_fails_cleanly() {
        let uploads = Uploads::new();
        let error = uploads
            .write_chunk("deadbeef", 0, 0, 0, b"data")
            .await
            .unwrap_err();

        assert!(matches!(error, UploadError::Unknown));
    }

    #[tokio::test]
    async fn progress_reflects_what_has_arrived() {
        let dir = tempfile::tempdir().unwrap();
        let uploads = Uploads::new();
        let progress = Arc::new(Progress::default());
        let data = payload(500, 6);

        let plan = uploads
            .begin(
                &request(&[("f.bin", data.len() as u64)]),
                dir.path().to_path_buf(),
                ConflictPolicy::Rename,
                Arc::clone(&progress),
            )
            .unwrap();

        use std::sync::atomic::Ordering;
        assert_eq!(progress.bytes_total.load(Ordering::Relaxed), 500);
        assert_eq!(progress.bytes_done.load(Ordering::Relaxed), 0);

        uploads
            .write_chunk(&plan.transfer_id, 0, 0, crate::crc32(&data), &data)
            .await
            .unwrap();

        assert_eq!(progress.bytes_done.load(Ordering::Relaxed), 500);
        assert_eq!(progress.files_done.load(Ordering::Relaxed), 1);
    }
}
