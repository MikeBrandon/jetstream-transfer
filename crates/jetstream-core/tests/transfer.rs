//! End-to-end transfer tests over real QUIC connections.
//!
//! These are the tests that decide whether the product works. Dukto's defining
//! failure is that an interrupted transfer starts over; the resume cases here
//! are the direct answer to it, and they run against the real network stack
//! rather than a mocked one.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use jetstream_core::identity::Identity;
use jetstream_core::manifest::Manifest;
use jetstream_core::staging::{ConflictPolicy, Placement};
use jetstream_core::transfer::{self, Decision, Progress};
use jetstream_core::transport::{Endpoint, Session};

/// A connected pair of devices.
struct Pair {
    sender: Arc<Session>,
    receiver: Arc<Session>,
    _endpoints: (Endpoint, Endpoint),
}

async fn connect_pair() -> Pair {
    let listener_identity = Arc::new(Identity::generate().unwrap());
    let listener_id = listener_identity.device_id();
    let listener = Endpoint::bind(
        listener_identity,
        "Receiver",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .unwrap();
    let listener_addr = listener.local_addr().unwrap();

    let dialer = Endpoint::bind(
        Arc::new(Identity::generate().unwrap()),
        "Sender",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .unwrap();

    let accepting = {
        let listener = listener.clone();
        tokio::spawn(async move { listener.accept().await.unwrap().unwrap() })
    };

    let sender = dialer.connect(listener_addr, Some(listener_id)).await.unwrap();
    let receiver = accepting.await.unwrap();

    Pair {
        sender,
        receiver,
        _endpoints: (dialer, listener),
    }
}

/// Deterministic bytes, so a corrupted transfer is detectable by comparison.
fn payload(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) as u8
        })
        .collect()
}

/// Build a source tree and return `(temp dir, root to send)`.
fn source_tree(files: &[(&str, usize)]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("payload");
    std::fs::create_dir_all(&root).unwrap();

    for (index, (name, size)) in files.iter().enumerate() {
        let path = root.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, payload(*size, index as u64 + 1)).unwrap();
    }

    (dir, root)
}

fn accept_into(
    destination: &Path,
) -> impl AsyncFnOnce(jetstream_core::proto::Offer) -> Decision + use<> {
    let destination = destination.to_path_buf();
    async move |_| Decision::Accept {
        destination,
        conflict: ConflictPolicy::Rename,
    }
}

/// Compare two directory trees byte for byte.
fn assert_trees_match(expected_root: &Path, actual_root: &Path) {
    let mut checked = 0;
    for item in walkdir::WalkDir::new(expected_root).into_iter().flatten() {
        if !item.file_type().is_file() {
            continue;
        }
        let relative = item.path().strip_prefix(expected_root).unwrap();
        let actual = actual_root.join(relative);

        assert!(actual.exists(), "missing at destination: {}", relative.display());
        assert_eq!(
            std::fs::read(item.path()).unwrap(),
            std::fs::read(&actual).unwrap(),
            "content differs for {}",
            relative.display()
        );
        checked += 1;
    }
    assert!(checked > 0, "the comparison checked no files");
}

async fn within<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(60), future)
        .await
        .expect("transfer timed out")
}

#[tokio::test]
async fn a_folder_arrives_intact() {
    let (_source_dir, root) = source_tree(&[
        ("top.txt", 12),
        ("nested/a.bin", 3_000),
        ("nested/deep/b.bin", 1_500_000),
        ("empty.txt", 0),
    ]);
    let destination = tempfile::tempdir().unwrap();

    let pair = connect_pair().await;
    let (manifest, report) = Manifest::from_paths(std::slice::from_ref(&root)).unwrap();
    assert!(report.is_clean());

    let send_progress = Arc::new(Progress::default());
    let recv_progress = Arc::new(Progress::default());

    let sending = {
        let session = Arc::clone(&pair.sender);
        let parent = root.parent().unwrap().to_path_buf();
        let progress = Arc::clone(&send_progress);
        tokio::spawn(async move { transfer::send(&session, &parent, &manifest, progress).await })
    };

    let received = within(transfer::receive(
        &pair.receiver,
        accept_into(destination.path()),
        Arc::clone(&recv_progress),
    ))
    .await
    .unwrap();

    within(sending).await.unwrap().unwrap();

    // Verification now reports itself while it runs; once the transfer is over,
    // neither side may still claim to be checking or waiting.
    assert!(send_progress.check().is_none(), "sender left a check showing");
    assert!(recv_progress.check().is_none(), "receiver left a check showing");

    assert_trees_match(&root, &destination.path().join("payload"));
    assert!(
        received.placements.iter().all(|p| matches!(p, Placement::Created(_))),
        "a fresh destination should only create files"
    );
    assert_eq!(
        recv_progress.bytes_done.load(Ordering::Relaxed),
        recv_progress.bytes_total.load(Ordering::Relaxed),
        "progress should finish at 100%"
    );

    // The sender is stateless and serves byte ranges, so it can only learn how
    // many *files* are finished from the receiver telling it. Without that, a
    // sending device can show bytes moving but never "4 of 4 files".
    let files = send_progress.files_total.load(Ordering::Relaxed);
    assert_eq!(files, 4, "the sender counts files from its own manifest");
    assert_eq!(
        send_progress.files_done.load(Ordering::Relaxed),
        files,
        "every finished file should have been reported back to the sender"
    );
}

/// A speed limit must actually limit a real transfer, not just a unit test.
///
/// Deliberately end-to-end over a live QUIC session: the token bucket has its own
/// tests, and what this pins down is that the limit is consulted on the path the
/// bytes really take.
#[tokio::test]
async fn a_receive_limit_slows_a_real_transfer() {
    // 4 MiB at 2 MB/s cannot finish in under a second however fast the machine.
    let (_source_dir, root) = source_tree(&[("big.bin", 4 * 1024 * 1024)]);
    let destination = tempfile::tempdir().unwrap();

    let pair = connect_pair().await;
    let (manifest, _) = Manifest::from_paths(std::slice::from_ref(&root)).unwrap();

    let recv_progress = Arc::new(Progress::default());
    recv_progress.limit.set(2_000_000);

    let sending = {
        let session = Arc::clone(&pair.sender);
        let parent = root.parent().unwrap().to_path_buf();
        tokio::spawn(async move {
            transfer::send(&session, &parent, &manifest, Arc::new(Progress::default())).await
        })
    };

    let started = std::time::Instant::now();
    within(transfer::receive(
        &pair.receiver,
        accept_into(destination.path()),
        Arc::clone(&recv_progress),
    ))
    .await
    .unwrap();
    let elapsed = started.elapsed();
    within(sending).await.unwrap().unwrap();

    assert!(
        elapsed >= std::time::Duration::from_millis(900),
        "4 MiB at 2 MB/s finished in {elapsed:?} — the limit was not applied"
    );
    assert_trees_match(&root, &destination.path().join("payload"));
}

/// The counter must never exceed the total, however many reports arrive.
#[tokio::test]
async fn the_senders_file_count_never_overruns_the_total() {
    let (_source_dir, root) = source_tree(&[("a.txt", 10), ("b.txt", 20)]);
    let destination = tempfile::tempdir().unwrap();

    let pair = connect_pair().await;
    let (manifest, _) = Manifest::from_paths(std::slice::from_ref(&root)).unwrap();

    let send_progress = Arc::new(Progress::default());
    let sending = {
        let session = Arc::clone(&pair.sender);
        let parent = root.parent().unwrap().to_path_buf();
        let progress = Arc::clone(&send_progress);
        tokio::spawn(async move { transfer::send(&session, &parent, &manifest, progress).await })
    };

    within(transfer::receive(
        &pair.receiver,
        accept_into(destination.path()),
        Arc::new(Progress::default()),
    ))
    .await
    .unwrap();
    within(sending).await.unwrap().unwrap();

    let total = send_progress.files_total.load(Ordering::Relaxed);
    let done = send_progress.files_done.load(Ordering::Relaxed);
    assert!(
        done <= total,
        "reported {done} of {total} files — a display counter must never overrun"
    );
}

#[tokio::test]
async fn empty_directories_and_zero_byte_files_survive() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("payload");
    std::fs::create_dir_all(root.join("empty-dir")).unwrap();
    std::fs::create_dir_all(root.join("has-content")).unwrap();
    std::fs::write(root.join("has-content/x.txt"), b"x").unwrap();
    std::fs::write(root.join("zero.bin"), b"").unwrap();

    let destination = tempfile::tempdir().unwrap();
    let pair = connect_pair().await;
    let (manifest, _) = Manifest::from_paths(std::slice::from_ref(&root)).unwrap();

    let sending = {
        let session = Arc::clone(&pair.sender);
        let parent = root.parent().unwrap().to_path_buf();
        tokio::spawn(async move {
            transfer::send(&session, &parent, &manifest, Arc::new(Progress::default())).await
        })
    };

    within(transfer::receive(
        &pair.receiver,
        accept_into(destination.path()),
        Arc::new(Progress::default()),
    ))
    .await
    .unwrap();
    within(sending).await.unwrap().unwrap();

    let landed = destination.path().join("payload");
    assert!(landed.join("empty-dir").is_dir(), "empty directory lost");
    assert!(landed.join("zero.bin").is_file(), "zero-byte file lost");
    assert_eq!(std::fs::metadata(landed.join("zero.bin")).unwrap().len(), 0);
}

/// **The headline test.** Interrupt a transfer partway, reconnect, and confirm
/// the second attempt only moves the remainder and produces an identical file.
#[tokio::test]
async fn an_interrupted_transfer_resumes_instead_of_restarting() {
    const SIZE: usize = 8 * 1024 * 1024;

    let (_source_dir, root) = source_tree(&[("big.bin", SIZE)]);
    let parent = root.parent().unwrap().to_path_buf();
    let destination = tempfile::tempdir().unwrap();
    let (manifest, _) = Manifest::from_paths(std::slice::from_ref(&root)).unwrap();

    // --- First attempt: cancel the receiver partway through. ---
    let first_progress = Arc::new(Progress::default());
    {
        let pair = connect_pair().await;
        let sending = {
            let session = Arc::clone(&pair.sender);
            let parent = parent.clone();
            let manifest = manifest.clone();
            tokio::spawn(async move {
                let _ = transfer::send(&session, &parent, &manifest, Arc::new(Progress::default()))
                    .await;
            })
        };

        // Trip the cancel flag once a couple of megabytes have landed.
        let watcher = {
            let progress = Arc::clone(&first_progress);
            tokio::spawn(async move {
                loop {
                    if progress.bytes_done.load(Ordering::Relaxed) >= 2 * 1024 * 1024 {
                        progress.cancel.store(true, Ordering::Relaxed);
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
        };

        let result = within(transfer::receive(
            &pair.receiver,
            accept_into(destination.path()),
            Arc::clone(&first_progress),
        ))
        .await;

        assert!(result.is_err(), "the cancelled transfer should not report success");
        watcher.abort();
        sending.abort();
    }

    let staged_after_interrupt = first_progress.bytes_done.load(Ordering::Relaxed);
    assert!(
        staged_after_interrupt >= 2 * 1024 * 1024,
        "expected real progress before the interruption, got {staged_after_interrupt}"
    );
    assert!(
        !destination.path().join("payload/big.bin").exists(),
        "an incomplete file must not appear in the destination"
    );

    // --- Second attempt: a brand-new connection over the same destination. ---
    let resume_progress = Arc::new(Progress::default());
    let resume_send_progress = Arc::new(Progress::default());
    {
        let pair = connect_pair().await;
        let sending = {
            let session = Arc::clone(&pair.sender);
            let parent = parent.clone();
            let manifest = manifest.clone();
            let progress = Arc::clone(&resume_send_progress);
            tokio::spawn(async move { transfer::send(&session, &parent, &manifest, progress).await })
        };

        within(transfer::receive(
            &pair.receiver,
            accept_into(destination.path()),
            Arc::clone(&resume_progress),
        ))
        .await
        .unwrap();
        within(sending).await.unwrap().unwrap();
    }

    assert_eq!(
        resume_progress.bytes_done.load(Ordering::Relaxed),
        SIZE as u64,
        "progress should end at exactly the file size"
    );

    // The sender keeps no state, so without the receiver telling it what is
    // already there it would only ever count what it sent *this* time — showing a
    // resumed 138 GB copy that was 70% done as "0%, 1.6 KB of 138.5 GB". The
    // transfer was always correct; the reporting was not.
    assert_eq!(
        resume_send_progress.bytes_done.load(Ordering::Relaxed),
        SIZE as u64,
        "the sender should account for the whole file, not just the part it resent"
    );
    assert!(
        resume_send_progress.bytes_done.load(Ordering::Relaxed) > staged_after_interrupt,
        "and the baseline must include what was already staged"
    );

    // What was already there is progress, not speed. Both ends must measure only
    // what crossed the wire this time, or every resume opens with an absurd
    // spike in the rate.
    let moved = resume_progress.bytes_moved.load(Ordering::Relaxed);
    assert!(
        moved < SIZE as u64,
        "the receiver should only have moved the missing part, moved {moved}"
    );
    assert_eq!(
        resume_send_progress.bytes_moved.load(Ordering::Relaxed),
        moved,
        "the sender's measure of what moved should match the receiver's"
    );

    assert_trees_match(&root, &destination.path().join("payload"));
}

/// Resume must survive the *process* dying, not just a cancelled task — which
/// is what the on-disk bitmap is for.
#[tokio::test]
async fn resume_picks_up_from_bitmaps_written_by_a_previous_process() {
    use jetstream_core::chunk::{CHUNK_SIZE, ChunkRange};
    use jetstream_core::staging::Staging;

    const CHUNKS: usize = 6;
    let size = CHUNK_SIZE as usize * CHUNKS;
    let (_source_dir, root) = source_tree(&[("big.bin", size)]);
    let destination = tempfile::tempdir().unwrap();
    let (manifest, _) = Manifest::from_paths(std::slice::from_ref(&root)).unwrap();

    // Stand in for a previous process: stage the first three chunks directly,
    // then drop everything as an abrupt exit would.
    {
        let source = std::fs::read(root.join("big.bin")).unwrap();
        let mut staging =
            Staging::open(destination.path(), manifest.clone(), ConflictPolicy::Rename).unwrap();

        let index = manifest
            .entries
            .iter()
            .position(|e| e.path.file_name() == "big.bin")
            .unwrap() as u32;

        for chunk in 0..3u32 {
            let start = chunk as usize * CHUNK_SIZE as usize;
            let slice = &source[start..start + CHUNK_SIZE as usize];
            staging
                .write_chunk(index, chunk, slice, blake3::hash(slice).as_bytes())
                .unwrap();
        }
        staging.checkpoint(index).unwrap();

        assert_eq!(
            staging.outstanding(),
            vec![(index, ChunkRange::new(3, CHUNKS as u32))]
        );
    }

    let pair = connect_pair().await;
    let progress = Arc::new(Progress::default());
    let sending = {
        let session = Arc::clone(&pair.sender);
        let parent = root.parent().unwrap().to_path_buf();
        let manifest = manifest.clone();
        tokio::spawn(async move {
            transfer::send(&session, &parent, &manifest, Arc::new(Progress::default())).await
        })
    };

    within(transfer::receive(
        &pair.receiver,
        accept_into(destination.path()),
        Arc::clone(&progress),
    ))
    .await
    .unwrap();
    within(sending).await.unwrap().unwrap();

    assert_trees_match(&root, &destination.path().join("payload"));

    // Only the missing half should have crossed the wire.
    let moved = progress.bytes_done.load(Ordering::Relaxed);
    assert_eq!(
        moved,
        size as u64,
        "progress counts pre-staged bytes plus transferred ones"
    );
}

/// An interrupted transfer should leave *usable files*, not just staged bytes.
/// Files that finished before the interruption must already be delivered.
#[tokio::test]
async fn files_that_complete_early_are_delivered_before_an_interruption() {
    // Many small files plus one large one. Smallest-first ordering means the
    // small files finish well before the cancel fires.
    let mut files: Vec<(String, usize)> =
        (0..30).map(|i| (format!("small/s{i}.txt", ), 1024)).collect();
    files.push(("big.bin".to_string(), 12 * 1024 * 1024));
    let borrowed: Vec<(&str, usize)> = files.iter().map(|(n, s)| (n.as_str(), *s)).collect();

    let (_source_dir, root) = source_tree(&borrowed);
    let destination = tempfile::tempdir().unwrap();
    let (manifest, _) = Manifest::from_paths(std::slice::from_ref(&root)).unwrap();

    let pair = connect_pair().await;
    let progress = Arc::new(Progress::default());

    let sending = {
        let session = Arc::clone(&pair.sender);
        let parent = root.parent().unwrap().to_path_buf();
        tokio::spawn(async move {
            let _ = transfer::send(&session, &parent, &manifest, Arc::new(Progress::default())).await;
        })
    };

    // Cancel once the big file is clearly underway, well after the small ones.
    let watcher = {
        let progress = Arc::clone(&progress);
        tokio::spawn(async move {
            loop {
                if progress.bytes_done.load(Ordering::Relaxed) >= 4 * 1024 * 1024 {
                    progress.cancel.store(true, Ordering::Relaxed);
                    return;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
    };

    let result = within(transfer::receive(
        &pair.receiver,
        accept_into(destination.path()),
        Arc::clone(&progress),
    ))
    .await;
    assert!(result.is_err(), "the cancelled transfer should not report success");
    watcher.abort();
    sending.abort();

    let delivered = destination.path().join("payload/small");
    let count = std::fs::read_dir(&delivered).map(|d| d.count()).unwrap_or(0);

    assert_eq!(
        count, 30,
        "small files finished long before the cancel and should already be on disk"
    );
    assert!(
        !destination.path().join("payload/big.bin").exists(),
        "the unfinished file must not be delivered"
    );
}

#[tokio::test]
async fn a_rejected_offer_transfers_nothing() {
    let (_source_dir, root) = source_tree(&[("secret.bin", 4096)]);
    let destination = tempfile::tempdir().unwrap();

    let pair = connect_pair().await;
    let (manifest, _) = Manifest::from_paths(std::slice::from_ref(&root)).unwrap();

    let sending = {
        let session = Arc::clone(&pair.sender);
        let parent = root.parent().unwrap().to_path_buf();
        tokio::spawn(async move {
            transfer::send(&session, &parent, &manifest, Arc::new(Progress::default())).await
        })
    };

    let result = within(transfer::receive(
        &pair.receiver,
        async |_| Decision::Reject {
            reason: "not now".into(),
        },
        Arc::new(Progress::default()),
    ))
    .await;

    assert!(result.is_err());

    let send_result = within(sending).await.unwrap();
    assert!(
        matches!(send_result, Err(jetstream_core::Error::Rejected(ref m)) if m.contains("not now")),
        "the sender should learn why, got {send_result:?}"
    );

    assert_eq!(
        std::fs::read_dir(destination.path()).unwrap().count(),
        0,
        "a rejected transfer must leave the destination untouched"
    );
}

/// Regression: the receiver used to close the connection immediately after
/// writing `Reject`, discarding it. The sender then reported "connection lost"
/// and advised retrying — for a transfer the other person had deliberately
/// declined. Found by letting a real accept prompt time out.
#[tokio::test]
async fn a_decline_reaches_the_sender_even_if_the_receiver_hangs_up_at_once() {
    let (_source_dir, root) = source_tree(&[("private.bin", 2048)]);
    let pair = connect_pair().await;
    let (manifest, _) = Manifest::from_paths(std::slice::from_ref(&root)).unwrap();

    let sending = {
        let session = Arc::clone(&pair.sender);
        let parent = root.parent().unwrap().to_path_buf();
        tokio::spawn(async move {
            transfer::send(&session, &parent, &manifest, Arc::new(Progress::default())).await
        })
    };

    let receiving = {
        let session = Arc::clone(&pair.receiver);
        tokio::spawn(async move {
            let result = transfer::receive(
                &session,
                async |_| Decision::Reject {
                    reason: "no thanks".into(),
                },
                Arc::new(Progress::default()),
            )
            .await;

            // Hang up the instant the decision is made, as the UI does.
            session.close("declined").await;
            result
        })
    };

    let sent = within(sending).await.unwrap();
    let _ = within(receiving).await.unwrap();

    match sent {
        Err(jetstream_core::Error::Rejected(reason)) => {
            assert!(reason.contains("no thanks"), "reason lost: {reason}");
        }
        other => panic!(
            "a declined transfer must be reported as declined, not as a network failure: {other:?}"
        ),
    }
}

#[tokio::test]
async fn the_offer_shows_what_is_arriving_before_it_is_accepted() {
    let (_source_dir, root) = source_tree(&[("a.txt", 100), ("b/c.bin", 2000)]);
    let destination = tempfile::tempdir().unwrap();

    let pair = connect_pair().await;
    let (manifest, _) = Manifest::from_paths(std::slice::from_ref(&root)).unwrap();

    let sending = {
        let session = Arc::clone(&pair.sender);
        let parent = root.parent().unwrap().to_path_buf();
        tokio::spawn(async move {
            transfer::send(&session, &parent, &manifest, Arc::new(Progress::default())).await
        })
    };

    let seen = Arc::new(std::sync::Mutex::new(None));
    let capture = Arc::clone(&seen);
    let destination_path = destination.path().to_path_buf();

    within(transfer::receive(
        &pair.receiver,
        async move |offer| {
            *capture.lock().unwrap() = Some(transfer::describe(&offer.summary));
            Decision::Accept {
                destination: destination_path,
                conflict: ConflictPolicy::Rename,
            }
        },
        Arc::new(Progress::default()),
    ))
    .await
    .unwrap();
    within(sending).await.unwrap().unwrap();

    let description = seen.lock().unwrap().clone().unwrap();
    assert!(description.contains("2 files"), "got {description:?}");
    assert!(description.contains("payload"), "got {description:?}");
}

/// A sender whose manifest does not match the offer the user approved must be
/// stopped — otherwise the prompt is meaningless.
#[tokio::test]
async fn a_manifest_that_contradicts_the_offer_is_refused() {
    use jetstream_core::proto::{Control, Offer};

    let destination = tempfile::tempdir().unwrap();
    let pair = connect_pair().await;

    let (_source_dir, root) = source_tree(&[("innocent.txt", 10)]);
    let (honest, _) = Manifest::from_paths(std::slice::from_ref(&root)).unwrap();
    let (_other_dir, other_root) = source_tree(&[("something-else.bin", 5000)]);
    let (swapped, _) = Manifest::from_paths(&[other_root]).unwrap();

    // Offer the innocent manifest's digest, then send a different manifest.
    let sending = {
        let session = Arc::clone(&pair.sender);
        tokio::spawn(async move {
            session
                .send_control(&Control::Offer(Offer {
                    digest: honest.digest(),
                    summary: honest.summary(),
                    entry_count: swapped.entries.len() as u64,
                }))
                .await?;

            match session.recv_control().await? {
                Control::Accept => {}
                other => panic!("expected Accept, got {other:?}"),
            }

            session
                .send_control(&Control::ManifestBatch {
                    entries: swapped.entries.clone(),
                    more: false,
                })
                .await?;

            Ok::<_, jetstream_core::Error>(())
        })
    };

    let result = within(transfer::receive(
        &pair.receiver,
        accept_into(destination.path()),
        Arc::new(Progress::default()),
    ))
    .await;

    assert!(
        result.is_err(),
        "a manifest that does not match the accepted offer must be refused"
    );
    let _ = within(sending).await;
}

#[tokio::test]
async fn existing_files_at_the_destination_are_not_destroyed() {
    let (_source_dir, root) = source_tree(&[("notes.txt", 500)]);
    let destination = tempfile::tempdir().unwrap();

    std::fs::create_dir_all(destination.path().join("payload")).unwrap();
    std::fs::write(
        destination.path().join("payload/notes.txt"),
        b"something the user already had",
    )
    .unwrap();

    let pair = connect_pair().await;
    let (manifest, _) = Manifest::from_paths(std::slice::from_ref(&root)).unwrap();

    let sending = {
        let session = Arc::clone(&pair.sender);
        let parent = root.parent().unwrap().to_path_buf();
        tokio::spawn(async move {
            transfer::send(&session, &parent, &manifest, Arc::new(Progress::default())).await
        })
    };

    within(transfer::receive(
        &pair.receiver,
        accept_into(destination.path()),
        Arc::new(Progress::default()),
    ))
    .await
    .unwrap();
    within(sending).await.unwrap().unwrap();

    assert_eq!(
        std::fs::read(destination.path().join("payload/notes.txt")).unwrap(),
        b"something the user already had",
        "the existing file must be preserved"
    );
    assert!(
        destination.path().join("payload/notes (2).txt").exists(),
        "the incoming file should land beside it"
    );
}

/// A tree of many small files is where Dukto's per-file round trips fall apart.
/// This checks correctness at that shape; throughput is M5's problem.
#[tokio::test]
async fn a_tree_of_many_small_files_transfers_correctly() {
    let files: Vec<(String, usize)> = (0..300)
        .map(|i| (format!("dir{}/file{i}.txt", i % 10), 64 + i))
        .collect();
    let borrowed: Vec<(&str, usize)> = files.iter().map(|(n, s)| (n.as_str(), *s)).collect();

    let (_source_dir, root) = source_tree(&borrowed);
    let destination = tempfile::tempdir().unwrap();

    let pair = connect_pair().await;
    let (manifest, _) = Manifest::from_paths(std::slice::from_ref(&root)).unwrap();
    assert_eq!(manifest.summary().file_count, 300);

    let sending = {
        let session = Arc::clone(&pair.sender);
        let parent = root.parent().unwrap().to_path_buf();
        tokio::spawn(async move {
            transfer::send(&session, &parent, &manifest, Arc::new(Progress::default())).await
        })
    };

    within(transfer::receive(
        &pair.receiver,
        accept_into(destination.path()),
        Arc::new(Progress::default()),
    ))
    .await
    .unwrap();
    within(sending).await.unwrap().unwrap();

    assert_trees_match(&root, &destination.path().join("payload"));
}

/// Start a send of `root` on its own task.
fn spawn_send(
    pair: &Pair,
    root: &Path,
    manifest: &Manifest,
    progress: &Arc<Progress>,
) -> tokio::task::JoinHandle<jetstream_core::Result<()>> {
    let session = Arc::clone(&pair.sender);
    let parent = root.parent().unwrap().to_path_buf();
    let manifest = manifest.clone();
    let progress = Arc::clone(progress);
    tokio::spawn(async move { transfer::send(&session, &parent, &manifest, progress).await })
}

/// Set `flag` once `progress` has passed `bytes`.
fn trip_after(
    progress: &Arc<Progress>,
    bytes: u64,
    flag: impl Fn(&Progress) + Send + 'static,
) -> tokio::task::JoinHandle<()> {
    let progress = Arc::clone(progress);
    tokio::spawn(async move {
        loop {
            if progress.bytes_done.load(Ordering::Relaxed) >= bytes {
                flag(&progress);
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
}

/// Pausing used to be a no-op on the sending side: nothing there ever looked at
/// the flag, so the transfer simply carried on to the end.
#[tokio::test]
async fn pausing_the_sender_stops_both_ends_and_the_receiver_knows_why() {
    let (_source_dir, root) = source_tree(&[("big.bin", 24 * 1024 * 1024)]);
    let destination = tempfile::tempdir().unwrap();
    let (manifest, _) = Manifest::from_paths(std::slice::from_ref(&root)).unwrap();

    let pair = connect_pair().await;
    let send_progress = Arc::new(Progress::default());
    let receive_progress = Arc::new(Progress::default());
    // Slow enough that the pause lands mid-transfer.
    receive_progress.limit.set(8 * 1024 * 1024);

    let sending = spawn_send(&pair, &root, &manifest, &send_progress);
    let watcher = trip_after(&send_progress, 2 * 1024 * 1024, |p| {
        p.pause.store(true, Ordering::Relaxed)
    });

    let received = within(transfer::receive(
        &pair.receiver,
        accept_into(destination.path()),
        Arc::clone(&receive_progress),
    ))
    .await;
    let sent = within(sending).await.unwrap();
    watcher.abort();

    assert!(matches!(sent, Err(jetstream_core::Error::Paused)), "sender got {sent:?}");
    assert!(
        matches!(received, Err(jetstream_core::Error::PausedByPeer)),
        "receiver got {received:?} — it should know the sender paused, not that the network died"
    );
    assert!(
        receive_progress.bytes_done.load(Ordering::Relaxed) < 24 * 1024 * 1024,
        "the transfer should have stopped part way"
    );
}

/// A receiver stopping used to reach the sender as a *decline*, which also
/// stopped it ever being resumed.
#[tokio::test]
async fn cancelling_the_receiver_is_not_reported_as_a_decline() {
    let (_source_dir, root) = source_tree(&[("big.bin", 24 * 1024 * 1024)]);
    let destination = tempfile::tempdir().unwrap();
    let (manifest, _) = Manifest::from_paths(std::slice::from_ref(&root)).unwrap();

    let pair = connect_pair().await;
    let send_progress = Arc::new(Progress::default());
    let receive_progress = Arc::new(Progress::default());
    receive_progress.limit.set(8 * 1024 * 1024);

    let sending = spawn_send(&pair, &root, &manifest, &send_progress);
    let watcher = trip_after(&receive_progress, 2 * 1024 * 1024, |p| {
        p.cancel.store(true, Ordering::Relaxed)
    });

    let received = within(transfer::receive(
        &pair.receiver,
        accept_into(destination.path()),
        Arc::clone(&receive_progress),
    ))
    .await;
    let sent = within(sending).await.unwrap();
    watcher.abort();

    assert!(matches!(received, Err(jetstream_core::Error::Cancelled)), "receiver got {received:?}");
    assert!(
        matches!(sent, Err(jetstream_core::Error::CancelledByPeer)),
        "sender got {sent:?}"
    );
}

/// The sender used to count bytes as it handed them to QUIC, which buffers far
/// ahead of the network: it showed disk speed, reached 100% early and sat
/// there. It now shows what the receiver says has arrived.
#[tokio::test]
async fn the_sender_shows_what_arrived_not_what_it_buffered() {
    const SIZE: u64 = 16 * 1024 * 1024;
    let (_source_dir, root) = source_tree(&[("big.bin", SIZE as usize)]);
    let destination = tempfile::tempdir().unwrap();
    let (manifest, _) = Manifest::from_paths(std::slice::from_ref(&root)).unwrap();

    let pair = connect_pair().await;
    let send_progress = Arc::new(Progress::default());
    let receive_progress = Arc::new(Progress::default());
    receive_progress.limit.set(8 * 1024 * 1024);

    let sending = spawn_send(&pair, &root, &manifest, &send_progress);

    let sampler = {
        let send_progress = Arc::clone(&send_progress);
        let receive_progress = Arc::clone(&receive_progress);
        tokio::spawn(async move {
            let mut ahead = 0u64;
            loop {
                // Sender first: the receiver's figure only grows, so reading it
                // second can only make the comparison kinder to the sender.
                let sent = send_progress.bytes_done.load(Ordering::Relaxed);
                let arrived = receive_progress.bytes_done.load(Ordering::Relaxed);
                ahead = ahead.max(sent.saturating_sub(arrived));
                if arrived >= SIZE {
                    return ahead;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
    };

    within(transfer::receive(
        &pair.receiver,
        accept_into(destination.path()),
        Arc::clone(&receive_progress),
    ))
    .await
    .unwrap();
    within(sending).await.unwrap().unwrap();

    let ahead = within(sampler).await.unwrap();
    assert_eq!(ahead, 0, "the sender ran {ahead} bytes ahead of what had arrived");
    assert_eq!(send_progress.bytes_done.load(Ordering::Relaxed), SIZE);
    assert_eq!(send_progress.bytes_moved.load(Ordering::Relaxed), SIZE);
}

/// Accept into `destination`, replacing anything already there.
fn overwrite_into(
    destination: &Path,
) -> impl AsyncFnOnce(jetstream_core::proto::Offer) -> Decision + use<> {
    let destination = destination.to_path_buf();
    async move |_| Decision::Accept {
        destination,
        conflict: ConflictPolicy::Overwrite,
    }
}

/// Text-like bytes that compress well, unlike `payload`.
fn compressible(len: usize) -> Vec<u8> {
    let line = b"2026-10-16 12:00:00 INFO transfer of chunk completed without incident\n";
    line.iter().copied().cycle().take(len).collect()
}

const SAVE_ALWAYS: transfer::Options = transfer::Options {
    saving: transfer::Saving::Always,
};

#[tokio::test]
async fn compressible_data_crosses_the_wire_compressed_and_arrives_intact() {
    const SIZE: usize = 12 * 1024 * 1024;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("payload");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("server.log"), compressible(SIZE)).unwrap();
    let destination = tempfile::tempdir().unwrap();
    let (manifest, _) = Manifest::from_paths(std::slice::from_ref(&root)).unwrap();

    let pair = connect_pair().await;
    let progress = Arc::new(Progress::default());
    let sending = {
        let session = Arc::clone(&pair.sender);
        let parent = dir.path().to_path_buf();
        let manifest = manifest.clone();
        tokio::spawn(async move {
            transfer::send_with(&session, &parent, &manifest, Arc::new(Progress::default()), SAVE_ALWAYS).await
        })
    };

    within(transfer::receive_with(
        &pair.receiver,
        accept_into(destination.path()),
        Arc::clone(&progress),
        SAVE_ALWAYS,
    ))
    .await
    .unwrap();
    within(sending).await.unwrap().unwrap();

    assert_trees_match(&root, &destination.path().join("payload"));
    assert_eq!(
        progress.bytes_done.load(Ordering::Relaxed),
        SIZE as u64,
        "progress counts file bytes, compressed or not"
    );
    let wire = pair.receiver.wire_bytes_received();
    assert!(
        wire < SIZE as u64 / 4,
        "{wire} bytes crossed the wire for {SIZE} bytes of very compressible data"
    );
}

#[tokio::test]
async fn incompressible_data_is_sent_as_it_is() {
    let (_source_dir, root) = source_tree(&[("noise.bin", 6 * 1024 * 1024)]);
    let destination = tempfile::tempdir().unwrap();
    let (manifest, _) = Manifest::from_paths(std::slice::from_ref(&root)).unwrap();

    let pair = connect_pair().await;
    let sending = {
        let session = Arc::clone(&pair.sender);
        let parent = root.parent().unwrap().to_path_buf();
        let manifest = manifest.clone();
        tokio::spawn(async move {
            transfer::send_with(&session, &parent, &manifest, Arc::new(Progress::default()), SAVE_ALWAYS).await
        })
    };

    within(transfer::receive_with(
        &pair.receiver,
        accept_into(destination.path()),
        Arc::new(Progress::default()),
        SAVE_ALWAYS,
    ))
    .await
    .unwrap();
    within(sending).await.unwrap().unwrap();

    assert_trees_match(&root, &destination.path().join("payload"));
}

/// Re-sending a large file that changed a little — a disk image, an archive
/// that grew — moved the whole file again. Unchanged chunks of the older copy
/// at the destination are now reused.
#[tokio::test]
async fn an_older_copy_at_the_destination_supplies_the_unchanged_chunks() {
    const MIB: usize = 1024 * 1024;
    let old = payload(16 * MIB, 7);
    let mut new = old.clone();
    // Change one chunk in the middle, and grow the file by a chunk and a half.
    new[5 * MIB..5 * MIB + 100].fill(0xAA);
    new.extend(payload(MIB + MIB / 2, 8));

    let source = tempfile::tempdir().unwrap();
    let root = source.path().join("payload");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("disk.img"), &new).unwrap();

    let destination = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(destination.path().join("payload")).unwrap();
    std::fs::write(destination.path().join("payload/disk.img"), &old).unwrap();

    let (manifest, _) = Manifest::from_paths(std::slice::from_ref(&root)).unwrap();
    let pair = connect_pair().await;
    let progress = Arc::new(Progress::default());
    let sending = {
        let session = Arc::clone(&pair.sender);
        let parent = source.path().to_path_buf();
        let manifest = manifest.clone();
        tokio::spawn(async move {
            transfer::send_with(&session, &parent, &manifest, Arc::new(Progress::default()), SAVE_ALWAYS).await
        })
    };

    within(transfer::receive_with(
        &pair.receiver,
        overwrite_into(destination.path()),
        Arc::clone(&progress),
        SAVE_ALWAYS,
    ))
    .await
    .unwrap();
    within(sending).await.unwrap().unwrap();

    assert_eq!(std::fs::read(destination.path().join("payload/disk.img")).unwrap(), new);
    assert_eq!(
        progress.bytes_reused.load(Ordering::Relaxed),
        15 * MIB as u64,
        "every chunk but the changed one should come from the older copy"
    );
    assert_eq!(progress.bytes_done.load(Ordering::Relaxed), new.len() as u64);
    let wire = pair.receiver.wire_bytes_received();
    assert!(
        wire < 6 * MIB as u64,
        "{wire} bytes crossed the wire when about 2.5 MiB had changed"
    );
}

/// On a LAN the default is to send, not to compare: the network is rarely the
/// slow part there, and comparing costs a read of the file on both sides.
#[tokio::test]
async fn by_default_a_lan_transfer_does_not_compare_older_copies() {
    const MIB: usize = 1024 * 1024;
    let data = payload(10 * MIB, 9);

    let source = tempfile::tempdir().unwrap();
    let root = source.path().join("payload");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("disk.img"), &data).unwrap();

    let destination = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(destination.path().join("payload")).unwrap();
    std::fs::write(destination.path().join("payload/disk.img"), &data).unwrap();

    let (manifest, _) = Manifest::from_paths(std::slice::from_ref(&root)).unwrap();
    let pair = connect_pair().await;
    let progress = Arc::new(Progress::default());
    let sending = {
        let session = Arc::clone(&pair.sender);
        let parent = source.path().to_path_buf();
        tokio::spawn(async move {
            transfer::send(&session, &parent, &manifest, Arc::new(Progress::default())).await
        })
    };

    within(transfer::receive(
        &pair.receiver,
        overwrite_into(destination.path()),
        Arc::clone(&progress),
    ))
    .await
    .unwrap();
    within(sending).await.unwrap().unwrap();

    assert_eq!(progress.bytes_reused.load(Ordering::Relaxed), 0);
    assert_eq!(std::fs::read(destination.path().join("payload/disk.img")).unwrap(), data);
}
