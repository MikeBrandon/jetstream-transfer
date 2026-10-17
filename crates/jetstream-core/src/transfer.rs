//! The transfer engine: one sender, one receiver, and a receiver-driven pull.
//!
//! # Why the receiver drives
//!
//! The receiver is the only party that knows what it already has, because it is
//! the only party that can look at its own disk. Making it the one that asks
//! collapses a whole category of problems:
//!
//! - **Resume is not a feature.** Reconnecting is the same code path as
//!   starting: read the bitmaps, work out what is missing, ask for it. There is
//!   no "resume mode" to get wrong.
//! - **The sender is stateless.** It serves whatever it is asked for and
//!   remembers nothing between requests, so a sender that restarts mid-transfer
//!   costs nothing. No negotiation to replay, no session to rebuild.
//! - **Duplicate and overlapping requests are harmless**, which means retry
//!   logic can be blunt and still correct.
//!
//! Each request gets its own QUIC stream, so parallelism is a matter of asking
//! for more at once — the protocol does not change. This module asks for one
//! range at a time; making it ask for several is [`M5`](crate) work and touches
//! nothing else.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;


use crate::chunk::{self, CHUNK_SIZE, ChunkRange};
use crate::error::{Error, Result};
use crate::manifest::{ENTRIES_PER_BATCH, Manifest, Summary};
use crate::path::to_extended_length;
use crate::proto::{
    self, ChunkHeader, ChunkHeaderV2, Control, DataRequest, MAX_CONTROL_FRAME, Offer, StopReason,
};
use crate::staging::{ConflictPolicy, Placement, Staging};
use crate::transport::Session;

/// Live counters for a transfer in progress, shared with whatever is drawing
/// the UI.
#[derive(Debug, Default)]
pub struct Progress {
    pub bytes_total: AtomicU64,
    pub bytes_done: AtomicU64,
    pub files_total: AtomicU64,
    pub files_done: AtomicU64,
    /// Bytes that actually crossed the wire during this attempt.
    ///
    /// `bytes_done` is what the progress bar shows, and on a resume it starts
    /// at everything already there. That is the right thing to *display* and the
    /// wrong thing to measure speed from: the jump from zero to the baseline read
    /// as tens of gigabytes a second. Rates come from this counter instead, which
    /// only ever grows by bytes that moved.
    pub bytes_moved: AtomicU64,
    /// Bytes copied from an older copy of a file already at the destination,
    /// rather than sent. Counted in `bytes_done`, never in `bytes_moved`.
    pub bytes_reused: AtomicU64,
    /// Set to ask the transfer to stop at the next chunk boundary. Staged data
    /// is kept, so a cancelled transfer can be resumed rather than restarted.
    pub cancel: AtomicBool,
    /// Set to ask the transfer to stop *and be continued later*.
    ///
    /// Mechanically the same as cancelling — stop at a chunk boundary and leave
    /// the staged data alone — but it has to be a separate flag because the two
    /// mean opposite things afterwards. A cancel is finished with; a pause is
    /// waiting to be picked up, and must not be swept up by the automatic retry
    /// watcher, which would restart the very thing the user just stopped.
    ///
    /// Pausing by holding the connection open was the alternative, and was
    /// rejected: a transfer paused over lunch would idle the QUIC connection out
    /// anyway, so it would need keepalives to survive something the resume path
    /// already handles for free. Stopping and continuing later is the same code
    /// as any other resume, which is the code most likely to be correct.
    pub pause: AtomicBool,
    /// Optional rate limit for this transfer.
    ///
    /// Lives here because `Progress` is already the shared control block both
    /// ends hold an `Arc` to, so a limit costs no change to any function
    /// signature and can be adjusted mid-transfer from the UI. Unlimited by
    /// default, and unlimited means one uncontended lock per chunk — around a
    /// hundred a second at full speed, which is nothing.
    pub limit: crate::throttle::Throttle,
    /// Set when the *other* device stopped on purpose, so the workers here stop
    /// at their next chunk boundary rather than draining whatever QUIC had
    /// already buffered. 0 = carry on, otherwise a [`StopReason`] code.
    peer_stop: std::sync::atomic::AtomicU8,

    /// What the transfer is doing while no data moves. See [`CheckKind`].
    ///
    /// Without this the row sat at 100% reading "5 B/s, 1s left" for as long
    /// as it took to read an 8 GB file back from disk - on both machines - and
    /// a user had no way to tell work from a hang.
    check_kind: std::sync::atomic::AtomicU8,
    /// Checks running right now. Several large files can finish together, so
    /// these aggregate rather than overwrite.
    check_active: std::sync::atomic::AtomicU32,
    check_total: AtomicU64,
    check_done: AtomicU64,
}

/// A step that reads a whole file instead of moving data, and so would
/// otherwise look like a stall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckKind {
    /// Reading an older copy, and the sender's original, to find chunks that
    /// need not be sent. Before any data moves.
    Comparing,
    /// Reading a finished file back to confirm it matches the original. This
    /// side's own read, so its progress is known.
    Verifying,
    /// This side is finished; the other device is still reading its copy.
    /// Nothing here can measure that, so it carries no progress.
    WaitingForPeer,
}

impl CheckKind {
    fn code(self) -> u8 {
        match self {
            Self::Comparing => 1,
            Self::Verifying => 2,
            Self::WaitingForPeer => 3,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Comparing),
            2 => Some(Self::Verifying),
            3 => Some(Self::WaitingForPeer),
            _ => None,
        }
    }
}

/// Ends a check when dropped, so an early return or an error can never leave
/// a transfer reporting a check that is no longer running.
pub(crate) struct CheckGuard(Arc<Progress>);

impl Drop for CheckGuard {
    fn drop(&mut self) {
        let progress = &self.0;
        // The last check to finish clears the lot. Totals from overlapping checks
        // are summed, so ending one early would leave a misleading percentage.
        if progress.check_active.fetch_sub(1, Ordering::AcqRel) == 1 {
            progress.check_total.store(0, Ordering::Relaxed);
            progress.check_done.store(0, Ordering::Relaxed);
            progress.check_kind.store(0, Ordering::Release);
        }
    }
}

impl Progress {
    /// The check under way, if any: what it is, and bytes read of bytes to read.
    pub fn check(&self) -> Option<(CheckKind, u64, u64)> {
        let kind = CheckKind::from_code(self.check_kind.load(Ordering::Acquire))?;
        Some((
            kind,
            self.check_done.load(Ordering::Relaxed),
            self.check_total.load(Ordering::Relaxed),
        ))
    }

    /// Start a check of `total` bytes. Ends when the guard is dropped.
    pub(crate) fn begin_check(self: &Arc<Self>, kind: CheckKind, total: u64) -> CheckGuard {
        self.check_active.fetch_add(1, Ordering::AcqRel);
        self.check_total.fetch_add(total, Ordering::Relaxed);
        self.check_kind.store(kind.code(), Ordering::Release);
        CheckGuard(Arc::clone(self))
    }

    pub(crate) fn check_advance(&self, bytes: u64) {
        self.check_done.fetch_add(bytes, Ordering::Relaxed);
    }

    /// This side has finished its part; the other device is still working.
    ///
    /// Only when nothing of ours is still running - our own measurable check
    /// is the more informative thing to show.
    pub(crate) fn wait_for_peer(&self) {
        if self.check_active.load(Ordering::Acquire) == 0 {
            self.check_kind
                .store(CheckKind::WaitingForPeer.code(), Ordering::Release);
        }
    }

    /// The other device answered, or data is moving again.
    pub(crate) fn stop_waiting_for_peer(&self) {
        let _ = self.check_kind.compare_exchange(
            CheckKind::WaitingForPeer.code(),
            0,
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
    }

    pub fn fraction(&self) -> f64 {
        let total = self.bytes_total.load(Ordering::Relaxed);
        if total == 0 {
            return 1.0;
        }
        self.bytes_done.load(Ordering::Relaxed) as f64 / total as f64
    }

    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    pub fn paused(&self) -> bool {
        self.pause.load(Ordering::Relaxed)
    }

    /// Count `bytes` as transferred, never past the total.
    ///
    /// The clamp is not cosmetic. A sender counts what it writes to the wire, so
    /// anything served twice — a re-requested chunk after a fault, a range that
    /// arrived but was not kept — is counted twice, and the figure drifts above
    /// the size of the transfer. Observed reading **201.4 GB of 138.5 GB**, which
    /// tells the user nothing except that the app cannot count.
    ///
    /// Bytes actually sent are still the right thing to *measure* — that is what
    /// the rate is derived from — so the raw addition happens and only the
    /// reported total is bounded.
    ///
    /// Public for transports outside this module, such as browser uploads, so
    /// their bytes count towards the speed shown as well as the progress.
    pub fn advance(&self, bytes: u64) {
        self.bytes_moved.fetch_add(bytes, Ordering::Relaxed);

        let total = self.bytes_total.load(Ordering::Relaxed);
        let updated = self.bytes_done.fetch_add(bytes, Ordering::Relaxed) + bytes;
        if total > 0 && updated > total {
            self.bytes_done.store(total, Ordering::Relaxed);
        }
    }

    /// Take a figure the peer reported as the new floor for `bytes_done`,
    /// counting any increase as bytes moved.
    fn raise_to(&self, bytes: u64) {
        let bytes = bytes.min(self.bytes_total.load(Ordering::Relaxed));
        let previous = self.bytes_done.fetch_max(bytes, Ordering::Relaxed);
        self.bytes_moved
            .fetch_add(bytes.saturating_sub(previous), Ordering::Relaxed);
    }

    /// Stop if the user — or the other device — asked us to, distinguishing why.
    fn check_interrupted(&self) -> Result<()> {
        if self.paused() {
            return Err(Error::Paused);
        }
        if self.cancelled() {
            return Err(Error::Cancelled);
        }
        match self.peer_stop.load(Ordering::Relaxed) {
            PEER_PAUSED => Err(Error::PausedByPeer),
            PEER_CANCELLED => Err(Error::CancelledByPeer),
            _ => Ok(()),
        }
    }

    fn note_peer_stop(&self, reason: StopReason) {
        let code = match reason {
            StopReason::Paused => PEER_PAUSED,
            StopReason::Cancelled => PEER_CANCELLED,
        };
        self.peer_stop.store(code, Ordering::Relaxed);
    }
}

const PEER_PAUSED: u8 = 1;
const PEER_CANCELLED: u8 = 2;

/// How often a waiting side looks at the pause and cancel flags.
const INTERRUPT_POLL: Duration = Duration::from_millis(100);

/// How often the receiver reports its totals to a sender that can read them.
const PROGRESS_REPORT: Duration = Duration::from_millis(250);

/// How long a receiver lets its transfer wind down after the sender stops, so
/// the disk writer flushes and exits before anything else can reopen the same
/// staging area.
const WIND_DOWN: Duration = Duration::from_secs(10);

/// Resolves when the user pauses or cancels, with the matching error.
///
/// Polled rather than signalled: the flags are plain atomics shared with the UI,
/// and a tenth of a second is far below what a person notices after a click.
async fn interrupted(progress: &Progress) -> Error {
    let mut ticker = tokio::time::interval(INTERRUPT_POLL);
    loop {
        ticker.tick().await;
        if progress.paused() {
            return Error::Paused;
        }
        if progress.cancelled() {
            return Error::Cancelled;
        }
    }
}

/// Tell a peer that can understand it that we stopped on purpose.
///
/// Best-effort: the connection is about to close either way, and the peer falls
/// back to reporting a lost connection, which is still resumable.
async fn announce_stop(session: &Session, error: &Error) {
    let reason = match error {
        Error::Paused => StopReason::Paused,
        Error::Cancelled => StopReason::Cancelled,
        _ => return,
    };
    if session.peer_has_live_status()
        && let Err(e) = session.send_control(&Control::Stop { reason }).await
    {
        tracing::debug!(error = %e, "could not tell the peer the transfer was stopped");
    }
}

/// The error for a peer that told us it stopped deliberately.
fn stopped_by_peer(reason: StopReason) -> Error {
    match reason {
        StopReason::Paused => Error::PausedByPeer,
        StopReason::Cancelled => Error::CancelledByPeer,
    }
}

/// When to spend CPU to save network: compressing chunks on the way out, and
/// reusing unchanged chunks of a file the receiver already has an older copy of.
///
/// Both cost CPU and disk on each side and both save bytes on the wire, which is
/// a good trade on a VPN or the internet and usually a bad one on a gigabit LAN,
/// where the network is rarely the slow part.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Saving {
    /// Only when the other device is not on the local network.
    #[default]
    Auto,
    Always,
    Never,
}

impl Saving {
    pub fn applies(self, peer: std::net::SocketAddr) -> bool {
        match self {
            Self::Auto => !crate::transport::quic::is_lan(peer),
            Self::Always => true,
            Self::Never => false,
        }
    }
}

/// Choices that shape a transfer without changing what it moves.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    pub saving: Saving,
}

/// zstd level for chunks. Low: on a link slow enough to want compression the
/// CPU is rarely the bottleneck, but there is no reason to make it one.
const ZSTD_LEVEL: i32 = 3;

/// A chunk is sent compressed only if that saves at least this fraction.
/// Anything less is not worth the receiver's time to undo.
const MIN_SAVING_PERCENT: usize = 5;

/// Give up compressing a range after this many chunks in a row that did not
/// shrink — the file is not compressible, whatever its name says.
const COMPRESSION_MISSES: u32 = 3;

/// Whether a file is worth trying to compress, judged by its extension.
///
/// Already-compressed formats would only cost CPU on both sides for nothing.
/// Anything not listed is tried, and given up on quickly if it does not shrink.
fn worth_compressing(path: &Path) -> bool {
    const PACKED: &[&str] = &[
        "7z", "aac", "apk", "avi", "avif", "br", "bz2", "cab", "deb", "docx", "epub", "flac",
        "gif", "gz", "heic", "heif", "jar", "jpeg", "jpg", "jxl", "m4a", "m4v", "mkv", "mov",
        "mp3", "mp4", "msi", "ogg", "opus", "png", "pptx", "rar", "rpm", "tgz", "webm", "webp",
        "wmv", "xlsx", "xz", "zip", "zst",
    ];
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_none_or(|ext| !PACKED.iter().any(|packed| ext.eq_ignore_ascii_case(packed)))
}

/// What the receiving side decided about an offer.
pub enum Decision {
    Accept {
        destination: PathBuf,
        conflict: ConflictPolicy,
    },
    Reject {
        reason: String,
    },
}

/// Result of a completed receive.
#[derive(Debug)]
pub struct Received {
    pub placements: Vec<Placement>,
    pub bytes: u64,
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

/// Offer `manifest` to the peer and serve whatever it asks for.
///
/// `root` is the directory the manifest's relative paths hang off — the parent
/// of whatever the user dropped.
pub async fn send(
    session: &Session,
    root: &Path,
    manifest: &Manifest,
    progress: Arc<Progress>,
) -> Result<()> {
    send_with(session, root, manifest, progress, Options::default()).await
}

/// [`send`], with [`Options`].
pub async fn send_with(
    session: &Session,
    root: &Path,
    manifest: &Manifest,
    progress: Arc<Progress>,
    options: Options,
) -> Result<()> {
    manifest.validate()?;

    progress
        .bytes_total
        .store(manifest.total_bytes(), Ordering::Relaxed);
    // The sender knows how many files there are from the manifest. It only learns
    // how many are *finished* from the receiver, via `Control::EntryDone`.
    progress
        .files_total
        .store(manifest.summary().file_count, Ordering::Relaxed);

    let offer = Offer {
        digest: manifest.digest(),
        summary: manifest.summary(),
        entry_count: manifest.entries.len() as u64,
    };

    session.send_control(&Control::Offer(offer)).await?;

    // Waiting on a person at the other end, possibly for minutes — so pausing or
    // cancelling here has to work too, not only once data is moving.
    let answer = tokio::select! {
        answer = session.recv_control() => answer?,
        stop = interrupted(&progress) => {
            announce_stop(session, &stop).await;
            return Err(stop);
        }
    };

    match answer {
        Control::Accept => {}
        Control::Reject { reason } => {
            return Err(Error::Rejected(proto::sanitize_name(&reason)));
        }
        other => {
            return Err(Error::Protocol(format!(
                "expected Accept or Reject, got {other:?}"
            )));
        }
    }

    // Stream the manifest in batches so a huge tree never needs a huge frame.
    for batch in manifest.entries.chunks(ENTRIES_PER_BATCH) {
        let more = batch.as_ptr_range().end != manifest.entries.as_ptr_range().end;
        session
            .send_control(&Control::ManifestBatch {
                entries: batch.to_vec(),
                more,
            })
            .await?;
    }
    if manifest.entries.is_empty() {
        session
            .send_control(&Control::ManifestBatch {
                entries: Vec::new(),
                more: false,
            })
            .await?;
    }

    // Compressed frames only to a peer that can read them, and compression
    // itself only where it pays — see `Saving`.
    let framing = Framing {
        v2: session.peer().capabilities.zstd,
        compress: session.peer().capabilities.zstd
            && options.saving.applies(session.peer().remote_address),
    };

    // However serving ends - complete, aborted, or the connection lost - this
    // side is no longer waiting on the receiver, and must not keep saying so.
    let outcome = serve_requests(session, root, manifest, Arc::clone(&progress), framing).await;
    progress.stop_waiting_for_peer();
    outcome
}

/// How chunk frames are written to this peer.
#[derive(Debug, Clone, Copy)]
struct Framing {
    /// Use [`ChunkHeaderV2`], which can carry compressed data.
    v2: bool,
    /// Try compressing chunks. Only ever true with `v2`.
    compress: bool,
}

/// Answer data-stream requests until the receiver says it is done.
///
/// Runs the control channel and the data streams concurrently: the receiver
/// signals completion on the control stream while its last data requests may
/// still be in flight.
async fn serve_requests(
    session: &Session,
    root: &Path,
    manifest: &Manifest,
    progress: Arc<Progress>,
    framing: Framing,
) -> Result<()> {
    // Shared between the three futures below: when the receiver was last heard
    // from, in milliseconds since this call began.
    let started = std::time::Instant::now();
    let activity = Arc::new(AtomicU64::new(0));

    // A receiver that reports its own totals is the authority on progress. The
    // sender's count of bytes handed to QUIC runs up to the whole send window
    // ahead of what has arrived, so it is only a fallback for older peers.
    let live = session.peer_has_live_status();

    let done = async {
        loop {
            let message = session.recv_control().await?;
            activity.store(elapsed_ms(&started), Ordering::Relaxed);

            match message {
                Control::Complete => {
                    // Everything arrived and verified, so the counters can settle
                    // at the totals — see the matching note in `receive` about
                    // files that have no chunks to report.
                    progress.raise_to(progress.bytes_total.load(Ordering::Relaxed));
                    let total = progress.files_total.load(Ordering::Relaxed);
                    progress.files_done.store(total, Ordering::Relaxed);
                    return Ok(());
                }
                // The receiver gave up after accepting. That is never a decline:
                // a person already said yes. Older receivers also sent this for
                // their own pause and cancel, with the error text as the reason.
                Control::Abort { reason } => {
                    return Err(match reason.as_str() {
                        "paused" | "cancelled" => Error::CancelledByPeer,
                        _ => Error::PeerFailed(proto::sanitize_name(&reason)),
                    });
                }
                Control::Stop { reason } => return Err(stopped_by_peer(reason)),
                Control::Progress { bytes, files } => {
                    progress.raise_to(bytes);
                    let total_files = progress.files_total.load(Ordering::Relaxed);
                    progress
                        .files_done
                        .fetch_max(files.min(total_files), Ordering::Relaxed);
                }
                Control::Ping(nonce) => session.send_control(&Control::Pong(nonce)).await?,
                // The receiver's resume baseline.
                //
                // `fetch_max`, not `store`, for two reasons. It is a *floor*, not
                // a correction: this message races the data streams, so a chunk
                // may already have been counted, and overwriting would throw that
                // away — a test caught exactly that, the sender opening at 1 MiB
                // instead of the 3 MiB already on disk. And a progress counter
                // that can go backwards is worse than one that is briefly low.
                //
                // Clamped to the totals, because these figures arrive from the
                // peer and a display must not be steerable into nonsense by a
                // number on the wire.
                //
                // With a live receiver nothing has been counted locally, so the
                // baseline is simply the truth and replaces whatever the caller
                // carried over from an earlier attempt. It is not counted as
                // bytes moved: it was already there.
                Control::AlreadyHave { bytes, files } => {
                    let total_bytes = progress.bytes_total.load(Ordering::Relaxed);
                    let total_files = progress.files_total.load(Ordering::Relaxed);
                    let (bytes, files) = (bytes.min(total_bytes), files.min(total_files));
                    if live {
                        progress.bytes_done.store(bytes, Ordering::Relaxed);
                        progress.files_done.store(files, Ordering::Relaxed);
                    } else {
                        progress.bytes_done.fetch_max(bytes, Ordering::Relaxed);
                        progress.files_done.fetch_max(files, Ordering::Relaxed);
                    }
                }
                // Counted rather than tracked per entry: the receiver reports each
                // file exactly once, and a duplicate would only inflate a display
                // number. Clamped to the total so it can never read "44 of 43".
                // A live receiver's `Progress` already carries the file count, and
                // adding these on top would count each file twice.
                Control::EntryDone { .. } if live => {}
                Control::EntryDone { .. } => {
                    let total = progress.files_total.load(Ordering::Relaxed);
                    let done = progress.files_done.load(Ordering::Relaxed);
                    if done < total {
                        progress.files_done.store(done + 1, Ordering::Relaxed);
                    }
                }
                other => tracing::debug!(?other, "ignoring control message while serving"),
            }
        }
    };

    let serving = async {
        loop {
            let (send, recv) = session.accept_stream().await?;
            activity.store(elapsed_ms(&started), Ordering::Relaxed);

            let root = root.to_path_buf();
            let manifest = manifest.clone();
            let progress = Arc::clone(&progress);

            // One task per request, so a slow disk read on one file does not
            // hold up the others.
            tokio::spawn(async move {
                if let Err(e) = answer(send, recv, &root, &manifest, progress, live, framing).await {
                    tracing::debug!(error = %e, "data request failed");
                }
            });
        }
    };

    // A sender that is neither being asked for anything nor being told to stop is
    // indistinguishable from a hung program, and it used to wait for ever.
    //
    // QUIC's own idle timeout cannot catch this: keepalives are enabled, so the
    // connection stays healthy as long as both processes are alive. A receiver
    // that finished but never sent `Complete` — or whose `Complete` was lost —
    // left the sending side pinned at "100%" with a Cancel button and no way to
    // finish. Observed on a real 138 GB transfer.
    //
    // Treated as an interruption rather than a failure, because that is what it
    // is: the staged data is intact and the transfer can be resumed.
    let watchdog = async {
        let mut ticker = tokio::time::interval(STALL_CHECK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let idle = elapsed_ms(&started).saturating_sub(activity.load(Ordering::Relaxed));
            if idle >= STALL_TIMEOUT.as_millis() as u64 {
                return Err(Error::Transport(format!(
                    "the other device stopped responding — nothing for {} seconds",
                    idle / 1000
                )));
            }
        }
    };

    let stop = async {
        let stop = interrupted(&progress).await;
        announce_stop(session, &stop).await;
        Err(stop)
    };

    tokio::select! {
        result = done => result,
        result = serving => result,
        result = watchdog => result,
        result = stop => result,
    }
}

/// Milliseconds since `started`, as a plain integer for atomic storage.
fn elapsed_ms(started: &std::time::Instant) -> u64 {
    started.elapsed().as_millis() as u64
}

async fn answer(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    root: &Path,
    manifest: &Manifest,
    progress: Arc<Progress>,
    live: bool,
    framing: Framing,
) -> Result<()> {
    let request: DataRequest = proto::read_frame(&mut recv, MAX_CONTROL_FRAME).await?;

    match request {
        DataRequest::Chunks { entry, range } => {
            // Data is moving again, so the receiver is not just checking any more.
            progress.stop_waiting_for_peer();
            let source = resolve_source(manifest, root, entry)?;
            let size = manifest.entries[entry as usize].size();

            // Read and hash on a blocking thread, feeding the network through a
            // small channel. Two things matter here:
            //
            //  * the file is opened **once** for the whole range and read
            //    sequentially, instead of open-seek-read per chunk;
            //  * disk reads and BLAKE3 overlap with the socket writes, rather
            //    than taking turns, which is what the serial version did.
            let compress = framing.compress && worth_compressing(&source);
            let mut chunks = read_range(source, size, range, compress);

            while let Some(prepared) = chunks.recv().await {
                let (header, payload) = prepared?;

                // Stop serving the moment the user pauses or cancels, rather than
                // finishing ranges nobody is going to wait for.
                progress.check_interrupted()?;

                // An upload cap. Independent of the receiver's own limit — either
                // side may want to protect its link, and neither has to know
                // about the other's choice. Whichever is lower simply wins. What
                // crosses the wire is what counts, compressed or not.
                progress.limit.take(payload.len() as u64).await;

                if framing.v2 {
                    let framed = ChunkHeaderV2 {
                        index: header.index,
                        len: header.len,
                        wire_len: payload.len() as u32,
                        hash: header.hash,
                    };
                    send.write_all(&framed.encode()).await?;
                } else {
                    send.write_all(&header.encode()).await?;
                }
                send.write_all(&payload).await?;

                // Bytes handed to QUIC, not bytes delivered — see `live`.
                if !live {
                    progress.advance(u64::from(header.len));
                }
            }
        }
        DataRequest::ChunkHashes { entry, range } => {
            let source = resolve_source(manifest, root, entry)?;
            let size = manifest.entries[entry as usize].size();
            let hashes = {
                let _check = progress.begin_check(CheckKind::Comparing, range_bytes(range, size));
                hash_chunks(source, size, range, Arc::clone(&progress)).await?
            };
            for hash in hashes {
                send.write_all(&hash).await?;
            }
        }
        DataRequest::FileHash { entry } => {
            let source = resolve_source(manifest, root, entry)?;
            let size = manifest.entries[entry as usize].size();
            let hash = {
                let _check = progress.begin_check(CheckKind::Verifying, size);
                hash_file(&source, Arc::clone(&progress)).await?
            };
            send.write_all(&hash).await?;
            // Our copy is checked; the receiver may still be reading its own.
            progress.wait_for_peer();
        }
    }

    send.finish().map_err(Error::transport)?;
    Ok(())
}

fn resolve_source(manifest: &Manifest, root: &Path, entry: u32) -> Result<PathBuf> {
    let item = manifest
        .entries
        .get(entry as usize)
        .ok_or_else(|| Error::Protocol(format!("peer asked for unknown entry {entry}")))?;

    if !item.is_file() {
        return Err(Error::Protocol(format!(
            "peer asked for data from non-file entry {:?}",
            item.path.as_str()
        )));
    }

    Ok(item.path.resolve_in(root))
}

/// Read and hash a range of chunks on a blocking thread.
///
/// Returns a channel so the caller can write to the socket while the next chunk
/// is being read and hashed. The bounded depth keeps at most a few megabytes in
/// flight and applies backpressure when the network is the slower side.
///
/// The second item is what goes on the wire: the chunk itself, or — when
/// `compress` is set and it shrinks enough — the chunk zstd-compressed. The
/// header always describes the uncompressed chunk.
fn read_range(
    path: PathBuf,
    size: u64,
    range: ChunkRange,
    compress: bool,
) -> tokio::sync::mpsc::Receiver<Result<(ChunkHeader, Vec<u8>)>> {
    // Three deep: enough to keep the socket fed across a disk hiccup, small
    // enough that eight concurrent requests do not hold 100 MB of buffers.
    let (tx, rx) = tokio::sync::mpsc::channel(3);
    let path = to_extended_length(&path);

    tokio::task::spawn_blocking(move || {
        use std::io::{Read, Seek, SeekFrom};

        let prepare = || -> Result<()> {
            let mut file = std::fs::File::open(&path)?;

            let (start, _) = chunk::chunk_span(range.start, size)?;
            file.seek(SeekFrom::Start(start))?;

            let mut trying = compress;
            let mut misses = 0;

            for index in range.iter() {
                let (_, len) = chunk::chunk_span(index, size)?;

                let mut data = vec![0u8; len];
                file.read_exact(&mut data)?;

                let header = ChunkHeader {
                    index,
                    len: len as u32,
                    hash: *blake3::hash(&data).as_bytes(),
                };

                let mut payload = data;
                if trying {
                    match zstd::bulk::compress(&payload, ZSTD_LEVEL) {
                        Ok(packed)
                            if packed.len() < payload.len() - payload.len() * MIN_SAVING_PERCENT / 100 =>
                        {
                            payload = packed;
                            misses = 0;
                        }
                        _ => {
                            misses += 1;
                            trying = misses < COMPRESSION_MISSES;
                        }
                    }
                }

                // A closed channel means the peer went away mid-request; stop
                // reading rather than finish work nobody will collect.
                if tx.blocking_send(Ok((header, payload))).is_err() {
                    return Ok(());
                }
            }
            Ok(())
        };

        if let Err(e) = prepare() {
            let _ = tx.blocking_send(Err(e));
        }
    });

    rx
}

/// The BLAKE3 of each chunk in a range, for [`DataRequest::ChunkHashes`].
async fn hash_chunks(
    path: PathBuf,
    size: u64,
    range: ChunkRange,
    progress: Arc<Progress>,
) -> Result<Vec<[u8; 32]>> {
    let path = to_extended_length(&path);

    tokio::task::spawn_blocking(move || -> Result<Vec<[u8; 32]>> {
        use std::io::{Read, Seek, SeekFrom};

        let mut file = std::fs::File::open(&path)?;
        let (start, _) = chunk::chunk_span(range.start, size)?;
        file.seek(SeekFrom::Start(start))?;

        let mut hashes = Vec::with_capacity(range.len() as usize);
        let mut buffer = vec![0u8; CHUNK_SIZE as usize];
        for index in range.iter() {
            let (_, len) = chunk::chunk_span(index, size)?;
            file.read_exact(&mut buffer[..len])?;
            hashes.push(*blake3::hash(&buffer[..len]).as_bytes());
            progress.check_advance(len as u64);
        }
        Ok(hashes)
    })
    .await
    .map_err(|e| Error::Io(std::io::Error::other(e)))?
}

async fn hash_file(path: &Path, progress: Arc<Progress>) -> Result<[u8; 32]> {
    let path = to_extended_length(path);

    tokio::task::spawn_blocking(move || -> Result<[u8; 32]> {
        use std::io::Read;

        let mut file = std::fs::File::open(&path)?;
        let mut hasher = blake3::Hasher::new();
        let mut buffer = vec![0u8; 256 * 1024];

        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
            progress.check_advance(read as u64);
        }
        Ok(*hasher.finalize().as_bytes())
    })
    .await
    .map_err(|e| Error::Io(std::io::Error::other(e)))?
}

/// Bytes covered by `range` in a file of `size` bytes.
fn range_bytes(range: ChunkRange, size: u64) -> u64 {
    let start = u64::from(range.start) * CHUNK_SIZE;
    let end = (u64::from(range.end) * CHUNK_SIZE).min(size);
    end.saturating_sub(start)
}

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------

/// Wait for an offer and hand it to `decide`.
///
/// The callback is where the trust store and the user prompt live: the engine
/// deliberately has no opinion about whether an offer should be accepted.
///
/// It returns a future because in a real application the answer comes from a
/// human clicking a button. A synchronous callback would force the UI to block
/// a runtime thread while a dialog sits on screen.
///
/// The offer is passed by value so the callback can hold it across an await
/// without borrowing from the engine's stack.
pub async fn receive<F>(session: &Session, decide: F, progress: Arc<Progress>) -> Result<Received>
where
    F: AsyncFnOnce(Offer) -> Decision,
{
    receive_with(session, decide, progress, Options::default()).await
}

/// [`receive`], with [`Options`].
pub async fn receive_with<F>(
    session: &Session,
    decide: F,
    progress: Arc<Progress>,
    options: Options,
) -> Result<Received>
where
    F: AsyncFnOnce(Offer) -> Decision,
{
    let offer = match session.recv_control().await? {
        Control::Offer(offer) => offer,
        other => {
            return Err(Error::Protocol(format!("expected an Offer, got {other:?}")));
        }
    };

    if offer.entry_count > crate::manifest::MAX_ENTRIES as u64 {
        let reason = format!("transfer has too many items ({})", offer.entry_count);
        session
            .send_control(&Control::Reject {
                reason: reason.clone(),
            })
            .await?;
        return Err(Error::Protocol(reason));
    }

    let (destination, conflict) = match decide(offer.clone()).await {
        Decision::Accept {
            destination,
            conflict,
        } => (destination, conflict),
        Decision::Reject { reason } => {
            session
                .send_control(&Control::Reject {
                    reason: reason.clone(),
                })
                .await?;
            return Err(Error::Rejected(reason));
        }
    };

    session.send_control(&Control::Accept).await?;

    let manifest = read_manifest(session, offer.entry_count).await?;
    if manifest.digest() != offer.digest {
        // The manifest we received is not the one that was described to us, so
        // the summary the user approved does not describe what is arriving.
        session
            .send_control(&Control::Abort {
                reason: "manifest does not match the offer".into(),
            })
            .await?;
        return Err(Error::Protocol(
            "manifest digest does not match the offer the user accepted".into(),
        ));
    }

    std::fs::create_dir_all(to_extended_length(&destination))?;
    let mut staging = Staging::open(&destination, manifest, conflict)?;

    // An older copy of a file already at the destination can stand in for
    // every chunk that has not changed — on a slow link, the difference between
    // re-sending a 20 GB disk image and sending the few megabytes that differ.
    // Skip never needs it: it leaves existing files alone entirely.
    if conflict != ConflictPolicy::Skip
        && session.peer().capabilities.chunk_hashes
        && options.saving.applies(session.peer().remote_address)
    {
        staging = reuse_older_copies(session, staging, &destination, &progress).await?;
    }

    progress
        .bytes_total
        .store(staging.manifest().total_bytes(), Ordering::Relaxed);
    progress.bytes_done.store(staging.bytes_present(), Ordering::Relaxed);
    progress.files_total.store(
        staging.manifest().summary().file_count,
        Ordering::Relaxed,
    );
    progress
        .files_done
        .store(staging.files_present(), Ordering::Relaxed);

    // Tell the sender what is already here. It keeps no state of its own, so
    // this is the only way its progress bar can start anywhere but zero.
    let already = Control::AlreadyHave {
        bytes: staging.bytes_present(),
        files: staging.files_present(),
    };
    if let Err(e) = session.send_control(&already).await {
        tracing::debug!(error = %e, "could not report the resume baseline to the sender");
    }

    let pulled = if session.peer_has_live_status() {
        pull_with_live_status(session, staging, &progress).await
    } else {
        pull_everything(session, staging, Arc::clone(&progress)).await
    };

    match pulled {
        Ok(received) => {
            // Settle the file counter. Files with no chunks — empty ones — are
            // created during the final tear-down rather than passing through
            // `finish_one`, so they never increment it as they go and the count
            // would otherwise stop short of the total on any tree containing one.
            // Reaching here means everything is verified and placed, which is
            // exactly what the total describes.
            let total = progress.files_total.load(Ordering::Relaxed);
            progress.files_done.store(total, Ordering::Relaxed);

            session.send_control(&Control::Complete).await?;
            Ok(received)
        }
        Err(e) => {
            // Staged chunks stay on disk, so this is a pause rather than a
            // loss — the next attempt picks up where this one stopped.
            match &e {
                // The sender stopped or vanished; there is nobody to tell.
                Error::PausedByPeer | Error::CancelledByPeer | Error::ConnectionClosed(_) => {}
                // Our user stopped it. A live sender is told so plainly; an older
                // one only understands `Abort`.
                Error::Paused | Error::Cancelled if session.peer_has_live_status() => {
                    announce_stop(session, &e).await;
                }
                _ => {
                    let _ = session
                        .send_control(&Control::Abort {
                            reason: e.to_string(),
                        })
                        .await;
                }
            }
            Err(e)
        }
    }
}

/// Pull everything while also talking to a live sender: reporting what has
/// arrived, and listening in case it stops.
async fn pull_with_live_status(
    session: &Session,
    staging: Staging,
    progress: &Arc<Progress>,
) -> Result<Received> {
    let pull = pull_everything(session, staging, Arc::clone(progress));
    tokio::pin!(pull);

    let listen = listen_to_sender(session, progress);
    tokio::pin!(listen);

    tokio::select! {
        result = &mut pull => result,
        stopped = &mut listen => {
            // Let the pull wind down rather than dropping it, so the disk writer
            // finishes and releases the staging area before anything — such as
            // the next attempt — opens it again. A deliberate stop has already
            // told the workers to finish their current chunk and go, so this ends
            // quickly.
            let deliberate = matches!(stopped, Error::PausedByPeer | Error::CancelledByPeer);
            match tokio::time::timeout(WIND_DOWN, &mut pull).await {
                // Everything had already arrived: that is a finished transfer,
                // whatever was said in the same moment.
                Ok(Ok(received)) => Ok(received),
                // A deliberate stop explains whatever the workers tripped over as
                // the sender hung up.
                _ if deliberate => Err(stopped),
                // Otherwise the control stream failed because the connection did,
                // and the pull's own error says more about where.
                Ok(Err(e)) => Err(e),
                Err(_) => Err(stopped),
            }
        }
        never = report_to_sender(session, progress) => match never {},
    }
}

/// Read the control stream for the life of a receive.
///
/// Returns only when there is a reason to stop: the sender said so, said
/// goodbye, or the stream failed.
async fn listen_to_sender(session: &Session, progress: &Progress) -> Error {
    loop {
        match session.recv_control().await {
            Ok(Control::Stop { reason }) => {
                progress.note_peer_stop(reason);
                return stopped_by_peer(reason);
            }
            Ok(Control::Goodbye { reason }) => {
                return Error::ConnectionClosed(proto::sanitize_name(&reason));
            }
            Ok(Control::Ping(nonce)) => {
                let _ = session.send_control(&Control::Pong(nonce)).await;
            }
            Ok(other) => tracing::debug!(?other, "ignoring control message while receiving"),
            Err(e) => return e,
        }
    }
}

/// Tell the sender how far we have got, a few times a second, for ever.
///
/// Only the receiver knows what has *arrived*; see [`Control::Progress`].
async fn report_to_sender(session: &Session, progress: &Progress) -> std::convert::Infallible {
    let mut ticker = tokio::time::interval(PROGRESS_REPORT);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last = None;

    loop {
        ticker.tick().await;

        let now = (
            progress.bytes_done.load(Ordering::Relaxed),
            progress.files_done.load(Ordering::Relaxed),
        );
        if last == Some(now) {
            continue;
        }
        last = Some(now);

        let report = Control::Progress {
            bytes: now.0,
            files: now.1,
        };
        if let Err(e) = session.send_control(&report).await {
            tracing::debug!(error = %e, "could not report progress to the sender");
        }
    }
}

async fn read_manifest(session: &Session, expected_entries: u64) -> Result<Manifest> {
    let mut entries = Vec::with_capacity(expected_entries.min(ENTRIES_PER_BATCH as u64) as usize);

    loop {
        match session.recv_control().await? {
            Control::ManifestBatch {
                entries: batch,
                more,
            } => {
                entries.extend(batch);

                if entries.len() as u64 > expected_entries {
                    return Err(Error::Protocol(format!(
                        "peer sent more manifest entries than the {expected_entries} it promised"
                    )));
                }
                if !more {
                    break;
                }
            }
            // The sender gave up while we were deciding.
            Control::Stop { reason } => return Err(stopped_by_peer(reason)),
            other => {
                return Err(Error::Protocol(format!(
                    "expected a manifest batch, got {other:?}"
                )));
            }
        }
    }

    if entries.len() as u64 != expected_entries {
        return Err(Error::Protocol(format!(
            "peer promised {expected_entries} manifest entries but sent {}",
            entries.len()
        )));
    }

    let manifest = Manifest { entries };
    manifest.validate()?;
    Ok(manifest)
}

/// How many chunk requests run at once.
///
/// The receive path used to be strictly serial — read a chunk off the wire,
/// verify it, write it to disk, then read the next — so the network idled while
/// the disk worked and vice versa. Measured, that put a hard ceiling near
/// 100 MB/s on loopback regardless of how the QUIC windows were tuned.
///
/// Eight is enough to keep both the sender's and the receiver's disks busy
/// through any plausible link, without so many streams that seeks start
/// thrashing on spinning media.
/// How long a sender waits with nothing happening before giving up.
///
/// Generous, because a legitimate gap can be long: the receiver may be verifying
/// a very large file, or writing to a slow disk, and neither sends anything while
/// it works. Short enough that a genuinely hung transfer does not sit there
/// overnight looking finished.
const STALL_TIMEOUT: Duration = Duration::from_secs(180);

/// How often the stall check runs. Coarse on purpose — this is a backstop.
const STALL_CHECK: Duration = Duration::from_secs(15);

const PARALLEL_REQUESTS: usize = 8;

/// Chunks per work item.
///
/// Large files are split into pieces so several streams can work on one file at
/// once; without this, a single-file transfer would get no parallelism at all.
/// 32 MiB per request keeps the per-request overhead irrelevant while still
/// giving eight workers something to do on a 256 MiB file.
const CHUNKS_PER_REQUEST: u32 = 32;

/// What the disk-writer thread is asked to do.
///
/// All disk I/O for a receive happens on one dedicated thread that owns the
/// [`Staging`] area. That is what lets the network run flat out: writers and
/// readers no longer take turns, and no blocking file operation ever lands on an
/// async runtime worker.
enum WriteCommand {
    Chunk {
        entry: u32,
        index: u32,
        data: Vec<u8>,
        hash: [u8; 32],
    },
    /// Read a completed file back and hash it, so the comparison with the
    /// sender's hash can wait for both reads at once rather than one after the
    /// other. Queued behind the file's chunks, so every byte is written first.
    Hash {
        entry: u32,
        reply: tokio::sync::oneshot::Sender<Result<[u8; 32]>>,
    },
    /// Verify a completed file and deliver it.
    Finish {
        entry: u32,
        hash: [u8; 32],
        /// This side's hash, already computed by `Hash`. `None` means compute it
        /// here, as before.
        local: Option<[u8; 32]>,
        /// True when the file fits in a single chunk, so the hash it was already
        /// verified against *is* its whole-file hash and there is nothing to
        /// re-read. See `Staging::finish_single_chunk_file`.
        single_chunk: bool,
        reply: tokio::sync::oneshot::Sender<Result<Placement>>,
    },
    /// Create directories and empty files, then tear down the staging area.
    Complete {
        reply: tokio::sync::oneshot::Sender<Result<Vec<Placement>>>,
    },
}

/// Fetch, verify, and deliver one file at a time.
///
/// Each file is placed the moment it is complete rather than batching every
/// placement to the end. That matters for an interrupted transfer: the work
/// already finished is *delivered*, not merely staged, so a user who cancels
/// halfway has usable files instead of an opaque staging directory. It also
/// keeps the delivery record advancing, which is what makes a later resume
/// cheap.
///
/// Files are taken smallest-first, so the most items become usable soonest.
async fn pull_everything(
    session: &Session,
    staging: Staging,
    progress: Arc<Progress>,
) -> Result<Received> {
    let bytes = staging.manifest().total_bytes();

    // Plan the work from what is on disk, before handing staging to the writer.
    // This is the same computation whether starting fresh or resuming a
    // transfer from last week.
    let mut work = std::collections::VecDeque::new();
    let mut remaining: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();

    // Remembered here because the writer thread takes ownership of staging.
    let single_chunk: std::collections::HashSet<u32> = staging
        .manifest()
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.is_file() && entry.chunk_count().unwrap_or(0) == 1)
        .map(|(index, _)| index as u32)
        .collect();
    let single_chunk = Arc::new(single_chunk);

    for entry in staging.manifest().transfer_order() {
        if staging.is_placed(entry) {
            continue;
        }

        let missing = staging
            .chunk_map(entry)
            .map(|map| map.missing_ranges())
            .unwrap_or_default();

        let mut pieces = 0;
        for range in missing {
            // Split so several streams can work on one large file.
            let mut start = range.start;
            while start < range.end {
                let end = (start + CHUNKS_PER_REQUEST).min(range.end);
                work.push_back((entry, ChunkRange::new(start, end)));
                pieces += 1;
                start = end;
            }
        }

        // A file with nothing missing still needs verifying and delivering —
        // it was fully staged by a previous run that never finished.
        remaining.insert(entry, pieces);
    }

    // The disk writer. A real OS thread, not a runtime task: it blocks on file
    // I/O for the whole transfer, which is exactly what must not happen on an
    // async worker.
    let (commands, mut inbox) = tokio::sync::mpsc::channel::<WriteCommand>(PARALLEL_REQUESTS * 2);
    let writer_progress = Arc::clone(&progress);
    let writer =
        tokio::task::spawn_blocking(move || run_writer(staging, &mut inbox, &writer_progress));

    // Shared queue plus per-entry counters. When a worker takes the last piece
    // of a file, it is the one that verifies and delivers it — which keeps
    // files landing as they complete rather than all at the end.
    let queue = Arc::new(std::sync::Mutex::new(work));
    let counters = Arc::new(std::sync::Mutex::new(remaining));

    let mut workers = Vec::with_capacity(PARALLEL_REQUESTS);
    for _ in 0..PARALLEL_REQUESTS {
        workers.push(pull_worker(
            session,
            Arc::clone(&queue),
            Arc::clone(&counters),
            Arc::clone(&single_chunk),
            commands.clone(),
            Arc::clone(&progress),
        ));
    }

    // Any worker failing aborts the transfer; staged data survives for a resume.
    let outcome = futures_util::future::try_join_all(workers).await;

    // Finish the files that had nothing left to fetch.
    if outcome.is_ok() {
        let leftovers: Vec<u32> = counters
            .lock()
            .expect("counters poisoned")
            .iter()
            .filter(|(_, pieces)| **pieces == 0)
            .map(|(&entry, _)| entry)
            .collect();

        for entry in leftovers {
            // Nothing was pulled for these in this session — they were staged by
            // an earlier run — so there is no verified chunk in memory and the
            // whole-file hash has to be fetched and checked.
            finish_one(session, entry, false, &commands, &progress).await?;
        }
    }

    let mut placements = Vec::new();
    if outcome.is_ok() {
        let (reply, answer) = tokio::sync::oneshot::channel();
        if commands.send(WriteCommand::Complete { reply }).await.is_ok() {
            placements = answer
                .await
                .map_err(|_| Error::Io(std::io::Error::other("the disk writer stopped")))??;
        }
    }

    // Dropping the last sender ends the writer loop.
    drop(commands);
    let placed_during_transfer = writer
        .await
        .map_err(|e| Error::Io(std::io::Error::other(e)))??;

    outcome?;

    placements.extend(placed_during_transfer);
    Ok(Received { placements, bytes })
}

/// One concurrent puller: take work, fetch it, hand it to the writer.
async fn pull_worker(
    session: &Session,
    queue: Arc<std::sync::Mutex<std::collections::VecDeque<(u32, ChunkRange)>>>,
    counters: Arc<std::sync::Mutex<std::collections::HashMap<u32, usize>>>,
    single_chunk: Arc<std::collections::HashSet<u32>>,
    commands: tokio::sync::mpsc::Sender<WriteCommand>,
    progress: Arc<Progress>,
) -> Result<()> {
    loop {
        progress.check_interrupted()?;

        let Some((entry, range)) = queue.lock().expect("queue poisoned").pop_front() else {
            return Ok(());
        };

        pull_range(session, entry, range, &commands, &progress).await?;

        // Whoever takes the count to zero owns finishing this file.
        let finished = {
            let mut counters = counters.lock().expect("counters poisoned");
            match counters.get_mut(&entry) {
                Some(pieces) => {
                    *pieces -= 1;
                    *pieces == 0
                }
                None => false,
            }
        };

        if finished {
            counters.lock().expect("counters poisoned").remove(&entry);
            finish_one(
                session,
                entry,
                single_chunk.contains(&entry),
                &commands,
                &progress,
            )
            .await?;
        }
    }
}

/// Ask for a file's whole-file hash, then have the writer verify and deliver it.
async fn finish_one(
    session: &Session,
    entry: u32,
    single_chunk: bool,
    commands: &tokio::sync::mpsc::Sender<WriteCommand>,
    progress: &Progress,
) -> Result<()> {
    // A file of one chunk was already fully verified when that chunk arrived, so
    // there is no whole-file hash to fetch and nothing left to check. On a
    // transfer of thousands of small files this removes a round trip and a full
    // file read on each side, per file.
    let (hash, local) = if single_chunk {
        ([0u8; 32], None)
    } else {
        // Both reads at once. The sender reads its original to hash it while the
        // writer reads this side's copy; one after the other they cost the sum,
        // together only the longer. For an 8 GB file that is the difference
        // between two full passes of waiting at 100% and one.
        let (reply, mine) = tokio::sync::oneshot::channel();
        commands
            .send(WriteCommand::Hash { entry, reply })
            .await
            .map_err(|_| writer_stopped())?;

        let ours = async {
            let local = mine.await.map_err(|_| writer_stopped())??;
            // Our half is done. If theirs is not, say so rather than go quiet.
            progress.wait_for_peer();
            Ok::<_, Error>(local)
        };
        let joined = tokio::try_join!(request_file_hash(session, entry), ours);
        // Before `?`: if the sender's half failed after ours finished, the wait
        // was already showing, and an error must not leave it there.
        progress.stop_waiting_for_peer();
        let (remote, local) = joined?;
        (remote, Some(local))
    };

    let (reply, answer) = tokio::sync::oneshot::channel();

    commands
        .send(WriteCommand::Finish {
            entry,
            hash,
            local,
            single_chunk,
            reply,
        })
        .await
        .map_err(|_| Error::Io(std::io::Error::other("the disk writer stopped")))?;

    answer
        .await
        .map_err(|_| Error::Io(std::io::Error::other("the disk writer stopped")))??;

    progress.files_done.fetch_add(1, Ordering::Relaxed);

    // Tell the sender, so its own progress can count files rather than only
    // bytes. Best-effort: a failure here means the sender shows a coarser number,
    // which is not worth failing a verified file over.
    if let Err(e) = session.send_control(&Control::EntryDone { entry }).await {
        tracing::debug!(entry, error = %e, "could not report a finished file to the sender");
    }

    Ok(())
}

fn writer_stopped() -> Error {
    Error::Io(std::io::Error::other("the disk writer stopped"))
}

/// The disk writer. Owns [`Staging`] for the whole transfer.
///
/// Returns the files delivered while the transfer was running; the final
/// [`WriteCommand::Complete`] returns the rest.
fn run_writer(
    mut staging: Staging,
    inbox: &mut tokio::sync::mpsc::Receiver<WriteCommand>,
    progress: &Arc<Progress>,
) -> Result<Vec<Placement>> {
    let mut placed = Vec::new();

    while let Some(command) = inbox.blocking_recv() {
        match command {
            WriteCommand::Chunk {
                entry,
                index,
                data,
                hash,
            } => {
                // Verification happens in here, before anything reaches the
                // partial file.
                if let Err(e) = staging.write_chunk(entry, index, &data, &hash) {
                    keep_what_arrived(&mut staging);
                    return Err(e);
                }
            }

            WriteCommand::Hash { entry, reply } => {
                let size = staging
                    .manifest()
                    .entries
                    .get(entry as usize)
                    .map(|e| e.size())
                    .unwrap_or(0);
                // The guard is dropped *before* replying: the caller treats the
                // reply as "our half is done" and may then show that it is
                // waiting for the other device, which it must not do while this
                // check still counts as running.
                let outcome = {
                    let _check = progress.begin_check(CheckKind::Verifying, size);
                    staging.hash_staged_file(entry, &mut |read| progress.check_advance(read))
                };
                let _ = reply.send(outcome);
            }

            WriteCommand::Finish {
                entry,
                hash,
                local,
                single_chunk,
                reply,
            } => {
                let outcome = if single_chunk {
                    staging.finish_single_chunk_file(entry)
                } else if let Some(local) = local {
                    staging.place_verified(entry, &local, &hash)
                } else {
                    staging.finish_file(entry, &hash)
                };
                if let Ok(placement) = &outcome {
                    placed.push(placement.clone());
                }
                // A dropped receiver means the transfer was abandoned; the work
                // is already done either way.
                let _ = reply.send(outcome);
            }

            WriteCommand::Complete { reply } => {
                // `finish` consumes staging, so this ends the loop.
                let outcome = std::mem::replace(&mut staging, Staging::placeholder()).finish();
                let _ = reply.send(outcome);
                return Ok(placed);
            }
        }
    }

    // Every sender is gone without a `Complete`: the transfer stopped early.
    keep_what_arrived(&mut staging);
    Ok(placed)
}

/// Record everything written so far, so the next attempt resumes from it.
fn keep_what_arrived(staging: &mut Staging) {
    if let Err(e) = staging.checkpoint_all() {
        tracing::warn!(error = %e, "could not record progress; some data may be fetched again");
    }
}

/// Fetch one range and hand each chunk to the writer.
///
/// Reads from the network and never touches the disk, so this can run eight at a
/// time without contending on anything but the writer's channel.
async fn pull_range(
    session: &Session,
    entry: u32,
    range: ChunkRange,
    commands: &tokio::sync::mpsc::Sender<WriteCommand>,
    progress: &Progress,
) -> Result<()> {
    let (mut send, mut recv) = session.open_stream().await?;
    proto::write_frame(&mut send, &DataRequest::Chunks { entry, range }).await?;
    send.finish().map_err(Error::transport)?;

    // A sender that can compress frames always uses the frame that can say so.
    let v2 = session.peer().capabilities.zstd;

    for expected_index in range.iter() {
        progress.check_interrupted()?;

        // Before reading the chunk, not after. Waiting here leaves the bytes in
        // the peer's send buffer and lets QUIC's own flow control push back on
        // the sender, which is what actually slows the wire down. Accounting for
        // them afterwards would limit only our bookkeeping while the data arrived
        // at full speed regardless.
        progress.limit.take(CHUNK_SIZE).await;

        let header = read_chunk_header(&mut recv, v2).await?;

        // Bound the lengths before allocating, so a hostile peer cannot make us
        // reserve or read an arbitrary amount — and cannot use compression to
        // make a small frame expand into a large one.
        if header.len as u64 > CHUNK_SIZE {
            return Err(Error::FrameTooLarge {
                size: header.len as usize,
                limit: CHUNK_SIZE as usize,
            });
        }
        if header.wire_len > header.len {
            return Err(Error::Protocol(format!(
                "chunk {} claims {} bytes on the wire for {} bytes of data",
                header.index, header.wire_len, header.len
            )));
        }
        if header.index != expected_index {
            return Err(Error::Protocol(format!(
                "expected chunk {expected_index}, peer sent {}",
                header.index
            )));
        }

        // Read in whatever pieces arrive and count each one, rather than one
        // whole chunk at a time. Eight streams share the link, so whole chunks
        // finished in near-lockstep: on a slow link nothing was counted for a
        // second or more and then eight megabytes at once, and the speed shown
        // flipped between zero and double.
        //
        // Progress counts file bytes, not wire bytes, so a compressed chunk is
        // credited in proportion as it arrives and adds up to its full length.
        let (len, wire_len) = (u64::from(header.len), u64::from(header.wire_len).max(1));
        let credit = |filled: usize| filled as u64 * len / wire_len;
        let mut wire = vec![0u8; header.wire_len as usize];
        let mut filled = 0;
        while filled < wire.len() {
            match recv.read(&mut wire[filled..]).await {
                Ok(Some(read)) => {
                    progress.advance(credit(filled + read) - credit(filled));
                    filled += read;
                }
                Ok(None) => {
                    return Err(Error::Transport(format!(
                        "chunk {}: the stream ended {} bytes early",
                        header.index,
                        wire.len() - filled
                    )));
                }
                Err(e) => {
                    return Err(Error::Transport(format!("chunk {}: {e}", header.index)));
                }
            }
        }

        let data = if header.compressed() {
            // Bounded by the declared length: anything that would expand past
            // it is refused rather than allocated.
            let data = zstd::bulk::decompress(&wire, header.len as usize).map_err(|e| {
                Error::Protocol(format!("chunk {} would not decompress: {e}", header.index))
            })?;
            if data.len() != header.len as usize {
                return Err(Error::Protocol(format!(
                    "chunk {} decompressed to {} bytes, not {}",
                    header.index,
                    data.len(),
                    header.len
                )));
            }
            data
        } else {
            wire
        };

        // The channel is bounded, so a disk that cannot keep up applies
        // backpressure here rather than growing a queue without limit.
        commands
            .send(WriteCommand::Chunk {
                entry,
                index: header.index,
                data,
                hash: header.hash,
            })
            .await
            .map_err(|_| Error::Io(std::io::Error::other("the disk writer stopped")))?;
    }

    Ok(())
}

/// Files at least this big are worth comparing with an older copy. Below it,
/// sending the file costs about what asking for its hashes would.
const REUSE_THRESHOLD: u64 = 8 * 1024 * 1024;

/// Chunk hashes asked for per request: 32 KiB of answer, and on the sender a
/// read of up to a gigabyte, which keeps any one request from taking minutes.
const HASHES_PER_REQUEST: u32 = 1024;

/// Copy every unchanged chunk from older copies of files at the destination.
///
/// For each large file not yet complete, if a file already sits where it will
/// land, ask the sender for the hashes of the missing chunks that copy could
/// cover, then read those chunks locally and keep each one whose hash matches.
/// Matching is chunk-for-chunk at the same offset, so it catches files changed
/// in place or added to at the end — the common cases for disk images,
/// archives, logs and databases — and every reused chunk is verified exactly
/// as a received one would be, before and after assembly.
///
/// Best-effort throughout. Anything that goes wrong leaves those chunks to be
/// fetched normally.
async fn reuse_older_copies(
    session: &Session,
    mut staging: Staging,
    destination: &Path,
    progress: &Arc<Progress>,
) -> Result<Staging> {
    let mut candidates = Vec::new();
    for (index, entry) in staging.manifest().entries.iter().enumerate() {
        let index = index as u32;
        if !entry.is_file() || entry.size() < REUSE_THRESHOLD || staging.is_placed(index) {
            continue;
        }
        let existing = to_extended_length(&entry.path.resolve_in(destination));
        let Ok(metadata) = std::fs::metadata(&existing) else {
            continue;
        };
        if !metadata.is_file() || metadata.len() == 0 {
            continue;
        }

        // Only chunks the older copy is long enough to hold in full.
        let size = entry.size();
        let usable = staging
            .chunk_map(index)
            .map(|map| map.missing_ranges())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|range| {
                let end = range
                    .iter()
                    .take_while(|&chunk| {
                        chunk::chunk_span(chunk, size)
                            .is_ok_and(|(offset, len)| offset + len as u64 <= metadata.len())
                    })
                    .last()?
                    + 1;
                Some(ChunkRange::new(range.start, end))
            })
            .collect::<Vec<_>>();
        if !usable.is_empty() {
            candidates.push((index, existing, size, usable));
        }
    }

    if candidates.is_empty() {
        return Ok(staging);
    }

    // Two reads of every candidate range - the sender's original for its hashes,
    // then this side's older copy - and nothing on the wire meanwhile, so it is
    // reported as one comparison covering both, or it would look like a stall.
    let compared: u64 = candidates
        .iter()
        .map(|(_, _, size, ranges)| ranges.iter().map(|r| range_bytes(*r, *size)).sum::<u64>())
        .sum();
    let _check = progress.begin_check(CheckKind::Comparing, compared * 2);

    // The network half: every hash, before touching the disk.
    let mut wanted = Vec::new();
    for (index, existing, size, ranges) in candidates {
        for range in ranges {
            let mut start = range.start;
            while start < range.end {
                let end = (start + HASHES_PER_REQUEST).min(range.end);
                let piece = ChunkRange::new(start, end);
                match request_chunk_hashes(session, index, piece).await {
                    Ok(hashes) => {
                        progress.check_advance(range_bytes(piece, size));
                        wanted.push((index, existing.clone(), size, piece, hashes));
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "could not get chunk hashes; sending in full");
                        break;
                    }
                }
                start = end;
            }
        }
    }

    // The disk half, off the async runtime: it may read gigabytes.
    let disk_progress = Arc::clone(progress);
    let (staging, reused) = tokio::task::spawn_blocking(move || {
        let mut reused = 0u64;
        for (index, existing, size, range, hashes) in wanted {
            reused += reuse_matching(&mut staging, index, &existing, size, range, &hashes);
            disk_progress.check_advance(range_bytes(range, size));
        }
        (staging, reused)
    })
    .await
    .map_err(|e| Error::Io(std::io::Error::other(e)))?;

    if reused > 0 {
        tracing::info!(reused, "reused unchanged data from older copies at the destination");
        progress.bytes_reused.fetch_add(reused, Ordering::Relaxed);
    }
    Ok(staging)
}

/// Stage every chunk of `existing` in `range` whose hash matches the sender's.
/// Returns the bytes reused.
fn reuse_matching(
    staging: &mut Staging,
    index: u32,
    existing: &Path,
    size: u64,
    range: ChunkRange,
    hashes: &[[u8; 32]],
) -> u64 {
    use std::io::{Read, Seek, SeekFrom};

    let Ok(mut file) = std::fs::File::open(existing) else {
        return 0;
    };
    let mut buffer = vec![0u8; CHUNK_SIZE as usize];
    let mut reused = 0u64;

    for (chunk, hash) in range.iter().zip(hashes) {
        let Ok((offset, len)) = chunk::chunk_span(chunk, size) else {
            break;
        };
        if file.seek(SeekFrom::Start(offset)).is_err() || file.read_exact(&mut buffer[..len]).is_err() {
            break;
        }
        // `write_chunk` checks the hash before writing, so a chunk that has
        // changed is simply refused here and fetched later.
        if let Ok(true) = staging.write_chunk(index, chunk, &buffer[..len], hash) {
            reused += len as u64;
        }
    }

    if reused > 0
        && let Err(e) = staging.checkpoint(index)
    {
        tracing::debug!(index, error = %e, "could not record reused chunks");
    }
    reused
}

async fn request_chunk_hashes(
    session: &Session,
    entry: u32,
    range: ChunkRange,
) -> Result<Vec<[u8; 32]>> {
    let (mut send, mut recv) = session.open_stream().await?;
    proto::write_frame(&mut send, &DataRequest::ChunkHashes { entry, range }).await?;
    send.finish().map_err(Error::transport)?;

    let mut hashes = vec![[0u8; 32]; range.len() as usize];
    for hash in &mut hashes {
        recv.read_exact(hash)
            .await
            .map_err(|e| Error::Transport(format!("chunk hashes for entry {entry}: {e}")))?;
    }
    Ok(hashes)
}

/// Read the next chunk header in whichever layout this sender uses, as the
/// newer one. An older header is a raw chunk: as many bytes on the wire as in
/// the chunk.
async fn read_chunk_header(recv: &mut quinn::RecvStream, v2: bool) -> Result<ChunkHeaderV2> {
    let failed = |e: quinn::ReadExactError| Error::Transport(format!("chunk header: {e}"));

    if v2 {
        let mut bytes = [0u8; ChunkHeaderV2::SIZE];
        recv.read_exact(&mut bytes).await.map_err(failed)?;
        Ok(ChunkHeaderV2::decode(&bytes))
    } else {
        let mut bytes = [0u8; ChunkHeader::SIZE];
        recv.read_exact(&mut bytes).await.map_err(failed)?;
        let header = ChunkHeader::decode(&bytes);
        Ok(ChunkHeaderV2 {
            index: header.index,
            len: header.len,
            wire_len: header.len,
            hash: header.hash,
        })
    }
}

async fn request_file_hash(session: &Session, entry: u32) -> Result<[u8; 32]> {
    let (mut send, mut recv) = session.open_stream().await?;
    proto::write_frame(&mut send, &DataRequest::FileHash { entry }).await?;
    send.finish().map_err(Error::transport)?;

    let mut hash = [0u8; 32];
    recv.read_exact(&mut hash)
        .await
        .map_err(|e| Error::Transport(format!("file hash for entry {entry}: {e}")))?;
    Ok(hash)
}

/// Render a summary the way an accept prompt should read.
pub fn describe(summary: &Summary) -> String {
    let size = human_bytes(summary.total_bytes);
    let files = match summary.file_count {
        1 => "1 file".to_string(),
        n => format!("{n} files"),
    };

    let names = if summary.top_level.is_empty() {
        String::new()
    } else {
        let shown = summary
            .top_level
            .iter()
            .map(|s| proto::sanitize_name(s))
            .collect::<Vec<_>>()
            .join(", ");
        let suffix = if summary.more_top_level { ", ..." } else { "" };
        format!(" ({shown}{suffix})")
    };

    format!("{files}, {size}{names}")
}

pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];

    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_sizes_read_naturally() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1024), "1.0 KB");
        assert_eq!(human_bytes(1536), "1.5 KB");
        assert_eq!(human_bytes(1024 * 1024 * 3), "3.0 MB");
        assert_eq!(human_bytes(1024u64.pow(4) * 2), "2.0 TB");
    }

    #[test]
    fn offers_are_described_for_a_prompt() {
        let summary = Summary {
            file_count: 12,
            directory_count: 3,
            total_bytes: 5 * 1024 * 1024,
            top_level: vec!["photos".into(), "notes.txt".into()],
            more_top_level: false,
        };
        assert_eq!(describe(&summary), "12 files, 5.0 MB (photos, notes.txt)");

        let single = Summary {
            file_count: 1,
            directory_count: 0,
            total_bytes: 900,
            top_level: vec!["a.txt".into()],
            more_top_level: false,
        };
        assert_eq!(describe(&single), "1 file, 900 B (a.txt)");
    }

    #[test]
    fn a_hostile_top_level_name_is_defanged_in_the_prompt() {
        // The prompt is the security decision point, so peer-supplied text in
        // it must not be able to misrepresent what is arriving.
        let summary = Summary {
            file_count: 1,
            directory_count: 0,
            total_bytes: 10,
            top_level: vec!["\u{202E}gnp.exe".into()],
            more_top_level: false,
        };
        assert!(!describe(&summary).contains('\u{202E}'));
    }

    #[test]
    fn a_check_reports_while_running_and_clears_when_done() {
        let progress = Arc::new(Progress::default());
        assert!(progress.check().is_none(), "nothing to report at rest");

        {
            let _check = progress.begin_check(CheckKind::Verifying, 1000);
            progress.check_advance(400);
            assert_eq!(progress.check(), Some((CheckKind::Verifying, 400, 1000)));
        }

        // The regression this exists for: a label left behind after the work
        // ends would be as misleading as no label during it.
        assert!(progress.check().is_none(), "must clear when the check ends");
    }

    #[test]
    fn overlapping_checks_clear_only_when_the_last_one_ends() {
        let progress = Arc::new(Progress::default());
        let first = progress.begin_check(CheckKind::Verifying, 100);
        let second = progress.begin_check(CheckKind::Verifying, 300);
        assert_eq!(progress.check().map(|c| c.2), Some(400), "totals add up");

        drop(first);
        assert!(progress.check().is_some(), "one is still running");
        drop(second);
        assert!(progress.check().is_none());
    }

    #[test]
    fn waiting_for_the_peer_never_hides_our_own_check() {
        let progress = Arc::new(Progress::default());

        // While our own read runs, it is the more useful thing to show.
        let check = progress.begin_check(CheckKind::Verifying, 100);
        progress.wait_for_peer();
        assert_eq!(progress.check().map(|c| c.0), Some(CheckKind::Verifying));
        drop(check);

        // Once ours is done, say we are waiting rather than go quiet...
        progress.wait_for_peer();
        assert_eq!(progress.check().map(|c| c.0), Some(CheckKind::WaitingForPeer));

        // ...and clear it when they answer.
        progress.stop_waiting_for_peer();
        assert!(progress.check().is_none());
    }

    #[test]
    fn stopping_the_wait_leaves_a_real_check_alone() {
        let progress = Arc::new(Progress::default());
        let _check = progress.begin_check(CheckKind::Comparing, 100);
        progress.stop_waiting_for_peer();
        assert_eq!(progress.check().map(|c| c.0), Some(CheckKind::Comparing));
    }

    #[test]
    fn progress_never_exceeds_the_total_however_much_is_resent() {
        // A sender counts what it writes, and a chunk served twice was counted
        // twice. On a real transfer that produced "201.4 GB of 138.5 GB".
        let progress = Progress::default();
        progress.bytes_total.store(1000, Ordering::Relaxed);

        for _ in 0..50 {
            progress.advance(100);
        }

        assert_eq!(
            progress.bytes_done.load(Ordering::Relaxed),
            1000,
            "5000 bytes of traffic for a 1000 byte transfer must still read 1000"
        );
        assert!((progress.fraction() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn progress_with_no_known_total_is_left_alone() {
        // Before the offer is accepted the total is zero, and clamping to it
        // would freeze the counter at nothing.
        let progress = Progress::default();
        progress.advance(4096);
        assert_eq!(progress.bytes_done.load(Ordering::Relaxed), 4096);
    }

    #[test]
    fn progress_reports_a_sane_fraction() {
        let progress = Progress::default();
        assert_eq!(progress.fraction(), 1.0, "an empty transfer is done");

        progress.bytes_total.store(1000, Ordering::Relaxed);
        progress.bytes_done.store(250, Ordering::Relaxed);
        assert_eq!(progress.fraction(), 0.25);
    }
}
