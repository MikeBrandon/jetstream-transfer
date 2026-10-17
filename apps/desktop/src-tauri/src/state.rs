//! Application state, and the plumbing between the engine and the window.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use jetstream_core::identity::{Identity, store};
use jetstream_core::rate::RateMeter;
use jetstream_core::staging::ConflictPolicy;
use jetstream_core::transfer::Progress;
use jetstream_core::transport::Endpoint;
use jetstream_core::trust::TrustStore;
use jetstream_core::{DEFAULT_PORT, DeviceId, default_device_name};
use jetstream_discovery::Discovery;
use tokio::sync::oneshot;

use crate::views::{Direction, SettingsView, TransferState, TransferView};

/// How long a browser upload may go without a chunk before its row says so.
///
/// A phone gives no signal when it goes — the tab closes, the screen locks, it
/// walks out of range — so without this its row sat at "active" for ever.
const BROWSER_STALL: std::time::Duration = std::time::Duration::from_secs(90);

pub struct AppState {
    pub identity: Arc<Identity>,
    pub endpoint: Endpoint,
    pub discovery: Discovery,
    pub trust: Mutex<TrustStore>,
    pub settings: Mutex<Settings>,
    pub data_dir: PathBuf,

    transfers: Mutex<HashMap<u64, Transfer>>,
    pending_offers: Mutex<HashMap<u64, oneshot::Sender<OfferAnswer>>>,
    next_id: AtomicU64,

    /// Browser receiver state. All of it is deliberately transient: nothing here
    /// is persisted, because a browser session is not a relationship worth
    /// remembering across restarts.
    web: Mutex<WebState>,
    /// The running server, if the user has turned it on. An async mutex because
    /// starting and stopping both await.
    pub web_server: tokio::sync::Mutex<Option<jetstream_web::WebServer>>,

    /// Completed and interrupted transfers, persisted.
    pub history: crate::history::History,
    /// Whether the close button has already been explained once.
    first_hide_done: std::sync::atomic::AtomicBool,

    /// Running from a `Jetstream Data` folder beside the executable.
    ///
    /// Surfaced to the UI because it changes two things a user should know:
    /// the private key is not DPAPI-wrapped, and anything that records this
    /// executable's path on the host machine will break when the drive moves.
    pub portable: bool,

    /// Devices the user added by address. See [`crate::manual`].
    pub manual: crate::manual::ManualPeers,

    /// History records whose automatic retry is running right now.
    ///
    /// Without this, the retry watcher starts another attempt every time it
    /// polls, because "interrupted and eligible" stays true for the whole
    /// duration of the attempt. On a transfer measured in hours that produced a
    /// pile of duplicate sessions hammering the peer.
    retrying: Mutex<HashSet<u64>>,
}

#[derive(Default)]
struct WebState {
    /// Files the user is offering for browsers to download.
    offers: Vec<PathBuf>,
    /// Text the user is sharing with browsers.
    shared_text: Option<String>,
    /// Maps a browser session's guest id to its in-flight transfer row, so the
    /// upload's completion can update the right one. Keyed by session rather
    /// than by label, which two phones of the same kind share.
    in_flight: HashMap<String, u64>,
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub device_name: String,
    pub download_dir: PathBuf,
    pub on_conflict: ConflictPolicy,
    /// Kilobytes per second; 0 means no limit.
    pub send_limit_kbps: u64,
    pub receive_limit_kbps: u64,
}

impl Settings {
    /// Load settings, falling back to sensible defaults.
    ///
    /// A malformed settings file is replaced rather than treated as fatal —
    /// unlike the trust store, nothing here is a security decision, and
    /// refusing to start over a bad preference would be absurd.
    pub fn load(dir: &Path) -> Self {
        let path = dir.join("settings.json");

        let stored: Option<SettingsView> = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok());

        match stored {
            Some(view) => Self {
                device_name: view.device_name,
                download_dir: PathBuf::from(view.download_dir),
                on_conflict: parse_conflict(&view.on_conflict),
                send_limit_kbps: view.send_limit_kbps,
                receive_limit_kbps: view.receive_limit_kbps,
            },
            None => Self::default(),
        }
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let view = self.to_view();
        let text = serde_json::to_string_pretty(&view)
            .unwrap_or_else(|_| "{}".to_string());
        std::fs::write(dir.join("settings.json"), text)
    }

    pub fn to_view(&self) -> SettingsView {
        SettingsView {
            device_name: self.device_name.clone(),
            download_dir: self.download_dir.display().to_string(),
            on_conflict: match self.on_conflict {
                ConflictPolicy::Rename => "rename",
                ConflictPolicy::Overwrite => "overwrite",
                ConflictPolicy::Skip => "skip",
            }
            .to_string(),
            send_limit_kbps: self.send_limit_kbps,
            receive_limit_kbps: self.receive_limit_kbps,
        }
    }

    /// The limit for one direction, in bytes per second.
    pub fn limit_bytes(&self, direction: Direction) -> u64 {
        let kbps = match direction {
            Direction::Sending => self.send_limit_kbps,
            Direction::Receiving => self.receive_limit_kbps,
        };
        kbps.saturating_mul(1000)
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            device_name: default_device_name(),
            download_dir: default_download_dir(),
            on_conflict: ConflictPolicy::Rename,
            // Unlimited by default. A transfer app's job is to be fast, and a
            // limit is something a user reaches for when they need the network
            // back — not a default that quietly makes everything slower.
            send_limit_kbps: 0,
            receive_limit_kbps: 0,
        }
    }
}

pub fn parse_conflict(text: &str) -> ConflictPolicy {
    match text {
        "overwrite" => ConflictPolicy::Overwrite,
        "skip" => ConflictPolicy::Skip,
        _ => ConflictPolicy::Rename,
    }
}

/// `%USERPROFILE%\Downloads\Jetstream`, or the data directory as a fallback.
///
/// A subfolder rather than Downloads itself: files arriving from another device
/// should be findable together, not scattered among browser downloads.
fn default_download_dir() -> PathBuf {
    directories::UserDirs::new()
        .and_then(|dirs| dirs.download_dir().map(Path::to_path_buf))
        .map(|dir| dir.join("Jetstream"))
        .unwrap_or_else(|| PathBuf::from("."))
}

use std::path::Path;

/// What the user chose in the accept dialog.
#[derive(Debug, Clone)]
pub struct OfferAnswer {
    pub accept: bool,
    /// Trust decision to remember, if any.
    pub remember: Option<jetstream_core::trust::TrustLevel>,
}

/// One transfer, live.
pub struct Transfer {
    pub direction: Direction,
    pub peer_name: String,
    pub peer_device_id: DeviceId,
    pub state: TransferState,
    pub progress: Arc<Progress>,
    pub summary: String,
    pub detail: Option<String>,
    pub started_at: i64,
    /// Smoothed speed, measured from bytes that moved in this attempt only.
    meter: RateMeter,
    /// What an earlier attempt of this same transfer had reached, shown until
    /// this attempt learns the real figure from the other side.
    ///
    /// Without it, every resume — automatic or not — dropped the row to 0% and
    /// "waiting…" for as long as the reconnect took, which reads exactly like
    /// starting again from scratch.
    carried: Option<(u64, u64)>,
    /// Frozen final counts, so a finished row keeps showing what it moved
    /// rather than reverting to whatever the atomics happen to hold.
    final_bytes: Option<(u64, u64)>,
    /// What the manifest walk could not include, with a reason each.
    pub skipped: Vec<crate::views::SkippedView>,
    /// Where this transfer's files are, for "show me in Explorer".
    ///
    /// A file rather than a folder where possible, so Explorer opens the folder
    /// *and highlights the item* — landing in a directory of 128,000 files with
    /// nothing selected is barely more use than not opening it.
    pub reveal: Option<PathBuf>,
    /// Negotiated speed of the wire to this peer, in bits per second.
    ///
    /// Resolved once when the session is established rather than per frame: the
    /// answer needs several system calls and cannot change without the
    /// connection dropping, so looking it up eight times a second would be pure
    /// waste.
    link_bps: Option<u64>,
    /// An upload from a browser, which no engine task watches over.
    browser: bool,
    /// When bytes last moved, and the count then — for noticing a browser that
    /// has gone quiet.
    last_moved: (Instant, u64),
}

impl Transfer {
    /// What to show: frozen at the end, live while running, and the previous
    /// attempt's figure until this one has a figure of its own.
    fn bytes(&self) -> (u64, u64) {
        if let Some(frozen) = self.final_bytes {
            return frozen;
        }

        let live = (
            self.progress.bytes_done.load(Ordering::Relaxed),
            self.progress.bytes_total.load(Ordering::Relaxed),
        );
        match self.carried {
            Some(carried) if live.0 == 0 && !matches!(self.state, TransferState::Active) => carried,
            _ => live,
        }
    }

    fn view(&self, id: u64) -> TransferView {
        let (bytes_done, bytes_total) = self.bytes();

        let running = !self.state.is_finished();
        let rate = if running { self.meter.rate() } else { 0 };
        let remaining = bytes_total.saturating_sub(bytes_done);

        TransferView {
            id,
            direction: self.direction,
            peer_name: self.peer_name.clone(),
            peer_device_id: self.peer_device_id.to_hex(),
            state: self.state,
            bytes_done,
            bytes_total,
            files_done: self.progress.files_done.load(Ordering::Relaxed),
            files_total: self.progress.files_total.load(Ordering::Relaxed),
            rate,
            limit: self.progress.limit.limit(),
            skipped: self.skipped.clone(),
            can_reveal: self.reveal.is_some(),
            link_ceiling: self
                .link_bps
                .map(jetstream_discovery::linkspeed::as_bytes_per_second),
            link_label: self
                .link_bps
                .map(jetstream_discovery::linkspeed::describe),
            // Only offer an estimate once the rate has settled. An ETA that
            // swings between "2 seconds" and "4 hours" is worse than none.
            eta: if running { self.meter.eta(remaining) } else { None },
            summary: self.summary.clone(),
            detail: self.detail.clone(),
            started_at: self.started_at,
            // Only the sender holds the data, so only it can pick a transfer up
            // again. A receive continues when the sender comes back.
            resumable: self.direction == Direction::Sending && self.state.is_resumable(),
        }
    }

    fn sample(&mut self) {
        let now = Instant::now();
        let done = self.progress.bytes_done.load(Ordering::Relaxed);
        let moved = self.progress.bytes_moved.load(Ordering::Relaxed);
        let fresh = moved > self.last_moved.1;
        if fresh {
            self.last_moved = (now, moved);
        }

        // A browser upload has no connection to lose, only silence. Say so when
        // it goes quiet, and pick back up when the page starts sending again.
        if self.browser {
            match self.state {
                TransferState::Interrupted if fresh => {
                    self.state = TransferState::Active;
                    self.detail = None;
                }
                TransferState::Active if now.duration_since(self.last_moved.0) > BROWSER_STALL => {
                    self.state = TransferState::Interrupted;
                    self.detail = Some(format!(
                        "{} stopped sending. What arrived is kept, and it carries on if the page reconnects.",
                        self.peer_name
                    ));
                    self.meter.reset();
                }
                _ => {}
            }
        }

        if self.state.is_finished() {
            return;
        }

        // Promote to Active the moment the transfer is under way. The engine has
        // no "the peer accepted" callback — a known total plus any progress,
        // including a resume baseline, *is* the signal — and inferring it here
        // keeps the rule in one place rather than having the UI second-guess a
        // stale `Waiting` label.
        if (done > 0 || moved > 0)
            && matches!(self.state, TransferState::Connecting | TransferState::Waiting)
        {
            self.state = TransferState::Active;
        }

        self.meter.update(now, moved);
    }
}

impl AppState {
    pub fn new(location: store::Location) -> anyhow::Result<Arc<Self>> {
        let portable = location.is_portable();
        let data_dir = location.dir;
        let data_dir_for_history = data_dir.clone();
        let identity = Arc::new(store::load_or_create_protected(
            &data_dir,
            location.protection,
        )?);
        let trust = TrustStore::load(&data_dir)?;
        let settings = Settings::load(&data_dir);

        std::fs::create_dir_all(&settings.download_dir).ok();

        // Prefer the well-known port so a peer that remembers this device can
        // reach it without discovery. Falling back to an ephemeral port when it
        // is taken keeps a second instance — or a launch racing a not-yet-dead
        // previous one — working instead of refusing to start.
        let endpoint = match Endpoint::bind_all(
            Arc::clone(&identity),
            settings.device_name.clone(),
            DEFAULT_PORT,
        ) {
            Ok(endpoint) => endpoint,
            Err(e) => {
                tracing::warn!(
                    port = DEFAULT_PORT,
                    error = %e,
                    "default port unavailable; using an ephemeral one"
                );
                Endpoint::bind_all(Arc::clone(&identity), settings.device_name.clone(), 0)?
            }
        };

        let port = endpoint.local_addr().map(|a| a.port()).unwrap_or(DEFAULT_PORT);
        let discovery = Discovery::start(identity.device_id(), &settings.device_name, port);
        let history = crate::history::History::load(&data_dir_for_history);

        Ok(Arc::new(Self {
            identity,
            endpoint,
            discovery,
            trust: Mutex::new(trust),
            settings: Mutex::new(settings),
            data_dir,
            transfers: Mutex::new(HashMap::new()),
            pending_offers: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(history.next_id()),
            web: Mutex::new(WebState::default()),
            web_server: tokio::sync::Mutex::new(None),
            history,
            first_hide_done: std::sync::atomic::AtomicBool::new(false),
            manual: crate::manual::ManualPeers::load(&data_dir_for_history),
            portable,
            retrying: Mutex::new(HashSet::new()),
        }))
    }

    /// Claim the right to retry a history record, if nobody else holds it.
    ///
    /// Check-and-insert in one lock, because the retry watcher and the manual
    /// Retry button can both reach for the same record.
    pub fn try_begin_retry(&self, record_id: u64) -> bool {
        self.retrying
            .lock()
            .expect("retrying poisoned")
            .insert(record_id)
    }

    pub fn end_retry(&self, record_id: u64) {
        self.retrying
            .lock()
            .expect("retrying poisoned")
            .remove(&record_id);
    }

    /// True the first time the window is hidden rather than closed, so the app
    /// can explain itself once instead of silently persisting.
    pub fn note_first_hide(&self) -> bool {
        !self
            .first_hide_done
            .swap(true, std::sync::atomic::Ordering::Relaxed)
    }

    pub fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn add_transfer(
        &self,
        id: u64,
        direction: Direction,
        peer_name: String,
        peer_device_id: DeviceId,
        summary: String,
        progress: Arc<Progress>,
    ) {
        let mut transfers = self.transfers.lock().expect("transfers poisoned");

        // The same id means another attempt at the same transfer: keep showing
        // how far it had got, and where its files are.
        let previous = transfers.get(&id);
        let carried = previous.map(Transfer::bytes).filter(|(done, _)| *done > 0);
        let reveal = previous.and_then(|transfer| transfer.reveal.clone());
        let started_at = previous.map_or_else(unix_now, |transfer| transfer.started_at);

        transfers.insert(
            id,
            Transfer {
                direction,
                peer_name,
                peer_device_id,
                state: TransferState::Connecting,
                progress,
                summary,
                detail: None,
                started_at,
                meter: RateMeter::new(),
                carried,
                final_bytes: None,
                skipped: Vec::new(),
                reveal,
                link_bps: None,
                browser: false,
                last_moved: (Instant::now(), 0),
            },
        );
    }

    /// Mark a row as a browser upload. See [`Transfer::browser`].
    pub fn mark_browser(&self, id: u64) {
        let mut transfers = self.transfers.lock().expect("transfers poisoned");
        if let Some(transfer) = transfers.get_mut(&id) {
            transfer.browser = true;
        }
    }

    /// Show `bytes` as where this transfer had got to, until it reports its own
    /// figure. For a resume after a restart, when there is no previous row in
    /// memory to carry over from — only what history recorded.
    pub fn carry(&self, id: u64, bytes: (u64, u64)) {
        if bytes.0 == 0 {
            return;
        }
        let mut transfers = self.transfers.lock().expect("transfers poisoned");
        if let Some(transfer) = transfers.get_mut(&id)
            && transfer.carried.is_none()
        {
            transfer.carried = Some(bytes);
        }
    }

    /// How far a transfer had got, as shown — for recording in history.
    pub fn shown_bytes(&self, id: u64) -> Option<(u64, u64)> {
        self.transfers
            .lock()
            .expect("transfers poisoned")
            .get(&id)
            .map(Transfer::bytes)
    }

    /// Remember where to point Explorer for this transfer.
    pub fn set_reveal(&self, id: u64, path: PathBuf) {
        let mut transfers = self.transfers.lock().expect("transfers poisoned");
        if let Some(transfer) = transfers.get_mut(&id) {
            transfer.reveal = Some(path);
        }
    }

    /// The path to show, if there is one.
    pub fn reveal_path(&self, id: u64) -> Option<PathBuf> {
        self.transfers
            .lock()
            .expect("transfers poisoned")
            .get(&id)
            .and_then(|transfer| transfer.reveal.clone())
    }

    /// Attach what the manifest walk left out, so the row can name it.
    pub fn note_skipped(&self, id: u64, skipped: Vec<crate::views::SkippedView>) {
        let mut transfers = self.transfers.lock().expect("transfers poisoned");
        if let Some(transfer) = transfers.get_mut(&id) {
            transfer.skipped = skipped;
        }
    }

    /// Record how fast the wire to this peer is, once the session exists.
    ///
    /// Takes the address the connection actually used, which is the only
    /// trustworthy input — the peer may advertise several.
    pub fn note_link_speed(&self, id: u64, peer: std::net::SocketAddr) {
        let speed = jetstream_discovery::linkspeed::to_peer(peer);
        let mut transfers = self.transfers.lock().expect("transfers poisoned");
        if let Some(transfer) = transfers.get_mut(&id) {
            transfer.link_bps = speed;
        }
    }

    pub fn set_state(&self, id: u64, state: TransferState, detail: Option<String>) {
        let mut transfers = self.transfers.lock().expect("transfers poisoned");
        if let Some(transfer) = transfers.get_mut(&id) {
            transfer.state = state;
            if detail.is_some() {
                transfer.detail = detail;
            }
            // Quiet time counts from when it started moving, not from when the
            // row appeared — an accept prompt can sit open for minutes.
            if state == TransferState::Active {
                transfer.last_moved.0 = Instant::now();
            }
            if state.is_finished() {
                transfer.final_bytes = Some(transfer.bytes());
            }
        }
    }

    pub fn cancel_transfer(&self, id: u64) {
        let mut transfers = self.transfers.lock().expect("transfers poisoned");
        if let Some(transfer) = transfers.get_mut(&id) {
            transfer.progress.cancel.store(true, Ordering::Relaxed);

            // No engine task watches a browser upload, so nothing else would
            // move the row on. The flag makes the server refuse the phone's
            // next chunk, which tells the page.
            if transfer.browser && !transfer.state.is_finished() {
                transfer.state = TransferState::Cancelled;
                transfer.detail = Some("Stopped. Files that had finished were kept.".into());
                transfer.final_bytes = Some(transfer.bytes());
            }
        }
    }

    pub fn pause_transfer(&self, id: u64) {
        let transfers = self.transfers.lock().expect("transfers poisoned");
        if let Some(transfer) = transfers.get(&id) {
            transfer.progress.pause.store(true, Ordering::Relaxed);
        }
    }

    /// Apply the configured limit for `direction` to a new transfer.
    pub fn apply_limit(&self, progress: &Progress, direction: Direction) {
        let bytes = self
            .settings
            .lock()
            .expect("settings poisoned")
            .limit_bytes(direction);
        progress.limit.set(bytes);
    }

    /// Override one running transfer's limit, in bytes per second. 0 lifts it.
    ///
    /// Per-transfer rather than only global because the useful question is
    /// usually "slow *this* down", not "slow everything down for ever".
    pub fn set_transfer_limit(&self, id: u64, bytes_per_second: u64) {
        let transfers = self.transfers.lock().expect("transfers poisoned");
        if let Some(transfer) = transfers.get(&id) {
            transfer.progress.limit.set(bytes_per_second);
        }
    }

    /// Snapshot for the UI, newest first, sampling rates along the way.
    pub fn transfer_views(&self) -> Vec<TransferView> {
        let mut transfers = self.transfers.lock().expect("transfers poisoned");

        let mut views: Vec<TransferView> = transfers
            .iter_mut()
            .map(|(&id, transfer)| {
                transfer.sample();
                transfer.view(id)
            })
            .collect();

        views.sort_by_key(|view| std::cmp::Reverse(view.id));
        views
    }

    /// Drop finished transfers from the list.
    pub fn clear_finished(&self) {
        self.transfers
            .lock()
            .expect("transfers poisoned")
            .retain(|_, transfer| !transfer.state.is_finished());
    }

    pub fn register_offer(&self, id: u64) -> oneshot::Receiver<OfferAnswer> {
        let (sender, receiver) = oneshot::channel();
        self.pending_offers
            .lock()
            .expect("offers poisoned")
            .insert(id, sender);
        receiver
    }

    /// Deliver the user's answer. Returns false if the offer already timed out.
    pub fn answer_offer(&self, id: u64, answer: OfferAnswer) -> bool {
        let sender = self
            .pending_offers
            .lock()
            .expect("offers poisoned")
            .remove(&id);

        match sender {
            Some(sender) => sender.send(answer).is_ok(),
            None => false,
        }
    }

    // --- Browser receiver ---------------------------------------------------

    pub fn set_web_offers(&self, paths: Vec<PathBuf>) {
        self.web.lock().expect("web poisoned").offers = paths;
    }

    pub fn web_offers(&self) -> Vec<PathBuf> {
        self.web.lock().expect("web poisoned").offers.clone()
    }

    pub fn set_web_shared_text(&self, text: Option<String>) {
        self.web.lock().expect("web poisoned").shared_text = text;
    }

    pub fn web_shared_text(&self) -> Option<String> {
        self.web.lock().expect("web poisoned").shared_text.clone()
    }

    pub fn remember_web_transfer(&self, guest_id: String, id: u64) {
        self.web.lock().expect("web poisoned").in_flight.insert(guest_id, id);
    }

    pub fn take_web_transfer(&self, guest_id: &str) -> Option<u64> {
        self.web.lock().expect("web poisoned").in_flight.remove(guest_id)
    }

    pub fn forget_offer(&self, id: u64) {
        self.pending_offers
            .lock()
            .expect("offers poisoned")
            .remove(&id);
    }
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
