//! Commands the frontend can invoke.
//!
//! Each one is deliberately thin: validate, call into the engine, convert to a
//! view type. Anything long-running spawns a task and reports back through
//! events, so a click never blocks the window.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use jetstream_core::manifest::Manifest;
use jetstream_core::transfer::{self, Progress};
use tauri::{AppHandle, Emitter, State};

use crate::state::{AppState, OfferAnswer, parse_conflict};
use crate::views::*;

type Reply<T> = Result<T, String>;

/// How long a transfer waits for the user to answer the accept dialog.
///
/// Generous — the user may be away from the machine — but finite, so a sender
/// eventually gets a clear rejection instead of hanging forever.
const OFFER_TIMEOUT: Duration = Duration::from_secs(180);

/// Refusal for the two settings that record this executable's path on the host.
///
/// Both would survive the portable copy being unplugged: a Run entry pointing at
/// a vanished drive, and a dead Send to shortcut. The user would be somewhere
/// else by the time either failed, so this refuses rather than warns.
const PORTABLE_LEAVES_TRACES: &str = "This is a portable copy, so it will not \
    write to this computer outside its own folder. Install Jetstream here to use \
    this setting.";

#[tauri::command]
pub fn get_self(state: State<'_, Arc<AppState>>) -> SelfView {
    let id = state.identity.device_id();
    let settings = state.settings.lock().expect("settings poisoned");

    SelfView {
        name: settings.device_name.clone(),
        device_id: id.to_hex(),
        fingerprint: id.fingerprint(),
        fingerprint_words: id.fingerprint_words().iter().map(|w| w.to_string()).collect(),
        port: state.endpoint.local_addr().map(|a| a.port()).unwrap_or(0),
        download_dir: settings.download_dir.display().to_string(),
        portable: state.portable,
        addresses: {
            let mut addresses: Vec<_> = jetstream_discovery::broadcast::announce_sources()
                .into_iter()
                .map(|source| source.address)
                .collect();
            // Self-assigned addresses last: they rarely reach anything.
            addresses.sort_by_key(|address| (address.is_link_local(), *address));
            addresses.iter().map(ToString::to_string).collect()
        },
    }
}

#[tauri::command]
pub fn list_peers(state: State<'_, Arc<AppState>>) -> Vec<PeerView> {
    let trust = state.trust.lock().expect("trust poisoned");

    state
        .discovery
        .peers()
        .iter()
        .map(|peer| {
            let view = TrustView::of(
                trust.level_for(&peer.device_id),
                trust.is_known(&peer.device_id),
            );
            PeerView::from_discovered(peer, view)
        })
        .collect()
}

#[tauri::command]
pub fn list_trusted(state: State<'_, Arc<AppState>>) -> Vec<TrustedView> {
    let online: std::collections::HashSet<_> = state
        .discovery
        .peers()
        .into_iter()
        .map(|peer| peer.device_id)
        .collect();

    state
        .trust
        .lock()
        .expect("trust poisoned")
        .devices()
        .iter()
        .map(|device| TrustedView::new(device, online.contains(&device.device_id)))
        .collect()
}

#[tauri::command]
pub fn set_trust(
    state: State<'_, Arc<AppState>>,
    device_id: String,
    name: String,
    trust: TrustView,
) -> Reply<()> {
    let id = device_id_of(&device_id)?;
    state
        .trust
        .lock()
        .expect("trust poisoned")
        .set_level(id, &name, trust.to_level())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn forget_device(state: State<'_, Arc<AppState>>, device_id: String) -> Reply<bool> {
    let id = device_id_of(&device_id)?;
    state
        .trust
        .lock()
        .expect("trust poisoned")
        .forget(&id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn list_transfers(state: State<'_, Arc<AppState>>) -> Vec<TransferView> {
    state.transfer_views()
}

#[tauri::command]
pub fn cancel_transfer(state: State<'_, Arc<AppState>>, id: u64) {
    state.cancel_transfer(id);
}

/// Stop a running transfer, keeping its place so it can be continued.
///
/// Stops at the next chunk boundary rather than instantly: a chunk is at most
/// 1 MiB, so the wait is imperceptible, and stopping mid-chunk would throw away
/// work that is already on the wire.
#[tauri::command]
pub fn pause_transfer(state: State<'_, Arc<AppState>>, id: u64) {
    state.pause_transfer(id);
}

/// Open this transfer's files in Explorer, with the item selected.
///
/// Selecting the item rather than merely opening the folder is the whole value:
/// a destination holding 128,000 files, opened with nothing highlighted, leaves
/// the user exactly where they started.
#[tauri::command]
pub fn reveal_transfer(app: AppHandle, state: State<'_, Arc<AppState>>, id: u64) -> Reply<()> {
    use tauri_plugin_opener::OpenerExt;

    let path = state
        .reveal_path(id)
        .ok_or("There is nowhere to open for this transfer.")?;

    // The recorded path may be gone — deleted, or on a drive now unplugged. Fall
    // back to the nearest ancestor that still exists rather than failing, so the
    // click does something useful instead of nothing.
    let target = if path.exists() {
        path
    } else {
        path.ancestors()
            .find(|candidate| candidate.exists())
            .map(|candidate| candidate.to_path_buf())
            .ok_or("That location no longer exists.")?
    };

    app.opener()
        .reveal_item_in_dir(&target)
        .map_err(|e| format!("Could not open {}: {e}", target.display()))
}

/// Limit one running transfer, in kilobytes per second. 0 lifts the limit.
#[tauri::command]
pub fn set_transfer_limit(state: State<'_, Arc<AppState>>, id: u64, kbps: u64) {
    state.set_transfer_limit(id, kbps.saturating_mul(1000));
}

#[tauri::command]
pub fn clear_finished(state: State<'_, Arc<AppState>>) {
    state.clear_finished();
}

#[tauri::command]
pub fn get_settings(state: State<'_, Arc<AppState>>) -> SettingsView {
    state.settings.lock().expect("settings poisoned").to_view()
}

/// Save preferences.
///
/// A new device name takes effect at once: the next announcement and the next
/// handshake carry it. It used to wait for a restart.
#[tauri::command]
pub fn save_settings(state: State<'_, Arc<AppState>>, settings: SettingsView) -> Reply<bool> {
    let download_dir = PathBuf::from(&settings.download_dir);
    if download_dir.as_os_str().is_empty() {
        return Err("Choose a folder for received files.".into());
    }
    std::fs::create_dir_all(&download_dir)
        .map_err(|e| format!("Cannot use {}: {e}", download_dir.display()))?;

    let mut current = state.settings.lock().expect("settings poisoned");
    let name = jetstream_core::proto::sanitize_name(&settings.device_name);
    let name_changed = current.device_name != name;

    current.device_name = name;
    current.download_dir = download_dir;
    current.on_conflict = parse_conflict(&settings.on_conflict);
    // These were shown, edited, and silently thrown away: the form sent them and
    // nothing here kept them.
    current.send_limit_kbps = settings.send_limit_kbps;
    current.receive_limit_kbps = settings.receive_limit_kbps;
    current.save(&state.data_dir).map_err(|e| e.to_string())?;

    if name_changed {
        state.endpoint.rename(&current.device_name);
        state.discovery.rename(&current.device_name);
    }

    Ok(name_changed)
}

#[tauri::command]
pub async fn run_diagnostics(state: State<'_, Arc<AppState>>) -> Reply<DiagnosticsView> {
    let identity = Arc::clone(&state.identity);
    let probe = jetstream_discovery::diagnostics::probe_inbound(identity).await;
    let report = state.discovery.diagnose();
    let firewall = FirewallView::check();

    let mut findings = Vec::new();

    // The firewall rule leads, because it is the one check that is a direct
    // observation about *our* reachability rather than an inference, and the
    // only one with a button attached.
    findings.push(FindingView {
        severity: if firewall.allowed {
            "ok"
        } else if firewall.state == "unknown" || firewall.state == "unsupported" {
            "note"
        } else {
            "problem"
        }
        .to_string(),
        summary: firewall.summary.clone(),
        remedy: firewall.remedy.clone(),
    });

    findings.push(finding_view(&probe));
    findings.extend(report.sorted().into_iter().map(finding_view));
    findings.sort_by_key(|finding| std::cmp::Reverse(severity_rank(&finding.severity)));

    Ok(DiagnosticsView {
        has_problems: findings.iter().any(|f| f.severity == "problem"),
        findings,
        firewall,
    })
}

fn finding_view(finding: &jetstream_discovery::diagnostics::Finding) -> FindingView {
    use jetstream_discovery::diagnostics::Severity;

    FindingView {
        severity: match finding.severity {
            Severity::Ok => "ok",
            Severity::Note => "note",
            Severity::Problem => "problem",
        }
        .to_string(),
        summary: finding.summary.clone(),
        remedy: finding.remedy.clone(),
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "problem" => 2,
        "note" => 1,
        _ => 0,
    }
}

/// Whether other devices can reach this one, and whether we can fix it.
#[tauri::command]
pub fn firewall_status() -> FirewallView {
    FirewallView::check()
}

/// Ask Windows for permission to accept inbound connections.
///
/// Triggers a UAC prompt. Returns the status *after* the attempt rather than a
/// bare success flag, because the user can decline the prompt and the elevated
/// helper can still fail — the only trustworthy answer is to look again.
#[tauri::command]
pub async fn allow_through_firewall() -> Reply<FirewallView> {
    use jetstream_discovery::firewall;

    let exe = firewall::current_exe()?;

    if firewall::is_elevated() {
        // Already administrator: no prompt needed.
        firewall::install(&exe)?;
        return Ok(FirewallView::check());
    }

    firewall::request_elevation(&exe, firewall::INSTALL_ARG)?;

    // The helper runs asynchronously, so poll rather than guess. Windows also
    // needs a moment to publish a new rule after the helper exits. It adds both
    // rules, so wait for both.
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let status = FirewallView::check();
        if status.allowed && status.browser_allowed {
            return Ok(status);
        }
    }

    Ok(FirewallView::check())
}

/// Which connected networks are Public, and which of those we can fix.
#[tauri::command]
pub fn network_profile_status() -> NetworkProfileView {
    NetworkProfileView::check()
}

/// Move unidentified networks from Public to Private.
///
/// Only ever touches networks with no internet connectivity — see
/// [`jetstream_discovery::netprofile`] for why that restriction is the whole
/// safety argument rather than a detail.
#[tauri::command]
pub async fn make_network_private() -> Reply<NetworkProfileView> {
    use jetstream_discovery::{firewall, netprofile};

    if netprofile::status()?.fixable.is_empty() {
        return Ok(NetworkProfileView::check());
    }

    if firewall::is_elevated() {
        netprofile::set_private()?;
        return Ok(NetworkProfileView::check());
    }

    let exe = firewall::current_exe()?;
    firewall::request_elevation(&exe, netprofile::SET_PRIVATE_ARG)?;

    // Poll for the same reason as the firewall: the user can decline, and
    // Windows takes a moment to republish the category.
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let status = NetworkProfileView::check();
        if !status.needs_fixing {
            return Ok(status);
        }
    }

    Ok(NetworkProfileView::check())
}

// ---------------------------------------------------------------------------
// Browser receiver
// ---------------------------------------------------------------------------

/// Turn the browser receiver on and mint a pairing code.
///
/// Off until asked for, deliberately: it is an unencrypted HTTP server, and one
/// that is only running while a panel is open is a much smaller thing to reason
/// about than one that is always listening.
///
/// `address` picks which of this machine's networks the code points at, for a
/// machine on more than one — the phone has to be on the same one.
#[tauri::command]
pub async fn start_web(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    address: Option<String>,
) -> Reply<WebStatusView> {
    let inner = Arc::clone(&state);

    let mut slot = inner.web_server.lock().await;
    if slot.is_none() {
        let server = crate::web::start(app, Arc::clone(&inner))
            .await
            .map_err(|e| e.to_string())?;
        *slot = Some(server);
    }

    let server = slot.as_ref().expect("just started");
    // Only an address the server actually offers; anything else falls back to
    // the default rather than minting a code for somewhere unreachable.
    let chosen = address
        .and_then(|text| text.parse::<std::net::IpAddr>().ok())
        .filter(|ip| server.addresses().iter().any(|address| address.ip == *ip));
    let code = match chosen {
        Some(ip) => server.pairing_code_for(ip),
        None => server.pairing_code(),
    };

    Ok(WebStatusView::running(server, Some(&code)))
}

/// Stop the browser receiver and drop every session.
#[tauri::command]
pub async fn stop_web(state: State<'_, Arc<AppState>>) -> Reply<WebStatusView> {
    if let Some(server) = state.web_server.lock().await.take() {
        server.stop().await;
    }
    state.set_web_offers(Vec::new());
    state.set_web_shared_text(None);

    Ok(WebStatusView::stopped())
}

#[tauri::command]
pub async fn web_status(state: State<'_, Arc<AppState>>) -> Reply<WebStatusView> {
    // Tauri requires an async command that borrows managed state to return a
    // `Result`, so this reports infallibly inside an `Ok`.
    Ok(match state.web_server.lock().await.as_ref() {
        Some(server) => WebStatusView::running(server, None),
        None => WebStatusView::stopped(),
    })
}

/// Choose what browsers may download, and any text to share with them.
#[tauri::command]
pub fn set_web_shared(
    state: State<'_, Arc<AppState>>,
    paths: Vec<String>,
    text: Option<String>,
) {
    state.set_web_offers(crate::web::offered_paths(paths));
    state.set_web_shared_text(text.filter(|t| !t.trim().is_empty()));
}

/// Answer a pending accept prompt.
#[tauri::command]
pub fn respond_to_offer(
    state: State<'_, Arc<AppState>>,
    id: u64,
    accept: bool,
    remember: Option<TrustView>,
) -> bool {
    state.answer_offer(
        id,
        OfferAnswer {
            accept,
            remember: remember.map(TrustView::to_level),
        },
    )
}

/// Send files or folders to a peer.
///
/// Returns as soon as the transfer is registered; everything after that is
/// reported through the `transfers` event.
#[tauri::command]
pub async fn send_to_peer(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    device_id: String,
    paths: Vec<String>,
) -> Reply<u64> {
    let target = device_id_of(&device_id)?;
    start_send(app, state.inner(), target, paths, None).await
}

/// Releases a retry claim however the attempt ends.
///
/// A guard rather than explicit calls because the claim has to survive into the
/// spawned task and be released on every path out of it — including the early
/// returns before the spawn. Missing one leaks the claim, and a leaked claim
/// means that transfer can never auto-resume again.
struct RetryClaim {
    state: Arc<AppState>,
    record_id: u64,
}

impl Drop for RetryClaim {
    fn drop(&mut self) {
        self.state.end_retry(self.record_id);
    }
}

/// Start a send, optionally as the continuation of an interrupted one.
///
/// When `retry_of` is set, the transfer **reuses that id**. One logical transfer
/// therefore keeps one row in the UI and one row in history across every attempt,
/// instead of spawning a fresh pair each time and appearing to start over.
async fn start_send(
    app: AppHandle,
    state: &Arc<AppState>,
    target: jetstream_core::DeviceId,
    paths: Vec<String>,
    retry_of: Option<u64>,
) -> Reply<u64> {
    if paths.is_empty() {
        return Err("Nothing to send.".into());
    }

    // Claimed before the manifest walk, not after: on a 100,000-file tree that
    // walk alone can outlast the retry poll interval, which is exactly how
    // duplicate attempts got started.
    let claim = match retry_of {
        Some(record_id) => {
            if !state.try_begin_retry(record_id) {
                return Err("That transfer is already resuming.".into());
            }
            Some(RetryClaim {
                state: Arc::clone(state),
                record_id,
            })
        }
        None => None,
    };

    let (peer_name, mut addresses) = reach(state, &target)?;

    let sources: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
    let root = common_root(&sources)?;

    // Built from `stat` alone, so this stays fast even on a huge folder.
    let (manifest, report) = Manifest::from_paths(&sources).map_err(|e| e.to_string())?;
    if manifest.entries.is_empty() {
        return Err("Those paths contain nothing that can be sent.".into());
    }

    let summary = transfer::describe(&manifest.summary());
    let summary_for_history = summary.clone();
    let total_bytes = manifest.total_bytes();
    let digest = hex::encode(manifest.digest());
    let detail = (!report.is_clean())
        .then(|| format!("{} item(s) skipped", report.skipped_count()));

    // A retry continues the same transfer, so it keeps the same id and replaces
    // its row rather than adding another.
    let id = retry_of.unwrap_or_else(|| state.next_id());
    let progress = Arc::new(Progress::default());
    state.apply_limit(&progress, Direction::Sending);
    state.add_transfer(
        id,
        Direction::Sending,
        peer_name.clone(),
        target,
        summary,
        Arc::clone(&progress),
    );
    // After a restart there is no earlier row to carry progress over from, but
    // history knows how far it got.
    if let Some(record) = retry_of.and_then(|id| state.history.get(id)) {
        state.carry(id, (record.transferred, record.bytes));
    }
    // What the user picked, so a finished send can show them what it sent.
    if let Some(first) = sources.first() {
        state.set_reveal(id, first.clone());
    }

    if detail.is_some() {
        state.set_state(id, TransferState::Connecting, detail);

        // The paths, not just the count. Truncated because a folder full of
        // symlinks would otherwise fill the window.
        let skipped: Vec<_> = report
            .skipped()
            .into_iter()
            .take(crate::views::MAX_SKIPPED_SHOWN)
            .map(|(path, reason)| crate::views::SkippedView {
                path: path.display().to_string(),
                reason,
            })
            .collect();
        state.note_skipped(id, skipped);
    }

    let inner = Arc::clone(state);
    tauri::async_runtime::spawn(async move {
        // Held for the life of the attempt; dropping it re-arms auto-resume.
        let _claim = claim;
        // Reachability decided the order; now prefer the fastest wire among the
        // ones that would work. A user who plugs in a gigabit cable while Wi-Fi
        // is still connected means to use the cable.
        jetstream_discovery::linkspeed::prefer_fast_links(&mut addresses);

        // Pin the identity discovery reported: a device that answers with a
        // different key is not the one the user clicked on.
        let session = match inner
            .endpoint
            .connect_any(&addresses, Some(target), Duration::from_secs(5))
            .await
        {
            Ok(session) => session,
            Err(e) => {
                // For a resume, not answering is the expected way to fail — the
                // other device is still away — and it will be tried again.
                let (state_after, detail) = if retry_of.is_some() {
                    (
                        TransferState::Interrupted,
                        format!("Could not reach {peer_name} yet — will try again when it is back."),
                    )
                } else {
                    (TransferState::Failed, e.to_string())
                };
                inner.set_state(id, state_after, Some(detail));
                let _ = app.emit("transfers", inner.transfer_views());
                return;
            }
        };

        {
            let mut trust = inner.trust.lock().expect("trust poisoned");
            let _ = trust.touch(
                &target,
                &session.peer().name,
                Some(session.peer().remote_address.to_string()),
            );
        }

        // The address the connection actually used, not one of several advertised.
        inner.note_link_speed(id, session.peer().remote_address);

        inner.set_state(id, TransferState::Waiting, None);
        let _ = app.emit("transfers", inner.transfer_views());

        let result = transfer::send(&session, &root, &manifest, Arc::clone(&progress)).await;

        let name = &peer_name;
        let (state_after, outcome, detail) = match &result {
            Ok(()) => (TransferState::Done, crate::history::Outcome::Completed, None),
            // The user stopped it. Neither of these may be recorded as
            // `Interrupted`, or the retry watcher would undo the user's decision.
            Err(jetstream_core::Error::Paused) => (
                TransferState::Paused,
                crate::history::Outcome::Paused,
                Some("Paused. Continue it whenever you like — nothing already sent will be sent again.".into()),
            ),
            Err(jetstream_core::Error::Cancelled) => (
                TransferState::Cancelled,
                crate::history::Outcome::Cancelled,
                Some(format!(
                    "Cancelled. What already reached {name} is kept there, so sending it again carries on from that point."
                )),
            ),
            Err(jetstream_core::Error::Rejected(reason)) => (
                TransferState::Rejected,
                crate::history::Outcome::Declined,
                Some(reason.clone()),
            ),
            // The other person stopped it. Not a decline — they had accepted —
            // and not something to retry behind their back.
            Err(jetstream_core::Error::CancelledByPeer) => (
                TransferState::Cancelled,
                crate::history::Outcome::Cancelled,
                Some(format!(
                    "{name} stopped receiving. Send it again to carry on — what already arrived is kept."
                )),
            ),
            Err(jetstream_core::Error::PausedByPeer) => (
                TransferState::Paused,
                crate::history::Outcome::Paused,
                Some(format!("{name} paused this. Continue it when they are ready.")),
            ),
            Err(e) => (
                TransferState::Interrupted,
                crate::history::Outcome::Interrupted,
                // Retried automatically when the peer reappears, so the message
                // says what will happen rather than what the user must do.
                Some(format!("{e} — will resume when {name} is back")),
            ),
        };

        inner.set_state(id, state_after, detail.clone());
        let transferred = inner.shown_bytes(id).map_or(0, |(done, _)| done);
        // Same id as the transfer, so a retry updates its own record instead of
        // creating a sibling that also wants retrying. `record` preserves the
        // attempt count, so the cap keeps working across attempts.
        inner.history.record(crate::history::Record {
            id,
            peer_device_id: target.to_hex(),
            peer_name: name.clone(),
            sources: sources.clone(),
            sending: true,
            summary: summary_for_history.clone(),
            bytes: total_bytes,
            outcome,
            at: crate::history::unix_now(),
            attempts: 0,
            detail,
            digest: Some(digest),
            destination: None,
            transferred,
        });
        // Getting somewhere is what separates a flaky link from a dead transfer.
        if progress.bytes_moved.load(std::sync::atomic::Ordering::Relaxed) > 0 {
            inner.history.note_progress(id);
        }

        match state_after {
            TransferState::Done => crate::tray::notify(
                &app,
                "Sent",
                &format!("{summary_for_history} reached {name}."),
            ),
            TransferState::Interrupted => crate::tray::notify(
                &app,
                "Transfer interrupted",
                &format!("The send to {name} stopped. It will resume by itself when {name} is back."),
            ),
            _ => {}
        }

        session.close("done").await;
        let _ = app.emit("transfers", inner.transfer_views());
        let _ = app.emit("history-changed", ());
    });

    Ok(id)
}

/// The name to show for a device and the addresses to try, best first.
///
/// Discovery if it currently sees the device. Otherwise the address it was last
/// reached at — which is what lets a send or a resume work across a VPN such as
/// Radmin or Tailscale, where broadcasts and mDNS often do not travel at all.
fn reach(
    state: &AppState,
    target: &jetstream_core::DeviceId,
) -> Reply<(String, Vec<std::net::SocketAddr>)> {
    if let Some(peer) = state.discovery.registry().get(target) {
        return Ok((peer.name.clone(), peer.addresses_by_preference()));
    }

    let trust = state.trust.lock().expect("trust poisoned");
    let known = trust
        .get(target)
        .ok_or("That device is not on the network right now.")?;
    let address = known
        .last_address
        .as_deref()
        .and_then(|address| address.parse().ok())
        .ok_or("That device is not on the network right now, and there is no address to try.")?;

    Ok((known.name.clone(), vec![address]))
}

/// All sources in one transfer must share a parent, because the manifest makes
/// each relative to its own.
fn common_root(sources: &[PathBuf]) -> Reply<PathBuf> {
    let mut parents = sources.iter().filter_map(|p| p.parent());
    let first = parents.next().ok_or("Nothing to send.")?.to_path_buf();

    for parent in parents {
        if parent != first {
            return Err(
                "Everything in one transfer has to come from the same folder. \
                 Send them as separate transfers, or send the folder that contains them."
                    .into(),
            );
        }
    }
    Ok(first)
}

// ---------------------------------------------------------------------------
// Devices added by address
// ---------------------------------------------------------------------------

/// How long to wait for a device typed in by address to answer.
const ADD_TIMEOUT: Duration = Duration::from_secs(6);

/// How often devices that discovery cannot see are checked.
///
/// Inside discovery's own expiry, so a device that keeps answering never drops
/// out of the list between checks.
const PROBE_EVERY: Duration = Duration::from_secs(20);

/// How long one check may take before the device counts as away.
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);

/// Find a device at an address and add it to the list.
///
/// For networks discovery cannot see across — a VPN such as Radmin or
/// Tailscale, or another subnet. Takes an IP address or host name, with or
/// without a port.
#[tauri::command]
pub async fn add_device_by_address(
    state: State<'_, Arc<AppState>>,
    address: String,
) -> Reply<PeerView> {
    let target = resolve_address(&address).await?;

    // No pin: this is first contact. The fingerprint is shown on the tile and
    // in the other side's prompt, exactly as for a discovered device.
    let session = tokio::time::timeout(ADD_TIMEOUT, state.endpoint.connect(target, None))
        .await
        .map_err(|_| {
            format!(
                "Nothing answered at {target}. Check the address, that Jetstream is running \
                 there, and that its firewall lets Jetstream through."
            )
        })?
        .map_err(|e| e.to_string())?;
    let peer = session.peer().clone();
    session.close("added by address").await;

    if peer.device_id == state.identity.device_id() {
        return Err("That address is this computer.".into());
    }

    state
        .discovery
        .note_reachable(peer.device_id, peer.name.clone(), peer.remote_address, false);
    state.manual.add(crate::manual::ManualPeer {
        device_id: peer.device_id.to_hex(),
        name: peer.name.clone(),
        address: peer.remote_address.to_string(),
    });

    let discovered = state
        .discovery
        .registry()
        .get(&peer.device_id)
        .ok_or("The device answered, but could not be added to the list.")?;
    let trust = state.trust.lock().expect("trust poisoned");
    Ok(PeerView::from_discovered(
        &discovered,
        TrustView::of(trust.level_for(&peer.device_id), trust.is_known(&peer.device_id)),
    ))
}

#[tauri::command]
pub fn list_manual_devices(state: State<'_, Arc<AppState>>) -> Vec<crate::manual::ManualPeer> {
    state.manual.all()
}

#[tauri::command]
pub fn forget_manual_device(state: State<'_, Arc<AppState>>, device_id: String) {
    state.manual.forget(&device_id);
}

/// Turn what a person typed into an address to dial.
async fn resolve_address(text: &str) -> Reply<std::net::SocketAddr> {
    use std::net::{IpAddr, SocketAddr};

    let text = text.trim();
    if text.is_empty() {
        return Err("Type the other device's address, such as 192.168.1.20.".into());
    }
    if let Ok(address) = text.parse::<SocketAddr>() {
        return Ok(address);
    }
    if let Ok(ip) = text.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, jetstream_core::DEFAULT_PORT));
    }

    // A host name, possibly with a port.
    let with_port = if text.rsplit_once(':').is_some_and(|(_, port)| port.parse::<u16>().is_ok()) {
        text.to_string()
    } else {
        format!("{text}:{}", jetstream_core::DEFAULT_PORT)
    };
    let mut found: Vec<SocketAddr> = tokio::net::lookup_host(&with_port)
        .await
        .map_err(|e| format!("Could not find {text}: {e}"))?
        .collect();
    // IPv4 first: it is what nearly every LAN and VPN actually routes.
    found.sort_by_key(|address| !address.is_ipv4());
    found
        .into_iter()
        .next()
        .ok_or_else(|| format!("{text} has no address."))
}

/// Keep devices discovery cannot see in the list while they answer.
///
/// Two kinds: those added by address, and paired devices with a transfer
/// waiting to resume, at the address they were last reached on. The second is
/// what makes resume work across a VPN without anyone adding anything — the
/// retry watcher only acts on a device it can see.
pub async fn keep_reachable(state: Arc<AppState>) {
    loop {
        tokio::time::sleep(PROBE_EVERY).await;

        let mut targets: Vec<(jetstream_core::DeviceId, String, std::net::SocketAddr, bool)> = state
            .manual
            .all()
            .into_iter()
            .filter_map(|peer| {
                Some((peer.device_id.parse().ok()?, peer.name, peer.address.parse().ok()?, false))
            })
            .collect();

        let present: std::collections::HashSet<_> = state
            .discovery
            .peers()
            .into_iter()
            .map(|peer| peer.device_id)
            .collect();
        {
            let trust = state.trust.lock().expect("trust poisoned");
            for device in state.history.awaiting_retry().into_keys() {
                if present.contains(&device) || targets.iter().any(|(id, ..)| *id == device) {
                    continue;
                }
                if let Some(known) = trust.get(&device)
                    && let Some(address) = known.last_address.as_deref().and_then(|a| a.parse().ok())
                {
                    targets.push((device, known.name.clone(), address, true));
                }
            }
        }

        let checks = targets.into_iter().map(|(device, name, address, saved)| {
            let state = Arc::clone(&state);
            async move {
                match tokio::time::timeout(PROBE_TIMEOUT, state.endpoint.probe(address, device)).await {
                    Ok(Ok(())) => state.discovery.note_reachable(device, name, address, saved),
                    Ok(Err(e)) => tracing::debug!(%address, error = %e, "device did not answer"),
                    Err(_) => tracing::debug!(%address, "device did not answer in time"),
                }
            }
        });
        futures_util::future::join_all(checks).await;
    }
}

// ---------------------------------------------------------------------------
// History and automatic resume
// ---------------------------------------------------------------------------

/// How often to look for a peer that owes us a retry.
const RETRY_POLL: Duration = Duration::from_secs(10);

/// Minimum wait between attempts at the same transfer.
///
/// Backs off so a peer that is reachable but consistently failing — declining,
/// out of disk — is not hammered.
const RETRY_BACKOFF: Duration = Duration::from_secs(30);

#[tauri::command]
pub fn list_history(state: State<'_, Arc<AppState>>) -> Vec<HistoryView> {
    state
        .history
        .all()
        .iter()
        .map(HistoryView::new)
        .collect()
}

#[tauri::command]
pub fn forget_history(state: State<'_, Arc<AppState>>, id: u64) {
    state.history.forget(id);
}

#[tauri::command]
pub fn clear_history(state: State<'_, Arc<AppState>>) {
    state.history.clear_finished();
}

/// Retry a remembered transfer now, without waiting for the watcher.
#[tauri::command]
pub async fn retry_transfer(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    id: u64,
) -> Reply<u64> {
    let record = state
        .history
        .all()
        .into_iter()
        .find(|r| r.id == id)
        .ok_or("That transfer is no longer in the history.")?;

    if !record.sending || record.sources.is_empty() {
        return Err("Only sends can be retried — the other device owns what it sent you.".into());
    }

    let paths = record
        .sources
        .iter()
        .map(|p| p.display().to_string())
        .collect();

    let device_id = record
        .device()
        .ok_or("That record's device id is unreadable.")?;

    // Continues the same record, and shares the watcher's in-flight claim — so
    // pressing Retry while an automatic attempt is running says so rather than
    // starting a second one.
    start_send(app, state.inner(), device_id, paths, Some(record.id)).await
}

/// Watch for peers that owe us a resume, and retry when they appear.
///
/// This is what turns "sending again will resume" from advice into behaviour.
/// The receiver still holds every staged chunk, so a retry moves only what was
/// actually missing.
pub async fn watch_for_retries(app: AppHandle, state: Arc<AppState>) {
    let mut last_attempt: std::collections::HashMap<u64, std::time::Instant> =
        std::collections::HashMap::new();

    loop {
        tokio::time::sleep(RETRY_POLL).await;

        let waiting = state.history.awaiting_retry();
        if waiting.is_empty() {
            continue;
        }

        // Only peers actually on the network right now.
        let present: std::collections::HashSet<_> = state
            .discovery
            .peers()
            .into_iter()
            .map(|peer| peer.device_id)
            .collect();

        for (device, records) in waiting {
            if !present.contains(&device) {
                continue;
            }

            for record in records {
                if last_attempt
                    .get(&record.id)
                    .is_some_and(|at| at.elapsed() < RETRY_BACKOFF)
                {
                    continue;
                }

                // A source that has been deleted or moved can never succeed, so
                // stop rather than burn attempts on it.
                if let Some(missing) = record.sources.iter().find(|p| !p.exists()) {
                    state.history.stop_retrying(
                        record.id,
                        crate::history::Outcome::Failed,
                        Some(format!("{} is no longer there", missing.display())),
                    );
                    continue;
                }

                last_attempt.insert(record.id, std::time::Instant::now());
                state.history.note_attempt(record.id);

                tracing::info!(
                    peer = %record.peer_name,
                    attempt = record.attempts + 1,
                    "resuming an interrupted transfer"
                );

                let paths = record
                    .sources
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect();

                // Continues the existing record rather than creating a new one,
                // and refuses to start if this record is already resuming.
                let Some(device_id) = record.device() else {
                    continue;
                };

                if let Err(e) =
                    start_send(app.clone(), &state, device_id, paths, Some(record.id)).await
                {
                    tracing::debug!(error = %e, "retry could not start");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Shell integration and startup
// ---------------------------------------------------------------------------

/// Whether the Explorer "Send to" entry is installed.
#[tauri::command]
pub fn send_to_status() -> bool {
    crate::sendto::is_installed()
}

/// Add or remove the "Send to" entry.
///
/// Per-user, so no administrator rights are needed — unlike the firewall rule,
/// this never prompts.
#[tauri::command]
pub fn set_send_to(state: State<'_, Arc<AppState>>, enabled: bool) -> Reply<bool> {
    if enabled {
        if state.portable {
            return Err(PORTABLE_LEAVES_TRACES.into());
        }
        crate::sendto::install()?;
    } else {
        crate::sendto::uninstall()?;
    }
    Ok(crate::sendto::is_installed())
}

/// Whether Jetstream starts with Windows.
#[tauri::command]
pub fn autostart_status(app: AppHandle) -> bool {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().is_enabled().unwrap_or(false)
}

/// Turn start-with-Windows on or off.
///
/// Worth offering prominently: a transfer app that is not running cannot
/// receive, and "it only works when I remember to open it" is the difference
/// between useful and abandoned.
#[tauri::command]
pub fn set_autostart(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    enabled: bool,
) -> Reply<bool> {
    use tauri_plugin_autostart::ManagerExt;

    let launcher = app.autolaunch();
    if enabled {
        if state.portable {
            return Err(PORTABLE_LEAVES_TRACES.into());
        }
        launcher.enable().map_err(|e| e.to_string())?;
    } else {
        launcher.disable().map_err(|e| e.to_string())?;
    }
    Ok(launcher.is_enabled().unwrap_or(false))
}

/// Receive loop: accept sessions and run the offer flow for each.
pub async fn serve_incoming(app: AppHandle, state: Arc<AppState>) {
    while let Some(accepted) = state.endpoint.accept().await {
        let session = match accepted {
            Ok(session) => session,
            Err(e) => {
                tracing::debug!(error = %e, "inbound connection rejected");
                continue;
            }
        };

        let app = app.clone();
        let state = Arc::clone(&state);
        tauri::async_runtime::spawn(async move {
            handle_incoming(app, state, session).await;
        });
    }
}

async fn handle_incoming(
    app: AppHandle,
    state: Arc<AppState>,
    session: Arc<jetstream_core::transport::Session>,
) {
    let peer = session.peer().clone();

    // Blocked devices are refused before the user is ever interrupted — that is
    // the entire point of blocking.
    let (level, known) = {
        let trust = state.trust.lock().expect("trust poisoned");
        (trust.level_for(&peer.device_id), trust.is_known(&peer.device_id))
    };
    if level.is_blocked() {
        tracing::info!(peer = %peer.name, "refused an offer from a blocked device");
        session.close("blocked").await;
        return;
    }

    let progress = Arc::new(Progress::default());
    state.apply_limit(&progress, Direction::Receiving);

    // Filled in once the offer says what this is. Nothing is added to the list
    // before then, so a connection that never offers anything — a reachability
    // probe, a peer that hangs up at once — leaves no stray row behind.
    let assigned: Arc<std::sync::Mutex<Option<Incoming>>> = Arc::default();

    let decide = {
        let app = app.clone();
        let state = Arc::clone(&state);
        let peer = peer.clone();
        let progress = Arc::clone(&progress);
        let assigned = Arc::clone(&assigned);
        let session = Arc::clone(&session);

        async move |offer: jetstream_core::proto::Offer| {
            let digest = hex::encode(offer.digest);
            let summary = transfer::describe(&offer.summary);

            // The same device offering exactly the same files is the transfer
            // already in the list, picking up where it stopped — not a new one.
            // It keeps its row, its history entry, and its folder.
            let earlier = state
                .history
                .unfinished_receive(&peer.device_id.to_hex(), &digest);
            let id = earlier.as_ref().map_or_else(|| state.next_id(), |record| record.id);

            let (download_dir, conflict) = {
                let settings = state.settings.lock().expect("settings poisoned");
                (settings.download_dir.clone(), settings.on_conflict)
            };
            // The partial data is wherever the first attempt put it, which is not
            // necessarily the folder the settings name today.
            let destination = earlier
                .as_ref()
                .and_then(|record| record.destination.clone())
                .filter(|folder| folder.is_dir())
                .unwrap_or(download_dir);

            state.add_transfer(
                id,
                Direction::Receiving,
                peer.name.clone(),
                peer.device_id,
                summary.clone(),
                Arc::clone(&progress),
            );
            if let Some(record) = &earlier {
                state.carry(id, (record.transferred, record.bytes));
            }
            state.note_link_speed(id, peer.remote_address);
            *assigned.lock().expect("assigned poisoned") = Some(Incoming {
                id,
                summary: summary.clone(),
                digest,
                total: offer.summary.total_bytes,
                destination: destination.clone(),
                withdrawn: false,
            });

            let accept = transfer::Decision::Accept {
                destination,
                conflict,
            };

            // Already said yes to exactly this, and it was interrupted rather
            // than stopped: asking again would be asking the same question twice.
            if earlier
                .as_ref()
                .is_some_and(|record| record.continues_without_asking(crate::history::unix_now()))
            {
                let _ = app.emit("notice", format!("Continuing {summary} from {}", peer.name));
                return accept;
            }
            if level.accepts_silently() {
                return accept;
            }

            state.set_state(id, TransferState::Waiting, None);
            let _ = app.emit("transfers", state.transfer_views());

            let view = OfferView {
                id,
                peer_name: peer.name.clone(),
                peer_device_id: peer.device_id.to_hex(),
                fingerprint: peer.device_id.fingerprint(),
                fingerprint_words: peer
                    .device_id
                    .fingerprint_words()
                    .iter()
                    .map(|w| w.to_string())
                    .collect(),
                first_contact: !known,
                summary,
                file_count: offer.summary.file_count,
                total_bytes: offer.summary.total_bytes,
                top_level: offer
                    .summary
                    .top_level
                    .iter()
                    .map(|s| jetstream_core::proto::sanitize_name(s))
                    .collect(),
                more_top_level: offer.summary.more_top_level,
                browser: false,
            };

            let answer = state.register_offer(id);
            let _ = app.emit("offer", &view);
            // The window may be closed to the tray — which is how it starts with
            // Windows. A prompt nobody can see is declined three minutes later.
            crate::tray::ask_for_attention(&app);
            crate::tray::notify(
                &app,
                &format!("{} wants to send you files", peer.name),
                &view.summary,
            );

            let answer = tokio::select! {
                answer = tokio::time::timeout(OFFER_TIMEOUT, answer) => answer.ok().and_then(Result::ok),
                // The sender gave up while the question was on screen. Take it
                // down rather than ask something nobody is waiting for.
                () = session.closed() => {
                    if let Some(incoming) = assigned.lock().expect("assigned poisoned").as_mut() {
                        incoming.withdrawn = true;
                    }
                    None
                }
            };

            match answer {
                Some(answer) => {
                    if let Some(level) = answer.remember {
                        let mut trust = state.trust.lock().expect("trust poisoned");
                        let _ = trust.set_level(peer.device_id, &peer.name, level);
                    }

                    if answer.accept {
                        accept
                    } else {
                        transfer::Decision::Reject {
                            reason: "declined".into(),
                        }
                    }
                }
                // Nobody was at the machine. Declining is the safe default —
                // silence must never be consent.
                None => {
                    state.forget_offer(id);
                    let _ = app.emit("offer-expired", id);
                    transfer::Decision::Reject {
                        reason: "nobody answered the prompt".into(),
                    }
                }
            }
        }
    };

    let result = transfer::receive(&session, decide, Arc::clone(&progress)).await;

    let Some(incoming) = assigned.lock().expect("assigned poisoned").take() else {
        // Never got as far as an offer: a reachability probe, or a peer that
        // hung up straight away. Nothing was shown, so there is nothing to say.
        if let Err(e) = &result {
            tracing::debug!(peer = %peer.name, error = %e, "inbound session ended before an offer");
        }
        session.close("finished").await;
        return;
    };
    let id = incoming.id;
    let name = &peer.name;

    let (state_after, outcome, detail) = match &result {
        Ok(received) => {
            let mut trust = state.trust.lock().expect("trust poisoned");
            let _ = trust.touch(
                &peer.device_id,
                &peer.name,
                Some(peer.remote_address.to_string()),
            );
            // A delivered file if there is one, so Explorer highlights it;
            // otherwise the folder, which is still better than nothing.
            let landed = received.placements.iter().find_map(|placement| match placement {
                jetstream_core::staging::Placement::Created(path)
                | jetstream_core::staging::Placement::Renamed(path)
                | jetstream_core::staging::Placement::Overwritten(path) => Some(path.clone()),
                jetstream_core::staging::Placement::Skipped(_) => None,
            });
            state.set_reveal(id, landed.unwrap_or_else(|| incoming.destination.clone()));

            (
                TransferState::Done,
                crate::history::Outcome::Completed,
                Some(
                    jetstream_core::staging::PlacementTally::of(&received.placements)
                        .describe(),
                ),
            )
        }
        Err(_) if incoming.withdrawn => (
            TransferState::Cancelled,
            crate::history::Outcome::Cancelled,
            Some(format!("{name} withdrew this before it was answered.")),
        ),
        Err(jetstream_core::Error::Rejected(reason)) => (
            TransferState::Rejected,
            crate::history::Outcome::Declined,
            Some(reason.clone()),
        ),
        Err(jetstream_core::Error::PausedByPeer) => (
            TransferState::Paused,
            crate::history::Outcome::Paused,
            Some(format!(
                "{name} paused this. It picks up where it stopped when they continue."
            )),
        ),
        Err(jetstream_core::Error::CancelledByPeer) => (
            TransferState::Cancelled,
            crate::history::Outcome::Cancelled,
            Some(format!("{name} cancelled this. Files that had finished were kept.")),
        ),
        Err(jetstream_core::Error::Cancelled | jetstream_core::Error::Paused) => (
            TransferState::Cancelled,
            crate::history::Outcome::Cancelled,
            Some(format!(
                "Stopped. What already arrived is kept — if {name} sends it again, it carries on from here."
            )),
        ),
        Err(e) => (
            TransferState::Interrupted,
            crate::history::Outcome::Interrupted,
            Some(format!(
                "{e} — what arrived is kept, and it carries on from here when {name} reconnects"
            )),
        ),
    };

    state.set_state(id, state_after, detail.clone());
    let transferred = state.shown_bytes(id).map_or(0, |(done, _)| done);
    state.history.record(crate::history::Record {
        id,
        peer_device_id: peer.device_id.to_hex(),
        peer_name: peer.name.clone(),
        sources: Vec::new(),
        sending: false,
        summary: incoming.summary.clone(),
        bytes: incoming.total,
        outcome,
        at: crate::history::unix_now(),
        attempts: 0,
        detail,
        digest: Some(incoming.digest),
        destination: Some(incoming.destination),
        transferred,
    });

    if state_after == TransferState::Done {
        crate::tray::notify(&app, &format!("Received from {name}"), &incoming.summary);
    }

    let _ = app.emit("transfers", state.transfer_views());
    let _ = app.emit("history-changed", ());
    session.close("finished").await;
}

/// What an inbound session turned out to be, once its offer arrived.
struct Incoming {
    id: u64,
    summary: String,
    digest: String,
    total: u64,
    destination: PathBuf,
    /// The sender hung up while the accept prompt was still open.
    withdrawn: bool,
}
