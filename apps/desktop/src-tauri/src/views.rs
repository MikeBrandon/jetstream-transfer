//! Types crossing the Rust/JavaScript boundary.
//!
//! Deliberately separate from the engine's own types. The frontend should not
//! have to know about `Arc<Progress>` or `SocketAddr`, and — more importantly —
//! pinning the shape here means an internal refactor cannot silently change the
//! UI contract.
//!
//! Everything here is `camelCase` on the wire, because that is what the
//! TypeScript side expects to read.

use jetstream_core::DeviceId;
use jetstream_core::trust::{TrustLevel, TrustedDevice};
use jetstream_discovery::DiscoveredPeer;
use serde::{Deserialize, Serialize};

/// This device, as shown in the header and the pairing dialog.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelfView {
    pub name: String,
    pub device_id: String,
    pub fingerprint: String,
    /// The six words individually, so the UI can lay them out as chips rather
    /// than one long hyphenated string a user has to parse visually.
    pub fingerprint_words: Vec<String>,
    pub port: u16,
    pub download_dir: String,
    /// Running from a `Jetstream Data` folder beside the executable.
    pub portable: bool,
}

/// A device on the network.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerView {
    pub device_id: String,
    pub name: String,
    pub fingerprint: String,
    pub address: Option<String>,
    /// Which mechanisms found it — shown in the tooltip, and the thing that
    /// makes a discovery problem diagnosable at a glance.
    pub sources: Vec<String>,
    /// Whether this device is in the trust store, and how it is treated.
    pub trust: TrustView,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TrustView {
    /// Never paired. Sending to it will prompt on the other end, and receiving
    /// from it will prompt here.
    Unknown,
    Ask,
    AutoAccept,
    Blocked,
}

impl TrustView {
    pub fn of(level: TrustLevel, known: bool) -> Self {
        match (known, level) {
            (false, _) => Self::Unknown,
            (true, TrustLevel::Ask) => Self::Ask,
            (true, TrustLevel::AutoAccept) => Self::AutoAccept,
            (true, TrustLevel::Blocked) => Self::Blocked,
        }
    }

    pub fn to_level(self) -> TrustLevel {
        match self {
            Self::AutoAccept => TrustLevel::AutoAccept,
            Self::Blocked => TrustLevel::Blocked,
            Self::Unknown | Self::Ask => TrustLevel::Ask,
        }
    }
}

impl PeerView {
    pub fn from_discovered(peer: &DiscoveredPeer, trust: TrustView) -> Self {
        Self {
            device_id: peer.device_id.to_hex(),
            name: peer.name.clone(),
            fingerprint: peer.device_id.fingerprint(),
            address: peer.best_address().map(|a| a.to_string()),
            sources: peer.sources.iter().map(|s| s.label().to_string()).collect(),
            trust,
        }
    }
}

/// A paired device, for the trusted-devices list.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedView {
    pub device_id: String,
    pub name: String,
    pub fingerprint: String,
    pub trust: TrustView,
    pub first_paired: i64,
    pub last_seen: i64,
    pub online: bool,
}

impl TrustedView {
    pub fn new(device: &TrustedDevice, online: bool) -> Self {
        Self {
            device_id: device.device_id.to_hex(),
            name: device.name.clone(),
            fingerprint: device.fingerprint(),
            trust: TrustView::of(device.level, true),
            first_paired: device.first_paired,
            last_seen: device.last_seen,
            online,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Direction {
    Sending,
    Receiving,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TransferState {
    Connecting,
    /// Offer sent, waiting for the other side to accept.
    Waiting,
    Active,
    Done,
    /// Stopped, but the staged data is still there. Retrying resumes.
    Interrupted,
    /// Stopped deliberately, waiting for the user to continue it.
    ///
    /// Held apart from `Interrupted` because the automatic retry watcher acts on
    /// that one. A paused transfer that looked interrupted would be restarted
    /// within seconds by the very machinery that makes resume feel automatic.
    Paused,
    Failed,
    Rejected,
    /// Stopped by the user and not coming back.
    Cancelled,
}

impl TransferState {
    pub fn is_finished(self) -> bool {
        matches!(
            self,
            Self::Done
                | Self::Interrupted
                | Self::Paused
                | Self::Failed
                | Self::Rejected
                | Self::Cancelled
        )
    }

    /// Whether re-running this transfer would pick up where it stopped.
    pub fn is_resumable(self) -> bool {
        matches!(self, Self::Interrupted | Self::Paused | Self::Cancelled)
    }
}

/// Something the manifest walk left out, and why.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedView {
    pub path: String,
    pub reason: String,
}

/// Most items a UI will ever usefully show for this.
///
/// A folder with thousands of symlinks would otherwise put thousands of rows in
/// the window, and the point is to answer "what did you leave out", which the
/// first few plus a count does perfectly well.
pub const MAX_SKIPPED_SHOWN: usize = 50;

/// One transfer, as the list renders it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferView {
    pub id: u64,
    pub direction: Direction,
    pub peer_name: String,
    pub peer_device_id: String,
    pub state: TransferState,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub files_done: u64,
    pub files_total: u64,
    /// Current rate limit in bytes per second, or `None` when unlimited.
    pub limit: Option<u64>,
    /// Items the walk could not include, with the reason for each.
    pub skipped: Vec<SkippedView>,
    /// Whether this row can open its files in Explorer.
    pub can_reveal: bool,
    /// Bytes per second this wire can carry at most, when known.
    ///
    /// Lets the UI say whether a rate is slow or simply at the limit. `None`
    /// means we could not determine it, and the UI must then say nothing rather
    /// than imply an unlimited link.
    pub link_ceiling: Option<f64>,
    /// The same figure as hardware speaks of it, e.g. `1 Gbps`.
    pub link_label: Option<String>,
    /// Bytes per second, averaged over a short window rather than the whole
    /// transfer, so the number reacts to what the network is doing now.
    pub rate: u64,
    /// Seconds remaining, or `None` when there is not enough signal to say.
    /// Better to show nothing than a wildly wrong estimate.
    pub eta: Option<u64>,
    pub summary: String,
    pub detail: Option<String>,
    pub started_at: i64,
    /// Whether running this transfer again would pick up where it stopped.
    /// Computed here so the UI's "Resume" affordance cannot drift out of step
    /// with what the engine will actually do.
    pub resumable: bool,
}

/// An incoming offer awaiting a decision.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OfferView {
    pub id: u64,
    pub peer_name: String,
    pub peer_device_id: String,
    pub fingerprint: String,
    pub fingerprint_words: Vec<String>,
    /// True the first time we have ever seen this device. The dialog leans much
    /// harder on fingerprint verification in that case.
    pub first_contact: bool,
    pub summary: String,
    pub file_count: u64,
    pub total_bytes: u64,
    pub top_level: Vec<String>,
    pub more_top_level: bool,
}

/// One diagnostic result.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingView {
    pub severity: String,
    pub summary: String,
    pub remedy: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsView {
    pub findings: Vec<FindingView>,
    pub has_problems: bool,
    pub firewall: FirewallView,
}

/// Whether Windows will let other devices reach us.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallView {
    /// `present`, `disabled`, `absent`, `unknown`, or `unsupported`.
    pub state: String,
    /// True only when inbound connections will actually arrive.
    pub allowed: bool,
    /// True when a one-click fix is available. Kept separate from `allowed`
    /// because a *disabled* rule cannot be fixed by adding another one, and
    /// offering a button that spends a UAC prompt to achieve nothing is worse
    /// than explaining the situation.
    pub can_fix: bool,
    pub summary: String,
    pub remedy: String,
}

/// Whether any connected network is categorised Public, and whether we can help.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkProfileView {
    /// True when at least one network is Public *and* safe to change.
    pub needs_fixing: bool,
    /// Names of the networks a fix would apply to.
    pub fixable: Vec<String>,
    /// Public networks deliberately left alone because they reach the internet.
    pub public_with_internet: Vec<String>,
    pub summary: String,
    pub remedy: String,
}

impl NetworkProfileView {
    pub fn check() -> Self {
        let status = match jetstream_discovery::netprofile::status() {
            Ok(status) => status,
            Err(detail) => {
                return Self {
                    needs_fixing: false,
                    fixable: Vec::new(),
                    public_with_internet: Vec::new(),
                    summary: "Could not read the Windows network profiles.".into(),
                    remedy: detail,
                };
            }
        };

        if status.fixable.is_empty() {
            return Self {
                needs_fixing: false,
                fixable: Vec::new(),
                public_with_internet: status.public_with_internet,
                summary: String::new(),
                remedy: String::new(),
            };
        }

        Self {
            needs_fixing: true,
            summary: format!(
                "{} is set to Public because Windows cannot identify it.",
                status.fixable.join(", ")
            ),
            // Says what it will and will not touch, because "change my network
            // security settings" deserves to be specific before it is clicked.
            remedy: "This happens when two computers are connected directly, with no router \
                     to identify. Jetstream can set it to Private, which is what lets Windows \
                     treat the other machine as a device on your own network. Networks that \
                     reach the internet are never changed."
                .into(),
            fixable: status.fixable,
            public_with_internet: status.public_with_internet,
        }
    }
}

impl FirewallView {
    pub fn check() -> Self {
        use jetstream_discovery::firewall::{self, RuleStatus};

        let Ok(exe) = firewall::current_exe() else {
            return Self::unknown("Could not determine where Jetstream is installed.");
        };

        match firewall::status(&exe) {
            RuleStatus::Present => Self {
                state: "present".into(),
                allowed: true,
                can_fix: false,
                summary: "Other devices are allowed to reach this one.".into(),
                remedy: String::new(),
            },
            RuleStatus::Absent => Self {
                state: "absent".into(),
                allowed: false,
                can_fix: true,
                summary: "Windows is blocking other devices from reaching this one.".into(),
                remedy: "Jetstream can fix this for you. Windows will ask for permission, \
                         because changing firewall settings always needs an administrator."
                    .into(),
            },
            RuleStatus::Moved(previous) => Self {
                state: "moved".into(),
                allowed: false,
                can_fix: true,
                summary: "Jetstream was allowed through the firewall from a different folder."
                    .into(),
                // Names the old path, because "you already did this and it stopped
                // working" is otherwise a genuinely confusing thing to be told.
                remedy: format!(
                    "Windows ties the permission to the program's location, and the existing \
                     rule still points at {previous}. Allowing it again updates the rule to \
                     where Jetstream is now — the old one is replaced, not added to."
                ),
            },
            RuleStatus::Disabled => Self {
                state: "disabled".into(),
                allowed: false,
                can_fix: false,
                summary: "Jetstream's firewall rule exists but has been switched off.".into(),
                remedy: "Someone or something disabled it. Re-enable 'Jetstream' in Windows \
                         Security > Firewall & network protection > Allow an app through firewall."
                    .into(),
            },
            RuleStatus::Unknown(detail) => Self::unknown(&detail),
        }
    }

    fn unknown(detail: &str) -> Self {
        Self {
            state: if cfg!(windows) { "unknown" } else { "unsupported" }.into(),
            allowed: false,
            can_fix: false,
            summary: "Could not check whether the firewall is allowing Jetstream through.".into(),
            remedy: detail.to_string(),
        }
    }
}

/// User-editable preferences.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsView {
    pub device_name: String,
    pub download_dir: String,
    /// `rename`, `overwrite`, or `skip`.
    pub on_conflict: String,
    /// Cap on outgoing transfers, in **kilobytes per second**. 0 is no limit.
    ///
    /// KB/s rather than bytes because it is what a person types. Two separate
    /// caps because which one matters depends on the direction of the traffic
    /// competing with everything else on the link.
    #[serde(default)]
    pub send_limit_kbps: u64,
    /// Cap on incoming transfers, in kilobytes per second. 0 is no limit.
    #[serde(default)]
    pub receive_limit_kbps: u64,
}

pub fn device_id_of(text: &str) -> Result<DeviceId, String> {
    text.parse::<DeviceId>()
        .map_err(|e| format!("not a valid device id: {e}"))
}

/// State of the browser receiver, for the panel that shows the QR code.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebStatusView {
    pub running: bool,
    /// The URL the QR code encodes. Empty unless a fresh code was just minted —
    /// a pairing code is single-use, so there is nothing to re-display.
    pub url: String,
    pub qr_svg: String,
    pub expires_in: u64,
    pub guests: u64,
    pub address: String,
}

impl WebStatusView {
    pub fn stopped() -> Self {
        Self {
            running: false,
            url: String::new(),
            qr_svg: String::new(),
            expires_in: 0,
            guests: 0,
            address: String::new(),
        }
    }
}

/// A remembered transfer, for the history list.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryView {
    pub id: u64,
    pub peer_name: String,
    pub peer_device_id: String,
    pub sending: bool,
    pub summary: String,
    pub bytes: u64,
    /// `completed`, `interrupted`, `declined`, or `failed`.
    pub outcome: String,
    pub at: i64,
    /// True when the app will retry this by itself once the peer reappears.
    pub will_retry: bool,
    pub attempts: u32,
    pub detail: Option<String>,
    /// True when the user can retry it by hand — a send with sources we still
    /// have, whatever its outcome.
    pub can_retry: bool,
}

impl HistoryView {
    pub fn new(record: &crate::history::Record) -> Self {
        use crate::history::Outcome;

        Self {
            id: record.id,
            peer_name: record.peer_name.clone(),
            peer_device_id: record.peer_device_id.clone(),
            sending: record.sending,
            summary: record.summary.clone(),
            bytes: record.bytes,
            outcome: match record.outcome {
                Outcome::Completed => "completed",
                Outcome::Interrupted => "interrupted",
                Outcome::Paused => "paused",
                Outcome::Cancelled => "cancelled",
                Outcome::Declined => "declined",
                Outcome::Failed => "failed",
            }
            .to_string(),
            at: record.at,
            will_retry: record.wants_retry(),
            attempts: record.attempts,
            detail: record.detail.clone(),
            can_retry: record.sending
                && !record.sources.is_empty()
                && record.outcome.can_continue(),
        }
    }
}
