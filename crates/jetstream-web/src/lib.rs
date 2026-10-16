//! The browser receiver: how a device without Jetstream installed takes part.
//!
//! A phone, a Mac, a locked-down work laptop, a friend's machine — anything with
//! a browser can send and receive by scanning a QR code. This is the single
//! feature that removes most of the "the other person doesn't have it" problem,
//! which is why it is a first-class part of the product rather than a
//! convenience bolted on the side.
//!
//! # Security posture, stated plainly
//!
//! This server speaks **plain HTTP**, and that is a deliberate choice with real
//! consequences. The alternative is a self-signed certificate, which makes every
//! browser show a full-page security warning — and telling users to click
//! through security warnings to use your app is worse than the thing it fixes.
//! A publicly-trusted certificate would need a hosted domain resolving to
//! private addresses, which is infrastructure this project does not have.
//!
//! So instead:
//!
//! - **Every session starts from a short-lived, single-use token** carried in
//!   the QR code. Knowing the port is not enough; you need the code. That
//!   token, not the choice of interface, is what keeps strangers out.
//! - **It listens on every IPv4 interface**, so a phone can reach it on
//!   whichever network it shares with this machine. It used to bind only the
//!   address the default route picked, and on a machine with Ethernet, Wi-Fi
//!   and a VPN adapter that was often not the one the phone was on — the QR
//!   pointed somewhere the phone could not reach and scanning did nothing. The
//!   Windows firewall rule for it admits the local subnet only.
//! - **It is off by default.** The user turns it on when they want it, and it
//!   stops when they close the panel.
//! - **Nothing arrives without a prompt.** A browser guest is never trusted, no
//!   matter how many times it has connected. There is no key to pin, so there is
//!   nothing to remember.
//!
//! What is genuinely weaker than the native path: traffic is unencrypted on the
//! local segment, and uploads carry a CRC-32 rather than a BLAKE3 hash, so
//! integrity is corruption-detection rather than cryptographic. Both are stated
//! in the UI. See [`crc32`] and
//! [`Staging::finish_file_chunkwise`](jetstream_core::staging::Staging::finish_file_chunkwise).

mod crc32;
mod routes;
mod session;
mod upload;

pub use crc32::crc32;
pub use session::{GuestInfo, PairingCode};

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use jetstream_core::staging::ConflictPolicy;
use jetstream_core::transfer::Progress;
use serde::Serialize;

use session::Sessions;
use upload::Uploads;

/// How long a pairing code stays valid.
///
/// Long enough to unlock a phone and open the camera, short enough that a code
/// left on screen is not a standing invitation.
pub const CODE_LIFETIME: std::time::Duration = std::time::Duration::from_secs(300);

/// How long a browser session lasts after the code is exchanged.
pub const SESSION_LIFETIME: std::time::Duration = std::time::Duration::from_secs(4 * 3600);

/// A file the app is offering for a browser to download.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OfferedFile {
    /// Opaque id used in the download URL. Not the path — a browser must never
    /// be able to name a file on disk.
    pub id: String,
    pub name: String,
    pub size: u64,
    #[serde(skip)]
    pub path: PathBuf,
}

/// What the app grants when it accepts a browser upload.
pub struct UploadGrant {
    pub destination: PathBuf,
    pub conflict: ConflictPolicy,
    /// Counters the app can show in its transfer list.
    pub progress: Arc<Progress>,
}

/// Summary of what a browser is proposing to send.
#[derive(Debug, Clone)]
pub struct UploadOffer {
    pub file_count: u64,
    pub total_bytes: u64,
    pub top_level: Vec<String>,
}

type Answer<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// The application behind the server.
///
/// Keeps this crate free of any dependency on Tauri, so the CLI can host the
/// browser receiver on a headless machine with the same code.
pub trait WebHandler: Send + Sync + 'static {
    /// Name shown to the browser, so a user can tell which machine answered.
    fn device_name(&self) -> String;

    /// Ask the user whether to accept an upload.
    ///
    /// Returning `None` declines. A browser guest is prompted **every time** —
    /// unlike a paired device there is no key to pin, so "remember this device"
    /// would be remembering nothing.
    fn accept_upload(&self, guest: GuestInfo, offer: UploadOffer) -> Answer<Option<UploadGrant>>;

    /// Called once an upload finishes, so the app can report it.
    fn upload_finished(&self, guest: GuestInfo, files: Vec<String>);

    /// Files currently offered for download.
    fn offered_files(&self) -> Vec<OfferedFile>;

    /// Text pasted in the browser and sent to this machine.
    fn receive_text(&self, guest: GuestInfo, text: String);

    /// Text this machine is offering to the browser, if any.
    fn text_to_share(&self) -> Option<String>;
}

/// A running browser receiver.
pub struct WebServer {
    address: SocketAddr,
    /// Every address a browser might use, best first. See [`LanAddress`].
    addresses: Vec<LanAddress>,
    sessions: Arc<Sessions>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Debug, thiserror::Error)]
pub enum WebError {
    #[error("could not start the browser receiver: {0}")]
    Bind(#[from] std::io::Error),

    #[error("this machine has no network address, so a browser could not reach it")]
    NoAddress,
}

/// One address this machine can be reached at, and the network it is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanAddress {
    pub ip: IpAddr,
    /// The interface name, e.g. `Wi-Fi` or `Ethernet 2`, so a person can tell
    /// which network a code is for.
    pub interface: String,
}

/// Port tried first, so the address a phone remembers stays the same between
/// sessions. Any free port is used if it is taken.
pub const PREFERRED_PORT: u16 = 4647;

pub(crate) struct AppState {
    pub handler: Arc<dyn WebHandler>,
    pub sessions: Arc<Sessions>,
    pub uploads: Arc<Uploads>,
}

impl WebServer {
    /// Bind and start serving.
    ///
    /// Binds the machine's LAN address specifically rather than every
    /// interface: the QR code can only carry one address anyway, and listening
    /// on interfaces we are not advertising widens the exposure for nothing.
    pub async fn start(handler: Arc<dyn WebHandler>) -> Result<Self, WebError> {
        Self::start_on(handler, PREFERRED_PORT).await
    }

    /// Start on `port`, or on any free port if that one is taken. Port 0 always
    /// takes any free port, which is what tests want.
    pub async fn start_on(handler: Arc<dyn WebHandler>, port: u16) -> Result<Self, WebError> {
        let addresses = lan_addresses();
        let primary = addresses.first().ok_or(WebError::NoAddress)?.ip;

        let any = SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port));
        let listener = match tokio::net::TcpListener::bind(any).await {
            Ok(listener) => listener,
            Err(_) if port != 0 => {
                tokio::net::TcpListener::bind(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)))
                    .await?
            }
            Err(e) => return Err(e.into()),
        };
        let address = SocketAddr::new(primary, listener.local_addr()?.port());

        let sessions = Arc::new(Sessions::new());
        let state = Arc::new(AppState {
            handler,
            sessions: Arc::clone(&sessions),
            uploads: Arc::new(Uploads::new()),
        });

        let router = routes::router(state);
        let (shutdown, on_shutdown) = tokio::sync::oneshot::channel();

        let task = tokio::spawn(async move {
            let served = axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = on_shutdown.await;
                })
                .await;

            if let Err(e) = served {
                tracing::warn!(error = %e, "browser receiver stopped");
            }
        });

        tracing::info!(%address, "browser receiver listening");

        Ok(Self {
            address,
            addresses,
            sessions,
            shutdown: Some(shutdown),
            task: Some(task),
        })
    }

    /// The address a QR code points at unless another is chosen.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Every address a browser might reach this machine at, best guess first.
    pub fn addresses(&self) -> &[LanAddress] {
        &self.addresses
    }

    /// Mint a pairing code and the URL a browser should open.
    pub fn pairing_code(&self) -> PairingCode {
        self.pairing_code_for(self.address.ip())
    }

    /// Mint a pairing code for a particular address — the network the phone is
    /// on, when this machine is on more than one.
    pub fn pairing_code_for(&self, ip: IpAddr) -> PairingCode {
        let address = SocketAddr::new(ip, self.address.port());
        self.sessions.issue_code(&format!("http://{address}"))
    }

    /// How many browsers are currently connected.
    pub fn guest_count(&self) -> usize {
        self.sessions.active_count()
    }

    /// Stop serving and drop every session.
    pub async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for WebServer {
    fn drop(&mut self) {
        // If the app forgot to `stop`, at least do not leave the port open.
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

/// The address the default route would use — the usual answer to "which
/// network is the phone on".
fn jetstream_discovery_lan_address() -> Option<IpAddr> {
    // Duplicated from `jetstream-discovery` rather than depending on it: this
    // crate has no other reason to pull in mDNS and a firewall COM binding, and
    // the routing-table trick is four lines.
    let socket = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    socket.connect(("192.0.2.1", 9)).ok()?; // TEST-NET-1, never routed
    let address = socket.local_addr().ok()?.ip();

    (!address.is_loopback() && !address.is_unspecified()).then_some(address)
}

/// Every IPv4 address a browser on some network could use, best first.
///
/// The default route's address leads, then private LAN addresses, then
/// anything else routable. Self-assigned `169.254` addresses come last: they
/// usually belong to an idle adapter, though on a direct cable they are the
/// only option.
fn lan_addresses() -> Vec<LanAddress> {
    let primary = jetstream_discovery_lan_address();

    let mut found: Vec<LanAddress> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|interface| match interface.ip() {
            IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => Some(LanAddress {
                ip: IpAddr::V4(v4),
                interface: interface.name,
            }),
            _ => None,
        })
        .collect();

    // The routing trick can name an address the interface list missed.
    if let Some(primary) = primary
        && !found.iter().any(|address| address.ip == primary)
    {
        found.push(LanAddress {
            ip: primary,
            interface: String::new(),
        });
    }

    let rank = |address: &LanAddress| match address.ip {
        ip if Some(ip) == primary => 0,
        IpAddr::V4(v4) if v4.is_private() => 1,
        IpAddr::V4(v4) if v4.is_link_local() => 3,
        _ => 2,
    };
    found.sort_by_key(|address| (rank(address), address.ip));
    found.dedup_by(|a, b| a.ip == b.ip);
    found
}

/// Render a pairing URL as an SVG QR code, ready to drop into the UI.
pub fn qr_svg(url: &str) -> Result<String, String> {
    use qrcode::QrCode;
    use qrcode::render::svg;

    let code = QrCode::new(url.as_bytes()).map_err(|e| format!("could not build a QR code: {e}"))?;

    // Colours chosen so the code stays scannable on the app's dark panel:
    // scanners need high contrast, and a "dark-mode" QR with a light module
    // colour on dark background reads inverted on many phone cameras. So the
    // modules stay dark on a light quiet zone, as the spec intends.
    Ok(code
        .render::<svg::Color>()
        .min_dimensions(220, 220)
        .quiet_zone(true)
        .dark_color(svg::Color("#0f1417"))
        .light_color(svg::Color("#ffffff"))
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_codes_render_as_scannable_svg() {
        let svg = qr_svg("http://192.168.1.6:51234/j/abcdef").unwrap();

        assert!(svg.starts_with("<?xml") || svg.starts_with("<svg"), "got: {}", &svg[..40]);
        assert!(svg.contains("#ffffff"), "needs a light quiet zone to scan");
        assert!(svg.len() > 500, "suspiciously small QR output");
    }

    #[test]
    fn the_default_route_address_is_offered_first() {
        let addresses = lan_addresses();
        if let Some(primary) = jetstream_discovery_lan_address() {
            assert_eq!(addresses.first().map(|a| a.ip), Some(primary));
        }
        assert!(addresses.iter().all(|a| !a.ip.is_loopback()));
    }

    #[test]
    fn a_lan_address_is_found_or_honestly_absent() {
        // Must not panic on a machine with no network.
        let address = jetstream_discovery_lan_address();
        if let Some(address) = address {
            assert!(!address.is_loopback());
        }
    }
}
