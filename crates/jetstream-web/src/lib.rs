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
//! - **The server binds only to a LAN address, never `0.0.0.0` on a routable
//!   interface it does not own.** It is reachable from the local network and
//!   nowhere else.
//! - **Every session starts from a short-lived, single-use token** carried in
//!   the QR code. Knowing the port is not enough; you need the code.
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
        let ip = jetstream_discovery_lan_address().ok_or(WebError::NoAddress)?;

        // Port 0: the OS picks. A fixed port would be one more thing to collide
        // and one more thing to guess.
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(ip, 0)).await?;
        let address = listener.local_addr()?;

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
            sessions,
            shutdown: Some(shutdown),
            task: Some(task),
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Mint a pairing code and the URL a browser should open.
    pub fn pairing_code(&self) -> PairingCode {
        self.sessions.issue_code(&format!("http://{}", self.address))
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

/// The LAN address a browser should be pointed at.
fn jetstream_discovery_lan_address() -> Option<IpAddr> {
    // Duplicated from `jetstream-discovery` rather than depending on it: this
    // crate has no other reason to pull in mDNS and a firewall COM binding, and
    // the routing-table trick is four lines.
    let socket = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    socket.connect(("192.0.2.1", 9)).ok()?; // TEST-NET-1, never routed
    let address = socket.local_addr().ok()?.ip();

    (!address.is_loopback() && !address.is_unspecified()).then_some(address)
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
    fn a_lan_address_is_found_or_honestly_absent() {
        // Must not panic on a machine with no network.
        let address = jetstream_discovery_lan_address();
        if let Some(address) = address {
            assert!(!address.is_loopback());
        }
    }
}
