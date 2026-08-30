//! Authenticated sessions between two devices.
//!
//! [`Session`] is the seam the rest of the engine is written against. Today it
//! is always backed by a direct QUIC connection; when relay support lands, a
//! relayed link becomes a second way to construct a `Session` and nothing above
//! this module changes. That is the whole reason peers are addressed by public
//! key rather than by socket address.

pub mod quic;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::Mutex;

pub use quic::Endpoint;

use crate::error::{Error, Result};
use crate::identity::DeviceId;
use crate::proto::{
    self, Capabilities, Control, Hello, MAX_CONTROL_FRAME, PROTOCOL_VERSION, Platform,
};

/// How long [`Session::close`] waits for the peer to read our final frames.
///
/// Short enough not to be felt, long enough to cover a loopback or LAN round
/// trip many times over.
const CLOSE_GRACE: std::time::Duration = std::time::Duration::from_millis(750);

/// What we know about the device on the other end, after authentication.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Cryptographically proven — derived from the key the peer used to
    /// complete the TLS handshake, not from anything it merely claimed.
    pub device_id: DeviceId,
    /// Display name. Peer-supplied and already run through
    /// [`proto::sanitize_name`], but still untrusted: never use it as a
    /// filesystem path or shell argument.
    pub name: String,
    pub platform: Platform,
    pub app_version: String,
    pub capabilities: Capabilities,
    pub remote_address: SocketAddr,
}

/// An authenticated, encrypted session with a peer.
///
/// Construction implies the handshake succeeded: the peer proved possession of
/// the key behind `peer().device_id`. It does *not* imply the peer is trusted —
/// that is a separate question the caller answers against the trust store.
pub struct Session {
    connection: quinn::Connection,
    peer: PeerInfo,
    control: Mutex<ControlStream>,
}

struct ControlStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl Session {
    /// Run the application handshake over an established QUIC connection.
    ///
    /// The dialing side opens the control stream and the listening side accepts
    /// it; both then send [`Hello`] before either reads, so the exchange costs
    /// one round trip rather than two.
    async fn handshake(
        connection: quinn::Connection,
        local: Hello,
        dialer: bool,
    ) -> Result<Arc<Self>> {
        let cert_device_id = crate::tls::peer_device_id(&connection)?;

        let (mut send, mut recv) = if dialer {
            connection.open_bi().await.map_err(Error::transport)?
        } else {
            connection.accept_bi().await.map_err(Error::transport)?
        };

        proto::write_frame(&mut send, &local).await?;
        let remote: Hello = proto::read_frame(&mut recv, MAX_CONTROL_FRAME).await?;

        // A peer may claim any id it likes in `Hello`. Only the TLS key proves
        // anything, so a disagreement means either a buggy peer or an attempt
        // to be logged and displayed as somebody else.
        if remote.device_id != cert_device_id {
            tracing::warn!(
                claimed = %remote.device_id.short(),
                proven = %cert_device_id.short(),
                "peer claimed a device id it cannot prove; dropping connection"
            );
            return Err(Error::Protocol(
                "peer's claimed device id does not match the key it authenticated with".into(),
            ));
        }

        if remote.version != PROTOCOL_VERSION {
            return Err(Error::VersionMismatch {
                peer: remote.version,
                ours: PROTOCOL_VERSION,
            });
        }

        let peer = PeerInfo {
            device_id: cert_device_id,
            name: proto::sanitize_name(&remote.name),
            platform: remote.platform,
            app_version: proto::sanitize_name(&remote.app_version),
            capabilities: remote.capabilities,
            remote_address: connection.remote_address(),
        };

        tracing::info!(
            device_id = %peer.device_id.short(),
            fingerprint = %peer.device_id.fingerprint(),
            name = %peer.name,
            addr = %peer.remote_address,
            "session established"
        );

        Ok(Arc::new(Self {
            connection,
            peer,
            control: Mutex::new(ControlStream { send, recv }),
        }))
    }

    pub fn peer(&self) -> &PeerInfo {
        &self.peer
    }

    /// Round-trip time estimated by QUIC. Useful for the UI and for sizing
    /// how far ahead the receiver should request chunks.
    pub fn rtt(&self) -> std::time::Duration {
        self.connection.rtt()
    }

    /// Open a stream for bulk data. Each file or chunk batch gets its own, so
    /// one slow file cannot head-of-line-block the others.
    pub async fn open_stream(&self) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        self.connection.open_bi().await.map_err(Error::transport)
    }

    pub async fn accept_stream(&self) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        self.connection.accept_bi().await.map_err(Error::transport)
    }

    /// Send a control message.
    pub async fn send_control(&self, message: &Control) -> Result<()> {
        let mut control = self.control.lock().await;
        proto::write_frame(&mut control.send, message).await
    }

    /// Await the next control message.
    pub async fn recv_control(&self) -> Result<Control> {
        let mut control = self.control.lock().await;
        proto::read_frame(&mut control.recv, MAX_CONTROL_FRAME).await
    }

    /// Application-level liveness probe. Returns the measured round trip.
    ///
    /// QUIC keepalives prove the socket is alive; this proves the peer's
    /// transfer loop is still running, which is the thing we actually care
    /// about before deciding a transfer has stalled.
    pub async fn ping(&self) -> Result<std::time::Duration> {
        let nonce = self.connection.stable_id() as u64;
        let started = std::time::Instant::now();

        self.send_control(&Control::Ping(nonce)).await?;
        match self.recv_control().await? {
            Control::Pong(echo) if echo == nonce => Ok(started.elapsed()),
            other => Err(Error::Protocol(format!("expected Pong({nonce}), got {other:?}"))),
        }
    }

    /// Close cleanly, telling the peer this was intentional.
    ///
    /// The distinction matters: a peer that sees `Goodbye` marks the transfer
    /// finished or cancelled, while a peer that sees the connection vanish
    /// keeps the staged chunks and schedules a resume.
    ///
    /// # Why this waits
    ///
    /// `Connection::close` is immediate and discards anything not yet
    /// acknowledged — including a `Reject` written microseconds earlier. The
    /// symptom is a declined transfer reporting "connection lost" on the
    /// sender, which then invites the user to retry something that was
    /// deliberately refused. So we give the peer a brief window to read our
    /// last frames and hang up first, and only force the close if it does not.
    pub async fn close(&self, reason: &str) {
        let _ = self
            .send_control(&Control::Goodbye {
                reason: reason.to_string(),
            })
            .await;

        let _ = tokio::time::timeout(CLOSE_GRACE, self.connection.closed()).await;
        self.connection.close(0u32.into(), reason.as_bytes());
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").field("peer", &self.peer).finish()
    }
}
