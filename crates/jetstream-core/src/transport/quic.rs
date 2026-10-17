//! QUIC endpoint: one UDP socket that both dials and listens.
//!
//! QUIC rather than TCP buys three things this application specifically needs:
//! independent streams so a stalled file cannot block its neighbours, TLS 1.3
//! folded into the handshake, and connection migration — a laptop that moves
//! from Ethernet to Wi-Fi keeps its transfer instead of restarting it.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};

use crate::error::{Error, Result};
use crate::identity::{DeviceId, Identity};
use crate::proto::Hello;
use crate::tls;
use crate::transport::Session;

/// How long a connection may sit idle before QUIC tears it down.
///
/// Generous on purpose. A transfer that pauses because the user's laptop slept
/// or the Wi-Fi roamed should reconnect and resume, not be treated as failed —
/// but 30s is short enough that a genuinely dead peer leaves the UI promptly.
const MAX_IDLE: Duration = Duration::from_secs(30);

/// Keepalive cadence, comfortably inside [`MAX_IDLE`].
const KEEP_ALIVE: Duration = Duration::from_secs(10);

/// Per-connection stream ceiling. Bulk transfer uses several streams in
/// parallel; this bounds how many a peer can force us to track.
const MAX_CONCURRENT_STREAMS: u32 = 512;

/// Per-stream receive window.
///
/// **This is the single most important throughput setting**, and quinn's default
/// is wrong for this application. That default works out to 1.19 MiB, derived
/// from an assumed 100 Mbit/s link at 100 ms round trip — sensible for the
/// internet, badly wrong for a LAN.
///
/// Our chunks are 1 MiB, so a 1.19 MiB window lets the sender put *one* chunk in
/// flight and then stall until the receiver drains it and a window update makes
/// the return trip. Measured, that capped a loopback transfer at 97 MB/s with
/// roughly 10 ms of dead time per chunk — the pipeline was empty most of the
/// time.
///
/// 32 MiB allows around 32 chunks in flight per stream, which keeps the sender's
/// disk reads, both BLAKE3 passes, and the receiver's writes all busy at once.
/// The cost is bounded memory per stream, which the stream ceiling above caps.
const STREAM_RECEIVE_WINDOW: u32 = 32 * 1024 * 1024;

/// Connection-wide send allowance.
///
/// Must exceed the per-stream window times the number of streams in flight, or
/// it becomes the new bottleneck the moment transfers run in parallel.
const SEND_WINDOW: u64 = 256 * 1024 * 1024;

/// Largest UDP payload path-MTU discovery is allowed to probe for.
///
/// quinn stops at 1452 by default, which is right for the internet — that is
/// what survives a 1500-byte path once IPv6 and UDP headers are subtracted, and
/// probing beyond it on a WAN risks a black hole.
///
/// On a LAN it leaves throughput on the table. At 1452 bytes, moving 100 MB/s
/// means around 71,000 datagrams a second, and on Windows each one is close to a
/// syscall — which is what actually caps a loopback transfer, not bandwidth.
/// Wired gigabit and 10GbE setups very often run 9000-byte jumbo frames, and
/// loopback carries far more than that.
///
/// Raising the ceiling is safe because this is a *probe* limit, not an
/// assumption: DPLPMTUD only adopts a larger size after a probe of that size
/// actually arrives, `min_mtu` stays at the conservative default, and a path
/// that later stops carrying large packets is detected and backed away from. On
/// an ordinary 1500-byte network the discovered value is still 1452.
const MTU_UPPER_BOUND: u16 = 9000;

/// Congestion window a connection starts with.
///
/// QUIC's default is ten packets — about 14 kB — because on the open internet a
/// new connection has no idea what the path can take, and guessing high hurts
/// everybody sharing it.
///
/// On a local network that caution costs real time. Measured on loopback, a
/// transfer took two to three seconds to climb to its steady 120 MB/s, so a
/// 512 MiB transfer averaged 103 MB/s while a 1 GiB one averaged 108 — the
/// difference being almost entirely time spent ramping. Most real transfers are
/// short enough that they never leave the ramp.
///
/// 1 MiB is chosen deliberately for a LAN: it is aggressive by internet
/// standards, and appropriate here because the path is a switch away and there
/// is no shared bottleneck to be a bad neighbour on. **A path that leaves the
/// LAN must not use this** — see [`is_lan`], which keeps VPN and internet
/// addresses on the conservative defaults, where a megabyte-sized first burst
/// mostly produces loss and a collapsed window.
const INITIAL_WINDOW: u64 = 1024 * 1024;

/// UDP socket buffer size requested from the OS.
///
/// The default on Windows is small enough that a burst can be dropped before
/// quinn gets a chance to read it, which on a fast link shows up as spurious
/// loss and a collapsed congestion window. Best-effort: the OS may clamp it.
const SOCKET_BUFFER: usize = 8 * 1024 * 1024;

/// A bound QUIC endpoint that can accept and initiate sessions.
/// How a connection to a peer *off* the local network paces itself.
///
/// LAN connections are unaffected by this: they keep the tuned Cubic setup that
/// was measured saturating gigabit Ethernet, whatever this is set to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RemoteCongestion {
    /// Cubic, quinn's default. Loss-based: it speeds up until packets drop, so on
    /// a link with an oversized buffer it fills the buffer first, which shows up
    /// as latency in the seconds and a rate that saws up and down.
    #[default]
    Standard,
    /// BBR. Paces at its estimate of the bottleneck's rate instead of probing
    /// for loss, which keeps queues short on over-buffered links.
    ///
    /// **Opt-in, and labelled experimental**, because quinn's own documentation
    /// says of its implementation "Experimental! Use at your own risk." It is
    /// also known to compete hard with other traffic on the same line. It cannot
    /// harm data or compatibility — pacing is local to the sender and invisible
    /// to the protocol — so the worst case is a slower or less even transfer,
    /// undone by switching back.
    Bbr,
}

/// Whether a connection should use BBR.
///
/// Never on a LAN, whatever the setting: that path has its own measured tuning,
/// and the setting is described to users as affecting internet and VPN peers
/// only.
fn uses_bbr(lan: bool, remote: RemoteCongestion) -> bool {
    !lan && remote == RemoteCongestion::Bbr
}

#[derive(Clone)]
pub struct Endpoint {
    inner: quinn::Endpoint,
    identity: Arc<Identity>,
    /// Shared by every clone, so a rename reaches whichever one dials next.
    local_name: Arc<std::sync::RwLock<String>>,
    /// The `RemoteCongestion` choice, as its discriminant. Shared by every clone
    /// for the same reason as `local_name`: a settings change must reach the
    /// next dial without rebuilding the endpoint.
    remote_congestion: Arc<std::sync::atomic::AtomicU8>,
}

impl Endpoint {
    /// Choose how connections to non-LAN peers pace themselves. Takes effect
    /// from the next connection this endpoint dials; one already open keeps the
    /// controller it started with.
    pub fn set_remote_congestion(&self, choice: RemoteCongestion) {
        let value = match choice {
            RemoteCongestion::Standard => 0,
            RemoteCongestion::Bbr => 1,
        };
        self.remote_congestion
            .store(value, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn remote_congestion(&self) -> RemoteCongestion {
        match self.remote_congestion.load(std::sync::atomic::Ordering::Relaxed) {
            1 => RemoteCongestion::Bbr,
            _ => RemoteCongestion::Standard,
        }
    }

    /// Bind to `addr`.
    ///
    /// Pass port 0 to let the OS choose; read it back with [`Endpoint::local_addr`].
    pub fn bind(identity: Arc<Identity>, local_name: impl Into<String>, addr: SocketAddr) -> Result<Self> {
        let crypto = QuicServerConfig::try_from(tls::server_config(&identity)?)
            .map_err(|e| Error::Crypto(format!("QUIC rejected the TLS config: {e}")))?;

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        server_config.transport_config(Arc::new(transport_config()));

        let socket = bind_socket(addr)?;
        let runtime = quinn::default_runtime()
            .ok_or_else(|| Error::Transport("no async runtime available".into()))?;

        let inner = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            runtime,
        )?;

        Ok(Self {
            inner,
            identity,
            local_name: Arc::new(std::sync::RwLock::new(proto_name(local_name.into()))),
            remote_congestion: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        })
    }

    /// Bind a dual-stack socket on every interface.
    ///
    /// See [`bind_socket`] for why this cannot simply hand `[::]` to quinn.
    ///
    /// Falls back to IPv4 alone on a machine with IPv6 switched off entirely,
    /// where the dual-stack socket cannot even be created. Refusing to start
    /// there would make the app useless on networks that are IPv4 anyway.
    pub fn bind_all(identity: Arc<Identity>, local_name: impl Into<String>, port: u16) -> Result<Self> {
        let local_name = local_name.into();

        match Self::bind(
            Arc::clone(&identity),
            local_name.clone(),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)),
        ) {
            Err(Error::Io(e)) if ipv6_unavailable(&e) => {
                tracing::info!("IPv6 is unavailable here; listening on IPv4 only");
                Self::bind(identity, local_name, SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
            }
            other => other,
        }
    }

    /// Change the name this device gives in every handshake from now on.
    pub fn rename(&self, name: &str) {
        *self.local_name.write().expect("name poisoned") = proto_name(name.to_string());
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.inner.local_addr()?)
    }

    pub fn device_id(&self) -> DeviceId {
        self.identity.device_id()
    }

    /// Dial a peer.
    ///
    /// `expected` pins the identity we require. Pass `Some` for any device the
    /// user has paired with — a mismatch then aborts the handshake rather than
    /// silently connecting to whatever now holds that address. Pass `None` only
    /// for deliberate first contact, and show the resulting fingerprint to the
    /// user before trusting it.
    pub async fn connect(&self, addr: SocketAddr, expected: Option<DeviceId>) -> Result<Arc<Session>> {
        // The dialer is the side that sends the files, so its congestion
        // settings are the ones that matter — and it knows where it is dialling.
        let transport = transport_config_for(is_lan(addr), self.remote_congestion());
        self.connect_using(addr, expected, transport).await
    }

    /// `connect`, with the transport settings supplied by the caller.
    ///
    /// Separate so tests can force a configuration that the address alone would
    /// never select — BBR over loopback, in particular.
    async fn connect_using(
        &self,
        addr: SocketAddr,
        expected: Option<DeviceId>,
        transport: quinn::TransportConfig,
    ) -> Result<Arc<Session>> {
        let crypto = QuicClientConfig::try_from(tls::client_config(&self.identity, expected)?)
            .map_err(|e| Error::Crypto(format!("QUIC rejected the TLS config: {e}")))?;

        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        client_config.transport_config(Arc::new(transport));

        let connection = self
            .inner
            .connect_with(client_config, addr, tls::CERT_SUBJECT)
            .map_err(Error::transport)?
            .await
            .map_err(|e| map_connection_error(e, expected))?;

        Session::handshake(connection, self.hello(), true).await
    }

    /// Dial a peer across several candidate addresses, using the first that
    /// answers.
    ///
    /// A discovered peer usually has more than one address — Wi-Fi, Ethernet,
    /// and whatever a VPN client or hypervisor has added — and no heuristic can
    /// reliably pick the reachable one from the outside. A machine running
    /// Hyper-V advertises a `172.31.x.x` virtual-switch address that is
    /// indistinguishable, on paper, from a real LAN address.
    ///
    /// So we stop guessing and try them in order with a short timeout each.
    /// Two or three failed attempts cost a fraction of a second; picking wrong
    /// and waiting out a full handshake timeout costs the user half a minute.
    ///
    /// A pinned-identity mismatch aborts immediately rather than moving on:
    /// something answering as the wrong device is worth surfacing, not
    /// skipping past.
    pub async fn connect_any(
        &self,
        addresses: &[SocketAddr],
        expected: Option<DeviceId>,
        per_attempt: Duration,
    ) -> Result<Arc<Session>> {
        if addresses.is_empty() {
            return Err(Error::Transport("no addresses to try for this peer".into()));
        }

        let mut failures = Vec::new();

        for &address in addresses {
            match tokio::time::timeout(per_attempt, self.connect(address, expected)).await {
                Ok(Ok(session)) => {
                    tracing::debug!(%address, "connected");
                    return Ok(session);
                }
                // Something answered, and it was the wrong device. That is worth
                // stopping for rather than quietly trying the next address.
                Ok(Err(e @ Error::IdentityMismatch { .. })) => return Err(e),
                Ok(Err(e)) => {
                    tracing::debug!(%address, error = %e, "address did not answer; trying the next");
                    failures.push(format!("{address}: {e}"));
                }
                Err(_) => {
                    tracing::debug!(%address, "address timed out; trying the next");
                    failures.push(format!("{address}: no response within {per_attempt:?}"));
                }
            }
        }

        // Report every attempt. Naming only the last one sends the user chasing
        // whichever address happened to sort last, which is rarely the real
        // problem.
        Err(Error::Transport(format!(
            "could not reach the peer at any of its {} address(es).\n  {}\n\
             If the other device is running, its firewall is the usual cause — \
             run `jet doctor` on it to check.",
            addresses.len(),
            failures.join("\n  "),
        )))
    }

    /// Check that `expected` is answering at `addr`, without starting a session.
    ///
    /// Completes the QUIC handshake — which proves the key, since the identity
    /// is pinned — and hangs up before any application traffic. That keeps it
    /// invisible on the other side: no session, no row in its transfer list, on
    /// this build or an older one.
    pub async fn probe(&self, addr: SocketAddr, expected: DeviceId) -> Result<()> {
        let crypto = QuicClientConfig::try_from(tls::client_config(&self.identity, Some(expected))?)
            .map_err(|e| Error::Crypto(format!("QUIC rejected the TLS config: {e}")))?;

        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        // A probe hangs up before any data moves, so pacing is irrelevant and the
        // experimental controller has no business on a reachability check.
        client_config.transport_config(Arc::new(transport_config_for(
            is_lan(addr),
            RemoteCongestion::Standard,
        )));

        let connection = self
            .inner
            .connect_with(client_config, addr, tls::CERT_SUBJECT)
            .map_err(Error::transport)?
            .await
            .map_err(|e| map_connection_error(e, Some(expected)))?;

        connection.close(0u32.into(), b"probe");
        Ok(())
    }

    /// Await the next inbound session.
    ///
    /// Returns `None` once the endpoint is closed. A failed handshake yields
    /// `Some(Err(..))` and does not stop the listener — one peer failing to
    /// authenticate must not take the daemon down.
    pub async fn accept(&self) -> Option<Result<Arc<Session>>> {
        let incoming = self.inner.accept().await?;
        let remote = incoming.remote_address();

        Some(match incoming.await {
            Ok(connection) => Session::handshake(connection, self.hello(), false).await,
            Err(e) => {
                tracing::debug!(%remote, error = %e, "inbound connection failed before handshake");
                Err(Error::transport(e))
            }
        })
    }

    /// Stop accepting and let in-flight connections drain.
    pub async fn shutdown(&self) {
        self.inner.close(0u32.into(), b"shutting down");
        self.inner.wait_idle().await;
    }

    fn hello(&self) -> Hello {
        let name = self.local_name.read().expect("name poisoned").clone();
        Hello::new(self.identity.device_id(), name)
    }
}

/// Whether a socket error means this machine has no IPv6 at all.
///
/// `EAFNOSUPPORT` on Linux (97) and macOS (47), `WSAEAFNOSUPPORT` on Windows.
fn ipv6_unavailable(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(97 | 47 | 10047))
}

fn proto_name(name: String) -> String {
    crate::proto::sanitize_name(&name)
}

/// Bind the UDP socket ourselves so an IPv6 wildcard bind really is dual-stack.
///
/// This exists because of a Windows default that is easy to miss and total in
/// its effect: `IPV6_V6ONLY` is **on**, so binding `[::]` listens for IPv6
/// only. Linux defaults it off, so the same code works there and the machine
/// silently refuses every IPv4 connection on Windows — which, on a home or
/// office LAN, is all of them. The app looks healthy, announces itself, appears
/// in everyone's peer list, and cannot receive a thing.
///
/// Turning it off is best-effort: a stack with IPv6 disabled entirely will
/// reject the option, and falling back to IPv6-only there is still better than
/// failing to start.
fn bind_socket(addr: SocketAddr) -> Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    // Only for the wildcard. Windows rejects a dual-stack socket bound to a
    // *specific* IPv6 address with WSAEINVAL, and asking for it there would be
    // meaningless anyway — `[::1]` cannot also be an IPv4 address.
    if addr.ip() == Ipv6Addr::UNSPECIFIED
        && let Err(e) = socket.set_only_v6(false)
    {
        tracing::warn!(error = %e, "could not enable dual-stack; IPv4 peers will not reach us");
    }

    // Best-effort buffer sizing. The OS may clamp these, and a smaller buffer
    // still works — it just drops bursts under load, which quinn reads as loss.
    if let Err(e) = socket.set_recv_buffer_size(SOCKET_BUFFER) {
        tracing::debug!(error = %e, "could not enlarge the UDP receive buffer");
    }
    if let Err(e) = socket.set_send_buffer_size(SOCKET_BUFFER) {
        tracing::debug!(error = %e, "could not enlarge the UDP send buffer");
    }

    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

/// Whether `addr` is on a local network rather than across a VPN or the
/// internet.
///
/// By address class, because nothing better is known before the first packet.
/// Private, link-local and loopback addresses are a LAN. Everything else —
/// including Radmin's `26.0.0.0/8` and Tailscale's `100.64.0.0/10`, which are
/// how VPN peers usually appear — is treated as a path that leaves the building.
pub fn is_lan(addr: SocketAddr) -> bool {
    // A dual-stack socket reports an IPv4 peer as `::ffff:a.b.c.d`; judge the
    // IPv4 address inside, or every LAN peer that dialled us looks remote.
    match addr.ip().to_canonical() {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
        std::net::IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback()
                // fe80::/10, link-local
                || first & 0xffc0 == 0xfe80
                // fc00::/7, unique local
                || first & 0xfe00 == 0xfc00
        }
    }
}

/// Transport settings for the listening side, which mostly receives.
fn transport_config() -> quinn::TransportConfig {
    // The listening side mostly receives, and its pacing only governs
    // acknowledgements, so it keeps the defaults.
    transport_config_for(true, RemoteCongestion::Standard)
}

/// Transport settings, tuned for a LAN or left conservative for anything else.
fn transport_config_for(lan: bool, remote: RemoteCongestion) -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    config
        .max_idle_timeout(Some(
            MAX_IDLE
                .try_into()
                .expect("MAX_IDLE is a small constant and always representable"),
        ))
        .keep_alive_interval(Some(KEEP_ALIVE))
        .max_concurrent_bidi_streams(MAX_CONCURRENT_STREAMS.into())
        .max_concurrent_uni_streams(MAX_CONCURRENT_STREAMS.into())
        // See STREAM_RECEIVE_WINDOW: quinn's default assumes a slow, distant
        // link and throttles a LAN transfer to one chunk in flight.
        .stream_receive_window(STREAM_RECEIVE_WINDOW.into())
        .send_window(SEND_WINDOW);

    if uses_bbr(lan, remote) {
        config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    }

    if !lan {
        // A VPN tunnel or the internet: quinn's defaults are tuned for exactly
        // this, and the LAN shortcuts below would only cause loss.
        return config;
    }

    // Let path-MTU discovery look for jumbo frames. See MTU_UPPER_BOUND.
    let mut mtud = quinn::MtuDiscoveryConfig::default();
    mtud.upper_bound(MTU_UPPER_BOUND);
    config.mtu_discovery_config(Some(mtud));

    // Start with a window sized for a LAN rather than for the internet. See
    // INITIAL_WINDOW for why this is safe here and would not be elsewhere.
    let mut cubic = quinn::congestion::CubicConfig::default();
    cubic.initial_window(INITIAL_WINDOW);
    config.congestion_controller_factory(Arc::new(cubic));

    config
}

#[cfg(test)]
mod lan_tests {
    use super::is_lan;

    #[test]
    fn local_addresses_get_the_lan_tuning_and_vpn_addresses_do_not() {
        for lan in [
            "192.168.1.20:4646",
            "10.0.0.5:4646",
            "172.20.1.1:4646",
            "169.254.10.2:4646",
            "127.0.0.1:4646",
            "[fe80::1]:4646",
            "[fd12:3456::1]:4646",
            "[::ffff:192.168.1.20]:4646",
        ] {
            assert!(is_lan(lan.parse().unwrap()), "{lan} is a LAN address");
        }

        for remote in [
            "26.14.120.8:4646",    // Radmin VPN
            "100.101.102.103:4646", // Tailscale
            "203.0.113.9:4646",
            "[2001:db8::1]:4646",
        ] {
            assert!(!is_lan(remote.parse().unwrap()), "{remote} leaves the LAN");
        }
    }
}

/// Turn a raw QUIC failure into something a user can act on.
///
/// The case that matters is a pinned-identity mismatch: rustls surfaces it as a
/// generic TLS alert, which as a user-facing message ("connection failed") is
/// useless and hides the one failure mode that might be an attack.
fn map_connection_error(error: quinn::ConnectionError, expected: Option<DeviceId>) -> Error {
    use quinn::ConnectionError;

    match &error {
        ConnectionError::TransportError(e) if is_access_denied_alert(e.code) => {
            if let Some(expected) = expected {
                Error::Transport(format!(
                    "the device at this address is not {} ({}). It may have been reinstalled, \
                     or something else is answering on its address — re-pair it if you expected \
                     this to change.",
                    expected.short(),
                    expected.fingerprint(),
                ))
            } else {
                Error::Transport("peer rejected our device identity".into())
            }
        }
        ConnectionError::TimedOut => Error::Transport(
            "no response from that address. Check the peer is running Jetstream and that \
             Windows Firewall is not blocking it."
                .into(),
        ),
        _ => Error::transport(error),
    }
}

/// TLS alerts cross the wire as QUIC transport error codes in the 0x100 range,
/// which `TransportErrorCode::crypto` constructs.
///
/// Our pinning verifier returns `ApplicationVerificationFailure`, which rustls
/// emits as `access_denied` (49) — that is the code this predicate exists to
/// catch. The certificate-specific alerts alongside it cover a peer rejecting
/// *us* for the same reason, and malformed certificates. Deliberately excludes
/// the generic `handshake_failure` (40), which also fires for version and
/// cipher mismatches and would make those look like an identity problem.
fn is_access_denied_alert(code: quinn::TransportErrorCode) -> bool {
    const BAD_CERTIFICATE: u8 = 42;
    const CERTIFICATE_UNKNOWN: u8 = 46;
    const UNKNOWN_CA: u8 = 48;
    const ACCESS_DENIED: u8 = 49;

    let code = u64::from(code);
    [BAD_CERTIFICATE, CERTIFICATE_UNKNOWN, UNKNOWN_CA, ACCESS_DENIED]
        .into_iter()
        .any(|alert| code == u64::from(quinn::TransportErrorCode::crypto(alert)))
}

#[cfg(test)]
mod scope_id_tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddrV6};

    /// A QUIC handshake over a **scoped** link-local IPv6 address.
    ///
    /// This is the assumption the direct-cable fix rests on: that a scope id set
    /// on a `SocketAddrV6` survives quinn, socket2 and the OS, and actually
    /// selects an interface. Worth a real connection rather than trust — if the
    /// scope were dropped anywhere in that stack, the fix would be silent and
    /// useless.
    #[tokio::test]
    async fn a_scoped_link_local_address_can_be_dialled() {
        let Some((address, scope)) = first_link_local() else {
            eprintln!("no link-local IPv6 interface here; skipping");
            return;
        };

        let listener = Endpoint::bind_all(
            Arc::new(crate::identity::Identity::generate().unwrap()),
            "scoped listener",
            0,
        )
        .unwrap();
        let port = listener.local_addr().unwrap().port();

        // The accepted session must be *held*. Dropping it closes the connection,
        // which the dialer then reports as `ConnectionLost` — a self-inflicted
        // failure that looks exactly like a network problem.
        let accepting = tokio::spawn(async move {
            let accepted = listener.accept().await;
            let session = accepted.and_then(|r| r.ok());
            // Keep the endpoint and session alive for the assertions below.
            (listener, session)
        });

        let dialer = Endpoint::bind_all(
            Arc::new(crate::identity::Identity::generate().unwrap()),
            "scoped dialer",
            0,
        )
        .unwrap();

        let target = SocketAddr::V6(SocketAddrV6::new(address, port, 0, scope));
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            dialer.connect(target, None),
        )
        .await;

        let session = result.expect("dialling timed out");
        let session = session.unwrap_or_else(|e| panic!("dialling {target} failed: {e}"));

        let (_listener, accepted) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            accepting,
        )
        .await
        .expect("accept timed out")
        .expect("the accept task panicked");

        assert!(
            accepted.is_some(),
            "the listener should have accepted the connection to {target}"
        );
        // Both ends still open, which is the whole claim: a scope id survives
        // quinn, socket2 and the OS, and selects an interface that works.
        assert_eq!(session.peer().remote_address.port(), port);
    }

    fn first_link_local() -> Option<(Ipv6Addr, u32)> {
        for interface in if_addrs::get_if_addrs().ok()? {
            if let if_addrs::IfAddr::V6(v6) = interface.addr
                && v6.ip.segments()[0] & 0xffc0 == 0xfe80
                && let Some(index) = interface.index
            {
                return Some((v6.ip, index));
            }
        }
        None
    }
}

#[cfg(test)]
mod congestion_tests {
    use super::*;

    #[test]
    fn the_default_changes_nothing() {
        // Existing behaviour must be untouched unless someone opts in.
        assert_eq!(RemoteCongestion::default(), RemoteCongestion::Standard);
        assert!(!uses_bbr(false, RemoteCongestion::default()));
        assert!(!uses_bbr(true, RemoteCongestion::default()));
    }

    #[test]
    fn a_lan_never_uses_bbr_whatever_the_setting() {
        // The setting is described as affecting internet and VPN peers only, and
        // the LAN path has its own measured tuning that must not be displaced.
        assert!(!uses_bbr(true, RemoteCongestion::Bbr));
    }

    #[test]
    fn bbr_applies_only_to_remote_peers_that_opted_in() {
        assert!(uses_bbr(false, RemoteCongestion::Bbr));
    }

    #[tokio::test]
    async fn a_choice_reaches_every_clone_of_the_endpoint() {
        // The app hands clones of one endpoint to different tasks; a settings
        // change has to reach whichever one dials next.
        let a = Endpoint::bind_all(Arc::new(Identity::generate().unwrap()), "a", 0).unwrap();
        let b = a.clone();
        a.set_remote_congestion(RemoteCongestion::Bbr);
        assert_eq!(b.remote_congestion(), RemoteCongestion::Bbr);
        b.set_remote_congestion(RemoteCongestion::Standard);
        assert_eq!(a.remote_congestion(), RemoteCongestion::Standard);
    }

    /// quinn labels its BBR experimental, so a config that merely builds is not
    /// enough evidence. This pushes real data through it end to end and checks
    /// that every byte arrives, in order.
    #[tokio::test]
    async fn bbr_carries_a_real_stream_intact() {
        const SIZE: usize = 24 * 1024 * 1024;

        let listener = Endpoint::bind_all(Arc::new(Identity::generate().unwrap()), "listener", 0).unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));

        let receiving = tokio::spawn(async move {
            let session = listener.accept().await.unwrap().unwrap();
            let (_send, mut recv) = session.accept_stream().await.unwrap();
            let mut got = Vec::with_capacity(SIZE);
            let mut buffer = vec![0u8; 64 * 1024];
            while let Some(n) = recv.read(&mut buffer).await.unwrap() {
                got.extend_from_slice(&buffer[..n]);
            }
            (listener, session, got)
        });

        let dialer = Endpoint::bind_all(Arc::new(Identity::generate().unwrap()), "dialer", 0).unwrap();
        // Forced on: loopback is a LAN, so the address alone would never pick it.
        let bbr = transport_config_for(false, RemoteCongestion::Bbr);
        let session = dialer.connect_using(target, None, bbr).await.unwrap();

        let payload: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
        let (mut send, _recv) = session.open_stream().await.unwrap();
        send.write_all(&payload).await.unwrap();
        send.finish().unwrap();

        let (_listener, _session, got) =
            tokio::time::timeout(std::time::Duration::from_secs(60), receiving)
                .await
                .expect("transfer over BBR timed out")
                .unwrap();

        assert_eq!(got.len(), SIZE, "every byte must arrive");
        assert!(got == payload, "and arrive unaltered, in order");
    }

    #[test]
    fn both_choices_build_a_valid_config_for_either_kind_of_peer() {
        for lan in [true, false] {
            for remote in [RemoteCongestion::Standard, RemoteCongestion::Bbr] {
                let _ = transport_config_for(lan, remote);
            }
        }
    }
}
