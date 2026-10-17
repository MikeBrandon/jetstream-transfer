//! UDP broadcast announcements.
//!
//! The crude mechanism, kept because it is the one that works on cheap flat
//! networks and on gear that filters multicast while passing broadcast. mDNS
//! covers the opposite case; running both is how the peer list stops being
//! empty.
//!
//! Announcements are unauthenticated and unencrypted by nature — they go to
//! every host on the segment. They therefore contain nothing sensitive: a
//! device id (public by design), a display name, and a port. Anyone can forge
//! one, which is exactly why the identity is re-established over TLS before a
//! byte of file data moves.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use jetstream_core::DeviceId;
use jetstream_core::proto::sanitize_name;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;

use crate::{ANNOUNCE_INTERVAL, DISCOVERY_PORT, SharedRegistry, Sighting, Source};

/// Announcements are tiny; anything larger is not ours.
const MAX_ANNOUNCE: usize = 512;

/// Rejects stray traffic on a shared port before we try to decode it.
const MAGIC: [u8; 4] = *b"JSTR";

const ANNOUNCE_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Announce {
    magic: [u8; 4],
    version: u16,
    device_id: DeviceId,
    name: String,
    /// Transfer port, which is not the port this announcement arrived on.
    port: u16,
}

fn encode_announce(device_id: DeviceId, name: &str, port: u16) -> std::io::Result<Vec<u8>> {
    postcard::to_stdvec(&Announce {
        magic: MAGIC,
        version: ANNOUNCE_VERSION,
        device_id,
        name: sanitize_name(name),
        port,
    })
    .map_err(std::io::Error::other)
}

/// Broadcast announcer and listener.
pub struct Broadcaster {
    socket: Arc<UdpSocket>,
    /// The encoded announcement. Behind a lock so a rename takes effect on the
    /// next round rather than at the next launch.
    announce: std::sync::RwLock<Vec<u8>>,
    device_id: DeviceId,
    transfer_port: u16,
}

impl Broadcaster {
    /// Bind the discovery socket.
    ///
    /// `SO_REUSEADDR` lets a second instance start on the same machine — which
    /// happens constantly during testing and whenever the app restarts before
    /// the old socket has drained — instead of failing with "address in use".
    pub fn bind(device_id: DeviceId, name: &str, transfer_port: u16) -> std::io::Result<Self> {
        use socket2::{Domain, Protocol, Socket, Type};

        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        socket.set_broadcast(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, DISCOVERY_PORT)).into())?;

        let socket = Arc::new(UdpSocket::from_std(socket.into())?);

        let announce = encode_announce(device_id, name, transfer_port)?;

        Ok(Self {
            socket,
            announce: std::sync::RwLock::new(announce),
            device_id,
            transfer_port,
        })
    }

    /// Announce a new display name from the next round on.
    pub fn rename(&self, name: &str) {
        match encode_announce(self.device_id, name, self.transfer_port) {
            Ok(encoded) => *self.announce.write().expect("announce poisoned") = encoded,
            Err(e) => tracing::warn!(error = %e, "could not encode the renamed announcement"),
        }
    }

    /// Announce ourselves periodically until the task is dropped.
    pub async fn announce_forever(&self) {
        let mut ticker = tokio::time::interval(ANNOUNCE_INTERVAL);
        // A missed tick should not cause a burst of catch-up announcements.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;
            self.announce_once().await;
        }
    }

    /// Send one round of announcements, once out of every interface we have.
    ///
    /// Sending is done from a socket **bound to each interface's own address**,
    /// not from the shared receive socket. Choosing the source address is what
    /// chooses the egress interface; letting the routing table decide sends one
    /// datagram out one adapter and silently strands every other network.
    ///
    /// Destination-based addressing is not sufficient on its own. Windows hands
    /// APIPA addresses to every adapter that has no DHCP lease — a Bluetooth PAN,
    /// an empty Hyper-V switch, a VPN client, *and* a real direct-cable link all
    /// land inside `169.254.0.0/16`. They share one broadcast address, so a
    /// single directed broadcast reaches whichever the routing table prefers and
    /// misses the rest. Per-interface sockets are the only way to cover them.
    ///
    /// The sockets are rebuilt every round rather than cached, which costs a few
    /// microseconds and means a cable being plugged in, a VPN connecting, or an
    /// adapter changing address is picked up automatically with no invalidation
    /// logic to get wrong.
    async fn announce_once(&self) {
        let announcement = self.announce.read().expect("announce poisoned").clone();
        let mut delivered = 0usize;
        let mut failures = Vec::new();

        for source in announce_sources() {
            let socket = match bind_sender(source.address) {
                Ok(socket) => socket,
                Err(e) => {
                    failures.push(format!("bind {}: {e}", source.address));
                    continue;
                }
            };

            // The directed broadcast first, then limited broadcast as a second
            // chance on the same interface: some virtual adapters accept one and
            // reject the other.
            for target in [source.broadcast, Ipv4Addr::BROADCAST] {
                match socket
                    .send_to(&announcement, SocketAddrV4::new(target, DISCOVERY_PORT))
                    .await
                {
                    Ok(_) => {
                        delivered += 1;
                        break;
                    }
                    // Normal and transient: an interface going down, or a
                    // virtual adapter that refuses broadcast entirely. Not
                    // worth alarming the user about.
                    Err(e) => failures.push(format!("{} -> {target}: {e}", source.address)),
                }
            }
        }

        if delivered == 0 {
            tracing::debug!(?failures, "no broadcast announcement could be sent");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// Listen for other devices' announcements until the task is dropped.
    pub async fn listen_forever(&self, registry: SharedRegistry) {
        let mut buffer = vec![0u8; MAX_ANNOUNCE];

        loop {
            let (len, from) = match self.socket.recv_from(&mut buffer).await {
                Ok(result) => result,
                Err(e) => {
                    tracing::debug!(error = %e, "discovery socket read failed");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };

            let Some(sighting) = self.parse(&buffer[..len], from) else {
                continue;
            };
            if registry.record(sighting) {
                tracing::debug!(%from, "found a peer by broadcast");
            }
        }
    }

    /// Decode an announcement, ignoring anything that is not a valid one from
    /// somebody else.
    fn parse(&self, bytes: &[u8], from: SocketAddr) -> Option<Sighting> {
        if bytes.len() > MAX_ANNOUNCE || !bytes.starts_with(&MAGIC) {
            return None;
        }

        let announce: Announce = postcard::from_bytes(bytes).ok()?;
        if announce.magic != MAGIC || announce.version != ANNOUNCE_VERSION {
            return None;
        }
        // Our own announcement comes back to us on the broadcast address.
        if announce.device_id == self.device_id {
            return None;
        }

        // The *source address* of the packet is authoritative for where the
        // peer is; the payload only says which port to use. A peer that could
        // name its own address could point us at a third party.
        Some(Sighting::observed(
            announce.device_id,
            sanitize_name(&announce.name),
            SocketAddr::new(from.ip(), announce.port),
            Source::Broadcast,
        ))
    }
}

/// One interface to announce from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnnounceSource {
    /// Local address to bind the sending socket to, which selects the interface.
    pub address: Ipv4Addr,
    /// That interface's subnet-directed broadcast address.
    pub broadcast: Ipv4Addr,
}

/// Every interface worth announcing from.
///
/// **This is the difference between working and not working on a real Windows
/// machine.** Sending to `255.255.255.255` from an unbound socket puts one
/// datagram on one interface, chosen by route metrics. Measured on the machine
/// this was written on, that was a Radmin VPN adapter while the actual LAN sat on
/// `Ethernet 4` — so every announcement went somewhere no peer could hear it, and
/// peers aged out of the list ~30 seconds after mDNS first found them.
///
/// Link-local (APIPA) addresses are **included**, which is not obvious. They
/// usually mean an adapter never got a DHCP lease — a Bluetooth PAN, an empty
/// Hyper-V switch, a disconnected NIC — and announcing there is wasted. But two
/// machines joined by a single cable with no DHCP server between them talk over
/// exactly these addresses, and that is a case this app has to serve: it is the
/// most direct way to move a large amount of data between two computers. A few
/// stray datagrams on idle adapters is a much smaller cost than direct-cable
/// discovery silently not working.
pub fn announce_sources() -> Vec<AnnounceSource> {
    let mut sources = Vec::new();

    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for interface in interfaces {
            // Loopback only ever reaches this machine, and we are not a peer of
            // ourselves.
            let if_addrs::IfAddr::V4(v4) = interface.addr else {
                continue;
            };
            if v4.ip.is_loopback() || v4.ip.is_unspecified() {
                continue;
            }

            // Prefer what the OS reports; fall back to deriving it from the
            // netmask, which some adapters leave unset.
            let broadcast = v4
                .broadcast
                .unwrap_or_else(|| derive_broadcast(v4.ip, v4.netmask));

            let source = AnnounceSource {
                address: v4.ip,
                broadcast,
            };

            // Deduplicated by *source*, not by destination: several adapters
            // legitimately share one broadcast address, and each still needs its
            // own datagram.
            if !sources.iter().any(|s: &AnnounceSource| s.address == v4.ip) {
                sources.push(source);
            }
        }
    }

    sources
}

/// Bind a short-lived sending socket to one interface's address.
fn bind_sender(source: Ipv4Addr) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_broadcast(true)?;
    socket.set_nonblocking(true)?;
    // Port 0: this socket only ever sends. Replies arrive on the shared
    // receive socket bound to the discovery port.
    socket.bind(&SocketAddr::from((source, 0)).into())?;

    UdpSocket::from_std(socket.into())
}

/// The broadcast address for `ip` within `netmask`: host bits all set.
fn derive_broadcast(ip: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr {
    let ip = u32::from(ip);
    let mask = u32::from(netmask);
    Ipv4Addr::from(ip | !mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(device_id: DeviceId, name: &str, port: u16) -> Vec<u8> {
        postcard::to_stdvec(&Announce {
            magic: MAGIC,
            version: ANNOUNCE_VERSION,
            device_id,
            name: name.to_string(),
            port,
        })
        .unwrap()
    }

    /// A `Broadcaster` without a socket, for exercising `parse` alone.
    fn parser(device_id: DeviceId) -> Broadcaster {
        // `bind` needs a real socket; construct the fields directly instead.
        // Non-blocking before tokio sees it: current tokio refuses to register
        // a blocking socket, and these tests failed on exactly that.
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket.set_nonblocking(true).unwrap();

        Broadcaster {
            socket: Arc::new(UdpSocket::from_std(socket).unwrap()),
            announce: std::sync::RwLock::new(Vec::new()),
            device_id,
            transfer_port: 0,
        }
    }

    #[tokio::test]
    async fn a_valid_announcement_becomes_a_sighting() {
        let us = DeviceId::from_bytes([1; 32]);
        let them = DeviceId::from_bytes([2; 32]);
        let broadcaster = parser(us);

        let from: SocketAddr = "192.168.1.50:4645".parse().unwrap();
        let sighting = broadcaster
            .parse(&encoded(them, "Laptop", 4646), from)
            .expect("should parse");

        assert_eq!(sighting.device_id, them);
        assert_eq!(sighting.name, "Laptop");
        assert_eq!(
            sighting.addresses,
            vec!["192.168.1.50:4646".parse::<SocketAddr>().unwrap()],
            "address comes from the packet source, port from the payload"
        );
    }

    #[tokio::test]
    async fn our_own_announcement_is_ignored() {
        let us = DeviceId::from_bytes([1; 32]);
        let broadcaster = parser(us);

        let from: SocketAddr = "192.168.1.50:4645".parse().unwrap();
        assert!(
            broadcaster.parse(&encoded(us, "Me", 4646), from).is_none(),
            "we must not list ourselves as a peer"
        );
    }

    #[tokio::test]
    async fn junk_on_the_port_is_ignored_without_panicking() {
        let broadcaster = parser(DeviceId::from_bytes([1; 32]));
        let from: SocketAddr = "192.168.1.50:4645".parse().unwrap();

        for junk in [
            &b""[..],
            &b"hello"[..],
            &b"HZND"[..],
            &[0xFF; 64][..],
            &vec![0u8; MAX_ANNOUNCE + 1][..],
        ] {
            assert!(broadcaster.parse(junk, from).is_none(), "junk should be ignored");
        }
    }

    #[tokio::test]
    async fn a_future_protocol_version_is_ignored() {
        let broadcaster = parser(DeviceId::from_bytes([1; 32]));
        let from: SocketAddr = "192.168.1.50:4645".parse().unwrap();

        let future = postcard::to_stdvec(&Announce {
            magic: MAGIC,
            version: ANNOUNCE_VERSION + 1,
            device_id: DeviceId::from_bytes([2; 32]),
            name: "Future".into(),
            port: 4646,
        })
        .unwrap();

        assert!(broadcaster.parse(&future, from).is_none());
    }

    #[tokio::test]
    async fn a_hostile_name_is_sanitized_before_it_reaches_the_peer_list() {
        let broadcaster = parser(DeviceId::from_bytes([1; 32]));
        let from: SocketAddr = "192.168.1.50:4645".parse().unwrap();

        let sighting = broadcaster
            .parse(
                &encoded(DeviceId::from_bytes([2; 32]), "\u{202E}evil\nname", 4646),
                from,
            )
            .unwrap();

        assert!(!sighting.name.contains('\u{202E}'));
        assert!(!sighting.name.contains('\n'));
    }

    #[test]
    fn broadcast_addresses_are_derived_from_the_netmask() {
        for (ip, mask, want) in [
            ("192.168.1.3", "255.255.255.0", "192.168.1.255"),
            ("10.0.5.20", "255.255.0.0", "10.0.255.255"),
            ("172.30.224.1", "255.255.240.0", "172.30.239.255"),
            ("26.10.20.30", "255.0.0.0", "26.255.255.255"),
        ] {
            assert_eq!(
                derive_broadcast(ip.parse().unwrap(), mask.parse().unwrap()),
                want.parse::<Ipv4Addr>().unwrap(),
                "{ip}/{mask}"
            );
        }
    }

    #[test]
    fn every_source_is_a_distinct_usable_local_address() {
        let sources = announce_sources();

        for source in &sources {
            assert!(!source.address.is_loopback(), "{:?}", source);
            assert!(!source.address.is_unspecified(), "{:?}", source);
            assert!(!source.broadcast.is_unspecified(), "{:?}", source);
        }

        let mut addresses: Vec<_> = sources.iter().map(|s| s.address).collect();
        addresses.sort();
        addresses.dedup();
        assert_eq!(
            addresses.len(),
            sources.len(),
            "one datagram per interface, not per address seen twice"
        );
    }

    /// Regression: APIPA addresses were excluded as "adapter never got a lease",
    /// which broke the direct-cable case — two machines joined by one cable with
    /// no DHCP between them communicate over exactly these addresses.
    #[test]
    fn link_local_interfaces_are_kept_as_sources() {
        let sources = announce_sources();

        // Only assert when this machine actually has one, so the test is honest
        // on hardware that does not.
        let apipa: Vec<_> = sources
            .iter()
            .filter(|s| s.address.is_link_local())
            .collect();

        if !apipa.is_empty() {
            for source in apipa {
                assert_eq!(
                    source.broadcast,
                    Ipv4Addr::new(169, 254, 255, 255),
                    "a /16 link-local subnet broadcasts to 169.254.255.255"
                );
            }
        }
    }

    /// Several adapters share `169.254.0.0/16`, so deduplicating by destination
    /// would collapse them into one and strand the rest.
    #[test]
    fn interfaces_sharing_a_broadcast_address_each_get_a_source() {
        let sources = announce_sources();
        let shared: Vec<_> = sources
            .iter()
            .filter(|s| s.broadcast == Ipv4Addr::new(169, 254, 255, 255))
            .collect();

        if shared.len() > 1 {
            let mut addresses: Vec<_> = shared.iter().map(|s| s.address).collect();
            addresses.sort();
            addresses.dedup();
            assert_eq!(
                addresses.len(),
                shared.len(),
                "each interface in the shared subnet needs its own datagram"
            );
        }
    }

    #[tokio::test]
    async fn announcements_stay_small_enough_for_one_datagram() {
        let announce = encoded(DeviceId::from_bytes([0xAB; 32]), &"n".repeat(200), 4646);
        assert!(
            announce.len() <= MAX_ANNOUNCE,
            "announcement grew to {} bytes",
            announce.len()
        );
    }
}
