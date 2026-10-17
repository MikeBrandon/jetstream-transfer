//! Finding other devices on the network, and explaining it when we cannot.
//!
//! # Why four mechanisms
//!
//! Dukto uses UDP broadcast alone, which is why it so often shows an empty
//! window: broadcast does not cross subnets, and a great many Wi-Fi networks
//! filter it outright through client isolation. Each mechanism here covers a
//! case the others miss:
//!
//! | Mechanism | Wins where |
//! |---|---|
//! | mDNS | Modern networks, mixed OS, Wi-Fi that drops broadcast |
//! | UDP broadcast | Simple flat LANs, and gear that filters multicast instead |
//! | Manual address | Different subnet, VPN, anything routed |
//! | Known-peer probe | A device you have paired with before, wherever it is |
//!
//! The last one quietly solves the cross-subnet complaint: once you have paired
//! with a device, we remember its address and contact it directly on startup
//! instead of waiting to overhear it.
//!
//! # Discovery is a hint, never a credential
//!
//! Everything on this page arrives unauthenticated. Any machine on the network
//! can broadcast any device id and any name it likes, so a peer that *appears*
//! to be your laptop may not be. That is not a flaw to fix here — it is why the
//! device id in a [`DiscoveredPeer`] is only ever used to *look up* which key to
//! pin, and why the authoritative identity comes from the TLS handshake in
//! `jetstream-core`. Never grant trust based on anything in this module.

pub mod broadcast;
pub mod diagnostics;
pub mod firewall;
pub mod linkspeed;
pub mod mdns;
pub mod netprofile;
pub mod wol;

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use jetstream_core::DeviceId;

/// DNS-SD service type. `_udp` because the transport is QUIC.
pub const SERVICE_TYPE: &str = "_jetstream._udp.local.";

/// Port for broadcast announcements.
///
/// Deliberately not the transfer port: that one is owned by the QUIC endpoint,
/// and having two sockets contend for it would be a needless source of
/// "address already in use" on startup.
pub const DISCOVERY_PORT: u16 = 4645;

/// How often we announce ourselves.
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(5);

/// A peer is dropped from the list after this long without a sighting.
///
/// Long enough to ride out a few missed announcements on a busy network, short
/// enough that a laptop that closed its lid disappears while the user is still
/// looking at the screen.
pub const PEER_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound on how long an mDNS-advertised peer may stay silent.
///
/// [`DiscoveredPeer::is_stale`] normally trusts mDNS to announce a withdrawal,
/// but that makes the peer list depend on an event arriving. If it never does —
/// a machine yanked off the network mid-flight, or a library that declines to
/// report an expiry — the entry would sit there forever, and a peer that cannot
/// be removed is worse than one removed too eagerly.
///
/// Longer than the 120-second record TTL that DNS-SD publishes with, so a peer
/// that is genuinely still there always refreshes well before this fires.
pub const MDNS_MAX_SILENCE: Duration = Duration::from_secs(150);

/// Which mechanism turned up a peer.
///
/// Kept per-peer because it is the single most useful diagnostic signal we
/// have: "mDNS found four devices and broadcast found none" says the network
/// filters broadcast, and no other check is needed to know it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {
    Mdns,
    Broadcast,
    Manual,
    Known,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Self::Mdns => "mDNS",
            Self::Broadcast => "broadcast",
            Self::Manual => "manual",
            Self::Known => "saved",
        }
    }
}

/// A device we have heard about but not yet authenticated.
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    /// **Claimed**, not proven. Use it to decide which key to pin, never to
    /// decide whether to trust.
    pub device_id: DeviceId,
    /// Peer-chosen display name, already sanitized.
    pub name: String,
    /// Everywhere we might reach it.
    pub addresses: Vec<SocketAddr>,
    /// Addresses we have actually received a packet from, or connected to.
    ///
    /// The distinction matters more than any heuristic. A machine with Hyper-V,
    /// WSL, and a VPN client advertises several perfectly plausible private
    /// addresses over mDNS — `172.31.96.1` on a virtual switch looks exactly as
    /// routable as `192.168.1.6` on the real network, and guessing wrong costs
    /// the user a connection timeout. An address a packet genuinely arrived
    /// from needs no guessing.
    pub observed: BTreeSet<SocketAddr>,
    pub sources: BTreeSet<Source>,
    pub last_seen: Instant,
    /// Whether mDNS currently advertises this device.
    ///
    /// mDNS is a *registry* with its own lifecycle, not a heartbeat: a record is
    /// published once with a long TTL, and withdrawal is announced explicitly.
    /// Ageing such a peer out on our own short clock was a bug — it deleted
    /// devices that were sitting there advertising themselves the whole time.
    pub mdns_present: bool,
}

impl DiscoveredPeer {
    /// Whether to drop this peer from the list.
    ///
    /// The two mechanisms have genuinely different liveness models, and treating
    /// them alike is what made peers vanish while still present:
    ///
    /// - **Broadcast** is a heartbeat every [`ANNOUNCE_INTERVAL`]. Silence for
    ///   [`PEER_TIMEOUT`] means gone.
    /// - **mDNS** publishes once and announces withdrawal. Present until it says
    ///   otherwise — bounded by [`MDNS_MAX_SILENCE`] so a withdrawal that never
    ///   arrives cannot strand the entry permanently.
    pub fn is_stale(&self, now: Instant) -> bool {
        let silence = now.duration_since(self.last_seen);
        if self.mdns_present {
            silence > MDNS_MAX_SILENCE
        } else {
            silence > PEER_TIMEOUT
        }
    }

    /// Best address to dial.
    ///
    /// A Windows machine typically has several addresses — Wi-Fi, Ethernet, and
    /// a stack of virtual adapters from VPN clients and hypervisors — and
    /// advertises all of them. Picking the first IPv4 is not good enough: an
    /// idle VPN adapter hands out a `169.254.x.x` APIPA address that looks
    /// perfectly valid and goes nowhere, and putting it first means the user
    /// clicks a peer and waits for a timeout.
    ///
    /// So addresses are ranked: proven-reachable first, then by plausibility.
    /// Even then the ranking is only a *starting order* — callers should walk
    /// [`DiscoveredPeer::addresses_by_preference`] and use the first that
    /// answers, because no heuristic can beat actually trying.
    pub fn best_address(&self) -> Option<SocketAddr> {
        self.addresses_by_preference().first().copied()
    }

    /// Every address, best first.
    ///
    /// A device with both Wi-Fi and Ethernet is reachable at either, so falling
    /// through the list is the correct dialling strategy.
    pub fn addresses_by_preference(&self) -> Vec<SocketAddr> {
        let mut addresses = self.addresses.clone();
        addresses.sort_by_key(|address| {
            // Observed normally beats every heuristic: a packet came from there,
            // so no guessing is needed.
            //
            // Except for APIPA, where it proves less than it appears to. A
            // `169.254.x.x` address says nothing about *which interface* reaches
            // it, and on a machine where several adapters claim `169.254.0.0/16`
            // — a VPN client, a Bluetooth PAN, an idle NIC — the routing table
            // picks by metric and can easily pick the wrong one. Measured on a
            // real pair of machines joined by a direct cable: the peer's APIPA
            // address routed out a Tailscale adapter (metric 261) instead of the
            // Ethernet carrying the traffic (metric 281), so every packet
            // vanished while broadcasts still arrived *from* that address
            // perfectly well.
            //
            // Receiving from an address proves the peer can reach us. It does not
            // prove we can reach the peer, and for APIPA those differ.
            //
            // Nor for a tunnelled IPv6 address, for a different reason: it is
            // reachable, just badly. One transfer that succeeds over Teredo marks
            // it observed, and without this it would then outrank a perfectly
            // good VPN address on every attempt after — a slow path that, once
            // chosen, chooses itself for ever.
            let trustworthy = self.observed.contains(address)
                && !is_apipa(address)
                && !is_tunnelled(address);
            (!trustworthy, address_rank(address))
        });
        addresses
    }
}

/// A self-assigned IPv4 address, handed out when there is no DHCP server.
///
/// Genuinely useful — two machines on a direct cable really do talk over these —
/// but ambiguous, because every adapter without a lease picks from the same
/// `169.254.0.0/16` and nothing in the address says which one is meant.
fn is_apipa(address: &SocketAddr) -> bool {
    matches!(address.ip(), std::net::IpAddr::V4(v4) if v4.is_link_local())
}

/// Lower is better. See [`DiscoveredPeer::best_address`].
fn address_rank(address: &SocketAddr) -> u8 {
    use std::net::IpAddr;

    // A link-local IPv6 address carrying a scope id names its interface exactly,
    // which makes it *more* dependable than an APIPA address that names none.
    // Ranked above APIPA for that reason, and above an unscoped `fe80::`, which
    // cannot be sent anywhere at all.
    if let IpAddr::V6(v6) = address.ip()
        && is_ipv6_link_local(&v6)
    {
        let scoped = matches!(address, SocketAddr::V6(v6) if v6.scope_id() != 0);
        return if scoped { 3 } else { 6 };
    }

    // Teredo and 6to4: IPv6 carried inside IPv4 by a transition mechanism, not
    // a real IPv6 path. They look like ordinary global addresses, which is the
    // problem — ranked as such they beat VPN addresses, and a transfer between
    // two machines on Radmin was measured running entirely through Teredo
    // (Microsoft's relay, behind a symmetric NAT) while the Radmin adapter sat
    // idle. Last of everything that can actually deliver a packet: below APIPA,
    // which is fast when it works, and above only an unscoped `fe80::`, which
    // cannot be sent anywhere.
    if is_tunnelled(address) {
        return 5;
    }

    match address.ip() {
        // Ordinary LAN addresses: 192.168/16, 10/8, 172.16/12. What a real
        // home or office network hands out, and what we want almost always.
        IpAddr::V4(v4) if v4.is_private() => 0,
        // A routable IPv4. Unusual on a LAN but genuinely reachable.
        IpAddr::V4(v4) if !v4.is_link_local() && !v4.is_loopback() => 1,
        // Global IPv6.
        IpAddr::V6(v6) if !is_ipv6_link_local(&v6) && !v6.is_loopback() => 2,
        // IPv6 link-local. Works, but needs a scope id to be useful.
        IpAddr::V6(_) => 3,
        // APIPA. Handed out by adapters with no DHCP — idle VPN clients,
        // disconnected NICs, hypervisor switches. Almost never reachable.
        IpAddr::V4(_) => 4,
    }
}

fn is_ipv6_link_local(address: &std::net::Ipv6Addr) -> bool {
    address.segments()[0] & 0xffc0 == 0xfe80
}

/// An IPv6 address that is really IPv4 underneath.
///
/// - **Teredo**, `2001:0000::/32` — tunnels through UDP via Microsoft's relays,
///   and Windows enables it by default, so most machines have one.
/// - **6to4**, `2002::/16` — the same idea through public relay routers, long
///   deprecated but still configured on some systems.
///
/// Both work, slowly and erratically, and neither is what anyone means by an
/// IPv6 connection.
pub fn is_tunnelled_ipv6(address: &std::net::Ipv6Addr) -> bool {
    let segments = address.segments();
    (segments[0] == 0x2001 && segments[1] == 0x0000) || segments[0] == 0x2002
}

fn is_tunnelled(address: &SocketAddr) -> bool {
    matches!(address.ip(), std::net::IpAddr::V6(v6) if is_tunnelled_ipv6(&v6))
}

/// A sighting reported by one of the mechanisms.
#[derive(Debug, Clone)]
pub struct Sighting {
    pub device_id: DeviceId,
    pub name: String,
    pub addresses: Vec<SocketAddr>,
    pub source: Source,
    /// True when `addresses` came from where a packet actually originated,
    /// rather than from what the peer claimed about itself. Broadcast and a
    /// completed connection are observed; mDNS records are claims.
    pub observed: bool,
}

impl Sighting {
    /// A sighting from a place we genuinely received traffic from.
    pub fn observed(device_id: DeviceId, name: String, address: SocketAddr, source: Source) -> Self {
        Self {
            device_id,
            name,
            addresses: vec![address],
            source,
            observed: true,
        }
    }

    /// A sighting assembled from a peer's own advertisement.
    pub fn claimed(
        device_id: DeviceId,
        name: String,
        addresses: Vec<SocketAddr>,
        source: Source,
    ) -> Self {
        Self {
            device_id,
            name,
            addresses,
            source,
            observed: false,
        }
    }
}

/// The merged view of who is out there.
///
/// Merging by device id rather than by address is what makes a device appear
/// once in the UI when mDNS, broadcast, and a saved address all find it — and
/// what lets a laptop keep its place in the list when it moves from Ethernet
/// to Wi-Fi.
#[derive(Debug, Default)]
pub struct Registry {
    peers: Mutex<HashMap<DeviceId, DiscoveredPeer>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a sighting. Returns `true` if this was a peer we had not seen.
    pub fn record(&self, sighting: Sighting) -> bool {
        let mut peers = self.peers.lock().expect("registry mutex poisoned");
        let now = Instant::now();

        match peers.get_mut(&sighting.device_id) {
            Some(existing) => {
                existing.last_seen = now;
                existing.sources.insert(sighting.source);
                if sighting.source == Source::Mdns {
                    existing.mdns_present = true;
                }

                // The freshest name wins: a user who renames their machine
                // should see it update rather than keep the stale label.
                if !sighting.name.is_empty() {
                    existing.name = sighting.name;
                }

                for address in sighting.addresses {
                    if !existing.addresses.contains(&address) {
                        existing.addresses.push(address);
                    }
                    if sighting.observed {
                        existing.observed.insert(address);
                    }
                }
                false
            }
            None => {
                let observed = if sighting.observed {
                    sighting.addresses.iter().copied().collect()
                } else {
                    BTreeSet::new()
                };

                peers.insert(
                    sighting.device_id,
                    DiscoveredPeer {
                        device_id: sighting.device_id,
                        name: sighting.name,
                        addresses: sighting.addresses,
                        observed,
                        sources: BTreeSet::from([sighting.source]),
                        last_seen: now,
                        mdns_present: sighting.source == Source::Mdns,
                    },
                );
                true
            }
        }
    }

    /// mDNS says this device withdrew its advertisement, or its record expired.
    ///
    /// Does not remove the peer outright: broadcast or a saved address may still
    /// be vouching for it, and a device reachable by one mechanism should not
    /// disappear because another lost sight of it. Clearing the flag simply lets
    /// the ordinary [`PEER_TIMEOUT`] apply again.
    pub fn mdns_withdrawn(&self, device_id: &DeviceId) {
        let mut peers = self.peers.lock().expect("registry mutex poisoned");
        if let Some(peer) = peers.get_mut(device_id) {
            peer.mdns_present = false;
            peer.sources.remove(&Source::Mdns);
        }
    }

    pub fn forget(&self, device_id: &DeviceId) {
        self.peers
            .lock()
            .expect("registry mutex poisoned")
            .remove(device_id);
    }

    /// Drop peers not seen recently. Returns how many were removed.
    pub fn expire(&self) -> usize {
        let mut peers = self.peers.lock().expect("registry mutex poisoned");
        let now = Instant::now();
        let before = peers.len();
        peers.retain(|_, peer| !peer.is_stale(now));
        before - peers.len()
    }

    /// Everyone currently visible, sorted by name for a stable UI ordering.
    pub fn peers(&self) -> Vec<DiscoveredPeer> {
        let mut peers: Vec<_> = self
            .peers
            .lock()
            .expect("registry mutex poisoned")
            .values()
            .cloned()
            .collect();

        peers.sort_by(|a, b| a.name.cmp(&b.name).then(a.device_id.cmp(&b.device_id)));
        peers
    }

    pub fn get(&self, device_id: &DeviceId) -> Option<DiscoveredPeer> {
        self.peers
            .lock()
            .expect("registry mutex poisoned")
            .get(device_id)
            .cloned()
    }

    pub fn len(&self) -> usize {
        self.peers.lock().expect("registry mutex poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How many peers each mechanism contributed.
    ///
    /// The input to [`diagnostics`]: a mechanism that found nothing while
    /// another found several is being filtered by the network.
    pub fn counts_by_source(&self) -> HashMap<Source, usize> {
        let peers = self.peers.lock().expect("registry mutex poisoned");
        let mut counts = HashMap::new();

        for peer in peers.values() {
            for &source in &peer.sources {
                *counts.entry(source).or_insert(0) += 1;
            }
        }
        counts
    }
}

/// Shared handle to the merged peer list.
pub type SharedRegistry = Arc<Registry>;

/// Runs every discovery mechanism and keeps the registry current.
///
/// Each mechanism runs in its own task and is expected to fail independently —
/// mDNS refusing to start on a locked-down machine must not stop broadcast, and
/// neither failing must stop the app. That is why nothing here returns an error
/// once started: a mechanism that cannot run simply contributes nothing, and
/// [`diagnostics`] reports the shortfall.
pub struct Discovery {
    registry: SharedRegistry,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    /// Held so the advertisement is withdrawn on drop, and for renaming.
    mdns: Option<Arc<mdns::Mdns>>,
    broadcaster: Option<Arc<broadcast::Broadcaster>>,
}

impl Discovery {
    /// Start advertising and browsing.
    pub fn start(device_id: DeviceId, name: &str, transfer_port: u16) -> Self {
        let registry: SharedRegistry = Arc::new(Registry::new());
        let mut tasks = Vec::new();

        let mdns = match mdns::Mdns::start(device_id, name, transfer_port) {
            Ok(mdns) => {
                let mdns = Arc::new(mdns);
                let browsing = Arc::clone(&mdns);
                let into = Arc::clone(&registry);
                tasks.push(tokio::spawn(async move {
                    browsing.browse_forever(into).await;
                }));
                Some(mdns)
            }
            Err(e) => {
                tracing::warn!(error = %e, "mDNS unavailable; falling back to broadcast only");
                None
            }
        };

        let broadcaster = match broadcast::Broadcaster::bind(device_id, name, transfer_port) {
            Ok(broadcaster) => {
                let broadcaster = Arc::new(broadcaster);

                let announcing = Arc::clone(&broadcaster);
                tasks.push(tokio::spawn(async move {
                    announcing.announce_forever().await;
                }));

                let listening = Arc::clone(&broadcaster);
                let into = Arc::clone(&registry);
                tasks.push(tokio::spawn(async move {
                    listening.listen_forever(into).await;
                }));
                Some(broadcaster)
            }
            Err(e) => {
                tracing::warn!(error = %e, "UDP broadcast unavailable; relying on mDNS only");
                None
            }
        };

        // Expire stale peers so the list reflects who is actually there.
        let expiring = Arc::clone(&registry);
        tasks.push(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(5));
            loop {
                ticker.tick().await;
                let gone = expiring.expire();
                if gone > 0 {
                    tracing::debug!(gone, "dropped peers that stopped announcing");
                }
            }
        }));

        Self {
            registry,
            tasks,
            mdns,
            broadcaster,
        }
    }

    /// Announce a new display name, without restarting anything.
    pub fn rename(&self, name: &str) {
        if let Some(broadcaster) = &self.broadcaster {
            broadcaster.rename(name);
        }
        if let Some(mdns) = &self.mdns {
            mdns.rename(name);
        }
    }

    pub fn registry(&self) -> &SharedRegistry {
        &self.registry
    }

    pub fn peers(&self) -> Vec<DiscoveredPeer> {
        self.registry.peers()
    }

    /// Record a peer whose identity we proved by connecting to it.
    ///
    /// Unlike a discovery sighting, this device id *was* verified — the caller
    /// completed a handshake. Marking the source lets the diagnostics tell
    /// "reachable but silent" apart from "not there at all".
    pub fn note_reachable(&self, device_id: DeviceId, name: String, address: SocketAddr, saved: bool) {
        self.registry.record(Sighting::observed(
            device_id,
            name,
            address,
            if saved { Source::Known } else { Source::Manual },
        ));
    }

    pub fn diagnose(&self) -> diagnostics::Report {
        diagnostics::diagnose(&self.registry)
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn device(byte: u8) -> DeviceId {
        DeviceId::from_bytes([byte; 32])
    }

    fn sighting(byte: u8, name: &str, port: u16, source: Source) -> Sighting {
        Sighting::claimed(
            device(byte),
            name.to_string(),
            vec![SocketAddr::from((Ipv4Addr::new(192, 168, 1, byte), port))],
            source,
        )
    }

    #[test]
    fn a_new_peer_is_recorded_once() {
        let registry = Registry::new();

        assert!(registry.record(sighting(1, "Laptop", 4646, Source::Mdns)));
        assert!(!registry.record(sighting(1, "Laptop", 4646, Source::Mdns)));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn one_device_found_by_several_mechanisms_appears_once() {
        // The property that keeps the UI honest: a device on the same network
        // is usually found three ways and must still be one tile.
        let registry = Registry::new();

        registry.record(sighting(7, "Studio", 4646, Source::Mdns));
        registry.record(sighting(7, "Studio", 4646, Source::Broadcast));
        registry.record(sighting(7, "Studio", 4646, Source::Known));

        assert_eq!(registry.len(), 1);
        let peer = registry.get(&device(7)).unwrap();
        assert_eq!(
            peer.sources,
            BTreeSet::from([Source::Mdns, Source::Broadcast, Source::Known])
        );
        assert_eq!(peer.addresses.len(), 1, "the same address must not be duplicated");
    }

    #[test]
    fn a_device_that_moves_networks_keeps_its_identity_and_gains_an_address() {
        let registry = Registry::new();
        registry.record(sighting(3, "Laptop", 4646, Source::Mdns));

        // Same device, new interface.
        registry.record(Sighting::claimed(
            device(3),
            "Laptop".into(),
            vec![SocketAddr::from((Ipv4Addr::new(10, 0, 0, 5), 4646))],
            Source::Mdns,
        ));

        assert_eq!(registry.len(), 1);
        assert_eq!(registry.get(&device(3)).unwrap().addresses.len(), 2);
    }

    #[test]
    fn a_renamed_device_shows_its_new_name() {
        let registry = Registry::new();
        registry.record(sighting(4, "Old Name", 4646, Source::Mdns));
        registry.record(sighting(4, "New Name", 4646, Source::Mdns));

        assert_eq!(registry.get(&device(4)).unwrap().name, "New Name");
    }

    /// Regression, found on a real two-machine network: both PCs saw each other
    /// on startup, then the peer vanished about 30 seconds later while still
    /// sitting there advertising itself. mDNS resolves once and republishes on a
    /// ~120 s TTL, so nothing refreshed `last_seen` inside our own 30 s window,
    /// and the peer was expired for being quiet when it had never left.
    #[test]
    fn an_mdns_peer_is_not_expired_for_being_quiet() {
        let registry = Registry::new();
        registry.record(sighting(1, "Advertising", 4646, Source::Mdns));

        // Well past PEER_TIMEOUT.
        let long_ago = Instant::now() - (PEER_TIMEOUT * 4);
        registry
            .peers
            .lock()
            .unwrap()
            .get_mut(&device(1))
            .unwrap()
            .last_seen = long_ago;

        assert_eq!(registry.expire(), 0, "mDNS says it is still there");
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn an_mdns_peer_cannot_linger_for_ever_without_a_withdrawal() {
        // Guards the one way the new rule could fail badly: if the removal event
        // never arrives, the entry must still eventually go.
        let registry = Registry::new();
        registry.record(sighting(1, "Ghost", 4646, Source::Mdns));

        registry
            .peers
            .lock()
            .unwrap()
            .get_mut(&device(1))
            .unwrap()
            .last_seen = Instant::now() - (MDNS_MAX_SILENCE * 2);

        assert_eq!(registry.expire(), 1, "silence beyond the bound wins");
    }

    #[test]
    fn withdrawing_an_mdns_advert_lets_the_peer_expire_again() {
        let registry = Registry::new();
        registry.record(sighting(1, "Leaving", 4646, Source::Mdns));

        let long_ago = Instant::now() - (PEER_TIMEOUT * 4);
        registry
            .peers
            .lock()
            .unwrap()
            .get_mut(&device(1))
            .unwrap()
            .last_seen = long_ago;

        registry.mdns_withdrawn(&device(1));
        assert_eq!(registry.expire(), 1, "nothing vouches for it now");
        assert!(registry.is_empty());
    }

    #[test]
    fn a_withdrawn_advert_keeps_a_peer_that_broadcast_still_sees() {
        // Losing one mechanism must not remove a device another can still
        // reach — the whole point of merging sources into one entry.
        let registry = Registry::new();
        registry.record(sighting(1, "Both", 4646, Source::Mdns));
        registry.record(sighting(1, "Both", 4646, Source::Broadcast));

        registry.mdns_withdrawn(&device(1));

        assert_eq!(registry.expire(), 0, "broadcast heard it moments ago");
        let peer = registry.get(&device(1)).unwrap();
        assert!(!peer.mdns_present);
        assert!(
            peer.sources.contains(&Source::Broadcast),
            "the surviving mechanism must still be credited"
        );
    }

    #[test]
    fn a_broadcast_only_peer_still_expires_on_silence() {
        // The heartbeat model must keep working: a machine that closed its lid
        // should leave the list while the user is still looking at it.
        let registry = Registry::new();
        registry.record(sighting(1, "Gone", 4646, Source::Broadcast));

        registry
            .peers
            .lock()
            .unwrap()
            .get_mut(&device(1))
            .unwrap()
            .last_seen = Instant::now() - (PEER_TIMEOUT * 2);

        assert_eq!(registry.expire(), 1);
    }

    #[test]
    fn ipv4_is_preferred_when_dialling() {
        let peer = DiscoveredPeer {
            device_id: device(1),
            name: "Mixed".into(),
            addresses: vec![
                SocketAddr::from((Ipv6Addr::LOCALHOST, 4646)),
                SocketAddr::from((Ipv4Addr::new(192, 168, 1, 9), 4646)),
            ],
            observed: BTreeSet::new(),
            sources: BTreeSet::from([Source::Mdns]),
            last_seen: Instant::now(),
            mdns_present: true,
        };

        assert_eq!(
            peer.best_address(),
            Some(SocketAddr::from((Ipv4Addr::new(192, 168, 1, 9), 4646)))
        );
    }

    /// Regression: on a machine with VPN and hypervisor adapters, an idle
    /// adapter's APIPA address was advertised alongside the real LAN one and
    /// got picked first, so clicking the peer just timed out.
    #[test]
    fn a_dead_apipa_address_never_wins_over_a_real_lan_address() {
        let peer = DiscoveredPeer {
            device_id: device(1),
            name: "Many Adapters".into(),
            addresses: vec![
                // Order as an adapter enumeration would produce it: junk first.
                SocketAddr::from((Ipv4Addr::new(169, 254, 83, 107), 4646)),
                SocketAddr::from((Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 4646)),
                SocketAddr::from((Ipv4Addr::new(192, 168, 1, 6), 4646)),
            ],
            observed: BTreeSet::new(),
            sources: BTreeSet::from([Source::Mdns]),
            last_seen: Instant::now(),
            mdns_present: true,
        };

        assert_eq!(
            peer.best_address(),
            Some(SocketAddr::from((Ipv4Addr::new(192, 168, 1, 6), 4646))),
            "the routable LAN address must win"
        );

        // Nothing is discarded — every address stays available as a fallback,
        // ordered worst-last. An unscoped `fe80::` sorts below even APIPA,
        // because APIPA might reach the peer and an address with no scope id
        // cannot be sent anywhere at all.
        let ordered = peer.addresses_by_preference();
        assert!(ordered[0].ip().to_string().starts_with("192.168"));
        assert_eq!(ordered[1].ip().to_string(), "169.254.83.107");
        assert_eq!(ordered.last().unwrap().ip().to_string(), "fe80::1");
    }

    /// Regression from a real transfer between two machines on Radmin VPN.
    ///
    /// The Radmin adapter carried under 1.5 KB/s while Windows' Teredo tunnel
    /// carried the whole transfer at ~1 MB/s, behind a symmetric NAT. The
    /// sender had ranked the receiver's Teredo address — `2001:0::/32`, which
    /// looks like ordinary global IPv6 — above its Radmin address.
    #[test]
    fn a_vpn_address_beats_a_teredo_address_even_once_teredo_has_worked() {
        let radmin = SocketAddr::from((Ipv4Addr::new(26, 238, 192, 96), 4646));
        let teredo: SocketAddr = "[2001:0:14c9:d700:476:233b:992e:c79d]:4646".parse().unwrap();

        let peer = DiscoveredPeer {
            device_id: device(1),
            name: "Friend".into(),
            addresses: vec![teredo, radmin],
            // The worst case: Teredo already carried a transfer, so it is
            // observed, while the Radmin address is only claimed.
            observed: BTreeSet::from([teredo]),
            sources: BTreeSet::from([Source::Mdns, Source::Known]),
            last_seen: Instant::now(),
            mdns_present: true,
        };

        assert_eq!(
            peer.best_address(),
            Some(radmin),
            "a tunnel through Microsoft's relays must not beat the VPN"
        );
        assert!(
            peer.addresses_by_preference().contains(&teredo),
            "still kept as a last resort — some peers have nothing else"
        );
    }

    #[test]
    fn tunnelled_ipv6_is_recognised_and_real_ipv6_is_not() {
        use std::net::Ipv6Addr;
        let parse = |s: &str| s.parse::<Ipv6Addr>().unwrap();

        // Teredo and 6to4.
        assert!(is_tunnelled_ipv6(&parse("2001:0:14c9:d700:476:233b:992e:c79d")));
        assert!(is_tunnelled_ipv6(&parse("2002:c000:204::1")));

        // Ordinary global IPv6 — including other 2001: blocks, which is the trap:
        // only 2001:0000::/32 is Teredo, not everything starting 2001.
        assert!(!is_tunnelled_ipv6(&parse("2001:db8::1")));
        assert!(!is_tunnelled_ipv6(&parse("2001:4860:4860::8888")));
        assert!(!is_tunnelled_ipv6(&parse("2606:4700:4700::1111")));
        assert!(!is_tunnelled_ipv6(&parse("fe80::1")));
    }

    #[test]
    fn a_tunnel_ranks_below_everything_that_can_really_deliver() {
        let teredo: SocketAddr = "[2001:0:14c9:d700::1]:4646".parse().unwrap();
        let six_to_four: SocketAddr = "[2002:c000:204::1]:4646".parse().unwrap();
        let real_v6: SocketAddr = "[2606:4700::1]:4646".parse().unwrap();
        let apipa = SocketAddr::from((Ipv4Addr::new(169, 254, 1, 2), 4646));
        let unscoped: SocketAddr = "[fe80::1]:4646".parse().unwrap();

        for tunnel in [teredo, six_to_four] {
            assert!(address_rank(&real_v6) < address_rank(&tunnel), "real IPv6 beats {tunnel}");
            assert!(address_rank(&apipa) < address_rank(&tunnel), "APIPA beats {tunnel}");
            // But a tunnel can deliver; an unscoped fe80 cannot be sent at all.
            assert!(address_rank(&tunnel) < address_rank(&unscoped));
        }
    }

    /// Regression from a direct-cable failure where every address timed out.
    ///
    /// Two machines, one Ethernet cable, no DHCP. The peer offered an APIPA
    /// address and two `fe80::` ones. The APIPA address had been *observed* (its
    /// broadcasts arrived fine) so it was tried first — and routed out a Tailscale
    /// adapter, because that adapter's metric beat the Ethernet's on the shared
    /// `169.254.0.0/16`. The scoped IPv6 address that did work was tried last.
    #[test]
    fn a_scoped_link_local_ipv6_beats_an_observed_apipa_address() {
        let apipa = SocketAddr::from((Ipv4Addr::new(169, 254, 120, 215), 4646));
        let scoped = SocketAddr::V6(std::net::SocketAddrV6::new(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0x46e5, 0x18b0, 0xceb, 0x6116),
            4646,
            0,
            8,
        ));

        let peer = DiscoveredPeer {
            device_id: device(1),
            name: "Direct Cable".into(),
            addresses: vec![apipa, scoped],
            // The APIPA address really was seen — and is still the wrong choice.
            observed: BTreeSet::from([apipa]),
            sources: BTreeSet::from([Source::Broadcast, Source::Mdns]),
            last_seen: Instant::now(),
            mdns_present: true,
        };

        assert_eq!(
            peer.best_address(),
            Some(scoped),
            "a scope id names the interface exactly; an APIPA address names none"
        );
        // Still tried, just not first: it is the only option on some networks.
        assert!(peer.addresses_by_preference().contains(&apipa));
    }

    #[test]
    fn an_unscoped_link_local_ipv6_is_the_last_resort() {
        // Without a scope id the kernel cannot send it anywhere, so it must never
        // be preferred over something that might work.
        let unscoped = SocketAddr::from((Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 4646));
        let apipa = SocketAddr::from((Ipv4Addr::new(169, 254, 1, 2), 4646));

        assert!(
            address_rank(&unscoped) > address_rank(&apipa),
            "an address that cannot be routed must rank below one that can"
        );
    }

    #[test]
    fn an_apipa_only_peer_is_still_offered_rather_than_hidden() {
        // Two machines on a switch with no DHCP genuinely do talk over APIPA.
        let peer = DiscoveredPeer {
            device_id: device(1),
            name: "Direct Cable".into(),
            addresses: vec![SocketAddr::from((Ipv4Addr::new(169, 254, 1, 2), 4646))],
            observed: BTreeSet::new(),
            sources: BTreeSet::from([Source::Mdns]),
            last_seen: Instant::now(),
            mdns_present: true,
        };

        assert!(peer.best_address().is_some());
    }

    #[test]
    fn an_ipv6_only_peer_is_still_reachable() {
        let peer = DiscoveredPeer {
            device_id: device(1),
            name: "V6".into(),
            addresses: vec![SocketAddr::from((Ipv6Addr::LOCALHOST, 4646))],
            observed: BTreeSet::new(),
            sources: BTreeSet::from([Source::Mdns]),
            last_seen: Instant::now(),
            mdns_present: true,
        };

        assert!(peer.best_address().is_some());
    }

    #[test]
    fn source_counts_reveal_a_filtered_mechanism() {
        let registry = Registry::new();
        for byte in 1..=3 {
            registry.record(sighting(byte, "Peer", 4646, Source::Mdns));
        }

        let counts = registry.counts_by_source();
        assert_eq!(counts.get(&Source::Mdns), Some(&3));
        assert_eq!(
            counts.get(&Source::Broadcast),
            None,
            "broadcast found nothing while mDNS found three — the signature of a filtered network"
        );
    }

    #[test]
    fn peers_are_listed_in_a_stable_order() {
        let registry = Registry::new();
        registry.record(sighting(3, "Zeta", 4646, Source::Mdns));
        registry.record(sighting(1, "Alpha", 4646, Source::Mdns));
        registry.record(sighting(2, "Mid", 4646, Source::Mdns));

        let names: Vec<String> = registry.peers().into_iter().map(|p| p.name).collect();
        assert_eq!(names, ["Alpha", "Mid", "Zeta"]);
    }

    #[test]
    fn forgetting_removes_a_peer() {
        let registry = Registry::new();
        registry.record(sighting(1, "Gone", 4646, Source::Manual));
        registry.forget(&device(1));

        assert!(registry.is_empty());
    }

    #[test]
    fn fresh_peers_are_not_expired() {
        let registry = Registry::new();
        registry.record(sighting(1, "Here", 4646, Source::Mdns));

        assert_eq!(registry.expire(), 0);
        assert_eq!(registry.len(), 1);
    }
}
