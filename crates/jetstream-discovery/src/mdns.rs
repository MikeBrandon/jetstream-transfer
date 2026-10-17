//! mDNS / DNS-SD advertisement and browsing.
//!
//! The mechanism that works on the networks broadcast does not: modern Wi-Fi
//! access points, mixed-OS environments, and anything where multicast is
//! forwarded but broadcast is filtered. It is also what makes a Jetstream
//! device visible to standard service-discovery tooling, which is useful when
//! debugging why two machines cannot see each other.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Mutex;

use jetstream_core::DeviceId;
use jetstream_core::proto::sanitize_name;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::{SERVICE_TYPE, SharedRegistry, Sighting, Source};

/// TXT record keys. Short because a TXT record is size-constrained.
const TXT_DEVICE_ID: &str = "id";
const TXT_NAME: &str = "n";

/// mDNS advertiser and browser.
pub struct Mdns {
    daemon: ServiceDaemon,
    fullname: String,
    device_id: DeviceId,
    transfer_port: u16,
    /// Which device each advertisement belongs to.
    ///
    /// `ServiceRemoved` carries only the DNS-SD fullname, but the registry is
    /// keyed by device id, so the mapping has to be remembered from when the
    /// service resolved. Without it a withdrawal cannot be acted on at all.
    advertised: Mutex<HashMap<String, DeviceId>>,
}

impl Mdns {
    /// Start advertising this device and return a handle for browsing.
    pub fn start(device_id: DeviceId, name: &str, transfer_port: u16) -> Result<Self, mdns_sd::Error> {
        let daemon = ServiceDaemon::new()?;

        // Before registering, so the advertisement never goes out on them.
        exclude_tunnel_interfaces(&daemon);

        let service = advertisement(device_id, name, transfer_port)?;
        let fullname = service.get_fullname().to_string();
        daemon.register(service)?;

        Ok(Self {
            daemon,
            fullname,
            device_id,
            transfer_port,
            advertised: Mutex::new(HashMap::new()),
        })
    }

    /// Advertise a new display name. Registering the same instance again
    /// replaces the old record and announces the change.
    pub fn rename(&self, name: &str) {
        let registered = advertisement(self.device_id, name, self.transfer_port)
            .and_then(|service| self.daemon.register(service));
        if let Err(e) = registered {
            tracing::warn!(error = %e, "could not advertise the new name over mDNS");
        }
    }

    /// Browse for peers until the task is dropped.
    pub async fn browse_forever(&self, registry: SharedRegistry) {
        let receiver = match self.daemon.browse(SERVICE_TYPE) {
            Ok(receiver) => receiver,
            Err(e) => {
                tracing::warn!(error = %e, "could not start mDNS browsing");
                return;
            }
        };

        loop {
            // `flume`'s async receiver keeps this off the runtime's blocking
            // pool, which matters because this task lives for the whole session.
            let event = match receiver.recv_async().await {
                Ok(event) => event,
                Err(_) => return, // daemon shut down
            };

            match event {
                ServiceEvent::ServiceResolved(service) => {
                    if let Some(sighting) = self.to_sighting(&service) {
                        self.advertised
                            .lock()
                            .expect("advertised map poisoned")
                            .insert(service.fullname.clone(), sighting.device_id);

                        if registry.record(sighting) {
                            tracing::debug!(host = %service.host, "found a peer by mDNS");
                        }
                    }
                }
                ServiceEvent::ServiceRemoved(_, fullname) => {
                    // Acted on rather than merely logged: an mDNS peer is held
                    // in the list for as long as it advertises itself, so this
                    // is the *only* signal that says it has gone.
                    let known = self
                        .advertised
                        .lock()
                        .expect("advertised map poisoned")
                        .remove(&fullname);

                    if let Some(device_id) = known {
                        registry.mdns_withdrawn(&device_id);
                        tracing::debug!(%fullname, "peer withdrew its mDNS advertisement");
                    }
                }
                _ => {}
            }
        }
    }

    fn to_sighting(&self, service: &mdns_sd::ResolvedService) -> Option<Sighting> {
        if service.fullname == self.fullname {
            return None;
        }

        let device_id: DeviceId = service
            .txt_properties
            .get_property_val_str(TXT_DEVICE_ID)?
            .parse()
            .ok()?;

        // Another instance of us, perhaps on a second interface.
        if device_id == self.device_id {
            return None;
        }

        let name = service
            .txt_properties
            .get_property_val_str(TXT_NAME)
            .map(sanitize_name)
            .unwrap_or_else(|| device_id.short());

        let addresses = unique_addresses(service, service.port);

        if addresses.is_empty() {
            return None;
        }

        Some(Sighting::claimed(device_id, name, addresses, Source::Mdns))
    }
}

/// This device's DNS-SD record.
fn advertisement(
    device_id: DeviceId,
    name: &str,
    transfer_port: u16,
) -> Result<ServiceInfo, mdns_sd::Error> {
    // The instance name must be unique on the network and stable for this
    // device. The device id's short form gives both, and unlike the display
    // name it cannot collide when two machines are called "Laptop".
    let instance = format!("jetstream-{}", device_id.short());
    let hostname = format!("jetstream-{}.local.", device_id.short());

    let properties = [
        (TXT_DEVICE_ID, device_id.to_hex()),
        (TXT_NAME, sanitize_name(name)),
    ];

    // `enable_addr_auto` lets the daemon track this machine's addresses,
    // so a device that moves between Wi-Fi and Ethernet keeps advertising
    // somewhere reachable instead of a stale address.
    Ok(ServiceInfo::new(
        SERVICE_TYPE,
        &instance,
        &hostname,
        (),
        transfer_port,
        &properties[..],
    )?
    .enable_addr_auto())
}

/// Flatten the resolved addresses, dropping duplicates and loopback.
///
/// Loopback is excluded because a peer advertising `127.0.0.1` is describing
/// *its* loopback, not somewhere we can reach it.
///
/// # Link-local IPv6 keeps its scope
///
/// A `fe80::` address is meaningless on its own. The same address can exist on
/// several interfaces, so the kernel needs a **scope id** — the interface index —
/// to know which one to send out of. Without it, connecting fails immediately or
/// goes out of whatever the routing table guesses.
///
/// This was a real, diagnosed failure. On two machines joined by a direct
/// Ethernet cable, `jetstream` offered three addresses and every one timed out:
///
/// ```text
/// 169.254.120.215:4646            no response within 5s
/// [fe80::c08c:d308:ba32:d390]:4646  no response within 5s
/// [fe80::46e5:18b0:ceb:6116]:4646   no response within 5s
/// ```
///
/// Yet `ping -6 fe80::46e5:18b0:ceb:6116%8` answered straight away. The cable
/// was fine; the address had simply been stripped of the one piece of
/// information that made it usable. mDNS hands us the scope in `ScopedIpV6` and
/// this used to discard it.
fn unique_addresses(service: &mdns_sd::ResolvedService, port: u16) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    let mut addresses = Vec::new();

    for scoped in &service.addresses {
        let address = match scoped {
            mdns_sd::ScopedIp::V4(v4) => SocketAddr::from((*v4.addr(), port)),
            mdns_sd::ScopedIp::V6(v6) => {
                // Only link-local addresses need — and may carry — a scope. A
                // global IPv6 address with a scope id attached would be refused.
                let scope = if is_link_local(v6.addr()) {
                    v6.scope_id().index
                } else {
                    0
                };
                SocketAddr::V6(std::net::SocketAddrV6::new(*v6.addr(), port, 0, scope))
            }
            // `ScopedIp` is non-exhaustive, so a future address family would land
            // here. Skipping it is right: we cannot dial what we cannot read.
            other => {
                tracing::debug!(?other, "ignoring an mDNS address of an unknown kind");
                continue;
            }
        };

        if address.ip().is_loopback() || !seen.insert(address) {
            continue;
        }
        addresses.push(address);
    }
    addresses
}

fn is_link_local(address: &std::net::Ipv6Addr) -> bool {
    address.segments()[0] & 0xffc0 == 0xfe80
}

impl Drop for Mdns {
    fn drop(&mut self) {
        // Withdraw the advertisement so peers drop us promptly rather than
        // waiting out the TTL and offering the user a device that is gone.
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

/// Keep Teredo and 6to4 interfaces out of mDNS entirely.
///
/// Ranking those addresses last on the *dialling* side fixes the choice, but
/// only once the other device runs a build that knows to. Not advertising them
/// from this side fixes it immediately for every peer, old builds included: an
/// address that is never offered cannot be picked. Measured case: a transfer
/// between two Radmin-connected machines ran entirely over Teredo because the
/// receiver advertised its Teredo address and the sender ranked it above Radmin.
///
/// Matched by address prefix rather than adapter name, because the name is
/// localised — "Teredo Tunneling Pseudo-Interface" on English Windows only.
/// Best-effort: an interface that cannot be disabled is logged and left alone,
/// since mDNS working on a tunnel is still better than mDNS not starting.
fn exclude_tunnel_interfaces(daemon: &ServiceDaemon) {
    let Ok(interfaces) = if_addrs::get_if_addrs() else {
        return;
    };

    for interface in interfaces {
        let if_addrs::IfAddr::V6(v6) = &interface.addr else {
            continue;
        };
        if !crate::is_tunnelled_ipv6(&v6.ip) {
            continue;
        }

        match daemon.disable_interface(mdns_sd::IfKind::Addr(std::net::IpAddr::V6(v6.ip))) {
            Ok(()) => tracing::debug!(interface = %interface.name, "not advertising on a tunnel interface"),
            Err(e) => tracing::debug!(interface = %interface.name, error = %e, "could not exclude a tunnel interface from mDNS"),
        }
    }
}
