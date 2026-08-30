//! How fast the wire to a peer actually is.
//!
//! Exists because of a real diagnosis that took measurement to reach. A transfer
//! sitting at 12 MB/s with the CPU at 5% looks like an application that is not
//! trying, and the natural conclusion is that the app is slow. It was not: the
//! Ethernet adapter had negotiated **100 Mbps** — 12.5 MB/s — and the transfer
//! was running at 96% of the physical maximum. Nothing in the interface said so,
//! so the only way to find out was to go and read the adapter's link speed by
//! hand.
//!
//! A rate is meaningless without its ceiling. Reporting both turns "why is this
//! slow" into "this is as fast as this cable goes", which is a different
//! sentence and usually the true one.
//!
//! The speed is looked up **per peer**, not once for the machine: a device
//! reached over Wi-Fi and a device reached over a 100 Mbps cable have different
//! ceilings at the same moment, and a machine with nine adapters has no single
//! answer.

use std::net::SocketAddr;

/// Link speed in bits per second for the interface that reaches `peer`.
///
/// `None` when it cannot be determined, which the UI must treat as "say nothing"
/// rather than as zero.
#[cfg(windows)]
pub fn to_peer(peer: SocketAddr) -> Option<u64> {
    windows_impl::link_speed(peer.ip())
}

#[cfg(not(windows))]
pub fn to_peer(_peer: SocketAddr) -> Option<u64> {
    None
}

/// Human-readable ceiling, e.g. `1.0 Gbps` or `100 Mbps`.
///
/// Rounded to the units people recognise from the hardware, so it reads as the
/// same number printed on a switch rather than an exact bit count.
pub fn describe(bits_per_second: u64) -> String {
    const MBIT: u64 = 1_000_000;
    const GBIT: u64 = 1_000 * MBIT;

    if bits_per_second >= GBIT {
        let gbps = bits_per_second as f64 / GBIT as f64;
        if (gbps - gbps.round()).abs() < 0.05 {
            format!("{} Gbps", gbps.round() as u64)
        } else {
            format!("{gbps:.1} Gbps")
        }
    } else {
        format!("{} Mbps", bits_per_second / MBIT)
    }
}

/// Reorder candidate addresses to try the fastest wire first.
///
/// Discovery ranks addresses by how likely they are to *reach* the peer, which is
/// the right first question and the wrong only one. A machine with both Wi-Fi and
/// a gigabit cable to the same device offers a private `192.168.x.x` over Wi-Fi
/// and a link-local address over the cable; reachability alone prefers the
/// routable Wi-Fi address, so a user who plugged in a cable specifically to go
/// faster gets 72 Mbps instead of 1 Gbps. Measured, not hypothetical.
///
/// A **stable** sort, so the existing reachability ranking survives as the
/// tiebreaker and addresses of unknown speed keep their original place rather
/// than being pushed to the back — unknown is not slow.
///
/// Costs a handful of syscalls per address, so this belongs on the connect path,
/// never in a render loop.
pub fn prefer_fast_links(addresses: &mut [SocketAddr]) {
    // Measured once per address up front: sorting comparators may call back
    // repeatedly, and each lookup walks the routing table.
    let speeds: std::collections::HashMap<SocketAddr, u64> = addresses
        .iter()
        .map(|&address| (address, to_peer(address).unwrap_or(0)))
        .collect();

    // Descending speed, unknown (0) treated as "no opinion" by sorting it with
    // the middle rather than last: the reachability order already decided those.
    let fastest = speeds.values().copied().max().unwrap_or(0);
    addresses.sort_by_key(|address| {
        let speed = speeds.get(address).copied().unwrap_or(0);
        if speed == 0 { 1u8 } else if speed == fastest { 0 } else { 2 }
    });
}

/// The ceiling as bytes per second, for comparing against a measured rate.
pub fn as_bytes_per_second(bits_per_second: u64) -> f64 {
    // Divided by 8 with no allowance for framing overhead. The honest ceiling is
    // a few percent lower, but claiming precision we have not measured would be
    // worse than a round number a user can check against the hardware.
    bits_per_second as f64 / 8.0
}

#[cfg(windows)]
mod windows_impl {
    use std::net::IpAddr;

    use windows::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, GetBestInterfaceEx, GetIfEntry2, MIB_IF_ROW2,
    };
    use windows::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, IN6_ADDR, IN_ADDR, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
    };
    use windows::core::PCWSTR;

    /// Read the link speed of the interface that reaches `peer`.
    ///
    /// Two steps, because either alone gets it wrong:
    ///
    /// 1. Ask the routing table (`GetBestInterfaceEx`). The kernel knows which
    ///    adapter carries the traffic, and guessing from subnets goes wrong on a
    ///    machine with a VPN and a hypervisor.
    /// 2. **Insist the answer is a physical adapter.** Measured on a real machine,
    ///    a link-local peer resolved to a Tailscale interface advertising
    ///    *100 Gbps* — five adapters shared `169.254.0.0/16` and a virtual one
    ///    won. Printing that as the ceiling would be worse than printing nothing,
    ///    because it says the wire is 8000× faster than it is.
    ///
    /// When the routed interface is virtual, fall back to a physical adapter on
    /// the same subnet, which is what a shared link-local range actually means.
    /// If there is no physical answer, return `None` and say nothing.
    pub fn link_speed(peer: IpAddr) -> Option<u64> {
        if let Some(index) = best_interface(peer)
            && let Some(speed) = hardware_speed(Selector::Index(index))
        {
            return Some(speed);
        }

        physical_on_same_subnet(peer)
    }

    enum Selector {
        Index(u32),
        Alias(String),
    }

    /// Link speed, but only for an interface backed by real hardware.
    fn hardware_speed(selector: Selector) -> Option<u64> {
        let mut row = MIB_IF_ROW2::default();

        match selector {
            Selector::Index(index) => row.InterfaceIndex = index,
            Selector::Alias(alias) => {
                let wide: Vec<u16> = alias.encode_utf16().chain(std::iter::once(0)).collect();
                // SAFETY: `wide` is NUL-terminated and outlives the call.
                if unsafe { ConvertInterfaceAliasToLuid(PCWSTR(wide.as_ptr()), &raw mut row.InterfaceLuid) }
                    .is_err()
                {
                    return None;
                }
            }
        }

        // SAFETY: exactly one of InterfaceIndex or InterfaceLuid is set, which is
        // the documented way to identify the row to fill in.
        if unsafe { GetIfEntry2(&raw mut row) }.is_err() {
            return None;
        }

        // The bit that separates a cable from a tunnel. Without it, VPN and
        // hypervisor adapters contribute confident nonsense.
        //
        // `InterfaceAndOperStatusFlags` is a packed bitfield the bindings expose
        // as a bare `u8`, so the bit has to be named here. From the SDK's
        // declaration order: HardwareInterface, FilterInterface,
        // ConnectorPresent, NotAuthenticated, NotMediaConnected, Paused,
        // LowPower, EndPointInterface. Only the first is wanted —
        // `ConnectorPresent` would additionally exclude Wi-Fi, which is a real
        // wire for this purpose.
        const HARDWARE_INTERFACE: u8 = 1 << 0;
        const NOT_MEDIA_CONNECTED: u8 = 1 << 4;

        let flags = row.InterfaceAndOperStatusFlags._bitfield;
        if flags & HARDWARE_INTERFACE == 0 {
            return None;
        }

        // A NIC with nothing plugged into it is still hardware, and still reports
        // a nominal speed. Measured: an idle spare Ethernet port claimed 1 Gbps
        // and won the link-local subnet over the cable actually carrying data at
        // 100 Mbps. "Connected" is the difference between a port and a wire.
        if flags & NOT_MEDIA_CONNECTED != 0 {
            return None;
        }

        // Belt and braces: the operational status must also be up. `1` is
        // `IfOperStatusUp`, the only value that means traffic can flow.
        if row.OperStatus.0 != 1 {
            return None;
        }

        let speed = row.TransmitLinkSpeed;
        // A zero or absurd figure is a driver that does not report one.
        (speed > 0 && speed <= 400_000_000_000).then_some(speed)
    }

    /// A physical adapter whose own subnet contains `peer`.
    fn physical_on_same_subnet(peer: IpAddr) -> Option<u64> {
        let IpAddr::V4(peer) = peer else {
            return None;
        };
        let peer = u32::from(peer);

        for interface in if_addrs::get_if_addrs().ok()? {
            let if_addrs::IfAddr::V4(v4) = interface.addr else {
                continue;
            };

            let mask = u32::from(v4.netmask);
            if mask == 0 || (u32::from(v4.ip) & mask) != (peer & mask) {
                continue;
            }

            // if-addrs reports the adapter's friendly name on Windows, which is
            // the same string `MIB_IF_ROW2.Alias` uses.
            if let Some(speed) = hardware_speed(Selector::Alias(interface.name)) {
                return Some(speed);
            }
        }

        None
    }

    fn best_interface(peer: IpAddr) -> Option<u32> {
        let mut index = 0u32;

        match peer {
            IpAddr::V4(v4) => {
                let mut addr = SOCKADDR_IN {
                    sin_family: AF_INET,
                    ..Default::default()
                };
                addr.sin_addr = IN_ADDR {
                    S_un: windows::Win32::Networking::WinSock::IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(v4.octets()),
                    },
                };

                // SAFETY: the SOCKADDR_IN is fully initialised and outlives the
                // call; casting to SOCKADDR is what this API expects.
                unsafe {
                    GetBestInterfaceEx(
                        &raw const addr as *const SOCKADDR,
                        &raw mut index,
                    )
                }
            }
            IpAddr::V6(v6) => {
                let mut addr = SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    ..Default::default()
                };
                addr.sin6_addr = IN6_ADDR {
                    u: windows::Win32::Networking::WinSock::IN6_ADDR_0 {
                        Byte: v6.octets(),
                    },
                };

                // SAFETY: as above.
                unsafe {
                    GetBestInterfaceEx(
                        &raw const addr as *const SOCKADDR,
                        &raw mut index,
                    )
                }
            }
        };

        (index != 0).then_some(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_the_speeds_people_recognise() {
        assert_eq!(describe(100_000_000), "100 Mbps");
        assert_eq!(describe(1_000_000_000), "1 Gbps");
        assert_eq!(describe(10_000_000_000), "10 Gbps");
        assert_eq!(describe(54_000_000), "54 Mbps");
        assert_eq!(describe(2_500_000_000), "2.5 Gbps");
    }

    #[test]
    fn a_hundred_megabit_link_is_twelve_and_a_half_megabytes() {
        // The number that made the original diagnosis obvious.
        let ceiling = as_bytes_per_second(100_000_000);
        assert!((ceiling - 12_500_000.0).abs() < 1.0);
    }

    #[test]
    fn ordering_by_speed_keeps_every_address_and_is_stable() {
        // The reachability order must survive as the tiebreaker, and nothing may
        // be dropped — a slower wire is still a working wire.
        let mut addresses: Vec<SocketAddr> = vec![
            "192.168.1.7:4646".parse().unwrap(),
            "169.254.120.215:4646".parse().unwrap(),
            "10.0.0.5:4646".parse().unwrap(),
        ];
        let before = addresses.clone();

        prefer_fast_links(&mut addresses);

        assert_eq!(addresses.len(), before.len(), "no address may be dropped");
        for address in &before {
            assert!(addresses.contains(address), "{address} went missing");
        }
    }

    #[test]
    fn ordering_an_empty_or_single_list_is_harmless() {
        let mut empty: Vec<SocketAddr> = Vec::new();
        prefer_fast_links(&mut empty);
        assert!(empty.is_empty());

        let mut one: Vec<SocketAddr> = vec!["192.168.1.7:4646".parse().unwrap()];
        prefer_fast_links(&mut one);
        assert_eq!(one.len(), 1);
    }

    #[test]
    fn looking_up_a_peer_never_panics() {
        // Called while rendering a transfer row, so it has to be safe blind.
        let _ = to_peer("192.168.1.7:4646".parse().unwrap());
        let _ = to_peer("[::1]:4646".parse().unwrap());
        let _ = to_peer("127.0.0.1:4646".parse().unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn a_reachable_peer_reports_a_plausible_speed() {
        // Loopback always resolves to an interface, so on Windows this exercises
        // the real lookup rather than only the None path.
        if let Some(speed) = to_peer("127.0.0.1:4646".parse().unwrap()) {
            assert!(speed > 0, "a reported speed must be positive");
            assert!(
                speed <= 400_000_000_000,
                "implausible link speed leaked through: {speed}"
            );
        }
    }
}
