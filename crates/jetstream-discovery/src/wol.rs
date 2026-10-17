//! Wake-on-LAN: waking a paired device that is asleep.
//!
//! A transfer waiting to resume, or a file someone wants to send, is stuck for
//! as long as the other machine sleeps. Most desktops and many laptops on mains
//! power will wake for a "magic packet" — six `0xFF` bytes and the network
//! card's hardware address sixteen times, broadcast on the local network.
//!
//! The hardware address is learned from this machine's own neighbour (ARP)
//! table while the device is online and was just talked to, so nothing extra
//! has to cross the wire. It only works on the same local network segment —
//! which is also the only place a magic packet reaches.

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

/// The port magic packets are conventionally sent to. Nothing listens on it;
/// the network card inspects the frame itself.
const WOL_PORT: u16 = 9;

/// A hardware (MAC) address.
pub type Mac = [u8; 6];

/// Format a MAC as `aa:bb:cc:dd:ee:ff`.
pub fn format_mac(mac: &Mac) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Parse `aa:bb:cc:dd:ee:ff` or `aa-bb-cc-dd-ee-ff`.
pub fn parse_mac(text: &str) -> Option<Mac> {
    let parts: Vec<_> = text.split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (byte, part) in mac.iter_mut().zip(parts) {
        *byte = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

/// The magic packet for `mac`.
pub fn magic_packet(mac: &Mac) -> Vec<u8> {
    let mut packet = vec![0xFF; 6];
    for _ in 0..16 {
        packet.extend_from_slice(mac);
    }
    packet
}

/// Broadcast a magic packet out of every interface. Returns how many sends
/// succeeded; zero means none could go anywhere.
pub fn wake(mac: &Mac) -> usize {
    let packet = magic_packet(mac);
    let mut sent = 0;

    for source in crate::broadcast::announce_sources() {
        let Ok(socket) = std::net::UdpSocket::bind(SocketAddrV4::new(source.address, 0)) else {
            continue;
        };
        if socket.set_broadcast(true).is_err() {
            continue;
        }
        for target in [source.broadcast, Ipv4Addr::BROADCAST] {
            if socket
                .send_to(&packet, SocketAddrV4::new(target, WOL_PORT))
                .is_ok()
            {
                sent += 1;
            }
        }
    }
    sent
}

/// The hardware address this machine has on record for `ip`, if any.
///
/// Only meaningful for a device on the same segment, and only after recent
/// traffic with it — exactly the moment this is asked, right after a session.
pub fn mac_for(ip: IpAddr) -> Option<Mac> {
    // Peers that dialled our dual-stack socket appear as `::ffff:a.b.c.d`.
    let IpAddr::V4(v4) = ip.to_canonical() else {
        return None;
    };
    // An all-zero or broadcast entry is not a device.
    neighbour_mac(v4).filter(|mac| *mac != [0; 6] && *mac != [0xFF; 6])
}

#[cfg(windows)]
fn neighbour_mac(ip: Ipv4Addr) -> Option<Mac> {
    use windows::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIpNetTable2, MIB_IPNET_TABLE2,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, NlnsIncomplete, NlnsUnreachable};

    let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
    // SAFETY: GetIpNetTable2 allocates the table and stores its address in
    // `table`; it is freed with FreeMibTable below on every path.
    if unsafe { GetIpNetTable2(AF_INET, &raw mut table) }.is_err() || table.is_null() {
        return None;
    }

    // SAFETY: on success `table` points at a MIB_IPNET_TABLE2 whose `Table`
    // array holds `NumEntries` rows, allocated contiguously by the call above.
    let rows = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };

    let wanted = u32::from_ne_bytes(ip.octets());
    let found = rows.iter().find_map(|row| {
        // SAFETY: reading the IPv4 view of the address union is valid because
        // the table was requested for AF_INET only.
        let address = unsafe { row.Address.Ipv4.sin_addr.S_un.S_addr };
        if address != wanted
            || row.PhysicalAddressLength != 6
            || row.State == NlnsUnreachable
            || row.State == NlnsIncomplete
        {
            return None;
        }
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&row.PhysicalAddress[..6]);
        Some(mac)
    });

    // SAFETY: `table` came from GetIpNetTable2 and is not used after this.
    unsafe { FreeMibTable(table.cast()) };
    found
}

#[cfg(target_os = "linux")]
fn neighbour_mac(ip: Ipv4Addr) -> Option<Mac> {
    // IP address, HW type, Flags, HW address, Mask, Device
    let table = std::fs::read_to_string("/proc/net/arp").ok()?;
    table.lines().skip(1).find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        (fields.first()?.parse::<Ipv4Addr>().ok()? == ip)
            .then(|| parse_mac(fields.get(3)?))
            .flatten()
    })
}

#[cfg(not(any(windows, target_os = "linux")))]
fn neighbour_mac(_ip: Ipv4Addr) -> Option<Mac> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_magic_packet_is_six_ff_then_the_address_sixteen_times() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let packet = magic_packet(&mac);

        assert_eq!(packet.len(), 6 + 16 * 6);
        assert!(packet[..6].iter().all(|&b| b == 0xFF));
        assert!(packet[6..].chunks(6).all(|chunk| chunk == mac));
    }

    #[test]
    fn mac_addresses_round_trip_in_either_notation() {
        let mac = parse_mac("00:1A:2b:3c:4D:5e").unwrap();
        assert_eq!(format_mac(&mac), "00:1a:2b:3c:4d:5e");
        assert_eq!(parse_mac("00-1a-2b-3c-4d-5e"), Some(mac));
        assert_eq!(parse_mac("00:1a:2b"), None);
        assert_eq!(parse_mac("zz:1a:2b:3c:4d:5e"), None);
    }

    #[test]
    fn looking_up_an_address_never_panics() {
        // Whatever this machine's neighbour table holds.
        let _ = mac_for("192.0.2.1".parse().unwrap());
        assert_eq!(mac_for("::1".parse().unwrap()), None);
    }
}
