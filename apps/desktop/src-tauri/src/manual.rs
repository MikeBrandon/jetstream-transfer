//! Devices added by address, for networks discovery cannot see across.
//!
//! Broadcast and mDNS stop at the edge of the local segment, and most VPNs —
//! Radmin, Tailscale, ZeroTier, a company VPN — carry neither. A device on the
//! other end is perfectly reachable but never appears in the list, so nothing
//! can be sent to it and an interrupted transfer never resumes. Adding it once
//! by address fixes all of that: it is checked every few seconds and listed for
//! as long as it answers.
//!
//! Only the address is remembered here. Trust is still decided by the key, the
//! same as for any discovered device.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

const FILE: &str = "manual_peers.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManualPeer {
    pub device_id: String,
    pub name: String,
    /// `ip:port` as it was reached.
    pub address: String,
}

pub struct ManualPeers {
    path: PathBuf,
    peers: Mutex<Vec<ManualPeer>>,
}

impl ManualPeers {
    /// Load, treating a damaged file as empty — losing it costs a user retyping
    /// an address, which is no reason to refuse to start.
    pub fn load(dir: &Path) -> Self {
        let path = dir.join(FILE);
        let peers = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();

        Self {
            path,
            peers: Mutex::new(peers),
        }
    }

    pub fn all(&self) -> Vec<ManualPeer> {
        self.peers.lock().expect("manual peers poisoned").clone()
    }

    /// Add a device, replacing any earlier address for it.
    pub fn add(&self, peer: ManualPeer) {
        let mut peers = self.peers.lock().expect("manual peers poisoned");
        peers.retain(|existing| existing.device_id != peer.device_id);
        peers.push(peer);
        self.write(&peers);
    }

    pub fn forget(&self, device_id: &str) {
        let mut peers = self.peers.lock().expect("manual peers poisoned");
        peers.retain(|existing| existing.device_id != device_id);
        self.write(&peers);
    }

    fn write(&self, peers: &[ManualPeer]) {
        let Ok(text) = serde_json::to_string_pretty(peers) else {
            return;
        };
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let temp = self.path.with_extension("tmp");
        if std::fs::write(&temp, text).is_ok() {
            let _ = std::fs::rename(&temp, &self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: &str, address: &str) -> ManualPeer {
        ManualPeer {
            device_id: id.into(),
            name: format!("Device {id}"),
            address: address.into(),
        }
    }

    #[test]
    fn added_devices_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        ManualPeers::load(dir.path()).add(peer("aa", "26.1.2.3:4646"));

        let loaded = ManualPeers::load(dir.path()).all();
        assert_eq!(loaded, vec![peer("aa", "26.1.2.3:4646")]);
    }

    #[test]
    fn adding_a_device_again_replaces_its_address() {
        let dir = tempfile::tempdir().unwrap();
        let peers = ManualPeers::load(dir.path());
        peers.add(peer("aa", "26.1.2.3:4646"));
        peers.add(peer("aa", "26.9.9.9:4646"));

        assert_eq!(peers.all(), vec![peer("aa", "26.9.9.9:4646")]);
    }

    #[test]
    fn a_forgotten_device_stays_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let peers = ManualPeers::load(dir.path());
        peers.add(peer("aa", "26.1.2.3:4646"));
        peers.forget("aa");

        assert!(ManualPeers::load(dir.path()).all().is_empty());
    }
}
