//! Which devices are welcome, remembered across restarts.
//!
//! TLS proves a peer holds a particular key. This module answers the separate
//! question of whether that key is *allowed to send us things* — the decision
//! Dukto never asks, which is why leaving it running on a public network means
//! anyone nearby can drop files into your folder unannounced.
//!
//! The model is trust-on-first-use, like SSH known-hosts:
//!
//! - An unknown device produces a prompt showing its six-word fingerprint and a
//!   summary of what it wants to send. Nothing is written to disk before the
//!   user answers.
//! - Once paired, a device can be set to prompt every time or to auto-accept.
//! - A blocked device is refused without a prompt, so a persistent nuisance
//!   cannot keep interrupting.
//!
//! A device's entry is keyed by its public key, never by name or address. A
//! peer can rename itself or move networks freely; it cannot become a
//! *different trusted device* without the corresponding private key.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::DeviceId;
use crate::proto::sanitize_name;

const STORE_FILE: &str = "trusted-devices.json";

/// What to do when this device makes an offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustLevel {
    /// Show a prompt every time. The default for a newly paired device —
    /// pairing establishes *who* they are, not blanket permission.
    #[default]
    Ask,
    /// Accept silently. Appropriate for a user's own machines.
    AutoAccept,
    /// Refuse without prompting.
    Blocked,
}

impl TrustLevel {
    pub fn accepts_silently(self) -> bool {
        self == Self::AutoAccept
    }

    pub fn is_blocked(self) -> bool {
        self == Self::Blocked
    }
}

/// A device the user has made a decision about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedDevice {
    pub device_id: DeviceId,
    /// Last known display name, for the UI. Peer-supplied, already sanitized.
    pub name: String,
    pub level: TrustLevel,
    /// Unix seconds. Shown as "paired 3 months ago", and a useful signal when a
    /// user is deciding whether an entry is still one they recognise.
    pub first_paired: i64,
    pub last_seen: i64,
    /// Where we last reached it. A hint for reconnecting without waiting for
    /// discovery — never a substitute for verifying the key.
    pub last_address: Option<String>,
}

impl TrustedDevice {
    /// The fingerprint the user compared when pairing.
    pub fn fingerprint(&self) -> String {
        self.device_id.fingerprint()
    }
}

/// The persisted set of trust decisions.
#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreFile {
    #[serde(default)]
    devices: Vec<TrustedDevice>,
}

/// Trust decisions, loaded from and saved to disk.
#[derive(Debug)]
pub struct TrustStore {
    path: PathBuf,
    devices: HashMap<DeviceId, TrustedDevice>,
}

impl TrustStore {
    /// Load the store from `dir`, starting empty if it does not exist yet.
    ///
    /// A corrupt store is *not* silently discarded — that would downgrade every
    /// paired device to unknown and quietly re-expose the user to prompts they
    /// already answered. It is surfaced so the app can say so.
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(STORE_FILE);

        let devices = match fs::read_to_string(&path) {
            Ok(text) => {
                let parsed: StoreFile = serde_json::from_str(&text).map_err(|e| {
                    Error::MalformedIdentity {
                        path: path.display().to_string(),
                        detail: format!("trust store is not valid JSON: {e}"),
                    }
                })?;
                parsed
                    .devices
                    .into_iter()
                    .map(|device| (device.device_id, device))
                    .collect()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e.into()),
        };

        Ok(Self { path, devices })
    }

    /// How we should treat an offer from this device.
    ///
    /// An unknown device is `Ask`, which is the safe default and the whole
    /// point: silence is never consent.
    pub fn level_for(&self, device_id: &DeviceId) -> TrustLevel {
        self.devices
            .get(device_id)
            .map(|device| device.level)
            .unwrap_or_default()
    }

    pub fn get(&self, device_id: &DeviceId) -> Option<&TrustedDevice> {
        self.devices.get(device_id)
    }

    pub fn is_known(&self, device_id: &DeviceId) -> bool {
        self.devices.contains_key(device_id)
    }

    /// Devices in a stable display order: most recently seen first.
    pub fn devices(&self) -> Vec<TrustedDevice> {
        let mut devices: Vec<_> = self.devices.values().cloned().collect();
        devices.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(a.name.cmp(&b.name)));
        devices
    }

    /// Record a decision, creating the entry if this is a first pairing.
    pub fn set_level(&mut self, device_id: DeviceId, name: &str, level: TrustLevel) -> Result<()> {
        let now = unix_now();

        self.devices
            .entry(device_id)
            .and_modify(|device| {
                device.level = level;
                device.last_seen = now;
                if !name.is_empty() {
                    device.name = sanitize_name(name);
                }
            })
            .or_insert_with(|| TrustedDevice {
                device_id,
                name: sanitize_name(name),
                level,
                first_paired: now,
                last_seen: now,
                last_address: None,
            });

        self.save()
    }

    /// Note that we just talked to this device.
    ///
    /// Only updates an existing entry — seeing an untrusted device on the
    /// network is not itself a reason to start remembering it.
    pub fn touch(&mut self, device_id: &DeviceId, name: &str, address: Option<String>) -> Result<()> {
        let Some(device) = self.devices.get_mut(device_id) else {
            return Ok(());
        };

        device.last_seen = unix_now();
        if !name.is_empty() {
            device.name = sanitize_name(name);
        }
        if address.is_some() {
            device.last_address = address;
        }
        self.save()
    }

    /// Forget a device entirely. It will prompt again on next contact.
    pub fn forget(&mut self, device_id: &DeviceId) -> Result<bool> {
        let removed = self.devices.remove(device_id).is_some();
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    /// Addresses worth trying on startup, before discovery has found anything.
    ///
    /// This is what makes a previously paired device reachable across a subnet
    /// boundary, where neither broadcast nor mDNS can help.
    pub fn known_addresses(&self) -> Vec<(DeviceId, String)> {
        self.devices
            .values()
            .filter(|device| !device.level.is_blocked())
            .filter_map(|device| {
                device
                    .last_address
                    .clone()
                    .map(|address| (device.device_id, address))
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.devices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = StoreFile {
            devices: self.devices(),
        };
        let text = serde_json::to_string_pretty(&file)
            .map_err(|e| Error::Protocol(format!("could not encode the trust store: {e}")))?;

        // Written via a temp file and renamed: losing the trust store to a
        // crash mid-write would silently un-pair every device.
        let temp = self.path.with_extension("tmp");
        fs::write(&temp, text)?;
        fs::rename(&temp, &self.path)?;
        Ok(())
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(byte: u8) -> DeviceId {
        DeviceId::from_bytes([byte; 32])
    }

    #[test]
    fn an_unknown_device_is_asked_about() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::load(dir.path()).unwrap();

        assert_eq!(store.level_for(&device(1)), TrustLevel::Ask);
        assert!(!store.is_known(&device(1)));
    }

    #[test]
    fn decisions_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();

        {
            let mut store = TrustStore::load(dir.path()).unwrap();
            store
                .set_level(device(1), "My Laptop", TrustLevel::AutoAccept)
                .unwrap();
            store.set_level(device(2), "Stranger", TrustLevel::Blocked).unwrap();
        }

        let store = TrustStore::load(dir.path()).unwrap();
        assert_eq!(store.level_for(&device(1)), TrustLevel::AutoAccept);
        assert_eq!(store.level_for(&device(2)), TrustLevel::Blocked);
        assert_eq!(store.get(&device(1)).unwrap().name, "My Laptop");
    }

    #[test]
    fn pairing_defaults_to_asking_rather_than_blanket_permission() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TrustStore::load(dir.path()).unwrap();

        store.set_level(device(1), "Laptop", TrustLevel::Ask).unwrap();

        assert!(store.is_known(&device(1)), "the device is now recognised");
        assert!(
            !store.level_for(&device(1)).accepts_silently(),
            "knowing who a device is must not imply accepting whatever it sends"
        );
    }

    #[test]
    fn a_decision_can_be_changed() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TrustStore::load(dir.path()).unwrap();

        store.set_level(device(1), "Laptop", TrustLevel::Ask).unwrap();
        store
            .set_level(device(1), "Laptop", TrustLevel::AutoAccept)
            .unwrap();

        assert_eq!(store.level_for(&device(1)), TrustLevel::AutoAccept);
        assert_eq!(store.len(), 1, "changing a decision must not duplicate the entry");
    }

    #[test]
    fn forgetting_a_device_makes_it_prompt_again() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TrustStore::load(dir.path()).unwrap();
        store
            .set_level(device(1), "Laptop", TrustLevel::AutoAccept)
            .unwrap();

        assert!(store.forget(&device(1)).unwrap());
        assert_eq!(store.level_for(&device(1)), TrustLevel::Ask);
        assert!(!store.forget(&device(1)).unwrap(), "forgetting twice is a no-op");
    }

    #[test]
    fn a_renamed_device_keeps_its_trust_decision() {
        // Identity is the key, not the name. A peer renaming itself must not
        // shed a block, nor silently inherit another device's permission.
        let dir = tempfile::tempdir().unwrap();
        let mut store = TrustStore::load(dir.path()).unwrap();

        store.set_level(device(1), "Old Name", TrustLevel::Blocked).unwrap();
        store.touch(&device(1), "New Name", None).unwrap();

        assert_eq!(store.level_for(&device(1)), TrustLevel::Blocked);
        assert_eq!(store.get(&device(1)).unwrap().name, "New Name");
    }

    #[test]
    fn touching_an_unknown_device_does_not_start_tracking_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TrustStore::load(dir.path()).unwrap();

        store.touch(&device(9), "Passer-by", Some("1.2.3.4:4646".into())).unwrap();

        assert!(store.is_empty(), "merely seeing a device is not a trust decision");
    }

    #[test]
    fn hostile_names_are_sanitized_on_the_way_in() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TrustStore::load(dir.path()).unwrap();

        store
            .set_level(device(1), "\u{202E}gnp.exe\nreal", TrustLevel::Ask)
            .unwrap();

        let name = &store.get(&device(1)).unwrap().name;
        assert!(!name.contains('\u{202E}'));
        assert!(!name.contains('\n'));
    }

    #[test]
    fn known_addresses_skip_blocked_devices() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TrustStore::load(dir.path()).unwrap();

        store.set_level(device(1), "Mine", TrustLevel::AutoAccept).unwrap();
        store.touch(&device(1), "Mine", Some("192.168.1.5:4646".into())).unwrap();

        store.set_level(device(2), "Nuisance", TrustLevel::Blocked).unwrap();
        store.touch(&device(2), "Nuisance", Some("192.168.1.9:4646".into())).unwrap();

        let addresses = store.known_addresses();
        assert_eq!(addresses.len(), 1, "we should not go looking for a blocked device");
        assert_eq!(addresses[0].0, device(1));
    }

    #[test]
    fn a_corrupt_store_is_reported_rather_than_silently_reset() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(STORE_FILE), "{ not json").unwrap();

        assert!(
            TrustStore::load(dir.path()).is_err(),
            "silently discarding trust decisions would re-expose the user without telling them"
        );
    }

    #[test]
    fn the_store_is_human_readable() {
        // Users should be able to inspect and, if they must, hand-edit this.
        let dir = tempfile::tempdir().unwrap();
        let mut store = TrustStore::load(dir.path()).unwrap();
        store.set_level(device(1), "Laptop", TrustLevel::AutoAccept).unwrap();

        let text = fs::read_to_string(dir.path().join(STORE_FILE)).unwrap();
        assert!(text.contains("auto-accept"), "got: {text}");
        assert!(text.contains("Laptop"));
    }
}
