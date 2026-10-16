//! Preferences kept per device: where its files go, and how to wake it.
//!
//! Separate from the trust store on purpose. Trust is a security decision with
//! its own careful persistence; a download folder is a convenience, and a
//! damaged file of conveniences should cost nothing worse than defaults.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

const FILE: &str = "devices.json";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePrefs {
    /// Where this device's files go, instead of the usual folder.
    #[serde(default)]
    pub download_dir: Option<PathBuf>,
    /// Hardware address for Wake-on-LAN, learned while the device was online.
    #[serde(default)]
    pub mac: Option<String>,
}

pub struct DevicePrefsStore {
    path: PathBuf,
    prefs: Mutex<HashMap<String, DevicePrefs>>,
}

impl DevicePrefsStore {
    pub fn load(dir: &Path) -> Self {
        let path = dir.join(FILE);
        let prefs = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        Self {
            path,
            prefs: Mutex::new(prefs),
        }
    }

    pub fn get(&self, device_id: &str) -> DevicePrefs {
        self.prefs
            .lock()
            .expect("device prefs poisoned")
            .get(device_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn all(&self) -> HashMap<String, DevicePrefs> {
        self.prefs.lock().expect("device prefs poisoned").clone()
    }

    /// Change one device's preferences. Writes only if something changed — the
    /// MAC is re-learned on every connection, and rewriting the file each time
    /// for the same answer would be pointless churn.
    pub fn update(&self, device_id: &str, change: impl FnOnce(&mut DevicePrefs)) {
        let mut prefs = self.prefs.lock().expect("device prefs poisoned");
        let entry = prefs.entry(device_id.to_string()).or_default();
        let before = entry.clone();
        change(entry);
        if *entry == before {
            return;
        }
        if *entry == DevicePrefs::default() {
            prefs.remove(device_id);
        }
        self.write(&prefs);
    }

    fn write(&self, prefs: &HashMap<String, DevicePrefs>) {
        let Ok(text) = serde_json::to_string_pretty(prefs) else {
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

/// A device name made safe to use as one folder name on Windows.
///
/// The name comes from the other device and is untrusted. It is already free of
/// control characters, but may still hold path separators, characters Windows
/// forbids in names, a reserved device name like `CON`, or trailing dots — any
/// of which would fail, or worse, point somewhere else.
pub fn folder_name_for(name: &str) -> String {
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];

    let cleaned: String = name
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    // Leading dots too: a name that begins `..` is harmless as one component,
    // but looks like a parent directory to anyone reading it.
    let trimmed = cleaned.trim().trim_matches(['.', ' ']).trim();

    if trimmed.is_empty() || trimmed.chars().all(|c| c == '.' || c == '_') {
        return "Device".to_string();
    }

    let stem = trimmed.split('.').next().unwrap_or(trimmed);
    if RESERVED.iter().any(|reserved| stem.eq_ignore_ascii_case(reserved)) {
        return format!("{trimmed}_");
    }
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferences_survive_a_restart_and_empty_ones_are_dropped() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = DevicePrefsStore::load(dir.path());
            store.update("aa", |p| p.download_dir = Some(PathBuf::from("D:\\Laptop")));
            store.update("bb", |p| p.mac = Some("00:11:22:33:44:55".into()));
            store.update("bb", |p| p.mac = None);
        }

        let store = DevicePrefsStore::load(dir.path());
        assert_eq!(store.get("aa").download_dir, Some(PathBuf::from("D:\\Laptop")));
        assert!(!store.all().contains_key("bb"), "an entry with nothing in it is removed");
    }

    #[test]
    fn device_names_become_safe_folder_names() {
        assert_eq!(folder_name_for("Mike's Laptop"), "Mike's Laptop");
        assert_eq!(folder_name_for("a/b\\c:d"), "a_b_c_d");
        assert_eq!(folder_name_for("..\\..\\Windows"), "_.._Windows");
        assert_eq!(folder_name_for("trailing dots..."), "trailing dots");
        assert_eq!(folder_name_for("CON"), "CON_");
        assert_eq!(folder_name_for("com1.txt"), "com1.txt_");
        assert_eq!(folder_name_for("   "), "Device");
        assert_eq!(folder_name_for(".."), "Device");
        assert!(!folder_name_for("<>:\"|?*").contains(['<', '>', ':', '"', '|', '?', '*']));
    }
}
