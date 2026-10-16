//! Watched folders: keep a folder sent to a device as it changes.
//!
//! Every so often the folder is walked — by `stat`, which is cheap — and any
//! file that is new or has changed since the last *successful* send goes to the
//! device as one transfer. Nothing is ever deleted at the other end: a file
//! removed here stays there. That is the safe direction to be wrong in, and
//! the same promise every other transfer makes.
//!
//! The record of what was sent only moves forward when a send completes. So an
//! interrupted batch is offered again unchanged next time — the same files, so
//! the same manifest digest — and the receiver resumes it rather than starting
//! over, exactly like any other interrupted transfer.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use jetstream_core::manifest::{Entry, Manifest};
use serde::{Deserialize, Serialize};

const FILE: &str = "watched_folders.json";

/// What a file looked like when it was last sent: size and modification time.
pub type Stamp = (u64, Option<i64>);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Job {
    pub id: u64,
    pub folder: PathBuf,
    pub device_id: String,
    pub device_name: String,
    pub enabled: bool,
    /// Unix seconds of the last completed send, 0 for never.
    #[serde(default)]
    pub last_synced: i64,
    /// Why the last check or send did not work, if it did not.
    #[serde(default)]
    pub problem: Option<String>,
    /// Every file sent so far, by manifest path.
    #[serde(default)]
    pub sent: BTreeMap<String, Stamp>,
    /// The batch that is being sent, or was interrupted: its manifest digest
    /// and the transfer id it ran under. A new attempt at the same batch reuses
    /// the id, so it continues as one transfer instead of starting another.
    #[serde(default)]
    pub pending: Option<(String, u64)>,
}

impl Job {
    /// Files new or changed since they were last sent, as a manifest that can be
    /// sent as it is — paths relative to the folder's parent, like a normal send
    /// of the folder.
    pub fn changes(&self, walked: &Manifest) -> Manifest {
        let entries: Vec<Entry> = walked
            .entries
            .iter()
            .filter(|entry| entry.is_file())
            .filter(|entry| self.sent.get(entry.path.as_str()) != Some(&stamp(entry)))
            .cloned()
            .collect();
        Manifest { entries }
    }
}

pub fn stamp(entry: &Entry) -> Stamp {
    (entry.size(), entry.mtime)
}

/// Everything in `manifest`, as a record of what was sent.
pub fn stamps(manifest: &Manifest) -> BTreeMap<String, Stamp> {
    manifest
        .entries
        .iter()
        .filter(|entry| entry.is_file())
        .map(|entry| (entry.path.as_str().to_string(), stamp(entry)))
        .collect()
}

pub struct Folders {
    path: PathBuf,
    jobs: Mutex<Vec<Job>>,
}

impl Folders {
    pub fn load(dir: &Path) -> Self {
        let path = dir.join(FILE);
        let jobs = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        Self {
            path,
            jobs: Mutex::new(jobs),
        }
    }

    pub fn all(&self) -> Vec<Job> {
        self.jobs.lock().expect("folders poisoned").clone()
    }

    #[cfg(test)]
    pub fn get(&self, id: u64) -> Option<Job> {
        self.all().into_iter().find(|job| job.id == id)
    }

    /// Add a job. `already_there` records the folder's current contents as sent,
    /// for a device that already has them — only later changes then go.
    pub fn add(&self, folder: PathBuf, device_id: String, device_name: String, already_there: BTreeMap<String, Stamp>) -> Job {
        let mut jobs = self.jobs.lock().expect("folders poisoned");
        let id = jobs.iter().map(|job| job.id).max().map_or(1, |max| max + 1);
        let job = Job {
            id,
            folder,
            device_id,
            device_name,
            enabled: true,
            last_synced: 0,
            problem: None,
            sent: already_there,
            pending: None,
        };
        jobs.push(job.clone());
        self.write(&jobs);
        job
    }

    pub fn remove(&self, id: u64) {
        let mut jobs = self.jobs.lock().expect("folders poisoned");
        jobs.retain(|job| job.id != id);
        self.write(&jobs);
    }

    pub fn update(&self, id: u64, change: impl FnOnce(&mut Job)) {
        let mut jobs = self.jobs.lock().expect("folders poisoned");
        if let Some(job) = jobs.iter_mut().find(|job| job.id == id) {
            change(job);
            self.write(&jobs);
        }
    }

    /// A batch arrived: record it as sent and forget it as pending.
    pub fn complete(&self, id: u64, batch: BTreeMap<String, Stamp>, at: i64) {
        self.update(id, |job| {
            job.sent.extend(batch);
            job.last_synced = at;
            job.pending = None;
            job.problem = None;
        });
    }

    fn write(&self, jobs: &[Job]) {
        let Ok(text) = serde_json::to_string_pretty(jobs) else {
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

    fn tree(files: &[(&str, &[u8])]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Photos");
        for (name, data) in files {
            let path = root.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, data).unwrap();
        }
        (dir, root)
    }

    fn walk(root: &Path) -> Manifest {
        Manifest::from_paths(&[root.to_path_buf()]).unwrap().0
    }

    #[test]
    fn a_new_job_sends_everything_unless_told_it_is_already_there() {
        let (_dir, root) = tree(&[("a.jpg", b"one"), ("trip/b.jpg", b"two")]);
        let walked = walk(&root);
        let store = Folders::load(tempfile::tempdir().unwrap().path());

        let fresh = store.add(root.clone(), "aa".into(), "Laptop".into(), BTreeMap::new());
        assert_eq!(fresh.changes(&walked).entries.len(), 2);

        let synced = store.add(root, "aa".into(), "Laptop".into(), stamps(&walked));
        assert!(synced.changes(&walked).entries.is_empty());
    }

    #[test]
    fn only_new_and_changed_files_are_sent() {
        let (_dir, root) = tree(&[("a.jpg", b"one"), ("b.jpg", b"two")]);
        let dir = tempfile::tempdir().unwrap();
        let store = Folders::load(dir.path());
        let job = store.add(root.clone(), "aa".into(), "Laptop".into(), stamps(&walk(&root)));

        std::fs::write(root.join("b.jpg"), b"two, edited").unwrap();
        std::fs::write(root.join("c.jpg"), b"three").unwrap();
        std::fs::remove_file(root.join("a.jpg")).unwrap();

        let batch = job.changes(&walk(&root));
        let mut names: Vec<_> = batch.entries.iter().map(|e| e.path.as_str().to_string()).collect();
        names.sort();
        assert_eq!(names, ["Photos/b.jpg", "Photos/c.jpg"], "a deletion is never sent");
        batch.validate().expect("a batch is a valid manifest on its own");
    }

    #[test]
    fn an_unfinished_batch_is_offered_again_unchanged() {
        let (_dir, root) = tree(&[("a.jpg", b"one")]);
        let dir = tempfile::tempdir().unwrap();
        let store = Folders::load(dir.path());
        let job = store.add(root.clone(), "aa".into(), "Laptop".into(), BTreeMap::new());

        let first = job.changes(&walk(&root));
        // Interrupted: nothing recorded. Same files, same digest, so it resumes.
        let again = store.get(job.id).unwrap().changes(&walk(&root));
        assert_eq!(first.digest(), again.digest());

        store.complete(job.id, stamps(&first), 1_800_000_000);
        let after = Folders::load(dir.path()).get(job.id).unwrap();
        assert!(after.changes(&walk(&root)).entries.is_empty());
        assert_eq!(after.last_synced, 1_800_000_000);
    }
}
