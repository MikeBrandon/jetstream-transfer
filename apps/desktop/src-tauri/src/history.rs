//! Transfer history, and automatic resume.
//!
//! # Why this exists
//!
//! Everything below the UI already resumes correctly — but only when someone
//! re-runs the transfer. Until now the app's answer to an interruption was a
//! message saying "sending again will resume", which puts the work back on the
//! user for something the engine can do by itself.
//!
//! So interrupted outbound transfers are remembered, and retried when the peer
//! comes back. The receiver's staged chunks are still there, so a retry costs
//! only what was actually missing.
//!
//! # Why JSON and not a database
//!
//! The plan called for SQLite. This is a bounded list of small records, appended
//! to and occasionally rewritten, read once at startup. A database would add a
//! dependency, a schema, and a migration story to hold a few hundred rows that
//! are never queried by anything but "show me the list". The staging directory
//! is already the source of truth for what has actually been transferred — this
//! file only records *intent*, and losing it costs a user a manual retry.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use jetstream_core::DeviceId;
use serde::{Deserialize, Serialize};

const FILE: &str = "history.json";

/// Records kept before the oldest are dropped.
///
/// Enough to cover a long working history, small enough that the file stays
/// trivial to read and rewrite.
const MAX_RECORDS: usize = 500;

/// How many times an interrupted transfer is retried automatically.
///
/// Bounded so a transfer that fails for a reason retrying cannot fix — the
/// source file was deleted, the peer keeps declining — does not retry forever.
/// After this the record stays, and the user can retry by hand.
pub const MAX_ATTEMPTS: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Outcome {
    Completed,
    /// Stopped with staged data intact. Eligible for automatic resume.
    Interrupted,
    /// Stopped by the user, with staged data intact, awaiting their decision.
    ///
    /// Resumable by hand but **never automatically** — see [`Outcome::is_resumable`].
    Paused,
    /// Stopped by the user and not to be retried.
    Cancelled,
    Declined,
    Failed,
}

impl Outcome {
    /// Whether the app may restart this on its own.
    ///
    /// Deliberately not "whether resuming would work". Pausing and cancelling
    /// both leave perfectly resumable staged data, but a user who stopped a
    /// transfer has told us something, and automatically starting it again would
    /// be overriding them rather than helping.
    pub fn is_resumable(self) -> bool {
        self == Self::Interrupted
    }

    /// Whether the user can pick this up by hand.
    ///
    /// Anything that did not finish. Wider than [`Outcome::is_resumable`] on
    /// purpose: a decline might be accepted on a second ask, and a failure might
    /// have been a full disk that has since been emptied. Deciding those for the
    /// user is not our place — only deciding what to retry *unasked* is.
    pub fn can_continue(self) -> bool {
        self != Self::Completed
    }
}

/// One transfer, remembered.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub id: u64,
    pub peer_device_id: String,
    pub peer_name: String,
    /// Only outbound transfers can be retried by us, so only they store sources.
    #[serde(default)]
    pub sources: Vec<PathBuf>,
    pub sending: bool,
    pub summary: String,
    pub bytes: u64,
    pub outcome: Outcome,
    pub at: i64,
    #[serde(default)]
    pub attempts: u32,
    #[serde(default)]
    pub detail: Option<String>,
}

impl Record {
    /// Whether the app should retry this without being asked.
    ///
    /// Receives are excluded: the sender owns the data, so only it can restart
    /// one. Ours would be an empty gesture.
    pub fn wants_retry(&self) -> bool {
        self.sending
            && self.outcome.is_resumable()
            && self.attempts < MAX_ATTEMPTS
            && !self.sources.is_empty()
    }

    pub fn device(&self) -> Option<DeviceId> {
        self.peer_device_id.parse().ok()
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Stored {
    #[serde(default)]
    records: Vec<Record>,
}

/// The persisted history.
pub struct History {
    path: PathBuf,
    records: Mutex<Vec<Record>>,
}

impl History {
    /// Load, treating a damaged file as empty.
    ///
    /// Unlike the trust store, nothing here is a security decision — losing it
    /// costs a user their list and some automatic retries, so starting fresh is
    /// better than refusing to launch.
    pub fn load(dir: &Path) -> Self {
        let path = dir.join(FILE);

        let records = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str::<Stored>(&text).ok())
            .map(|stored| stored.records)
            .unwrap_or_default();

        Self {
            path,
            records: Mutex::new(records),
        }
    }

    /// Record a finished transfer, replacing any earlier record with the same id.
    ///
    /// The attempt count is **not** taken from `record`. It belongs to
    /// [`History::note_attempt`], and letting a completion overwrite it was a bug
    /// with teeth: every retry wrote `attempts: 0`, so [`MAX_ATTEMPTS`] never
    /// engaged and a failing transfer retried for ever.
    pub fn record(&self, mut record: Record) {
        let mut records = self.records.lock().expect("history poisoned");

        if let Some(existing) = records.iter_mut().find(|r| r.id == record.id) {
            record.attempts = existing.attempts;
            *existing = record;
        } else {
            records.push(record);
        }

        // Newest first, then trim.
        records.sort_by_key(|r| std::cmp::Reverse(r.at));
        records.truncate(MAX_RECORDS);

        self.write(&records);
    }

    /// Note that a retry was attempted, so the count cannot run away.
    pub fn note_attempt(&self, id: u64) {
        let mut records = self.records.lock().expect("history poisoned");
        if let Some(record) = records.iter_mut().find(|r| r.id == id) {
            record.attempts += 1;
        }
        self.write(&records);
    }

    /// Mark a transfer as no longer wanting a retry, without losing the record.
    pub fn stop_retrying(&self, id: u64, outcome: Outcome, detail: Option<String>) {
        let mut records = self.records.lock().expect("history poisoned");
        if let Some(record) = records.iter_mut().find(|r| r.id == id) {
            record.outcome = outcome;
            record.detail = detail;
        }
        self.write(&records);
    }

    pub fn all(&self) -> Vec<Record> {
        self.records.lock().expect("history poisoned").clone()
    }

    /// Transfers that should be retried, grouped by the peer they need.
    pub fn awaiting_retry(&self) -> HashMap<DeviceId, Vec<Record>> {
        let mut by_peer: HashMap<DeviceId, Vec<Record>> = HashMap::new();

        for record in self.records.lock().expect("history poisoned").iter() {
            if !record.wants_retry() {
                continue;
            }
            if let Some(device) = record.device() {
                by_peer.entry(device).or_default().push(record.clone());
            }
        }
        by_peer
    }

    pub fn forget(&self, id: u64) {
        let mut records = self.records.lock().expect("history poisoned");
        records.retain(|r| r.id != id);
        self.write(&records);
    }

    /// Drop everything that has finished, keeping anything still retryable.
    pub fn clear_finished(&self) {
        let mut records = self.records.lock().expect("history poisoned");
        records.retain(Record::wants_retry);
        self.write(&records);
    }

    fn write(&self, records: &[Record]) {
        let stored = Stored {
            records: records.to_vec(),
        };
        let Ok(text) = serde_json::to_string_pretty(&stored) else {
            return;
        };

        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        // Atomic rename so a crash mid-write cannot corrupt the list. No fsync:
        // this is a convenience record, and paying a durability barrier after
        // every transfer would be out of proportion.
        let temp = self.path.with_extension("tmp");
        if std::fs::write(&temp, text).is_ok() {
            let _ = std::fs::rename(&temp, &self.path);
        }
    }
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: u64, sending: bool, outcome: Outcome) -> Record {
        Record {
            id,
            peer_device_id: DeviceId::from_bytes([id as u8; 32]).to_hex(),
            peer_name: format!("Peer {id}"),
            sources: vec![PathBuf::from("C:\\files\\thing.bin")],
            sending,
            summary: "1 file, 1.0 MB".into(),
            bytes: 1_048_576,
            outcome,
            at: 1_700_000_000 + id as i64,
            attempts: 0,
            detail: None,
        }
    }

    #[test]
    fn records_survive_a_restart_newest_first() {
        let dir = tempfile::tempdir().unwrap();

        {
            let history = History::load(dir.path());
            history.record(record(1, true, Outcome::Completed));
            history.record(record(2, true, Outcome::Interrupted));
        }

        let history = History::load(dir.path());
        let all = history.all();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, 2, "newest first");
    }

    #[test]
    fn recording_the_same_id_twice_updates_rather_than_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let history = History::load(dir.path());

        history.record(record(1, true, Outcome::Interrupted));
        history.record(record(1, true, Outcome::Completed));

        let all = history.all();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].outcome, Outcome::Completed);
    }

    #[test]
    fn only_interrupted_sends_are_retried() {
        assert!(record(1, true, Outcome::Interrupted).wants_retry());

        // A receive cannot be restarted by us: the sender holds the data.
        assert!(!record(1, false, Outcome::Interrupted).wants_retry());
        assert!(!record(1, true, Outcome::Completed).wants_retry());
        assert!(!record(1, true, Outcome::Declined).wants_retry());
        assert!(!record(1, true, Outcome::Failed).wants_retry());

        // The two the user chose. Both leave resumable data, and both must be
        // left alone — restarting them would override a deliberate decision.
        assert!(!record(1, true, Outcome::Paused).wants_retry());
        assert!(!record(1, true, Outcome::Cancelled).wants_retry());
        assert!(
            record(1, true, Outcome::Paused).outcome.can_continue(),
            "but the user must still be able to continue it by hand"
        );

        // Nothing to send from.
        let mut sourceless = record(1, true, Outcome::Interrupted);
        sourceless.sources.clear();
        assert!(!sourceless.wants_retry());
    }

    #[test]
    fn retries_stop_after_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let history = History::load(dir.path());
        history.record(record(1, true, Outcome::Interrupted));

        for _ in 0..MAX_ATTEMPTS {
            assert!(history.all()[0].wants_retry());
            history.note_attempt(1);
        }

        assert!(
            !history.all()[0].wants_retry(),
            "a transfer that cannot succeed must stop retrying rather than loop forever"
        );
    }

    /// Regression, seen on a real 95 GB transfer that produced five duplicate
    /// resume attempts. Every completed attempt wrote `attempts: 0`, so the cap
    /// reset each time and the transfer retried without limit.
    #[test]
    fn a_completed_attempt_does_not_reset_the_attempt_count() {
        let dir = tempfile::tempdir().unwrap();
        let history = History::load(dir.path());

        history.record(record(1, true, Outcome::Interrupted));
        history.note_attempt(1);
        history.note_attempt(1);
        assert_eq!(history.all()[0].attempts, 2);

        // What the end of an attempt writes: a fresh record for the same id,
        // carrying attempts: 0 from `Record` construction.
        history.record(record(1, true, Outcome::Interrupted));

        assert_eq!(
            history.all()[0].attempts,
            2,
            "the attempt count belongs to note_attempt, not to the completion path"
        );
    }

    #[test]
    fn retrying_under_the_same_id_never_grows_the_history() {
        // Each retry must continue one record. Writing a new id per attempt made
        // every attempt spawn another retryable record, so they multiplied.
        let dir = tempfile::tempdir().unwrap();
        let history = History::load(dir.path());

        history.record(record(1, true, Outcome::Interrupted));
        for _ in 0..4 {
            history.note_attempt(1);
            history.record(record(1, true, Outcome::Interrupted));
        }

        assert_eq!(
            history.all().len(),
            1,
            "one logical transfer must stay one record however many attempts it takes"
        );
        assert_eq!(history.all()[0].attempts, 4);
    }

    #[test]
    fn awaiting_retry_groups_by_peer() {
        let dir = tempfile::tempdir().unwrap();
        let history = History::load(dir.path());

        history.record(record(1, true, Outcome::Interrupted));
        history.record(record(2, true, Outcome::Interrupted));
        history.record(record(3, true, Outcome::Completed));

        let waiting = history.awaiting_retry();
        assert_eq!(waiting.len(), 2, "one group per distinct peer");
        assert!(waiting.values().all(|records| records.len() == 1));
    }

    #[test]
    fn clearing_keeps_what_still_needs_retrying() {
        let dir = tempfile::tempdir().unwrap();
        let history = History::load(dir.path());

        history.record(record(1, true, Outcome::Completed));
        history.record(record(2, true, Outcome::Interrupted));
        history.clear_finished();

        let all = history.all();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, 2, "an in-flight retry must not be swept away");
    }

    #[test]
    fn the_list_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let history = History::load(dir.path());

        for id in 0..(MAX_RECORDS as u64 + 50) {
            history.record(record(id, true, Outcome::Completed));
        }

        assert_eq!(history.all().len(), MAX_RECORDS);
    }

    #[test]
    fn a_damaged_file_reads_as_empty_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE), "{ not json").unwrap();

        assert!(History::load(dir.path()).all().is_empty());
    }

    #[test]
    fn the_file_is_human_readable() {
        let dir = tempfile::tempdir().unwrap();
        let history = History::load(dir.path());
        history.record(record(1, true, Outcome::Interrupted));

        let text = std::fs::read_to_string(dir.path().join(FILE)).unwrap();
        assert!(text.contains("interrupted"), "got: {text}");
        assert!(text.contains("Peer 1"));
    }
}
