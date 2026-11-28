//! The operation ledger: what became of each native request that carries an
//! operation key (`idempotency_key`), so a retry gets the first attempt's
//! outcome and never runs it twice.
//!
//! - **Fingerprint.** A request's intent is its canonical JSON (keys
//!   sorted at every level, no whitespace) without the fields of a single
//!   attempt: `v`, `operation_id`, `idempotency_key`, `tenant`,
//!   `deadline_unix_ms`, `first_attempt_unix_ms` and `correlation_id`. Its
//!   SHA-256 is the fingerprint. The same key with another fingerprint is a
//!   `conflict`, never the first reply.
//! - **Durable mode** (`[sessions] ledger`): each keyed mutation is written
//!   to an append-only file before it runs (`pending`), and its outcome
//!   after (`applied` or `failed`), each write reaching the disk (`fsync`)
//!   before the next step. A `pending` with no outcome after a restart is
//!   `unknown`: the request may or may not have taken effect, and a retry
//!   gets that answer instead of running it again. The file is rewritten
//!   without the expired entries when it grows. It holds replies (with SDP,
//!   which may carry SRTP keys): it is created readable by the relay's user
//!   only.
//! - **Memory mode** (no file): the same rules for a process's lifetime.
//! - **Expiry.** An entry lives for the retention period. A request that
//!   says when it was first attempted (`first_attempt_unix_ms`) and is older
//!   than that is refused (`expired`) rather than run: its first attempt's
//!   outcome is no longer known. A tenant holds at most a quota of entries;
//!   beyond it, keyed requests are refused (`exhausted`), never evicting an
//!   entry that a retry could still need.

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};

/// The fields of a single attempt, left out of a request's fingerprint.
pub const ATTEMPT_FIELDS: [&str; 7] = [
    "v",
    "operation_id",
    "idempotency_key",
    "tenant",
    "deadline_unix_ms",
    "first_attempt_unix_ms",
    "correlation_id",
];

/// Records in the file after which it is rewritten (without the expired).
const COMPACT_AFTER: usize = 50_000;

/// What became of an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Running (in this process), or written as running before a restart
    /// (then it is reported `unknown`).
    Pending,
    Applied,
    Failed,
    /// Begun before a restart, with no outcome written: it may or may not
    /// have taken effect.
    Unknown,
}

/// One operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub op: String,
    pub fingerprint: String,
    pub status: Status,
    /// The reply given (an applied or failed operation's).
    #[serde(default)]
    pub reply: Option<Json>,
    /// The resources it made or changed (endpoint, mixer, stream, … ids).
    #[serde(default)]
    pub resources: Vec<String>,
    pub at_ms: u64,
}

/// A line of the file.
#[derive(Debug, Serialize, Deserialize)]
struct Record {
    tenant: String,
    key: String,
    #[serde(flatten)]
    entry: Entry,
}

/// Why the ledger cannot take an operation.
#[derive(Debug)]
pub enum LedgerError {
    /// The tenant holds its quota of entries.
    Quota,
    /// Writing the file failed: nothing is recorded.
    Storage(std::io::Error),
}

/// The ledger.
#[derive(Debug)]
pub struct Ledger {
    file: Option<(PathBuf, std::fs::File)>,
    entries: HashMap<(String, String), Entry>,
    order: VecDeque<((String, String), u64)>,
    records: usize,
    pub retention_ms: u64,
    pub quota: usize,
    /// Entries per tenant.
    per_tenant: HashMap<String, usize>,
}

/// `v` with its object keys sorted at every level.
fn canonical(v: &Json) -> Json {
    match v {
        Json::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            // serde_json's map keeps insertion order with `preserve_order`,
            // sorted order without: insert sorted either way.
            let mut m = serde_json::Map::new();
            for k in keys {
                if let Some(x) = o.get(k) {
                    m.insert(k.clone(), canonical(x));
                }
            }
            Json::Object(m)
        }
        Json::Array(a) => Json::Array(a.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

/// A request's fingerprint: SHA-256 (hex) of its canonical JSON without
/// the fields of a single attempt.
#[must_use]
pub fn fingerprint(body: &serde_json::Map<String, Json>) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let mut intent = body.clone();
    for f in ATTEMPT_FIELDS {
        intent.remove(f);
    }
    let text = canonical(&Json::Object(intent)).to_string();
    let digest = Sha256::digest(text.as_bytes());
    let mut hex = String::with_capacity(64);
    for b in digest {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// The default retention and quota of a ledger in memory.
pub const DEFAULT_RETENTION_MS: u64 = 300_000;
pub const DEFAULT_QUOTA: usize = 100_000;

impl Default for Ledger {
    fn default() -> Self {
        Self::in_memory(DEFAULT_RETENTION_MS, DEFAULT_QUOTA)
    }
}

impl Ledger {
    /// A ledger in memory only.
    #[must_use]
    pub fn in_memory(retention_ms: u64, quota: usize) -> Self {
        Ledger {
            file: None,
            entries: HashMap::new(),
            order: VecDeque::new(),
            records: 0,
            retention_ms,
            quota,
            per_tenant: HashMap::new(),
        }
    }

    /// The ledger in the file at `path` (made if missing), with what it
    /// holds read back: an operation begun and never finished is `unknown`.
    ///
    /// # Errors
    ///
    /// When the file cannot be opened, read or written.
    pub fn open(
        path: &Path,
        retention_ms: u64,
        quota: usize,
        now_ms: u64,
    ) -> std::io::Result<Self> {
        use std::io::BufRead;
        let mut l = Self::in_memory(retention_ms, quota);
        if let Ok(f) = std::fs::File::open(path) {
            for line in std::io::BufReader::new(f).lines() {
                let line = line?;
                // A line cut short by a crash (the last one) is skipped.
                let Ok(r) = serde_json::from_str::<Record>(&line) else {
                    continue;
                };
                l.put((r.tenant, r.key), r.entry);
            }
        }
        for e in l.entries.values_mut() {
            if e.status == Status::Pending {
                e.status = Status::Unknown;
            }
        }
        l.expire(now_ms);
        // Rewritten at once: compact, and the unknowns recorded as such.
        l.rewrite(path)?;
        Ok(l)
    }

    /// Whether outcomes reach the disk before they are acknowledged.
    #[must_use]
    pub fn durable(&self) -> bool {
        self.file.is_some()
    }

    fn put(&mut self, key: (String, String), entry: Entry) {
        if !self.entries.contains_key(&key) {
            *self.per_tenant.entry(key.0.clone()).or_default() += 1;
            self.order.push_back((key.clone(), entry.at_ms));
        }
        self.entries.insert(key, entry);
    }

    /// The operation `key` of `tenant`, if known.
    #[must_use]
    pub fn get(&self, tenant: &str, key: &str) -> Option<&Entry> {
        self.entries.get(&(tenant.to_owned(), key.to_owned()))
    }

    /// The operations whose outcome is unknown: (tenant, key, entry).
    pub fn unknown(&self) -> impl Iterator<Item = (&str, &str, &Entry)> {
        self.entries
            .iter()
            .filter(|(_, e)| e.status == Status::Unknown)
            .map(|((t, k), e)| (t.as_str(), k.as_str(), e))
    }

    /// Forget entries older than the retention period.
    pub fn expire(&mut self, now_ms: u64) {
        while let Some((k, at)) = self.order.front() {
            if now_ms.saturating_sub(*at) < self.retention_ms {
                break;
            }
            let k = k.clone();
            self.order.pop_front();
            if self.entries.remove(&k).is_some()
                && let Some(n) = self.per_tenant.get_mut(&k.0)
            {
                *n = n.saturating_sub(1);
            }
        }
    }

    /// Record `entry` for (`tenant`, `key`): in memory, and on disk (synced)
    /// in durable mode.
    ///
    /// # Errors
    ///
    /// [`LedgerError::Quota`] for a new key beyond the tenant's quota,
    /// [`LedgerError::Storage`] when the file cannot be written (the entry
    /// is then not recorded).
    pub fn record(&mut self, tenant: &str, key: &str, entry: Entry) -> Result<(), LedgerError> {
        let k = (tenant.to_owned(), key.to_owned());
        if !self.entries.contains_key(&k)
            && self.per_tenant.get(tenant).copied().unwrap_or(0) >= self.quota
        {
            return Err(LedgerError::Quota);
        }
        if let Some((_, f)) = &mut self.file {
            let line = serde_json::to_string(&Record {
                tenant: tenant.to_owned(),
                key: key.to_owned(),
                entry: entry.clone(),
            })
            .map_err(|e| LedgerError::Storage(std::io::Error::other(e)))?;
            f.write_all(line.as_bytes())
                .and_then(|()| f.write_all(b"\n"))
                .and_then(|()| f.sync_data())
                .map_err(LedgerError::Storage)?;
            self.records += 1;
        }
        self.put(k, entry);
        if self.records > COMPACT_AFTER
            && let Some((path, _)) = &self.file
        {
            let path = path.clone();
            if let Err(e) = self.rewrite(&path) {
                log::warn!("ledger: compacting {}: {e}", path.display());
            }
        }
        Ok(())
    }

    /// Rewrite the file with the live entries (aside, synced, renamed).
    fn rewrite(&mut self, path: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = path.with_extension("tmp");
        {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            for ((tenant, key), _) in &self.order {
                if let Some(e) = self.entries.get(&(tenant.clone(), key.clone())) {
                    let line = serde_json::to_string(&Record {
                        tenant: tenant.clone(),
                        key: key.clone(),
                        entry: e.clone(),
                    })
                    .map_err(std::io::Error::other)?;
                    f.write_all(line.as_bytes())?;
                    f.write_all(b"\n")?;
                }
            }
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        // The rename on the disk too. Not fatal: until it is, a crash
        // leaves the file it replaced, which holds every entry kept here
        // and more.
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty())
            && let Err(e) = std::fs::File::open(dir).and_then(|d| d.sync_all())
        {
            log::warn!("ledger: syncing {}: {e}", dir.display());
        }
        let f = std::fs::OpenOptions::new()
            .append(true)
            .mode(0o600)
            .open(path)?;
        self.records = self.entries.len();
        self.file = Some((path.to_path_buf(), f));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body(v: &Json) -> serde_json::Map<String, Json> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn a_fingerprint_is_the_intent_only() {
        let a = fingerprint(&body(
            &json!({"op": "x", "codecs": ["PCMU"], "o": {"b": 1, "a": 2},
            "operation_id": "1", "deadline_unix_ms": 5, "idempotency_key": "k"}),
        ));
        let b = fingerprint(&body(
            &json!({"o": {"a": 2, "b": 1}, "codecs": ["PCMU"], "op": "x",
            "operation_id": "2", "deadline_unix_ms": 9, "first_attempt_unix_ms": 1}),
        ));
        assert_eq!(a, b, "attempt fields and key order do not matter");
        let c = fingerprint(&body(
            &json!({"op": "x", "codecs": ["PCMA"], "o": {"a": 2, "b": 1}}),
        ));
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
    }

    fn entry(status: Status, at_ms: u64) -> Entry {
        Entry {
            op: "endpoint.create".into(),
            fingerprint: "f".into(),
            status,
            reply: Some(json!({"ok": true})),
            resources: vec!["ep-1".into()],
            at_ms,
        }
    }

    #[test]
    fn a_pending_operation_is_unknown_after_a_restart() {
        let dir = std::env::temp_dir().join(format!("rtpflux-ledger-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut l = Ledger::open(&path, 60_000, 10, 1000).unwrap();
        assert!(l.durable());
        l.record("t", "a", entry(Status::Pending, 1000)).unwrap();
        l.record("t", "a", entry(Status::Applied, 1001)).unwrap();
        l.record("t", "b", entry(Status::Pending, 1002)).unwrap();
        drop(l);
        // A torn last line (a crash in the middle of a write) is skipped.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"tenant\":\"t\",\"key\":\"c\",\"op")
            .unwrap();
        let l = Ledger::open(&path, 60_000, 10, 2000).unwrap();
        assert_eq!(l.get("t", "a").unwrap().status, Status::Applied);
        assert_eq!(l.get("t", "b").unwrap().status, Status::Unknown);
        assert!(l.get("t", "c").is_none());
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&path).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o600);
        // Expired at open.
        let l = Ledger::open(&path, 60_000, 10, 70_000).unwrap();
        assert!(l.get("t", "a").is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_tenant_has_a_quota() {
        let mut l = Ledger::in_memory(60_000, 2);
        l.record("t", "a", entry(Status::Applied, 1)).unwrap();
        l.record("t", "b", entry(Status::Applied, 1)).unwrap();
        assert!(matches!(
            l.record("t", "c", entry(Status::Applied, 1)),
            Err(LedgerError::Quota)
        ));
        // An existing key is updated; another tenant has its own.
        l.record("t", "a", entry(Status::Failed, 2)).unwrap();
        l.record("u", "a", entry(Status::Applied, 1)).unwrap();
        l.expire(70_000);
        l.record("t", "c", entry(Status::Applied, 70_000)).unwrap();
    }
}
