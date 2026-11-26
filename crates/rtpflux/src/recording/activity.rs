//! What became of finished recordings: counters (conversions, S3 uploads,
//! webhook notifications), for `/metrics` and the web UI's Statistics
//! page, and the most recent uploads and webhook deliveries, for its
//! Recordings page.
//!
//! Written by the conversion thread, the S3 store and the webhook thread
//! once per recording or notification (never per packet), read by the
//! metrics and web UI threads. The lists keep the last [`KEEP`] entries
//! each; older ones are dropped. Error texts are cleaned of URL queries
//! and credentials (a presigned S3 URL carries its signature in its query),
//! and cut to [`ERROR_MAX`] characters.

use serde_json::{Value, json};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// Entries each list keeps.
pub const KEEP: usize = 200;
/// Characters of an error text kept.
pub const ERROR_MAX: usize = 300;

/// The counters and recent events of recordings after they end.
#[derive(Debug, Default)]
pub struct Activity {
    /// Recordings converted to their audio format (or kept as pcap).
    pub converted: AtomicU64,
    /// Conversions that failed (the pcap is kept).
    pub conversions_failed: AtomicU64,
    /// Files uploaded to S3.
    pub uploaded: AtomicU64,
    /// Files whose every upload attempt failed (kept locally).
    pub uploads_failed: AtomicU64,
    /// Webhook notifications answered with 2xx.
    pub webhooks_delivered: AtomicU64,
    /// … given up after their attempts, or refused (a final status).
    pub webhooks_failed: AtomicU64,
    /// … dropped unsent (a full queue, or the relay stopping).
    pub webhooks_dropped: AtomicU64,
    uploads: Mutex<VecDeque<Value>>,
    deliveries: Mutex<VecDeque<Value>>,
}

/// Milliseconds since the Unix epoch.
#[must_use]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// `text` without the queries and credentials of the URLs in it, at most
/// [`ERROR_MAX`] characters.
#[must_use]
pub fn clean_error(text: &str) -> String {
    let mut out = String::new();
    for (i, word) in text.split(' ').enumerate() {
        if i > 0 {
            out.push(' ');
        }
        match word.find("://") {
            Some(at) => {
                let (scheme, rest) = word.split_at(at + 3);
                // Credentials before the host, the query and fragment after.
                let rest = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
                let rest = rest.split(['?', '#']).next().unwrap_or("");
                out.push_str(scheme);
                out.push_str(rest);
            }
            None => out.push_str(word),
        }
    }
    out.chars().take(ERROR_MAX).collect()
}

fn push(list: &Mutex<VecDeque<Value>>, event: Value) {
    let mut l = list
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if l.len() >= KEEP {
        l.pop_front();
    }
    l.push_back(event);
}

fn newest_first(list: &Mutex<VecDeque<Value>>) -> Vec<Value> {
    list.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .rev()
        .cloned()
        .collect()
}

/// One file of an upload, as the Recordings page lists it.
#[derive(Debug, Clone)]
pub struct UploadedFile {
    pub name: String,
    /// The object key (uploaded), or none (kept locally).
    pub key: Option<String>,
    pub size: u64,
    /// Why it was not uploaded.
    pub error: Option<String>,
}

impl Activity {
    /// A recording's files were uploaded (or tried): counted, and listed.
    pub fn upload(&self, call_id: &str, from_tag: &str, bucket: &str, files: &[UploadedFile]) {
        let ok = files.iter().filter(|f| f.key.is_some()).count() as u64;
        self.uploaded.fetch_add(ok, Ordering::Relaxed);
        self.uploads_failed
            .fetch_add(files.len() as u64 - ok, Ordering::Relaxed);
        push(
            &self.uploads,
            json!({
                "at_ms": now_ms(),
                "call_id": call_id,
                "from_tag": from_tag,
                "bucket": bucket,
                "complete": files.iter().all(|f| f.key.is_some()),
                "files": files.iter().map(|f| json!({
                    "name": f.name,
                    "key": f.key,
                    "size": f.size,
                    "error": f.error.as_deref().map(clean_error),
                })).collect::<Vec<_>>(),
            }),
        );
    }

    /// A webhook notification's outcome: `delivered`, `failed` (given up),
    /// `rejected` (a final status) or `dropped` (never sent); counted, and
    /// listed.
    #[allow(clippy::too_many_arguments)] // One event's fields.
    pub fn delivery(
        &self,
        delivery: &str,
        call_id: &str,
        outcome: &'static str,
        status: Option<u16>,
        attempts: u32,
        error: Option<&str>,
    ) {
        let counter = match outcome {
            "delivered" => &self.webhooks_delivered,
            "dropped" => &self.webhooks_dropped,
            _ => &self.webhooks_failed,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        push(
            &self.deliveries,
            json!({
                "at_ms": now_ms(),
                "delivery": delivery,
                "call_id": call_id,
                "outcome": outcome,
                "status": status,
                "attempts": attempts,
                "error": error.map(clean_error),
            }),
        );
    }

    /// The recent uploads, newest first.
    #[must_use]
    pub fn uploads(&self) -> Vec<Value> {
        newest_first(&self.uploads)
    }

    /// The recent webhook deliveries, newest first.
    #[must_use]
    pub fn deliveries(&self) -> Vec<Value> {
        newest_first(&self.deliveries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_lose_queries_and_credentials() {
        assert_eq!(
            clean_error("http://127.0.0.1:9/rec/a.wav?X-Amz-Signature=abc: Connection refused"),
            "http://127.0.0.1:9/rec/a.wav Connection refused"
        );
        assert_eq!(
            clean_error("posting https://user:pw@hooks.example/x?token=t#f failed"),
            "posting https://hooks.example/x failed"
        );
        assert_eq!(clean_error(&"x".repeat(1000)).len(), ERROR_MAX);
    }

    #[test]
    fn lists_keep_the_newest_and_counters_count() {
        let a = Activity::default();
        for i in 0..KEEP + 5 {
            a.delivery(&format!("d{i}"), "c", "delivered", Some(200), 1, None);
        }
        let d = a.deliveries();
        assert_eq!(d.len(), KEEP);
        assert_eq!(d[0]["delivery"], format!("d{}", KEEP + 4), "newest first");
        assert_eq!(
            a.webhooks_delivered.load(Ordering::Relaxed),
            KEEP as u64 + 5
        );
        a.delivery("x", "c", "dropped", None, 0, Some("queue full"));
        a.delivery("y", "c", "rejected", Some(400), 1, None);
        assert_eq!(a.webhooks_dropped.load(Ordering::Relaxed), 1);
        assert_eq!(a.webhooks_failed.load(Ordering::Relaxed), 1);
        a.upload(
            "c",
            "t",
            "b",
            &[
                UploadedFile {
                    name: "a.wav".into(),
                    key: Some("k/a.wav".into()),
                    size: 8,
                    error: None,
                },
                UploadedFile {
                    name: "a.json".into(),
                    key: None,
                    size: 2,
                    error: Some("http://s3/x?sig=1 refused".into()),
                },
            ],
        );
        let u = &a.uploads()[0];
        assert_eq!(u["complete"], false);
        assert_eq!(u["files"][1]["error"], "http://s3/x refused");
        assert_eq!(
            (
                a.uploaded.load(Ordering::Relaxed),
                a.uploads_failed.load(Ordering::Relaxed)
            ),
            (1, 1)
        );
    }
}
