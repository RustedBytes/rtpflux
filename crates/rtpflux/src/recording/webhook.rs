//! `[recording.s3.webhook]`: after a finished recording is uploaded to S3,
//! an HTTP `POST` with a JSON description of it (call, tags, metadata, and
//! each uploaded object's key, URL, type and size).
//!
//! Notifications are delivered by a thread of their own, from a bounded
//! queue, so a slow or unreachable receiver never holds up converting and
//! uploading the next recording; when the queue is full a notification is
//! dropped and logged. Each delivery is tried up to `attempts` times:
//! timeouts, connection errors, 5xx, 408 and 429 are retried after an
//! exponential backoff with jitter (at least what `Retry-After` asks, at
//! most `backoff_max_ms`); any other status is final. Every attempt has a
//! strict deadline (`timeout_ms`, DNS to response, with `connect_timeout_ms`
//! for the connection), redirects are not followed, and the response body
//! is not read. When the relay stops, what is queued gets one attempt each
//! within twice `timeout_ms`, then the rest is dropped and logged.
//!
//! With `RTPFLUX_WEBHOOK_SECRET` in the environment (never the
//! configuration file), each request carries
//! `X-Rtpflux-Signature: sha256=<hex>`, the HMAC-SHA256 of
//! `<X-Rtpflux-Timestamp>.<body>` keyed with it. `X-Rtpflux-Delivery` is the
//! same on every attempt of one notification, for receivers to drop repeats.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The environment variable holding the signing secret.
pub const SECRET_ENV: &str = "RTPFLUX_WEBHOOK_SECRET";

/// The `event` of a notification (and its `X-Rtpflux-Event` header).
pub const EVENT_UPLOADED: &str = "recording.uploaded";

/// `[recording.s3.webhook]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WebhookConfig {
    /// Where notifications are posted: an `http://` or `https://` URL.
    pub url: String,
    /// Each attempt's deadline, from resolving the host to the response's
    /// headers, in milliseconds (100 to 60 000).
    pub timeout_ms: u64,
    /// Each attempt's deadline for connecting (100 to `timeout_ms`).
    pub connect_timeout_ms: u64,
    /// Attempts per notification (1 to 20).
    pub attempts: u32,
    /// The delay before the first retry, doubled for each further one, in
    /// milliseconds (10 to 60 000); each delay is jittered (half of it, plus
    /// up to half of it at random).
    pub backoff_ms: u64,
    /// The longest delay between attempts (`backoff_ms` to 600 000),
    /// `Retry-After` included.
    pub backoff_max_ms: u64,
    /// Notifications waiting to be delivered (1 to 100 000); more are
    /// dropped and logged.
    pub queue: usize,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        WebhookConfig {
            url: String::new(),
            timeout_ms: 5_000,
            connect_timeout_ms: 2_000,
            attempts: 5,
            backoff_ms: 1_000,
            backoff_max_ms: 30_000,
            queue: 1_000,
        }
    }
}

impl WebhookConfig {
    /// Every problem with the settings, as `webhook.<key>: …` (shown
    /// under `recording.s3.`).
    #[must_use]
    pub fn problems(&self) -> Vec<String> {
        let mut p = Vec::new();
        let key = |k: &str, why: &str| format!("webhook.{k}: {why}");
        if !(self.url.starts_with("https://") || self.url.starts_with("http://")) {
            p.push(key("url", "an http:// or https:// URL is needed"));
        }
        if !(100..=60_000).contains(&self.timeout_ms) {
            p.push(key("timeout_ms", "100 to 60000"));
        }
        if self.connect_timeout_ms < 100 || self.connect_timeout_ms > self.timeout_ms {
            p.push(key("connect_timeout_ms", "100 to timeout_ms"));
        }
        if !(1..=20).contains(&self.attempts) {
            p.push(key("attempts", "1 to 20"));
        }
        if !(10..=60_000).contains(&self.backoff_ms) {
            p.push(key("backoff_ms", "10 to 60000"));
        }
        if self.backoff_max_ms < self.backoff_ms || self.backoff_max_ms > 600_000 {
            p.push(key("backoff_max_ms", "backoff_ms to 600000"));
        }
        if !(1..=100_000).contains(&self.queue) {
            p.push(key("queue", "1 to 100000"));
        }
        p
    }

    /// The delay before attempt `next` (2 for the first retry), before
    /// jitter: `backoff_ms` doubled per retry, at most `backoff_max_ms`.
    #[must_use]
    pub fn backoff(&self, next: u32) -> u64 {
        let doublings = next.saturating_sub(2).min(30);
        self.backoff_ms
            .saturating_mul(1 << doublings)
            .min(self.backoff_max_ms)
    }
}

/// One uploaded object, as the notification describes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UploadedFile {
    /// The object key in the bucket.
    pub key: String,
    /// The object's (unsigned) URL.
    pub url: String,
    pub content_type: &'static str,
    /// Its size in octets.
    pub size: u64,
}

/// A notification's body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Event {
    /// [`EVENT_UPLOADED`].
    pub event: &'static str,
    /// The same on every attempt (also in `X-Rtpflux-Delivery`).
    pub delivery: String,
    /// Unix time of the upload, in milliseconds.
    pub uploaded_ms: u64,
    pub call_id: String,
    pub from_tag: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_tag: Option<String>,
    /// The media section, from 1.
    pub section: usize,
    /// The recording's metadata (`[recording.metadata]`, `start
    /// recording`'s).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    pub bucket: String,
    pub files: Vec<UploadedFile>,
    /// Every file of the recording was uploaded.
    pub complete: bool,
    /// The names of files that could not be uploaded (kept locally).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_uploaded: Vec<String>,
}

impl Event {
    /// A notification of `files` (uploaded to `bucket`) of the recording
    /// `meta` describes, with a fresh delivery id.
    #[must_use]
    pub fn uploaded(
        meta: &super::convert::Meta,
        bucket: &str,
        files: Vec<UploadedFile>,
        not_uploaded: Vec<String>,
    ) -> Self {
        Event {
            event: EVENT_UPLOADED,
            delivery: format!("{:032x}", rand::random::<u128>()),
            uploaded_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
            call_id: meta.call_id.clone(),
            from_tag: meta.from_tag.clone(),
            to_tag: meta.to_tag.clone(),
            section: meta.section,
            metadata: meta.metadata.clone(),
            bucket: bucket.to_owned(),
            complete: not_uploaded.is_empty(),
            files,
            not_uploaded,
        }
    }
}

/// `sha256=<hex>`: the HMAC-SHA256 of `<timestamp>.<body>` keyed with
/// `secret`.
#[must_use]
pub fn signature(secret: &[u8], timestamp: u64, body: &[u8]) -> String {
    use hmac::{KeyInit as _, Mac as _};
    use std::fmt::Write as _;
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    // HMAC takes keys of any length.
    let mut mac = HmacSha256::new_from_slice(secret).unwrap_or_else(|_| unreachable!());
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    let mut out = String::from("sha256=");
    for b in mac.finalize().into_bytes() {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(feature = "s3")]
pub use delivery::{Notifier, WebhookError};

#[cfg(feature = "s3")]
mod delivery {
    use super::super::activity::Activity;
    use super::{Event, SECRET_ENV, WebhookConfig};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    /// Response headers larger than this end the attempt.
    const MAX_RESPONSE_HEADERS: usize = 16 * 1024;

    /// Why the webhook cannot be used.
    #[derive(Debug)]
    pub enum WebhookError {
        /// The URL cannot be parsed.
        Url(url::ParseError),
        /// The delivery thread cannot be started.
        Thread(std::io::Error),
    }

    impl std::fmt::Display for WebhookError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                WebhookError::Url(e) => write!(f, "recording.s3.webhook.url: {e}"),
                WebhookError::Thread(e) => write!(f, "recording webhook thread: {e}"),
            }
        }
    }

    impl std::error::Error for WebhookError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                WebhookError::Url(e) => Some(e),
                WebhookError::Thread(e) => Some(e),
            }
        }
    }

    /// Queues notifications for the delivery thread. Dropping it lets the
    /// thread deliver what is queued (one attempt each, within twice
    /// `timeout_ms`) and waits for it.
    pub struct Notifier {
        tx: Option<SyncSender<Event>>,
        /// Where outcomes are counted and listed (drops here too).
        activity: Arc<Activity>,
        closing: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
        /// The URL without query or credentials, for logs.
        target: String,
    }

    impl std::fmt::Debug for Notifier {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Notifier({})", self.target)
        }
    }

    /// How one attempt went.
    enum Outcome {
        Delivered(u16),
        /// Worth another attempt: why, and the `Retry-After` delay asked.
        Retry(String, Option<Duration>),
        /// Not worth another: the status.
        Final(u16),
    }

    /// The delivery thread's side.
    struct Sender {
        config: WebhookConfig,
        agent: ureq::Agent,
        secret: Option<Vec<u8>>,
        target: String,
        closing: Arc<AtomicBool>,
        activity: Arc<Activity>,
    }

    /// `scheme://host[:port]/path` of `url`: no credentials, no query (a
    /// token in either stays out of the logs).
    fn redact(url: &url::Url) -> String {
        let port = url.port().map_or_else(String::new, |p| format!(":{p}"));
        format!(
            "{}://{}{port}{}",
            url.scheme(),
            url.host_str().unwrap_or(""),
            url.path()
        )
    }

    impl Notifier {
        /// Start delivering to `config.url`, counting and listing outcomes
        /// in `activity`; the signing secret, if any, is read from
        /// [`SECRET_ENV`].
        ///
        /// # Errors
        ///
        /// When the URL cannot be parsed or the thread cannot start.
        pub fn start(
            config: &WebhookConfig,
            activity: Arc<Activity>,
        ) -> Result<Self, WebhookError> {
            let secret = std::env::var(SECRET_ENV)
                .ok()
                .filter(|s| !s.is_empty())
                .map(String::into_bytes);
            Self::start_with_secret(config, secret, activity)
        }

        /// [`Notifier::start`] with the secret given.
        ///
        /// # Errors
        ///
        /// As [`Notifier::start`].
        pub(crate) fn start_with_secret(
            config: &WebhookConfig,
            secret: Option<Vec<u8>>,
            activity: Arc<Activity>,
        ) -> Result<Self, WebhookError> {
            let url: url::Url = config.url.parse().map_err(WebhookError::Url)?;
            let target = redact(&url);
            let agent = ureq::Agent::config_builder()
                .timeout_global(Some(Duration::from_millis(config.timeout_ms)))
                .timeout_connect(Some(Duration::from_millis(config.connect_timeout_ms)))
                .max_redirects(0)
                .max_redirects_will_error(false)
                .http_status_as_error(false)
                .max_response_header_size(MAX_RESPONSE_HEADERS)
                .build()
                .into();
            let signed = secret.is_some();
            let closing = Arc::new(AtomicBool::new(false));
            let (tx, rx) = std::sync::mpsc::sync_channel(config.queue.max(1));
            let sender = Sender {
                config: config.clone(),
                agent,
                secret,
                target: target.clone(),
                closing: Arc::clone(&closing),
                activity: Arc::clone(&activity),
            };
            let thread = std::thread::Builder::new()
                .name("rtpflux-webhook".to_owned())
                .spawn(move || sender.run(&rx))
                .map_err(WebhookError::Thread)?;
            log::info!(
                "recording: uploads notified to {target}{}",
                if signed { " (signed)" } else { "" }
            );
            Ok(Notifier {
                tx: Some(tx),
                activity,
                closing,
                thread: Some(thread),
                target,
            })
        }

        /// Queue `event`; dropped (and logged) when the queue is full.
        pub fn notify(&self, event: Event) {
            let Some(tx) = &self.tx else { return };
            match tx.try_send(event) {
                Ok(()) => {}
                Err(TrySendError::Full(e)) => {
                    log::warn!(
                        "recording: webhook queue full; notification {} of {} dropped",
                        e.delivery,
                        e.call_id
                    );
                    self.activity.delivery(
                        &e.delivery,
                        &e.call_id,
                        "dropped",
                        None,
                        0,
                        Some("queue full"),
                    );
                }
                Err(TrySendError::Disconnected(e)) => {
                    log::warn!(
                        "recording: webhook thread gone; notification {} of {} dropped",
                        e.delivery,
                        e.call_id
                    );
                    self.activity.delivery(
                        &e.delivery,
                        &e.call_id,
                        "dropped",
                        None,
                        0,
                        Some("delivery thread gone"),
                    );
                }
            }
        }
    }

    impl Drop for Notifier {
        fn drop(&mut self) {
            self.closing.store(true, Ordering::Release);
            drop(self.tx.take());
            if let Some(t) = self.thread.take() {
                t.thread().unpark();
                let _ = t.join();
            }
        }
    }

    impl Sender {
        fn run(&self, rx: &Receiver<Event>) {
            let mut drain_until: Option<Instant> = None;
            let mut dropped = 0usize;
            for event in rx {
                if self.closing.load(Ordering::Acquire) {
                    let until = *drain_until.get_or_insert_with(|| {
                        Instant::now() + 2 * Duration::from_millis(self.config.timeout_ms)
                    });
                    if Instant::now() >= until {
                        dropped += 1;
                        self.activity.delivery(
                            &event.delivery,
                            &event.call_id,
                            "dropped",
                            None,
                            0,
                            Some("the relay stopped"),
                        );
                        continue;
                    }
                }
                self.deliver(&event);
            }
            if dropped > 0 {
                log::warn!(
                    "recording: {dropped} webhook notification(s) to {} not sent: the relay stopped",
                    self.target
                );
            }
        }

        /// Deliver `event`, retrying as the configuration says (once only
        /// while the relay stops).
        fn deliver(&self, event: &Event) {
            let body = match serde_json::to_vec(event) {
                Ok(b) => b,
                Err(e) => {
                    log::warn!("recording: webhook body for {}: {e}", event.call_id);
                    let why = e.to_string();
                    self.activity.delivery(
                        &event.delivery,
                        &event.call_id,
                        "failed",
                        None,
                        0,
                        Some(&why),
                    );
                    return;
                }
            };
            let mut attempt = 1;
            loop {
                match self.post(event, &body) {
                    Outcome::Delivered(status) => {
                        self.activity.delivery(
                            &event.delivery,
                            &event.call_id,
                            "delivered",
                            Some(status),
                            attempt,
                            None,
                        );
                        log::debug!(
                            "recording: webhook {} for {} delivered ({status}, attempt {attempt})",
                            event.delivery,
                            event.call_id
                        );
                        return;
                    }
                    Outcome::Final(status) => {
                        self.activity.delivery(
                            &event.delivery,
                            &event.call_id,
                            "rejected",
                            Some(status),
                            attempt,
                            None,
                        );
                        log::warn!(
                            "recording: webhook {} for {}: {} answered {status}; not retried",
                            event.delivery,
                            event.call_id,
                            self.target
                        );
                        return;
                    }
                    Outcome::Retry(why, retry_after) => {
                        let stopping = self.closing.load(Ordering::Acquire);
                        if attempt >= self.config.attempts || stopping {
                            self.activity.delivery(
                                &event.delivery,
                                &event.call_id,
                                "failed",
                                None,
                                attempt,
                                Some(&why),
                            );
                            log::warn!(
                                "recording: webhook {} for {} to {}: {why}; gave up after {attempt} attempt(s)",
                                event.delivery,
                                event.call_id,
                                self.target
                            );
                            return;
                        }
                        let delay = self.delay(attempt + 1, retry_after);
                        log::debug!(
                            "recording: webhook {} (attempt {attempt}): {why}; retrying in {} ms",
                            event.delivery,
                            delay.as_millis()
                        );
                        if !self.sleep(delay) {
                            self.activity.delivery(
                                &event.delivery,
                                &event.call_id,
                                "failed",
                                None,
                                attempt,
                                Some(&why),
                            );
                            log::warn!(
                                "recording: webhook {} for {}: {why}; not retried, the relay stops",
                                event.delivery,
                                event.call_id
                            );
                            return;
                        }
                        attempt += 1;
                    }
                }
            }
        }

        /// The jittered delay before attempt `next`, at least `retry_after`,
        /// at most `backoff_max_ms`.
        fn delay(&self, next: u32, retry_after: Option<Duration>) -> Duration {
            let base = self.config.backoff(next);
            let half = base / 2;
            let jittered = half + rand::random_range(0..=base - half);
            let max = Duration::from_millis(self.config.backoff_max_ms);
            Duration::from_millis(jittered)
                .max(retry_after.unwrap_or_default())
                .min(max)
        }

        /// Sleep for `d`, unless the relay starts stopping; whether it
        /// slept the whole time.
        fn sleep(&self, d: Duration) -> bool {
            let until = Instant::now() + d;
            loop {
                if self.closing.load(Ordering::Acquire) {
                    return false;
                }
                let now = Instant::now();
                if now >= until {
                    return true;
                }
                std::thread::park_timeout(until - now);
            }
        }

        /// One attempt.
        fn post(&self, event: &Event, body: &[u8]) -> Outcome {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let mut request = self
                .agent
                .post(&self.config.url)
                .header("Content-Type", "application/json")
                .header("User-Agent", concat!("rtpflux/", env!("CARGO_PKG_VERSION")))
                .header("X-Rtpflux-Event", event.event)
                .header("X-Rtpflux-Delivery", &event.delivery)
                .header("X-Rtpflux-Timestamp", timestamp.to_string());
            if let Some(secret) = &self.secret {
                request = request.header(
                    "X-Rtpflux-Signature",
                    super::signature(secret, timestamp, body),
                );
            }
            match request.send(body) {
                Ok(response) => {
                    let status = response.status().as_u16();
                    match status {
                        200..=299 => Outcome::Delivered(status),
                        408 | 429 | 500..=599 => {
                            let retry_after = response
                                .headers()
                                .get("retry-after")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.trim().parse::<u64>().ok())
                                .map(Duration::from_secs);
                            Outcome::Retry(format!("status {status}"), retry_after)
                        }
                        _ => Outcome::Final(status),
                    }
                }
                Err(e) => Outcome::Retry(e.to_string(), None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "s3")]
    use std::sync::Arc;

    #[test]
    fn settings() {
        let ok = WebhookConfig {
            url: "https://hooks.example.com/rec".to_owned(),
            ..WebhookConfig::default()
        };
        assert_eq!(ok.problems(), Vec::<String>::new());
        let bad = WebhookConfig {
            url: "ftp://x".to_owned(),
            timeout_ms: 50,
            connect_timeout_ms: 10,
            attempts: 0,
            backoff_ms: 5,
            backoff_max_ms: 1,
            queue: 0,
        };
        let p = bad.problems();
        for k in [
            "url",
            "timeout_ms",
            "connect_timeout_ms",
            "attempts",
            "backoff_ms",
            "backoff_max_ms",
            "queue",
        ] {
            assert!(
                p.iter().any(|x| x.starts_with(&format!("webhook.{k}:"))),
                "{k}: {p:?}"
            );
        }
        // A connect timeout longer than the attempt's.
        let p = WebhookConfig {
            connect_timeout_ms: 9_000,
            ..ok.clone()
        }
        .problems();
        assert_eq!(p.len(), 1, "{p:?}");
    }

    /// The TOML section: defaults for what it leaves out, unknown keys
    /// refused, and problems named by their full key.
    #[test]
    fn the_toml_section() {
        use crate::config::Config;
        let base = "[[interface]]\nname = \"a\"\naddress = \"10.0.0.1\"\n\
                    [recording]\ndir = \"/tmp\"\nstorage = \"s3\"\n\
                    [recording.s3]\nbucket = \"b\"\nregion = \"r\"\n";
        let text =
            format!("{base}[recording.s3.webhook]\nurl = \"https://h.example/x\"\nattempts = 3\n");
        let parsed: Config = toml::from_str(&text).unwrap();
        assert_eq!(
            parsed.recording.s3.webhook,
            Some(WebhookConfig {
                url: "https://h.example/x".to_owned(),
                attempts: 3,
                ..WebhookConfig::default()
            })
        );
        let none: Config = toml::from_str(base).unwrap();
        assert_eq!(none.recording.s3.webhook, None);
        assert!(
            toml::from_str::<Config>(&format!(
                "{base}[recording.s3.webhook]\nurl = \"https://h/\"\nretries = 3\n"
            ))
            .is_err(),
            "unknown keys are refused"
        );
        if cfg!(feature = "s3") {
            let bad = format!("{base}[recording.s3.webhook]\nurl = \"h\"\ntimeout_ms = 0\n");
            let Err(crate::config::ConfigError::Invalid(p)) = Config::from_toml(&bad) else {
                panic!("accepted");
            };
            let p: Vec<String> = p.iter().map(ToString::to_string).collect();
            assert!(
                p.contains(
                    &"recording.s3.webhook.url: an http:// or https:// URL is needed".to_owned()
                ),
                "{p:?}"
            );
            assert!(
                p.iter()
                    .any(|x| x.starts_with("recording.s3.webhook.timeout_ms:")),
                "{p:?}"
            );
        }
    }

    #[test]
    fn backoff_doubles_up_to_the_maximum() {
        let c = WebhookConfig {
            backoff_ms: 100,
            backoff_max_ms: 1_000,
            ..WebhookConfig::default()
        };
        let delays: Vec<u64> = (2..=8).map(|n| c.backoff(n)).collect();
        assert_eq!(delays, [100, 200, 400, 800, 1_000, 1_000, 1_000]);
        assert_eq!(c.backoff(u32::MAX), 1_000, "no overflow");
    }

    /// What the fake receiver does with one request.
    #[cfg(feature = "s3")]
    #[derive(Clone, Copy)]
    enum Reply {
        /// Answer with this status (and `Retry-After` seconds).
        Status(u16, Option<u64>),
        /// Read the request, then say nothing for this long.
        Silent(std::time::Duration),
    }

    /// A request the fake receiver got: its headers (lowercase), its body,
    /// and when it arrived.
    #[cfg(feature = "s3")]
    type Got = (String, Vec<u8>, std::time::Instant);

    /// A fake receiver: one connection per reply, in order.
    #[cfg(feature = "s3")]
    fn receiver(
        replies: Vec<Reply>,
    ) -> (
        String,
        std::sync::mpsc::Receiver<Got>,
        std::thread::JoinHandle<()>,
    ) {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            for reply in replies {
                let Ok((conn, _)) = listener.accept() else {
                    return;
                };
                let mut r = BufReader::new(conn.try_clone().unwrap());
                let (mut headers, mut len) = (String::new(), 0usize);
                loop {
                    let mut h = String::new();
                    if r.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                        break;
                    }
                    let h = h.to_ascii_lowercase();
                    if let Some(v) = h.strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap();
                    }
                    headers.push_str(&h);
                }
                let mut body = vec![0; len];
                let _ = r.read_exact(&mut body);
                let _ = tx.send((headers, body, std::time::Instant::now()));
                let mut w = conn;
                match reply {
                    Reply::Status(status, retry_after) => {
                        let ra = retry_after
                            .map_or_else(String::new, |s| format!("Retry-After: {s}\r\n"));
                        let _ = write!(
                            w,
                            "HTTP/1.1 {status} X\r\n{ra}Content-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                    }
                    // Held open on its own thread: the next connection
                    // is accepted meanwhile.
                    Reply::Silent(d) => drop(std::thread::spawn(move || {
                        std::thread::sleep(d);
                        drop(w);
                    })),
                }
            }
        });
        (url, rx, t)
    }

    #[cfg(feature = "s3")]
    fn event(call: &str) -> Event {
        Event {
            event: EVENT_UPLOADED,
            delivery: format!("d-{call}"),
            uploaded_ms: 1,
            call_id: call.to_owned(),
            from_tag: "a".to_owned(),
            to_tag: None,
            section: 1,
            metadata: BTreeMap::new(),
            bucket: "b".to_owned(),
            files: Vec::new(),
            complete: true,
            not_uploaded: Vec::new(),
        }
    }

    #[cfg(feature = "s3")]
    fn config(url: &str) -> WebhookConfig {
        WebhookConfig {
            url: url.to_owned(),
            timeout_ms: 2_000,
            connect_timeout_ms: 500,
            attempts: 4,
            backoff_ms: 40,
            backoff_max_ms: 1_000,
            queue: 16,
        }
    }

    /// 503 (with `Retry-After: 0`) and 500 are retried after the backoff,
    /// then 200 ends it: three requests, one delivery id, each signed.
    #[cfg(feature = "s3")]
    #[test]
    fn retries_server_errors_with_backoff_and_signs() {
        let (url, got, server) = receiver(vec![
            Reply::Status(503, Some(0)),
            Reply::Status(500, None),
            Reply::Status(200, None),
        ]);
        let n =
            Notifier::start_with_secret(&config(&url), Some(b"s3cr3t".to_vec()), Arc::default())
                .unwrap();
        n.notify(event("c1"));
        // Wait for the three attempts: dropping the notifier means the relay
        // stops, which ends retrying.
        let got: Vec<Got> = (0..3)
            .map(|_| got.recv_timeout(std::time::Duration::from_secs(5)).unwrap())
            .collect();
        drop(n);
        server.join().unwrap();
        let header = |h: &str, name: &str| {
            h.lines()
                .find_map(|l| l.strip_prefix(&format!("{name}: ")))
                .map(|v| v.trim().to_owned())
                .unwrap()
        };
        for (headers, body, _) in &got {
            assert_eq!(header(headers, "x-rtpflux-delivery"), "d-c1");
            let ts: u64 = header(headers, "x-rtpflux-timestamp").parse().unwrap();
            assert_eq!(
                header(headers, "x-rtpflux-signature"),
                signature(b"s3cr3t", ts, body)
            );
            let v: serde_json::Value = serde_json::from_slice(body).unwrap();
            assert_eq!(v["call_id"], "c1");
        }
        // Each retry waited at least half its backoff (40 ms, then 80 ms).
        let gaps: Vec<_> = got.windows(2).map(|w| w[1].2 - w[0].2).collect();
        assert!(gaps[0] >= std::time::Duration::from_millis(20), "{gaps:?}");
        assert!(gaps[1] >= std::time::Duration::from_millis(40), "{gaps:?}");
    }

    /// A 4xx other than 408 and 429 is final.
    #[cfg(feature = "s3")]
    #[test]
    fn a_client_error_is_not_retried() {
        let (url, got, server) = receiver(vec![Reply::Status(400, None)]);
        let n = Notifier::start_with_secret(&config(&url), None, Arc::default()).unwrap();
        n.notify(event("c2"));
        got.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        // Longer than the backoff: a retry would have come by now.
        std::thread::sleep(std::time::Duration::from_millis(300));
        drop(n);
        server.join().unwrap();
        assert_eq!(got.try_iter().count(), 0, "not retried");
    }

    /// A receiver that never answers: each attempt ends at its deadline,
    /// not later.
    #[cfg(feature = "s3")]
    #[test]
    fn each_attempt_ends_at_its_deadline() {
        let silent = Reply::Silent(std::time::Duration::from_secs(3));
        let (url, got, _server) = receiver(vec![silent, silent]);
        let c = WebhookConfig {
            timeout_ms: 300,
            connect_timeout_ms: 200,
            attempts: 2,
            backoff_ms: 10,
            ..config(&url)
        };
        let start = std::time::Instant::now();
        let n = Notifier::start_with_secret(&c, None, Arc::default()).unwrap();
        n.notify(event("c3"));
        // Two attempts of 300 ms and a short backoff, then given up.
        let first = got.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        let second = got.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        let gap = second.2 - first.2;
        assert!(
            gap >= std::time::Duration::from_millis(300)
                && gap < std::time::Duration::from_millis(900),
            "the first attempt lasted its deadline: {gap:?}"
        );
        drop(n);
        assert!(
            start.elapsed() < std::time::Duration::from_millis(1_500),
            "{:?}",
            start.elapsed()
        );
    }

    /// The relay stops while the receiver is dead: what is queued gets one
    /// attempt each within twice the deadline, the rest is dropped.
    #[cfg(feature = "s3")]
    #[test]
    fn stopping_with_a_dead_receiver_is_bounded() {
        let silent = Reply::Silent(std::time::Duration::from_secs(5));
        let (url, _got, _server) = receiver(vec![silent; 20]);
        let c = WebhookConfig {
            timeout_ms: 200,
            connect_timeout_ms: 100,
            attempts: 5,
            backoff_ms: 1_000,
            ..config(&url)
        };
        let n = Notifier::start_with_secret(&c, None, Arc::default()).unwrap();
        for i in 0..10 {
            n.notify(event(&format!("q{i}")));
        }
        let start = std::time::Instant::now();
        drop(n);
        // Twice the deadline to start attempts, plus the last one's own.
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn signatures_follow_the_documented_scheme() {
        // HMAC-SHA256("key", "1700000000.{}"), from Python's hmac module.
        assert_eq!(
            signature(b"key", 1_700_000_000, b"{}"),
            "sha256=9d713ed406bb7076d4123f0dc2c39d2df5c654ed4b0cd56b52c8b4c940bd63ae"
        );
    }
}
