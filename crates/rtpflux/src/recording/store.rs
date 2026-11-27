//! Where finished recordings are kept: the local directory (the default),
//! or an S3 bucket (builds with the `s3` feature).
//!
//! With S3, the files of a finished recording are uploaded from the
//! conversion thread with presigned `PUT` requests (AWS Signature
//! Version 4), each up to three times, and the local copies removed once
//! uploaded (unless they are to be kept). A file that cannot be uploaded
//! stays in the local directory, and the failure is logged. Credentials come
//! from the environment (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
//! optionally `AWS_SESSION_TOKEN`), never from the configuration file.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// `[recording] storage`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Storage {
    /// The local `[recording] dir`.
    #[default]
    Local,
    /// An S3 bucket (`[recording.s3]`).
    S3,
}

/// `[recording.s3]`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct S3Config {
    pub bucket: String,
    /// E.g. `eu-west-1`.
    pub region: String,
    /// The service URL; by default AWS's for `region`. Set it for
    /// S3-compatible servers (`MinIO`, Ceph, R2, …).
    pub endpoint: Option<String>,
    /// Prepended to each file name to make the object key, e.g. `calls/`.
    pub prefix: String,
    /// Path-style URLs (`endpoint/bucket/key`) instead of virtual-hosted
    /// ones (`bucket.endpoint/key`); most S3-compatible servers need them.
    pub path_style: bool,
    /// Keep the local files after uploading them.
    pub keep_local: bool,
    /// `[recording.s3.webhook]`: notify after each recording's upload.
    pub webhook: Option<super::webhook::WebhookConfig>,
}

impl S3Config {
    /// The endpoint URL.
    #[must_use]
    pub fn endpoint(&self) -> String {
        self.endpoint
            .clone()
            .unwrap_or_else(|| format!("https://s3.{}.amazonaws.com", self.region))
    }

    /// Every problem with the settings.
    #[must_use]
    pub fn problems(&self) -> Vec<S3Problem> {
        let mut p = Vec::new();
        if !cfg!(feature = "s3") {
            p.push(S3Problem::NoS3Support);
        }
        if self.bucket.is_empty() {
            p.push(S3Problem::NoBucket);
        }
        if self.region.is_empty() {
            p.push(S3Problem::NoRegion);
        }
        if let Some(e) = &self.endpoint
            && !(e.starts_with("https://") || e.starts_with("http://"))
        {
            p.push(S3Problem::Endpoint(e.clone()));
        }
        if let Some(w) = &self.webhook {
            p.extend(w.problems().into_iter().map(S3Problem::Webhook));
        }
        p
    }
}

/// A problem with the `[recording.s3]` settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S3Problem {
    /// This build has no S3 support.
    NoS3Support,
    /// No bucket.
    NoBucket,
    /// No region.
    NoRegion,
    /// An endpoint that is not an http(s) URL.
    Endpoint(String),
    /// A `[recording.s3.webhook]` setting (the message names it).
    Webhook(String),
}

impl std::fmt::Display for S3Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            S3Problem::NoS3Support => {
                f.write_str("storage s3: this build has no S3 support (cargo feature `s3`)")
            }
            S3Problem::NoBucket => f.write_str("s3.bucket: required with storage = \"s3\""),
            S3Problem::NoRegion => f.write_str("s3.region: required with storage = \"s3\""),
            S3Problem::Endpoint(e) => {
                write!(f, "s3.endpoint {e}: an http:// or https:// URL is needed")
            }
            S3Problem::Webhook(why) => write!(f, "s3.{why}"),
        }
    }
}

/// The object key of a recording file: `prefix` + its path under the
/// recording directory `root` (a `recording-path` subdirectory kept, with
/// `/`), or its file name when it is directly in `root` or outside it.
#[must_use]
pub fn object_key(prefix: &str, root: Option<&Path>, path: &Path) -> Option<String> {
    let under_root = root
        .and_then(|r| path.strip_prefix(r).ok())
        .filter(|p| p.components().count() > 1);
    let name = match under_root {
        Some(rel) => rel
            .iter()
            .map(|c| c.to_string_lossy())
            .collect::<Vec<_>>()
            .join("/"),
        None => path.file_name()?.to_string_lossy().into_owned(),
    };
    Some(format!("{prefix}{name}"))
}

/// The content type of a recording file.
#[must_use]
pub fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("wav") => "audio/wav",
        Some("flac") => "audio/flac",
        Some("opus") => "audio/ogg",
        Some("mp3") => "audio/mpeg",
        Some("json") => "application/json",
        Some("pcap") => "application/vnd.tcpdump.pcap",
        _ => "application/octet-stream",
    }
}

/// Where finished recordings go.
pub enum Store {
    /// They stay in the local directory.
    Local,
    /// They are uploaded.
    #[cfg(feature = "s3")]
    S3(Box<s3::S3Store>),
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Store::Local => f.write_str("Store::Local"),
            #[cfg(feature = "s3")]
            Store::S3(s) => write!(f, "Store::S3({})", s.describe()),
        }
    }
}

/// Why recordings cannot be stored where the configuration says, or one
/// could not be uploaded.
#[derive(Debug)]
pub enum StoreError {
    /// S3 is asked for, but this build has no S3 support.
    NoS3Support,
    /// S3 credentials are not in the environment.
    NoCredentials,
    /// `s3.endpoint` is not a URL.
    #[cfg(feature = "s3")]
    Endpoint(url::ParseError),
    /// The bucket's URLs cannot be built from the endpoint and name.
    #[cfg(feature = "s3")]
    Bucket(rusty_s3::BucketError),
    /// A path without a file name to upload as.
    NoFileName,
    /// The file to upload cannot be opened.
    Open(std::io::Error),
    /// Every upload attempt failed; the last one's error.
    #[cfg(feature = "s3")]
    Upload(Box<ureq::Error>),
    /// The webhook cannot be used.
    #[cfg(feature = "s3")]
    Webhook(super::webhook::WebhookError),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::NoS3Support => {
                f.write_str("this build has no S3 support (cargo feature `s3`)")
            }
            StoreError::NoCredentials => f.write_str(
                "S3 recording storage needs AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in the environment",
            ),
            #[cfg(feature = "s3")]
            StoreError::Endpoint(e) => write!(f, "s3.endpoint: {e}"),
            #[cfg(feature = "s3")]
            StoreError::Bucket(e) => write!(f, "s3: {e}"),
            StoreError::NoFileName => f.write_str("no file name"),
            StoreError::Open(e) => e.fmt(f),
            #[cfg(feature = "s3")]
            StoreError::Upload(e) => e.fmt(f),
            #[cfg(feature = "s3")]
            StoreError::Webhook(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(feature = "s3")]
            StoreError::Endpoint(e) => Some(e),
            #[cfg(feature = "s3")]
            StoreError::Bucket(e) => Some(e),
            StoreError::Open(e) => Some(e),
            #[cfg(feature = "s3")]
            StoreError::Upload(e) => Some(&**e),
            #[cfg(feature = "s3")]
            StoreError::Webhook(e) => Some(e),
            _ => None,
        }
    }
}

impl Store {
    /// The store `[recording]` asks for; for S3 the credentials are read
    /// from the environment.
    ///
    /// # Errors
    ///
    /// When S3 is asked for but cannot be used: no S3 support in this
    /// build, a bad endpoint, or credentials missing.
    pub fn from_config(
        storage: Storage,
        config: &S3Config,
        dir: Option<&Path>,
        activity: &std::sync::Arc<super::activity::Activity>,
    ) -> Result<Self, StoreError> {
        match storage {
            Storage::Local => Ok(Store::Local),
            #[cfg(feature = "s3")]
            Storage::S3 => {
                let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
                let (Some(key), Some(secret)) =
                    (get("AWS_ACCESS_KEY_ID"), get("AWS_SECRET_ACCESS_KEY"))
                else {
                    return Err(StoreError::NoCredentials);
                };
                let credentials = match get("AWS_SESSION_TOKEN") {
                    Some(token) => rusty_s3::Credentials::new_with_token(key, secret, token),
                    None => rusty_s3::Credentials::new(key, secret),
                };
                let mut store = s3::S3Store::new(config, credentials)?
                    .with_activity(std::sync::Arc::clone(activity));
                if let Some(w) = &config.webhook {
                    let n = super::webhook::Notifier::start(w, std::sync::Arc::clone(activity))
                        .map_err(StoreError::Webhook)?;
                    store = store.with_notifier(n);
                }
                Ok(Store::S3(Box::new(match dir {
                    Some(d) => store.with_root(d),
                    None => store,
                })))
            }
            #[cfg(not(feature = "s3"))]
            Storage::S3 => {
                let _ = (config, dir, activity);
                Err(StoreError::NoS3Support)
            }
        }
    }

    /// Whether finished recordings are uploaded (not only kept locally).
    #[must_use]
    pub fn uploads(&self) -> bool {
        !matches!(self, Store::Local)
    }

    /// Keep the finished recording's `files` (of the recording `meta`
    /// describes): nothing to do locally; with S3, upload each (and remove
    /// the uploaded local copies unless they are kept), then queue the
    /// webhook's notification if one is set. Returns the files left on the
    /// local disk.
    #[must_use]
    pub fn keep(&self, files: &[PathBuf], meta: &super::convert::Meta) -> Vec<PathBuf> {
        match self {
            Store::Local => {
                let _ = meta;
                files.to_vec()
            }
            #[cfg(feature = "s3")]
            Store::S3(s) => s.keep(files, meta),
        }
    }
}

#[cfg(feature = "s3")]
pub mod s3 {
    //! Uploading to S3.

    use super::super::activity::{self, Activity};
    use super::super::webhook::{Event, Notifier, UploadedFile};
    use super::{PathBuf, S3Config, StoreError, content_type};
    use rusty_s3::{Bucket, Credentials, S3Action as _, UrlStyle};
    use std::sync::Arc;
    use std::time::Duration;

    /// Attempts per file.
    const ATTEMPTS: u32 = 3;

    /// An S3 bucket and the credentials to write to it.
    pub struct S3Store {
        bucket: Bucket,
        credentials: Credentials,
        prefix: String,
        keep_local: bool,
        agent: ureq::Agent,
        /// The first retry's delay (doubling after it).
        backoff: Duration,
        /// The local recording directory: keys keep paths under it.
        root: Option<std::path::PathBuf>,
        /// `[recording.s3.webhook]`'s delivery.
        notifier: Option<Notifier>,
        /// Where uploads are counted and listed.
        activity: Arc<Activity>,
    }

    impl S3Store {
        /// A store for `config`, signing with `credentials`.
        ///
        /// # Errors
        ///
        /// When the endpoint is not a usable URL. (`config.webhook` is
        /// started by [`super::Store::from_config`]; see
        /// [`S3Store::with_notifier`].)
        pub fn new(config: &S3Config, credentials: Credentials) -> Result<Self, StoreError> {
            let endpoint: url::Url = config.endpoint().parse().map_err(StoreError::Endpoint)?;
            let style = if config.path_style {
                UrlStyle::Path
            } else {
                UrlStyle::VirtualHost
            };
            let bucket = Bucket::new(
                endpoint,
                style,
                config.bucket.clone(),
                config.region.clone(),
            )
            .map_err(StoreError::Bucket)?;
            let agent = ureq::Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(300)))
                .build()
                .into();
            Ok(S3Store {
                bucket,
                credentials,
                prefix: config.prefix.clone(),
                keep_local: config.keep_local,
                agent,
                backoff: Duration::from_secs(1),
                root: None,
                notifier: None,
                activity: Arc::default(),
            })
        }

        /// Keys keep a file's path under `dir` (a `recording-path`
        /// subdirectory), not only its name.
        #[must_use]
        pub fn with_root(mut self, dir: &std::path::Path) -> Self {
            self.root = Some(dir.to_path_buf());
            self
        }

        /// Retry sooner (tests).
        #[cfg(test)]
        pub(crate) fn with_backoff(mut self, backoff: Duration) -> Self {
            self.backoff = backoff;
            self
        }

        /// `bucket/prefix`, for logs.
        #[must_use]
        pub fn describe(&self) -> String {
            format!("{}/{}", self.bucket.name(), self.prefix)
        }

        /// Upload `path` as `prefix` + its path under the recording
        /// directory (its file name when outside it); returns the key. The
        /// file is streamed (with its length), not read into memory: an
        /// hour of 48 kHz WAV is some 690 MB.
        ///
        /// # Errors
        ///
        /// When the file cannot be read or every attempt fails.
        pub fn upload(&self, path: &std::path::Path) -> Result<String, StoreError> {
            let key = super::object_key(&self.prefix, self.root.as_deref(), path)
                .ok_or(StoreError::NoFileName)?;
            let mut delay = self.backoff;
            let mut attempt = 1;
            loop {
                // Signed per attempt: a presigned URL is valid for a while.
                let url = self
                    .bucket
                    .put_object(Some(&self.credentials), &key)
                    .sign(Duration::from_mins(15));
                let file = std::fs::File::open(path).map_err(StoreError::Open)?;
                match self
                    .agent
                    .put(url.as_str())
                    .header("Content-Type", content_type(path))
                    .send(file)
                {
                    Ok(_) => return Ok(key),
                    Err(e) if attempt == ATTEMPTS => return Err(StoreError::Upload(Box::new(e))),
                    Err(e) => log::debug!(
                        "recording: uploading {} (attempt {attempt}): {e}; retrying",
                        path.display()
                    ),
                }
                std::thread::sleep(delay);
                delay *= 2;
                attempt += 1;
            }
        }

        /// Notify uploads through `notifier`.
        #[must_use]
        pub fn with_notifier(mut self, notifier: Notifier) -> Self {
            self.notifier = Some(notifier);
            self
        }

        /// Count and list uploads in `activity`.
        #[must_use]
        pub fn with_activity(mut self, activity: Arc<Activity>) -> Self {
            self.activity = activity;
            self
        }

        /// Upload each of `files`; remove the uploaded ones unless they are
        /// kept; then queue the webhook's notification of what was uploaded
        /// (if anything was, and a webhook is set). Returns the files left
        /// on the local disk.
        #[must_use]
        pub fn keep(
            &self,
            files: &[PathBuf],
            meta: &crate::recording::convert::Meta,
        ) -> Vec<PathBuf> {
            let mut left = Vec::new();
            let (mut uploaded, mut not_uploaded) = (Vec::new(), Vec::new());
            let mut listed = Vec::new();
            for f in files {
                // Before the upload: the local copy may be removed after.
                let size = std::fs::metadata(f).map_or(0, |m| m.len());
                let name = f
                    .file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
                match self.upload(f) {
                    Ok(key) => {
                        listed.push(activity::UploadedFile {
                            name,
                            key: Some(key.clone()),
                            size,
                            error: None,
                        });
                        uploaded.push(UploadedFile {
                            url: self.bucket.object_url(&key).to_string(),
                            key: key.clone(),
                            content_type: content_type(f),
                            size,
                        });
                        log::info!(
                            "recording: {} uploaded to s3://{}/{key}",
                            f.display(),
                            self.bucket.name()
                        );
                        if self.keep_local {
                            left.push(f.clone());
                        } else if let Err(e) = std::fs::remove_file(f) {
                            log::warn!("recording: removing {}: {e}", f.display());
                            left.push(f.clone());
                        }
                    }
                    Err(e) => {
                        log::warn!("recording: uploading {}: {e}; kept locally", f.display());
                        not_uploaded.push(name.clone());
                        listed.push(activity::UploadedFile {
                            name,
                            key: None,
                            size,
                            error: Some(e.to_string()),
                        });
                        left.push(f.clone());
                    }
                }
            }
            if !listed.is_empty() {
                self.activity
                    .upload(&meta.call_id, &meta.from_tag, self.bucket.name(), &listed);
            }
            if let Some(n) = &self.notifier
                && !uploaded.is_empty()
            {
                n.notify(Event::uploaded(
                    meta,
                    self.bucket.name(),
                    uploaded,
                    not_uploaded,
                ));
            }
            left
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A recording's description, for `keep`.
    fn meta() -> crate::recording::convert::Meta {
        crate::recording::convert::Meta {
            call_id: "call-1@example".to_owned(),
            from_tag: "alice".to_owned(),
            to_tag: Some("bob".to_owned()),
            section: 1,
            left_port: 30_000,
            opus_pts: Vec::new(),
            amr_pts: Vec::new(),
            amr_wb_pts: Vec::new(),
            metadata: [("agent".to_owned(), "42".to_owned())].into(),
        }
    }

    #[test]
    fn settings_and_content_types() {
        let mut c = S3Config::default();
        let p = c.problems();
        assert!(p.contains(&S3Problem::NoBucket), "{p:?}");
        assert!(p.contains(&S3Problem::NoRegion), "{p:?}");
        assert_eq!(p.contains(&S3Problem::NoS3Support), !cfg!(feature = "s3"));
        c.bucket = "b".to_owned();
        c.region = "eu-west-1".to_owned();
        assert_eq!(c.endpoint(), "https://s3.eu-west-1.amazonaws.com");
        c.endpoint = Some("ftp://x".to_owned());
        assert!(
            c.problems()
                .contains(&S3Problem::Endpoint("ftp://x".to_owned()))
        );
        for (name, ct) in [
            ("a.wav", "audio/wav"),
            ("a.flac", "audio/flac"),
            ("a.opus", "audio/ogg"),
            ("a.mp3", "audio/mpeg"),
            ("a.json", "application/json"),
            ("a.pcap", "application/vnd.tcpdump.pcap"),
            ("a", "application/octet-stream"),
        ] {
            assert_eq!(content_type(Path::new(name)), ct);
        }
        let files = vec![PathBuf::from("/x/a.wav")];
        assert_eq!(Store::Local.keep(&files, &meta()), files);
        assert!(Store::from_config(Storage::Local, &c, None, &std::sync::Arc::default()).is_ok());
        assert_eq!(format!("{:?}", Store::Local), "Store::Local");
    }

    #[test]
    fn object_keys_keep_the_subdirectory() {
        let root = Path::new("/var/lib/rtpflux/rec");
        let key = |p: &str| object_key("calls/", Some(root), Path::new(p));
        assert_eq!(
            key("/var/lib/rtpflux/rec/c-1.wav").as_deref(),
            Some("calls/c-1.wav")
        );
        assert_eq!(
            key("/var/lib/rtpflux/rec/acme/agents/call-42.wav").as_deref(),
            Some("calls/acme/agents/call-42.wav")
        );
        assert_eq!(
            key("/elsewhere/x.wav").as_deref(),
            Some("calls/x.wav"),
            "outside: the name"
        );
        assert_eq!(
            object_key("", None, Path::new("/var/lib/rtpflux/rec/acme/x.wav")).as_deref(),
            Some("x.wav"),
            "no root: the name, as before"
        );
        assert_eq!(object_key("p/", Some(root), Path::new("/")), None);
    }

    /// A fake S3: answers each request with the next of `statuses`, and
    /// reports (request line, headers, body) of each.
    /// A request the fake S3 received: request line, headers, body.
    #[cfg(feature = "s3")]
    type Received = (String, String, Vec<u8>);

    #[cfg(feature = "s3")]
    fn fake_s3(
        statuses: Vec<u16>,
    ) -> (
        String,
        std::sync::mpsc::Receiver<Received>,
        std::thread::JoinHandle<()>,
    ) {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            for status in statuses {
                let (conn, _) = listener.accept().unwrap();
                let mut r = BufReader::new(conn.try_clone().unwrap());
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                let (mut headers, mut len) = (String::new(), 0usize);
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).unwrap();
                    if h == "\r\n" {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap();
                    }
                    headers.push_str(&h);
                }
                let mut body = vec![0; len];
                r.read_exact(&mut body).unwrap();
                let mut w = conn;
                write!(
                    w,
                    "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
                tx.send((line, headers, body)).unwrap();
            }
        });
        (format!("http://{addr}"), rx, t)
    }

    #[cfg(feature = "s3")]
    #[test]
    fn uploads_with_signed_requests_retries_and_cleans_up() {
        let dir = std::env::temp_dir().join(format!("rtpflux-s3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (wav, json) = (dir.join("c-1.wav"), dir.join("c-1.json"));
        std::fs::write(&wav, b"RIFF....").unwrap();
        std::fs::write(&json, b"{}").unwrap();
        // The first PUT fails once, then both succeed.
        let (endpoint, seen, server) = fake_s3(vec![500, 200, 200]);
        let config = S3Config {
            bucket: "rec".to_owned(),
            region: "eu-west-1".to_owned(),
            endpoint: Some(endpoint),
            prefix: "calls/".to_owned(),
            path_style: true,
            keep_local: false,
            webhook: None,
        };
        let store = s3::S3Store::new(&config, rusty_s3::Credentials::new("AKIDEXAMPLE", "secret"))
            .unwrap()
            .with_backoff(std::time::Duration::from_millis(10));
        assert_eq!(store.describe(), "rec/calls/");
        let left = Store::S3(Box::new(store)).keep(&[wav.clone(), json.clone()], &meta());
        server.join().unwrap();
        assert!(left.is_empty(), "{left:?}");
        assert!(
            !wav.exists() && !json.exists(),
            "uploaded files are removed"
        );
        let requests: Vec<_> = seen.try_iter().collect();
        assert_eq!(requests.len(), 3);
        let (line, headers, body) = &requests[1];
        assert!(line.starts_with("PUT /rec/calls/c-1.wav?"), "{line}");
        for part in [
            "X-Amz-Algorithm=AWS4-HMAC-SHA256",
            "X-Amz-Credential=AKIDEXAMPLE",
            "X-Amz-Signature=",
        ] {
            assert!(line.contains(part), "{part}: {line}");
        }
        assert!(
            headers
                .to_ascii_lowercase()
                .contains("content-type: audio/wav"),
            "{headers}"
        );
        assert_eq!(body, b"RIFF....");
        assert!(requests[2].0.starts_with("PUT /rec/calls/c-1.json?"));

        // Nobody listening: the file stays.
        std::fs::write(&wav, b"RIFF").unwrap();
        let config = S3Config {
            endpoint: Some("http://127.0.0.1:9".to_owned()),
            ..config
        };
        let store = s3::S3Store::new(&config, rusty_s3::Credentials::new("k", "s"))
            .unwrap()
            .with_backoff(std::time::Duration::from_millis(1));
        assert_eq!(
            store.keep(std::slice::from_ref(&wav), &meta()),
            std::slice::from_ref(&wav)
        );
        assert!(wav.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// After an upload the webhook is told: one POST with the call, its
    /// metadata, and each uploaded object's key, URL, type and size; a file
    /// that could not be uploaded is named as such.
    #[cfg(feature = "s3")]
    #[test]
    #[allow(clippy::too_many_lines)] // One upload, then all it should have told.
    fn uploads_are_notified_to_the_webhook() {
        use std::sync::atomic::Ordering::Relaxed;
        let dir = std::env::temp_dir().join(format!("rtpflux-s3-hook-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (wav, json) = (dir.join("c-1.wav"), dir.join("c-1.json"));
        std::fs::write(&wav, b"RIFF....").unwrap();
        std::fs::write(&json, b"{}").unwrap();
        // The WAV is stored; the JSON fails all three attempts.
        let (endpoint, _seen, server) = fake_s3(vec![200, 500, 500, 500]);
        let (hook, posts, hook_server) = fake_s3(vec![200]);
        let webhook = crate::recording::webhook::WebhookConfig {
            url: format!("{hook}/rec?token=t"),
            ..Default::default()
        };
        let config = S3Config {
            bucket: "rec".to_owned(),
            region: "eu-west-1".to_owned(),
            endpoint: Some(endpoint.clone()),
            prefix: "calls/".to_owned(),
            path_style: true,
            keep_local: false,
            webhook: Some(webhook.clone()),
        };
        assert_eq!(config.problems().len(), 0, "{:?}", config.problems());
        let activity = std::sync::Arc::new(crate::recording::activity::Activity::default());
        let notifier = crate::recording::webhook::Notifier::start_with_secret(
            &webhook,
            None,
            std::sync::Arc::clone(&activity),
        )
        .unwrap();
        let store = s3::S3Store::new(
            &S3Config {
                webhook: None,
                ..config
            },
            rusty_s3::Credentials::new("k", "s"),
        )
        .unwrap()
        .with_backoff(std::time::Duration::from_millis(1))
        .with_activity(std::sync::Arc::clone(&activity))
        .with_notifier(notifier);
        let left = store.keep(&[wav.clone(), json.clone()], &meta());
        assert_eq!(left, std::slice::from_ref(&json));
        drop(store); // waits for the notification
        server.join().unwrap();
        hook_server.join().unwrap();
        let (line, headers, body) = posts.recv().unwrap();
        assert!(line.starts_with("POST /rec?token=t "), "{line}");
        let h = headers.to_ascii_lowercase();
        for needle in [
            "content-type: application/json",
            "x-rtpflux-event: recording.uploaded",
            "x-rtpflux-delivery: ",
            "x-rtpflux-timestamp: ",
        ] {
            assert!(h.contains(needle), "{needle}: {headers}");
        }
        assert!(
            !h.contains("x-rtpflux-signature"),
            "no secret, no signature"
        );
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["event"], "recording.uploaded");
        assert_eq!(v["call_id"], "call-1@example");
        assert_eq!(v["from_tag"], "alice");
        assert_eq!(v["to_tag"], "bob");
        assert_eq!(v["metadata"]["agent"], "42");
        assert_eq!(v["bucket"], "rec");
        assert_eq!(v["complete"], false);
        assert_eq!(v["not_uploaded"], serde_json::json!(["c-1.json"]));
        let files = v["files"].as_array().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["key"], "calls/c-1.wav");
        assert_eq!(files[0]["url"], format!("{endpoint}/rec/calls/c-1.wav"));
        assert_eq!(files[0]["content_type"], "audio/wav");
        assert_eq!(files[0]["size"], 8);
        // Counted and listed for the web UI and /metrics.
        let up = &activity.uploads()[0];
        assert_eq!(
            (
                &up["call_id"],
                &up["complete"],
                &up["files"][0]["key"],
                &up["files"][1]["key"]
            ),
            (
                &serde_json::json!("call-1@example"),
                &serde_json::json!(false),
                &serde_json::json!("calls/c-1.wav"),
                &serde_json::Value::Null
            )
        );
        assert!(
            !up["files"][1]["error"].as_str().unwrap().contains("X-Amz"),
            "no signature in the error: {up}"
        );
        assert_eq!(activity.deliveries()[0]["outcome"], "delivered");
        assert_eq!(
            (
                activity.uploaded.load(Relaxed),
                activity.uploads_failed.load(Relaxed),
                activity.webhooks_delivered.load(Relaxed)
            ),
            (1, 1, 1)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Against a real S3-compatible server, when one is named: set
    /// `RTPFLUX_S3_TEST_ENDPOINT` (e.g. `http://127.0.0.1:9000` for `MinIO`),
    /// `RTPFLUX_S3_TEST_BUCKET`, `AWS_ACCESS_KEY_ID` and
    /// `AWS_SECRET_ACCESS_KEY`, then run with `--ignored`. The bucket is
    /// created if needed; an upload is read back and compared.
    #[cfg(feature = "s3")]
    #[test]
    #[ignore = "needs an S3-compatible server"]
    fn a_real_server_accepts_the_signatures() {
        use rusty_s3::S3Action as _;
        let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} is not set"));
        let config = S3Config {
            bucket: env("RTPFLUX_S3_TEST_BUCKET"),
            region: std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_owned()),
            endpoint: Some(env("RTPFLUX_S3_TEST_ENDPOINT")),
            prefix: "rtpflux-test/".to_owned(),
            path_style: true,
            keep_local: true,
            webhook: None,
        };
        let creds =
            rusty_s3::Credentials::new(env("AWS_ACCESS_KEY_ID"), env("AWS_SECRET_ACCESS_KEY"));
        let bucket = rusty_s3::Bucket::new(
            config.endpoint().parse().unwrap(),
            rusty_s3::UrlStyle::Path,
            config.bucket.clone(),
            config.region.clone(),
        )
        .unwrap();
        let create = bucket
            .create_bucket(&creds)
            .sign(std::time::Duration::from_secs(60));
        let _ = ureq::put(create.as_str()).send_empty();
        let path =
            std::env::temp_dir().join(format!("rtpflux-real-s3-{}.json", std::process::id()));
        std::fs::write(&path, b"{\"hello\": 1}").unwrap();
        let store = s3::S3Store::new(&config, creds.clone()).unwrap();
        let key = store.upload(&path).unwrap();
        let get = bucket
            .get_object(Some(&creds), &key)
            .sign(std::time::Duration::from_secs(60));
        let body = ureq::get(get.as_str())
            .call()
            .unwrap()
            .body_mut()
            .read_to_vec()
            .unwrap();
        assert_eq!(body, b"{\"hello\": 1}");
        std::fs::remove_file(&path).unwrap();
    }
}
