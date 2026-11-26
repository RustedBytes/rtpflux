//! A read-only administrator web UI (`[webui]`): a Preact + TypeScript
//! single-page app (sources in `webui/ui/`, the built bundle embedded) over
//! a small JSON API ([`api`]) that only reads: counters, process and
//! configuration facts, the dialogs and the last log lines.
//!
//! Every request needs the login (HTTP Basic auth, [`auth`]), which is sent
//! with each request: listen on 127.0.0.1, or put a TLS reverse proxy in
//! front.

pub mod api;
mod assets;
pub mod auth;
pub mod http;
pub mod logs;
pub mod recordings;

use crate::config::{Config, XdpMode};
use crate::control::WebLink;
use crate::daemon::StartError;
use crate::metrics::Sources;
use serde_json::{Value, json};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread::JoinHandle;

/// What the Overview page shows of the configuration (no secrets).
#[must_use]
pub fn config_facts(config: &Config) -> Value {
    let addrs = |a: &[SocketAddr]| a.iter().map(ToString::to_string).collect::<Vec<_>>();
    let r = &config.recording;
    json!({
        "interfaces": config.interfaces.iter().map(|i| json!({
            "name": i.name,
            "address": i.address.to_string(),
            "advertise": i.advertised().to_string(),
        })).collect::<Vec<_>>(),
        "ports": format!("{}-{}", config.ports.min, config.ports.max),
        "sessions_max": config.sessions.max,
        "timeout_s": config.sessions.timeout,
        "workers": config.runtime.workers,
        "state_file": config.sessions.state_file.as_ref().map(|p| p.display().to_string()),
        // Without its password.
        "state_redis": config.sessions.redis_target().ok().flatten().map(|t| t.describe()),
        "control": addrs(&config.control.listen),
        // ng over TCP, and over HTTP and WebSocket.
        "control_tcp": addrs(&config.control.listen_tcp),
        "control_http": addrs(&config.control.listen_http),
        "metrics": addrs(&config.metrics.listen),
        "receive": match config.runtime.receive {
            crate::config::Receive::IoUring => "io_uring",
            crate::config::Receive::Recvmmsg => "recvmmsg",
        },
        "timeouts": {
            "media_s": config.sessions.timeout,
            "silent_s": config.sessions.silent_timeout,
            "offer_s": config.sessions.offer_timeout,
            "final_s": config.sessions.final_timeout,
        },
        "strict_source": config.sessions.strict_source,
        "ice": {
            "mode": match config.ice.mode {
                crate::config::IceMode::Full => "full",
                crate::config::IceMode::Lite => "lite",
            },
            "stun_server": config.ice.stun_server,
        },
        // What `--check` warns about, as at start.
        "warnings": config.warnings().iter().map(ToString::to_string).collect::<Vec<_>>(),
        "xdp": if config.xdp.enabled {
            json!({
                "devices": config.xdp.devices,
                "mode": match config.xdp.mode { XdpMode::Native => "native", XdpMode::Generic => "generic" },
                "af_xdp": config.xdp.af_xdp,
            })
        } else {
            Value::Null
        },
        "recording": r.dir.as_ref().map(|d| json!({
            "dir": d.display().to_string(),
            "format": r.format.name(),
            "channels": r.channels.name(),
            "sample_rate": r.sample_rate,
            "storage": format!("{:?}", r.storage).to_lowercase(),
            "s3": (r.storage == crate::recording::store::Storage::S3).then(|| s3_facts(&r.s3)),
        })),
    })
}

/// `[recording.s3]` as the UI shows it: no credentials (they are only in
/// the environment), URLs without queries or user names.
fn s3_facts(s3: &crate::recording::store::S3Config) -> Value {
    use crate::recording::activity::clean_error as clean_url;
    json!({
        "bucket": s3.bucket,
        "region": s3.region,
        "endpoint": clean_url(&s3.endpoint()),
        "prefix": s3.prefix,
        "path_style": s3.path_style,
        "keep_local": s3.keep_local,
        "webhook": s3.webhook.as_ref().map(|w| json!({
            "url": clean_url(&w.url),
            "signed": std::env::var(crate::recording::webhook::SECRET_ENV).is_ok_and(|v| !v.is_empty()),
            "timeout_ms": w.timeout_ms,
            "connect_timeout_ms": w.connect_timeout_ms,
            "attempts": w.attempts,
            "backoff_ms": w.backoff_ms,
            "backoff_max_ms": w.backoff_max_ms,
            "queue": w.queue,
        })),
    })
}

/// A running web UI.
#[derive(Debug)]
pub struct WebUi {
    pub addr: SocketAddr,
    pub thread: JoinHandle<()>,
}

/// Start the UI configured in `[webui]` (none without `listen`), serving
/// until `stop` is set.
///
/// # Errors
///
/// When the address cannot be bound, the login is malformed or the thread
/// cannot start.
pub fn start(
    config: &Config,
    sources: Sources,
    control: WebLink,
    stop: Arc<AtomicBool>,
) -> Result<Option<WebUi>, crate::daemon::StartError> {
    let w = &config.webui;
    let Some(listen) = w.listen else {
        return Ok(None);
    };
    let creds =
        auth::Credentials::new(&w.user, &w.password_hash).map_err(StartError::WebUiLogin)?;
    let listener = TcpListener::bind(listen).map_err(StartError::listen("webui", listen))?;
    let addr = listener
        .local_addr()
        .map_err(StartError::listen("webui", listen))?;
    let api = api::Api::new(
        sources,
        control,
        config_facts(config),
        w.refresh_ms,
        recordings::Recordings::new(config.recording.dir.clone()),
    );
    let server = Arc::new(http::Server::new(
        api,
        creds,
        w.realm.clone(),
        w.max_connections,
    ));
    let thread = std::thread::Builder::new()
        .name("rtpflux-webui".to_owned())
        .spawn(move || server.serve(&listener, &stop))
        .map_err(StartError::thread("the web UI thread"))?;
    log::info!("web UI on http://{addr}/");
    Ok(Some(WebUi { addr, thread }))
}
