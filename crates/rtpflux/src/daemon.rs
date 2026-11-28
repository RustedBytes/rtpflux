//! The daemon: the command line, and starting and stopping the relay, its
//! `ng` server, its metrics endpoint and its web UI.
//!
//! `main` parses the command line, runs [`preflight`], installs logging,
//! blocks the stop signals, [`Daemon::start`]s and, on a signal,
//! [`Daemon::stop`]s.

use crate::config::{self, Config, LogLevel};
use crate::control::{Control, serve};
use crate::metrics;
use crate::relay::Relay;
use std::io::Write;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

/// The command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cli {
    /// Configuration file (`-c`, `--config`).
    pub config: PathBuf,
    /// Log level; overrides `RUST_LOG` and the configuration file
    /// (`-l`, `--log-level`).
    pub log_level: Option<LogLevel>,
    /// Validate the configuration and exit (`--check`).
    pub check: bool,
    /// Print the documented example configuration and exit
    /// (`--print-example-config`).
    pub print_example_config: bool,
    /// Read a password (one line on standard input) and print the
    /// `[webui] password_hash` value for it (`--webui-hash`).
    pub webui_hash: bool,
}

/// The default configuration file.
pub const DEFAULT_CONFIG: &str = "/etc/rtpflux/rtpflux.toml";

/// `--help`.
pub const HELP: &str = "\
A fast RTP media relay

Usage: rtpflux [OPTIONS]

Options:
  -c, --config <PATH>         Configuration file [default: /etc/rtpflux/rtpflux.toml]
  -l, --log-level <LEVEL>     Log level; overrides `RUST_LOG` and the configuration file
                              [possible values: error, warn, info, debug, trace]
      --check                 Validate the configuration and exit
      --print-example-config  Print the documented example configuration and exit
      --webui-hash            Read a password (one line on standard input) and print the
                              `[webui] password_hash` value for it
  -h, --help                  Print help
  -V, --version               Print version
";

/// Why the command line does not give a [`Cli`] to run with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliExit {
    /// `--help`: print [`HELP`], exit successfully.
    Help,
    /// `--version`: print the version, exit successfully.
    Version,
    /// A usage error: print it, exit with status 2.
    Usage(String),
}

impl CliExit {
    /// What to print, and whether it goes to standard error.
    #[must_use]
    pub fn message(&self) -> (String, bool) {
        match self {
            CliExit::Help => (HELP.to_owned(), false),
            CliExit::Version => (format!("rtpflux {}\n", env!("CARGO_PKG_VERSION")), false),
            CliExit::Usage(e) => (
                format!(
                    "error: {e}\n\nUsage: rtpflux [OPTIONS]\n\nFor more information, try '--help'.\n"
                ),
                true,
            ),
        }
    }

    /// The process exit status.
    #[must_use]
    pub fn status(&self) -> u8 {
        match self {
            CliExit::Help | CliExit::Version => 0,
            CliExit::Usage(_) => 2,
        }
    }
}

impl Cli {
    /// Parse the arguments, the program name first (as
    /// `std::env::args_os()` gives them).
    ///
    /// # Errors
    ///
    /// `--help` and `--version`, and usage errors: an unknown option, a
    /// missing or invalid value, an option given twice, or options that
    /// exclude each other.
    pub fn try_parse_from<I, T>(args: I) -> Result<Cli, CliExit>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString>,
    {
        let usage = CliExit::Usage;
        let mut cli = Cli {
            config: PathBuf::from(DEFAULT_CONFIG),
            log_level: None,
            check: false,
            print_example_config: false,
            webui_hash: false,
        };
        let mut seen: Vec<&'static str> = Vec::new();
        let mut args = args.into_iter().map(Into::into).skip(1);
        while let Some(arg) = args.next() {
            let Some(text) = arg.to_str() else {
                return Err(usage(format!(
                    "unexpected argument '{}' found",
                    arg.to_string_lossy()
                )));
            };
            let (name, attached) = option(text)?;
            if seen.contains(&name) {
                return Err(usage(format!(
                    "the argument '{name}' cannot be used multiple times"
                )));
            }
            seen.push(name);
            let takes_value = name.ends_with('>');
            if !takes_value && attached.is_some() {
                return Err(usage(format!("unexpected value for '{name}'")));
            }
            let value = if takes_value {
                match attached.or_else(|| args.next()) {
                    Some(v) => Some(v),
                    None => {
                        return Err(usage(format!(
                            "a value is required for '{name}' but none was supplied"
                        )));
                    }
                }
            } else {
                None
            };
            match (name, value) {
                ("--config <PATH>", Some(v)) => cli.config = PathBuf::from(v),
                ("--log-level <LEVEL>", Some(v)) => {
                    let level = v.to_str().and_then(|v| v.parse().ok());
                    let Some(level) = level else {
                        return Err(usage(format!(
                            "invalid value '{}' for '{name}'\n  [possible values: error, warn, info, debug, trace]",
                            v.to_string_lossy()
                        )));
                    };
                    cli.log_level = Some(level);
                }
                ("--check", _) => cli.check = true,
                ("--print-example-config", _) => cli.print_example_config = true,
                _ => cli.webui_hash = true,
            }
        }
        // Options that exclude each other.
        let modes = [
            ("--check", cli.check),
            ("--print-example-config", cli.print_example_config),
            ("--webui-hash", cli.webui_hash),
        ];
        let mut given = modes.iter().filter(|(_, on)| *on).map(|(n, _)| *n);
        if let (Some(a), Some(b)) = (given.next(), given.next()) {
            return Err(usage(format!(
                "the argument '{b}' cannot be used with '{a}'"
            )));
        }
        Ok(cli)
    }
}

/// An option's canonical name (as usage errors show it) and a value
/// attached to it (`--opt=v`, `-ov`, `-o=v`), or why `text` is not one.
fn option(text: &str) -> Result<(&'static str, Option<std::ffi::OsString>), CliExit> {
    let unexpected = || CliExit::Usage(format!("unexpected argument '{text}' found"));
    if let Some(long) = text.strip_prefix("--") {
        let (n, v) = match long.split_once('=') {
            Some((n, v)) => (n, Some(v.into())),
            None => (long, None),
        };
        let name = match n {
            "config" => "--config <PATH>",
            "log-level" => "--log-level <LEVEL>",
            "check" => "--check",
            "print-example-config" => "--print-example-config",
            "webui-hash" => "--webui-hash",
            "help" => return Err(CliExit::Help),
            "version" => return Err(CliExit::Version),
            _ => return Err(unexpected()),
        };
        return Ok((name, v));
    }
    let Some(short) = text.strip_prefix('-').filter(|s| !s.is_empty()) else {
        return Err(unexpected());
    };
    let (c, rest) = short.split_at(1);
    let name = match c {
        "c" => "--config <PATH>",
        "l" => "--log-level <LEVEL>",
        "h" if rest.is_empty() => return Err(CliExit::Help),
        "V" if rest.is_empty() => return Err(CliExit::Version),
        _ => return Err(unexpected()),
    };
    Ok((
        name,
        (!rest.is_empty()).then(|| rest.trim_start_matches('=').into()),
    ))
}

/// What the command line asks for before anything starts.
#[derive(Debug)]
pub enum Preflight {
    /// Run the relay with this configuration.
    Run(Box<Config>),
    /// Done (`--print-example-config`, `--check`): exit successfully.
    Done,
    /// The configuration cannot be used (reported on `err`): exit with
    /// failure.
    Failed,
}

/// Handle `--print-example-config` and `--check`, and load the
/// configuration: what to print goes to `out`, problems (and, with
/// `--check`, warnings) to `err`.
pub fn preflight(cli: &Cli, out: &mut dyn Write, err: &mut dyn Write) -> Preflight {
    if cli.webui_hash {
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            let _ = writeln!(err, "rtpflux: cannot read the password");
            return Preflight::Failed;
        }
        let password = line.trim_end_matches(['\r', '\n']);
        if password.is_empty() {
            let _ = writeln!(err, "rtpflux: the password is empty");
            return Preflight::Failed;
        }
        let _ = writeln!(
            out,
            "{}",
            crate::webui::auth::make_hash(password.as_bytes())
        );
        return Preflight::Done;
    }
    if cli.print_example_config {
        let _ = write!(out, "{}", config::EXAMPLE);
        return Preflight::Done;
    }
    let config = match Config::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(err, "rtpflux: {}: {e}", cli.config.display());
            return Preflight::Failed;
        }
    };
    if cli.check {
        // At run time the warnings are logged instead, once logging is up.
        for w in config.warnings() {
            let _ = writeln!(err, "rtpflux: {}: warning: {w}", cli.config.display());
        }
        let _ = writeln!(out, "{}: configuration is valid", cli.config.display());
        return Preflight::Done;
    }
    Preflight::Run(Box::new(config))
}

/// Raise the open-file limit to its hard limit: every call holds four
/// sockets, so the common default soft limit (1024) caps a relay at about
/// 250 calls. Returns a warning when even the hard limit is below what
/// `sessions.max` needs.
#[must_use]
pub fn raise_fd_limit(sessions: usize) -> Option<String> {
    use nix::sys::resource::{Resource, getrlimit, setrlimit};
    let Ok((soft, hard)) = getrlimit(Resource::RLIMIT_NOFILE) else {
        return None;
    };
    if soft < hard
        && let Err(e) = setrlimit(Resource::RLIMIT_NOFILE, hard, hard)
    {
        log::warn!("cannot raise the open-file limit from {soft} to {hard}: {e}");
    }
    let limit = getrlimit(Resource::RLIMIT_NOFILE).map_or(soft, |(s, _)| s);
    fd_shortfall(limit, sessions)
}

/// The warning when `limit` open files cannot serve `sessions` calls.
fn fd_shortfall(limit: u64, sessions: usize) -> Option<String> {
    let needed = u64::try_from(sessions.saturating_mul(4))
        .unwrap_or(u64::MAX)
        .saturating_add(64);
    (limit < needed).then(|| {
        format!(
            "open-file limit {limit} is below the {needed} that sessions.max = {sessions} needs (4 sockets per call); raise LimitNOFILE / ulimit -n"
        )
    })
}

/// Why the daemon cannot start.
#[derive(Debug)]
pub enum StartError {
    /// The media relay cannot start.
    Relay(crate::relay::RelayError),
    /// An address cannot be listened on: by what (`ng`, `metrics`,
    /// `webui`), which, and why.
    Listen {
        what: &'static str,
        addr: SocketAddr,
        source: std::io::Error,
    },
    /// The control thread's link for a listener cannot be made.
    Link {
        what: &'static str,
        source: nix::Error,
    },
    /// A thread cannot be started.
    Thread {
        what: &'static str,
        source: std::io::Error,
    },
    /// `[webui] user` and `password_hash` cannot be used.
    WebUiLogin(crate::webui::auth::CredentialsError),
    /// The operation ledger cannot be opened.
    Ledger {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    /// The ownership claims (`[ha] state`) cannot be read: without the
    /// epochs it accepted, an old controller could come back.
    Ownership {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    /// The native API's socket cannot be made.
    Native {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::Relay(e) => write!(f, "cannot start the media relay: {e}"),
            StartError::Listen { what, addr, source } => {
                write!(f, "{what}: cannot listen on {addr}: {source}")
            }
            StartError::Link { what, source } => write!(f, "cannot start {what}: {source}"),
            StartError::Thread { what, source } => write!(f, "cannot start {what}: {source}"),
            StartError::WebUiLogin(e) => write!(f, "webui.password_hash: {e}"),
            StartError::Ledger { path, source } => {
                write!(f, "sessions.ledger: {}: {source}", path.display())
            }
            StartError::Ownership { path, source } => {
                write!(f, "ha.state: {}: {source}", path.display())
            }
            StartError::Native { path, source } => {
                write!(f, "control.native_socket: {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for StartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StartError::Relay(e) => Some(e),
            StartError::Listen { source, .. }
            | StartError::Thread { source, .. }
            | StartError::Native { source, .. }
            | StartError::Ledger { source, .. }
            | StartError::Ownership { source, .. } => Some(source),
            StartError::Link { source, .. } => Some(source),
            StartError::WebUiLogin(e) => Some(e),
        }
    }
}

impl StartError {
    /// A thread named `what` that could not start.
    pub(crate) fn thread(what: &'static str) -> impl FnOnce(std::io::Error) -> StartError {
        move |source| StartError::Thread { what, source }
    }

    /// `addr`, listened on by `what`, refused.
    pub(crate) fn listen(
        what: &'static str,
        addr: SocketAddr,
    ) -> impl FnOnce(std::io::Error) -> StartError {
        move |source| StartError::Listen { what, addr, source }
    }
}

/// The `ng` sockets (non-blocking).
fn bind_control(addrs: &[SocketAddr]) -> Result<Vec<UdpSocket>, StartError> {
    addrs
        .iter()
        .map(|&addr| {
            UdpSocket::bind(addr)
                .and_then(|s| s.set_nonblocking(true).map(|()| s))
                .map_err(StartError::listen("ng", addr))
        })
        .collect()
}

/// The `ng` listeners on TCP, HTTP and WebSocket: their bound addresses
/// and threads.
fn start_streams(
    control: &mut Control,
    config: &Config,
    stop: &Arc<AtomicBool>,
) -> Result<(Vec<SocketAddr>, Vec<JoinHandle<()>>), StartError> {
    let mut stream_addrs = Vec::new();
    let mut stream_threads = Vec::new();
    if !config.control.listen_tcp.is_empty() || !config.control.listen_http.is_empty() {
        let link = control.ng_link().map_err(|source| StartError::Link {
            what: "the ng stream listeners",
            source,
        })?;
        let kinds = config
            .control
            .listen_tcp
            .iter()
            .map(|a| (*a, false))
            .chain(config.control.listen_http.iter().map(|a| (*a, true)));
        for (addr, http) in kinds {
            let listener =
                std::net::TcpListener::bind(addr).map_err(StartError::listen("ng", addr))?;
            let bound = listener
                .local_addr()
                .map_err(StartError::listen("ng", addr))?;
            log::info!(
                "ng over {} on {bound}",
                if http { "HTTP/WebSocket" } else { "TCP" }
            );
            stream_addrs.push(bound);
            let (stop, link) = (Arc::clone(stop), link.clone());
            let t = std::thread::Builder::new()
                .name("rtpflux-ng-listen".to_owned())
                .spawn(move || {
                    if http {
                        crate::ngstream::serve_http(&listener, &link, &stop);
                    } else {
                        crate::ngstream::serve_tcp(&listener, &link, &stop);
                    }
                })
                .map_err(StartError::thread("an ng listener"))?;
            stream_threads.push(t);
        }
    }
    Ok((stream_addrs, stream_threads))
}

/// The native API's listener, if `[control] native_socket` is set: its
/// thread.
fn start_native(
    control: &mut Control,
    config: &Config,
    stop: &Arc<AtomicBool>,
) -> Result<(Vec<SocketAddr>, Vec<JoinHandle<()>>), StartError> {
    let c = &config.control;
    let mut addrs = Vec::new();
    if c.native_socket.is_none() && c.native_listen.is_empty() {
        return Ok((addrs, Vec::new()));
    }
    control.set_native_max_endpoints(c.native_max_endpoints);
    control.set_native_journal(c.native_event_journal);
    control.set_native_rate_limit(c.native_rate_limit);
    control.set_ng_protect_native(c.ng_protect_native);
    if let Some(path) = &config.sessions.ledger {
        control
            .open_ledger(
                path,
                config.sessions.ledger_retention.saturating_mul(1000),
                config.sessions.ledger_quota,
            )
            .map_err(|source| StartError::Ledger {
                path: path.clone(),
                source,
            })?;
        log::info!("native: operation ledger in {}", path.display());
    }
    if let (true, Some(path)) = (config.ha.enabled, &config.ha.state) {
        control
            .open_ownership(path, &config.ha.authority_keys)
            .map_err(|source| StartError::Ownership {
                path: path.clone(),
                source,
            })?;
        log::info!(
            "native: ownership fencing on ({} authority keys), claims in {}",
            config.ha.authority_keys.len(),
            path.display()
        );
    }
    control.set_pcm_dir(c.pcm_dir.clone());
    crate::pcm::shard::configure(config.runtime.pcm_shards);
    let link = control.native_link().map_err(|source| StartError::Link {
        what: "the native API",
        source,
    })?;
    let mut threads = Vec::new();
    let tokens = if c.native_listen.is_empty() {
        None
    } else {
        let set =
            crate::native::TokenSet::new(c.native_tokens.clone(), c.native_tokens_file.clone())
                .map_err(|source| StartError::Native {
                    path: c.native_tokens_file.clone().unwrap_or_default(),
                    source,
                })?;
        Some(Arc::new(set))
    };
    for addr in &c.native_listen {
        let listener =
            std::net::TcpListener::bind(addr).map_err(StartError::listen("native", *addr))?;
        let bound = listener
            .local_addr()
            .map_err(StartError::listen("native", *addr))?;
        log::info!("native API on tcp {bound}");
        addrs.push(bound);
        let (stop, link) = (Arc::clone(stop), link.clone());
        let tokens = tokens.clone().ok_or_else(|| StartError::Native {
            path: std::path::PathBuf::new(),
            source: std::io::Error::other("no tokens"),
        })?;
        threads.push(
            std::thread::Builder::new()
                .name("rtpflux-native-tcp".to_owned())
                .spawn(move || crate::native::serve_tcp(&listener, &link, &tokens, &stop))
                .map_err(StartError::thread("the native API listener"))?,
        );
    }
    let Some(path) = &c.native_socket else {
        return Ok((addrs, threads));
    };
    let listener =
        crate::native::bind(path, &c.native_uids, c.native_socket_group).map_err(|source| {
            StartError::Native {
                path: path.clone(),
                source,
            }
        })?;
    log::info!("native API on {}", path.display());
    let (stop, uids) = (Arc::clone(stop), config.control.native_uids.clone());
    let t = std::thread::Builder::new()
        .name("rtpflux-native-listen".to_owned())
        .spawn(move || crate::native::serve(&listener, &link, &uids, &stop))
        .map_err(StartError::thread("the native API listener"))?;
    threads.push(t);
    Ok((addrs, threads))
}

/// The control plane over `relay`: state file (dialogs restored from it)
/// and recording directory (created) from the configuration.
fn control_for(relay: Relay, config: &Config) -> Control {
    let mut control = Control::new(relay, config.interfaces.clone());
    control.set_state_file(config.sessions.state_file.clone());
    // Validated with the configuration; the writer thread starts here.
    match config.sessions.redis_target() {
        Ok(Some(target)) => match crate::redis::Writer::spawn(target) {
            Ok(w) => {
                log::info!("state: kept in {}", w.target().describe());
                control.set_state_redis(Some(w));
            }
            Err(e) => log::warn!("state: cannot start the Redis writer: {e}"),
        },
        Ok(None) => {}
        Err(e) => log::warn!("state: sessions.redis: {e}"),
    }
    control.set_max_message(config.control.max_message);
    control.set_ice(config.ice.mode, config.ice.pacing_ms);
    if let Some(server) = &config.ice.stun_server {
        let shared = crate::srflx::Shared::default();
        match crate::srflx::spawn(server.clone(), config.interfaces.clone(), shared.clone()) {
            Ok(()) => control.set_srflx(shared),
            Err(e) => log::warn!("ice: cannot start asking {server}: {e}"),
        }
    }
    control.set_offer_timeout(std::time::Duration::from_secs(
        config.sessions.offer_timeout,
    ));
    control.set_max_sessions(config.sessions.max);
    control.set_final_timeout(config.sessions.final_timeout);
    control.set_strict_source(config.sessions.strict_source);
    if let Some(dir) = &config.recording.dir {
        if let Err(e) = std::fs::create_dir_all(dir) {
            log::warn!("recording: {}: {e}", dir.display());
        }
        let removed = crate::recording::convert::remove_partial(dir);
        if removed > 0 {
            log::info!("recording: removed {removed} partly converted file(s)");
        }
    }
    control.set_recording_dir(config.recording.dir.clone());
    control.set_recording_settings(config.recording.settings());
    control.set_recording_naming(
        &config.recording.file_name,
        config.recording.metadata.clone(),
    );
    control.set_max_mixer_recordings(config.recording.max_mixer_recordings);
    let restored = control.restore();
    if restored > 0 {
        log::info!("restored {restored} call(s) from the saved state");
    }
    control
}

/// A running relay: its control thread and metrics threads.
#[derive(Debug)]
pub struct Daemon {
    stop: Arc<AtomicBool>,
    control_addrs: Vec<SocketAddr>,
    stream_addrs: Vec<SocketAddr>,
    native_addrs: Vec<SocketAddr>,
    metrics_addrs: Vec<SocketAddr>,
    control_thread: JoinHandle<()>,
    metrics_threads: Vec<JoinHandle<()>>,
    webui: Option<crate::webui::WebUi>,
}

impl Daemon {
    /// Start the media relay, the `ng` server, the metrics endpoint and the
    /// web UI.
    ///
    /// # Errors
    ///
    /// When the relay cannot start or an address cannot be bound.
    pub fn start(config: &Config) -> Result<Self, StartError> {
        log::info!(
            "rtpflux {} starting: {} interface(s), ports {}-{}, up to {} sessions, xdp {}",
            env!("CARGO_PKG_VERSION"),
            config.interfaces.len(),
            config.ports.min,
            config.ports.max,
            config.sessions.max,
            if config.xdp.enabled { "on" } else { "off" }
        );
        for i in &config.interfaces {
            log::debug!(
                "interface {}: bind {}, advertise {}",
                i.name,
                i.address,
                i.advertised()
            );
        }
        let relay = Relay::start(config).map_err(StartError::Relay)?;
        let sockets = bind_control(&config.control.listen)?;
        let control_addrs: Vec<SocketAddr> =
            sockets.iter().filter_map(|s| s.local_addr().ok()).collect();
        for addr in &control_addrs {
            log::info!("ng control on udp {addr}");
        }
        let listeners = metrics::bind(&config.metrics.listen)?;
        let metrics_addrs: Vec<SocketAddr> = listeners
            .iter()
            .filter_map(|l| l.local_addr().ok())
            .collect();
        let stop = Arc::new(AtomicBool::new(false));
        let workers = relay.worker_stats();
        let recording = relay.recording_activity();
        let xdp_flows = relay.xdp_flows();
        let mut control = control_for(relay, config);
        let sources = metrics::Sources {
            workers,
            control: control.stats(),
            recording,
            srflx: control.srflx(),
            xdp_flows,
        };
        let webui = if config.webui.listen.is_some() {
            let link = control.web_link().map_err(|source| StartError::Link {
                what: "the web UI",
                source,
            })?;
            crate::webui::start(config, sources.clone(), link, Arc::clone(&stop))?
        } else {
            None
        };
        let (stream_addrs, stream_threads) = start_streams(&mut control, config, &stop)?;
        let mut metrics_threads = Vec::new();
        metrics_threads.extend(stream_threads);
        let (native_addrs, native_threads) = start_native(&mut control, config, &stop)?;
        metrics_threads.extend(native_threads);
        for (listener, addr) in listeners.into_iter().zip(&metrics_addrs) {
            log::info!("metrics on http://{addr}/metrics");
            let (stop, sources) = (Arc::clone(&stop), sources.clone());
            let t = std::thread::Builder::new()
                .name("rtpflux-metrics".to_owned())
                .spawn(move || metrics::serve(&listener, &sources, &stop))
                .map_err(StartError::thread("the metrics thread"))?;
            metrics_threads.push(t);
        }
        let control_thread = {
            let stop = Arc::clone(&stop);
            std::thread::Builder::new()
                .name("rtpflux-control".to_owned())
                .spawn(move || {
                    crate::essential("the ng control thread", || {
                        if let Err(e) = serve(&mut control, &sockets, &stop) {
                            log::error!("ng control: {e}");
                        }
                        // The peers learned since the last change are kept too.
                        control.save();
                        // `control` (and with it the relay) is dropped here.
                    });
                })
                .map_err(StartError::thread("the control thread"))?
        };
        Ok(Daemon {
            stop,
            control_addrs,
            stream_addrs,
            native_addrs,
            metrics_addrs,
            control_thread,
            metrics_threads,
            webui,
        })
    }

    /// The bound web UI address, if it runs.
    #[must_use]
    pub fn webui_addr(&self) -> Option<SocketAddr> {
        self.webui.as_ref().map(|w| w.addr)
    }

    /// The bound `ng` TCP and HTTP addresses, in the order configured
    /// (TCP ones first).
    #[must_use]
    pub fn stream_addrs(&self) -> &[SocketAddr] {
        &self.stream_addrs
    }

    /// The bound TCP addresses of the native API.
    #[must_use]
    pub fn native_addrs(&self) -> &[SocketAddr] {
        &self.native_addrs
    }

    /// The bound `ng` addresses (useful with port 0).
    #[must_use]
    pub fn control_addrs(&self) -> &[SocketAddr] {
        &self.control_addrs
    }

    /// The bound metrics addresses.
    #[must_use]
    pub fn metrics_addrs(&self) -> &[SocketAddr] {
        &self.metrics_addrs
    }

    /// Stop serving, save the dialogs (with a state file) and wait for the
    /// threads.
    pub fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.control_thread.join();
        for t in self.metrics_threads {
            let _ = t.join();
        }
        if let Some(w) = self.webui {
            let _ = w.thread.join();
        }
        log::info!("stopped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_flags() {
        let cli =
            Cli::try_parse_from(["rtpflux", "-c", "x.toml", "--log-level", "debug", "--check"])
                .unwrap();
        assert_eq!(cli.config, PathBuf::from("x.toml"));
        assert_eq!(cli.log_level, Some(LogLevel::Debug));
        assert!(cli.check);
        assert!(Cli::try_parse_from(["rtpflux", "--check", "--print-example-config"]).is_err());
        assert!(Cli::try_parse_from(["rtpflux", "--log-level", "loud"]).is_err());
    }

    #[test]
    fn every_form_of_the_command_line() {
        let parse = |args: &[&str]| {
            Cli::try_parse_from(std::iter::once("rtpflux").chain(args.iter().copied()))
        };
        let base = parse(&[]).unwrap();
        assert_eq!(base.config, PathBuf::from(DEFAULT_CONFIG));
        assert_eq!(
            (
                base.log_level,
                base.check,
                base.print_example_config,
                base.webui_hash
            ),
            (None, false, false, false)
        );
        // Values separate, attached and after `=`.
        for args in [
            &["-c", "a.toml", "-l", "trace"][..],
            &["--config", "a.toml", "--log-level", "trace"],
            &["--config=a.toml", "--log-level=trace"],
            &["-ca.toml", "-ltrace"],
            &["-c=a.toml", "-l=trace"],
        ] {
            let c = parse(args).unwrap();
            assert_eq!(
                (c.config, c.log_level),
                (PathBuf::from("a.toml"), Some(LogLevel::Trace)),
                "{args:?}"
            );
        }
        assert!(parse(&["--webui-hash"]).unwrap().webui_hash);
        assert!(
            parse(&["--print-example-config"])
                .unwrap()
                .print_example_config
        );
        // Help and version, short and long.
        for (args, want) in [
            (&["-h"][..], CliExit::Help),
            (&["--help"], CliExit::Help),
            (&["-V"], CliExit::Version),
            (&["--version"], CliExit::Version),
            (&["--check", "--help"], CliExit::Help),
        ] {
            assert_eq!(parse(args).unwrap_err(), want, "{args:?}");
        }
        assert_eq!(CliExit::Help.message(), (HELP.to_owned(), false));
        assert_eq!(CliExit::Version.status(), 0);
        // Usage errors, each with its reason.
        for (args, reason) in [
            (&["--bogus"][..], "unexpected argument '--bogus' found"),
            (&["-x"], "unexpected argument '-x' found"),
            (&["config.toml"], "unexpected argument 'config.toml' found"),
            (&["-"], "unexpected argument '-' found"),
            (
                &["-c"],
                "a value is required for '--config <PATH>' but none was supplied",
            ),
            (
                &["--log-level"],
                "a value is required for '--log-level <LEVEL>'",
            ),
            (
                &["-l", "INFO"],
                "invalid value 'INFO' for '--log-level <LEVEL>'",
            ),
            (
                &["-c", "a", "--config", "b"],
                "the argument '--config <PATH>' cannot be used multiple times",
            ),
            (&["--check", "--check"], "cannot be used multiple times"),
            (&["--check=yes"], "unexpected value for '--check'"),
            (
                &["--check", "--webui-hash"],
                "the argument '--webui-hash' cannot be used with '--check'",
            ),
            (
                &["--print-example-config", "--webui-hash"],
                "cannot be used with",
            ),
            (&["-hx"], "unexpected argument '-hx' found"),
        ] {
            let e = parse(args).unwrap_err();
            let (text, to_stderr) = e.message();
            assert!(to_stderr && e.status() == 2, "{args:?}");
            assert!(
                text.starts_with("error: ") && text.contains(reason),
                "{args:?}: {text}"
            );
        }
        // A path that is not UTF-8 is taken as it is.
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt as _;
            let raw = std::ffi::OsStr::from_bytes(b"/tmp/\xff.toml");
            let c = Cli::try_parse_from([
                std::ffi::OsStr::new("rtpflux"),
                std::ffi::OsStr::new("-c"),
                raw,
            ])
            .unwrap();
            assert_eq!(c.config.as_os_str(), raw);
        }
    }

    #[test]
    fn the_fd_limit_warning() {
        assert_eq!(fd_shortfall(1_000_000, 100), None);
        let w = fd_shortfall(1024, 5000).unwrap();
        assert!(
            w.contains("20064") && w.contains("sessions.max = 5000"),
            "{w}"
        );
        assert_eq!(raise_fd_limit(1), None, "a handful of calls always fits");
    }

    #[test]
    fn an_address_in_use_is_reported() {
        let taken = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = taken.local_addr().unwrap();
        let e = bind_control(&[addr]).unwrap_err();
        assert!(
            matches!(&e, StartError::Listen { what: "ng", addr: a, source }
                if *a == addr && source.kind() == std::io::ErrorKind::AddrInUse),
            "{e}"
        );
        assert!(
            e.to_string()
                .starts_with(&format!("ng: cannot listen on {addr}")),
            "{e}"
        );
    }
}
