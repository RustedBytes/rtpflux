//! The rtpflux daemon: see [`rtpflux::daemon`].

// No `unsafe` here, and no way to allow it (AGENTS.md §5).
#![forbid(unsafe_code)]
use nix::sys::signal::{SigSet, Signal};
use rtpflux::config::{self, LogFormat, LogLevel};
use rtpflux::daemon::{Cli, Daemon, Preflight, preflight, raise_fd_limit};
use std::io::Write as _;
use std::process::ExitCode;
use tracing_subscriber::filter::Targets;

/// A level as a filter for every target.
fn everywhere(level: LogLevel) -> Targets {
    // The level names are `Targets`' own, so this always parses.
    level.as_str().parse().unwrap_or_default()
}

/// Install the logging backend. Precedence: `--log-level`, then `RUST_LOG`
/// (`level` or `target=level,…`, e.g. `info,rtpflux::relay=debug`), then
/// `[log] level`. Records from the `log` macros are forwarded to it. With
/// `ring` lines, the web UI keeps the last ones too.
fn init_logging(cli_level: Option<LogLevel>, config: config::Log, ring: usize) {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    let mut bad_env = None;
    let filter = match cli_level {
        Some(level) => everywhere(level),
        None => match std::env::var("RUST_LOG") {
            Ok(spec) if !spec.trim().is_empty() => spec.parse().unwrap_or_else(|_| {
                bad_env = Some(spec);
                everywhere(config.level)
            }),
            _ => everywhere(config.level),
        },
    };
    if ring > 0 {
        rtpflux::webui::logs::enable(ring);
    }
    let fmt = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
    let registry = tracing_subscriber::registry()
        .with(filter)
        .with(rtpflux::webui::logs::RingLayer);
    let _ = match config.format {
        LogFormat::Full => registry.with(fmt).try_init(),
        LogFormat::Compact => registry.with(fmt.compact()).try_init(),
    };
    if let Some(spec) = bad_env {
        log::warn!(
            "RUST_LOG={spec:?} is not `level` or `target=level,…`; using level {}",
            config.level.as_str()
        );
    }
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse_from(std::env::args_os()) {
        Ok(cli) => cli,
        Err(exit) => {
            let (text, to_stderr) = exit.message();
            let _ = if to_stderr {
                std::io::stderr().write_all(text.as_bytes())
            } else {
                std::io::stdout().write_all(text.as_bytes())
            };
            return ExitCode::from(exit.status());
        }
    };
    let config = match preflight(&cli, &mut std::io::stdout(), &mut std::io::stderr()) {
        Preflight::Run(config) => config,
        Preflight::Done => return ExitCode::SUCCESS,
        Preflight::Failed => return ExitCode::FAILURE,
    };
    let ring = if config.webui.listen.is_some() {
        config.webui.log_buffer
    } else {
        0
    };
    init_logging(cli.log_level, config.log, ring);
    for warning in config.warnings() {
        log::warn!("configuration: {warning}");
    }
    if let Some(warning) = raise_fd_limit(config.sessions.max) {
        log::warn!("{warning}");
    }
    // Block SIGINT/SIGTERM before any thread starts (threads inherit the
    // mask), then wait for them synchronously: no signal handler needed.
    let mut signals = SigSet::empty();
    signals.add(Signal::SIGINT);
    signals.add(Signal::SIGTERM);
    if let Err(e) = signals.thread_block() {
        log::error!("cannot block signals: {e}");
        return ExitCode::FAILURE;
    }
    let daemon = match Daemon::start(&config) {
        Ok(d) => d,
        Err(e) => {
            log::error!("{e}");
            return ExitCode::FAILURE;
        }
    };
    match signals.wait() {
        Ok(sig) => log::info!("{sig}: shutting down"),
        Err(e) => log::error!("waiting for signals: {e}"),
    }
    daemon.stop();
    ExitCode::SUCCESS
}
