//! Daemon configuration: a TOML file (see `config/rtpflux.toml`), parsed
//! once at start-up and validated before anything is bound or allocated.
//!
//! Every section has defaults except `[[interface]]`, which must appear at
//! least once. Unknown keys are rejected so that typos fail loudly.

use serde::Deserialize;
use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

mod warnings;
pub use warnings::Warning;

/// The whole configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub control: Control,
    /// Media interfaces; at least one.
    #[serde(rename = "interface")]
    pub interfaces: Vec<Interface>,
    #[serde(default)]
    pub ports: Ports,
    #[serde(default)]
    pub sessions: Sessions,
    #[serde(default)]
    pub runtime: Runtime,
    #[serde(default)]
    pub xdp: Xdp,
    #[serde(default)]
    pub log: Log,
    #[serde(default)]
    pub metrics: Metrics,
    #[serde(default)]
    pub webui: WebUi,
    #[serde(default)]
    pub recording: Recording,
    #[serde(default)]
    pub ice: Ice,
}

/// The relay's ICE agent towards endpoints that use ICE.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IceMode {
    /// A full agent (RFC 8445): checks of its own, nomination, consent
    /// freshness (RFC 7675).
    #[default]
    Full,
    /// A lite agent: it only answers checks.
    Lite,
}

/// `[ice]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Ice {
    pub mode: IceMode,
    /// Ta, the pacing of connectivity checks (ms; RFC 8445 §14.2, at least
    /// 5).
    pub pacing_ms: u64,
    /// A STUN server (`host:port`) the relay asks for its public address,
    /// to offer server-reflexive candidates when it is behind a NAT.
    pub stun_server: Option<String>,
}

impl Default for Ice {
    fn default() -> Self {
        Ice {
            mode: IceMode::Full,
            pacing_ms: 50,
            stun_server: None,
        }
    }
}

/// `[control]`: where the `ng` protocol is served.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Control {
    /// UDP endpoints for `ng` commands.
    pub listen: Vec<SocketAddr>,
    /// TCP endpoints for `ng` commands (`cookie bencode` messages back to
    /// back, as rtpengine's `listen-tcp-ng`).
    pub listen_tcp: Vec<SocketAddr>,
    /// HTTP endpoints: `POST /ng`, `POST /ng-plain`, and WebSocket with the
    /// `ng.rtpengine.com` / `ng-plain.rtpengine.com` subprotocols.
    pub listen_http: Vec<SocketAddr>,
    /// Largest accepted command datagram, in octets.
    pub max_message: usize,
}

impl Default for Control {
    fn default() -> Self {
        Control {
            listen: vec![SocketAddr::from(([127, 0, 0, 1], 2223))],
            listen_tcp: Vec::new(),
            listen_http: Vec::new(),
            max_message: 65_535,
        }
    }
}

/// `[[interface]]`: a logical media interface. Direction flags in `ng`
/// commands (`direction=external`) select interfaces by `name`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interface {
    pub name: String,
    /// Local address media sockets bind to.
    pub address: IpAddr,
    /// Address written into SDP; defaults to `address` (set it behind a 1:1 NAT).
    pub advertise: Option<IpAddr>,
}

impl Interface {
    /// The address put into rewritten SDP.
    #[must_use]
    pub fn advertised(&self) -> IpAddr {
        self.advertise.unwrap_or(self.address)
    }
}

/// `[ports]`: the media port range. RTP uses even ports and RTCP the next
/// odd one, so the range starts even and holds at least one pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Ports {
    pub min: u16,
    pub max: u16,
}

impl Default for Ports {
    fn default() -> Self {
        Ports {
            min: 30_000,
            max: 60_000,
        }
    }
}

impl Ports {
    /// Number of RTP/RTCP pairs in the range.
    #[must_use]
    pub fn pairs(self) -> usize {
        (usize::from(self.max) + 1).saturating_sub(usize::from(self.min)) / 2
    }
}

/// `[sessions]`: limits and timeouts (seconds).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Sessions {
    /// Concurrent dialogs: an offer for a new one beyond it is refused
    /// (re-offers always pass). The port range must serve this many.
    pub max: usize,
    /// No media in either direction for this long ends the call.
    pub timeout: u64,
    /// The same, for calls on hold: a section either party offered or
    /// answered `sendonly`, `recvonly` or `inactive`, or with `0.0.0.0`.
    pub silent_timeout: u64,
    /// A call is deleted this long after its first offer, whatever its
    /// activity; 0 = never.
    pub final_timeout: u64,
    /// An offer without an answer is dropped after this long.
    pub offer_timeout: u64,
    /// Every call as if the proxy sent the `strict-source` flag: once a
    /// side's address is known, media from any other source is dropped
    /// (no injection, but a phone whose NAT mapping changes mid-call is
    /// not followed).
    pub strict_source: bool,
    /// Write the dialogs here within a second of a change (at most once a
    /// second, so a crash can lose the last second's changes) and on
    /// shutdown, and restore them at start (none: calls do not survive a
    /// restart). A file that cannot be used is kept aside as `<name>.bad`.
    pub state_file: Option<PathBuf>,
    /// Also (or instead) keep them in Redis:
    /// `redis://[[user]:password@]host[:port][/db]`.
    pub redis: Option<String>,
    /// The Redis key they are kept under.
    pub redis_key: String,
}

impl Sessions {
    /// Where in Redis the dialogs are kept, if anywhere.
    ///
    /// # Errors
    ///
    /// A malformed `redis` URL or an empty key.
    pub fn redis_target(&self) -> Result<Option<crate::redis::Target>, crate::redis::TargetError> {
        self.redis
            .as_deref()
            .map(|url| crate::redis::Target::parse(url, &self.redis_key))
            .transpose()
    }

    /// Whether calls are kept across restarts (a state file or Redis).
    #[must_use]
    pub fn persistent(&self) -> bool {
        self.state_file.is_some() || self.redis.is_some()
    }
}

impl Default for Sessions {
    fn default() -> Self {
        Sessions {
            max: 5_000,
            timeout: 60,
            silent_timeout: 3_600,
            final_timeout: 0,
            offer_timeout: 3_600,
            strict_source: false,
            state_file: None,
            redis: None,
            redis_key: crate::redis::DEFAULT_KEY.to_owned(),
        }
    }
}

/// `[runtime]`: threads and buffers, all allocated once at start-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Runtime {
    /// Media worker threads, one session shard each; 0 = one per CPU.
    pub workers: usize,
    /// Datagrams per receive/send system call.
    pub batch: usize,
    /// Slots in each worker's packet ring; a power of two.
    pub ring_capacity: usize,
    /// Size of each packet buffer in octets.
    pub packet_buffer: usize,
    /// How the media workers receive: `io_uring` (multishot receive on
    /// every socket at once, into `ring_capacity` provided buffers per
    /// worker; the default, with `recvmmsg` where the kernel lacks it) or
    /// `recvmmsg` (epoll, then batches per socket).
    pub receive: Receive,
}

/// `runtime.receive`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub enum Receive {
    #[serde(rename = "recvmmsg")]
    Recvmmsg,
    #[default]
    #[serde(rename = "io_uring")]
    IoUring,
}

impl Default for Runtime {
    fn default() -> Self {
        Runtime {
            workers: 0,
            batch: 32,
            ring_capacity: 4_096,
            packet_buffer: 2_048,
            receive: Receive::IoUring,
        }
    }
}

/// `[xdp]`: the in-driver fast path for established plain RTP streams.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Xdp {
    pub enabled: bool,
    /// Network devices to attach to (e.g. `eth0`).
    pub devices: Vec<String>,
    pub mode: XdpMode,
    /// The compiled XDP program (`rtpflux-xdp-ebpf`, release build).
    pub object: PathBuf,
    /// Receive what the kernel does not relay (encrypted, WebRTC and BUNDLE
    /// calls, calls not yet settled) through `AF_XDP` sockets on the first
    /// device, instead of the kernel's UDP stack. Needs a build with the
    /// `af-xdp` feature.
    pub af_xdp: bool,
    /// Frames (4 KiB each) of the `AF_XDP` memory of each receive queue.
    pub af_xdp_frames: u32,
}

impl Default for Xdp {
    fn default() -> Self {
        Xdp {
            enabled: false,
            devices: Vec::new(),
            mode: XdpMode::Native,
            object: PathBuf::from("/usr/lib/rtpflux/rtpflux-xdp"),
            af_xdp: false,
            af_xdp_frames: 2048,
        }
    }
}

/// How the XDP program is attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XdpMode {
    /// In the driver (fastest; needs driver support).
    Native,
    /// In the generic kernel path (works everywhere, slower).
    Generic,
}

/// `[webui]`: the read-only administrator web UI.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WebUi {
    /// HTTP address of the UI (none: off).
    pub listen: Option<SocketAddr>,
    /// Login name.
    pub user: String,
    /// `sha256:<salt>:<hex of sha256(salt ‖ password)>`, from
    /// `rtpflux --webui-hash`.
    pub password_hash: String,
    /// Basic-auth realm.
    pub realm: String,
    /// Concurrent HTTP connections.
    pub max_connections: usize,
    /// How often the UI polls, in milliseconds.
    pub refresh_ms: u64,
    /// Log lines kept in memory for the Logs page (0: off).
    pub log_buffer: usize,
}

impl Default for WebUi {
    fn default() -> Self {
        WebUi {
            listen: None,
            user: String::new(),
            password_hash: String::new(),
            realm: "rtpflux".to_owned(),
            max_connections: 64,
            refresh_ms: 2000,
            log_buffer: 2000,
        }
    }
}

/// `[metrics]`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Metrics {
    /// HTTP addresses serving Prometheus metrics on `/metrics` (none: off).
    pub listen: Vec<SocketAddr>,
}

/// `[recording]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Recording {
    /// Where `start recording` writes (none: recording off).
    pub dir: Option<PathBuf>,
    /// What a recording becomes when it ends: `pcap` (as recorded), `wav`,
    /// `flac`, `opus` or `mp3`.
    pub format: crate::recording::Format,
    /// `stereo` (caller left, callee right) or `mono`.
    pub channels: crate::recording::Channels,
    /// Samples per second: 8000, 16000, 24000 or 48000.
    pub sample_rate: u32,
    /// kbit/s, for `opus` and `mp3`.
    pub bitrate: u32,
    /// Keep the pcap after converting it.
    pub keep_pcap: bool,
    /// Where finished recordings go: `local` (`dir`) or `s3`.
    pub storage: crate::recording::store::Storage,
    /// `[recording.s3]`.
    pub s3: crate::recording::store::S3Config,
    /// How files are named, without the extension: text and the
    /// placeholders `{call_id}`, `{from_tag}`, `{to_tag}`, `{section}`,
    /// `{date}`, `{time}` (UTC) and `{timestamp}`.
    pub file_name: String,
    /// `[recording.metadata]`: tags every recording carries (in its JSON
    /// and the audio file); `start recording` can add more.
    pub metadata: std::collections::BTreeMap<String, String>,
}

impl Default for Recording {
    fn default() -> Self {
        let s = crate::recording::Settings::default();
        Recording {
            dir: None,
            format: s.format,
            channels: s.channels,
            sample_rate: s.sample_rate,
            bitrate: s.bitrate,
            keep_pcap: s.keep_pcap,
            storage: crate::recording::store::Storage::Local,
            s3: crate::recording::store::S3Config::default(),
            file_name: crate::recording::naming::DEFAULT_FILE_NAME.to_owned(),
            metadata: std::collections::BTreeMap::new(),
        }
    }
}

impl Recording {
    /// The default conversion of recordings.
    #[must_use]
    pub fn settings(&self) -> crate::recording::Settings {
        crate::recording::Settings {
            format: self.format,
            channels: self.channels,
            sample_rate: self.sample_rate,
            bitrate: self.bitrate,
            keep_pcap: self.keep_pcap,
        }
    }
}

/// `[log]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Log {
    pub level: LogLevel,
    pub format: LogFormat,
}

impl Default for Log {
    fn default() -> Self {
        Log {
            level: LogLevel::Info,
            format: LogFormat::Full,
        }
    }
}

/// Log level; `RUST_LOG` and `--log-level` take precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    /// Every level, quietest first.
    pub const ALL: [LogLevel; 5] = [
        LogLevel::Error,
        LogLevel::Warn,
        LogLevel::Info,
        LogLevel::Debug,
        LogLevel::Trace,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }
}

impl std::str::FromStr for LogLevel {
    type Err = ();

    /// One of `error`, `warn`, `info`, `debug`, `trace`.
    fn from_str(s: &str) -> Result<Self, ()> {
        LogLevel::ALL
            .into_iter()
            .find(|l| l.as_str() == s)
            .ok_or(())
    }
}

/// Log line format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Timestamp, level, target, message.
    Full,
    /// Shorter lines.
    Compact,
}

/// A rule a configuration breaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    NoControlListen,
    MaxMessage,
    NoInterface,
    IcePacing,
    /// `ice.stun_server` that is not host:port.
    StunServer(String),
    EmptyInterfaceName,
    /// An interface name with whitespace or control characters, which
    /// `direction` in `ng` commands cannot name reliably.
    InterfaceName(String),
    DuplicateInterface(String),
    /// An interface (named) bound to the unspecified address.
    UnspecifiedAddress(String),
    /// An interface (named) advertising the unspecified address.
    UnspecifiedAdvertise(String),
    PortsMin,
    PortsOrder,
    /// Too few port pairs for `sessions.max`.
    TooFewPorts {
        pairs: usize,
        sessions: usize,
    },
    NoSessions,
    SessionTimeouts,
    Redis(crate::redis::TargetError),
    SilentTimeout,
    RingCapacity,
    Batch,
    PacketBuffer,
    Recording(crate::recording::settings::Problem),
    RecordingS3(crate::recording::store::S3Problem),
    RecordingDir,
    /// `recording.file_name` that cannot be used, and why.
    RecordingFileName(String),
    /// `[recording.metadata]` that cannot be used, and why.
    RecordingMetadata(String),
    WebUiUser,
    WebUiLogin(crate::webui::auth::CredentialsError),
    WebUiRealm,
    WebUiConnections,
    WebUiRefresh,
    WebUiLogBuffer,
    XdpDevices,
    /// More flow entries needed (4 per call) than the kernel map holds.
    XdpFlows {
        sessions: usize,
        flows: u64,
    },
    AfXdpNeedsXdp,
    NoAfXdpSupport,
    AfXdpFrames(u32),
    /// An `xdp.devices` entry that is not a network device name (empty,
    /// longer than 15 octets, or with '/', whitespace or control
    /// characters).
    XdpDevice(String),
    /// The same device twice in `xdp.devices`.
    DuplicateXdpDevice(String),
    /// Two listeners on the same address and transport: `second` (the key
    /// of the later one) clashes with `first`.
    ListenConflict {
        first: &'static str,
        second: &'static str,
        addr: SocketAddr,
    },
    /// A `control.listen` address inside the media port range of an
    /// interface it shares an address with: media sockets cannot bind it.
    ControlInMediaPorts {
        addr: SocketAddr,
        interface: String,
    },
}

impl fmt::Display for Problem {
    // One arm per problem: long, but flat.
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Problem::NoControlListen => {
                f.write_str("control.listen: at least one endpoint is required")
            }
            Problem::MaxMessage => {
                f.write_str("control.max_message: must be between 512 and 65535")
            }
            Problem::NoInterface => {
                f.write_str("interface: at least one [[interface]] is required")
            }
            Problem::IcePacing => f.write_str("ice.pacing_ms: must be between 5 and 1000"),
            Problem::StunServer(s) => write!(
                f,
                "ice.stun_server: '{s}' is not host:port (port 1 to 65535, IPv6 in brackets)"
            ),
            Problem::EmptyInterfaceName => f.write_str("interface.name: must not be empty"),
            Problem::InterfaceName(n) => write!(
                f,
                "interface.name {n:?}: must not contain whitespace or control characters"
            ),
            Problem::DuplicateInterface(n) => {
                write!(f, "interface.name: '{n}' appears more than once")
            }
            Problem::UnspecifiedAddress(n) => {
                write!(f, "interface '{n}': address must be a concrete address")
            }
            Problem::UnspecifiedAdvertise(n) => {
                write!(f, "interface '{n}': advertise must be a concrete address")
            }
            Problem::PortsMin => {
                f.write_str("ports.min: must be even and non-zero (RTP on even, RTCP on odd ports)")
            }
            Problem::PortsOrder => f.write_str("ports: min must be below max"),
            Problem::TooFewPorts { pairs, sessions } => write!(
                f,
                "ports: {pairs} RTP/RTCP pairs cannot serve sessions.max = {sessions} (two pairs per call)"
            ),
            Problem::NoSessions => f.write_str("sessions.max: must be at least 1"),
            Problem::SessionTimeouts => {
                f.write_str("sessions: timeout and offer_timeout must be at least 1 second")
            }
            Problem::Redis(e) => write!(f, "sessions.redis: {e}"),
            Problem::SilentTimeout => {
                f.write_str("sessions.silent_timeout: must not be shorter than sessions.timeout")
            }
            Problem::RingCapacity => f.write_str("runtime.ring_capacity: must be a power of two"),
            Problem::Batch => write!(
                f,
                "runtime.batch: must be between 1 and {} and at most runtime.ring_capacity",
                crate::relay::MAX_BATCH
            ),
            Problem::PacketBuffer => {
                f.write_str("runtime.packet_buffer: must be between 1500 and 65535 octets")
            }
            Problem::Recording(p) => write!(f, "recording.{p}"),
            Problem::RecordingS3(p) => write!(f, "recording.{p}"),
            Problem::RecordingDir => f.write_str(
                "recording.dir: needed with storage = \"s3\" (files are made there, then uploaded)",
            ),
            Problem::RecordingFileName(why) => write!(f, "recording.file_name: {why}"),
            Problem::RecordingMetadata(why) => write!(f, "recording.metadata: {why}"),
            Problem::WebUiUser => f.write_str("webui.user: required, without ':'"),
            Problem::WebUiLogin(e) => write!(f, "webui.password_hash: {e}"),
            Problem::WebUiRealm => {
                f.write_str("webui.realm: must not contain '\"' or control characters")
            }
            Problem::WebUiConnections => f.write_str("webui.max_connections: 1 to 4096"),
            Problem::WebUiRefresh => f.write_str("webui.refresh_ms: 500 to 60000"),
            Problem::WebUiLogBuffer => f.write_str("webui.log_buffer: at most 100000"),
            Problem::XdpDevices => f.write_str("xdp.devices: required when xdp.enabled = true"),
            Problem::XdpFlows { sessions, flows } => write!(
                f,
                "xdp: sessions.max = {sessions} needs {flows} flow entries (4 per call), the map holds {}",
                rtpflux_xdp_common::FLOW_MAP_ENTRIES
            ),
            Problem::AfXdpNeedsXdp => f.write_str("xdp.af_xdp: needs xdp.enabled = true"),
            Problem::NoAfXdpSupport => {
                f.write_str("xdp.af_xdp: this build has no AF_XDP support (cargo feature `af-xdp`)")
            }
            Problem::AfXdpFrames(n) => {
                write!(f, "xdp.af_xdp_frames = {n}: 64 to 65536 are allowed")
            }
            Problem::XdpDevice(d) => write!(
                f,
                "xdp.devices: {d:?} is not a device name (1 to 15 octets, no '/', whitespace or control characters)"
            ),
            Problem::DuplicateXdpDevice(d) => {
                write!(f, "xdp.devices: '{d}' appears more than once")
            }
            Problem::ListenConflict {
                first,
                second,
                addr,
            } => write!(
                f,
                "{second}: {addr} clashes with a {first} address (same port, same or wildcard address)"
            ),
            Problem::ControlInMediaPorts { addr, interface } => write!(
                f,
                "control.listen: {addr} is inside the media ports of interface '{interface}' (ports.min to ports.max)"
            ),
        }
    }
}

/// Why a configuration cannot be used.
#[derive(Debug)]
pub enum ConfigError {
    Read(std::io::Error),
    Parse(toml::de::Error),
    Invalid(Vec<Problem>),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Read(e) => write!(f, "cannot read configuration: {e}"),
            ConfigError::Parse(e) => write!(f, "cannot parse configuration: {e}"),
            ConfigError::Invalid(problems) => {
                write!(f, "invalid configuration:")?;
                for p in problems {
                    write!(f, "\n  - {p}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Read(e) => Some(e),
            ConfigError::Parse(e) => Some(e),
            ConfigError::Invalid(_) => None,
        }
    }
}

impl Config {
    /// Read, parse and validate a configuration file.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] when the file cannot be read or parsed, or fails
    /// [`Config::validate`].
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(ConfigError::Read)?;
        Self::from_toml(&text)
    }

    /// Parse and validate configuration text.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] when the text cannot be parsed or fails validation.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let config: Config = toml::from_str(text).map_err(ConfigError::Parse)?;
        config.validate().map_err(ConfigError::Invalid)?;
        Ok(config)
    }

    /// Check the cross-field rules; returns every problem found.
    ///
    /// # Errors
    ///
    /// The list of problems, when there is at least one.
    pub fn validate(&self) -> Result<(), Vec<Problem>> {
        let mut problems = Vec::new();
        if self.control.listen.is_empty() {
            problems.push(Problem::NoControlListen);
        }
        if !(512..=65_535).contains(&self.control.max_message) {
            problems.push(Problem::MaxMessage);
        }
        if self.interfaces.is_empty() {
            problems.push(Problem::NoInterface);
        }
        if !(5..=1_000).contains(&self.ice.pacing_ms) {
            problems.push(Problem::IcePacing);
        }
        if let Some(server) = &self.ice.stun_server
            && !is_host_port(server)
        {
            problems.push(Problem::StunServer(server.clone()));
        }
        let mut names = HashSet::new();
        for i in &self.interfaces {
            if i.name.is_empty() {
                problems.push(Problem::EmptyInterfaceName);
            } else if i.name.chars().any(|c| c.is_whitespace() || c.is_control()) {
                problems.push(Problem::InterfaceName(i.name.clone()));
            } else if !names.insert(i.name.as_str()) {
                problems.push(Problem::DuplicateInterface(i.name.clone()));
            }
            if i.address.is_unspecified() {
                problems.push(Problem::UnspecifiedAddress(i.name.clone()));
            }
            if i.advertise.is_some_and(|a| a.is_unspecified()) {
                problems.push(Problem::UnspecifiedAdvertise(i.name.clone()));
            }
        }
        let p = self.ports;
        if p.min == 0 || !p.min.is_multiple_of(2) {
            problems.push(Problem::PortsMin);
        }
        if p.min >= p.max {
            problems.push(Problem::PortsOrder);
        } else if p.pairs() < self.sessions.max.saturating_mul(2) {
            // Two streams (caller and callee side) per call, one pair each.
            problems.push(Problem::TooFewPorts {
                pairs: p.pairs(),
                sessions: self.sessions.max,
            });
        }
        let s = &self.sessions;
        if s.max == 0 {
            problems.push(Problem::NoSessions);
        }
        if s.timeout == 0 || s.offer_timeout == 0 {
            problems.push(Problem::SessionTimeouts);
        }
        if let Err(e) = s.redis_target() {
            problems.push(Problem::Redis(e));
        }
        if s.silent_timeout < s.timeout {
            problems.push(Problem::SilentTimeout);
        }
        let r = self.runtime;
        if !r.ring_capacity.is_power_of_two() {
            problems.push(Problem::RingCapacity);
        }
        if r.batch == 0 || r.batch > crate::relay::MAX_BATCH || r.batch > r.ring_capacity {
            problems.push(Problem::Batch);
        }
        if !(1_500..=65_535).contains(&r.packet_buffer) {
            problems.push(Problem::PacketBuffer);
        }
        self.listen_problems(&mut problems);
        self.recording_problems(&mut problems);
        self.xdp_problems(&mut problems);
        self.webui_problems(&mut problems);
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems)
        }
    }

    /// Listeners: no address twice on one transport, and no `ng` socket
    /// where media sockets bind.
    fn listen_problems(&self, problems: &mut Vec<Problem>) {
        let udp = self.control.listen.iter().map(|a| ("control.listen", *a));
        let tcp = (self.control.listen_tcp.iter())
            .map(|a| ("control.listen_tcp", *a))
            .chain(
                self.control
                    .listen_http
                    .iter()
                    .map(|a| ("control.listen_http", *a)),
            )
            .chain(self.metrics.listen.iter().map(|a| ("metrics.listen", *a)))
            .chain(self.webui.listen.iter().map(|a| ("webui.listen", *a)));
        for transport in [udp.collect::<Vec<_>>(), tcp.collect()] {
            for (k, &(second, addr)) in transport.iter().enumerate() {
                let earlier = transport.get(..k).unwrap_or_default();
                if let Some(&(first, _)) = earlier.iter().find(|(_, a)| clash(*a, addr)) {
                    problems.push(Problem::ListenConflict {
                        first,
                        second,
                        addr,
                    });
                }
            }
        }
        let pairs = u32::try_from(self.ports.pairs()).unwrap_or(u32::MAX);
        let media = u32::from(self.ports.min)
            ..u32::from(self.ports.min).saturating_add(pairs.saturating_mul(2));
        for &addr in &self.control.listen {
            if !media.contains(&u32::from(addr.port())) {
                continue;
            }
            let shared = self
                .interfaces
                .iter()
                .find(|i| clash(addr, SocketAddr::new(i.address, addr.port())));
            if let Some(i) = shared {
                problems.push(Problem::ControlInMediaPorts {
                    addr,
                    interface: i.name.clone(),
                });
            }
        }
    }

    /// The `[recording]` rules.
    fn recording_problems(&self, problems: &mut Vec<Problem>) {
        if let Some(why) = crate::recording::naming::check_file_name(&self.recording.file_name) {
            problems.push(Problem::RecordingFileName(why));
        }
        if let Some(why) = crate::recording::naming::check_metadata(&self.recording.metadata) {
            problems.push(Problem::RecordingMetadata(why));
        }
        problems.extend(
            self.recording
                .settings()
                .problems()
                .into_iter()
                .map(Problem::Recording),
        );
        if self.recording.storage == crate::recording::store::Storage::S3 {
            problems.extend(
                self.recording
                    .s3
                    .problems()
                    .into_iter()
                    .map(Problem::RecordingS3),
            );
            if self.recording.dir.is_none() {
                problems.push(Problem::RecordingDir);
            }
        }
    }

    /// The `[webui]` rules.
    fn webui_problems(&self, problems: &mut Vec<Problem>) {
        let w = &self.webui;
        if w.listen.is_none() {
            return;
        }
        if w.user.is_empty() || w.user.contains(':') {
            problems.push(Problem::WebUiUser);
        }
        if let Err(e) = crate::webui::auth::Credentials::new(&w.user, &w.password_hash) {
            problems.push(Problem::WebUiLogin(e));
        }
        if w.realm.contains('"') || w.realm.chars().any(char::is_control) {
            problems.push(Problem::WebUiRealm);
        }
        if !(1..=4096).contains(&w.max_connections) {
            problems.push(Problem::WebUiConnections);
        }
        if !(500..=60_000).contains(&w.refresh_ms) {
            problems.push(Problem::WebUiRefresh);
        }
        if w.log_buffer > 100_000 {
            problems.push(Problem::WebUiLogBuffer);
        }
    }

    /// The `[xdp]` rules.
    fn xdp_problems(&self, problems: &mut Vec<Problem>) {
        let s = &self.sessions;
        if self.xdp.enabled {
            if self.xdp.devices.is_empty() {
                problems.push(Problem::XdpDevices);
            }
            let mut seen = HashSet::new();
            for d in &self.xdp.devices {
                if !is_device_name(d) {
                    problems.push(Problem::XdpDevice(d.clone()));
                } else if !seen.insert(d.as_str()) {
                    problems.push(Problem::DuplicateXdpDevice(d.clone()));
                }
            }
            let flows = u64::try_from(s.max.saturating_mul(4)).unwrap_or(u64::MAX);
            if flows > u64::from(rtpflux_xdp_common::FLOW_MAP_ENTRIES) {
                problems.push(Problem::XdpFlows {
                    sessions: s.max,
                    flows,
                });
            }
        }
        if self.xdp.af_xdp {
            if !self.xdp.enabled {
                problems.push(Problem::AfXdpNeedsXdp);
            }
            if !cfg!(feature = "af-xdp") {
                problems.push(Problem::NoAfXdpSupport);
            }
            if !(64..=65_536).contains(&self.xdp.af_xdp_frames) {
                problems.push(Problem::AfXdpFrames(self.xdp.af_xdp_frames));
            }
        }
    }
}

/// Whether two sockets of one transport cannot both be bound: the same
/// port, and the same address or a wildcard of the same family. Port 0
/// (any free port) never clashes.
fn clash(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() != 0
        && a.port() == b.port()
        && (a.ip() == b.ip()
            || (a.is_ipv4() == b.is_ipv4() && (a.ip().is_unspecified() || b.ip().is_unspecified())))
}

/// `host:port` or `[v6]:port`, with a non-empty host and a port from 1.
fn is_host_port(s: &str) -> bool {
    let Some((host, port)) = s.rsplit_once(':') else {
        return false;
    };
    let host_ok = match host.strip_prefix('[') {
        Some(v6) => v6
            .strip_suffix(']')
            .is_some_and(|a| a.parse::<std::net::Ipv6Addr>().is_ok()),
        None => !host.is_empty() && !host.contains(':') && !host.contains(char::is_whitespace),
    };
    host_ok && port.parse::<u16>().is_ok_and(|p| p != 0)
}

/// A Linux network device name: 1 to 15 octets (`IFNAMSIZ` - 1), no '/',
/// whitespace or control characters.
fn is_device_name(s: &str) -> bool {
    (1..=15).contains(&s.len())
        && s != "."
        && s != ".."
        && !s
            .chars()
            .any(|c| c == '/' || c.is_whitespace() || c.is_control())
}

/// The documented example configuration (also the `--print-default-config`
/// output).
pub const EXAMPLE: &str = include_str!("../../../config/rtpflux.toml");

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        [[interface]]
        name = "external"
        address = "203.0.113.10"
    "#;

    #[test]
    fn example_file_is_valid() {
        let c = Config::from_toml(EXAMPLE).unwrap();
        assert_eq!(c.interfaces.len(), 2);
    }

    #[test]
    fn minimal_config_gets_defaults() {
        let c = Config::from_toml(MINIMAL).unwrap();
        assert_eq!(c.control, Control::default());
        assert_eq!(c.ports, Ports::default());
        assert_eq!(c.sessions, Sessions::default());
        assert_eq!(c.runtime, Runtime::default());
        assert_eq!(c.xdp, Xdp::default());
        assert_eq!(
            c.interfaces[0].advertised(),
            "203.0.113.10".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let text = format!("{MINIMAL}\n[ports]\nminimum = 30000\n");
        assert!(matches!(
            Config::from_toml(&text),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn interface_is_required() {
        assert!(matches!(
            Config::from_toml("[ports]\nmin = 30000\n"),
            Err(ConfigError::Parse(_))
        ));
        assert!(matches!(
            Config::from_toml("interface = []\n"),
            Err(ConfigError::Invalid(_))
        ));
    }

    /// The problems found, as their text.
    fn problems(text: &str) -> Vec<String> {
        match Config::from_toml(text) {
            Err(ConfigError::Invalid(p)) => p.iter().map(ToString::to_string).collect(),
            other => panic!("expected validation errors, got {other:?}"),
        }
    }

    #[test]
    fn problems_are_typed() {
        let text = format!(
            "{MINIMAL}\n[[interface]]\nname = \"external\"\naddress = \"0.0.0.0\"\n\
             [ports]\nmin = 30001\nmax = 30000\n"
        );
        let Err(ConfigError::Invalid(p)) = Config::from_toml(&text) else {
            panic!("expected validation errors");
        };
        for want in [
            Problem::DuplicateInterface("external".to_owned()),
            Problem::UnspecifiedAddress("external".to_owned()),
            Problem::PortsMin,
            Problem::PortsOrder,
        ] {
            assert!(p.contains(&want), "{want:?} in {p:?}");
        }
    }

    #[test]
    fn redis_state() {
        let p = problems(&format!(
            "{MINIMAL}\n[sessions]\nredis = \"rediss://cache:6379\"\n"
        ));
        assert!(
            p.iter().any(|m| m.starts_with("sessions.redis: rediss://")),
            "{p:?}"
        );
        let p = problems(&format!(
            "{MINIMAL}\n[sessions]\nredis = \"redis://cache\"\nredis_key = \"\"\n"
        ));
        assert!(
            p.iter().any(|m| m.contains("key must not be empty")),
            "{p:?}"
        );
        let c = Config::from_toml(&format!(
            "{MINIMAL}\n[sessions]\nredis = \"redis://:pw@cache:6380/1\"\n"
        ))
        .unwrap();
        assert!(c.sessions.persistent() && c.sessions.state_file.is_none());
        let t = c.sessions.redis_target().unwrap().unwrap();
        assert_eq!(t.describe(), "redis://:***@cache:6380/1 key rtpflux:state");
        assert!(!Config::from_toml(MINIMAL).unwrap().sessions.persistent());
    }

    #[test]
    fn cross_field_rules() {
        let p = problems(&format!("{MINIMAL}\n[ports]\nmin = 30001\nmax = 30000\n"));
        assert!(p.iter().any(|m| m.starts_with("ports.min")));
        assert!(
            p.iter()
                .any(|m| m.starts_with("ports: min must be below max"))
        );

        let p = problems(&format!(
            "{MINIMAL}\n[ports]\nmin = 30000\nmax = 30009\n[sessions]\nmax = 10\n"
        ));
        assert!(p.iter().any(|m| m.contains("cannot serve sessions.max")));

        let p = problems(&format!(
            "{MINIMAL}\n[runtime]\nring_capacity = 1000\nbatch = 0\n"
        ));
        assert_eq!(p.len(), 2);

        let p = problems(&format!("{MINIMAL}\n[xdp]\nenabled = true\n"));
        assert!(p.iter().any(|m| m.starts_with("xdp.devices")));

        let dup = r#"
            [[interface]]
            name = "a"
            address = "10.0.0.1"
            [[interface]]
            name = "a"
            address = "0.0.0.0"
        "#;
        let p = problems(dup);
        assert!(p.iter().any(|m| m.contains("appears more than once")));
        assert!(p.iter().any(|m| m.contains("concrete address")));
    }

    #[test]
    fn every_rule_is_checked_and_reported_together() {
        let p = problems(
            r#"
            [control]
            listen = []
            max_message = 100
            [[interface]]
            name = ""
            address = "0.0.0.0"
            [[interface]]
            name = "x"
            address = "10.0.0.1"
            advertise = "0.0.0.0"
            [[interface]]
            name = "x"
            address = "10.0.0.2"
            [ports]
            min = 30001
            max = 30000
            [sessions]
            max = 0
            timeout = 0
            silent_timeout = 0
            [runtime]
            ring_capacity = 100
            batch = 0
            packet_buffer = 100
            [xdp]
            enabled = true
            "#,
        );
        for needle in [
            "control.listen",
            "control.max_message",
            "interface.name: must not be empty",
            "'x' appears more than once",
            "address must be a concrete address",
            "advertise must be a concrete address",
            "ports.min: must be even",
            "ports: min must be below max",
            "sessions.max: must be at least 1",
            "timeout and offer_timeout",
            "runtime.ring_capacity",
            "runtime.batch",
            "runtime.packet_buffer",
            "xdp.devices: required",
        ] {
            assert!(p.iter().any(|x| x.contains(needle)), "{needle}: {p:#?}");
        }
        assert!(
            problems("interface = []")
                .iter()
                .any(|x| x.contains("at least one [[interface]]"))
        );
        let p = problems(
            "[[interface]]\nname = \"a\"\naddress = \"10.0.0.1\"\n[sessions]\nmax = 20000\n[ports]\nmin = 2\nmax = 65535\n[xdp]\nenabled = true\ndevices = [\"eth0\"]\n",
        );
        assert!(p.iter().any(|x| x.contains("flow entries")), "{p:#?}");
        let p = problems(
            "[[interface]]\nname = \"a\"\naddress = \"10.0.0.1\"\n[sessions]\ntimeout = 60\nsilent_timeout = 10\n",
        );
        assert!(p.iter().any(|x| x.contains("silent_timeout")), "{p:#?}");
    }

    #[test]
    fn errors_read_well() {
        let e = Config::load(Path::new("/nonexistent/rtpflux.toml")).unwrap_err();
        assert!(
            e.to_string().starts_with("cannot read configuration: "),
            "{e}"
        );
        let e = Config::from_toml("[[interface]\n").unwrap_err();
        assert!(
            e.to_string().starts_with("cannot parse configuration: "),
            "{e}"
        );
        let e = Config::from_toml("interface = []").unwrap_err();
        let text = e.to_string();
        assert!(text.starts_with("invalid configuration:\n  - "), "{text}");
        for (level, name) in [
            (LogLevel::Error, "error"),
            (LogLevel::Warn, "warn"),
            (LogLevel::Info, "info"),
            (LogLevel::Debug, "debug"),
            (LogLevel::Trace, "trace"),
        ] {
            assert_eq!(level.as_str(), name);
            assert_eq!(name.parse(), Ok(level));
        }
        assert_eq!("loud".parse::<LogLevel>(), Err(()));
        assert_eq!("INFO".parse::<LogLevel>(), Err(()));
    }

    #[test]
    fn listeners_must_not_clash() {
        let Err(ConfigError::Invalid(p)) = Config::from_toml(&format!(
            "{MINIMAL}\n[control]\nlisten = [\"127.0.0.1:2223\", \"0.0.0.0:2223\", \"[::1]:2223\", \"127.0.0.1:0\", \"127.0.0.1:0\"]\n\
             listen_tcp = [\"127.0.0.1:2223\"]\nlisten_http = [\"127.0.0.1:8080\"]\n\
             [metrics]\nlisten = [\"0.0.0.0:8080\"]\n"
        )) else {
            panic!("expected validation errors");
        };
        // UDP and TCP on one port, the IPv6 loopback, and port 0 are fine.
        assert_eq!(
            p,
            vec![
                Problem::ListenConflict {
                    first: "control.listen",
                    second: "control.listen",
                    addr: "0.0.0.0:2223".parse().unwrap(),
                },
                Problem::ListenConflict {
                    first: "control.listen_http",
                    second: "metrics.listen",
                    addr: "0.0.0.0:8080".parse().unwrap(),
                },
            ]
        );
        let text = p[1].to_string();
        assert!(
            text.starts_with("metrics.listen: 0.0.0.0:8080 clashes with a control.listen_http"),
            "{text}"
        );
    }

    #[test]
    fn control_port_outside_the_media_ports() {
        let p = problems(&format!(
            "{MINIMAL}\n[control]\nlisten = [\"0.0.0.0:30010\"]\n[ports]\nmin = 30000\nmax = 30099\n[sessions]\nmax = 10\n"
        ));
        assert!(
            p.iter()
                .any(|x| x.contains("media ports of interface 'external'")),
            "{p:#?}"
        );
        // Another address, or a port past the last pair, does not clash.
        for listen in ["127.0.0.1:30010", "203.0.113.10:30100"] {
            Config::from_toml(&format!(
                "{MINIMAL}\n[control]\nlisten = [\"{listen}\"]\n[ports]\nmin = 30000\nmax = 30100\n[sessions]\nmax = 10\n"
            ))
            .unwrap();
        }
    }

    #[test]
    fn stun_servers_interface_names_and_devices() {
        for good in [
            "stun.example.net:3478",
            "192.0.2.1:3478",
            "[2001:db8::1]:3478",
        ] {
            assert!(is_host_port(good), "{good}");
        }
        for bad in [
            "stun",
            ":3478",
            "stun:0",
            "stun:65536",
            "2001:db8::1:3478",
            "[x]:3478",
            "a b:1",
        ] {
            assert!(!is_host_port(bad), "{bad}");
        }
        let p = problems(
            "[[interface]]\nname = \"pub lic\"\naddress = \"10.0.0.1\"\n\
             [xdp]\nenabled = true\ndevices = [\"eth0\", \"eth0\", \"\", \"a-very-long-name0\", \"../x\"]\n",
        );
        for needle in [
            "interface.name \"pub lic\"",
            "'eth0' appears more than once",
            "xdp.devices: \"\" is not",
            "xdp.devices: \"a-very-long-name0\" is not",
            "xdp.devices: \"../x\" is not",
        ] {
            assert!(p.iter().any(|x| x.contains(needle)), "{needle}: {p:#?}");
        }
    }

    #[test]
    fn s3_storage_needs_a_bucket_a_region_and_a_directory() {
        let p = problems(&format!(
            "{MINIMAL}\n[recording]\nstorage = \"s3\"\n[recording.s3]\nendpoint = \"ftp://x\"\n"
        ));
        for needle in ["s3.bucket", "s3.region", "s3.endpoint", "recording.dir"] {
            assert!(p.iter().any(|x| x.contains(needle)), "{needle}: {p:#?}");
        }
        let ok = format!(
            "{MINIMAL}\n[recording]\ndir = \"/tmp\"\nstorage = \"s3\"\n[recording.s3]\nbucket = \"b\"\nregion = \"r\"\n"
        );
        assert_eq!(Config::from_toml(&ok).is_ok(), cfg!(feature = "s3"));
    }
}
