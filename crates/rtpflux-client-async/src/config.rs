//! Where the relay is, and the client's limits.

use std::path::PathBuf;
use std::time::Duration;

/// How to reach the relay's native API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// Its Unix socket (`[control] native_socket`).
    Unix(PathBuf),
    /// Its TCP endpoint (`[control] native_listen`), authenticated with a
    /// tenant's token (`native_tokens`).
    Tcp { addr: String, token: String },
}

/// The client's configuration. Every queue is bounded; every wait has a
/// deadline.
#[derive(Debug, Clone)]
pub struct Config {
    pub transport: Transport,
    /// The tenant named in requests (over TCP the token decides it, and
    /// this is not sent).
    pub tenant: Option<String>,
    /// Request connections (requests are spread over them).
    pub connections: usize,
    /// Requests waiting to be written, per connection.
    pub queue_per_connection: usize,
    /// Requests written and not answered yet, per connection.
    pub in_flight_per_connection: usize,
    /// A request's deadline when it gives none.
    pub default_deadline: Duration,
    /// How long connecting (and authenticating) may take.
    pub connect_timeout: Duration,
    /// Reconnect backoff: first wait, and the longest.
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    /// Events queued for the consumer of an event stream; more are
    /// dropped and reported as a gap.
    pub event_queue: usize,
}

impl Config {
    /// A configuration with the defaults, for `transport`.
    #[must_use]
    pub fn new(transport: Transport) -> Self {
        Config {
            transport,
            tenant: None,
            connections: 4,
            queue_per_connection: 256,
            in_flight_per_connection: 64,
            default_deadline: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(3),
            backoff_min: Duration::from_millis(50),
            backoff_max: Duration::from_secs(5),
            event_queue: 4096,
        }
    }

    /// The Unix socket at `path`, with the defaults.
    #[must_use]
    pub fn unix(path: impl Into<PathBuf>) -> Self {
        Self::new(Transport::Unix(path.into()))
    }

    /// TCP to `addr` with `token`, with the defaults.
    #[must_use]
    pub fn tcp(addr: impl Into<String>, token: impl Into<String>) -> Self {
        Self::new(Transport::Tcp {
            addr: addr.into(),
            token: token.into(),
        })
    }
}
