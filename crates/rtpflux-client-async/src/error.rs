//! What can go wrong with a request, typed so a call controller can decide
//! what to do: retry (with the same idempotency key), reconcile, or give up.

/// The relay's error code (see `docs/native-api.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    NotFound,
    Conflict,
    Unsupported,
    Exhausted,
    Timeout,
    Unauthorized,
    Invalid,
    Internal,
    /// Durable storage failed (nothing done, unless the message says the
    /// operation was applied).
    Unavailable,
    /// The operation key's first attempt is older than the relay's ledger
    /// keeps: it was not run again.
    Expired,
    /// The operation began before a restart of the relay and its outcome
    /// was not recorded: reconcile before trying again with a new key.
    UnknownOutcome,
    /// Under the relay's `[ha]`: the request does not prove the current
    /// ownership epoch (and owner token) of what it touches. Nothing was
    /// done; claim the group again from the authority.
    Fenced,
    /// A code this client does not know.
    Other(String),
}

impl ErrorCode {
    /// The code named `s` on the wire.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "not_found" => ErrorCode::NotFound,
            "conflict" => ErrorCode::Conflict,
            "unsupported" => ErrorCode::Unsupported,
            "exhausted" => ErrorCode::Exhausted,
            "timeout" => ErrorCode::Timeout,
            "unauthorized" => ErrorCode::Unauthorized,
            "invalid" => ErrorCode::Invalid,
            "internal" => ErrorCode::Internal,
            "unavailable" => ErrorCode::Unavailable,
            "expired" => ErrorCode::Expired,
            "unknown_outcome" => ErrorCode::UnknownOutcome,
            "fenced" => ErrorCode::Fenced,
            other => ErrorCode::Other(other.to_owned()),
        }
    }
}

/// Why a request failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaError {
    /// The relay refused: nothing was done (unless the code is `timeout`
    /// from a worker's confirmation; see `docs/native-api.md`).
    Refused { code: ErrorCode, message: String },
    /// The deadline passed before the reply. If the request had been
    /// written, it may have taken effect: retry with the same idempotency
    /// key, or reconcile (`endpoint.query`, `endpoint.list`).
    Timeout { sent: bool },
    /// The connection was lost. If the request had been written
    /// (`sent`), it may have taken effect, as for [`MediaError::Timeout`].
    Disconnected { sent: bool },
    /// The client's bounded queues are full: nothing was sent.
    Overloaded,
    /// The relay answered something that is not the protocol.
    Protocol(String),
    /// The client is shut down.
    Closed,
}

impl MediaError {
    /// Whether the request may have taken effect although it failed: the
    /// caller should retry with the same idempotency key, or reconcile.
    #[must_use]
    pub fn outcome_unknown(&self) -> bool {
        matches!(
            self,
            MediaError::Timeout { sent: true } | MediaError::Disconnected { sent: true }
        )
    }

    /// The relay's error code, if it refused.
    #[must_use]
    pub fn code(&self) -> Option<&ErrorCode> {
        match self {
            MediaError::Refused { code, .. } => Some(code),
            _ => None,
        }
    }
}

impl std::fmt::Display for MediaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MediaError::Refused { code, message } => write!(f, "refused ({code:?}): {message}"),
            MediaError::Timeout { sent } => write!(f, "timed out (sent: {sent})"),
            MediaError::Disconnected { sent } => write!(f, "disconnected (sent: {sent})"),
            MediaError::Overloaded => f.write_str("the client's queues are full"),
            MediaError::Protocol(why) => write!(f, "protocol: {why}"),
            MediaError::Closed => f.write_str("the client is shut down"),
        }
    }
}

impl std::error::Error for MediaError {}
