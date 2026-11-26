//! Why an ng command failed. The text of each error ([`Display`](core::fmt::Display)) is the
//! reply's `error-reason`, unchanged from what rtpengine-style clients
//! have seen so far; the variants let code (and tests) tell the cases
//! apart without matching on text.

use crate::relay::RelayError;
use crate::subscription::Refusal;
use rtpflux_core::dtls::Setup;
use std::fmt;

/// A request that is malformed or asks for what cannot be done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    /// A command rtpflux does not know.
    UnknownCommand(String),
    /// An interface the configuration does not have.
    UnknownInterface(String),
    /// An `endpoint-learning` value not known.
    UnknownLearning(String),
    /// A `transport-protocol` not supported.
    UnsupportedTransport(String),
    /// An `ICE` value not supported.
    UnsupportedIce(String),
    /// An `ICE-lite` value not supported.
    UnsupportedIceLite(String),
    /// An option value rtpflux does not know (`DTLS`, `rtcp-mux`).
    UnsupportedOption(String),
    /// `SDES` options that leave no suite, or turn SDES off towards an
    /// answerer offered an SDES profile.
    Sdes(&'static str),
    /// `DTLS=off` towards an answerer offered a DTLS profile.
    DtlsOff,
    /// `codec: strip` left a media section (from 1) without a codec.
    NoCodecLeft(usize),
    /// A request too large to encode.
    TooLarge,
    /// A publish whose offer or answer cannot be made.
    BadPublish,
    /// `play media` without `file` or `blob`.
    PlayNeedsFile,
    /// A `file` that is not UTF-8.
    FileNotUtf8,
    /// `play media` without its listener.
    PlayNeedsListener,
    /// `start-pos` past the end of the media.
    StartPastEnd,
    /// The listener receives no G.711 audio to play into.
    NoG711,
    /// Keys asked for while an announcement plays to the listener.
    AnnouncementPlaying,
    /// Keys asked for to a listener without telephone events or G.711.
    NoKeyPath,
    /// A key that is not a number.
    NotANumber(String),
    /// A recording format not known.
    UnknownRecordingFormat(String),
    /// A `channels` value other than stereo or mono.
    BadChannels(String),
    /// Recording settings that cannot be used, with why.
    Recording(Vec<crate::recording::settings::Problem>),
    /// A DTMF `code` that is not a key or an event.
    BadCode,
    /// A subscription with no source named.
    NoSource,
    /// No party with that tag.
    UnknownTag(String),
    /// No party with that label.
    UnknownLabel(String),
    /// The call has no dialog between the parties named.
    UnknownDialogue,
    /// A subscription transport not supported.
    SubscribeTransport(String),
    /// The sources have no media.
    NothingToSubscribe,
    /// No SDP known from that party.
    NoSdpFrom(String),
    /// A new dialog beyond `sessions.max` (the limit).
    TooManySessions(usize),
    /// `metadata` of `start recording` that cannot be used, and why.
    BadMetadata(String),
    /// `recording-path`, `recording-file`, `output-destination` or
    /// `recording-pattern` that cannot be used: the option and why.
    BadRecordingName(&'static str, String),
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestError::UnknownCommand(c) => write!(f, "unknown command {c}"),
            RequestError::UnknownInterface(i) => write!(f, "unknown interface {i}"),
            RequestError::UnknownLearning(l) => write!(f, "unknown endpoint-learning {l}"),
            RequestError::UnsupportedTransport(p) => {
                write!(f, "unsupported transport-protocol {p}")
            }
            RequestError::UnsupportedIce(o) => write!(f, "unsupported ICE option {o}"),
            RequestError::UnsupportedIceLite(o) => write!(f, "unsupported ICE-lite option {o}"),
            RequestError::UnsupportedOption(o) => write!(f, "unsupported option {o}"),
            RequestError::Sdes(why) => write!(f, "SDES: {why}"),
            RequestError::DtlsOff => f.write_str(
                "DTLS=off: the answerer is offered a DTLS-SRTP profile (set transport-protocol)",
            ),
            RequestError::NoCodecLeft(i) => {
                write!(
                    f,
                    "codec strip: no codec left to offer in media section {i}"
                )
            }
            RequestError::TooLarge => f.write_str("request too large"),
            RequestError::BadPublish => f.write_str("publish: bad request"),
            RequestError::PlayNeedsFile => f.write_str("play media needs file or blob"),
            RequestError::FileNotUtf8 => f.write_str("file: not UTF-8"),
            RequestError::PlayNeedsListener => {
                f.write_str("play media needs from-tag (the listener)")
            }
            RequestError::StartPastEnd => f.write_str("start-pos is past the end of the media"),
            RequestError::NoG711 => f.write_str("the listener receives no G.711 audio"),
            RequestError::AnnouncementPlaying => {
                f.write_str("an announcement is playing to the listener")
            }
            RequestError::NoKeyPath => {
                f.write_str("the listener receives neither telephone events nor G.711 audio")
            }
            RequestError::NotANumber(k) => write!(f, "{k}: not a number"),
            RequestError::UnknownRecordingFormat(r) => write!(f, "unknown recording format {r}"),
            RequestError::BadChannels(c) => write!(f, "channels {c}: stereo or mono"),
            RequestError::Recording(p) => {
                for (i, x) in p.iter().enumerate() {
                    if i > 0 {
                        f.write_str("; ")?;
                    }
                    x.fmt(f)?;
                }
                Ok(())
            }
            RequestError::BadCode => f.write_str("code: keys 0-9 * # A-D, or an event 0-15"),
            RequestError::NoSource => f.write_str("no source: from-tag, from-tags or flag all"),
            RequestError::UnknownTag(t) => write!(f, "no party with tag {t}"),
            RequestError::UnknownLabel(l) => write!(f, "no party with label {l}"),
            RequestError::UnknownDialogue => f.write_str("Unknown dialogue"),
            RequestError::SubscribeTransport(t) => write!(
                f,
                "subscriptions are RTP, SRTP with SDES or DTLS-SRTP, not {t}"
            ),
            RequestError::NothingToSubscribe => {
                f.write_str("the sources have no media to subscribe to")
            }
            RequestError::NoSdpFrom(t) => write!(f, "no SDP known from {t}"),
            RequestError::BadMetadata(why) => write!(f, "metadata: {why}"),
            RequestError::BadRecordingName(option, why) => write!(f, "{option}: {why}"),
            RequestError::TooManySessions(max) => {
                write!(f, "session limit reached (sessions.max = {max})")
            }
        }
    }
}

impl std::error::Error for RequestError {}

/// An SDP body that does not parse, cannot be rewritten, or does not fit
/// the offer it answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdpError {
    /// The body does not read.
    Read(rtpflux_core::sdp::SdpError),
    /// The body cannot be rewritten.
    Rewrite(rtpflux_core::sdp::SdpError),
    /// An answer with another number of sections than its offer.
    SectionCount { answer: usize, offer: usize },
    /// A re-offer that changes what a bundled answerer took.
    BundledReoffer,
    /// `a=setup:holdconn`.
    Holdconn,
    /// DTLS-SRTP without a fingerprint the relay can check.
    NoFingerprint,
    /// An answer's `a=setup` that does not answer.
    SetupAnswer(Setup),
    /// An SDES key of the wrong length for its suite.
    KeyLength,
    /// SRTP offered without a usable `a=crypto`.
    NoCryptoOffered,
    /// An answer with SRTP to an offer without.
    SrtpNotOffered,
    /// SRTP answered without a usable `a=crypto`.
    NoCryptoAnswered,
    /// An answer section (1-based) whose formats were none of those
    /// offered.
    FormatsNotOffered { section: usize },
    /// A section (1-based) whose address is of another IP family than
    /// the interface that side uses: the relay could not reach it.
    Family {
        section: usize,
        interface: String,
        ipv6: bool,
    },
    /// A subscriber refusing a section (1-based) of what it was offered.
    Refused {
        section: usize,
        why: Refusal,
        kind: String,
    },
}

impl fmt::Display for SdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SdpError::Read(e) => write!(f, "SDP: {e}"),
            SdpError::Rewrite(e) => write!(f, "SDP rewrite: {e}"),
            SdpError::SectionCount { answer, offer } => {
                write!(
                    f,
                    "answer has {answer} media sections, the offer had {offer}"
                )
            }
            SdpError::BundledReoffer => f.write_str(
                "a re-offer to a bundled answerer must keep the media sections, \
                 their profiles, and stay unbundled",
            ),
            SdpError::Holdconn => f.write_str("a=setup:holdconn is not supported"),
            SdpError::NoFingerprint => f.write_str(
                "DTLS-SRTP without a usable a=fingerprint (sha-1 or sha-2, upper-case hex)",
            ),
            SdpError::SetupAnswer(s) => write!(f, "a=setup:{} is not a valid answer", s.name()),
            SdpError::KeyLength => f.write_str("key length"),
            SdpError::NoCryptoOffered => write!(
                f,
                "SRTP offered without a usable a=crypto line \
                 (supported: AES_CM_128/256_HMAC_SHA1_80/32, AEAD_AES_128/256_GCM; \
                 one key, no MKI)"
            ),
            SdpError::SrtpNotOffered => f.write_str("the answer uses SRTP but the offer did not"),
            SdpError::NoCryptoAnswered => write!(
                f,
                "SRTP answered without a usable a=crypto line \
             (supported: AES_CM_128/256_HMAC_SHA1_80/32, AEAD_AES_128/256_GCM; \
             one key, no MKI)"
            ),
            SdpError::FormatsNotOffered { section } => write!(
                f,
                "answer section {section}: none of its formats was offered (RFC 3264 §6.1)"
            ),
            SdpError::Family {
                section,
                interface,
                ipv6,
            } => write!(
                f,
                "section {section}: an {} address, but interface {interface} has no {} address",
                if *ipv6 { "IPv6" } else { "IPv4" },
                if *ipv6 { "IPv6" } else { "IPv4" },
            ),
            SdpError::Refused { section, why, kind } => match why {
                Refusal::Dtls => {
                    write!(
                        f,
                        "the subscriber does not take DTLS-SRTP in section {section}"
                    )
                }
                Refusal::Srtp => {
                    write!(f, "the subscriber does not take SRTP in section {section}")
                }
                Refusal::Formats => write!(
                    f,
                    "the subscriber accepts none of the {kind} formats of section {section}"
                ),
            },
        }
    }
}

impl std::error::Error for SdpError {}

/// Why a saved call or subscription cannot be restored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    /// A saved call that does not read.
    UnreadableEntry,
    /// A saved subscription that does not read.
    UnreadableSubscription,
    /// It names an interface the configuration no longer has.
    GoneInterface,
    /// A subscription whose call was not restored.
    CallGone,
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            StateError::UnreadableEntry => "unreadable entry",
            StateError::UnreadableSubscription => "unreadable subscription",
            StateError::GoneInterface => "an interface the configuration no longer has",
            StateError::CallGone => "its call is gone",
        })
    }
}

/// A failed ng command.
#[derive(Debug)]
pub enum Error {
    /// No call with that call-id (and from-tag).
    UnknownCall,
    /// The call exists, but not with that tag.
    UnknownCallOrTag,
    /// An answer for a call that was never offered.
    NoOffer,
    /// A key the command needs is not in the request.
    Missing(String),
    /// The request is malformed or asks for what cannot be done: an
    /// unknown command, interface, option value or recording format, or a
    /// feature missing what it needs. The text says which.
    Request(RequestError),
    /// The SDP body does not parse, cannot be rewritten, or does not fit
    /// the offer it answers.
    Sdp(SdpError),
    /// A feature the configuration does not enable.
    NotConfigured(&'static str),
    /// A file or the system's random source could not be read: which,
    /// and why.
    Io {
        path: String,
        source: std::io::Error,
    },
    /// A media file that cannot be played.
    Media(crate::media_file::MediaError),
    /// A saved call that cannot be restored.
    State(StateError),
    /// The relay refused (no free ports, an unknown interface, …).
    Relay(RelayError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnknownCall => f.write_str("unknown call"),
            Error::UnknownCallOrTag => f.write_str("unknown call or tag"),
            Error::NoOffer => f.write_str("unknown call (no offer)"),
            Error::Missing(key) => write!(f, "missing {key}"),
            Error::Request(e) => e.fmt(f),
            Error::Sdp(e) => e.fmt(f),
            Error::State(e) => e.fmt(f),
            Error::Io { path, source } => write!(f, "{path}: {source}"),
            Error::Media(e) => e.fmt(f),
            Error::NotConfigured(what) => f.write_str(what),
            Error::Relay(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Relay(e) => Some(e),
            Error::Io { source, .. } => Some(source),
            Error::Media(e) => Some(e),
            _ => None,
        }
    }
}

impl From<crate::media_file::MediaError> for Error {
    fn from(e: crate::media_file::MediaError) -> Self {
        Error::Media(e)
    }
}

impl Error {
    /// A request asking for something the relay does not do, or not so:
    /// `what` says what.
    pub(crate) fn unsupported(what: impl Into<String>) -> Error {
        Error::Request(RequestError::UnsupportedOption(what.into()))
    }

    /// `path` could not be read.
    pub(crate) fn io(path: &str) -> impl FnOnce(std::io::Error) -> Error + '_ {
        move |source| Error::Io {
            path: path.to_owned(),
            source,
        }
    }
}

impl From<RequestError> for Error {
    fn from(e: RequestError) -> Self {
        Error::Request(e)
    }
}

impl From<SdpError> for Error {
    fn from(e: SdpError) -> Self {
        Error::Sdp(e)
    }
}

impl From<RelayError> for Error {
    fn from(e: RelayError) -> Self {
        Error::Relay(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `error-reason` texts clients see do not change with the types.
    #[test]
    fn the_wire_text_is_kept() {
        let cases = [
            (Error::UnknownCall, "unknown call"),
            (Error::UnknownCallOrTag, "unknown call or tag"),
            (Error::NoOffer, "unknown call (no offer)"),
            (Error::Missing("call-id".to_owned()), "missing call-id"),
            (
                Error::Request(RequestError::UnknownCommand("x".to_owned())),
                "unknown command x",
            ),
            (Error::Sdp(SdpError::KeyLength), "key length"),
            (
                Error::NotConfigured("recording is not configured ([recording] dir)"),
                "recording is not configured ([recording] dir)",
            ),
            (
                Error::Io {
                    path: "/dev/urandom".to_owned(),
                    source: std::io::Error::other("gone"),
                },
                "/dev/urandom: gone",
            ),
            (
                Error::State(StateError::UnreadableEntry),
                "unreadable entry",
            ),
        ];
        for (e, text) in cases {
            assert_eq!(e.to_string(), text);
        }
        let relay = RelayError::PortsExhausted;
        let text = relay.to_string();
        assert_eq!(Error::from(relay).to_string(), text);
    }
}
