//! The options of `offer` and `answer`: endpoint learning, ICE, the
//! transport protocol and the `codec` options.

#[allow(clippy::wildcard_imports)]
use super::*;

/// How an ICE offer passed through (`ICE=force-relay`, `optional`) treats
/// the endpoints' own relay candidates; the relay is a relay candidate
/// either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Passthrough {
    /// `optional`: kept.
    KeepRelays,
    /// `force-relay`: dropped (the relay is the only relay).
    DropRelays,
}

/// `ICE`: whether the relay is an ICE agent towards each side, or passes
/// the endpoints' own ICE through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum IcePolicy {
    /// Towards both sides when the offerer uses ICE.
    Default,
    /// Never: ICE attributes are removed.
    Remove,
    /// Towards both sides.
    Force,
    /// `force-relay`: the endpoints' ICE passed through (their own relay
    /// candidates dropped), the relay a relay candidate; `force` for an
    /// offer without ICE.
    ForceRelay,
    /// `optional`: the same, keeping all the endpoints' candidates.
    Optional,
}

/// `ICE-lite`: towards which side the relay is a lite agent rather than a
/// full one (rtpengine's values): `forward` towards the recipient of the
/// offer, `backward` towards its sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum IceLite {
    Off,
    Forward,
    Backward,
    Both,
}

/// The SRTP suites, in the order the relay prefers them when it picks one.
pub(super) const SUITES: [Suite; 6] = [
    Suite::AesCm128HmacSha1_80,
    Suite::AesCm128HmacSha1_32,
    Suite::AeadAes128Gcm,
    Suite::AeadAes256Gcm,
    Suite::AesCm256HmacSha1_80,
    Suite::AesCm256HmacSha1_32,
];

/// `SDES` (or `SDES-<value>` flags): `off`, and the suites the relay may
/// offer the answerer (`no-<suite>`, `only-<suite>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Independent SDES switches.
pub(super) struct SdesOpts {
    pub(super) off: bool,
    /// `unencrypted_srtp`, `unencrypted_srtcp`, `unauthenticated_srtp`:
    /// the protection the relay's keys towards the answerer leave out (and
    /// lines declaring it are accepted).
    pub(super) policy: rtpflux_srtp::Policy,
    /// Allowed suites, a bit per entry of [`SUITES`].
    allowed: u8,
    /// `lifetime`: the relay's keys carry `|2^31`.
    pub(super) lifetime: bool,
    /// `static`: an answer to a re-offer keeps the keys agreed.
    pub(super) static_keys: bool,
    /// `nonew`: only suites the offerer offered are offered.
    pub(super) nonew: bool,
    /// `prefer`: SDES over DTLS when an offer carries both.
    pub(super) prefer: bool,
    /// `order:<suites>`: the order suites are offered in; `offerer_pref:
    /// <suites>`: which of the offerer's is taken (positions in
    /// [`SUITES`], first first).
    order: Option<[Option<Suite>; 6]>,
    offerer_pref: Option<[Option<Suite>; 6]>,
    /// `key-<suite>:<key>`: the proxy's own key for a suite.
    pub(super) keys: [Option<rtpflux_srtp::MasterKey>; 6],
}

impl Default for SdesOpts {
    fn default() -> Self {
        SdesOpts {
            off: false,
            policy: rtpflux_srtp::Policy::NONE,
            allowed: 0x3f,
            lifetime: false,
            static_keys: false,
            nonew: false,
            prefer: false,
            order: None,
            offerer_pref: None,
            keys: [None; 6],
        }
    }
}

impl SdesOpts {
    fn bit(suite: Suite) -> u8 {
        SUITES
            .iter()
            .position(|&s| s == suite)
            .map_or(0, |i| 1 << i)
    }

    /// Whether `suite` may be used.
    pub(super) fn allows(self, suite: Suite) -> bool {
        self.allowed & Self::bit(suite) != 0
    }

    /// Whether the options restrict the suites.
    pub(super) fn restricts(self) -> bool {
        self.allowed != 0x3f
    }

    /// The suite the relay offers the answerer first: the first allowed of
    /// `order:` when given, else `preferred` (the offerer's) when allowed,
    /// else the first allowed one.
    pub(super) fn pick(self, preferred: Suite) -> Option<Suite> {
        if self.order.is_some()
            && let Some(s) = self.offer_order().next()
        {
            return Some(s);
        }
        if self.allowed & Self::bit(preferred) != 0 {
            return Some(preferred);
        }
        self.offer_order().next()
    }

    /// The allowed suites in the order they are offered (`order:` first).
    pub(super) fn offer_order(self) -> impl Iterator<Item = Suite> {
        let listed = self.order.unwrap_or([None; 6]);
        listed
            .into_iter()
            .flatten()
            .chain(SUITES)
            .enumerate()
            .filter_map(move |(i, s)| {
                // Each suite once, at its first place.
                let first = listed
                    .iter()
                    .flatten()
                    .chain(SUITES.iter())
                    .position(|&x| x == s)
                    == Some(i);
                (first && self.allowed & Self::bit(s) != 0).then_some(s)
            })
    }

    /// The rank of one of the offerer's suites (`offerer_pref:`; lower
    /// first); suites it does not list come after, in the offer's order.
    pub(super) fn offerer_rank(self, suite: Suite) -> usize {
        self.offerer_pref
            .and_then(|p| p.iter().flatten().position(|&s| s == suite))
            .unwrap_or(usize::MAX)
    }

    /// Whether `offerer_pref:` was given.
    pub(super) fn ranks_offerer(self) -> bool {
        self.offerer_pref.is_some()
    }

    /// The proxy's key for `suite` (`key-<suite>:<key>`), if any.
    pub(super) fn key_for(self, suite: Suite) -> Option<rtpflux_srtp::MasterKey> {
        self.keys
            .iter()
            .flatten()
            .find(|k| k.suite == suite)
            .copied()
    }
}

/// `DTLS`: `off` (never DTLS-SRTP), or the relay's role in the SDP it
/// writes: `passive` (it waits for the handshake) or `active` (it starts
/// it). Without it the relay offers `actpass` and answers as the offerer
/// leaves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DtlsOpt {
    Off,
    Passive,
    Active,
}

/// `rtcp-mux` (or `rtcp-mux-<value>` flags), RFC 5761: what the relay
/// offers the answerer and accepts from the offerer. Without it, RTCP is
/// multiplexed on both sides when the offerer offers it and the answerer
/// accepts it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum MuxPolicy {
    #[default]
    Default,
    /// `offer`: offer it to the answerer even when the offerer did not.
    Offer,
    /// `require`: as `offer`, and the answerer is taken to have accepted
    /// it (no separate RTCP port is advertised, for WebRTC clients).
    Require,
    /// `demux`: accept it from the offerer, do not offer it to the
    /// answerer (the relay splits RTCP).
    Demux,
    /// `accept`: accept it from the offerer whatever the answerer does.
    Accept,
    /// `reject`: neither accept it from the offerer nor offer it.
    Reject,
}

/// Request options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub(super) struct Opts {
    pub(super) trust_address: bool,
    pub(super) strict_source: bool,
    /// `media-handover`: a new source can take a learned address over.
    pub(super) media_handover: bool,
    /// `unidirectional`: offload media that flows one way.
    pub(super) unidirectional: bool,
    /// `OSRTP`: `offer` (a plain offer becomes an OSRTP one to the
    /// answerer), `accept` (an OSRTP offer is taken even when the answer
    /// is plain); `offer-legacy`, `accept-legacy`: the same in the legacy
    /// form (each stream offered twice).
    pub(super) osrtp: (bool, bool),
    pub(super) osrtp_legacy: (bool, bool),
    pub(super) replace_origin: bool,
    pub(super) learning: Learning,
    pub(super) received_from: Option<IpAddr>,
    /// `transport-protocol`: the profile offered to the answerer.
    pub(super) transport: Option<Transport>,
    pub(super) ice: IcePolicy,
    /// `ICE-lite` (none: the configured mode).
    pub(super) ice_lite: Option<IceLite>,
    /// `always transcode`: keep the offerer's telephone events and convert
    /// when the answerer refuses them.
    pub(super) always_transcode: bool,
    pub(super) codecs: CodecOpts,
    pub(super) sdes: SdesOpts,
    pub(super) dtls: Option<DtlsOpt>,
    /// ICE passed through (`force-relay`, `optional` with an ICE offer).
    pub(super) ice_passthrough: Option<Passthrough>,
    /// `DTLS-reverse`: the relay's role towards DTLS offered to it
    /// (`passive`, the default, or `active`).
    pub(super) dtls_reverse: Option<DtlsOpt>,
    /// `track-state`: a re-offer of an answered dialog keeps its agreed
    /// state until the answer, for `rollback`.
    pub(super) track_state: bool,
    /// `DTLS-fingerprint`: the hash of the relay's fingerprint (else the
    /// peer's, else SHA-256).
    pub(super) dtls_hash: Option<rtpflux_core::dtls::HashFn>,
    pub(super) rtcp_mux: MuxPolicy,
    /// `ptime`, `ptime-reverse`: the packet time (ms) of the answerer's
    /// and of the offerer's leg; the relay repacketises to it.
    pub(super) ptime: Option<u16>,
    pub(super) ptime_reverse: Option<u16>,
    /// `address-family`: the answerer's side is IPv6 (`IP6`) or IPv4.
    pub(super) address_family: Option<bool>,
    /// `media echo`: (towards the receiver of this message, towards its
    /// sender) what becomes of their media.
    pub(super) media_echo: Option<[crate::relay::Echo; 2]>,
    /// `media-address`: the address written into the SDP returned.
    pub(super) media_address: Option<IpAddr>,
}

/// A packet time option: whole milliseconds (an integer or a string), a
/// multiple of 10 from 10 to 200.
fn ptime_opt(d: &Dict<'_>, key: &str) -> Result<Option<u16>, Error> {
    if d.get(key.as_bytes()).is_none() {
        return Ok(None);
    }
    let v = super::args::number_or_none(d, key.as_bytes()).and_then(|n| u16::try_from(n).ok());
    match v.filter(|&ms| crate::relay::repack::Repacker::new(ms).is_some()) {
        Some(ms) => Ok(Some(ms)),
        None => Err(Error::unsupported(format!(
            "{key}: whole milliseconds, a multiple of 10 from {} to {}",
            crate::relay::repack::MIN_MS,
            crate::relay::repack::MAX_MS
        ))),
    }
}

/// The values of option `key` (a list or a string of words) and of the
/// flags `<key>-<value>`.
fn values<'a>(d: &Dict<'a>, key: &[u8]) -> Vec<&'a [u8]> {
    let mut out = words(d.get(key));
    for f in words(d.get(b"flags")) {
        if let Some(v) = f
            .strip_prefix(key)
            .and_then(|r| r.strip_prefix(b"-"))
            .filter(|v| !v.is_empty())
        {
            out.push(v);
        }
    }
    out
}

/// `SDES`: the values it acts on; the others are reported by
/// [`unknown_options`].
fn sdes_opts(d: &Dict<'_>) -> SdesOpts {
    let mut o = SdesOpts::default();
    let mut only = 0u8;
    for v in values(d, b"SDES") {
        if v == b"off" {
            o.off = true;
        } else if let Some(s) = v.strip_prefix(b"no-").and_then(Suite::from_name) {
            o.allowed &= !SdesOpts::bit(s);
        } else if let Some(s) = v.strip_prefix(b"only-").and_then(Suite::from_name) {
            only |= SdesOpts::bit(s);
        } else if let Some(p) = o.policy.with_param(&v.to_ascii_uppercase()) {
            o.policy = p;
        } else {
            sdes_value(&mut o, v);
        }
    }
    if only != 0 {
        o.allowed &= only;
    }
    // Such keys are counter-mode ones: AEAD suites always protect fully.
    if !o.policy.is_none() {
        for s in [Suite::AeadAes128Gcm, Suite::AeadAes256Gcm] {
            o.allowed &= !SdesOpts::bit(s);
        }
    }
    o
}

/// The other `SDES` values: their effect on `o`; whether known.
fn sdes_value(o: &mut SdesOpts, v: &[u8]) -> bool {
    let suites = |list: &[u8]| {
        let mut out = [None; 6];
        for (slot, s) in out
            .iter_mut()
            .zip(list.split(|&c| c == b',').filter_map(Suite::from_name))
        {
            *slot = Some(s);
        }
        out
    };
    match v {
        b"lifetime" => o.lifetime = true,
        // Keys are always written with base64's padding.
        b"pad" => {}
        b"static" => o.static_keys = true,
        b"nonew" => o.nonew = true,
        b"prefer" => o.prefer = true,
        b"encrypted_srtp" => o.policy.unencrypted_srtp = false,
        b"encrypted_srtcp" => o.policy.unencrypted_srtcp = false,
        b"authenticated_srtp" => o.policy.unauthenticated_srtp = false,
        _ => {
            if let Some(list) = v.strip_prefix(b"order:") {
                o.order = Some(suites(list));
            } else if let Some(list) = v.strip_prefix(b"offerer_pref:") {
                o.offerer_pref = Some(suites(list));
            } else if let Some((suite, key)) = v.strip_prefix(b"key-").and_then(|r| {
                let at = r.iter().position(|&c| c == b':')?;
                Some((Suite::from_name(&r[..at])?, &r[at + 1..]))
            }) && let Some(k) = rtpflux_core::sdp::decode_key(suite, key)
                && let Some(slot) = o.keys.iter_mut().find(|k| k.is_none())
            {
                *slot = Some(k);
            } else {
                return false;
            }
        }
    }
    true
}

/// Whether an `SDES` value is one rtpflux acts on.
fn sdes_known(v: &[u8]) -> bool {
    if sdes_value(&mut SdesOpts::default(), v) {
        return true;
    }
    v == b"off"
        || rtpflux_srtp::Policy::NONE
            .with_param(&v.to_ascii_uppercase())
            .is_some()
        || v.strip_prefix(b"no-")
            .or_else(|| v.strip_prefix(b"only-"))
            .and_then(Suite::from_name)
            .is_some()
}

fn dtls_opt(d: &Dict<'_>) -> Result<Option<DtlsOpt>, Error> {
    Ok(match d.get_bytes(b"DTLS") {
        None => None,
        Some(b"off" | b"no" | b"disable") => Some(DtlsOpt::Off),
        Some(b"passive") => Some(DtlsOpt::Passive),
        Some(b"active") => Some(DtlsOpt::Active),
        Some(other) => {
            return Err(Error::unsupported(format!(
                "DTLS {}",
                String::from_utf8_lossy(other)
            )));
        }
    })
}

fn mux_policy(d: &Dict<'_>) -> Result<MuxPolicy, Error> {
    let mut policy = MuxPolicy::Default;
    for v in values(d, b"rtcp-mux") {
        let p = match v {
            b"offer" => MuxPolicy::Offer,
            b"require" => MuxPolicy::Require,
            b"demux" => MuxPolicy::Demux,
            b"accept" => MuxPolicy::Accept,
            b"reject" => MuxPolicy::Reject,
            other => {
                return Err(Error::unsupported(format!(
                    "rtcp-mux {}",
                    String::from_utf8_lossy(other)
                )));
            }
        };
        if policy != MuxPolicy::Default && policy != p {
            return Err(Error::unsupported(
                "rtcp-mux: conflicting values".to_owned(),
            ));
        }
        policy = p;
    }
    Ok(policy)
}

/// `codec: {transcode: [...], mask: [...]}` or the flags
/// `codec-transcode-<name>` / `codec-mask-<name>`. Only PCMU, PCMA and
/// opus can be transcoded; other names are ignored.
pub(super) fn codec_opts(d: &Dict<'_>) -> CodecOpts {
    let mut o = CodecOpts::default();
    for (key, spec) in codec_names(d) {
        let s = Spec::of(spec);
        if key == b"transcode" && s.name.eq_ignore_ascii_case(b"telephone-event") {
            o.telephone_event = true;
            continue;
        }
        let Some(codec) = Codec::from_name(s.name) else {
            continue;
        };
        match key {
            b"transcode" => o.transcode = o.transcode.or(Some(codec)),
            b"mask" | b"consume" => {
                if let Some(slot) = o.mask.iter_mut().find(|m| m.is_none()) {
                    *slot = Some(codec);
                }
            }
            b"accept" => o.accept = o.accept.or(Some(codec)),
            b"ignore" => {
                if let Some(slot) = o.ignore.iter_mut().find(|m| m.is_none()) {
                    *slot = Some(codec);
                }
            }
            _ => {}
        }
        if key == b"transcode" || key == b"set" {
            match codec {
                Codec::Opus => o.opus_bitrate = s.opus_bitrate().or(o.opus_bitrate),
                Codec::Amr => o.amr_bitrate = s.amr_bitrate(codec).or(o.amr_bitrate),
                Codec::AmrWb => o.amr_wb_bitrate = s.amr_bitrate(codec).or(o.amr_wb_bitrate),
                _ => {}
            }
        }
    }
    o
}

/// The Opus bitrates the relay's encoder takes (bit/s, RFC 7587 §3.1.1).
const OPUS_BITRATES: core::ops::RangeInclusive<u32> = 6_000..=510_000;

/// A codec as `codec` options write it: `name[/clock[/channels[/param]]]`
/// (rtpengine's), the fourth field Opus's bitrate.
struct Spec<'a> {
    name: &'a [u8],
    param: Option<&'a [u8]>,
}

impl<'a> Spec<'a> {
    fn of(spec: &'a [u8]) -> Self {
        let mut f = spec.split(|&c| c == b'/');
        Spec {
            name: f.next().unwrap_or_default(),
            param: f.nth(2),
        }
    }

    /// The bitrate it gives an AMR `codec`, if one of its modes'.
    fn amr_bitrate(&self, codec: Codec) -> Option<u32> {
        let bps = std::str::from_utf8(self.param?).ok()?.parse().ok()?;
        codec.amr_mode_of(bps).map(|_| bps)
    }

    /// The bitrate it gives Opus, if any and in range.
    fn opus_bitrate(&self) -> Option<u32> {
        std::str::from_utf8(self.param?)
            .ok()?
            .parse()
            .ok()
            .filter(|b| OPUS_BITRATES.contains(b))
    }
}

/// What the reply's `warning` says of the `codec` options: the names the
/// relay does not know (ignored, as rtpengine ignores them), and
/// parameters it cannot apply (only Opus's bitrate is set).
pub(super) fn codec_warnings(d: &Dict<'_>) -> Vec<String> {
    let mut out = Vec::new();
    for (key, spec) in codec_names(d) {
        if !matches!(key, b"transcode" | b"mask" | b"set" | b"accept") {
            continue;
        }
        let s = Spec::of(spec);
        let text = |why: &str| {
            format!(
                "codec {} {}: {why}",
                String::from_utf8_lossy(key),
                String::from_utf8_lossy(spec)
            )
        };
        if key == b"transcode" && s.name.eq_ignore_ascii_case(b"telephone-event") {
            continue;
        }
        match Codec::from_name(s.name) {
            None => out.push(text("unknown, ignored")),
            Some(Codec::Opus) if key != b"mask" && s.param.is_some() => {
                if s.opus_bitrate().is_none() {
                    out.push(text(&format!(
                        "an Opus bitrate is {} to {} bit/s, ignored",
                        OPUS_BITRATES.start(),
                        OPUS_BITRATES.end()
                    )));
                }
            }
            Some(c @ (Codec::Amr | Codec::AmrWb)) if key != b"mask" && s.param.is_some() => {
                if s.amr_bitrate(c).is_none() {
                    out.push(text("not one of the codec's mode bitrates, ignored"));
                }
            }
            Some(_) if key == b"set" || (key == b"transcode" && s.param.is_some()) => {
                out.push(text(
                    "only Opus's bitrate and AMR's mode can be set, ignored",
                ));
            }
            Some(_) => {}
        }
    }
    out
}

/// Keys of `offer` and `answer` that identify the call or the message, or
/// that rtpflux acts on (some only in one of the two, or with recording).
const KNOWN_KEYS: &[&[u8]] = &[
    b"command",
    b"call-id",
    b"from-tag",
    b"to-tag",
    b"via-branch",
    b"label",
    b"set-label",
    b"DTMF-delay",
    b"sdp",
    b"flags",
    b"received-from",
    b"supports",
    b"sip-message-type",
    b"direction",
    b"endpoint-learning",
    b"replace",
    b"transport-protocol",
    b"ICE",
    b"ICE-lite",
    b"codec",
    b"record-call",
    b"record call",
    b"metadata",
    b"SDES",
    b"DTLS",
    b"rtcp-mux",
    b"OSRTP",
    b"DTLS-fingerprint",
    b"DTLS-reverse",
    b"ptime",
    b"ptime-reverse",
    b"address-family",
    b"media-address",
    b"sdp-attr",
    b"media echo",
    b"media-echo",
    b"recording-path",
    b"recording-file",
    b"recording-pattern",
    b"output-destination",
];

/// Flags of `offer` and `answer` that rtpflux acts on, or that ask for
/// what it always does (`symmetric`: media goes back where it comes from).
const KNOWN_FLAGS: &[&[u8]] = &[
    b"track-state",
    b"trust-address",
    b"strict-source",
    b"fragment",
    b"always transcode",
    b"always-transcode",
    b"symmetric",
    b"asymmetric",
    b"port-latching",
    b"port latching",
    b"loop-protect",
    b"loop protect",
    b"media-handover",
    b"unidirectional",
    b"strip-extmap",
    b"generate-mid",
    b"no-rtcp-attribute",
    b"full-rtcp-attribute",
    b"force-increment-sdp-version",
];

/// Flag prefixes rtpflux reads (the rest of the flag is a value).
const KNOWN_FLAG_PREFIXES: &[&[u8]] = &[
    b"codec-transcode-",
    b"codec-mask-",
    b"codec-strip-",
    b"codec-except-",
    b"codec-offer-",
    b"codec-set-",
    b"codec-accept-",
    b"codec-consume-",
    b"codec-ignore-",
    b"rtcp-mux-",
];

/// `replace` items (also as `replace-<item>` flags): `session-connection`
/// and `zero-address` are always done (every `c=` is the relay's).
const KNOWN_REPLACE: &[&[u8]] = &[
    b"origin",
    b"session-connection",
    b"zero-address",
    b"username",
    b"session-name",
    b"sdp-version",
    b"force-increment-sdp-version",
    b"origin-full",
];

/// `codec` keys rtpflux reads.
const KNOWN_CODEC_KEYS: &[&[u8]] = &[
    b"transcode",
    b"mask",
    b"strip",
    b"except",
    b"offer",
    b"set",
    b"accept",
    b"consume",
    b"ignore",
];

/// What the reply's `warning` says of an `offer` or `answer`'s options:
/// each key, flag, `replace` item and `codec` key that rtpflux does not
/// act on (rtpengine options it does not implement), so that a proxy
/// configured for rtpengine learns which of its options had no effect.
pub(super) fn unknown_options(d: &Dict<'_>) -> Vec<String> {
    let mut out = Vec::new();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    for (key, _) in d {
        if !KNOWN_KEYS.contains(&key) {
            out.push(format!("option {}: not supported, ignored", text(key)));
        }
    }
    for f in words(d.get(b"flags")) {
        let known = KNOWN_FLAGS.contains(&f)
            || f.strip_prefix(b"OSRTP-").is_some_and(|v| !v.is_empty())
            || f.strip_prefix(b"replace-")
                .is_some_and(|r| KNOWN_REPLACE.contains(&r))
            || f.strip_prefix(b"SDES-").is_some_and(|v| !v.is_empty())
            || KNOWN_FLAG_PREFIXES
                .iter()
                .any(|p| f.len() > p.len() && f.starts_with(p));
        if !known {
            out.push(format!("flag {}: not supported, ignored", text(f)));
        }
    }
    for v in values(d, b"OSRTP") {
        if !matches!(
            v,
            b"offer"
                | b"offer-RFC"
                | b"offer-legacy"
                | b"accept"
                | b"accept-RFC"
                | b"accept-legacy"
        ) {
            out.push(format!("OSRTP {}: not supported, ignored", text(v)));
        }
    }
    for v in values(d, b"SDES") {
        if !sdes_known(v) {
            out.push(format!("SDES {}: not supported, ignored", text(v)));
        }
    }
    for r in words(d.get(b"replace")) {
        if !KNOWN_REPLACE.contains(&r) {
            out.push(format!("replace {}: not supported, ignored", text(r)));
        }
    }
    if let Some(Value::Dict(c)) = d.get(b"codec") {
        for (key, _) in &c {
            if !KNOWN_CODEC_KEYS.contains(&key) {
                out.push(format!("codec {}: not supported, ignored", text(key)));
            }
        }
    }
    out
}

/// The strings of a list, or the space-separated words of a string (as
/// [`list_contains`] reads them).
pub(super) fn words(v: Option<Value<'_>>) -> Vec<&[u8]> {
    match v {
        Some(Value::Bytes(b)) => b.split(|&c| c == b' ').filter(|w| !w.is_empty()).collect(),
        v => super::args::strings(v),
    }
}

/// The `codec` options that choose the offerer's formats the answerer is
/// offered: the names of `strip`, `except` and `offer` (dictionary keys or
/// `codec-strip-<name>`, … flags), in order.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct CodecNames<'a> {
    pub(super) strip: Vec<&'a [u8]>,
    pub(super) except: Vec<&'a [u8]>,
    pub(super) offer: Vec<&'a [u8]>,
}

impl<'a> CodecNames<'a> {
    pub(super) fn of(d: &Dict<'a>) -> Self {
        let mut n = CodecNames::default();
        let mut transcode = Vec::new();
        for (key, name) in codec_names(d) {
            match key {
                // `consume` and `ignore` keep the codec from B too.
                b"strip" | b"consume" | b"ignore" => n.strip.push(name),
                b"except" => n.except.push(name),
                b"offer" => n.offer.push(name),
                b"transcode" => transcode.push(name),
                _ => {}
            }
        }
        // A codec to transcode to that the offerer already has is kept,
        // whatever is stripped (it is offered either way).
        if !n.strip.is_empty() {
            n.except.extend(transcode);
        }
        n
    }

    pub(super) fn filter(&self) -> rtpflux_core::sdp::FormatFilter<'_> {
        rtpflux_core::sdp::FormatFilter {
            strip: &self.strip,
            except: &self.except,
            offer: &self.offer,
        }
    }
}

/// The `codec` keys holding codec names, and their flag forms.
const CODEC_KEYS: [(&[u8], &[u8]); 9] = [
    (b"transcode", b"codec-transcode-"),
    (b"mask", b"codec-mask-"),
    (b"strip", b"codec-strip-"),
    (b"except", b"codec-except-"),
    (b"offer", b"codec-offer-"),
    (b"set", b"codec-set-"),
    (b"accept", b"codec-accept-"),
    (b"consume", b"codec-consume-"),
    (b"ignore", b"codec-ignore-"),
];

/// The codec names of `codec: {transcode, mask, strip, except, offer}` and
/// of the `codec-<key>-<name>` flags, with their key.
fn codec_names<'a>(d: &Dict<'a>) -> Vec<(&'static [u8], &'a [u8])> {
    let mut names: Vec<(&'static [u8], &'a [u8])> = Vec::new();
    if let Some(Value::Dict(c)) = d.get(b"codec") {
        for (key, _) in CODEC_KEYS {
            match c.get(key) {
                Some(Value::List(l)) => names.extend(l.iter().filter_map(|v| match v {
                    Value::Bytes(b) => Some((key, b)),
                    _ => None,
                })),
                Some(Value::Bytes(b)) => names.push((key, b)),
                _ => {}
            }
        }
    }
    if let Some(Value::List(flags)) = d.get(b"flags") {
        for f in &flags {
            if let Value::Bytes(f) = f
                && let Some((key, n)) = CODEC_KEYS.iter().find_map(|&(key, prefix)| {
                    Some((key, f.strip_prefix(prefix).filter(|n| !n.is_empty())?))
                })
            {
                names.push((key, n));
            }
        }
    }
    names
}

/// `DTLS-reverse`: the relay's role towards DTLS offered to it.
fn dtls_reverse(d: &Dict<'_>) -> Result<Option<DtlsOpt>, Error> {
    Ok(match d.get_bytes(b"DTLS-reverse") {
        None => None,
        Some(b"passive") => Some(DtlsOpt::Passive),
        Some(b"active") => Some(DtlsOpt::Active),
        Some(other) => {
            return Err(Error::unsupported(format!(
                "DTLS-reverse {}",
                String::from_utf8_lossy(other)
            )));
        }
    })
}

/// `OSRTP` in its legacy form: (`offer-legacy`, `accept-legacy` or
/// `accept`).
pub(super) fn legacy_flags(d: &Dict<'_>) -> (bool, bool) {
    let v = values(d, b"OSRTP");
    (
        v.contains(&&b"offer-legacy"[..]),
        v.contains(&&b"accept-legacy"[..]),
    )
}

/// `OSRTP`: (`offer`, `accept`).
fn osrtp(d: &Dict<'_>) -> (bool, bool) {
    let v = values(d, b"OSRTP");
    (
        v.iter()
            .any(|v| matches!(*v, b"offer" | b"offer-RFC" | b"offer-legacy")),
        v.iter()
            .any(|v| matches!(*v, b"accept" | b"accept-RFC" | b"accept-legacy")),
    )
}

/// `media echo` (or `media-echo`): what becomes of the media of the
/// receiver of this message and of its sender (rtpengine's values).
fn media_echo(d: &Dict<'_>) -> Result<Option<[crate::relay::Echo; 2]>, Error> {
    use crate::relay::Echo::{Discard, Echo, Normal};
    let Some(v) = d
        .get_bytes(b"media echo")
        .or_else(|| d.get_bytes(b"media-echo"))
    else {
        return Ok(None);
    };
    Ok(Some(match v {
        b"blackhole" | b"sinkhole" => [Discard, Discard],
        // The receiver hears itself; the sender's media is dropped.
        b"forward" => [Echo, Discard],
        b"backwards" => [Discard, Echo],
        b"both" => [Echo, Echo],
        b"off" | b"none" => [Normal, Normal],
        other => {
            return Err(Error::unsupported(format!(
                "media echo {}",
                String::from_utf8_lossy(other)
            )));
        }
    }))
}

/// `address-family`: the answerer's side is IPv6 (`IP6`) or IPv4.
fn address_family(d: &Dict<'_>) -> Result<Option<bool>, Error> {
    Ok(match d.get_bytes(b"address-family") {
        None => None,
        Some(f) if f.eq_ignore_ascii_case(b"IP4") => Some(false),
        Some(f) if f.eq_ignore_ascii_case(b"IP6") => Some(true),
        Some(other) => {
            return Err(Error::unsupported(format!(
                "address-family {}",
                String::from_utf8_lossy(other)
            )));
        }
    })
}

/// `media-address`: the address written into the SDP returned.
fn media_address(d: &Dict<'_>) -> Result<Option<IpAddr>, Error> {
    Ok(match d.get_bytes(b"media-address") {
        None => None,
        Some(a) => Some(
            std::str::from_utf8(a)
                .ok()
                .and_then(|t| t.parse().ok())
                .ok_or_else(|| {
                    Error::unsupported(format!("media-address {}", String::from_utf8_lossy(a)))
                })?,
        ),
    })
}

pub(super) fn opts(d: &Dict<'_>) -> Result<Opts, Error> {
    let learning = match d.get_bytes(b"endpoint-learning") {
        None | Some(b"heuristic" | b"delayed") => Learning::Heuristic,
        Some(b"immediate") => Learning::Immediate,
        Some(b"off") => Learning::Off,
        Some(other) => {
            return Err(Error::Request(RequestError::UnknownLearning(
                String::from_utf8_lossy(other).into_owned(),
            )));
        }
    };
    // `asymmetric`: the endpoint does not send from where it receives, so
    // nothing is learned from its packets.
    let learning = if list_contains(d, b"flags", b"asymmetric") {
        Learning::Off
    } else {
        learning
    };
    let received_from = match d.get(b"received-from") {
        Some(Value::List(l)) => l.iter().nth(1).and_then(|v| match v {
            Value::Bytes(b) => std::str::from_utf8(b).ok()?.parse().ok(),
            _ => None,
        }),
        _ => None,
    };
    let transport = match d.get_bytes(b"transport-protocol") {
        None => None,
        Some(p) => match Transport::parse(p) {
            Transport::Other => {
                return Err(Error::Request(RequestError::UnsupportedTransport(
                    String::from_utf8_lossy(p).into_owned(),
                )));
            }
            t => Some(t),
        },
    };
    let ice = match d.get_bytes(b"ICE") {
        None | Some(b"default") => IcePolicy::Default,
        // `reject`: the offer's ICE is ignored, so none is answered (the
        // relay terminates ICE, so this is `remove`).
        Some(b"remove" | b"reject") => IcePolicy::Remove,
        Some(b"force") => IcePolicy::Force,
        Some(b"force-relay") => IcePolicy::ForceRelay,
        Some(b"optional") => IcePolicy::Optional,
        Some(other) => {
            return Err(Error::Request(RequestError::UnsupportedIce(
                String::from_utf8_lossy(other).into_owned(),
            )));
        }
    };
    let ice_lite = match d.get_bytes(b"ICE-lite") {
        None => None,
        Some(b"off" | b"none") => Some(IceLite::Off),
        Some(b"forward") => Some(IceLite::Forward),
        Some(b"backward") => Some(IceLite::Backward),
        Some(b"both") => Some(IceLite::Both),
        Some(other) => {
            return Err(Error::Request(RequestError::UnsupportedIceLite(
                String::from_utf8_lossy(other).into_owned(),
            )));
        }
    };
    Ok(Opts {
        sdes: sdes_opts(d),
        dtls: dtls_opt(d)?,
        dtls_reverse: dtls_reverse(d)?,
        track_state: list_contains(d, b"flags", b"track-state"),
        ice_passthrough: None,
        dtls_hash: match d.get_bytes(b"DTLS-fingerprint") {
            None => None,
            Some(h) => Some(rtpflux_core::dtls::HashFn::parse(h).ok_or_else(|| {
                Error::unsupported(format!("DTLS-fingerprint {}", String::from_utf8_lossy(h)))
            })?),
        },
        rtcp_mux: mux_policy(d)?,
        ptime: ptime_opt(d, "ptime")?,
        ptime_reverse: ptime_opt(d, "ptime-reverse")?,
        address_family: address_family(d)?,
        media_echo: media_echo(d)?,
        media_address: media_address(d)?,
        codecs: codec_opts(d),
        ice,
        ice_lite,
        always_transcode: list_contains(d, b"flags", b"always transcode")
            || list_contains(d, b"flags", b"always-transcode"),
        transport,
        trust_address: list_contains(d, b"flags", b"trust-address"),
        strict_source: list_contains(d, b"flags", b"strict-source"),
        media_handover: list_contains(d, b"flags", b"media-handover"),
        unidirectional: list_contains(d, b"flags", b"unidirectional"),
        osrtp: osrtp(d),
        osrtp_legacy: legacy_flags(d),
        replace_origin: list_contains(d, b"replace", b"origin")
            || list_contains(d, b"flags", b"replace-origin"),
        learning,
        received_from,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtpflux_ng::bencode::decode;

    /// `opts` of a bencoded dictionary.
    fn of(text: &[u8]) -> Result<Opts, Error> {
        let Ok(Value::Dict(d)) = decode(text) else {
            panic!("not a dictionary")
        };
        opts(&d)
    }

    #[test]
    fn learning_ice_transport_and_addresses() {
        let o = of(b"de").unwrap();
        assert_eq!(
            (o.learning, o.ice, o.transport),
            (Learning::Heuristic, IcePolicy::Default, None)
        );
        assert!(!o.trust_address && !o.strict_source && !o.replace_origin);
        for (value, learning) in [
            (&b"7:delayed"[..], Learning::Heuristic),
            (b"9:immediate", Learning::Immediate),
            (b"3:off", Learning::Off),
        ] {
            let text = [&b"d17:endpoint-learning"[..], value, b"e"].concat();
            assert_eq!(of(&text).unwrap().learning, learning);
        }
        assert_eq!(
            of(b"d17:endpoint-learning5:nevere")
                .unwrap_err()
                .to_string(),
            "unknown endpoint-learning never"
        );
        assert_eq!(of(b"d3:ICE6:removee").unwrap().ice, IcePolicy::Remove);
        assert_eq!(of(b"d3:ICE5:forcee").unwrap().ice, IcePolicy::Force);
        assert_eq!(of(b"d3:ICE7:defaulte").unwrap().ice, IcePolicy::Default);
        assert_eq!(
            of(b"d3:ICE4:lazye").unwrap_err().to_string(),
            "unsupported ICE option lazy"
        );
        assert_eq!(
            of(b"d18:transport-protocol8:RTP/SAVPe").unwrap().transport,
            Some(Transport::Savp)
        );
        assert_eq!(
            of(b"d18:transport-protocol3:TCPe").unwrap_err().to_string(),
            "unsupported transport-protocol TCP"
        );
        let o = of(b"d13:received-froml3:IP49:192.0.2.7ee").unwrap();
        assert_eq!(o.received_from, Some("192.0.2.7".parse().unwrap()));
        assert_eq!(
            of(b"d13:received-froml3:IP4i7eee").unwrap().received_from,
            None
        );
        assert_eq!(of(b"d13:received-from3:IP4e").unwrap().received_from, None);
        let o = of(b"d5:flagsl13:trust-address13:strict-sourcee7:replacel6:originee").unwrap();
        assert!(o.trust_address && o.strict_source && o.replace_origin);
        let o = of(b"d5:flags27:trust-address strict-source7:replace6:origine").unwrap();
        assert!(
            o.trust_address && o.strict_source && o.replace_origin,
            "space-separated"
        );
    }

    /// `unknown_options` of a bencoded dictionary.
    fn unknown(text: &[u8]) -> Vec<String> {
        let Ok(Value::Dict(d)) = decode(text) else {
            panic!("not a dictionary")
        };
        unknown_options(&d)
    }

    #[test]
    fn sdes_dtls_and_rtcp_mux_options() {
        let o = of(b"de").unwrap();
        assert_eq!(
            (o.sdes, o.dtls, o.rtcp_mux),
            (SdesOpts::default(), None, MuxPolicy::Default)
        );
        assert_eq!(
            o.sdes.pick(Suite::AeadAes256Gcm),
            Some(Suite::AeadAes256Gcm)
        );
        // A list, or flags; `no-` of the preferred one falls back in order.
        let o = of(b"d4:SDESl26:no-AES_CM_128_HMAC_SHA1_80ee").unwrap();
        assert!(o.sdes.restricts() && !o.sdes.off);
        assert_eq!(
            o.sdes.pick(Suite::AesCm128HmacSha1_80),
            Some(Suite::AesCm128HmacSha1_32)
        );
        let o = of(b"d5:flagsl8:SDES-off26:SDES-only-AEAD_AES_256_GCMee").unwrap();
        assert!(o.sdes.off);
        assert_eq!(
            o.sdes.pick(Suite::AesCm128HmacSha1_80),
            Some(Suite::AeadAes256Gcm)
        );
        let o = of(b"d4:SDESl21:only-AEAD_AES_128_GCM19:no-AEAD_AES_128_GCMee").unwrap();
        assert_eq!(o.sdes.pick(Suite::AeadAes128Gcm), None);
        assert_eq!(
            of(b"d4:DTLS7:passivee").unwrap().dtls,
            Some(DtlsOpt::Passive)
        );
        assert_eq!(of(b"d4:DTLS2:noe").unwrap().dtls, Some(DtlsOpt::Off));
        assert_eq!(
            of(b"d4:DTLS3:yese").unwrap_err().to_string(),
            "unsupported option DTLS yes"
        );
        assert_eq!(
            of(b"d8:rtcp-muxl5:demuxee").unwrap().rtcp_mux,
            MuxPolicy::Demux
        );
        assert_eq!(
            of(b"d5:flagsl16:rtcp-mux-requireee").unwrap().rtcp_mux,
            MuxPolicy::Require
        );
        assert_eq!(
            of(b"d8:rtcp-muxl5:offer6:rejectee")
                .unwrap_err()
                .to_string(),
            "unsupported option rtcp-mux: conflicting values"
        );
    }

    #[test]
    fn asymmetric_and_ice_reject() {
        assert_eq!(
            of(b"d5:flagsl10:asymmetricee").unwrap().learning,
            Learning::Off,
            "nothing learned"
        );
        assert_eq!(of(b"d3:ICE6:rejecte").unwrap().ice, IcePolicy::Remove);
    }

    #[test]
    fn unknown_options_are_named() {
        // What Kamailio sends for `trust-address replace-origin`.
        assert_eq!(
            unknown(
                b"d7:call-id1:c8:from-tag1:f3:sdp1:x7:command5:offer\
                  5:flagsl13:trust-addresse7:replacel6:originee"
            ),
            Vec::<String>::new()
        );
        assert_eq!(
            unknown(b"d5:flagsl14:replace-origin20:codec-transcode-PCMA9:symmetricee"),
            Vec::<String>::new()
        );
        assert_eq!(
            unknown(
                b"d5:flagsl12:asymmetricXY11:codec-mask-e5:lebell1:ae\
                  7:replacel9:frobnicat6:origine5:codecd7:frobnicl1:xeee"
            ),
            [
                "option lebel: not supported, ignored",
                "flag asymmetricXY: not supported, ignored",
                "flag codec-mask-: not supported, ignored",
                "replace frobnicat: not supported, ignored",
                "codec frobnic: not supported, ignored",
            ]
        );
        assert_eq!(
            unknown(b"d5:flags17:loop-protecx asym7:replace6:origine"),
            [
                "flag loop-protecx: not supported, ignored",
                "flag asym: not supported, ignored"
            ],
            "space-separated"
        );
    }

    #[test]
    fn codec_options_as_a_dictionary_or_flags() {
        let o = of(b"d5:codecd9:transcodel4:PCMA4:opuse4:maskl4:PCMU5:G7224eee").unwrap();
        assert_eq!(o.codecs.transcode, Some(Codec::Pcma), "the first one");
        assert_eq!(
            o.codecs.mask,
            [Some(Codec::Pcmu), None],
            "unknown names ignored"
        );
        let o = of(b"d5:codecd9:transcode4:opus4:mask4:PCMAee").unwrap();
        assert_eq!(o.codecs.transcode, Some(Codec::Opus));
        assert_eq!(o.codecs.mask, [Some(Codec::Pcma), None]);
        let o = of(b"d5:flagsl20:codec-transcode-PCMU15:codec-mask-PCMA15:codec-mask-opusi1eee")
            .unwrap();
        assert_eq!(o.codecs.transcode, Some(Codec::Pcmu));
        assert_eq!(o.codecs.mask, [Some(Codec::Pcma), Some(Codec::Opus)]);
        let o = of(b"d5:codecd9:transcodeli1eeee").unwrap();
        assert_eq!(o.codecs, CodecOpts::default());
    }
}
