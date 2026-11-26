//! Rewriting an SDP towards one side: the relay's address, ports,
//! keys, ICE and DTLS attributes, and format changes for transcoding.

#[allow(clippy::wildcard_imports)]
use super::*;
use crate::rtp::PtSet;

/// The relay's side of one media section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Independent attribute switches.
pub struct Relayed<'a> {
    pub rtp_port: u16,
    pub rtcp_port: u16,
    /// Replace the `m=` protocol (`None` keeps it).
    pub transport: Option<Transport>,
    /// The relay's SDES key for this section: written as the only
    /// `a=crypto` line. Incoming `a=crypto` lines are always removed.
    pub crypto: Option<Crypto>,
    /// Further keys offered after [`Relayed::crypto`] (other suites), one
    /// `a=crypto` line each.
    pub more_crypto: &'a [Option<Crypto>],
    /// Write each key with the lifetime `|2^31` (`SDES-lifetime`).
    pub sdes_lifetime: bool,
    /// The relay's ICE-lite credentials for this section: written with its
    /// host candidates. Incoming ICE attributes are always removed.
    pub ice: Option<IceAttrs<'a>>,
    /// Write this `a=mid` (replacing the input's).
    pub mid: Option<&'a [u8]>,
    /// Write `a=rtcp-mux` (replacing the input's): a bundled section.
    pub rtcp_mux: bool,
    /// An added format with this dynamic payload type is this codec (Opus,
    /// AMR): its `a=rtpmap` (and `a=fmtp`) are written as such.
    pub dynamic: Option<(Pt, Codec)>,
    /// An added format with this payload type is `telephone-event/8000`
    /// (RFC 4733), with `a=fmtp:<pt> 0-15`.
    pub telephone_event: Option<Pt>,
    /// Drop the input's `a=mid` and `a=rtcp-mux` even when not writing
    /// them: an answer from a bundled endpoint relayed to an endpoint that
    /// did not offer BUNDLE (`rtcp_mux` still writes `a=rtcp-mux`).
    pub unbundle: bool,
    /// Drop the input's `a=rtcp-mux` (unless writing it): the relay does
    /// not multiplex RTCP towards this side (the `rtcp-mux` options).
    pub drop_rtcp_mux: bool,
    /// The relay's DTLS role and certificate fingerprint for this section.
    /// Incoming `a=setup`, `a=fingerprint` and `a=tls-id` are always
    /// removed.
    pub dtls: Option<DtlsAttrs<'a>>,
    /// Changes to the `m=` format list (transcoding), with the
    /// `a=rtpmap`, `a=fmtp` and `a=rtcp-fb` lines of removed formats
    /// dropped and an `a=rtpmap` written for each added format (a static
    /// one, or [`Relayed::dynamic`]).
    pub formats: [Option<FormatEdit>; 2],
    /// Keep only these payload types of the input, in this order (the
    /// `codec` options `strip`, `except` and `offer`), before
    /// [`Relayed::formats`] apply; the lines of the others are dropped.
    pub select: Option<&'a [Pt]>,
    /// The proxy's attribute edits for this section (`sdp-attr`).
    pub attrs: AttrEdits<'a>,
    /// What becomes of `a=rtcp` (RFC 3605).
    pub rtcp_attr: RtcpAttr,
    /// ICE passed through (`ICE=force-relay`, `optional`): the section kept
    /// as it is (its `m=`, `c=`, ICE, keys), the relay added as a relay
    /// candidate.
    pub passthrough: Option<RelayCandidate>,
    /// Write `a=ptime` with this value (replacing the input's, of the
    /// section or the session): the relay repacketises to it.
    pub ptime: Option<u16>,
    /// Remove the input's `a=zrtp-hash`: the relay changes this section's
    /// media (terminates SRTP or DTLS on either side, transcodes, sorts a
    /// BUNDLE group), so the endpoints' end-to-end ZRTP (RFC 6189) cannot
    /// work across it; without the hash (§8.1) they see that it is
    /// unavailable rather than broken. A plain relay keeps it.
    pub strip_zrtp: bool,
}

/// One change to a media section's format list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatEdit {
    /// Put the second payload type where the first one is.
    Replace(Pt, Pt),
    /// Drop a payload type.
    Remove(Pt),
    /// Add a payload type at the end (unless present).
    Append(Pt),
}

/// The encoding name of a static G.711 payload type (RFC 3551 Table 4).
#[must_use]
pub const fn g711_name(pt: Pt) -> Option<&'static str> {
    match pt.get() {
        0 => Some("PCMU"),
        8 => Some("PCMA"),
        _ => None,
    }
}

impl Relayed<'_> {
    /// Whether `pt`'s lines go: removed or replaced.
    pub(super) fn drops_format(&self, pt: Pt) -> bool {
        self.select.is_some_and(|s| !s.contains(&pt))
            || self.formats.iter().flatten().any(|e| match *e {
                FormatEdit::Replace(from, _) | FormatEdit::Remove(from) => from == pt,
                FormatEdit::Append(_) => false,
            })
    }

    /// The payload types this section's edits add.
    pub(super) fn added_formats(&self) -> impl Iterator<Item = Pt> + '_ {
        self.formats.iter().flatten().filter_map(|e| match *e {
            FormatEdit::Replace(_, to) | FormatEdit::Append(to) => Some(to),
            FormatEdit::Remove(_) => None,
        })
    }
}

impl Relayed<'_> {
    /// The relay's ports, protocol and keys left as in the input.
    #[must_use]
    pub const fn ports(rtp_port: u16, rtcp_port: u16) -> Self {
        Relayed {
            rtp_port,
            rtcp_port,
            transport: None,
            crypto: None,
            more_crypto: &[],
            sdes_lifetime: false,
            ice: None,
            dtls: None,
            mid: None,
            rtcp_mux: false,
            unbundle: false,
            drop_rtcp_mux: false,
            dynamic: None,
            telephone_event: None,
            formats: [None; 2],
            select: None,
            attrs: AttrEdits::NONE,
            rtcp_attr: RtcpAttr::AsInput,
            ptime: None,
            passthrough: None,
            strip_zrtp: false,
        }
    }
}

/// The payload type an `a=rtpmap:`, `a=fmtp:` or `a=rtcp-fb:` value is
/// about.
pub(super) fn format_attr_pt(value: &[u8]) -> Option<Pt> {
    let rest = value
        .strip_prefix(b"rtpmap:")
        .or_else(|| value.strip_prefix(b"fmtp:"))
        .or_else(|| value.strip_prefix(b"rtcp-fb:"))?;
    let end = rest.iter().position(|&c| c == b' ').unwrap_or(rest.len());
    super::read::pt_of(rest.get(..end)?)
}

/// Write the format list with `relayed`'s edits applied.
pub(super) fn write_formats<'f>(
    w: &mut Out<'_>,
    formats: impl Iterator<Item = &'f str>,
    relayed: &Relayed<'_>,
) -> Result<(), SdpError> {
    let mut present = PtSet::EMPTY;
    let mut emit = |w: &mut Out<'_>, p: Pt| {
        if !present.insert(p) {
            return Ok(());
        }
        w.fmt(format_args!(" {p}"))
    };
    let edit = |pt: Pt| {
        relayed
            .formats
            .iter()
            .flatten()
            .try_fold(pt, |p, e| match *e {
                FormatEdit::Replace(from, to) if p == from => Some(to),
                FormatEdit::Remove(from) if p == from => None,
                _ => Some(p),
            })
    };
    // The input's payload types, written in its order, or (with a
    // selection) noted and written in the selection's order.
    let mut offered = PtSet::EMPTY;
    for tok in formats {
        match super::read::pt_of(tok.as_bytes()) {
            // Not an RTP payload type (0-127): kept as it is.
            None => {
                w.put(b" ")?;
                w.put(tok.as_bytes())?;
            }
            Some(pt) if relayed.select.is_some() => {
                offered.insert(pt);
            }
            Some(pt) => {
                if let Some(p) = edit(pt) {
                    emit(w, p)?;
                }
            }
        }
    }
    for &pt in relayed.select.unwrap_or_default() {
        if offered.contains(pt)
            && let Some(p) = edit(pt)
        {
            emit(w, p)?;
        }
    }
    // Added formats, and replacements whose original was in the input
    // but left out by the selection: at the end.
    let selected = |pt: Pt| relayed.select.is_none_or(|s| s.contains(&pt));
    for e in relayed.formats.iter().flatten() {
        match *e {
            FormatEdit::Append(p) => emit(w, p)?,
            FormatEdit::Replace(from, to) if offered.contains(from) && !selected(from) => {
                emit(w, to)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// DTLS-SRTP attributes (RFC 5763 §5): `a=setup` and `a=fingerprint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtlsAttrs<'a> {
    pub setup: Setup,
    /// The whole attribute value, e.g. `sha-256 AB:…`.
    pub fingerprint: &'a str,
}

/// The relay's ICE attributes (RFC 8839 §5): credentials, and whether RTCP
/// has a candidate of its own (no `rtcp-mux`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct IceAttrs<'a> {
    pub ufrag: &'a [u8],
    pub pwd: &'a [u8],
    pub rtcp_candidate: bool,
    /// Write the candidates (only in the first section of a BUNDLE group).
    pub candidates: bool,
    /// A lite agent (`a=ice-lite`); otherwise a full one (`ice2`).
    pub lite: bool,
    /// Tell the peer it may trickle (`a=ice-options:trickle`).
    pub trickle: bool,
    /// The relay's server-reflexive address, if it has one: a candidate on
    /// the same port, related to the host one.
    pub srflx: Option<IpAddr>,
}

/// How to rewrite an SDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan<'a> {
    /// The relay's address on the interface facing the SDP's recipient.
    pub address: IpAddr,
    /// One entry per media section, in order.
    pub media: &'a [Relayed<'a>],
    /// Also rewrite the `o=` address.
    pub replace_origin: bool,
    /// Write `a=group:BUNDLE` with these tags (none: no group).
    pub bundle: &'a [&'a [u8]],
    /// Session-level edits the proxy asked for.
    pub session: SessionEdits<'a>,
    /// Every active section is passed through ([`Relayed::passthrough`]):
    /// the session-level `c=` and attributes are kept too.
    pub keep_connection: bool,
}

/// The relay as an ICE relay candidate of a section passed through: its
/// RTCP port as component 2 too (`rtcp`), the section's own relay
/// candidates dropped (`drop_relay`, `force-relay`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayCandidate {
    pub rtcp: bool,
    pub drop_relay: bool,
}

/// Attribute edits (rtpengine's `sdp-attr`) at one level: attribute
/// values (without `a=`) to add, attributes to remove (by name, the part
/// before `:`, or by whole value), and whole values to substitute.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AttrEdits<'a> {
    pub add: &'a [&'a [u8]],
    pub remove: &'a [&'a [u8]],
    pub substitute: &'a [(&'a [u8], &'a [u8])],
}

impl AttrEdits<'_> {
    pub const NONE: AttrEdits<'static> = AttrEdits {
        add: &[],
        remove: &[],
        substitute: &[],
    };

    /// Whether an input attribute `value` is removed.
    fn removes(&self, value: &[u8]) -> bool {
        let name = value.split(|&c| c == b':').next().unwrap_or(value);
        self.remove.iter().any(|&r| r == name || r == value)
    }

    /// What an input attribute `value` is substituted by.
    fn substitute(&self, value: &[u8]) -> Option<&[u8]> {
        self.substitute
            .iter()
            .find(|(from, _)| *from == value)
            .map(|&(_, to)| to)
    }

    fn write_added(&self, w: &mut Out<'_>) -> Result<(), SdpError> {
        for a in self.add {
            w.put(b"a=")?;
            w.put(a)?;
            w.put(b"\r\n")?;
        }
        Ok(())
    }
}

/// `a=rtcp` (RFC 3605): rewritten where the input has it (`AsInput`),
/// never written (`Omit`, rtpengine's `no-rtcp-attribute`), or always
/// written for a section without `rtcp-mux` (`Full`,
/// `full-rtcp-attribute`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RtcpAttr {
    #[default]
    AsInput,
    Omit,
    Full,
}

/// Session-level edits: the `o=` user name (`-`) and version, `s=` (`-`),
/// and the session's attribute edits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionEdits<'a> {
    pub username: bool,
    pub session_name: bool,
    /// The `o=` version written.
    pub version: Option<u64>,
    /// `origin-full`: the whole `o=` line is the relay's, `o=- <this
    /// session id> <version> IN <family> <relay address>`.
    pub origin: Option<u64>,
    pub attrs: AttrEdits<'a>,
}

impl SessionEdits<'_> {
    pub const NONE: SessionEdits<'static> = SessionEdits {
        username: false,
        session_name: false,
        version: None,
        origin: None,
        attrs: AttrEdits::NONE,
    };
}

/// The `o=` version of an SDP (its third field), if well formed.
#[must_use]
pub fn origin_version(sdp: &[u8]) -> Option<u64> {
    origin_field(sdp, 2)
}

/// The `o=` session id of an SDP (its second field), if well formed.
#[must_use]
pub fn origin_session(sdp: &[u8]) -> Option<u64> {
    origin_field(sdp, 1)
}

fn origin_field(sdp: &[u8], n: usize) -> Option<u64> {
    let line = lines(sdp).find(|l| l.starts_with(b"o="))?;
    let v = text(line.get(2..)?).ok()?.split_ascii_whitespace().nth(n)?;
    decimal(v.as_bytes(), u64::MAX)
}

pub(super) struct Out<'b> {
    pub(super) buf: &'b mut [u8],
    pub(super) pos: usize,
}

impl Out<'_> {
    pub(super) fn put(&mut self, b: &[u8]) -> Result<(), SdpError> {
        let end = self.pos.checked_add(b.len()).ok_or(SdpError::Overflow)?;
        self.buf
            .get_mut(self.pos..end)
            .ok_or(SdpError::Overflow)?
            .copy_from_slice(b);
        self.pos = end;
        Ok(())
    }

    pub(super) fn fmt(&mut self, args: core::fmt::Arguments<'_>) -> Result<(), SdpError> {
        struct W<'x, 'b>(&'x mut Out<'b>, bool);
        impl core::fmt::Write for W<'_, '_> {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                if self.0.put(s.as_bytes()).is_err() {
                    self.1 = true;
                    return Err(core::fmt::Error);
                }
                Ok(())
            }
        }
        let mut w = W(self, false);
        let r = core::fmt::write(&mut w, args);
        if w.1 || r.is_err() {
            Err(SdpError::Overflow)
        } else {
            Ok(())
        }
    }
}

pub(super) fn family(a: IpAddr) -> &'static str {
    if a.is_ipv4() { "IP4" } else { "IP6" }
}

/// The peers' DTLS attributes: the relay terminates DTLS on each side.
pub(super) fn is_dtls_attr(value: &[u8]) -> bool {
    [&b"setup:"[..], b"fingerprint:", b"tls-id:"]
        .iter()
        .any(|p| value.starts_with(p))
}

pub(super) fn is_ice(value: &[u8]) -> bool {
    const ICE: [&[u8]; 8] = [
        b"candidate:",
        b"remote-candidates:",
        b"ice-ufrag:",
        b"ice-pwd:",
        b"ice-options:",
        b"ice-pacing:",
        b"ice-lite",
        b"end-of-candidates",
    ];
    ICE.iter().any(|p| value.starts_with(p))
}

/// The relay's session-level ICE lines: `a=ice-lite` where it is a lite
/// agent, `a=ice-options` (`ice2`, RFC 8445 §10; `trickle` when the peer
/// trickles) where it is a full one.
fn write_session_ice(w: &mut Out<'_>, plan: &Plan<'_>) -> Result<(), SdpError> {
    let ice = || plan.media.iter().filter_map(|r| r.ice);
    if ice().any(|i| i.lite) {
        w.put(b"a=ice-lite\r\n")?;
    }
    if ice().any(|i| !i.lite) {
        w.put(if ice().any(|i| i.trickle) {
            b"a=ice-options:trickle ice2\r\n".as_slice()
        } else {
            b"a=ice-options:ice2\r\n".as_slice()
        })?;
    }
    Ok(())
}

/// The relay's ICE lines for one media section (RFC 8839 §5.1, §5.4,
/// §5.5): credentials, one host candidate per component, end of candidates.
pub(super) fn write_ice(
    w: &mut Out<'_>,
    ice: &IceAttrs<'_>,
    addr: IpAddr,
    relayed: &Relayed<'_>,
) -> Result<(), SdpError> {
    w.put(b"a=ice-ufrag:")?;
    w.put(ice.ufrag)?;
    w.put(b"\r\na=ice-pwd:")?;
    w.put(ice.pwd)?;
    w.put(b"\r\n")?;
    if !ice.candidates {
        return Ok(());
    }
    let components: &[(u32, u16)] = if ice.rtcp_candidate {
        &[(1, relayed.rtp_port), (2, relayed.rtcp_port)]
    } else {
        &[(1, relayed.rtp_port)]
    };
    for &(c, port) in components {
        w.fmt(format_args!(
            "a=candidate:1 {c} UDP {} {addr} {port} typ host\r\n",
            crate::ice::checklist::candidate_priority(126, 65_535, c)
        ))?;
    }
    if let Some(public) = ice
        .srflx
        .filter(|p| *p != addr && p.is_ipv4() == addr.is_ipv4())
    {
        for &(c, port) in components {
            w.fmt(format_args!(
                "a=candidate:2 {c} UDP {} {public} {port} typ srflx raddr {addr} rport {port}\r\n",
                crate::ice::checklist::candidate_priority(100, 65_535, c)
            ))?;
        }
    }
    w.put(b"a=end-of-candidates\r\n")
}

/// The rewritten `m=` line of one media section.
pub(super) fn write_media(
    w: &mut Out<'_>,
    value: &[u8],
    relayed: &Relayed<'_>,
) -> Result<(), SdpError> {
    if relayed.passthrough.is_some() {
        w.put(b"m=")?;
        w.put(value)?;
        return w.put(b"\r\n");
    }
    // The reader's rules (a plain decimal port); its tokens, rewritten
    // with single spaces.
    super::read::parse_m(value)?;
    let t = text(value)?;
    let mut f = t.split_ascii_whitespace();
    let kind = f.next().ok_or(SdpError::Malformed)?;
    let port = f.next().ok_or(SdpError::Malformed)?;
    let proto = f.next().ok_or(SdpError::Malformed)?;
    // A port of 0 rejects the stream: keep it.
    let rejected = relayed.rtp_port == 0;
    let suffix = port.split_once('/').map(|(_, n)| n);
    let new_port = if rejected { 0 } else { relayed.rtp_port };
    let proto = relayed.transport.and_then(Transport::name).unwrap_or(proto);
    match suffix {
        Some(n) => w.fmt(format_args!("m={kind} {new_port}/{n} {proto}"))?,
        None => w.fmt(format_args!("m={kind} {new_port} {proto}"))?,
    }
    write_formats(w, f, relayed)?;
    w.put(b"\r\n")
}

/// The relay's own attributes for a media section (added formats, SDES
/// key, `a=mid`, `a=rtcp-mux`, DTLS role and fingerprint, ICE). They go
/// after the section's `i=`, `c=` and `b=` lines, before its first `a=`
/// (RFC 8866 §5: the lines of a media description in that order).
pub(super) fn write_media_attrs(
    w: &mut Out<'_>,
    relayed: &Relayed<'_>,
    addr: IpAddr,
) -> Result<(), SdpError> {
    let rejected = relayed.rtp_port == 0;
    if let Some(c) = relayed.passthrough.filter(|_| !rejected) {
        // Type preference 0 (relay), local preference 65535 (RFC 8445
        // §5.1.2.1): below every other candidate.
        let ports = [(1, relayed.rtp_port), (2, relayed.rtcp_port)];
        for (component, port) in ports.into_iter().take(if c.rtcp { 2 } else { 1 }) {
            w.fmt(format_args!(
                "a=candidate:rtpflux {component} UDP {} {addr} {port} typ relay raddr {addr} rport {port}\r\n",
                // Component 1 or 2: no overflow.
                (65_535u32 << 8).wrapping_add(256u32.wrapping_sub(component))
            ))?;
        }
        return Ok(());
    }
    for pt in relayed.added_formats() {
        if relayed.telephone_event == Some(pt) {
            w.fmt(format_args!(
                "a=rtpmap:{pt} telephone-event/8000\r\na=fmtp:{pt} 0-15\r\n"
            ))?;
            continue;
        }
        let added = match relayed.dynamic {
            Some((dynamic_pt, dynamic)) if dynamic_pt == pt => Some(dynamic),
            _ => Codec::of_static(pt),
        };
        if let Some(added) = added {
            w.fmt(format_args!("a=rtpmap:{pt} {}\r\n", added.rtpmap()))?;
            if let Some(fmtp) = added.fmtp() {
                w.fmt(format_args!("a=fmtp:{pt} {fmtp}\r\n"))?;
            }
        }
    }
    if let Some(p) = relayed.ptime.filter(|_| !rejected) {
        w.fmt(format_args!("a=ptime:{p}\r\n"))?;
    }
    let keys = relayed
        .crypto
        .iter()
        .chain(relayed.more_crypto.iter().flatten())
        .filter(|_| !rejected);
    for c in keys {
        let (key, n) = b64_key(c.key.bytes());
        w.fmt(format_args!(
            "a=crypto:{} {} inline:",
            c.tag,
            c.key.suite.name()
        ))?;
        w.put(key.get(..n).unwrap_or_default())?;
        if relayed.sdes_lifetime {
            w.put(b"|2^31")?;
        }
        for p in c.key.policy.params() {
            w.put(b" ")?;
            w.put(p.as_bytes())?;
        }
        w.put(b"\r\n")?;
    }
    if let Some(mid) = relayed.mid {
        w.put(b"a=mid:")?;
        w.put(mid)?;
        w.put(b"\r\n")?;
    }
    if relayed.rtcp_mux && !rejected {
        w.put(b"a=rtcp-mux\r\n")?;
    }
    if relayed.rtcp_attr == RtcpAttr::Full && !relayed.rtcp_mux && !rejected {
        w.fmt(format_args!(
            "a=rtcp:{} IN {} {}\r\n",
            relayed.rtcp_port,
            family(addr),
            addr
        ))?;
    }
    relayed.attrs.write_added(w)?;
    if let Some(d) = relayed.dtls.filter(|_| !rejected) {
        w.fmt(format_args!(
            "a=setup:{}\r\na=fingerprint:{}\r\n",
            d.setup.name(),
            d.fingerprint
        ))?;
    }
    if let Some(ice) = relayed.ice.filter(|_| !rejected) {
        write_ice(w, &ice, addr, relayed)?;
    }
    Ok(())
}

/// The `o=` line (`value` after `o=`) as `plan` has it: the relay's own
/// (`origin-full`), or the input's with the user name, version or address
/// replaced.
fn write_origin(w: &mut Out<'_>, value: &[u8], plan: &Plan<'_>) -> Result<(), SdpError> {
    let addr = plan.address;
    // o=<user> <sess-id> <sess-version> IN <addrtype> <address>
    let t = text(value)?;
    if let Some(sess) = plan.session.origin {
        return w.fmt(format_args!(
            "o=- {sess} {} IN {} {}\r\n",
            plan.session.version.unwrap_or(0),
            family(addr),
            addr
        ));
    }
    let mut it = t.split_ascii_whitespace();
    let f: [&str; 3] = [
        it.next().unwrap_or("-"),
        it.next().unwrap_or("0"),
        it.next().unwrap_or("0"),
    ];
    let user = if plan.session.username { "-" } else { f[0] };
    w.fmt(format_args!("o={user} {} ", f[1]))?;
    match plan.session.version {
        Some(v) => w.fmt(format_args!("{v}"))?,
        None => w.put(f[2].as_bytes())?,
    }
    if plan.replace_origin {
        w.fmt(format_args!(" IN {} {}\r\n", family(addr), addr))
    } else {
        for rest in it {
            w.put(b" ")?;
            w.put(rest.as_bytes())?;
        }
        w.put(b"\r\n")
    }
}

/// Rewrite `sdp` according to `plan` into `out`; returns the length.
///
/// # Errors
///
/// [`SdpError::Overflow`] when `out` is too small; [`SdpError::Malformed`]
/// when the plan does not cover every media section or a relevant line is
/// malformed.
pub fn rewrite(sdp: &[u8], plan: &Plan<'_>, out: &mut [u8]) -> Result<usize, SdpError> {
    let mut w = Out { buf: out, pos: 0 };
    let addr = plan.address;
    let mut media: Option<usize> = None;
    // The section whose own attributes are still to be written.
    let mut pending: Option<usize> = None;
    let mut next = 0;
    let flush = |w: &mut Out<'_>, pending: &mut Option<usize>| -> Result<(), SdpError> {
        if let Some(i) = pending.take() {
            let relayed = plan.media.get(i).ok_or(SdpError::Malformed)?;
            write_media_attrs(w, relayed, addr)?;
        }
        Ok(())
    };
    for line in lines(sdp) {
        let value = line.get(2..).unwrap_or_default();
        if line.get(1) != Some(&b'=') {
            w.put(line)?;
            w.put(b"\r\n")?;
            continue;
        }
        // `line` has at least two octets (checked above).
        match line.first().copied().unwrap_or_default() {
            b'o' if plan.session.origin.is_some()
                || plan.replace_origin
                || plan.session.username
                || plan.session.version.is_some() =>
            {
                write_origin(&mut w, value, plan)?;
            }
            b's' if plan.session.session_name => w.put(b"s=-\r\n")?,
            b'c' if match media {
                Some(i) => plan.media.get(i).is_some_and(|r| r.passthrough.is_some()),
                None => plan.keep_connection,
            } =>
            {
                w.put(line)?;
                w.put(b"\r\n")?;
            }
            b'c' => {
                parse_c(value)?;
                w.fmt(format_args!("c=IN {} {}\r\n", family(addr), addr))?;
            }
            b'm' => {
                flush(&mut w, &mut pending)?;
                if next == 0 {
                    plan.session.attrs.write_added(&mut w)?;
                    write_session_ice(&mut w, plan)?;
                }
                if next == 0 && !plan.bundle.is_empty() {
                    w.put(b"a=group:BUNDLE")?;
                    for id in plan.bundle {
                        w.put(b" ")?;
                        w.put(id)?;
                    }
                    w.put(b"\r\n")?;
                }
                let relayed = plan.media.get(next).ok_or(SdpError::Malformed)?;
                media = Some(next);
                pending = Some(next);
                // A media section per `plan.media` entry (`get` above).
                next = next.wrapping_add(1);
                write_media(&mut w, value, relayed)?;
            }
            b'a' if pending.is_some() => {
                flush(&mut w, &mut pending)?;
                rewrite_attr(&mut w, line, value, plan, media)?;
            }
            b'a' => rewrite_attr(&mut w, line, value, plan, media)?,
            _ => {
                w.put(line)?;
                w.put(b"\r\n")?;
            }
        }
    }
    flush(&mut w, &mut pending)?;
    if next == 0 {
        plan.session.attrs.write_added(&mut w)?;
    }
    if next != plan.media.len() {
        return Err(SdpError::Malformed);
    }
    Ok(w.pos)
}

/// One `a=` line (`value` after `a=`) of the session (`media` none) or of
/// media section `media`: dropped, rewritten or kept.
fn rewrite_attr(
    w: &mut Out<'_>,
    line: &[u8],
    value: &[u8],
    plan: &Plan<'_>,
    media: Option<usize>,
) -> Result<(), SdpError> {
    let addr = plan.address;
    // The proxy's edits (`sdp-attr`) come first.
    let edits = match media {
        Some(i) => plan.media.get(i).map_or(AttrEdits::NONE, |r| r.attrs),
        None => plan.session.attrs,
    };
    if edits.removes(value) {
        return Ok(());
    }
    if let Some(to) = edits.substitute(value) {
        w.put(b"a=")?;
        w.put(to)?;
        return w.put(b"\r\n");
    }
    // Passed through: kept as it is, but for the section's own relay
    // candidates under `force-relay`.
    let through = match media {
        Some(i) => plan.media.get(i).and_then(|r| r.passthrough),
        None => plan.keep_connection.then_some(RelayCandidate {
            rtcp: false,
            drop_relay: false,
        }),
    };
    if let Some(c) = through {
        let relay =
            value.starts_with(b"candidate:") && value.windows(10).any(|x| x == b" typ relay");
        if !(c.drop_relay && relay) {
            w.put(line)?;
            w.put(b"\r\n")?;
        }
        return Ok(());
    }
    match () {
        () if is_ice(value) || is_dtls_attr(value) => {}
        () if value == b"group" || value == b"bundle-only" => {}
        () if value.starts_with(b"mid:")
            && media
                .and_then(|i| plan.media.get(i))
                .is_some_and(|r| r.mid.is_some() || r.unbundle) => {}
        () if value == b"rtcp-mux"
            && media
                .and_then(|i| plan.media.get(i))
                .is_some_and(|r| r.rtcp_mux || r.unbundle || r.drop_rtcp_mux) => {}
        () if value
            .strip_prefix(b"group:")
            .is_some_and(|g| !keeps_group(g)) => {}
        () if media.is_some() && value.starts_with(b"crypto:") => {}
        // The relay's own packet time, where it sets one.
        () if value.starts_with(b"ptime:")
            && match media {
                Some(i) => plan.media.get(i).is_some_and(|r| r.ptime.is_some()),
                None => plan.media.iter().any(|r| r.ptime.is_some()),
            } => {}
        // ZRTP's hash, where the relay transforms the media: in that
        // section, or (session-level) anywhere.
        () if value.starts_with(b"zrtp-hash:")
            && match media {
                Some(i) => plan.media.get(i).is_some_and(|r| r.strip_zrtp),
                None => plan.media.iter().any(|r| r.strip_zrtp),
            } => {}
        () if format_attr_pt(value).is_some_and(|pt| {
            media
                .and_then(|i| plan.media.get(i))
                .is_some_and(|r| r.drops_format(pt) || r.added_formats().any(|a| a == pt))
        }) => {}
        // A session-level a=rtcp (meaningless, RFC 3605 is media-level)
        // is dropped, as the reader ignores it.
        () if media.is_none() && value.starts_with(b"rtcp:") => {}
        () if value.starts_with(b"rtcp:")
            && media
                .and_then(|i| plan.media.get(i))
                .is_some_and(|r| r.rtcp_attr != RtcpAttr::AsInput) => {}
        () if value.starts_with(b"rtcp:") => {
            let relayed = media
                .and_then(|i| plan.media.get(i))
                .ok_or(SdpError::Malformed)?;
            w.fmt(format_args!(
                "a=rtcp:{} IN {} {}\r\n",
                relayed.rtcp_port,
                family(addr),
                addr
            ))?;
        }
        () => {
            w.put(line)?;
            w.put(b"\r\n")?;
        }
    }
    Ok(())
}
