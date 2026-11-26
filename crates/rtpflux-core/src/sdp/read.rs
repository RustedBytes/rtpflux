//! Reading an SDP: the media sections and the attributes the relay uses.

#[allow(clippy::wildcard_imports)]
use super::*;

/// A decimal number (ASCII digits only, leading zeros allowed) below
/// `limit`.
/// A payload type written in decimal (0–127).
pub(super) fn pt_of(text: &[u8]) -> Option<Pt> {
    Pt::from_decimal(text)
}

/// `value` split at the first `sep` (which neither part keeps).
pub(super) fn split_at_byte(value: &[u8], sep: u8) -> Option<(&[u8], &[u8])> {
    let i = value.iter().position(|&b| b == sep)?;
    let (head, tail) = value.split_at_checked(i)?;
    Some((head, tail.get(1..)?))
}

pub(super) fn decimal(text: &[u8], limit: u64) -> Option<u64> {
    if text.is_empty() {
        return None;
    }
    let mut v = 0u64;
    for &c in text {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v
            .checked_mul(10)?
            .checked_add(u64::from(c.checked_sub(b'0')?))?;
    }
    (v < limit).then_some(v)
}

/// `a=rtcp` (RFC 3605 §2.1): a port, optionally followed by network type,
/// address type and address, single spaces; `None` when malformed.
pub(super) fn parse_rtcp(value: &[u8]) -> Option<u16> {
    let mut f = value.split(|&b| b == b' ');
    let port = u16::try_from(decimal(f.next()?, 65_536)?).ok()?;
    match (f.next(), f.next(), f.next(), f.next()) {
        (None, ..) => Some(port),
        (Some(n), Some(t), Some(a), None) if !n.is_empty() && !t.is_empty() && !a.is_empty() => {
            Some(port)
        }
        _ => None,
    }
}

pub(super) fn lines(sdp: &[u8]) -> impl Iterator<Item = &[u8]> {
    sdp.split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .filter(|l| !l.is_empty())
}

pub(super) fn text(b: &[u8]) -> Result<&str, SdpError> {
    core::str::from_utf8(b).map_err(|_| SdpError::Encoding)
}

/// `c=IN IP4|IP6 <addr>[/ttl...]` → the address; `None` for a host name
/// (legal, RFC 8866 §5.7, but nothing the relay can send to).
///
/// # Errors
///
/// [`SdpError::Malformed`] for another network or address type, or an
/// address of the other family.
pub(super) fn parse_c(value: &[u8]) -> Result<Option<IpAddr>, SdpError> {
    let mut f = text(value)?.split(' ');
    let (net, kind, addr) = (
        f.next().ok_or(SdpError::Malformed)?,
        f.next().ok_or(SdpError::Malformed)?,
        f.next().ok_or(SdpError::Malformed)?,
    );
    if net != "IN" || f.next().is_some() {
        return Err(SdpError::Malformed);
    }
    let addr = addr.split('/').next().unwrap_or(addr);
    match (kind, addr.parse::<IpAddr>()) {
        ("IP4", Ok(a @ IpAddr::V4(_))) | ("IP6", Ok(a @ IpAddr::V6(_))) => Ok(Some(a)),
        // A host name (an address of the other family is malformed).
        ("IP4" | "IP6", Err(_)) if !addr.is_empty() => Ok(None),
        _ => Err(SdpError::Malformed),
    }
}

/// Keep `value` if it is a fingerprint the relay can check and there is
/// room.
pub(super) fn add_fingerprint(fps: &mut [Option<Fingerprint>; MAX_FINGERPRINTS], value: &[u8]) {
    if let Some(f) = Fingerprint::parse(value)
        && let Some(slot) = fps.iter_mut().find(|f| f.is_none())
    {
        *slot = Some(f);
    }
}

/// `m=<media> <port>[/<n>] <proto> <fmt> ...` → the port and profile.
/// Fields are split on any whitespace, as the rewriter splits them (which
/// writes them back with single spaces); the port is plain decimal (no
/// sign).
pub(super) fn parse_m(value: &[u8]) -> Result<(u16, Transport, PayloadTypes), SdpError> {
    let mut f = text(value)?.split_ascii_whitespace();
    let _media = f.next().ok_or(SdpError::Malformed)?;
    let port = f.next().ok_or(SdpError::Malformed)?;
    let proto = f.next().ok_or(SdpError::Malformed)?;
    let port = port.split('/').next().unwrap_or(port);
    let port = u16::try_from(decimal(port.as_bytes(), 65_536).ok_or(SdpError::Malformed)?)
        .map_err(|_| SdpError::Malformed)?;
    let mut types = PayloadTypes::EMPTY;
    for fmt in f {
        if let Some(pt) = pt_of(fmt.as_bytes()) {
            types.push(pt);
        }
    }
    Ok((port, Transport::parse(proto.as_bytes()), types))
}

/// `<pt> opus/48000[/2]` (RFC 7587 §7: always 48000 Hz and two channels;
/// the channel count is accepted missing).
pub(super) fn parse_opus(value: &[u8]) -> Option<Pt> {
    let (pt, rest) = split_at_byte(value, b' ')?;
    let pt = pt_of(pt)?;
    let mut enc = rest.split(|&b| b == b'/');
    (enc.next()?.eq_ignore_ascii_case(b"opus") && enc.next()? == b"48000").then_some(pt)
}

/// `<pt> AMR/8000[/1]` or `<pt> AMR-WB/16000[/1]` (RFC 4867 §8.1): the
/// payload type and which one.
pub(super) fn parse_amr(value: &[u8]) -> Option<(Pt, Codec)> {
    let (pt, rest) = split_at_byte(value, b' ')?;
    let pt = pt_of(pt)?;
    let mut enc = rest.split(|&b| b == b'/');
    let (name, rate) = (enc.next()?, enc.next()?);
    if name.eq_ignore_ascii_case(b"AMR") && rate == b"8000" {
        Some((pt, Codec::Amr))
    } else if name.eq_ignore_ascii_case(b"AMR-WB") && rate == b"16000" {
        Some((pt, Codec::AmrWb))
    } else {
        None
    }
}

/// `<pt> <param>=<value>;…`: the AMR parameters that matter here,
/// `octet-align` and `mode-set` (RFC 4867 §8.1; names case-insensitive,
/// spaces around `;` allowed).
pub(super) fn parse_amr_fmtp(value: &[u8]) -> Option<AmrFmtp> {
    let (pt, rest) = split_at_byte(value, b' ')?;
    let pt = pt_of(pt)?;
    let mut f = AmrFmtp {
        pt,
        octet_align: false,
        mode_set: None,
    };
    for param in rest.split(|&b| b == b';') {
        let param = param.trim_ascii();
        let Some((name, v)) = split_at_byte(param, b'=') else {
            continue;
        };
        let (name, v) = (name.trim_ascii(), v.trim_ascii());
        if name.eq_ignore_ascii_case(b"octet-align") {
            f.octet_align = v == b"1";
        } else if name.eq_ignore_ascii_case(b"mode-set") {
            let mut set = 0u16;
            for m in v.split(|&b| b == b',') {
                let mode = decimal(m.trim_ascii(), 9)?;
                set |= 1u16.checked_shl(u32::try_from(mode).ok()?)?;
            }
            f.mode_set = Some(set);
        }
    }
    Some(f)
}

/// `<pt> telephone-event/<rate>[/…]` (the encoding name is
/// case-insensitive, RFC 8866 §6.6).
pub(super) fn parse_telephone_event(value: &[u8]) -> Option<(Pt, u32)> {
    let (pt, rest) = split_at_byte(value, b' ')?;
    let pt = pt_of(pt)?;
    let mut enc = rest.split(|&b| b == b'/');
    if !enc.next()?.eq_ignore_ascii_case(b"telephone-event") {
        return None;
    }
    let rate = u32::try_from(decimal(enc.next()?, 1 << 32)?).ok()?;
    (rate > 0).then_some((pt, rate))
}

/// One media-level `a=` line (`value` after `a=`) into `m`.
pub(super) fn read_attribute(m: &mut Media, rtcp_seen: &mut bool, value: &[u8]) {
    if value.starts_with(b"ice-ufrag:") {
        m.ice = true;
    } else if let Some(v) = value.strip_prefix(b"mid:") {
        m.mid = Mid::new(v);
    } else if value == b"bundle-only" {
        m.bundle_only = true;
    } else if let Some(v) = value.strip_prefix(b"ptime:") {
        // Whole milliseconds (a fraction, `20.0`, is cut).
        let whole = v.split(|&c| c == b'.').next().unwrap_or_default();
        m.ptime = decimal(whole, 1001).and_then(|p| u16::try_from(p).ok());
    } else if let Some(v) = value.strip_prefix(b"rtpmap:") {
        // Only for a format the m-line lists: an `a=rtpmap` of another
        // payload type offers nothing (RFC 8866 §6.6, RFC 3264 §5.1).
        let listed = |pt: Pt| m.payload_types.as_slice().contains(&pt);
        if m.telephone_event.is_none() {
            m.telephone_event = parse_telephone_event(v).filter(|&(pt, _)| listed(pt));
        }
        if m.opus.is_none() {
            m.opus = parse_opus(v).filter(|&pt| listed(pt));
        }
        match parse_amr(v) {
            Some((pt, Codec::Amr)) if m.amr.is_none() && listed(pt) => m.amr = Some(pt),
            Some((pt, Codec::AmrWb)) if m.amr_wb.is_none() && listed(pt) => m.amr_wb = Some(pt),
            _ => {}
        }
    } else if let Some(v) = value.strip_prefix(b"fmtp:") {
        if let Some(f) = parse_amr_fmtp(v)
            && let Some(slot) = m.amr_fmtp.iter_mut().find(|s| s.is_none())
        {
            *slot = Some(f);
        }
    } else if let Some(v) = value.strip_prefix(b"setup:") {
        m.setup = Setup::parse(v);
    } else if let Some(v) = value.strip_prefix(b"fingerprint:") {
        add_fingerprint(&mut m.fingerprints, v);
    } else if let Some(d) = Direction::parse(value) {
        m.direction = d;
    } else if value == b"rtcp-mux" {
        m.rtcp_mux = true;
    } else if value == b"rtcp" || value.starts_with(b"rtcp:") {
        // RFC 3605: the first a=rtcp counts; a malformed one is ignored like
        // any unusable attribute (RFC 8866 §5.13), leaving the default
        // port + 1.
        if !*rtcp_seen {
            *rtcp_seen = true;
            if let Some(port) = value.strip_prefix(b"rtcp:").and_then(parse_rtcp) {
                m.rtcp_port = port;
            }
        }
    } else if let Some(v) = value.strip_prefix(b"crypto:") {
        if let Some(c) = parse_crypto(v) {
            if m.crypto.is_none() {
                m.crypto = Some(c);
            }
            if let Some(slot) = m.cryptos.iter_mut().find(|s| s.is_none()) {
                *slot = Some(c);
            }
        }
        if let Some(c) = parse_crypto_declared(v)
            && let Some(slot) = m.declared.iter_mut().find(|s| s.is_none())
        {
            *slot = Some(c);
        }
    }
}

/// Check that `sdp` is a body the relay can rewrite and relay: it starts
/// with `v=` (RFC 8866 §5), and every media section with a port has a
/// `c=` line, its own or the session's (RFC 8866 §5.7). [`read_media`]
/// itself reads leniently; offers and answers are checked with this first.
///
/// # Errors
///
/// [`SdpError::NotSdp`] or [`SdpError::NoConnection`].
pub fn check_body(sdp: &[u8]) -> Result<(), SdpError> {
    let mut all = lines(sdp);
    if !all.next().is_some_and(|l| l.starts_with(b"v=")) {
        return Err(SdpError::NotSdp);
    }
    let mut session_c = false;
    // The current section: whether it has a port, and a c= line.
    let mut section: Option<(bool, bool)> = None;
    let unconnected = |s: Option<(bool, bool)>, session_c: bool| {
        s.is_some_and(|(port, c)| port && !c && !session_c)
    };
    for line in all {
        match line {
            [b'm', b'=', rest @ ..] => {
                if unconnected(section, session_c) {
                    return Err(SdpError::NoConnection);
                }
                // `<media> <port>[/<n>] ...`; a malformed port is
                // read_media's to refuse.
                let port = rest
                    .split(|&b| b == b' ')
                    .nth(1)
                    .and_then(|p| p.split(|&b| b == b'/').next())
                    .and_then(|p| decimal(p, 65_536))
                    .is_some_and(|p| p != 0);
                section = Some((port, false));
            }
            [b'c', b'=', ..] => match &mut section {
                Some((_, c)) => *c = true,
                None => session_c = true,
            },
            _ => {}
        }
    }
    if unconnected(section, session_c) {
        return Err(SdpError::NoConnection);
    }
    Ok(())
}

/// Read the media sections into `out`; returns how many there are.
///
/// # Errors
///
/// [`SdpError`] for malformed relevant lines or too many media sections.
pub fn read_media(sdp: &[u8], out: &mut [Media; MAX_MEDIA]) -> Result<usize, SdpError> {
    let mut session_addr = None;
    let mut session_ice = false;
    let mut session_setup = None;
    // A session-level direction attribute: the default of every section.
    let mut session_direction = Direction::SendRecv;
    let mut session_fps = [None; MAX_FINGERPRINTS];
    let mut n = 0;
    // (media, has seen an a=rtcp)
    let mut cur: Option<(Media, bool)> = None;
    let mut finish = |cur: &mut Option<(Media, bool)>,
                      n: &mut usize,
                      session_fps: [Option<Fingerprint>; MAX_FINGERPRINTS]|
     -> Result<(), SdpError> {
        if let Some((mut m, _)) = cur.take() {
            if m.fingerprints.iter().all(Option::is_none) {
                m.fingerprints = session_fps;
            }
            if *n == MAX_MEDIA {
                return Err(SdpError::TooManyMedia);
            }
            *out.get_mut(*n).ok_or(SdpError::TooManyMedia)? = m;
            // At most MAX_MEDIA (checked above).
            *n = n.wrapping_add(1);
        }
        Ok(())
    };
    for line in lines(sdp) {
        let (kind, value) = (line.first(), line.get(2..).unwrap_or_default());
        if line.get(1) != Some(&b'=') {
            continue;
        }
        match kind {
            Some(b'm') => {
                finish(&mut cur, &mut n, session_fps)?;
                let (port, transport, payload_types) = parse_m(value)?;
                cur = Some((
                    Media {
                        port,
                        address: session_addr,
                        // RTP + 1 (RFC 3550 §11); none above 65535.
                        rtcp_port: port.checked_add(1).ok_or(SdpError::Malformed)?,
                        rtcp_mux: false,
                        transport,
                        crypto: None,
                        cryptos: [None; MAX_CRYPTOS],
                        declared: [None; MAX_CRYPTOS],
                        ice: session_ice,
                        setup: session_setup,
                        fingerprints: [None; MAX_FINGERPRINTS],
                        mid: None,
                        bundle_only: false,
                        payload_types,
                        telephone_event: None,
                        opus: None,
                        amr: None,
                        amr_wb: None,
                        amr_fmtp: [None; 4],
                        direction: session_direction,
                        // Media level only (RFC 8866 §6.4).
                        ptime: None,
                    },
                    false,
                ));
            }
            Some(b'c') => {
                let a = parse_c(value)?;
                match &mut cur {
                    Some((m, _)) => m.address = a,
                    None => session_addr = a,
                }
            }
            Some(b'a') if cur.is_none() && value.starts_with(b"ice-ufrag:") => session_ice = true,
            Some(b'a') if cur.is_none() && Direction::parse(value).is_some() => {
                session_direction = Direction::parse(value).unwrap_or_default();
            }
            Some(b'a') if cur.is_none() && value.starts_with(b"setup:") => {
                session_setup = Setup::parse(value.get(6..).unwrap_or_default());
            }
            Some(b'a') if cur.is_none() && value.starts_with(b"fingerprint:") => {
                add_fingerprint(&mut session_fps, value.get(12..).unwrap_or_default());
            }
            Some(b'a') => {
                if let Some((m, rtcp_seen)) = &mut cur {
                    read_attribute(m, rtcp_seen, value);
                }
            }
            _ => {}
        }
    }
    finish(&mut cur, &mut n, session_fps)?;
    Ok(n)
}
