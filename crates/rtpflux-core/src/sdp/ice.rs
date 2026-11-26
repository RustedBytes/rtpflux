//! ICE in SDP: the `candidate` attribute (RFC 8839 §5.1) and the lines of
//! an `application/trickle-ice-sdpfrag` body (RFC 8840 §9.2).
//!
//! `candidate` values are split on single spaces; numbers are kept as
//! written (and parsed): foundation 1–32 ice-chars, component 1–3 digits
//! 1–256, transport a token, priority 1–10 digits 1 … 2^31 − 1, an address
//! of visible characters, port 1–5 digits below 65536, `typ` and a token,
//! then optional `raddr` and `rport` (in that order) and extension
//! name/value pairs (names other than raddr/rport; unknown ones ignored).

/// A parsed `a=candidate` value; the text fields are as written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate<'a> {
    pub foundation: &'a [u8],
    pub component_text: &'a [u8],
    pub component: u16,
    pub transport: &'a [u8],
    pub priority: u32,
    pub addr: &'a [u8],
    pub port_text: &'a [u8],
    pub port: u16,
    pub typ: &'a [u8],
    pub raddr: Option<&'a [u8]>,
    pub rport: Option<u16>,
}

impl Candidate<'_> {
    /// UDP (transport names are case-insensitive).
    #[must_use]
    pub fn is_udp(&self) -> bool {
        self.transport.eq_ignore_ascii_case(b"udp")
    }

    /// The same candidate for RFC 8840 §4.4: address, port, transport and
    /// component equal.
    #[must_use]
    pub fn same(&self, other: &Candidate<'_>) -> bool {
        self.addr == other.addr
            && self.port_text == other.port_text
            && self.transport.eq_ignore_ascii_case(other.transport)
            && self.component_text == other.component_text
    }
}

const fn ice_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'+' || c == b'/'
}

const fn token_char(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

fn token(w: &[u8]) -> bool {
    !w.is_empty() && w.iter().all(|&c| token_char(c))
}

fn vchar(w: &[u8]) -> bool {
    !w.is_empty() && w.iter().all(|&c| (0x21..=0x7e).contains(&c))
}

/// 1 to `max` digits; their value.
fn digits(w: &[u8], max: usize) -> Option<u64> {
    if w.is_empty() || w.len() > max || !w.iter().all(u8::is_ascii_digit) {
        return None;
    }
    w.iter().try_fold(0u64, |v, &d| {
        v.checked_mul(10)?
            .checked_add(u64::from(d.checked_sub(b'0')?))
    })
}

/// Parse an `a=candidate` value (after `candidate:`).
#[must_use]
pub fn parse_candidate(v: &[u8]) -> Option<Candidate<'_>> {
    let mut words = v.split(|&c| c == b' ');
    let foundation = words.next()?;
    let component_text = words.next()?;
    let transport = words.next()?;
    let priority = words.next()?;
    let addr = words.next()?;
    let port_text = words.next()?;
    if words.next()? != b"typ" {
        return None;
    }
    let typ = words.next()?;
    if foundation.is_empty() || foundation.len() > 32 || !foundation.iter().all(|&c| ice_char(c)) {
        return None;
    }
    let component = u16::try_from(digits(component_text, 3)?).ok()?;
    let priority = u32::try_from(digits(priority, 10)?).ok()?;
    let port = u16::try_from(digits(port_text, 5)?).ok()?;
    if !(1..=256).contains(&component)
        || !(1..=0x7fff_ffff).contains(&priority)
        || !token(transport)
        || !vchar(addr)
        || !token(typ)
    {
        return None;
    }
    let mut rest = words.peekable();
    let mut raddr = None;
    let mut rport = None;
    if rest.peek() == Some(&&b"raddr"[..]) {
        rest.next();
        let a = rest.next()?;
        if !vchar(a) {
            return None;
        }
        raddr = Some(a);
    }
    if rest.peek() == Some(&&b"rport"[..]) {
        rest.next();
        rport = Some(u16::try_from(digits(rest.next()?, 5)?).ok()?);
    }
    // Extensions: name/value pairs, ignored.
    while let Some(name) = rest.next() {
        let value = rest.next()?;
        if !token(name) || name == b"raddr" || name == b"rport" || !vchar(value) {
            return None;
        }
    }
    Some(Candidate {
        foundation,
        component_text,
        component,
        transport,
        priority,
        addr,
        port_text,
        port,
        typ,
        raddr,
        rport,
    })
}

/// One line of a trickle-ice-sdpfrag body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragLine<'a> {
    Ufrag(&'a [u8]),
    Pwd(&'a [u8]),
    EndOfCandidates,
    /// A pseudo `m=` line (its content is ignored).
    Media,
    Mid(&'a [u8]),
    Candidate(Candidate<'a>),
    /// Anything else, including an ungrammatical candidate: ignored.
    Other,
}

/// Classify a line (without its line end). Attribute names are matched
/// case-insensitively.
#[must_use]
pub fn frag_line(l: &[u8]) -> FragLine<'_> {
    if l.starts_with(b"m=") {
        return FragLine::Media;
    }
    let Some(rest) = l.strip_prefix(b"a=") else {
        return FragLine::Other;
    };
    match super::read::split_at_byte(rest, b':') {
        Some((name, value)) => {
            if name.eq_ignore_ascii_case(b"ice-ufrag") {
                FragLine::Ufrag(value)
            } else if name.eq_ignore_ascii_case(b"ice-pwd") {
                FragLine::Pwd(value)
            } else if name.eq_ignore_ascii_case(b"mid") {
                FragLine::Mid(value)
            } else if name.eq_ignore_ascii_case(b"candidate") {
                parse_candidate(value).map_or(FragLine::Other, FragLine::Candidate)
            } else {
                FragLine::Other
            }
        }
        None if rest.eq_ignore_ascii_case(b"end-of-candidates") => FragLine::EndOfCandidates,
        None => FragLine::Other,
    }
}

/// The lines of a body (CRLF or LF line ends).
pub fn frag_lines(body: &[u8]) -> impl Iterator<Item = FragLine<'_>> {
    body.split(|&c| c == b'\n')
        .map(|l| frag_line(l.strip_suffix(b"\r").unwrap_or(l)))
}

/// A media section's ICE as its SDP gives it (media-level values over
/// session-level ones, RFC 8839 §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionIce<'a> {
    pub ufrag: Option<&'a [u8]>,
    pub pwd: Option<&'a [u8]>,
    /// `a=ice-lite` (session level).
    pub lite: bool,
    /// `trickle` among the `a=ice-options`.
    pub trickle: bool,
    /// `a=end-of-candidates` (session or media level).
    pub end_of_candidates: bool,
    /// The section's lines (its `m=` line first).
    section: &'a [u8],
}

impl<'a> SectionIce<'a> {
    /// The section's `a=candidate` lines that are grammatical (RFC 8839
    /// §5.1), in order.
    pub fn candidates(&self) -> impl Iterator<Item = Candidate<'a>> {
        lines(self.section).filter_map(|l| {
            let v = l.strip_prefix(b"a=")?;
            let (name, value) = super::read::split_at_byte(v, b':')?;
            name.eq_ignore_ascii_case(b"candidate")
                .then(|| parse_candidate(value))
                .flatten()
        })
    }
}

fn lines(sdp: &[u8]) -> impl Iterator<Item = &[u8]> {
    sdp.split(|&c| c == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
}

/// What an attribute line says about ICE.
fn ice_attr<'a>(l: &'a [u8], ice: &mut SectionIce<'a>) {
    let Some(v) = l.strip_prefix(b"a=") else {
        return;
    };
    let (name, value) = match super::read::split_at_byte(v, b':') {
        Some((name, value)) => (name, Some(value)),
        None => (v, None),
    };
    match (name, value) {
        (n, Some(u)) if n.eq_ignore_ascii_case(b"ice-ufrag") => ice.ufrag = Some(u),
        (n, Some(p)) if n.eq_ignore_ascii_case(b"ice-pwd") => ice.pwd = Some(p),
        (n, None) if n.eq_ignore_ascii_case(b"ice-lite") => ice.lite = true,
        (n, None) if n.eq_ignore_ascii_case(b"end-of-candidates") => ice.end_of_candidates = true,
        (n, Some(o))
            if n.eq_ignore_ascii_case(b"ice-options")
                && o.split(|&c| c == b' ').any(|t| t == b"trickle") =>
        {
            ice.trickle = true;
        }
        _ => {}
    }
}

/// The ICE of media section `index` (counting `m=` lines from 0) of `sdp`.
#[must_use]
pub fn section_ice(sdp: &[u8], index: usize) -> Option<SectionIce<'_>> {
    let mut ice = SectionIce {
        ufrag: None,
        pwd: None,
        lite: false,
        trickle: false,
        end_of_candidates: false,
        section: &[],
    };
    // Session level, up to the first `m=` line.
    let mut at = 0;
    let mut m = 0;
    let mut start = None;
    for l in sdp.split_inclusive(|&c| c == b'\n') {
        let line = l.strip_suffix(b"\n").unwrap_or(l);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.starts_with(b"m=") {
            if start.is_some() {
                ice.section = sdp.get(start.unwrap_or(0)..at)?;
                return Some(ice);
            }
            if m == index {
                start = Some(at);
            }
            // At most one per line.
            m = m.wrapping_add(1);
        } else if m == 0 || start.is_some() {
            // Session lines, or this section's (they override).
            ice_attr(line, &mut ice);
        }
        // The lines' lengths add up to at most the SDP's.
        at = at.wrapping_add(l.len());
    }
    let start = start?;
    ice.section = sdp.get(start..)?;
    Some(ice)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates() {
        let c = parse_candidate(
            b"2 1 UDP 1694498815 192.0.2.3 5010 typ srflx raddr 192.0.2.1 rport 8998",
        )
        .unwrap();
        assert_eq!((c.component, c.priority, c.port), (1, 1_694_498_815, 5010));
        assert_eq!(
            (c.typ, c.raddr, c.rport),
            (&b"srflx"[..], Some(&b"192.0.2.1"[..]), Some(8998))
        );
        assert!(c.is_udp());
        let c =
            parse_candidate(b"1 1 UDP 2130706432 2001:db8:a0b:12f0::1 5000 typ host generation 0")
                .unwrap();
        assert_eq!(c.addr, b"2001:db8:a0b:12f0::1");
        for bad in [
            &b"1 0 UDP 1 192.0.2.1 9 typ host"[..],
            b"1 1 UDP 0 192.0.2.1 9 typ host",
            b"1 1 UDP 2147483648 192.0.2.1 9 typ host",
            b"1 1 UDP 1 192.0.2.1 65536 typ host",
            b"1 1 UDP 1 192.0.2.1 9 type host",
            b"1  1 UDP 1 192.0.2.1 9 typ host",
            b"1 1 UDP 1 192.0.2.1 9 typ host generation",
            b"1 1 UDP 1 192.0.2.1 9 typ srflx rport 1 raddr 192.0.2.2",
            b"f\xc3\xa9 1 UDP 1 192.0.2.1 9 typ host",
        ] {
            assert_eq!(parse_candidate(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn sections() {
        let sdp = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\na=ice-ufrag:sess\r\na=ice-pwd:sessionpasswordsessionpw\r\na=ice-options:trickle ice2\r\nt=0 0\r\nm=audio 5000 RTP/AVP 0\r\na=candidate:1 1 UDP 2130706431 192.0.2.1 5000 typ host\r\na=candidate:bad\r\nm=video 5002 RTP/AVP 96\r\na=ice-ufrag:vid1\r\na=candidate:2 1 UDP 2130706431 192.0.2.1 5002 typ host\r\na=candidate:3 1 UDP 1694498815 198.51.100.1 7000 typ srflx raddr 192.0.2.1 rport 5002\r\na=end-of-candidates\r\n";
        let a = section_ice(sdp, 0).unwrap();
        assert_eq!(
            (a.ufrag, a.lite, a.trickle, a.end_of_candidates),
            (Some(&b"sess"[..]), false, true, false)
        );
        assert_eq!(a.candidates().count(), 1);
        let v = section_ice(sdp, 1).unwrap();
        assert_eq!(v.ufrag, Some(&b"vid1"[..]));
        assert_eq!(v.pwd, Some(&b"sessionpasswordsessionpw"[..]));
        assert!(v.end_of_candidates);
        let mut c = v.candidates();
        assert_eq!(c.next().map(|c| c.port), Some(5002));
        assert_eq!(c.next().map(|c| c.typ), Some(&b"srflx"[..]));
        assert_eq!(c.next(), None);
        assert_eq!(section_ice(sdp, 2), None);
        let lite = section_ice(b"v=0\r\na=ice-lite\r\nm=audio 1 RTP/AVP 0\r\n", 0).unwrap();
        assert!(lite.lite && lite.ufrag.is_none());
    }

    #[test]
    fn fragment_lines() {
        let body = b"a=ICE-UFRAG:8hhY\r\na=ice-pwd:x\r\nm=audio 9 RTP/AVP 0\r\na=mid:1\r\na=end-of-candidates\r\na=x:y\r\n";
        let want = [
            FragLine::Ufrag(b"8hhY"),
            FragLine::Pwd(b"x"),
            FragLine::Media,
            FragLine::Mid(b"1"),
            FragLine::EndOfCandidates,
            FragLine::Other,
            FragLine::Other,
        ];
        assert!(frag_lines(body).eq(want));
    }
}
