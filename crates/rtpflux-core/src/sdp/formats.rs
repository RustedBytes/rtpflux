//! Formats by name: the encoding of a payload type in a media section, and
//! rtpengine's `codec` options `strip`, `except` and `offer`, which choose
//! the offerer's formats the answerer is offered.

#[allow(clippy::wildcard_imports)]
use super::*;

/// The static payload types of RFC 3551 (Tables 4 and 5): encoding name and
/// clock rate, for a section without an `a=rtpmap` for them.
const STATIC: [(u8, &[u8], u32); 24] = [
    (0, b"PCMU", 8000),
    (3, b"GSM", 8000),
    (4, b"G723", 8000),
    (5, b"DVI4", 8000),
    (6, b"DVI4", 16_000),
    (7, b"LPC", 8000),
    (8, b"PCMA", 8000),
    (9, b"G722", 8000),
    (10, b"L16", 44_100),
    (11, b"L16", 44_100),
    (12, b"QCELP", 8000),
    (13, b"CN", 8000),
    (14, b"MPA", 90_000),
    (15, b"G728", 8000),
    (16, b"DVI4", 11_025),
    (17, b"DVI4", 22_050),
    (18, b"G729", 8000),
    (25, b"CelB", 90_000),
    (26, b"JPEG", 90_000),
    (28, b"nv", 90_000),
    (31, b"H261", 90_000),
    (32, b"MPV", 90_000),
    (33, b"MP2T", 90_000),
    (34, b"H263", 90_000),
];

/// The encoding name and clock rate of payload type `pt` in media section
/// `index` (from 0) of `sdp`: its `a=rtpmap`, or the static assignment.
#[must_use]
pub fn format_name(sdp: &[u8], index: usize, pt: Pt) -> Option<(&[u8], u32)> {
    let mut section = None::<usize>;
    for line in lines(sdp) {
        if line.starts_with(b"m=") {
            // Stops past `index`: no overflow.
            section = Some(section.map_or(0, |s| s.saturating_add(1)));
            if section > Some(index) {
                break;
            }
            continue;
        }
        if section != Some(index) {
            continue;
        }
        let Some(rest) = line.strip_prefix(b"a=rtpmap:") else {
            continue;
        };
        let mut f = rest.splitn(2, |&c| c == b' ');
        if f.next().and_then(read::pt_of) != Some(pt) {
            continue;
        }
        let enc = f.next()?;
        let mut parts = enc.split(|&c| c == b'/');
        let name = parts.next()?;
        let clock = parts
            .next()
            .and_then(|c| decimal(c, u64::from(u32::MAX) + 1))
            .and_then(|c| u32::try_from(c).ok())?;
        return Some((name, clock));
    }
    STATIC
        .iter()
        .find(|&&(p, ..)| p == pt.get())
        .map(|&(_, name, clock)| (name, clock))
}

/// Whether a format named `name` at `clock` Hz is the one `spec` names:
/// an encoding name (case-insensitive), optionally `/<clock rate>` (and a
/// channel count, not compared), as `opus`, `opus/48000` or
/// `opus/48000/2`.
#[must_use]
pub fn format_matches(name: &[u8], clock: u32, spec: &[u8]) -> bool {
    let mut parts = spec.split(|&c| c == b'/');
    let spec_name = parts.next().unwrap_or_default();
    if !spec_name.eq_ignore_ascii_case(name) {
        return false;
    }
    match parts.next() {
        None => true,
        Some(c) => decimal(c, u64::from(u32::MAX) + 1) == Some(u64::from(clock)),
    }
}

/// rtpengine's `codec` options that choose formats: `strip` removes the
/// formats it names (`all`: every format), `except` and `offer` keep the
/// formats they name whatever `strip` says, and `offer` also puts its
/// formats first, in its order.
#[derive(Debug, Clone, Copy, Default)]
pub struct FormatFilter<'a> {
    pub strip: &'a [&'a [u8]],
    pub except: &'a [&'a [u8]],
    pub offer: &'a [&'a [u8]],
}

impl FormatFilter<'_> {
    /// Whether the filter changes anything.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.strip.is_empty() && self.except.is_empty() && self.offer.is_empty()
    }
}

/// The formats of media section `index` of `sdp` (its payload types
/// `offered`, in order) that `filter` keeps, in the order the answerer is
/// offered them.
#[must_use]
pub fn select(sdp: &[u8], index: usize, offered: &[Pt], filter: &FormatFilter<'_>) -> PayloadTypes {
    let named = |pt: Pt, specs: &[&[u8]]| {
        format_name(sdp, index, pt)
            .is_some_and(|(name, clock)| specs.iter().any(|s| format_matches(name, clock, s)))
    };
    let all = filter.strip.iter().any(|s| s.eq_ignore_ascii_case(b"all"));
    let kept = |pt: Pt| {
        !(all || named(pt, filter.strip)) || named(pt, filter.except) || named(pt, filter.offer)
    };
    let mut out = PayloadTypes::EMPTY;
    for spec in filter.offer {
        for &pt in offered {
            if !out.as_slice().contains(&pt) && named(pt, core::slice::from_ref(spec)) {
                out.push(pt);
            }
        }
    }
    for &pt in offered {
        if !out.as_slice().contains(&pt) && kept(pt) {
            out.push(pt);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SDP: &[u8] = b"v=0\r\n\
        m=audio 4000 RTP/AVP 0 8 96 101 13\r\n\
        a=rtpmap:96 opus/48000/2\r\n\
        a=rtpmap:101 telephone-event/8000\r\n\
        m=video 4002 RTP/AVP 96\r\n\
        a=rtpmap:96 VP8/90000\r\n";

    /// The payload types `select` keeps, as numbers (at most 8).
    fn sel<const N: usize>(
        index: usize,
        offered: [u8; N],
        f: FormatFilter<'_>,
    ) -> ([u8; 8], usize) {
        let pts = offered.map(|p| Pt::new(p).unwrap());
        let got = select(SDP, index, &pts, &f);
        let mut out = [0; 8];
        for (o, p) in out.iter_mut().zip(got.as_slice()) {
            *o = p.get();
        }
        (out, got.as_slice().len())
    }

    fn is(got: ([u8; 8], usize), want: &[u8]) -> bool {
        &got.0[..got.1] == want
    }

    #[test]
    fn names_from_rtpmap_or_the_static_table() {
        let p = |v| Pt::new(v).unwrap();
        assert_eq!(format_name(SDP, 0, p(96)), Some((&b"opus"[..], 48_000)));
        assert_eq!(format_name(SDP, 1, p(96)), Some((&b"VP8"[..], 90_000)));
        assert_eq!(format_name(SDP, 0, p(8)), Some((&b"PCMA"[..], 8000)));
        assert_eq!(format_name(SDP, 0, p(13)), Some((&b"CN"[..], 8000)));
        assert_eq!(format_name(SDP, 0, p(100)), None, "dynamic, no rtpmap");
        assert_eq!(format_name(SDP, 5, p(96)), None, "no such section");
        assert_eq!(
            format_name(b"m=audio 1 RTP/AVP 96\r\na=rtpmap:96 x\r\n", 0, p(96)),
            None,
            "no clock rate"
        );
        assert!(format_matches(b"opus", 48_000, b"OPUS"));
        assert!(format_matches(b"opus", 48_000, b"opus/48000/2"));
        assert!(!format_matches(b"opus", 48_000, b"opus/16000"));
        assert!(!format_matches(b"opus", 48_000, b"opus/x"));
        assert!(!format_matches(b"PCMA", 8000, b"PCM"));
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One case per option.
    fn strip_except_and_offer() {
        let all = [&b"all"[..]];
        let offered: [u8; 5] = [0, 8, 96, 101, 13];
        assert!(is(sel(0, offered, FormatFilter::default()), &offered));
        let strip = [&b"PCMU"[..], b"CN"];
        assert!(is(
            sel(
                0,
                offered,
                FormatFilter {
                    strip: &strip,
                    ..Default::default()
                }
            ),
            &[8, 96, 101]
        ));
        let except = [&b"opus"[..], b"telephone-event"];
        assert!(is(
            sel(
                0,
                offered,
                FormatFilter {
                    strip: &all,
                    except: &except,
                    ..Default::default()
                }
            ),
            &[96, 101]
        ));
        let offer = [&b"opus/48000"[..], b"PCMA"];
        assert!(
            is(
                sel(
                    0,
                    offered,
                    FormatFilter {
                        offer: &offer,
                        ..Default::default()
                    }
                ),
                &[96, 8, 0, 101, 13]
            ),
            "offer reorders, keeps the rest"
        );
        assert!(is(
            sel(
                0,
                offered,
                FormatFilter {
                    strip: &all,
                    offer: &offer,
                    ..Default::default()
                }
            ),
            &[96, 8]
        ));
        let g729 = [&b"G729"[..]];
        assert!(
            is(
                sel(
                    0,
                    offered,
                    FormatFilter {
                        offer: &g729,
                        ..Default::default()
                    }
                ),
                &offered
            ),
            "a codec not offered is not added"
        );
        assert!(is(
            sel(
                0,
                offered,
                FormatFilter {
                    strip: &all,
                    ..Default::default()
                }
            ),
            &[]
        ));
        // Per section: video's 96 is VP8.
        let vp8 = [&b"VP8"[..]];
        assert!(is(
            sel(
                1,
                [96],
                FormatFilter {
                    strip: &vp8,
                    ..Default::default()
                }
            ),
            &[]
        ));
        assert!(is(
            sel(
                0,
                offered,
                FormatFilter {
                    strip: &vp8,
                    ..Default::default()
                }
            ),
            &offered
        ));
    }
}
