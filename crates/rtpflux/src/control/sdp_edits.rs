//! The SDP edits a proxy asks for besides the relay's own (rtpengine's
//! options): `replace` (`username`, `session-name`, `sdp-version`,
//! `force-increment-sdp-version`), `sdp-attr`, and the flags
//! `strip-extmap`, `generate-mid`, `no-rtcp-attribute` and
//! `full-rtcp-attribute`.

use super::opts::words;
#[allow(clippy::wildcard_imports)]
use super::*;
use rtpflux_core::sdp::{AttrEdits, RtcpAttr, SessionEdits};

/// How the `o=` version is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VersionMode {
    /// As the sender wrote it.
    Input,
    /// `sdp-version`: the relay's own, raised when what the recipient
    /// gets changes.
    Changes,
    /// `force-increment-sdp-version`: raised every time.
    Always,
}

/// Attribute edits at one level, as the request names them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct Lists<'a> {
    add: Vec<&'a [u8]>,
    remove: Vec<&'a [u8]>,
    substitute: Vec<(&'a [u8], &'a [u8])>,
}

impl<'a> Lists<'a> {
    fn of(d: &Dict<'a>) -> Self {
        let mut l = Lists {
            add: super::args::strings_or_one(d.get(b"add")),
            remove: super::args::strings_or_one(d.get(b"remove")),
            substitute: Vec::new(),
        };
        if let Some(Value::List(pairs)) = d.get(b"substitute") {
            for p in &pairs {
                if let Value::List(p) = p {
                    let mut it = p.iter();
                    if let (Some(Value::Bytes(from)), Some(Value::Bytes(to))) =
                        (it.next(), it.next())
                    {
                        l.substitute.push((from, to));
                    }
                }
            }
        }
        l
    }

    fn edits(&self) -> AttrEdits<'_> {
        AttrEdits {
            add: &self.add,
            remove: &self.remove,
            substitute: &self.substitute,
        }
    }
}

/// The edits of one request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Independent edit switches.
pub(super) struct SdpEdits<'a> {
    username: bool,
    session_name: bool,
    /// `origin-full`: the whole `o=` line is the relay's, fixed per
    /// recipient (its version as with `sdp-version`).
    origin_full: bool,
    pub(super) version: VersionMode,
    /// Session level (`sdp-attr` key `global` or `none`).
    session: Lists<'a>,
    /// Per media kind (`audio`, `video`, …).
    kinds: Vec<(&'a [u8], Lists<'a>)>,
    generate_mid: bool,
    rtcp_attr: RtcpAttr,
}

/// `a=mid` values `generate-mid` gives sections without one.
const MIDS: [&[u8]; MAX_MEDIA] = [b"0", b"1", b"2", b"3", b"4", b"5", b"6", b"7"];

impl<'a> SdpEdits<'a> {
    pub(super) fn of(d: &Dict<'a>) -> Self {
        let flags = words(d.get(b"flags"));
        let flag = |f: &[u8]| flags.contains(&f);
        // `replace` items, and `replace-<item>` flags.
        let mut replace = words(d.get(b"replace"));
        replace.extend(flags.iter().filter_map(|f| f.strip_prefix(b"replace-")));
        let replaces = |r: &[u8]| replace.contains(&r);
        let mut session = Lists::default();
        let mut kinds: Vec<(&[u8], Lists<'a>)> = Vec::new();
        if let Some(Value::Dict(attrs)) = d.get(b"sdp-attr") {
            for (kind, v) in &attrs {
                let Value::Dict(v) = v else { continue };
                if kind == b"global" || kind == b"none" || kind == b"session" {
                    session = Lists::of(&v);
                } else {
                    kinds.push((kind, Lists::of(&v)));
                }
            }
        }
        if flag(b"strip-extmap") {
            session.remove.push(b"extmap");
            for kind in [&b"audio"[..], b"video", b"text", b"application"] {
                match kinds.iter_mut().find(|(k, _)| *k == kind) {
                    Some((_, l)) => l.remove.push(b"extmap"),
                    None => kinds.push((
                        kind,
                        Lists {
                            remove: vec![b"extmap"],
                            ..Lists::default()
                        },
                    )),
                }
            }
        }
        SdpEdits {
            username: replaces(b"username"),
            session_name: replaces(b"session-name"),
            origin_full: replaces(b"origin-full"),
            version: if replaces(b"force-increment-sdp-version")
                || flag(b"force-increment-sdp-version")
            {
                VersionMode::Always
            } else if replaces(b"sdp-version") || replaces(b"origin-full") {
                VersionMode::Changes
            } else {
                VersionMode::Input
            },
            session,
            kinds,
            generate_mid: flag(b"generate-mid"),
            rtcp_attr: if flag(b"no-rtcp-attribute") {
                RtcpAttr::Omit
            } else if flag(b"full-rtcp-attribute") {
                RtcpAttr::Full
            } else {
                RtcpAttr::AsInput
            },
        }
    }

    /// Add a session-level attribute (`loop protect`'s mark).
    pub(super) fn add_session(&mut self, value: &'a [u8]) {
        self.session.add.push(value);
    }

    /// The session-level edits, with the `o=` (version, session id).
    pub(super) fn session(&self, origin: Option<(u64, u64)>) -> SessionEdits<'_> {
        SessionEdits {
            username: self.username,
            session_name: self.session_name,
            version: origin.map(|(v, _)| v),
            origin: origin.filter(|_| self.origin_full).map(|(_, s)| s),
            attrs: self.session.edits(),
        }
    }

    /// Apply the section-level edits to `relayed` (the sections of `sdp`
    /// in order); `offer`: an offer, where `generate-mid` applies.
    pub(super) fn apply<'r>(
        &'r self,
        sdp: &[u8],
        media: &[Media],
        relayed: &mut [Relayed<'r>],
        offer: bool,
    ) {
        let kinds = section_kinds(sdp);
        for (i, r) in relayed.iter_mut().enumerate() {
            if self.rtcp_attr != RtcpAttr::AsInput {
                r.rtcp_attr = self.rtcp_attr;
            }
            if let Some((_, l)) = kinds
                .get(i)
                .and_then(|k| self.kinds.iter().find(|(kind, _)| kind == k))
            {
                r.attrs = l.edits();
            }
            let taken = |mid: &[u8]| {
                media
                    .iter()
                    .any(|m| m.mid.as_ref().is_some_and(|x| x.as_bytes() == mid))
            };
            if offer
                && self.generate_mid
                && r.mid.is_none()
                && media.get(i).is_some_and(|m| m.mid.is_none() && m.port != 0)
                && let Some(&mid) = MIDS.get(i).filter(|m| !taken(m))
            {
                r.mid = Some(mid);
            }
        }
    }
}

/// The media kind (`audio`, `video`, …) of each section of `sdp`.
fn section_kinds(sdp: &[u8]) -> Vec<&[u8]> {
    sdp.split(|&c| c == b'\n')
        .filter_map(|l| l.strip_prefix(b"m="))
        .map(|l| l.split(|&c| c == b' ').next().unwrap_or_default())
        .collect()
}

/// A digest of an SDP, for `sdp-version`: whether what a party gets
/// changed.
pub(super) fn digest(sdp: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    sdp.hash(&mut h);
    h.finish()
}

/// The `o=` versions the relay set (`sdp-version`): per recipient (its
/// tag; `None`: the answerer before its answer), the version and the
/// digest of what it got.
pub(super) type Versions = Vec<(Option<Vec<u8>>, u64, u64, u64)>;

/// The `o=` version (and session id, fixed at the first) to send
/// `recipient`, whose SDP rendered with them fixed has digest `digest`;
/// `input`: the sender's (session id, version).
pub(super) fn next_version(
    versions: &mut Versions,
    recipient: Option<&[u8]>,
    mode: VersionMode,
    (input_sess, input): (u64, u64),
    digest: u64,
) -> Option<(u64, u64)> {
    if mode == VersionMode::Input {
        return None;
    }
    let entry = versions
        .iter_mut()
        .find(|(t, ..)| t.as_deref() == recipient);
    if let Some((_, v, d, sess)) = entry {
        if mode == VersionMode::Always || *d != digest {
            *v = v.wrapping_add(1);
            *d = digest;
        }
        return Some((*v, *sess));
    }
    let v = if mode == VersionMode::Always {
        input.wrapping_add(1)
    } else {
        input
    };
    versions.push((recipient.map(<[u8]>::to_vec), v, digest, input_sess));
    Some((v, input_sess))
}

/// The answerer's tag is known: its versions were kept under `None`.
pub(super) fn name_answerer(versions: &mut Versions, tag: &[u8]) {
    if let Some(e) = versions.iter_mut().find(|(t, ..)| t.is_none()) {
        e.0 = Some(tag.to_vec());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_rise_when_the_sdp_changes() {
        let mut v = Versions::new();
        let n = |v: &mut Versions, r: Option<&[u8]>, m, d| {
            next_version(v, r, m, (42, 7), d).map(|(v, _)| v)
        };
        assert_eq!(n(&mut v, None, VersionMode::Input, 1), None);
        assert_eq!(
            n(&mut v, None, VersionMode::Changes, 1),
            Some(7),
            "the sender's first"
        );
        assert_eq!(
            n(&mut v, None, VersionMode::Changes, 1),
            Some(7),
            "unchanged"
        );
        assert_eq!(n(&mut v, None, VersionMode::Changes, 2), Some(8), "changed");
        name_answerer(&mut v, b"bob");
        assert_eq!(n(&mut v, Some(b"bob"), VersionMode::Changes, 2), Some(8));
        assert_eq!(
            n(&mut v, Some(b"alice"), VersionMode::Changes, 5),
            Some(7),
            "per party"
        );
        assert_eq!(n(&mut v, Some(b"bob"), VersionMode::Always, 2), Some(9));
        assert_eq!(n(&mut v, Some(b"carol"), VersionMode::Always, 2), Some(8));
        // The session id stays the first one's.
        assert_eq!(
            next_version(&mut v, Some(b"bob"), VersionMode::Changes, (99, 1), 2),
            Some((9, 42))
        );
    }
}
