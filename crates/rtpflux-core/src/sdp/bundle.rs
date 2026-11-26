//! BUNDLE groups (RFC 5888, RFC 8843): reading the offered group and
//! answering it.

#[allow(clippy::wildcard_imports)]
use super::*;

/// The identification tags of the first session-level `a=group:BUNDLE`
/// line (RFC 8843 §7.1), into `out`; returns how many.
#[must_use]
pub fn bundle_group(sdp: &[u8], out: &mut [Option<Mid>; MAX_MEDIA]) -> usize {
    for line in lines(sdp) {
        if line.starts_with(b"m=") {
            break;
        }
        // The semantics token is exactly BUNDLE (not `BUNDLEX`).
        if let Some(ids) = line
            .strip_prefix(b"a=group:BUNDLE")
            .filter(|rest| rest.is_empty() || rest.starts_with(b" "))
        {
            let mut n = 0;
            for id in ids.split(|&b| b == b' ').filter(|i| !i.is_empty()) {
                if let (Some(slot), Some(mid)) = (out.get_mut(n), Mid::new(id)) {
                    *slot = Some(mid);
                    // At most `out.len()` (`get_mut` above).
                    n = n.wrapping_add(1);
                }
            }
            return n;
        }
    }
    0
}

/// The answer's BUNDLE group (RFC 5888 §9: the offered group, without the
/// tags of refused media sections) into `out`; returns how many tags.
pub fn answer_group<'a>(offered: &[&'a [u8]], refused: &[&[u8]], out: &mut [&'a [u8]]) -> usize {
    let mut n = 0;
    for id in offered.iter().filter(|id| !refused.contains(id)) {
        if let Some(slot) = out.get_mut(n) {
            *slot = id;
            // At most `out.len()` (`get_mut` above).
            n = n.wrapping_add(1);
        }
    }
    n
}

/// Whether the relay passes on an `a=group` value (RFC 5888 §5:
/// `semantics *(SP identification-tag)`). The relay terminates each media
/// section's transport on its own ports and does not take part in BUNDLE
/// (RFC 8843), so like an answerer that does not understand it (RFC 5888
/// §9.4) it drops BUNDLE groups (and malformed lines); other groups (LS,
/// FID, …) concern the endpoints and pass unchanged.
#[must_use]
pub fn keeps_group(value: &[u8]) -> bool {
    let semantics = value.split(|&b| b == b' ').next().unwrap_or_default();
    !semantics.is_empty() && semantics != b"BUNDLE"
}
