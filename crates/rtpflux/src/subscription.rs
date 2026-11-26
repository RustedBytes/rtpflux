//! A subscription's decisions: which parties of a call are its sources,
//! and whether the subscriber's answer can be taken.

use rtpflux_core::rtp::Pt;

/// How a `subscribe request` names its sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pick<'a> {
    /// Flag `all`: every party of the call.
    All,
    /// `from-tags`.
    Tags(Vec<&'a [u8]>),
    /// `from-tag`.
    One(&'a [u8]),
    /// None of them.
    Missing,
}

/// Why no sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectError {
    /// The call has no dialogs.
    UnknownCall,
    /// No `from-tag` (nor `from-tags`, nor `all`).
    NoFromTag,
    /// The parties named are none.
    NoSource,
    /// No party of the call has this tag.
    UnknownTag(Vec<u8>),
}

/// The party tagged `tag` among the call's `dialogs` (from-tag, to-tag):
/// the first dialog that has it, and whether it is the answerer.
#[must_use]
pub fn find(dialogs: &[(&[u8], Option<&[u8]>)], tag: &[u8]) -> Option<(usize, bool)> {
    dialogs.iter().enumerate().find_map(|(k, (from, to))| {
        if *from == tag {
            Some((k, false))
        } else if *to == Some(tag) {
            Some((k, true))
        } else {
            None
        }
    })
}

/// The sources (dialog, answerer, tag) of a subscription to the call
/// whose dialogs are `dialogs`, sorted: the parties named, each once, in
/// the order named.
///
/// # Errors
///
/// [`SelectError`] when the call has no dialogs, nothing names a source,
/// or a tag is no party's.
pub fn select(
    dialogs: &[(&[u8], Option<&[u8]>)],
    pick: &Pick<'_>,
) -> Result<Vec<(usize, bool, Vec<u8>)>, SelectError> {
    if dialogs.is_empty() {
        return Err(SelectError::UnknownCall);
    }
    let tags: Vec<&[u8]> = match pick {
        Pick::All => dialogs
            .iter()
            .flat_map(|(from, to)| core::iter::once(*from).chain(*to))
            .collect(),
        Pick::Tags(t) => t.clone(),
        Pick::One(t) => vec![t],
        Pick::Missing => return Err(SelectError::NoFromTag),
    };
    if tags.is_empty() {
        return Err(SelectError::NoSource);
    }
    let mut out: Vec<(usize, bool, Vec<u8>)> = Vec::new();
    for tag in tags {
        let (k, b) = find(dialogs, tag).ok_or_else(|| SelectError::UnknownTag(tag.to_vec()))?;
        if !out.iter().any(|(_, _, t)| t == tag) {
            out.push((k, b, tag.to_vec()));
        }
    }
    Ok(out)
}

/// A copy offered to the subscriber: with DTLS-SRTP, with an SDES key,
/// its formats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offered<'a> {
    pub dtls: bool,
    pub key: bool,
    pub formats: &'a [Pt],
}

/// A section of the subscriber's answer: its port, DTLS-SRTP with a
/// fingerprint, SRTP with an SDES key, its formats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answered<'a> {
    pub port: u16,
    pub dtls: bool,
    pub sdes: bool,
    pub formats: &'a [Pt],
}

/// Why an answer section is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// DTLS-SRTP was offered and not taken.
    Dtls,
    /// SRTP with SDES was offered and not taken.
    Srtp,
    /// None of the offered formats (copies are not transcoded).
    Formats,
}

fn refusal(s: &Offered<'_>, a: &Answered<'_>) -> Option<Refusal> {
    if s.dtls && !a.dtls {
        Some(Refusal::Dtls)
    } else if s.key && !a.sdes {
        Some(Refusal::Srtp)
    } else if !s.formats.iter().any(|pt| a.formats.contains(pt)) {
        Some(Refusal::Formats)
    } else {
        None
    }
}

/// The subscriber's answer `answer` to the copies `offered`, section by
/// section: the sections to copy (answered and enabled), or the first one
/// refused (from 1) and why. Nothing is taken unless all are.
///
/// # Errors
///
/// The first section refused.
pub fn check_answer(
    offered: &[Offered<'_>],
    answer: &[Answered<'_>],
) -> Result<Vec<usize>, (usize, Refusal)> {
    let enabled: Vec<usize> = (0..offered.len())
        .filter(|&k| answer.get(k).is_some_and(|a| a.port != 0))
        .collect();
    for &k in &enabled {
        if let Some(r) = refusal(&offered[k], &answer[k]) {
            return Err((k + 1, r));
        }
    }
    Ok(enabled)
}
