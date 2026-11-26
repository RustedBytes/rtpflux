//! Trickled candidates (RFC 8840 §4.4, §9): an
//! `application/trickle-ice-sdpfrag` body and what it delivers.
//!
//! A body has session-level lines, then pseudo `m=` sections naming a
//! stream with `a=mid`. It is taken only when every part names the current
//! ICE generation (ice-ufrag and ice-pwd, media level over session level);
//! candidates already known for the stream (same address, port, transport,
//! component) and repeats within the body are dropped, the rest delivered
//! in order. An end-of-candidates before the first section ends every
//! stream; inside a section, its stream.

use rtpflux_core::sdp::ice::{Candidate, FragLine, frag_lines};

/// One pseudo `m=` section.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Section<'a> {
    pub mid: &'a [u8],
    pub ufrag: Option<&'a [u8]>,
    pub pwd: Option<&'a [u8]>,
    pub candidates: Vec<Candidate<'a>>,
    pub end_of_candidates: bool,
}

/// A parsed body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fragment<'a> {
    pub ufrag: Option<&'a [u8]>,
    pub pwd: Option<&'a [u8]>,
    /// End of all trickling.
    pub end_of_candidates: bool,
    pub sections: Vec<Section<'a>>,
}

impl<'a> Fragment<'a> {
    #[must_use]
    pub fn parse(body: &'a [u8]) -> Self {
        let mut f = Fragment::default();
        for l in frag_lines(body) {
            let cur = f.sections.last_mut();
            match (l, cur) {
                (FragLine::Media, _) => f.sections.push(Section::default()),
                (FragLine::Ufrag(v), None) => f.ufrag = Some(v),
                (FragLine::Ufrag(v), Some(s)) => s.ufrag = Some(v),
                (FragLine::Pwd(v), None) => f.pwd = Some(v),
                (FragLine::Pwd(v), Some(s)) => s.pwd = Some(v),
                (FragLine::EndOfCandidates, None) => f.end_of_candidates = true,
                (FragLine::EndOfCandidates, Some(s)) => s.end_of_candidates = true,
                (FragLine::Mid(v), Some(s)) => s.mid = v,
                (FragLine::Candidate(c), Some(s)) => s.candidates.push(c),
                _ => {}
            }
        }
        f
    }

    /// Every part names generation `(ufrag, pwd)`.
    #[must_use]
    pub fn current(&self, ufrag: &[u8], pwd: &[u8]) -> bool {
        let named = |u: Option<&[u8]>, p: Option<&[u8]>| u == Some(ufrag) && p == Some(pwd);
        if self.sections.is_empty() {
            return named(self.ufrag, self.pwd);
        }
        self.sections
            .iter()
            .all(|s| named(s.ufrag.or(self.ufrag), s.pwd.or(self.pwd)))
    }
}

/// What a section delivers to its stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery<'a> {
    pub mid: &'a [u8],
    pub candidates: Vec<Candidate<'a>>,
    pub end_of_candidates: bool,
}

/// Deliver `f` for generation `(ufrag, pwd)`, given the candidates already
/// known per stream: `None` when the body is for another generation;
/// otherwise the session-wide end-of-candidates and each section's
/// delivery.
#[must_use]
pub fn deliver<'a, 'k>(
    ufrag: &[u8],
    pwd: &[u8],
    known: impl Fn(&[u8]) -> Vec<Candidate<'k>>,
    f: &Fragment<'a>,
) -> Option<(bool, Vec<Delivery<'a>>)> {
    if !f.current(ufrag, pwd) {
        return None;
    }
    let sections = f
        .sections
        .iter()
        .map(|s| {
            let known = known(s.mid);
            let mut fresh: Vec<Candidate<'a>> = Vec::new();
            for c in &s.candidates {
                if !known.iter().any(|k| c.same(k)) && !fresh.iter().any(|k| c.same(k)) {
                    fresh.push(*c);
                }
            }
            Delivery {
                mid: s.mid,
                candidates: fresh,
                end_of_candidates: s.end_of_candidates || f.end_of_candidates,
            }
        })
        .collect();
    Some((f.end_of_candidates, sections))
}
