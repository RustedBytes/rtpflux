//! Codec transcoding offered and settled (`codec: transcode`, `codec:
//! mask`): which codec the relay offers the answerer besides the
//! offerer's, under which payload type, and from the answer whether it
//! transcodes and how the answer to the offerer changes.

use rtpflux_core::rtp::Pt;
use rtpflux_core::sdp::{Codec, FormatEdit};

/// Transcoding offered for a section: A's codec (and its payload type),
/// the codec offered to B in addition (and the payload type the relay
/// gives it), and whether A's codec is withheld from B (masked: B must
/// take the other one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecPlan {
    pub a_pt: Pt,
    pub a: Codec,
    pub b_pt: Pt,
    pub b: Codec,
    pub masked: bool,
    /// The bitrate of the relay's Opus encoder, whichever side it encodes
    /// for (`opus/48000/2/<bitrate>`).
    pub opus_bitrate: Option<u32>,
    /// The bitrate (an AMR mode) of the relay's AMR encoder towards A and
    /// towards B, each checked against that side's `mode-set`.
    pub amr_bitrate: [Option<u32>; 2],
}

/// The payload type the relay gives a dynamic codec (Opus, AMR) when it
/// adds it: 111 (Opus's usual one) unless the offer uses it, else the first
/// free dynamic one.
#[must_use]
pub fn free_dynamic_pt(formats: &[Pt]) -> Option<Pt> {
    core::iter::once(111)
        .chain(96..=127)
        .filter_map(Pt::new)
        .find(|pt| !formats.contains(pt))
}

/// The plan for an offer whose formats are `offer` (each with its codec,
/// if known), asked to transcode into `transcode` and to withhold the
/// codecs of `mask`: A's first codec the relay transcodes, and the wanted
/// one, if A does not offer it and this build has both
/// ([`crate::codec::supported`]).
#[must_use]
pub fn plan(
    offer: &[(Pt, Option<Codec>)],
    transcode: Option<Codec>,
    mask: &[Codec],
) -> Option<CodecPlan> {
    let formats: Vec<Pt> = offer.iter().map(|(pt, _)| *pt).collect();
    let (a_pt, a) = offer
        .iter()
        .find_map(|&(pt, c)| c.filter(|&c| crate::codec::supported(c)).map(|c| (pt, c)))?;
    let b = transcode.filter(|&c| c != a && crate::codec::supported(c))?;
    let b_pt = match b.static_pt() {
        Some(pt) if formats.contains(&pt) => return None,
        Some(pt) => pt,
        None if offer.iter().any(|&(_, c)| c == Some(b)) => return None,
        None => free_dynamic_pt(&formats)?,
    };
    Some(CodecPlan {
        a_pt,
        a,
        b_pt,
        b,
        masked: mask.contains(&a),
        opus_bitrate: None,
        amr_bitrate: [None; 2],
    })
}

impl CodecPlan {
    /// The format change towards B.
    #[must_use]
    pub fn towards_b(self) -> FormatEdit {
        if self.masked {
            FormatEdit::Replace(self.a_pt, self.b_pt)
        } else {
            FormatEdit::Append(self.b_pt)
        }
    }

    /// A's and B's codec with its payload type when it is a dynamic one
    /// (Opus, AMR): their `a=rtpmap` lines are written as such.
    #[must_use]
    pub fn dynamic(self) -> [Option<(Pt, Codec)>; 2] {
        [
            self.a.static_pt().is_none().then_some((self.a_pt, self.a)),
            self.b.static_pt().is_none().then_some((self.b_pt, self.b)),
        ]
    }

    /// What B sends, converted for A; and what A sends, for B.
    #[must_use]
    pub fn transcodes(self) -> (super::Transcode, super::Transcode) {
        let bitrate = |to: Codec, towards: usize| match to {
            Codec::Opus => self.opus_bitrate,
            Codec::Amr | Codec::AmrWb => self.amr_bitrate[towards],
            _ => None,
        };
        (
            super::Transcode {
                from: (self.b_pt, self.b),
                to: (self.a_pt, self.a),
                bitrate: bitrate(self.a, 0),
            },
            super::Transcode {
                from: (self.a_pt, self.a),
                to: (self.b_pt, self.b),
                bitrate: bitrate(self.b, 1),
            },
        )
    }
}

/// Settle `plan` from the answer's first format: the plan when B took
/// the codec only the relay offered (transcoding both ways), and the change
/// to the answer towards A (A's own codec back for the added one, or the
/// added one gone).
#[must_use]
pub fn settle(
    plan: Option<CodecPlan>,
    first: Option<Pt>,
) -> (Option<CodecPlan>, Option<FormatEdit>) {
    let xcode = plan.filter(|c| first == Some(c.b_pt));
    let toward_a = plan.map(|c| match xcode {
        Some(_) => FormatEdit::Replace(c.b_pt, c.a_pt),
        None => FormatEdit::Remove(c.b_pt),
    });
    (xcode, toward_a)
}
