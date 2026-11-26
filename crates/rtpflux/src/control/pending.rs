//! What a section's offer decided for its answer, in the state file
//! ([`state::SavedPending`]): so an answer that comes after a restart is
//! handled as it would have been (the relay's keys offered to B,
//! opportunistic SRTP, `rtcp-mux` and DTLS roles, `ptime`, transcoding,
//! telephone events, ICE passed through).

use super::media::MediaState;
use super::opts::{MuxPolicy, Passthrough};
use crate::relay::codecs::CodecPlan;
use crate::relay::xcode;
use crate::state::{self, SavedCodecPlan, SavedPending};
use rtpflux_core::dtls::Setup;
use rtpflux_core::rtp::Pt;
use rtpflux_core::sdp::{Codec, Crypto, FormatEdit};

const MUX: [(MuxPolicy, &str); 6] = [
    (MuxPolicy::Default, ""),
    (MuxPolicy::Offer, "offer"),
    (MuxPolicy::Require, "require"),
    (MuxPolicy::Demux, "demux"),
    (MuxPolicy::Accept, "accept"),
    (MuxPolicy::Reject, "reject"),
];

fn edit_of(e: FormatEdit) -> (String, u8, Option<u8>) {
    match e {
        FormatEdit::Replace(a, b) => ("replace".to_owned(), a.get(), Some(b.get())),
        FormatEdit::Remove(a) => ("remove".to_owned(), a.get(), None),
        FormatEdit::Append(a) => ("append".to_owned(), a.get(), None),
    }
}

fn edit_from((op, a, b): &(String, u8, Option<u8>)) -> Option<FormatEdit> {
    let a = Pt::new(*a)?;
    Some(match op.as_str() {
        "replace" => FormatEdit::Replace(a, Pt::new((*b)?)?),
        "remove" => FormatEdit::Remove(a),
        "append" => FormatEdit::Append(a),
        _ => return None,
    })
}

fn codec_of(c: &CodecPlan) -> SavedCodecPlan {
    SavedCodecPlan {
        a_pt: c.a_pt.get(),
        a: c.a.name().to_owned(),
        b_pt: c.b_pt.get(),
        b: c.b.name().to_owned(),
        masked: c.masked,
        opus_bitrate: c.opus_bitrate,
        amr_bitrate: c.amr_bitrate,
    }
}

fn codec_from(c: &SavedCodecPlan) -> Option<CodecPlan> {
    Some(CodecPlan {
        a_pt: Pt::new(c.a_pt)?,
        a: Codec::from_name(c.a.as_bytes())?,
        b_pt: Pt::new(c.b_pt)?,
        b: Codec::from_name(c.b.as_bytes())?,
        masked: c.masked,
        opus_bitrate: c.opus_bitrate,
        amr_bitrate: c.amr_bitrate,
    })
}

impl MediaState {
    /// What to save of the offer's decisions; `None` when there is
    /// nothing besides the defaults.
    pub(super) fn pending(&self) -> Option<SavedPending> {
        let p = SavedPending {
            b_alt: self
                .b_alt
                .iter()
                .flatten()
                .map(|c| (c.tag, state::key_text(&c.key)))
                .collect(),
            osrtp_a: self
                .osrtp
                .a
                .map(|(c, k)| (c.tag, state::key_text(&c.key), state::key_text(&k))),
            osrtp_b: self.osrtp.b.as_ref().map(state::key_text),
            // As the state file has it: whether relays are dropped.
            passthrough: self.passthrough.map(|p| p == Passthrough::DropRelays),
            mux_policy: MUX
                .iter()
                .find(|(m, _)| *m == self.mux_policy)
                .map_or("", |(_, n)| n)
                .to_owned(),
            b_setup: self.b_setup.name().to_owned(),
            a_actpass: self.a_actpass,
            ptime: self.ptime,
            codec: self.codec.as_ref().map(codec_of),
            a_formats: self.a_formats.map(edit_of),
            te_toward_a: self.te_toward_a.map(edit_of),
            dtmf_plan: self.dtmf_plan.map(|p| match p {
                xcode::Plan::Offered(pt) => (pt.get(), None),
                xcode::Plan::Kept(pt, rate) => (pt.get(), Some(rate)),
            }),
        };
        // As restored without it.
        let default = SavedPending {
            b_setup: Setup::Actpass.name().to_owned(),
            a_actpass: true,
            ..SavedPending::default()
        };
        (p != default).then_some(p)
    }

    /// Set the saved decisions `p` again; a field that does not read back
    /// keeps the restored default.
    pub(super) fn restore_pending(&mut self, p: &SavedPending) {
        for (slot, (tag, key)) in self.b_alt.iter_mut().zip(&p.b_alt) {
            *slot = state::key_of(key).map(|key| Crypto { tag: *tag, key });
        }
        self.osrtp.a = p.osrtp_a.as_ref().and_then(|(tag, theirs, ours)| {
            Some((
                Crypto {
                    tag: *tag,
                    key: state::key_of(theirs)?,
                },
                state::key_of(ours)?,
            ))
        });
        self.osrtp.b = p.osrtp_b.as_deref().and_then(state::key_of);
        self.passthrough = p.passthrough.map(|drop| {
            if drop {
                Passthrough::DropRelays
            } else {
                Passthrough::KeepRelays
            }
        });
        if let Some((m, _)) = MUX.iter().find(|(_, n)| *n == p.mux_policy) {
            self.mux_policy = *m;
        }
        if let Some(s) = Setup::parse(p.b_setup.as_bytes()) {
            self.b_setup = s;
        }
        self.a_actpass = p.a_actpass;
        self.ptime = p.ptime;
        self.codec = p.codec.as_ref().and_then(codec_from);
        self.a_formats = p.a_formats.as_ref().and_then(edit_from);
        self.te_toward_a = p.te_toward_a.as_ref().and_then(edit_from);
        self.dtmf_plan = p.dtmf_plan.and_then(|(pt, rate)| {
            let pt = Pt::new(pt)?;
            Some(match rate {
                None => xcode::Plan::Offered(pt),
                Some(r) => xcode::Plan::Kept(pt, r),
            })
        });
    }
}
