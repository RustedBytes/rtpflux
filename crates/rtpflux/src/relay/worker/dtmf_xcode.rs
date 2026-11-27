//! DTMF transcoding (rtpengine's): telephone events (RFC 4733) from one
//! side become in-band tones in the other side's G.711 audio, and in-band
//! tones in one side's G.711 audio become telephone events for the other.
//!
//! Both directions play a live key towards the other side with the tone
//! player ([`super::tones`]): it starts when the key does and ends when it
//! is released, and the source's own audio to the other side is held back
//! meanwhile (as rtpengine suppresses audio during DTMF). Event packets that
//! become tones are not relayed.

#[allow(clippy::wildcard_imports)]
use super::*;
use crate::relay::DtmfXcode;
use rtpflux_core::dtmf_inband::{Change, Detector, FRAME};

/// Samples decoded from one packet, at most (120 ms at 16 kHz and more).
pub(super) const MAX_PCM: usize = 2880;

/// Per RTP slot whose side's DTMF is transcoded.
#[derive(Debug, Default)]
pub(super) struct XcodeState {
    pub(super) x: Option<DtmfXcode>,
    detector: Detector,
    /// The incoming events being played as tones.
    events: crate::relay::xcode::EventTones,
    /// The side's audio in a codec other than G.711: decoded to 8 kHz to
    /// look for its tones.
    audio_in: Option<Box<AudioIn>>,
}

/// A decoder to 8 kHz PCM (made when the call is set up: none on the
/// packet path).
#[derive(Debug)]
pub(super) struct AudioIn {
    decoder: crate::codec::Decoder,
    down: Option<crate::codec::Resampler>,
    wide: Box<[i16]>,
}

impl AudioIn {
    pub(super) fn new(codec: crate::relay::Codec) -> Option<Box<Self>> {
        use crate::relay::Codec;
        if matches!(codec, Codec::Pcmu | Codec::Pcma) {
            return None;
        }
        // Opus decodes at 8 kHz itself; a wideband codec is brought down.
        let decoder = crate::codec::Decoder::new(codec, 8000)?;
        let down = match decoder.rate() {
            8000 => None,
            rate => Some(crate::codec::Resampler::new(rate, 8000)?),
        };
        Some(Box::new(AudioIn {
            decoder,
            down,
            wide: vec![0; MAX_PCM].into_boxed_slice(),
        }))
    }

    /// Decode `payload` to 8 kHz into `out`: the samples written.
    pub(super) fn decode(&mut self, payload: &[u8], out: &mut [i16]) -> Option<usize> {
        let n = self.decoder.decode(payload, &mut self.wide)?;
        match &mut self.down {
            None => {
                let n = n.min(out.len());
                out[..n].copy_from_slice(&self.wide[..n]);
                Some(n)
            }
            Some(down) => down.process(&self.wide[..n], out),
        }
    }
}

impl XcodeState {
    pub(super) fn new(x: DtmfXcode) -> Self {
        XcodeState {
            x: Some(x),
            audio_in: x.audio.and_then(|(_, codec)| AudioIn::new(codec)),
            ..XcodeState::default()
        }
    }
}

impl Worker {
    /// Telephone events and DTMF transcoding for the RTP packet at
    /// `bufs[at..at + len]` from slot `leg` (relayed as `decision`): true
    /// when it is consumed.
    pub(super) fn dtmf_in(
        &mut self,
        leg: Slot,
        decision: Decision,
        (at, len): (usize, usize),
        now: u64,
    ) -> bool {
        if leg.is_rtcp() || matches!(decision, Decision::Drop(_)) {
            return false;
        }
        if let Some(Some(d)) = self.dtmf.get_mut(leg) {
            d.packet(&self.bufs[at..at + len], now, leg);
            if d.unsent_any() {
                let finished = d.take_unsent();
                self.report_dtmf(leg, finished);
            }
        }
        // DTMF security first: what it lets through (or rewrites) may be
        // transcoded then.
        if self.secured(leg) && self.dtmf_secure(leg, (at, len), now) {
            return true;
        }
        self.xcode.get(leg).is_some_and(Option::is_some) && self.dtmf_xcode(leg, (at, len))
    }

    /// The RTP packet at `bufs[at..at + len]` from slot `leg`: converted as
    /// its side's DTMF transcoding says. True when it is consumed (an event
    /// played as tones: not relayed).
    pub(super) fn dtmf_xcode(&mut self, leg: Slot, (at, len): (usize, usize)) -> bool {
        let Some(Some(st)) = self.xcode.get(leg) else {
            return false;
        };
        let Some(x) = st.x else {
            return false;
        };
        let Some(partner) = self.legs.get(leg).copied().flatten().map(|l| l.partner) else {
            return false;
        };
        let Some(call) = self.call_of(leg) else {
            return false;
        };
        let Ok(p) = rtpflux_core::rtp::Packet::parse(&self.bufs[at..at + len]) else {
            return false;
        };
        let (pt, ts) = (p.payload_type(), p.timestamp());
        let event_pt = self.dtmf.get(leg).and_then(Option::as_ref).map(|d| d.pt);
        // This side's events: tones for the other.
        if let (Some(law), Some(ept)) = (x.to_inband, event_pt)
            && pt == ept
        {
            let payload = p.payload();
            if payload.len() < 4 {
                return true;
            }
            let (code, end, volume) = (payload[0], payload[1] & 0x80 != 0, payload[1] & 0x3f);
            let Some(Some(st)) = self.xcode.get_mut(leg) else {
                return true;
            };
            let (start, ends) = st.events.packet(ts, code, end);
            if let Some(code) = start {
                self.live_tone_start(
                    call,
                    partner,
                    leg,
                    code,
                    volume,
                    ToneMode::Inband {
                        pt: law.0,
                        codec: law.1,
                    },
                );
            }
            if ends {
                self.live_tone_end(partner);
            }
            return true;
        }
        // This side's in-band tones: events for the other. G.711 is read
        // as it is; another codec (its audio's) is decoded to 8 kHz first.
        let law = pt == rtpflux_core::g711::PT_PCMU || pt == rtpflux_core::g711::PT_PCMA;
        let coded = x.audio.is_some_and(|(apt, _)| apt == pt) && !law;
        if let Some((ept, rate)) = x.to_events
            && (law || coded)
        {
            let payload = p.payload();
            let Some(Some(st)) = self.xcode.get_mut(leg) else {
                return false;
            };
            let mut pcm = [0i16; MAX_PCM];
            let n = if law {
                let n = payload.len().min(MAX_PCM);
                for (o, &c) in pcm.iter_mut().zip(&payload[..n]) {
                    *o = if pt == rtpflux_core::g711::PT_PCMA {
                        rtpflux_core::g711::alaw_to_linear(c)
                    } else {
                        rtpflux_core::g711::ulaw_to_linear(c)
                    };
                }
                n
            } else {
                st.audio_in
                    .as_mut()
                    .and_then(|a| a.decode(payload, &mut pcm))
                    .unwrap_or(0)
            };
            let mut changes = [None; MAX_PCM / FRAME];
            for (k, chunk) in pcm[..n].chunks(FRAME).enumerate() {
                changes[k] = st.detector.frame(chunk);
            }
            for c in changes.into_iter().flatten() {
                match c {
                    Change::Start(code) => {
                        self.live_tone_start(
                            call,
                            partner,
                            leg,
                            code,
                            10,
                            ToneMode::Event { pt: ept, rate },
                        );
                    }
                    Change::End => self.live_tone_end(partner),
                }
            }
        }
        false
    }
}
