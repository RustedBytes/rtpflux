//! Telephone-event detection on a leg (RFC 4733), with the events kept
//! for `query`.

#[allow(clippy::wildcard_imports)]
use super::*;
use rtpflux_core::rtp::Pt;

/// Telephone-event detection on one RTP leg.
pub(super) struct DtmfLeg {
    pub(super) pt: Pt,
    pub(super) rate: u32,
    pub(super) detector: Detector,
    /// When the last report arrived (worker ms) and the reported end of
    /// the event then (timestamp units): the stream's clock for timeouts.
    pub(super) last_ms: u64,
    pub(super) last_end: u64,
    pub(super) events: Vec<DtmfEvent>,
}

/// Events kept per leg for `query`.
pub(super) const MAX_DTMF_EVENTS: usize = 256;

impl DtmfLeg {
    pub(super) fn new(pt: Pt, rate: u32) -> Box<Self> {
        Box::new(DtmfLeg {
            pt,
            rate,
            // RFC 4733 §2.5.1.2: updates every 50 ms or so; audio packets 20 ms.
            detector: Detector::new(rate / 50),
            last_ms: 0,
            last_end: 0,
            events: Vec::new(),
        })
    }

    pub(super) fn finished(&mut self, f: Finished, slot: Slot) {
        let duration_ms = u32::try_from(u64::from(f.duration) * 1000 / u64::from(self.rate.max(1)))
            .unwrap_or(u32::MAX);
        match rtpflux_core::dtmf::digit(f.code) {
            Some(d) => log::info!("dtmf: slot {slot}: '{d}' ({duration_ms} ms)"),
            None => log::info!("dtmf: slot {slot}: event {} ({duration_ms} ms)", f.code),
        }
        if self.events.len() < MAX_DTMF_EVENTS {
            self.events.push(DtmfEvent {
                code: f.code,
                ts: f.ts,
                duration_ms,
            });
        }
    }

    /// An authentic RTP packet of this leg.
    pub(super) fn packet(&mut self, packet: &[u8], now_ms: u64, slot: Slot) {
        let Ok(p) = rtpflux_core::rtp::Packet::parse(packet) else {
            return;
        };
        if p.payload_type() != self.pt {
            if let Some(f) = self.detector.media() {
                self.finished(f, slot);
            }
            return;
        }
        let Some(ev) = rtpflux_core::dtmf::decode(p.payload()) else {
            return;
        };
        self.last_ms = now_ms;
        self.last_end = u64::from(p.timestamp()) + u64::from(ev.duration);
        for f in self
            .detector
            .report(p.timestamp(), ev)
            .into_iter()
            .flatten()
        {
            self.finished(f, slot);
        }
    }

    /// The worker's clock: an event that went quiet ends.
    pub(super) fn tick(&mut self, now_ms: u64, slot: Slot) {
        if self.detector.current().is_none() {
            return;
        }
        let now = self.last_end + now_ms.saturating_sub(self.last_ms) * u64::from(self.rate) / 1000;
        if let Some(f) = self.detector.tick(now) {
            self.finished(f, slot);
        }
    }
}
