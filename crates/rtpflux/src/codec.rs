//! Voice codecs as the relay uses them: one RTP payload of a codec to
//! linear PCM ([`Decoder`]), linear PCM to one payload ([`Encoder`]), and
//! 8 ⇄ 16 kHz resampling between them ([`Resampler`]). Transcoding and
//! recording both go through here.
//!
//! | Codec | Audio | Frames | Implementation |
//! |---|---|---|---|
//! | G.711 μ/A-law | 8 kHz | any | `rtpflux_core::g711` |
//! | G.722 | 16 kHz | sample pairs | `rtpflux_core::g722` |
//! | G.729 (+ Annex B) | 8 kHz | 10 ms, 10 octets (2-octet SID last) | `g729-sys` (a port of bcg729) |
//! | Opus | 8 or 16 kHz here | 2.5–60 ms, up to 120 ms per packet | `opus-rs` |
//! | AMR / AMR-WB | 8 / 16 kHz | 20 ms, RFC 4867 octet-aligned | `amr-nb` / `amr-wb` (feature `amr`) |
//!
//! Every state is made once, when a leg is set up; a packet is converted
//! in the caller's buffers with no allocation, except AMR's payload
//! packing (one small vector per packet).

use rtpflux_core::sdp::Codec;
use rtpflux_core::{g711, g722};

/// Most samples one payload decodes to: 120 ms (Opus's longest packet) at
/// 16 kHz.
pub const MAX_SAMPLES: usize = 1920;
/// Most samples an Opus packet decodes to here: 120 ms at 48 kHz
/// (recordings decode Opus at their output rate).
pub const MAX_OPUS_SAMPLES: usize = 5760;
/// The largest Opus frame (RFC 6716 §3.2.1).
const MAX_OPUS_FRAME: usize = 1275;
/// G.729: samples and octets per 10 ms frame, octets per SID frame.
const G729_SAMPLES: usize = g729_sys::FRAME_SAMPLES;
const G729_OCTETS: usize = g729_sys::VOICE_FRAME_BYTES;
const G729_SID: usize = 2;
/// Most AMR frames one packet carries here (120 ms).
#[cfg(feature = "amr")]
const MAX_AMR_FRAMES: usize = 6;

/// Whether this build transcodes `codec` (AMR needs the `amr` feature).
#[must_use]
pub const fn supported(codec: Codec) -> bool {
    cfg!(feature = "amr") || !matches!(codec, Codec::Amr | Codec::AmrWb)
}

/// The audio rate of `codec` as decoded and encoded here; Opus takes the
/// rate of the codec on the other side (`other`), 8 or 16 kHz.
#[must_use]
pub fn rate(codec: Codec, other: u32) -> u32 {
    match codec {
        Codec::G722 | Codec::AmrWb => 16_000,
        Codec::Opus => {
            if other == 16_000 {
                16_000
            } else {
                8000
            }
        }
        Codec::Pcmu | Codec::Pcma | Codec::G729 | Codec::Amr => 8000,
    }
}

/// Whether the relay decodes and encodes `codec` (so it can find DTMF
/// tones in it and play them in it).
#[must_use]
pub fn converts(codec: Codec) -> bool {
    match codec {
        Codec::Pcmu | Codec::Pcma | Codec::G722 | Codec::G729 | Codec::Opus => true,
        Codec::Amr | Codec::AmrWb => cfg!(feature = "amr"),
    }
}

/// A decoder of one codec's payloads.
pub enum Decoder {
    Law(Codec),
    G722(Box<g722::Decoder>),
    G729(Box<g729_sys::Decoder>),
    Opus {
        decoder: Box<opus_rs::OpusDecoder>,
        rate: u32,
        pcm: Box<[f32]>,
    },
    #[cfg(feature = "amr")]
    Amr(Box<amr_nb::Decoder>),
    #[cfg(feature = "amr")]
    AmrWb(Box<amr_wb::Decoder>),
}

impl core::fmt::Debug for Decoder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Decoder({} Hz)", self.rate())
    }
}

impl Decoder {
    /// A decoder of `codec`; Opus decodes at `opus_rate` (8000, 16000,
    /// 24000 or 48000). `None` when the codec is not built in or refuses.
    #[must_use]
    pub fn new(codec: Codec, opus_rate: u32) -> Option<Self> {
        Some(match codec {
            Codec::Pcmu | Codec::Pcma => Decoder::Law(codec),
            Codec::G722 => Decoder::G722(Box::default()),
            Codec::G729 => Decoder::G729(Box::default()),
            Codec::Opus => Decoder::Opus {
                decoder: Box::new(opus_rs::OpusDecoder::new(opus_rate.cast_signed(), 1).ok()?),
                rate: opus_rate,
                pcm: vec![0.0; MAX_OPUS_SAMPLES].into_boxed_slice(),
            },
            #[cfg(feature = "amr")]
            Codec::Amr => Decoder::Amr(Box::default()),
            #[cfg(feature = "amr")]
            Codec::AmrWb => Decoder::AmrWb(Box::default()),
            #[cfg(not(feature = "amr"))]
            Codec::Amr | Codec::AmrWb => return None,
        })
    }

    /// The rate of the PCM it produces.
    #[must_use]
    pub fn rate(&self) -> u32 {
        match self {
            Decoder::Law(_) | Decoder::G729(_) => 8000,
            Decoder::G722(_) => 16_000,
            Decoder::Opus { rate, .. } => *rate,
            #[cfg(feature = "amr")]
            Decoder::Amr(_) => 8000,
            #[cfg(feature = "amr")]
            Decoder::AmrWb(_) => 16_000,
        }
    }

    /// Decode one payload into `out`; returns the samples written, or
    /// `None` when it is malformed or `out` is too short.
    pub fn decode(&mut self, payload: &[u8], out: &mut [i16]) -> Option<usize> {
        match self {
            Decoder::Law(law) => {
                let out = out.get_mut(..payload.len())?;
                for (o, &c) in out.iter_mut().zip(payload) {
                    *o = if *law == Codec::Pcma {
                        g711::alaw_to_linear(c)
                    } else {
                        g711::ulaw_to_linear(c)
                    };
                }
                Some(payload.len())
            }
            Decoder::G722(d) => {
                let n = payload.len() * 2;
                Some(d.decode(payload, out.get_mut(..n)?))
            }
            Decoder::G729(d) => {
                // Voice frames, then at most one SID frame (RFC 3551 §4.5.6).
                let voice = payload.len() / G729_OCTETS;
                let rest = payload.len() % G729_OCTETS;
                if rest != 0 && rest != G729_SID {
                    return None;
                }
                let frames = voice + usize::from(rest == G729_SID);
                let out = out.get_mut(..frames * G729_SAMPLES)?;
                for (k, o) in out.as_chunks_mut::<G729_SAMPLES>().0.iter_mut().enumerate() {
                    let at = k * G729_OCTETS;
                    let sid = k == voice;
                    let frame = if sid {
                        &payload[at..at + G729_SID]
                    } else {
                        &payload[at..at + G729_OCTETS]
                    };
                    *o = d.decode(frame, false, sid, false);
                }
                Some(frames * G729_SAMPLES)
            }
            Decoder::Opus { decoder, pcm, .. } => {
                let max = out.len().min(MAX_OPUS_SAMPLES);
                let n = decoder.decode(payload, max, &mut pcm[..]).ok()?;
                for (o, &s) in out.iter_mut().zip(pcm.get(..n)?) {
                    // ±1.0 is full scale.
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        *o = (s * 32_768.0).clamp(-32_768.0, 32_767.0) as i16;
                    }
                }
                Some(n)
            }
            #[cfg(feature = "amr")]
            Decoder::Amr(d) => {
                use amr_nb::rfc4867::{Packing, read_rtp};
                let (_, frames) = read_rtp(payload, Packing::OctetAligned).ok()?;
                let mut n = 0;
                for f in frames.take(MAX_AMR_FRAMES) {
                    let o: &mut [i16; amr_nb::L_FRAME] =
                        out.get_mut(n..n + amr_nb::L_FRAME)?.try_into().ok()?;
                    d.decode(f.frame_type, f.mode, &f.bits, o);
                    n += amr_nb::L_FRAME;
                }
                Some(n)
            }
            #[cfg(feature = "amr")]
            Decoder::AmrWb(d) => {
                use amr_wb::rfc4867::{Packing, read_rtp};
                let (_, frames) = read_rtp(payload, Packing::OctetAligned).ok()?;
                let mut n = 0;
                for f in frames.take(MAX_AMR_FRAMES) {
                    let o: &mut [i16; amr_wb::L_FRAME] =
                        out.get_mut(n..n + amr_wb::L_FRAME)?.try_into().ok()?;
                    d.decode(f.frame_type, f.mode, &f.bits, o);
                    n += amr_wb::L_FRAME;
                }
                Some(n)
            }
        }
    }
}

/// Opus at one rate: one frame at a time, joined into one packet.
pub struct OpusEncoding {
    encoder: opus_rs::OpusEncoder,
    rate: u32,
    /// One frame's encoding, when a packet is made of several.
    part: [u8; MAX_OPUS_FRAME],
}

impl OpusEncoding {
    /// Opus's frame sizes (2.5 to 60 ms) at this rate, largest first.
    fn frame_sizes(&self) -> [usize; 6] {
        let ms = self.rate as usize / 1000;
        [60 * ms, 40 * ms, 20 * ms, 10 * ms, 5 * ms, 5 * ms / 2]
    }

    /// Encode `pcm` as one packet: one frame when its length is a frame
    /// size, else equal frames in a code 3 packet with variable sizes (RFC
    /// 6716 §3.2.5), within 120 ms. `None` when no split fits or a frame
    /// fails.
    fn encode(&mut self, pcm: &[i16], out: &mut [u8]) -> Option<usize> {
        let sizes = self.frame_sizes();
        if sizes.contains(&pcm.len()) {
            let room = out.len().min(MAX_OPUS_FRAME);
            return self
                .encoder
                .encode_i16(pcm, pcm.len(), &mut out[..room])
                .ok();
        }
        let frame = sizes
            .into_iter()
            .find(|f| *f > 0 && pcm.len().is_multiple_of(*f))?;
        let count = pcm.len() / frame;
        if count > 48 || pcm.len() > 120 * self.rate as usize / 1000 {
            return None;
        }
        let mut toc = None;
        // Frame data goes after the TOC, the count and the sizes (at most
        // two octets per frame but the last).
        let head = 2 + 2 * (count - 1);
        let mut data_at = head;
        let mut lens = [0usize; 48];
        for (k, chunk) in pcm.chunks_exact(frame).enumerate() {
            let n = self.encoder.encode_i16(chunk, frame, &mut self.part).ok()?;
            let (&t, body) = self.part.get(..n)?.split_first()?;
            // One frame (code 0) of the configuration of the others.
            if t & 0x03 != 0 || toc.is_some_and(|x| x != t) {
                return None;
            }
            toc = Some(t);
            out.get_mut(data_at..data_at + body.len())?
                .copy_from_slice(body);
            lens[k] = body.len();
            data_at += body.len();
        }
        // The real header (its sizes may take fewer octets than reserved):
        // the frame data moves up to follow it.
        let mut h = [0u8; 2 + 2 * 47];
        h[0] = toc? | 0x03;
        h[1] = 0x80 | u8::try_from(count).ok()?; // VBR, no padding
        let mut hl = 2;
        for &len in &lens[..count - 1] {
            if len < 252 {
                h[hl] = u8::try_from(len).ok()?;
                hl += 1;
            } else {
                let first = 252 + (len & 3);
                h[hl] = u8::try_from(first).ok()?;
                h[hl + 1] = u8::try_from((len - first) / 4).ok()?;
                hl += 2;
            }
        }
        out.copy_within(head..data_at, hl);
        out.get_mut(..hl)?.copy_from_slice(&h[..hl]);
        Some(hl + (data_at - head))
    }
}

/// An encoder into one codec's payloads.
pub enum Encoder {
    Law(Codec),
    G722(Box<g722::Encoder>),
    G729(Box<g729_sys::Encoder>),
    Opus(Box<OpusEncoding>),
    #[cfg(feature = "amr")]
    Amr(Box<amr_nb::Encoder>, amr_nb::Mode),
    #[cfg(feature = "amr")]
    AmrWb(Box<amr_wb::Encoder>, amr_wb::Mode),
}

impl core::fmt::Debug for Encoder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Encoder({} Hz)", self.rate())
    }
}

impl Encoder {
    /// An encoder into `codec`; Opus encodes at `opus_rate` (8000 or
    /// 16000). `None` when the codec is not built in or refuses.
    #[must_use]
    pub fn new(codec: Codec, opus_rate: u32) -> Option<Self> {
        Some(match codec {
            Codec::Pcmu | Codec::Pcma => Encoder::Law(codec),
            Codec::G722 => Encoder::G722(Box::default()),
            // No VAD/DTX: every frame is a voice frame (valid whether or not
            // the peer has Annex B).
            Codec::G729 => Encoder::G729(Box::new(g729_sys::Encoder::new(false))),
            Codec::Opus => {
                let mut e = opus_rs::OpusEncoder::new(
                    opus_rate.cast_signed(),
                    1,
                    opus_rs::Application::Voip,
                )
                .ok()?;
                // The codec's default (64 kbit/s) is more than speech
                // needs: 24 kbit/s narrowband, 32 kbit/s wideband.
                e.bitrate_bps = if opus_rate >= 16_000 { 32_000 } else { 24_000 };
                Encoder::Opus(Box::new(OpusEncoding {
                    encoder: e,
                    rate: opus_rate,
                    part: [0; MAX_OPUS_FRAME],
                }))
            }
            #[cfg(feature = "amr")]
            Codec::Amr => Encoder::Amr(
                Box::new(amr_nb::Encoder::new(amr_nb::Dtx::Off)),
                amr_nb::Mode::MR122,
            ),
            #[cfg(feature = "amr")]
            Codec::AmrWb => Encoder::AmrWb(
                Box::new(amr_wb::Encoder::new(amr_wb::Dtx::Off)),
                amr_wb::Mode::MD1265,
            ),
            #[cfg(not(feature = "amr"))]
            Codec::Amr | Codec::AmrWb => return None,
        })
    }

    /// Set the bitrate (bit/s): an Opus encoder's, or an AMR one's mode of
    /// that bitrate (one of its modes; the caller checked that the peer
    /// takes it). Other codecs have a fixed bitrate.
    pub fn set_bitrate(&mut self, bps: u32) {
        match self {
            Encoder::Opus(o) => o.encoder.bitrate_bps = bps.cast_signed(),
            #[cfg(feature = "amr")]
            Encoder::Amr(_, mode) => {
                if let Some(m) = Codec::Amr
                    .amr_mode_of(bps)
                    .and_then(|i| amr_nb::Mode::from_index(usize::from(i)))
                {
                    *mode = m;
                }
            }
            #[cfg(feature = "amr")]
            Encoder::AmrWb(_, mode) => {
                if let Some(m) = Codec::AmrWb
                    .amr_mode_of(bps)
                    .and_then(|i| amr_wb::Mode::from_index(usize::from(i)))
                {
                    *mode = m;
                }
            }
            _ => {}
        }
    }

    /// The rate of the PCM it takes.
    #[must_use]
    pub fn rate(&self) -> u32 {
        match self {
            Encoder::Law(_) | Encoder::G729(_) => 8000,
            Encoder::G722(_) => 16_000,
            Encoder::Opus(o) => o.rate,
            #[cfg(feature = "amr")]
            Encoder::Amr(..) => 8000,
            #[cfg(feature = "amr")]
            Encoder::AmrWb(..) => 16_000,
        }
    }

    /// Encode `pcm` (a whole number of the codec's frames) as one payload
    /// into `out`; returns its length, or `None` when `pcm` does not split
    /// into frames or `out` is too short.
    pub fn encode(&mut self, pcm: &[i16], out: &mut [u8]) -> Option<usize> {
        match self {
            Encoder::Law(law) => {
                let out = out.get_mut(..pcm.len())?;
                for (o, &s) in out.iter_mut().zip(pcm) {
                    *o = if *law == Codec::Pcma {
                        g711::linear_to_alaw(s)
                    } else {
                        g711::linear_to_ulaw(s)
                    };
                }
                Some(pcm.len())
            }
            Encoder::G722(e) => {
                if !pcm.len().is_multiple_of(2) {
                    return None;
                }
                let n = pcm.len() / 2;
                Some(e.encode(pcm, out.get_mut(..n)?))
            }
            Encoder::G729(e) => {
                if pcm.is_empty() || !pcm.len().is_multiple_of(G729_SAMPLES) {
                    return None;
                }
                let n = pcm.len() / G729_SAMPLES * G729_OCTETS;
                let out = out.get_mut(..n)?;
                for (frame, o) in pcm
                    .as_chunks::<G729_SAMPLES>()
                    .0
                    .iter()
                    .zip(out.as_chunks_mut::<G729_OCTETS>().0)
                {
                    if usize::from(e.encode_into(frame, o)) != G729_OCTETS {
                        return None;
                    }
                }
                Some(n)
            }
            Encoder::Opus(o) => o.encode(pcm, out),
            #[cfg(feature = "amr")]
            Encoder::Amr(e, mode) => amr_packet(pcm, out, |f| Some(e.encode(*mode, f))),
            #[cfg(feature = "amr")]
            Encoder::AmrWb(e, mode) => amr_wb_packet(pcm, out, |f| Some(e.encode(*mode, f))),
        }
    }
}

/// AMR frames of `pcm`, packed octet-aligned with no mode request.
#[cfg(feature = "amr")]
fn amr_packet(
    pcm: &[i16],
    out: &mut [u8],
    mut encode: impl FnMut(&[i16; amr_nb::L_FRAME]) -> Option<amr_nb::rfc4867::Frame>,
) -> Option<usize> {
    use amr_nb::rfc4867::{Packing, write_rtp};
    let count = pcm.len() / amr_nb::L_FRAME;
    if count == 0 || count > MAX_AMR_FRAMES || !pcm.len().is_multiple_of(amr_nb::L_FRAME) {
        return None;
    }
    let mut frames = Vec::with_capacity(count);
    for f in pcm.as_chunks::<{ amr_nb::L_FRAME }>().0 {
        frames.push(encode(f)?);
    }
    let bytes = write_rtp(None, &frames, Packing::OctetAligned).ok()?;
    out.get_mut(..bytes.len())?.copy_from_slice(&bytes);
    Some(bytes.len())
}

#[cfg(feature = "amr")]
fn amr_wb_packet(
    pcm: &[i16],
    out: &mut [u8],
    mut encode: impl FnMut(&[i16; amr_wb::L_FRAME]) -> Option<amr_wb::rfc4867::Frame>,
) -> Option<usize> {
    use amr_wb::rfc4867::{Packing, write_rtp};
    let count = pcm.len() / amr_wb::L_FRAME;
    if count == 0 || count > MAX_AMR_FRAMES || !pcm.len().is_multiple_of(amr_wb::L_FRAME) {
        return None;
    }
    let mut frames = Vec::with_capacity(count);
    for f in pcm.as_chunks::<{ amr_wb::L_FRAME }>().0 {
        frames.push(encode(f)?);
    }
    let bytes = write_rtp(None, &frames, Packing::OctetAligned).ok()?;
    out.get_mut(..bytes.len())?.copy_from_slice(&bytes);
    Some(bytes.len())
}

/// Taps of the half-band filter (odd).
const TAPS: usize = 31;

/// 8 ⇄ 16 kHz conversion of one stream: a windowed-sinc half-band low-pass
/// at 4 kHz, applied after zero-stuffing (up) or before dropping every
/// other sample (down). It keeps its history between packets, so a
/// stream's packets join without clicks. No allocation.
#[derive(Debug, Clone)]
pub struct Resampler {
    up: bool,
    taps: [f32; TAPS],
    history: [f32; TAPS],
}

impl Resampler {
    /// From `from` Hz to `to` Hz: `None` unless one is 8000 and the other
    /// 16000.
    #[must_use]
    pub fn new(from: u32, to: u32) -> Option<Self> {
        let up = match (from, to) {
            (8000, 16_000) => true,
            (16_000, 8000) => false,
            _ => return None,
        };
        let mut taps = [0f32; TAPS];
        #[allow(clippy::cast_precision_loss)]
        let center = (TAPS - 1) as f64 / 2.0;
        let mut sum = 0.0;
        let mut raw = [0f64; TAPS];
        for (i, t) in raw.iter_mut().enumerate() {
            #[allow(clippy::cast_precision_loss)]
            let x = i as f64 - center;
            // Cut-off at a quarter of the high rate (4 kHz at 16 kHz).
            let sinc = if x == 0.0 {
                0.5
            } else {
                (core::f64::consts::FRAC_PI_2 * x).sin() / (core::f64::consts::PI * x)
            };
            #[allow(clippy::cast_precision_loss)]
            let window =
                0.54 - 0.46 * (2.0 * core::f64::consts::PI * i as f64 / (TAPS - 1) as f64).cos();
            *t = sinc * window;
            sum += *t;
        }
        // Unity gain at DC for the low rate; twice that when upsampling (the
        // stuffed zeros halve the energy).
        let gain = if up { 2.0 / sum } else { 1.0 / sum };
        for (t, r) in taps.iter_mut().zip(raw) {
            #[allow(clippy::cast_possible_truncation)]
            {
                *t = (r * gain) as f32;
            }
        }
        Some(Resampler {
            up,
            taps,
            history: [0.0; TAPS],
        })
    }

    fn push(&mut self, x: f32) {
        self.history.copy_within(..TAPS - 1, 1);
        self.history[0] = x;
    }

    fn output(&self) -> i16 {
        let y: f32 = self
            .taps
            .iter()
            .zip(&self.history)
            .map(|(t, s)| t * s)
            .sum();
        #[allow(clippy::cast_possible_truncation)]
        {
            y.round().clamp(-32_768.0, 32_767.0) as i16
        }
    }

    /// Convert `input` into `out`; returns the samples written (twice or
    /// half as many), or `None` when `out` is too short.
    pub fn process(&mut self, input: &[i16], out: &mut [i16]) -> Option<usize> {
        if self.up {
            let out = out.get_mut(..input.len() * 2)?;
            for (&x, o) in input.iter().zip(out.as_chunks_mut::<2>().0) {
                self.push(f32::from(x));
                o[0] = self.output();
                self.push(0.0);
                o[1] = self.output();
            }
            Some(input.len() * 2)
        } else {
            let n = input.len() / 2;
            let out = out.get_mut(..n)?;
            for (pair, o) in input.as_chunks::<2>().0.iter().zip(out.iter_mut()) {
                self.push(f32::from(pair[0]));
                self.push(f32::from(pair[1]));
                *o = self.output();
            }
            Some(n)
        }
    }
}

#[cfg(test)]
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    /// A tone at `hz`, `ms` long, at `rate`.
    fn tone(hz: f64, rate: u32, ms: usize) -> Vec<i16> {
        let n = rate as usize * ms / 1000;
        (0..n)
            .map(|i| {
                (8000.0 * (2.0 * core::f64::consts::PI * hz * i as f64 / f64::from(rate)).sin())
                    as i16
            })
            .collect()
    }

    fn rms(s: &[i16]) -> f64 {
        (s.iter().map(|&v| f64::from(v).powi(2)).sum::<f64>() / s.len().max(1) as f64).sqrt()
    }

    /// The correlation of `got` with a tone of `hz` at `rate`: near 1 when
    /// `got` is that tone (at any phase).
    fn tone_match(got: &[i16], hz: f64, rate: u32) -> f64 {
        let w = 2.0 * core::f64::consts::PI * hz / f64::from(rate);
        let (mut c, mut s) = (0.0, 0.0);
        for (i, &v) in got.iter().enumerate() {
            c += f64::from(v) * (w * i as f64).cos();
            s += f64::from(v) * (w * i as f64).sin();
        }
        let amp = 2.0 * (c * c + s * s).sqrt() / got.len() as f64;
        amp / (rms(got) * core::f64::consts::SQRT_2)
    }

    /// Every codec encodes a tone and decodes it back as that tone, packet
    /// after packet (20 ms each), with no allocation in between.
    #[test]
    fn each_codec_round_trips_a_tone() {
        for codec in Codec::ALL.into_iter().filter(|&c| supported(c)) {
            let rate = rate(codec, 8000);
            let mut enc = Encoder::new(codec, rate).unwrap();
            let mut dec = Decoder::new(codec, rate).unwrap();
            assert_eq!((enc.rate(), dec.rate()), (rate, rate), "{codec:?}");
            let input = tone(1000.0, rate, 400);
            let frame = rate as usize / 50;
            let mut decoded = Vec::new();
            let mut payload = [0u8; 1500];
            let mut pcm = [0i16; MAX_SAMPLES];
            for chunk in input.chunks_exact(frame) {
                let n = enc
                    .encode(chunk, &mut payload)
                    .unwrap_or_else(|| panic!("{codec:?} encodes"));
                let m = dec
                    .decode(&payload[..n], &mut pcm)
                    .unwrap_or_else(|| panic!("{codec:?} decodes"));
                assert_eq!(m, frame, "{codec:?}");
                decoded.extend_from_slice(&pcm[..m]);
            }
            // Past the codecs' start-up, the tone is there at about its level.
            let tail = &decoded[decoded.len() / 2..];
            let level = rms(tail) / rms(&input);
            assert!((0.5..1.5).contains(&level), "{codec:?}: level {level}");
            assert!(
                tone_match(tail, 1000.0, rate) > 0.9,
                "{codec:?}: not the tone"
            );
        }
    }

    #[test]
    fn frame_rules() {
        let mut g729 = Encoder::new(Codec::G729, 8000).unwrap();
        let mut out = [0u8; 100];
        assert_eq!(
            g729.encode(&[0; 160], &mut out),
            Some(20),
            "two 10 ms frames"
        );
        assert_eq!(g729.encode(&[0; 100], &mut out), None, "not whole frames");
        let mut dec = Decoder::new(Codec::G729, 8000).unwrap();
        let mut pcm = [0i16; 400];
        assert_eq!(
            dec.decode(&[0; 22], &mut pcm),
            Some(240),
            "two frames and a SID"
        );
        assert_eq!(
            dec.decode(&[0; 15], &mut pcm),
            None,
            "neither frames nor SID"
        );
        let mut g722 = Encoder::new(Codec::G722, 16_000).unwrap();
        assert_eq!(g722.encode(&[0; 320], &mut out[..]), None, "out too short");
        assert_eq!(g722.encode(&[0; 199], &mut [0u8; 200]), None, "odd samples");
        // Opus: 30 ms is three 10 ms frames.
        let mut opus = Encoder::new(Codec::Opus, 8000).unwrap();
        let mut big = [0u8; 1500];
        let n = opus.encode(&tone(440.0, 8000, 30), &mut big).unwrap();
        assert_eq!(big[0] & 3, 3, "a code 3 packet");
        assert_eq!(big[1] & 0x3f, 3, "of three frames");
        assert!(n < 300);
        // 250 samples (31.25 ms) split into no Opus frame size.
        assert_eq!(opus.encode(&[0; 250], &mut big), None);
    }

    #[test]
    fn resampling_keeps_a_tone_and_its_level() {
        assert!(Resampler::new(8000, 48_000).is_none());
        let input = tone(1000.0, 8000, 200);
        let mut up = Resampler::new(8000, 16_000).unwrap();
        let mut wide = vec![0i16; input.len() * 2];
        // In 20 ms pieces, as packets come.
        let mut at = 0;
        for chunk in input.chunks(160) {
            at += up.process(chunk, &mut wide[at..]).unwrap();
        }
        assert_eq!(at, input.len() * 2);
        let tail = &wide[wide.len() / 2..];
        assert!(
            (rms(tail) / rms(&input) - 1.0).abs() < 0.05,
            "{}",
            rms(tail) / rms(&input)
        );
        assert!(tone_match(tail, 1000.0, 16_000) > 0.98);
        let mut down = Resampler::new(16_000, 8000).unwrap();
        let mut back = vec![0i16; input.len()];
        assert_eq!(down.process(&wide, &mut back), Some(input.len()));
        let tail = &back[back.len() / 2..];
        assert!((rms(tail) / rms(&input) - 1.0).abs() < 0.05);
        assert!(tone_match(tail, 1000.0, 8000) > 0.98);
        // A 6 kHz tone at 16 kHz is above 8 kHz's band: filtered out.
        let high = tone(6000.0, 16_000, 200);
        let mut down = Resampler::new(16_000, 8000).unwrap();
        let mut out = vec![0i16; high.len() / 2];
        down.process(&high, &mut out).unwrap();
        assert!(
            rms(&out[200..]) < rms(&high) * 0.05,
            "aliasing: {}",
            rms(&out[200..])
        );
        assert_eq!(down.process(&high, &mut [0i16; 10]), None);
    }
}
