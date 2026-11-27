//! A conference mixer (`mixer.create`): N − 1 mixing on a thread of its
//! own, the media workers only copying and playing packets.
//!
//! Each participant is an endpoint whose leg has a PCM stream with the
//! mixer instead of an external service ([`crate::pcm::stream::WorkerEnd`]):
//! its worker copies what the endpoint sends into a bounded queue, and
//! plays the 20 ms G.711 frames the mixer sends back. Every 20 ms the
//! mixer:
//!
//! 1. takes each participant's packets through its own jitter buffer,
//!    decoder and loss concealment, resampled to 16 kHz (the mix's clock):
//!    a participant with nothing due contributes silence;
//! 2. sums the frames in 32 bits (each scaled by its gain; a muted
//!    participant adds nothing), and gives each participant the sum minus
//!    its own contribution, through its own limiter, so nothing clips
//!    before its own voice is taken out;
//! 3. encodes each mix in the participant's own codec (narrowband ones
//!    get it resampled to 8 kHz first) and queues it for its worker (a
//!    full queue drops the frame and counts it);
//! 4. reports the active speaker: the loudest participant whose voice is
//!    detected, when it changes (held at least [`SPEAKER_HOLD_MS`]).
//!
//! A participant has a [`Role`]: an ordinary participant (a supervisor
//! barging in is one), a listener (hears everyone, heard by no one), or a
//! whisperer (heard by one participant only, added to that listener's mix
//! alone, never to the sum).
//!
//! At most [`MAX_PARTICIPANTS`]. The mix is wideband (16 kHz): G.722,
//! Opus and AMR-WB participants hear it so, the others narrowband.

use super::receive::Receive;
use super::stream::{Encoded, INJECT_QUEUE, MAX_ENCODED, RtpCopy, WorkerEnd, encoder_for};
use crate::relay::media_events::{MediaEventKind, MediaEvents, Subject};
use rtpflux_core::dsp::Rate;
use rtpflux_core::dsp::gain::{Limiter, db_to_q16};
use rtpflux_core::dsp::mix::Mixer;
use rtpflux_core::dsp::resample::Resampler;
use rtpflux_core::dsp::vad::{Vad, VadEvent};
use rtpflux_core::rtp::Pt;
use rtpflux_core::sdp::Codec;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{
    Receiver, Sender, SyncSender, TryRecvError, TrySendError, channel, sync_channel,
};
use std::time::{Duration, Instant};

/// Participants of one mixer, at most.
pub const MAX_PARTICIPANTS: usize = 64;
/// The shortest time a speaker stays the active one.
pub const SPEAKER_HOLD_MS: u64 = 500;
/// RTP packets queued per participant for the mixer, at most.
const FORK_QUEUE: usize = 64;
/// The mix's rate, and its 20 ms frame.
const MIX_RATE: u32 = 16_000;
const MIX_FRAME: usize = 320;

/// A participant to add: its key (the endpoint's), how its audio arrives
/// (codec, RTP clock) and the payload type it hears (in the same codec).
#[derive(Debug, Clone)]
pub struct Joining {
    pub key: String,
    pub codec: Codec,
    pub clock: u32,
    pub pt: Pt,
    pub subject: Subject,
}

/// What a participant is in the conference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    /// Hears everyone, heard by everyone (also a supervisor barging in).
    Participant,
    /// Hears everyone, heard by no one (a supervisor listening).
    Listen,
    /// Hears everyone, heard only by the participant with this key (a
    /// supervisor whispering to an agent).
    Whisper(String),
}

/// What the control side asks of a mixer thread.
enum Ask {
    Add(Box<Participant>),
    Remove(String),
    Mute(String, bool),
    /// Gain in dB.
    Gain(String, i32),
    Role(String, Role),
}

struct Participant {
    key: String,
    subject: Subject,
    fork: Receiver<RtpCopy>,
    inject: SyncSender<Encoded>,
    /// Its codec's encoder, and from the mix's rate to the encoder's (a
    /// narrowband codec's).
    encoder: crate::codec::Encoder,
    narrow: Option<Resampler>,
    receive: Receive,
    pending: Vec<i16>,
    limiter: Limiter,
    vad: Vad,
    gain_db: i32,
    muted: bool,
    /// Its voice is detected now.
    speaking: bool,
    /// Its frame's energy (mean square), this frame.
    energy: u64,
    /// Its worker let go of it (its call ended).
    gone: bool,
    /// Its in-band key presses.
    keys: Option<super::inband::Keys>,
    role: Role,
    /// Its frame this period (kept for a whisper's listener).
    frame: [i16; MIX_FRAME],
    dropped: Arc<AtomicU64>,
}

impl Participant {
    /// Its next 20 ms at the mix's rate: what is due of its packets
    /// (silence for what is missing), its in-band keys reported.
    fn next_frame(
        &mut self,
        elapsed: u64,
        ended: &mut Vec<super::inband::Key>,
        events: &MediaEvents,
    ) -> [i16; MIX_FRAME] {
        loop {
            match self.fork.try_recv() {
                Ok(pkt) => self.receive.push(&pkt),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.gone = true;
                    break;
                }
            }
        }
        self.receive.pull(elapsed, &mut self.pending);
        // A participant far behind (a stall) skips ahead.
        if self.pending.len() > 10 * MIX_FRAME {
            let extra = self.pending.len() - 2 * MIX_FRAME;
            self.pending.drain(..extra);
        }
        let have = self.pending.len().min(MIX_FRAME);
        let mut frame = [0i16; MIX_FRAME];
        frame[..have].copy_from_slice(&self.pending[..have]);
        self.pending.drain(..have);
        self.energy = Vad::energy(&frame);
        if let Some(k) = &mut self.keys {
            ended.clear();
            k.feed(&frame[..have], ended);
            for key in ended.iter() {
                events.emit(
                    self.subject.clone(),
                    MediaEventKind::Dtmf {
                        code: key.code,
                        duration_ms: key.duration_ms,
                        rtp_timestamp: 0,
                        inband: true,
                    },
                );
            }
        }
        frame
    }
}

/// The control side's handle on a mixer.
#[derive(Debug)]
pub struct MixerHandle {
    pub id: u32,
    asks: Sender<Ask>,
    stop: Arc<AtomicBool>,
    /// The participants' keys.
    pub participants: Vec<String>,
}

impl std::fmt::Debug for Ask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ask")
    }
}

impl MixerHandle {
    /// Add `p`: the end its worker holds (to start its stream with).
    ///
    /// # Errors
    ///
    /// When the mixer is full, has the participant already, or its codec
    /// is not decoded.
    pub fn add(&mut self, p: Joining) -> Result<WorkerEnd, &'static str> {
        if self.participants.len() >= MAX_PARTICIPANTS {
            return Err("the mixer is full");
        }
        if self.participants.contains(&p.key) {
            return Err("a participant already");
        }
        let receive = Receive::new(p.codec, p.clock, MIX_RATE, p.pt.get())
            .ok_or("the codec is not decoded")?;
        let (encoder, enc_rate) = encoder_for(p.codec).ok_or("the codec is not encoded")?;
        let narrow = (enc_rate != MIX_RATE)
            .then(|| Resampler::new(MIX_RATE, enc_rate).ok())
            .flatten();
        let (fork_tx, fork_rx) = sync_channel(FORK_QUEUE);
        let (inject_tx, inject_rx) = sync_channel(INJECT_QUEUE);
        let dropped = Arc::new(AtomicU64::new(0));
        let part = Participant {
            key: p.key.clone(),
            subject: p.subject,
            fork: fork_rx,
            inject: inject_tx,
            encoder,
            narrow,
            receive,
            pending: Vec::with_capacity(4 * MIX_FRAME),
            limiter: Limiter::new(Rate::Hz16000),
            vad: Vad::new(Rate::Hz16000),
            gain_db: 0,
            muted: false,
            speaking: false,
            energy: 0,
            gone: false,
            keys: super::inband::Keys::new(MIX_RATE),
            role: Role::Participant,
            frame: [0; MIX_FRAME],
            dropped: Arc::clone(&dropped),
        };
        self.asks
            .send(Ask::Add(Box::new(part)))
            .map_err(|_| "the mixer stopped")?;
        self.participants.push(p.key);
        Ok(WorkerEnd {
            fork: fork_tx,
            inject: Some((inject_rx, p.pt, p.clock)),
            played: Arc::new(AtomicU64::new(0)),
            flushes: Arc::new(AtomicU64::new(0)),
            dropped,
        })
    }

    /// Remove participant `key`.
    pub fn remove(&mut self, key: &str) -> bool {
        let had = self.participants.iter().any(|k| k == key);
        self.participants.retain(|k| k != key);
        let _ = self.asks.send(Ask::Remove(key.to_owned()));
        had
    }

    /// Mute (or unmute) participant `key`: the others stop hearing it.
    pub fn mute(&self, key: &str, muted: bool) {
        let _ = self.asks.send(Ask::Mute(key.to_owned(), muted));
    }

    /// Participant `key`'s role.
    pub fn role(&self, key: &str, role: Role) {
        let _ = self.asks.send(Ask::Role(key.to_owned(), role));
    }

    /// Participant `key`'s gain, in dB (−60 to +24).
    pub fn gain(&self, key: &str, db: i32) {
        let _ = self.asks.send(Ask::Gain(key.to_owned(), db));
    }

    /// Stop the mixer.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for MixerHandle {
    /// A mixer no one holds (destroyed, or the relay stopping) stops.
    fn drop(&mut self) {
        self.stop();
    }
}

/// Start mixer `id`; its events (the active speaker) go to `events`.
///
/// # Errors
///
/// When its thread cannot start.
pub fn start(id: u32, events: MediaEvents) -> std::io::Result<MixerHandle> {
    let (asks, rx) = channel();
    let stop = Arc::new(AtomicBool::new(false));
    let s = Arc::clone(&stop);
    std::thread::Builder::new()
        .name("rtpflux-mixer".to_owned())
        .spawn(move || run(id, &rx, &s, &events))?;
    Ok(MixerHandle {
        id,
        asks,
        stop,
        participants: Vec::new(),
    })
}

/// The gain of `db` in Q8 (unity 256).
fn q8(db: i32) -> u16 {
    u16::try_from((db_to_q16(db) + 128) >> 8).unwrap_or(u16::MAX)
}

/// Apply what the control side asked.
fn apply(asks: &Receiver<Ask>, parts: &mut Vec<Participant>) {
    while let Ok(a) = asks.try_recv() {
        match a {
            Ask::Add(p) => parts.push(*p),
            Ask::Remove(k) => parts.retain(|p| p.key != k),
            Ask::Mute(k, m) => {
                if let Some(p) = parts.iter_mut().find(|p| p.key == k) {
                    p.muted = m;
                }
            }
            Ask::Gain(k, db) => {
                if let Some(p) = parts.iter_mut().find(|p| p.key == k) {
                    p.gain_db = db;
                }
            }
            Ask::Role(k, role) => {
                if let Some(p) = parts.iter_mut().find(|p| p.key == k) {
                    p.role = role;
                }
            }
        }
    }
}

fn run(id: u32, asks: &Receiver<Ask>, stop: &AtomicBool, events: &MediaEvents) {
    let mut parts: Vec<Participant> = Vec::new();
    let mut mixer: Box<Mixer<MAX_PARTICIPANTS>> = Box::default();
    let mut out = [0i16; MIX_FRAME];
    let mut narrow_out = [0i16; MIX_FRAME];
    let mut payload = [0u8; MAX_ENCODED];
    let mut ended = Vec::new();
    let start = Instant::now();
    let mut next = start;
    let mut speaker: Option<String> = None;
    let mut speaker_since = 0u64;
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(next.saturating_duration_since(Instant::now()));
        next += Duration::from_millis(20);
        apply(asks, &mut parts);
        let elapsed = u64::try_from(start.elapsed().as_millis()).unwrap_or(0);
        if mixer.begin(MIX_FRAME).is_err() {
            break;
        }
        // Each one's next 20 ms (silence when nothing is due).
        for (i, p) in parts.iter_mut().enumerate() {
            let frame = p.next_frame(elapsed, &mut ended, events);
            match p.vad.frame(&frame) {
                VadEvent::SpeechStarted => p.speaking = true,
                VadEvent::SpeechEnded => p.speaking = false,
                VadEvent::None => {}
            }
            // Only participants are in the sum; a whisper is added for its
            // listener alone.
            let _ = mixer.set_muted(i, p.muted || p.role != Role::Participant);
            let _ = mixer.set_gain_q8(i, q8(p.gain_db));
            let _ = mixer.add(i, &frame);
            p.frame = frame;
        }
        // The whispers: (listener, frame, gain).
        let whispers: Vec<(String, [i16; MIX_FRAME], u16)> = parts
            .iter()
            .filter(|p| !p.muted)
            .filter_map(|p| match &p.role {
                Role::Whisper(to) => Some((to.clone(), p.frame, q8(p.gain_db))),
                _ => None,
            })
            .collect();
        // Each one hears the others.
        for (i, p) in parts.iter_mut().enumerate() {
            let whisper = whispers
                .iter()
                .find(|(to, ..)| *to == p.key)
                .map_or((&[][..], 0), |(_, f, g)| (&f[..], *g));
            if mixer
                .output_for_with(i, whisper, &mut out, &mut p.limiter)
                .is_err()
            {
                continue;
            }
            let pcm: &[i16] = match &mut p.narrow {
                Some(r) => {
                    let n = r.process(&out, &mut narrow_out);
                    &narrow_out[..n]
                }
                None => &out,
            };
            let Some(n) = p.encoder.encode(pcm, &mut payload) else {
                continue;
            };
            match p.inject.try_send(Encoded::new(&payload[..n])) {
                Ok(()) | Err(TrySendError::Disconnected(_)) => {}
                Err(TrySendError::Full(_)) => {
                    p.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        // The active speaker.
        let loudest = parts
            .iter()
            .filter(|p| p.speaking && !p.muted && p.role == Role::Participant)
            .max_by_key(|p| p.energy);
        if let Some(p) = loudest
            && speaker.as_deref() != Some(p.key.as_str())
            && elapsed.saturating_sub(speaker_since) >= SPEAKER_HOLD_MS
        {
            speaker = Some(p.key.clone());
            speaker_since = elapsed;
            events.emit(
                p.subject.clone(),
                MediaEventKind::ActiveSpeaker { mixer: id },
            );
        }
        // Participants whose worker let go (their call ended).
        parts.retain(|p| !p.gone);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unity_gain_is_256() {
        assert_eq!(q8(0), 256);
        assert!(q8(-6) > 120 && q8(-6) < 136);
        assert!(q8(6) > 500 && q8(6) < 520);
    }
}
