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
//! A participant can also be **deafened** (it hears silence, and is still
//! heard), have an **output gain** (on what it hears; the input gain is on
//! what it says), and **taps**: PCM streams that get a copy of its packets
//! (speech recognition on a conference leg), [`MAX_TAPS`] at most. A tap
//! whose queue is full loses the copy, never the mix.
//!
//! At most [`MAX_PARTICIPANTS`]. The mix is wideband (16 kHz): G.722,
//! Opus and AMR-WB participants hear it so, the others narrowband.
//!
//! A mixer can be **recorded** ([`MixerHandle::record`]): each period, the
//! mix a listener hears (the sum of the participants heard by everyone,
//! through a limiter of its own; whisperers too with `include_whispers`)
//! goes to the recording's bounded queue as one [`MixBlock`], numbered by
//! its period. A full queue drops the block and counts it: the conference
//! never waits for the recording. A pause ([`MixerHandle::pause_recording`])
//! is answered once the mixer has taken it: no block after the answer
//! belongs to the pause.

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
/// Taps of one participant, at most.
pub const MAX_TAPS: usize = 4;
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

/// One period of a recorded mix: its number (from 0, counted while
/// recording and not paused) and its 20 ms at 16 kHz; with tracks, each
/// participant's own input too (after its input gain, whatever its role
/// or mute).
#[derive(Clone)]
pub struct MixBlock {
    pub tick: u64,
    pub pcm: [i16; MIX_FRAME],
    pub tracks: Vec<(Arc<str>, [i16; MIX_FRAME])>,
}

/// Samples per [`MixBlock`], and their rate.
pub const BLOCK_SAMPLES: usize = MIX_FRAME;
pub const BLOCK_RATE: u32 = MIX_RATE;

/// Where a mixer's recording goes.
pub struct MixTap {
    pub blocks: SyncSender<MixBlock>,
    /// Whisperers in the recording too (compliance).
    pub include_whispers: bool,
    /// Each participant's own input too.
    pub tracks: bool,
    /// Blocks the queue had no room for.
    pub lost: Arc<AtomicU64>,
    /// Starts paused (a paused recording restored after a restart).
    pub paused: bool,
}

/// What the control side asks of a mixer thread.
enum Ask {
    Record(Option<MixTap>),
    /// Pause (or resume) the recording; answered once taken.
    RecordPause(bool, SyncSender<()>),
    Add(Box<Participant>),
    Remove(String),
    Mute(String, bool),
    /// Gain in dB.
    Gain(String, i32),
    Role(String, Role),
    Deaf(String, bool),
    /// Gain in dB on what it hears.
    OutGain(String, i32),
    Tap(String, SyncSender<RtpCopy>),
}

#[allow(
    clippy::struct_excessive_bools,
    reason = "independent switches: muted, deafened, speaking, gone"
)]
struct Participant {
    key: String,
    /// The key, for recorded tracks.
    name: Arc<str>,
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
    deaf: bool,
    out_gain_db: i32,
    /// Copies of its packets for PCM streams.
    taps: Vec<SyncSender<RtpCopy>>,
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
                Ok(pkt) => {
                    // A copy for each tap; a tap that went away is let go.
                    self.taps.retain(|t| {
                        !matches!(t.try_send(pkt.clone()), Err(TrySendError::Disconnected(_)))
                    });
                    self.receive.push(&pkt);
                }
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
    /// Set when its thread ends, however it ends.
    thread_done: Arc<AtomicBool>,
    /// The participants' keys.
    pub participants: Vec<String>,
}

/// Sets its flag when dropped: at the end of a mixer's thread, a panic
/// included.
struct Done(Arc<AtomicBool>);

impl Drop for Done {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
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
            name: Arc::from(p.key.as_str()),
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
            deaf: false,
            out_gain_db: 0,
            taps: Vec::new(),
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
            consumed: Arc::new(AtomicU64::new(0)),
            flushes: Arc::new(AtomicU64::new(0)),
            dropped,
        })
    }

    /// Remove participant `key`; whether it was one.
    pub fn remove(&mut self, key: &str) -> bool {
        let had = self.participants.iter().any(|k| k == key);
        self.participants.retain(|k| k != key);
        // A mixer that stopped has let go of everyone already.
        let _ = self.asks.send(Ask::Remove(key.to_owned()));
        had
    }

    /// Whether the mixer's thread is still running (it stops when told,
    /// or if it failed): a change asked of a stopped mixer does nothing.
    #[must_use]
    pub fn running(&self) -> bool {
        !self.thread_done.load(Ordering::Relaxed)
    }

    /// Mute (or unmute) participant `key`: the others stop hearing it.
    #[must_use]
    pub fn mute(&self, key: &str, muted: bool) -> bool {
        self.asks.send(Ask::Mute(key.to_owned(), muted)).is_ok()
    }

    /// Participant `key`'s role.
    #[must_use]
    pub fn role(&self, key: &str, role: Role) -> bool {
        self.asks.send(Ask::Role(key.to_owned(), role)).is_ok()
    }

    /// Deafen participant `key` (it hears silence), or not.
    #[must_use]
    pub fn deafen(&self, key: &str, deaf: bool) -> bool {
        self.asks.send(Ask::Deaf(key.to_owned(), deaf)).is_ok()
    }

    /// The gain of what participant `key` hears, in dB.
    #[must_use]
    pub fn output_gain(&self, key: &str, db: i32) -> bool {
        self.asks.send(Ask::OutGain(key.to_owned(), db)).is_ok()
    }

    /// A copy of participant `key`'s packets into `tap` (a PCM stream's).
    #[must_use]
    pub fn tap(&self, key: &str, tap: SyncSender<RtpCopy>) -> bool {
        self.asks.send(Ask::Tap(key.to_owned(), tap)).is_ok()
    }

    /// Participant `key`'s gain, in dB (−60 to +24).
    #[must_use]
    pub fn gain(&self, key: &str, db: i32) -> bool {
        self.asks.send(Ask::Gain(key.to_owned(), db)).is_ok()
    }

    /// Record the mix into `tap` (`None`: stop recording; the queue's
    /// sender is let go, after the last block). Whether the mixer took it (false: it has stopped).
    #[must_use]
    pub fn record(&self, tap: Option<MixTap>) -> bool {
        self.asks.send(Ask::Record(tap)).is_ok()
    }

    /// Pause (or resume) the recording, waiting at most `wait` for the
    /// mixer to take it; whether it did.
    #[must_use]
    pub fn pause_recording(&self, pause: bool, wait: Duration) -> bool {
        let (tx, rx) = sync_channel(1);
        if self.asks.send(Ask::RecordPause(pause, tx)).is_err() {
            return false;
        }
        rx.recv_timeout(wait).is_ok()
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
    let thread_done = Arc::new(AtomicBool::new(false));
    let done = Done(Arc::clone(&thread_done));
    std::thread::Builder::new()
        .name("rtpflux-mixer".to_owned())
        .spawn(move || {
            let _done = done;
            run(id, &rx, &s, &events);
        })?;
    Ok(MixerHandle {
        id,
        asks,
        stop,
        thread_done,
        participants: Vec::new(),
    })
}

/// A mixer's period.
const PERIOD: Duration = Duration::from_millis(20);
/// How far behind its schedule a mixer may run before it skips ahead.
const MAX_BEHIND: Duration = Duration::from_millis(100);

/// When the period due at `next` is more than [`MAX_BEHIND`] late at
/// `now`, move `next` to the period now due; the periods skipped.
fn catch_up(next: &mut Instant, now: Instant) -> u64 {
    let late = now.saturating_duration_since(*next);
    if late <= MAX_BEHIND {
        return 0;
    }
    let periods = late.as_nanos() / PERIOD.as_nanos();
    let skipped = u32::try_from(periods).unwrap_or(u32::MAX);
    *next += PERIOD.saturating_mul(skipped);
    u64::from(skipped)
}

/// Far behind (the thread was starved): skip ahead rather than run the
/// missed periods back to back, which would burst them at the
/// participants. A recording keeps its timeline: the periods skipped are
/// lost, silence at their place.
fn skip_ahead(next: &mut Instant, rec: Option<&mut Recording>) {
    let skipped = catch_up(next, Instant::now());
    if skipped > 0
        && let Some(r) = rec.filter(|r| !r.paused)
    {
        r.tick += skipped;
        r.tap.lost.fetch_add(skipped, Ordering::Relaxed);
    }
}

/// The active speaker: the loudest participant speaking, reported when it
/// changes, held at least [`SPEAKER_HOLD_MS`].
fn active_speaker(
    id: u32,
    parts: &[Participant],
    (speaker, since): (&mut Option<String>, &mut u64),
    elapsed: u64,
    events: &MediaEvents,
) {
    let loudest = parts
        .iter()
        .filter(|p| p.speaking && !p.muted && p.role == Role::Participant)
        .max_by_key(|p| p.energy);
    if let Some(p) = loudest
        && speaker.as_deref() != Some(p.key.as_str())
        && elapsed.saturating_sub(*since) >= SPEAKER_HOLD_MS
    {
        *speaker = Some(p.key.clone());
        *since = elapsed;
        events.emit(
            p.subject.clone(),
            MediaEventKind::ActiveSpeaker { mixer: id },
        );
    }
}

/// The gain of `db` in Q8 (unity 256).
fn q8(db: i32) -> u16 {
    u16::try_from((db_to_q16(db) + 128) >> 8).unwrap_or(u16::MAX)
}

/// A mixer's recording, on its thread.
struct Recording {
    tap: MixTap,
    paused: bool,
    tick: u64,
    limiter: Limiter,
}

/// Apply what the control side asked.
fn apply(asks: &Receiver<Ask>, parts: &mut Vec<Participant>, rec: &mut Option<Recording>) {
    while let Ok(a) = asks.try_recv() {
        match a {
            Ask::Record(tap) => {
                *rec = tap.map(|tap| Recording {
                    paused: tap.paused,
                    tap,
                    tick: 0,
                    limiter: Limiter::new(Rate::Hz16000),
                });
            }
            Ask::RecordPause(pause, done) => {
                if let Some(r) = rec {
                    r.paused = pause;
                }
                let _ = done.try_send(());
            }
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
            Ask::Deaf(k, d) => {
                if let Some(p) = parts.iter_mut().find(|p| p.key == k) {
                    p.deaf = d;
                }
            }
            Ask::OutGain(k, db) => {
                if let Some(p) = parts.iter_mut().find(|p| p.key == k) {
                    p.out_gain_db = db;
                }
            }
            Ask::Tap(k, t) => {
                if let Some(p) = parts.iter_mut().find(|p| p.key == k)
                    && p.taps.len() < MAX_TAPS
                {
                    p.taps.push(t);
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
    let mut rec: Option<Recording> = None;
    let mut acc = [0i32; MIX_FRAME];
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(next.saturating_duration_since(Instant::now()));
        next += PERIOD;
        apply(asks, &mut parts, &mut rec);
        skip_ahead(&mut next, rec.as_mut());
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
        // The recording: what a listener hears.
        if let Some(r) = rec.as_mut().filter(|r| !r.paused) {
            record(r, &mixer, &parts, &mut acc);
        }
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
            // Deafened: silence (its packets still flow). Its output gain.
            if p.deaf {
                out.fill(0);
            } else if p.out_gain_db != 0 {
                let g = i32::from(q8(p.out_gain_db));
                for s in &mut out {
                    *s = i16::try_from((i32::from(*s) * g) >> 8).unwrap_or(if *s < 0 {
                        i16::MIN
                    } else {
                        i16::MAX
                    });
                }
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
        active_speaker(
            id,
            &parts,
            (&mut speaker, &mut speaker_since),
            elapsed,
            events,
        );
        // Participants whose worker let go (their call ended).
        parts.retain(|p| !p.gone);
    }
}

/// This period's mix into recording `r`: the sum (participants heard by
/// everyone), whisperers too if asked, limited; a full queue loses it.
fn record(
    r: &mut Recording,
    mixer: &Mixer<MAX_PARTICIPANTS>,
    parts: &[Participant],
    acc: &mut [i32; MIX_FRAME],
) {
    for (a, &s) in acc.iter_mut().zip(mixer.sum()) {
        *a = s;
    }
    if r.tap.include_whispers {
        for p in parts
            .iter()
            .filter(|p| !p.muted && matches!(p.role, Role::Whisper(_)))
        {
            let g = i32::from(q8(p.gain_db));
            for (a, &x) in acc.iter_mut().zip(&p.frame) {
                *a = a.wrapping_add((i32::from(x) * g) >> 8);
            }
        }
    }
    let mut block = MixBlock {
        tick: r.tick,
        pcm: [0; MIX_FRAME],
        tracks: if r.tap.tracks {
            parts
                .iter()
                .map(|p| {
                    let mut t = p.frame;
                    rtpflux_core::dsp::gain::apply_gain_q8(&mut t, q8(p.gain_db));
                    (Arc::clone(&p.name), t)
                })
                .collect()
        } else {
            Vec::new()
        },
    };
    r.limiter.process(acc, &mut block.pcm);
    r.tick += 1;
    if let Err(TrySendError::Full(_)) = r.tap.blocks.try_send(block) {
        r.tap.lost.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A recording whose queue is full loses the period and counts it;
    /// the periods go on being numbered (the writer fills the gap).
    #[test]
    fn a_full_recording_queue_loses_and_counts() {
        let (tx, rx) = sync_channel(1);
        let lost = Arc::new(AtomicU64::new(0));
        let mut r = Recording {
            tap: MixTap {
                blocks: tx,
                include_whispers: false,
                tracks: false,
                lost: Arc::clone(&lost),
                paused: false,
            },
            paused: false,
            tick: 0,
            limiter: Limiter::new(Rate::Hz16000),
        };
        let mut mixer: Box<Mixer<MAX_PARTICIPANTS>> = Box::default();
        let mut acc = [0i32; MIX_FRAME];
        for _ in 0..3 {
            mixer.begin(MIX_FRAME).unwrap();
            record(&mut r, &mixer, &[], &mut acc);
        }
        assert_eq!(lost.load(Ordering::Relaxed), 2, "no room for two");
        assert_eq!(rx.try_recv().unwrap().tick, 0);
        mixer.begin(MIX_FRAME).unwrap();
        record(&mut r, &mixer, &[], &mut acc);
        assert_eq!(rx.try_recv().unwrap().tick, 3, "numbered on");
    }

    /// A mixer whose thread has ended says so, and takes no recording.
    #[test]
    fn a_stopped_mixer_says_so() {
        let (events, _inbox) = crate::relay::media_events::channel().unwrap();
        let m = start(1, events).unwrap();
        assert!(m.running());
        m.stop();
        let end = Instant::now() + Duration::from_secs(2);
        while m.running() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!m.running());
        let (tx, _rx) = sync_channel(1);
        assert!(!m.record(Some(MixTap {
            blocks: tx,
            include_whispers: false,
            tracks: false,
            lost: Arc::default(),
            paused: false,
        })));
        assert!(!m.mute("p", true));
        assert!(!m.pause_recording(true, Duration::from_millis(50)));
    }

    /// A mixer a little late keeps its pace; one far behind skips the
    /// periods it missed instead of bursting them.
    #[test]
    fn far_behind_skips_ahead() {
        let base = Instant::now();
        let mut next = base;
        assert_eq!(catch_up(&mut next, base + Duration::from_millis(90)), 0);
        assert_eq!(next, base);
        assert_eq!(catch_up(&mut next, base + Duration::from_millis(1_010)), 50);
        assert_eq!(next, base + Duration::from_millis(1_000));
        assert!(base + Duration::from_millis(1_010) - next < PERIOD);
    }

    #[test]
    fn unity_gain_is_256() {
        assert_eq!(q8(0), 256);
        assert!(q8(-6) > 120 && q8(-6) < 136);
        assert!(q8(6) > 500 && q8(6) < 520);
    }
}
