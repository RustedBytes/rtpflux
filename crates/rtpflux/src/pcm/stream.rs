//! A PCM stream, between a media worker and an external audio service's
//! Unix socket (see [`super::frame`] for the frames).
//!
//! The worker does no signal processing for a stream: it copies what the
//! endpoint sends (RTP payloads) into a bounded queue ([`FORK_QUEUE`]),
//! dropping and counting when it is full, and plays 20 ms frames it takes
//! from another ([`INJECT_QUEUE`]), as it plays an announcement.
//!
//! Everything else runs on a **PCM shard** ([`super::shard`]): a few
//! threads, each serving many streams through one epoll loop, a stream
//! always on the same shard. There are no threads per stream. Every 20 ms a
//! shard ticks each of its streams; when a service's socket is readable
//! it reads that service.
//!
//! - **To the service**: a jitter buffer (40 ms target delay, reordering
//!   and duplicates handled), the endpoint's decoder, loss concealment,
//!   resampling to the stream's rate, voice activity detection
//!   (`speech.started`/`speech.ended`) and in-band DTMF, then 20 ms audio
//!   frames into a bounded write buffer ([`WRITE_BUFFER`]). A service that
//!   reads too slowly loses frames, which a gap frame reports. Nothing
//!   ever waits for it.
//! - **From the service**: its audio, resampled and encoded in the
//!   endpoint's codec, into the worker's queue. When that queue is full
//!   the shard stops reading the socket (backpressure, bounded memory):
//!   the service's writes wait, other streams do not. A flush
//!   (`stream.flush`, or a flush frame) starts a new **generation**.
//!   Everything queued is dropped, and frames made before the flush are
//!   dropped by the worker even if they were already on their way. Marks
//!   still waiting are answered as flushed, and the flush is reported
//!   (`stream.flushed`; with protocol 2, a flush frame to the service).
//!   With protocol 2, late audio of an older generation is dropped and
//!   counted, and a late mark is answered as flushed. A mark is answered (`stream.mark`) once the audio before it
//!   has been sent to the endpoint as RTP.

use super::frame::{self, HEADER, Header, Kind};
use crate::relay::media_events::{MediaEventKind, MediaEvents, Subject};
use rtpflux_core::dsp::Rate;
use rtpflux_core::dsp::resample::Resampler;
use rtpflux_core::dsp::vad::{Vad, VadEvent};
use rtpflux_core::rtp::Pt;
use rtpflux_core::sdp::Codec;
use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::time::{Duration, Instant};

/// RTP packets the worker queues for the stream, at most.
pub const FORK_QUEUE: usize = 64;
/// 20 ms frames queued for the worker to play, at most (100 ms).
pub const INJECT_QUEUE: usize = 5;
/// Octets waiting to be written to a service, at most (12 frames: 240 ms
/// of audio): beyond, frames are dropped and counted (a gap frame says
/// how many), and the shard never waits for a slow service.
pub const WRITE_BUFFER: usize = 12 * frame::MAX_FRAME;
/// Frames taken from one service per wake-up, at most: a busy service
/// does not starve the others of its shard.
const READS_PER_PASS: usize = 8;
/// The largest RTP payload copied.
pub const MAX_PAYLOAD: usize = 1500;
/// The largest encoded 20 ms payload (G.711 and G.722 take 160 octets,
/// Opus at the relay's bitrates under 100).
pub const MAX_ENCODED: usize = 640;
/// The rate Opus is encoded at (wideband).
pub const OPUS_INPUT_RATE: u32 = 16_000;

/// 20 ms of audio encoded for the endpoint, moved by value (no allocation).
#[derive(Clone, Copy)]
pub struct Encoded {
    len: u16,
    /// The stream's flush count when it was made: the worker drops it if
    /// a flush came since.
    flush: u64,
    data: [u8; MAX_ENCODED],
}

impl Encoded {
    /// The payload `p` (cut at [`MAX_ENCODED`]).
    #[must_use]
    pub fn new(p: &[u8]) -> Self {
        let n = p.len().min(MAX_ENCODED);
        let mut e = Encoded {
            len: u16::try_from(n).unwrap_or(0),
            flush: 0,
            data: [0; MAX_ENCODED],
        };
        e.data[..n].copy_from_slice(&p[..n]);
        e
    }

    /// The payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.data[..usize::from(self.len)]
    }

    /// Made after `n` flushes.
    #[must_use]
    pub fn after_flushes(mut self, n: u64) -> Self {
        self.flush = n;
        self
    }

    /// The flushes before it was made.
    #[must_use]
    pub fn flushes(&self) -> u64 {
        self.flush
    }
}

/// An encoder of what an endpoint hears, and the rate it takes: Opus at
/// [`OPUS_INPUT_RATE`], the others at their own. `None` when the codec is
/// not built in.
#[must_use]
pub fn encoder_for(codec: Codec) -> Option<(crate::codec::Encoder, u32)> {
    let e = crate::codec::Encoder::new(codec, OPUS_INPUT_RATE)?;
    let rate = e.rate();
    Some((e, rate))
}
/// Marks waiting to be answered, at most.
const MAX_MARKS: usize = 256;

/// An RTP packet's payload and what the jitter buffer needs of its header:
/// moved through the queue by value (its slots are preallocated), so the
/// worker never allocates for it.
#[derive(Clone)]
pub struct RtpCopy {
    pub pt: u8,
    pub seq: u16,
    pub ts: u32,
    pub marker: bool,
    pub ssrc: u32,
    len: u16,
    data: [u8; MAX_PAYLOAD],
}

impl RtpCopy {
    /// The payload `p` (cut at [`MAX_PAYLOAD`]) and its header fields:
    /// payload type, sequence number, timestamp, marker, SSRC.
    #[must_use]
    pub fn new(pt: u8, (seq, ts): (u16, u32), marker: bool, ssrc: u32, p: &[u8]) -> Self {
        let n = p.len().min(MAX_PAYLOAD);
        let mut c = RtpCopy {
            pt,
            seq,
            ts,
            marker,
            ssrc,
            len: u16::try_from(n).unwrap_or(0),
            data: [0; MAX_PAYLOAD],
        };
        c.data[..n].copy_from_slice(&p[..n]);
        c
    }

    /// The payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.data[..usize::from(self.len)]
    }
}

/// What a stream is: its id, its service's socket, its rate, the codec the
/// endpoint sends (and its RTP clock), the payload type and codec it is
/// sent (`None`: nothing injected), the frame protocol's version, and
/// where its events go.
#[derive(Debug, Clone)]
pub struct Spec {
    pub id: u32,
    /// The service's socket; `None`: detectors only (VAD, in-band DTMF),
    /// nothing sent anywhere.
    pub socket: Option<std::path::PathBuf>,
    pub rate: u32,
    /// The payload type of the endpoint's audio (other packets, telephone
    /// events say, are not audio).
    pub pt: Pt,
    pub codec: Codec,
    pub clock: u32,
    pub inject: Option<(Pt, Codec)>,
    /// 1, or 2 (flush generations).
    pub protocol: u8,
    /// The detectors on at the start ([`VAD`], [`DTMF`]).
    pub detect: u8,
    pub events: MediaEvents,
    pub subject: Subject,
}

/// What the worker holds of a stream.
#[derive(Debug)]
pub struct WorkerEnd {
    /// What the endpoint sends, for the stream.
    pub fork: SyncSender<RtpCopy>,
    /// 20 ms payloads to play to the endpoint, their payload type and RTP
    /// clock.
    pub inject: Option<(Receiver<Encoded>, Pt, u32)>,
    /// Frames sent to the endpoint (counted by the worker).
    pub played: Arc<AtomicU64>,
    /// Frames taken off the inject queue: sent, or dropped by a flush.
    pub consumed: Arc<AtomicU64>,
    /// Flushes asked for: the worker drops its queue when it changes, and
    /// any frame made before the latest.
    pub flushes: Arc<AtomicU64>,
    /// Packets dropped because the fork queue was full.
    pub dropped: Arc<AtomicU64>,
}

/// A detector of [`Spec::detect`]: voice activity.
pub const VAD: u8 = 1;
/// A detector of [`Spec::detect`]: in-band DTMF.
pub const DTMF: u8 = 2;

/// The control side's handle on a stream: flush it, switch its detectors,
/// stop it.
#[derive(Debug, Clone)]
pub struct Handle {
    pub id: u32,
    flushes: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    detect: Arc<std::sync::atomic::AtomicU8>,
}

impl Handle {
    /// Drop the audio queued for the endpoint (barge-in): a new
    /// generation.
    pub fn flush(&self) {
        self.flushes.fetch_add(1, Ordering::Relaxed);
    }

    /// End the stream: its shard lets it go and closes its socket.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Switch the detectors ([`VAD`], [`DTMF`]); taken at the next tick.
    pub fn detect(&self, detectors: u8) {
        self.detect.store(detectors, Ordering::Relaxed);
    }

    /// The detectors on.
    #[must_use]
    pub fn detectors(&self) -> u8 {
        self.detect.load(Ordering::Relaxed)
    }
}

/// Connect to the service, say hello, and hand the stream to its shard.
///
/// # Errors
///
/// When the service's socket cannot be connected to, the rate, protocol or
/// codec is not one a stream may use, or the shards cannot start.
pub fn start(spec: &Spec) -> std::io::Result<(WorkerEnd, Handle)> {
    if !frame::valid_rate(spec.rate) || !matches!(spec.protocol, 1 | 2) {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "rate or protocol",
        ));
    }
    let sock = match &spec.socket {
        Some(path) => Some(connect(spec, path)?),
        None => None,
    };
    let Some(receive) =
        super::receive::Receive::new(spec.codec, spec.clock, spec.rate, spec.pt.get())
    else {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "the endpoint's codec is not decoded",
        ));
    };
    let to = Rate::from_hz(spec.rate)
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, "rate"))?;
    let (fork_tx, fork_rx) = sync_channel(FORK_QUEUE);
    let played = Arc::new(AtomicU64::new(0));
    let consumed = Arc::new(AtomicU64::new(0));
    let flushes = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicU64::new(0));
    let (inject, worker_inject) = if sock.is_some() {
        inject_for(spec)?
    } else {
        (None, None)
    };
    let detect = Arc::new(std::sync::atomic::AtomicU8::new(spec.detect));
    let stream = Stream {
        spec: spec.clone(),
        sock,
        receive,
        vad: Vad::new(to),
        keys: super::inband::Keys::new(spec.rate),
        ended_keys: Vec::new(),
        fresh: Vec::with_capacity(4 * 960),
        to,
        out: Outgoing {
            pending: Vec::with_capacity(4 * 960),
            seq: 0,
            timestamp_ms: 0,
            discontinuity: true,
            missed: 0,
            frame: Vec::with_capacity(frame::MAX_FRAME),
            buf: Vec::with_capacity(WRITE_BUFFER + frame::MAX_FRAME),
        },
        fork: fork_rx,
        reported_drops: 0,
        begun: Instant::now(),
        inject,
        rbuf: vec![0u8; 2 * frame::MAX_FRAME],
        rlen: 0,
        seen_flushes: 0,
        stale: 0,
        played: Arc::clone(&played),
        consumed: Arc::clone(&consumed),
        flushes: Arc::clone(&flushes),
        dropped: Arc::clone(&dropped),
        stop: Arc::clone(&stop),
        detect: Arc::clone(&detect),
        ended: false,
    };
    super::shard::submit(Box::new(stream))?;
    Ok((
        WorkerEnd {
            fork: fork_tx,
            inject: worker_inject,
            played,
            consumed,
            flushes: Arc::clone(&flushes),
            dropped,
        },
        Handle {
            id: spec.id,
            flushes,
            stop,
            detect,
        },
    ))
}

/// The service's socket, said hello to (the stream's id, rate and
/// protocol), then non-blocking.
fn connect(spec: &Spec, path: &std::path::Path) -> std::io::Result<UnixStream> {
    let mut sock = UnixStream::connect(path)?;
    sock.set_write_timeout(Some(Duration::from_millis(100)))?;
    let hello = Header {
        version: spec.protocol,
        kind: Kind::Hello,
        discontinuity: false,
        stream: spec.id,
        seq: 0,
        timestamp_ms: 0,
        rate: spec.rate,
        samples: 0,
        generation: 0,
    };
    sock.write_all(&hello.encode())?;
    sock.set_nonblocking(true)?;
    Ok(sock)
}

/// The service's side of a stream that injects audio: the shard's, and
/// the worker's queue with its payload type and clock.
type Injection = (Option<Inject>, Option<(Receiver<Encoded>, Pt, u32)>);

fn inject_for(spec: &Spec) -> std::io::Result<Injection> {
    Ok(if let Some((pt, codec)) = spec.inject {
        let (encoder, enc_rate) = encoder_for(codec)
            .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidInput, "codec"))?;
        let (tx, rx) = sync_channel(INJECT_QUEUE);
        let inject = Inject {
            tx,
            encoder,
            enc_rate,
            frame: (enc_rate / 50) as usize,
            resampler: None,
            pending: Vec::with_capacity(4 * 960),
            narrow: vec![0i16; 2 * 960],
            samples: Vec::with_capacity(frame::MAX_SAMPLES),
            ready: None,
            queued: 0,
            marks: VecDeque::new(),
        };
        (Some(inject), Some((rx, pt, spec.clock)))
    } else {
        (None, None)
    })
}

/// Decoded, concealed and resampled audio, cut into 20 ms frames, and the
/// frames waiting to be written.
struct Outgoing {
    pending: Vec<i16>,
    seq: u32,
    timestamp_ms: u64,
    discontinuity: bool,
    /// Frames the service missed since the last one it got.
    missed: u32,
    frame: Vec<u8>,
    /// Octets not yet written ([`WRITE_BUFFER`] at most, but for control
    /// frames).
    buf: Vec<u8>,
}

/// The service's audio on its way to the endpoint.
struct Inject {
    tx: SyncSender<Encoded>,
    encoder: crate::codec::Encoder,
    enc_rate: u32,
    /// Samples in 20 ms at `enc_rate`.
    frame: usize,
    resampler: Option<(u32, Resampler)>,
    pending: Vec<i16>,
    narrow: Vec<i16>,
    samples: Vec<i16>,
    /// A frame waiting for room in the worker's queue: nothing more is read
    /// meanwhile.
    ready: Option<Encoded>,
    /// Frames put in the worker's queue.
    queued: u64,
    /// (mark id, frames queued before it, its generation).
    marks: VecDeque<(u32, u64, u64)>,
}

/// A stream, as its shard holds it.
pub struct Stream {
    spec: Spec,
    /// The service's socket (`None`: detectors only).
    sock: Option<UnixStream>,
    receive: super::receive::Receive,
    vad: Vad,
    keys: Option<super::inband::Keys>,
    ended_keys: Vec<super::inband::Key>,
    fresh: Vec<i16>,
    to: Rate,
    out: Outgoing,
    fork: Receiver<RtpCopy>,
    reported_drops: u64,
    begun: Instant,
    inject: Option<Inject>,
    /// What was read of the service's frames, not taken yet.
    rbuf: Vec<u8>,
    rlen: usize,
    /// Flushes taken: the current generation.
    seen_flushes: u64,
    /// Late frames of an older generation, dropped.
    stale: u64,
    played: Arc<AtomicU64>,
    consumed: Arc<AtomicU64>,
    flushes: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    detect: Arc<std::sync::atomic::AtomicU8>,
    ended: bool,
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stream")
            .field("id", &self.spec.id)
            .field("generation", &self.seen_flushes)
            .finish_non_exhaustive()
    }
}

impl Stream {
    pub(super) fn id(&self) -> u32 {
        self.spec.id
    }

    /// Whether the shard should read the service now: not while a frame
    /// waits for room in the worker's queue (backpressure).
    pub(super) fn wants_read(&self) -> bool {
        self.inject.as_ref().is_none_or(|i| i.ready.is_none())
    }

    /// Late frames dropped so far (an older generation's).
    #[must_use]
    pub fn stale(&self) -> u64 {
        self.stale
    }

    fn emit(&self, kind: MediaEventKind) {
        self.spec.events.emit(self.spec.subject.clone(), kind);
    }

    fn played_ms(&self) -> u64 {
        self.played.load(Ordering::Relaxed).saturating_mul(20)
    }

    /// Every 20 ms: the endpoint's audio to the service, the service's to
    /// the worker, marks, writes. `false`: the stream ended.
    pub(super) fn tick(&mut self) -> bool {
        if self.stop.load(Ordering::Relaxed) {
            return false;
        }
        self.take_flush();
        if !self.fork_tick() {
            return false;
        }
        self.pump();
        self.answer_marks();
        self.write_out()
    }

    /// The endpoint's audio of the last 20 ms, decoded and analysed, into
    /// frames for the service.
    /// `false` once nothing can send it packets any more (its call ended,
    /// or, for a tap, its participant left the mixer).
    fn fork_tick(&mut self) -> bool {
        loop {
            match self.fork.try_recv() {
                Ok(p) => self.receive.push(&p),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => return false,
            }
        }
        let drops = self.dropped.load(Ordering::Relaxed);
        if drops != self.reported_drops || self.receive.restarted {
            self.out.discontinuity = true;
            self.reported_drops = drops;
            self.receive.restarted = false;
        }
        self.fresh.clear();
        let elapsed = u64::try_from(self.begun.elapsed().as_millis()).unwrap_or(0);
        self.receive.pull(elapsed, &mut self.fresh);
        let detect = self.detect.load(Ordering::Relaxed);
        for chunk in self.fresh.chunks(self.to.hz() as usize / 50) {
            if detect & VAD == 0 {
                break;
            }
            match self.vad.frame(chunk) {
                VadEvent::SpeechStarted => self.emit(MediaEventKind::SpeechStarted),
                VadEvent::SpeechEnded => self.emit(MediaEventKind::SpeechEnded),
                VadEvent::None => {}
            }
        }
        if let Some(k) = self.keys.as_mut().filter(|_| detect & DTMF != 0) {
            self.ended_keys.clear();
            k.feed(&self.fresh, &mut self.ended_keys);
            for key in &self.ended_keys {
                self.spec.events.emit(
                    self.spec.subject.clone(),
                    MediaEventKind::Dtmf {
                        code: key.code,
                        duration_ms: key.duration_ms,
                        rtp_timestamp: 0,
                        inband: true,
                    },
                );
            }
        }
        // Detectors only: nothing to send.
        if self.sock.is_some() {
            self.out.pending.extend_from_slice(&self.fresh);
            self.frames_out();
        }
        true
    }

    /// The header of a frame to the service.
    fn header(&self, kind: Kind, seq: u32, timestamp_ms: u64, samples: u16) -> Header {
        Header {
            version: self.spec.protocol,
            kind,
            discontinuity: kind != Kind::Audio || self.out.discontinuity,
            stream: self.spec.id,
            seq,
            timestamp_ms,
            rate: self.spec.rate,
            samples,
            generation: (self.seen_flushes & 0xff) as u8,
        }
    }

    /// The whole 20 ms frames of `out.pending`, into the write buffer; a
    /// frame without room is lost (and the next gap frame says so).
    fn frames_out(&mut self) {
        let per = (self.spec.rate / 50) as usize;
        while self.out.pending.len() >= per {
            let samples = u16::try_from(per).unwrap_or(0);
            if self.out.buf.len() + HEADER + 2 * per > WRITE_BUFFER {
                self.out.missed += 1;
                self.out.discontinuity = true;
            } else {
                self.gap_out();
                let h = self.header(Kind::Audio, self.out.seq, self.out.timestamp_ms, samples);
                frame::audio(&h, &self.out.pending[..per], &mut self.out.frame);
                self.out.buf.extend_from_slice(&self.out.frame);
                self.out.discontinuity = false;
                self.out.seq = self.out.seq.wrapping_add(1);
            }
            self.out.timestamp_ms += 20;
            self.out.pending.drain(..per);
        }
        // Said as soon as there is room, even if no audio follows.
        self.gap_out();
    }

    /// The frames the service missed, told (once the write buffer has
    /// room for the gap frame).
    fn gap_out(&mut self) {
        if self.out.missed > 0 && self.out.buf.len() + HEADER <= WRITE_BUFFER {
            let gap = self.header(Kind::Gap, self.out.missed, self.out.timestamp_ms, 0);
            self.out.buf.extend_from_slice(&gap.encode());
            self.out.missed = 0;
        }
    }

    /// Write what the service can take now; `false` when it is gone.
    fn write_out(&mut self) -> bool {
        let Some(sock) = &mut self.sock else {
            return true;
        };
        while !self.out.buf.is_empty() {
            match sock.write(&self.out.buf) {
                Ok(0) => return false,
                Ok(n) => {
                    self.out.buf.drain(..n);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(_) => return false,
            }
        }
        true
    }

    /// A flush asked for since the last look (by the API, or the service):
    /// a new generation. What waits goes, marks waiting are answered as
    /// flushed, and the flush is reported.
    fn take_flush(&mut self) {
        let f = self.flushes.load(Ordering::Relaxed);
        if f == self.seen_flushes {
            return;
        }
        self.seen_flushes = f;
        let played_ms = self.played_ms();
        if let Some(i) = &mut self.inject {
            i.pending.clear();
            i.ready = None;
            let marks: Vec<(u32, u64, u64)> = i.marks.drain(..).collect();
            for (mark, _, generation) in marks {
                self.emit(MediaEventKind::StreamMark {
                    stream: self.spec.id,
                    mark,
                    generation,
                    played_ms,
                    flushed: true,
                });
            }
        }
        if self.spec.protocol == 2 && self.sock.is_some() {
            // The acknowledgment: the new generation, and the audio sent
            // before it.
            let ack = self.header(
                Kind::Flush,
                u32::try_from(f & 0xffff_ffff).unwrap_or(0),
                played_ms,
                0,
            );
            self.out.buf.extend_from_slice(&ack.encode());
        }
        self.emit(MediaEventKind::StreamFlushed {
            stream: self.spec.id,
            generation: f,
            played_ms,
        });
    }

    /// The service's pending audio, encoded, into the worker's queue until
    /// it is full.
    fn pump(&mut self) {
        let flushes = self.seen_flushes;
        let Some(i) = &mut self.inject else {
            return;
        };
        loop {
            let frame = match i.ready.take() {
                Some(f) => f,
                None if i.pending.len() >= i.frame => {
                    let mut out = [0u8; MAX_ENCODED];
                    let n = i.encoder.encode(&i.pending[..i.frame], &mut out);
                    i.pending.drain(..i.frame);
                    match n {
                        Some(n) => Encoded::new(&out[..n]).after_flushes(flushes),
                        None => continue,
                    }
                }
                None => return,
            };
            match i.tx.try_send(frame) {
                Ok(()) => i.queued += 1,
                Err(TrySendError::Full(f)) => {
                    i.ready = Some(f);
                    return;
                }
                Err(TrySendError::Disconnected(_)) => return,
            }
        }
    }

    /// Marks whose audio the worker has taken.
    fn answer_marks(&mut self) {
        let done = self.consumed.load(Ordering::Relaxed);
        let played_ms = self.played_ms();
        let Some(i) = &mut self.inject else {
            return;
        };
        let mut answered = Vec::new();
        while i.marks.front().is_some_and(|&(_, at, _)| at <= done) {
            if let Some(m) = i.marks.pop_front() {
                answered.push(m);
            }
        }
        for (mark, _, generation) in answered {
            self.emit(MediaEventKind::StreamMark {
                stream: self.spec.id,
                mark,
                generation,
                played_ms,
                flushed: false,
            });
        }
    }

    /// Read what the service sent, a few frames at most, while the worker
    /// has room; `false` when the service is gone or broke the protocol.
    pub(super) fn read(&mut self) -> bool {
        self.take_flush();
        for _ in 0..READS_PER_PASS {
            self.pump();
            if !self.wants_read() {
                break;
            }
            match self.take_frame() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(()) => return false,
            }
            // Not a whole frame yet: more from the socket.
            let Some(sock) = &mut self.sock else {
                break;
            };
            match sock.read(&mut self.rbuf[self.rlen..]) {
                Ok(0) => return false,
                Ok(n) => self.rlen += n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => {
                    log::debug!("pcm {}: {e}", self.spec.id);
                    return false;
                }
            }
        }
        self.pump();
        self.answer_marks();
        self.write_out()
    }

    /// Take one whole frame from what was read: `Ok(false)` when there is
    /// none yet, `Err` when the service broke the protocol.
    fn take_frame(&mut self) -> Result<bool, ()> {
        if self.rlen < HEADER {
            return Ok(false);
        }
        let h = Header::parse(&self.rbuf[..HEADER]).map_err(|e| {
            log::debug!("pcm {}: {e}", self.spec.id);
        })?;
        let need = HEADER + h.payload_len();
        if self.rlen < need {
            return Ok(false);
        }
        self.frame_in(&h, need);
        self.rbuf.copy_within(need..self.rlen, 0);
        self.rlen -= need;
        Ok(true)
    }

    /// A frame from the service (its payload at `rbuf[HEADER..end]`).
    fn frame_in(&mut self, h: &Header, end: usize) {
        if h.kind == Kind::Flush {
            self.flushes.fetch_add(1, Ordering::Relaxed);
            self.take_flush();
            return;
        }
        // Protocol 2: a frame of an older generation is late audio of what
        // was flushed.
        let current = (self.seen_flushes & 0xff) as u8;
        if self.spec.protocol == 2
            && matches!(h.kind, Kind::Audio | Kind::Mark)
            && h.generation != current
        {
            self.stale += 1;
            // Its mark is answered: flushed, never to play.
            if h.kind == Kind::Mark {
                self.emit(MediaEventKind::StreamMark {
                    stream: self.spec.id,
                    mark: h.seq,
                    generation: u64::from(h.generation),
                    played_ms: self.played_ms(),
                    flushed: true,
                });
            }
            return;
        }
        let Some(i) = &mut self.inject else {
            return;
        };
        match h.kind {
            Kind::Audio => {
                i.samples.clear();
                i.samples.extend(
                    self.rbuf[HEADER..end]
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|b| i16::from_le_bytes(*b)),
                );
                if h.rate == i.enc_rate {
                    i.pending.extend_from_slice(&i.samples);
                    return;
                }
                let r = match &mut i.resampler {
                    Some((rate, r)) if *rate == h.rate => r,
                    slot => {
                        let Ok(r) = Resampler::new(h.rate, i.enc_rate) else {
                            return;
                        };
                        &mut slot.insert((h.rate, r)).1
                    }
                };
                let n = r.process(&i.samples, &mut i.narrow);
                i.pending.extend_from_slice(&i.narrow[..n]);
            }
            Kind::Mark => {
                if i.marks.len() < MAX_MARKS {
                    // After the frames queued and those still to come of
                    // what was sent before it.
                    let waiting = u64::from(i.ready.is_some());
                    let partial = u64::from(!i.pending.len().is_multiple_of(i.frame));
                    let at = i.queued + waiting + (i.pending.len() / i.frame) as u64 + partial;
                    i.marks.push_back((h.seq, at, self.seen_flushes));
                }
            }
            Kind::Hello | Kind::Gap | Kind::Flush => {}
        }
    }

    /// The stream is over (stopped, its service gone, or its call ended):
    /// said once.
    pub(super) fn end(&mut self) {
        if self.ended {
            return;
        }
        self.ended = true;
        self.stop.store(true, Ordering::Relaxed);
        if self.stale > 0 {
            log::debug!("pcm {}: {} late frames dropped", self.spec.id, self.stale);
        }
        self.emit(MediaEventKind::StreamEnded {
            stream: self.spec.id,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_copy_keeps_its_payload() {
        let c = RtpCopy::new(0, (7, 160), true, 9, &[1, 2, 3]);
        assert_eq!((c.pt, c.seq, c.ts, c.marker, c.ssrc), (0, 7, 160, true, 9));
        assert_eq!(c.payload(), [1, 2, 3]);
        let long = RtpCopy::new(0, (0, 0), false, 0, &[0; 3000]);
        assert_eq!(long.payload().len(), MAX_PAYLOAD);
    }
}
