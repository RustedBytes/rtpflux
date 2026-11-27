//! A PCM stream's two threads, between a media worker and an external
//! audio service's Unix socket (see [`super::frame`] for the frames).
//!
//! The worker does no signal processing for a stream: it copies what the
//! endpoint sends (RTP payloads) into a bounded queue ([`FORK_QUEUE`]),
//! dropping and counting when it is full, and plays 20 ms G.711 frames it
//! takes from another ([`INJECT_QUEUE`]), as it plays an announcement.
//! Everything else happens here, on the stream's own threads:
//!
//! - **To the service** (the *fork* thread): a jitter buffer (40 ms target
//!   delay, reordering and duplicates handled), the endpoint's decoder,
//!   loss concealment, resampling to the stream's rate, voice activity
//!   detection (`speech.started`/`speech.ended` events), then 20 ms audio
//!   frames. A service that reads too slowly loses frames (never more than
//!   [`WRITE_TIMEOUT`] of waiting each), told by a gap frame.
//! - **From the service** (the *inject* thread): its audio frames,
//!   resampled to 8 kHz and encoded in G.711, into the worker's queue: a
//!   full queue blocks this thread only, which stops reading the socket
//!   (the service's writes then wait: backpressure, bounded memory). A
//!   flush (`stream.flush`, or a flush frame) drops what is queued
//!   (barge-in). A mark is answered (`stream.mark`) once the audio before
//!   it has played.

use super::frame::{self, FrameError, HEADER, Header, Kind};
use crate::relay::media_events::{MediaEventKind, MediaEvents, Subject};
use rtpflux_core::dsp::Rate;
use rtpflux_core::dsp::resample::Resampler;
use rtpflux_core::dsp::vad::{Vad, VadEvent};
use rtpflux_core::rtp::Pt;
use rtpflux_core::sdp::Codec;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// RTP packets the worker queues for the fork thread, at most.
pub const FORK_QUEUE: usize = 64;
/// 20 ms frames queued for the worker to play, at most (100 ms).
pub const INJECT_QUEUE: usize = 5;
/// The longest a write to the service may wait.
pub const WRITE_TIMEOUT: Duration = Duration::from_millis(100);
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
    data: [u8; MAX_ENCODED],
}

impl Encoded {
    /// The payload `p` (cut at [`MAX_ENCODED`]).
    #[must_use]
    pub fn new(p: &[u8]) -> Self {
        let n = p.len().min(MAX_ENCODED);
        let mut e = Encoded {
            len: u16::try_from(n).unwrap_or(0),
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
/// endpoint sends (and its RTP clock), the G.711 payload type it is sent
/// (`None`: nothing injected), and where its events go.
#[derive(Debug, Clone)]
pub struct Spec {
    pub id: u32,
    pub socket: std::path::PathBuf,
    pub rate: u32,
    /// The payload type of the endpoint's audio (other packets, telephone
    /// events say, are not audio).
    pub pt: Pt,
    pub codec: Codec,
    pub clock: u32,
    pub inject: Option<(Pt, Codec)>,
    pub events: MediaEvents,
    pub subject: Subject,
}

/// What the worker holds of a stream.
#[derive(Debug)]
pub struct WorkerEnd {
    /// What the endpoint sends, for the fork thread.
    pub fork: SyncSender<RtpCopy>,
    /// 20 ms payloads to play to the endpoint, their payload type and RTP
    /// clock.
    pub inject: Option<(Receiver<Encoded>, Pt, u32)>,
    /// Frames played (counted by the worker).
    pub played: Arc<AtomicU64>,
    /// Flushes asked for (the worker drops its queue when it changes).
    pub flushes: Arc<AtomicU64>,
    /// Packets dropped because the fork queue was full.
    pub dropped: Arc<AtomicU64>,
}

/// The control side's handle on a stream: flush it, stop it.
#[derive(Debug, Clone)]
pub struct Handle {
    pub id: u32,
    flushes: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

impl Handle {
    /// Drop the audio queued for the endpoint (barge-in).
    pub fn flush(&self) {
        self.flushes.fetch_add(1, Ordering::Relaxed);
    }

    /// End the stream: its threads stop, and its socket is closed.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Connect to the service and start the stream's threads.
///
/// # Errors
///
/// When the service's socket cannot be connected to, or a thread cannot
/// start, or the rate is not one a stream may use.
pub fn start(spec: &Spec) -> std::io::Result<(WorkerEnd, Handle)> {
    if !frame::valid_rate(spec.rate) {
        return Err(std::io::Error::new(ErrorKind::InvalidInput, "rate"));
    }
    let sock = UnixStream::connect(&spec.socket)?;
    sock.set_write_timeout(Some(WRITE_TIMEOUT))?;
    sock.set_read_timeout(Some(Duration::from_millis(20)))?;
    let writer = Arc::new(Mutex::new(sock.try_clone()?));
    let (fork_tx, fork_rx) = sync_channel(FORK_QUEUE);
    let played = Arc::new(AtomicU64::new(0));
    let flushes = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicU64::new(0));
    // Hello: the stream's id and rate.
    {
        let h = Header {
            kind: Kind::Hello,
            discontinuity: false,
            stream: spec.id,
            seq: 0,
            timestamp_ms: 0,
            rate: spec.rate,
            samples: 0,
        };
        writer
            .lock()
            .map_err(|_| std::io::Error::other("lock"))?
            .write_all(&h.encode())?;
    }
    let inject = if let Some((pt, codec)) = spec.inject {
        let (encoder, enc_rate) = encoder_for(codec)
            .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidInput, "codec"))?;
        let (tx, rx) = sync_channel(INJECT_QUEUE);
        let (s, played, flushes, stop) = (
            spec.clone(),
            Arc::clone(&played),
            Arc::clone(&flushes),
            Arc::clone(&stop),
        );
        let reader = sock.try_clone()?;
        std::thread::Builder::new()
            .name("rtpflux-pcm-in".to_owned())
            .spawn(move || {
                inject_loop(
                    &s,
                    reader,
                    &tx,
                    (encoder, enc_rate),
                    (&played, &flushes, &stop),
                );
            })?;
        Some((rx, pt, spec.clock))
    } else {
        None
    };
    {
        let (s, stop, dropped) = (spec.clone(), Arc::clone(&stop), Arc::clone(&dropped));
        std::thread::Builder::new()
            .name("rtpflux-pcm-out".to_owned())
            .spawn(move || fork_loop(&s, &fork_rx, &writer, &stop, &dropped))?;
    }
    Ok((
        WorkerEnd {
            fork: fork_tx,
            inject,
            played,
            flushes: Arc::clone(&flushes),
            dropped,
        },
        Handle {
            id: spec.id,
            flushes,
            stop,
        },
    ))
}

/// Decoded, concealed and resampled audio, cut into 20 ms frames.
struct Outgoing {
    rate: u32,
    pending: Vec<i16>,
    seq: u32,
    timestamp_ms: u64,
    discontinuity: bool,
    /// Frames the service missed since the last one it got.
    missed: u32,
    out: Vec<u8>,
}

impl Outgoing {
    /// Send the whole 20 ms frames of `pending`.
    fn flush_frames(&mut self, id: u32, writer: &Mutex<UnixStream>) -> bool {
        let per = (self.rate / 50) as usize;
        while self.pending.len() >= per {
            let samples = u16::try_from(per).unwrap_or(0);
            let mut ok = true;
            if let Ok(mut w) = writer.lock() {
                if self.missed > 0 {
                    let gap = Header {
                        kind: Kind::Gap,
                        discontinuity: true,
                        stream: id,
                        seq: self.missed,
                        timestamp_ms: self.timestamp_ms,
                        rate: self.rate,
                        samples: 0,
                    };
                    if w.write_all(&gap.encode()).is_ok() {
                        self.missed = 0;
                    }
                }
                let h = Header {
                    kind: Kind::Audio,
                    discontinuity: self.discontinuity,
                    stream: id,
                    seq: self.seq,
                    timestamp_ms: self.timestamp_ms,
                    rate: self.rate,
                    samples,
                };
                frame::audio(&h, &self.pending[..per], &mut self.out);
                match w.write_all(&self.out) {
                    Ok(()) => {
                        self.discontinuity = false;
                        self.seq = self.seq.wrapping_add(1);
                    }
                    Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                        // Too slow: this frame is lost, the next says so.
                        self.missed += 1;
                        self.discontinuity = true;
                    }
                    Err(_) => ok = false,
                }
            }
            self.timestamp_ms += 20;
            self.pending.drain(..per);
            if !ok {
                return false;
            }
        }
        true
    }
}

/// To the service: jitter buffer, decoding, concealment, resampling
/// ([`super::receive`]), VAD.
fn fork_loop(
    spec: &Spec,
    rx: &Receiver<RtpCopy>,
    writer: &Mutex<UnixStream>,
    stop: &AtomicBool,
    dropped: &AtomicU64,
) {
    let Some(mut receive) =
        super::receive::Receive::new(spec.codec, spec.clock, spec.rate, spec.pt.get())
    else {
        log::warn!("pcm {}: the endpoint's codec is not decoded", spec.id);
        return;
    };
    let Ok(to) = Rate::from_hz(spec.rate) else {
        return;
    };
    let mut vad = Vad::new(to);
    let mut keys = super::inband::Keys::new(spec.rate);
    let mut ended = Vec::new();
    let mut out = Outgoing {
        rate: spec.rate,
        pending: Vec::with_capacity(4 * 960),
        seq: 0,
        timestamp_ms: 0,
        discontinuity: true,
        missed: 0,
        out: Vec::with_capacity(frame::MAX_FRAME),
    };
    let mut fresh = Vec::with_capacity(4 * 960);
    let start = Instant::now();
    let mut next_tick = start;
    let mut reported_drops = 0u64;
    while !stop.load(Ordering::Relaxed) {
        let wait = next_tick.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok(p) => {
                receive.push(&p);
                continue;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        next_tick += Duration::from_millis(20);
        let drops = dropped.load(Ordering::Relaxed);
        if drops != reported_drops || receive.restarted {
            out.discontinuity = true;
            reported_drops = drops;
            receive.restarted = false;
        }
        fresh.clear();
        receive.pull(
            u64::try_from(start.elapsed().as_millis()).unwrap_or(0),
            &mut fresh,
        );
        for chunk in fresh.chunks(to.hz() as usize / 50) {
            match vad.frame(chunk) {
                VadEvent::SpeechStarted => spec
                    .events
                    .emit(spec.subject.clone(), MediaEventKind::SpeechStarted),
                VadEvent::SpeechEnded => spec
                    .events
                    .emit(spec.subject.clone(), MediaEventKind::SpeechEnded),
                VadEvent::None => {}
            }
        }
        if let Some(k) = &mut keys {
            ended.clear();
            k.feed(&fresh, &mut ended);
            for key in &ended {
                spec.events.emit(
                    spec.subject.clone(),
                    MediaEventKind::Dtmf {
                        code: key.code,
                        duration_ms: key.duration_ms,
                        rtp_timestamp: 0,
                        inband: true,
                    },
                );
            }
        }
        out.pending.extend_from_slice(&fresh);
        if !out.flush_frames(spec.id, writer) {
            break;
        }
    }
    stop.store(true, Ordering::Relaxed);
    spec.events.emit(
        spec.subject.clone(),
        MediaEventKind::StreamEnded { stream: spec.id },
    );
}

/// Read one frame from the service: its header and payload (into
/// `payload`). `Ok(None)`: nothing yet.
fn read_frame(
    sock: &mut UnixStream,
    head: &mut [u8; HEADER],
    payload: &mut Vec<u8>,
    stop: &AtomicBool,
) -> std::io::Result<Option<Header>> {
    let mut got = 0;
    while got < HEADER {
        if stop.load(Ordering::Relaxed) {
            return Err(ErrorKind::Interrupted.into());
        }
        match sock.read(&mut head[got..]) {
            Ok(0) => return Err(ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                if got == 0 {
                    return Ok(None);
                }
            }
            Err(e) => return Err(e),
        }
    }
    let h = Header::parse(head)
        .map_err(|e: FrameError| std::io::Error::new(ErrorKind::InvalidData, e.to_string()))?;
    payload.resize(h.payload_len(), 0);
    let mut got = 0;
    while got < payload.len() {
        if stop.load(Ordering::Relaxed) {
            return Err(ErrorKind::Interrupted.into());
        }
        match sock.read(&mut payload[got..]) {
            Ok(0) => return Err(ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(Some(h))
}

/// From the service: resampling to the encoder's rate, encoding in the
/// endpoint's codec, into the worker's queue.
#[allow(clippy::too_many_lines)] // One loop: read, convert, queue, marks.
fn inject_loop(
    spec: &Spec,
    mut sock: UnixStream,
    tx: &SyncSender<Encoded>,
    (mut encoder, enc_rate): (crate::codec::Encoder, u32),
    (played, flushes, stop): (&AtomicU64, &AtomicU64, &AtomicBool),
) {
    let mut head = [0u8; HEADER];
    let mut payload = Vec::with_capacity(frame::MAX_FRAME);
    let mut samples = Vec::with_capacity(frame::MAX_SAMPLES);
    let frame = (enc_rate / 50) as usize;
    let mut narrow = vec![0i16; 2 * 960];
    let mut pending: Vec<i16> = Vec::with_capacity(4 * frame);
    let mut payload_out = [0u8; MAX_ENCODED];
    let mut resampler: Option<(u32, Resampler)> = None;
    let mut queued = 0u64;
    let mut seen_flushes = flushes.load(Ordering::Relaxed);
    // (mark id, frames queued before it).
    let mut marks: std::collections::VecDeque<(u32, u64)> = std::collections::VecDeque::new();
    let mut ready: Option<Encoded> = None;
    while !stop.load(Ordering::Relaxed) {
        // A flush: what is not queued yet goes; the worker drops its queue.
        let f = flushes.load(Ordering::Relaxed);
        if f != seen_flushes {
            seen_flushes = f;
            pending.clear();
            ready = None;
            // The frames the worker drops never play: count them played.
            queued = played.load(Ordering::Relaxed).max(queued);
        }
        // Marks whose audio has played.
        let done = played.load(Ordering::Relaxed);
        while marks.front().is_some_and(|&(_, at)| at <= done) {
            if let Some((id, _)) = marks.pop_front() {
                spec.events.emit(
                    spec.subject.clone(),
                    MediaEventKind::StreamMark {
                        stream: spec.id,
                        mark: id,
                    },
                );
            }
        }
        // A frame waiting for room in the worker's queue: nothing more is
        // read meanwhile (the service waits).
        if let Some(frame) = ready.take() {
            match tx.try_send(frame) {
                Ok(()) => queued += 1,
                Err(TrySendError::Full(f)) => {
                    ready = Some(f);
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(TrySendError::Disconnected(_)) => break,
            }
            continue;
        }
        if pending.len() >= frame {
            let n = encoder.encode(&pending[..frame], &mut payload_out);
            pending.drain(..frame);
            if let Some(n) = n {
                ready = Some(Encoded::new(&payload_out[..n]));
            }
            continue;
        }
        let h = match read_frame(&mut sock, &mut head, &mut payload, stop) {
            Ok(Some(h)) => h,
            Ok(None) => continue,
            Err(e) => {
                if e.kind() != ErrorKind::Interrupted && e.kind() != ErrorKind::UnexpectedEof {
                    log::debug!("pcm {}: {e}", spec.id);
                }
                break;
            }
        };
        match h.kind {
            Kind::Audio => {
                samples.clear();
                samples.extend(
                    payload
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|b| i16::from_le_bytes(*b)),
                );
                if h.rate == enc_rate {
                    pending.extend_from_slice(&samples);
                    continue;
                }
                let r = match &mut resampler {
                    Some((rate, r)) if *rate == h.rate => r,
                    slot => {
                        let Ok(r) = Resampler::new(h.rate, enc_rate) else {
                            continue;
                        };
                        &mut slot.insert((h.rate, r)).1
                    }
                };
                let n = r.process(&samples, &mut narrow);
                pending.extend_from_slice(&narrow[..n]);
            }
            Kind::Mark => {
                if marks.len() < MAX_MARKS {
                    // After the frames queued and those still to come of
                    // what was sent before it.
                    let partial = u64::from(!pending.is_empty());
                    let at = queued + (pending.len() / frame) as u64 + partial;
                    marks.push_back((h.seq, at));
                }
            }
            Kind::Flush => {
                flushes.fetch_add(1, Ordering::Relaxed);
            }
            Kind::Hello | Kind::Gap => {}
        }
    }
    stop.store(true, Ordering::Relaxed);
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
