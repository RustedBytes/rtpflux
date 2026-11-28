//! Recording a conference mixer (`recording.start` with `mixer_id`).
//!
//! The mixer thread hands each period's mix to a bounded queue
//! ([`crate::pcm::mixer::MixTap`]). A writer thread of the recording's own
//! takes the blocks and appends them to a **spool**: raw 16-bit
//! little-endian PCM, 16 kHz mono, one file per section (a restart of the
//! relay begins a new one). A block the queue had no room for, or one the
//! writer could not write, is silence at its place: the timeline stays
//! continuous, and the loss is counted.
//!
//! With **tracks**, each participant's own input (after its input gain,
//! whatever its role or mute) also goes to a spool of its own, on the same
//! timeline: silence before it joined and after it left, so each track
//! lines up with the mix sample for sample.
//!
//! When the recording ends, its sections are converted on the recording
//! conversion thread like a call's pcap ([`super::convert::run`]): each
//! spool becomes an audio file in the chosen format and rate (resampled
//! from 16 kHz; stereo is the same mix on both channels), with its JSON
//! report and tags, then stored (locally or on S3) and reported.

use super::encode::Pcm;
use super::settings::{Format, Settings};
use crate::pcm::mixer::{BLOCK_RATE, BLOCK_SAMPLES, MixBlock};
use rtpflux_core::dsp::resample::Resampler;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};

/// The spool's extension.
pub const SPOOL: &str = "mixpcm";

/// A mixer recording's sections, to convert when it ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MixJob {
    /// The native API's recording id.
    pub recording_id: String,
    /// The spools, section after section, and when each began (ms since
    /// the epoch).
    pub spools: Vec<PathBuf>,
    pub starts: Vec<u64>,
    /// The participants' tracks: (section from 1, endpoint id, spool).
    /// One that was never written (no such spool) is skipped.
    pub tracks: Vec<(usize, String, PathBuf)>,
}

/// Where participant `key`'s track of a section is spooled.
pub type TrackPath = Arc<dyn Fn(&str) -> PathBuf + Send + Sync>;

/// What the writer hands over when its queue closes: the conversion job
/// (set when the recording ends for good, not when the relay stops) and
/// where it goes; and whether the writer is done (then the job is sent
/// by whoever sets it: [`hand_over`]).
#[derive(Debug, Default)]
pub struct Handover {
    job: Option<(super::Job, Sender<super::Job>)>,
    writer_done: bool,
}

/// A writer's hand-over, shared with the control side.
pub type Finish = Arc<Mutex<Handover>>;

/// The recording ends: `job` goes to `jobs` once the writer has written
/// everything (at once if it is already done).
///
/// # Errors
///
/// When it went at once and no converter is left to take it.
pub fn hand_over(
    finish: &Finish,
    job: super::Job,
    jobs: Sender<super::Job>,
) -> Result<(), &'static str> {
    // A writer that panicked holding the lock leaves the hand-over as it
    // was: still usable.
    let mut h = finish
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if h.writer_done {
        drop(h);
        jobs.send(job).map_err(|_| "no recording converter")
    } else {
        h.job = Some((job, jobs));
        Ok(())
    }
}

/// Counters a writer keeps.
#[derive(Debug, Default)]
pub struct Written {
    /// Periods in the spool (silence included).
    pub periods: AtomicU64,
    /// Periods of the mix that could not be written (a full disk): lost,
    /// silence in their place once writing works again.
    pub failed: AtomicU64,
}

/// Bytes per period in a spool.
const PERIOD_BYTES: u64 = (BLOCK_SAMPLES * 2) as u64;

/// Start the writer of one section: the blocks from `blocks` into the
/// spool at `path` (a new file: one that exists is never written into),
/// until the queue closes; then the job in `finish`, if any, goes to the
/// converter.
///
/// # Errors
///
/// When the spool cannot be created or the thread started.
pub fn spawn_writer(
    path: &Path,
    blocks: Receiver<MixBlock>,
    written: Arc<Written>,
    finish: Finish,
    tracks: Option<TrackPath>,
) -> std::io::Result<()> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    let owned = path.to_owned();
    let spawned = std::thread::Builder::new()
        .name("rtpflux-mixrec".to_owned())
        .spawn(move || {
            let mut spool = Out::new(file, owned);
            write(&mut spool, &blocks, &written, &finish, tracks.as_ref());
        });
    if let Err(e) = spawned {
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}

/// A period's samples as little-endian bytes.
fn le(pcm: &[i16; BLOCK_SAMPLES], out: &mut [u8; BLOCK_SAMPLES * 2]) {
    for (b, s) in out.as_chunks_mut::<2>().0.iter_mut().zip(pcm) {
        *b = s.to_le_bytes();
    }
}

/// A spool being written, a whole period at a time: a write that fails
/// part way (a full disk) is cut back off, so the file always holds whole
/// periods and every sample stays in its place.
struct Out {
    file: File,
    path: PathBuf,
    /// Periods in the file.
    periods: u64,
    /// A failure was logged (once per file).
    logged: bool,
}

impl Out {
    fn new(file: File, path: PathBuf) -> Self {
        Out {
            file,
            path,
            periods: 0,
            logged: false,
        }
    }

    /// Append one period; whether it was written.
    fn put(&mut self, data: &[u8; BLOCK_SAMPLES * 2]) -> bool {
        match self.file.write_all(data) {
            Ok(()) => {
                self.periods += 1;
                true
            }
            Err(e) => {
                if !self.logged {
                    log::warn!("recording: {}: {e}", self.path.display());
                    self.logged = true;
                }
                // Whatever part of it went in, out again.
                let whole = self.periods * PERIOD_BYTES;
                let undone = self.file.set_len(whole).and_then(|()| {
                    use std::io::Seek as _;
                    self.file.seek(std::io::SeekFrom::Start(whole)).map(drop)
                });
                if let Err(e) = undone {
                    log::warn!("recording: {}: {e}", self.path.display());
                }
                false
            }
        }
    }

    /// Bring the file to `tick` periods with silence (periods lost on the
    /// way, or written when writing works again).
    fn fill_to(&mut self, tick: u64) {
        let silence = [0u8; BLOCK_SAMPLES * 2];
        while self.periods < tick && self.put(&silence) {}
    }

    /// On the disk; logged if not.
    fn sync(&mut self) {
        if let Err(e) = self.file.sync_data() {
            log::warn!("recording: {}: {e}", self.path.display());
        }
    }
}

/// A participant's track, buffered: on its first failure it is given up
/// (its file removed), never left with samples out of place.
struct Track {
    out: BufWriter<File>,
    path: PathBuf,
}

impl Track {
    /// A new track file at `path` with `periods` of silence (it was not
    /// there yet); `None` (logged) when it cannot be made.
    fn open(path: PathBuf, periods: u64) -> Option<Self> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path);
        let mut t = match file {
            Ok(f) => Track {
                out: BufWriter::with_capacity(64 * 1024, f),
                path,
            },
            Err(e) => {
                log::warn!("recording: track {}: {e}", path.display());
                return None;
            }
        };
        let silence = [0u8; BLOCK_SAMPLES * 2];
        for _ in 0..periods {
            if !t.put(&silence) {
                return None;
            }
        }
        Some(t)
    }

    /// Append one period; false (the track given up) on failure.
    fn put(&mut self, data: &[u8]) -> bool {
        if let Err(e) = self.out.write_all(data) {
            self.give_up(&e);
            return false;
        }
        true
    }

    fn give_up(&self, e: &std::io::Error) {
        log::warn!(
            "recording: track {}: {e}; the track is given up",
            self.path.display()
        );
        if let Err(e) = std::fs::remove_file(&self.path) {
            log::warn!("recording: removing {}: {e}", self.path.display());
        }
    }

    /// Flush and sync; false (the track given up) on failure.
    fn finish(mut self) -> bool {
        match self
            .out
            .flush()
            .and_then(|()| self.out.get_ref().sync_data())
        {
            Ok(()) => true,
            Err(e) => {
                self.give_up(&e);
                false
            }
        }
    }
}

fn write(
    spool: &mut Out,
    blocks: &Receiver<MixBlock>,
    written: &Written,
    finish: &Finish,
    track_path: Option<&TrackPath>,
) {
    let silence = [0u8; BLOCK_SAMPLES * 2];
    let mut bytes = [0u8; BLOCK_SAMPLES * 2];
    // The next period expected, and the mix's periods not written.
    let mut next = 0u64;
    let mut failed = 0u64;
    let mut tracks: HashMap<Arc<str>, Track> = HashMap::new();
    // Tracks given up: not opened again.
    let mut given_up: Vec<Arc<str>> = Vec::new();
    for block in blocks {
        // Periods lost on the way: silence in their place, on every track.
        spool.fill_to(block.tick);
        for _ in next..block.tick {
            tracks.retain(|_, t| t.put(&silence));
        }
        le(&block.pcm, &mut bytes);
        if spool.periods != block.tick || !spool.put(&bytes) {
            failed += 1;
        }
        if let Some(track_path) = track_path {
            for (key, pcm) in &block.tracks {
                if !tracks.contains_key(key) && !given_up.contains(key) {
                    // Silence from the section's start.
                    match Track::open(track_path(key), block.tick) {
                        Some(t) => {
                            tracks.insert(Arc::clone(key), t);
                        }
                        None => given_up.push(Arc::clone(key)),
                    }
                }
                if let Some(t) = tracks.get_mut(key) {
                    le(pcm, &mut bytes);
                    if !t.put(&bytes) {
                        tracks.remove(key);
                        given_up.push(Arc::clone(key));
                    }
                }
            }
            // Those that left (or were not in this period): silence.
            tracks.retain(|key, t| block.tracks.iter().any(|(k, _)| k == key) || t.put(&silence));
        }
        next = block.tick + 1;
        written.periods.store(spool.periods, Ordering::Relaxed);
        written.failed.store(failed, Ordering::Relaxed);
    }
    spool.sync();
    for t in tracks.into_values() {
        t.finish();
    }
    let job = {
        let mut h = finish
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        h.writer_done = true;
        h.job.take()
    };
    if let Some((job, jobs)) = job
        && jobs.send(job).is_err()
    {
        // The relay is stopping: the recording is converted when it is
        // back (a stopped recording in the state is converted again).
        log::warn!(
            "recording: {}: no converter left, not converted now",
            spool.path.display()
        );
    }
}

/// A spool as the encoders' source: resampled to `rate`, on `channels`
/// channels (the same mix on each).
struct Spool {
    reader: BufReader<File>,
    resampler: Resampler,
    channels: usize,
    input: Vec<i16>,
    resampled: Vec<i16>,
    /// Output frames not given out yet.
    pending: std::collections::VecDeque<i16>,
    raw: Vec<u8>,
    done: bool,
    frames: u64,
    /// A read that failed: the conversion fails with it (never a file
    /// silently cut short).
    error: Option<std::io::Error>,
}

impl Spool {
    fn open(path: &Path, rate: u32, channels: usize) -> std::io::Result<Self> {
        let resampler = Resampler::new(BLOCK_RATE, rate)
            .map_err(|_| std::io::Error::other(format!("sample rate {rate}")))?;
        Ok(Spool {
            reader: BufReader::new(File::open(path)?),
            resampler,
            channels: channels.max(1),
            input: Vec::with_capacity(BLOCK_SAMPLES),
            resampled: vec![0; BLOCK_SAMPLES * 4],
            pending: std::collections::VecDeque::new(),
            raw: vec![0; BLOCK_SAMPLES * 2],
            done: false,
            frames: 0,
            error: None,
        })
    }

    /// One more period from the file into `pending`; false at the end.
    fn more(&mut self) -> bool {
        if self.done {
            return false;
        }
        let mut got = 0;
        while got < self.raw.len() {
            match self.reader.read(&mut self.raw[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    self.error = Some(e);
                    self.done = true;
                    return false;
                }
            }
        }
        if got < 2 {
            self.done = true;
            return false;
        }
        self.input.clear();
        self.input.extend(
            self.raw[..got - got % 2]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| i16::from_le_bytes(*b)),
        );
        let n = self.resampler.process(&self.input, &mut self.resampled);
        for &s in &self.resampled[..n] {
            for _ in 0..self.channels {
                self.pending.push_back(s);
            }
        }
        if got < self.raw.len() {
            self.done = true;
        }
        true
    }
}

impl Pcm for Spool {
    fn fill(&mut self, frames: usize, out: &mut Vec<i16>) -> usize {
        while self.pending.len() < frames * self.channels && self.more() {}
        let n = (self.pending.len() / self.channels).min(frames);
        out.extend(self.pending.drain(..n * self.channels));
        self.frames += n as u64;
        n
    }
}

/// The JSON file written next to a section's audio.
#[derive(Debug, Serialize)]
struct Report<'a> {
    #[serde(flatten)]
    meta: &'a super::Meta,
    recording_id: &'a str,
    file: String,
    format: Format,
    channels: super::settings::Channels,
    sample_rate: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    bitrate: Option<u32>,
    duration_ms: u64,
}

/// Convert one section's spool; returns its audio file and its report.
///
/// # Errors
///
/// When the spool cannot be read, or the files written.
pub fn convert_section(
    spool: &Path,
    (section, started_ms): (usize, u64),
    job: &MixJob,
    settings: &Settings,
    meta: &super::Meta,
) -> std::io::Result<(PathBuf, PathBuf)> {
    if settings.format == Format::Pcap {
        return Err(std::io::Error::other("a mixer recording has no pcap"));
    }
    let out = spool.with_extension(settings.format.extension());
    let part = out.with_extension(format!("{}.part", settings.format.extension()));
    let mut meta = meta.clone();
    meta.section = section;
    let tags = super::naming::tags(&meta, started_ms);
    let mut src = Spool::open(spool, settings.sample_rate, settings.channels.count())?;
    let encoded = super::encode::encode(&mut src, settings, &tags, &part)
        .and_then(|()| src.error.take().map_or(Ok(()), Err));
    if let Err(e) = encoded {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    let report = Report {
        meta: &meta,
        recording_id: &job.recording_id,
        file: out
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
        format: settings.format,
        channels: settings.channels,
        sample_rate: settings.sample_rate,
        bitrate: settings.format.lossy().then_some(settings.bitrate),
        duration_ms: src.frames * 1000 / u64::from(settings.sample_rate),
    };
    let json = spool.with_extension("json");
    let json_part = spool.with_extension("json.part");
    let body = serde_json::to_vec_pretty(&report).map_err(std::io::Error::other)?;
    if let Err(e) =
        std::fs::write(&json_part, body).and_then(|()| std::fs::rename(&json_part, &json))
    {
        let _ = std::fs::remove_file(&json_part);
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    std::fs::rename(&part, &out)?;
    Ok((out, json))
}

/// What became of one spool.
enum Converted {
    /// Its audio file and report, made now.
    Made(PathBuf, PathBuf),
    /// Made before (its spool gone, its audio there): converted again
    /// after a restart that came before its outcome was saved.
    Before(PathBuf),
    /// Never written (a track of a participant that was not there).
    Nothing,
    Failed(String),
}

/// Convert `spool` (its section and start), its spool removed once done.
fn convert_one(
    spool: &Path,
    at: (usize, u64),
    job: &MixJob,
    settings: &Settings,
    meta: &super::Meta,
) -> Converted {
    if !spool.exists() {
        let out = spool.with_extension(settings.format.extension());
        return if out.exists() {
            Converted::Before(out)
        } else {
            Converted::Nothing
        };
    }
    match convert_section(spool, at, job, settings, meta) {
        Ok((out, json)) => {
            log::info!(
                "recording: {} written ({})",
                out.display(),
                job.recording_id
            );
            if let Err(e) = std::fs::remove_file(spool) {
                log::warn!("recording: removing {}: {e}", spool.display());
            }
            Converted::Made(out, json)
        }
        Err(e) => {
            log::warn!(
                "recording: converting {}: {e}; the spool is kept",
                spool.display()
            );
            Converted::Failed(format!("{}: {e}", spool.display()))
        }
    }
}

/// Convert every section of `job` (and its tracks), keep the files in
/// `store`, and report the outcome as recording `job.recording_id`'s: the
/// first section's file, the tracks', whether all was uploaded, and what
/// could not be converted (its spool kept). With no audio at all, it
/// failed.
pub(super) fn run(
    job: &MixJob,
    conversion: &super::Conversion,
    store: &super::store::Store,
    events: Option<&crate::relay::media_events::MediaEvents>,
) {
    use crate::relay::media_events::{MediaEventKind, Subject};
    let mut audio = Vec::new();
    let mut keep = Vec::new();
    let mut errors = Vec::new();
    let start = |section: usize| job.starts.get(section - 1).copied().unwrap_or(0);
    for (i, spool) in job.spools.iter().enumerate() {
        match convert_one(
            spool,
            (i + 1, start(i + 1)),
            job,
            &conversion.settings,
            &conversion.meta,
        ) {
            Converted::Made(out, json) => {
                keep.push(out.clone());
                keep.push(json);
                audio.push(out);
            }
            Converted::Before(out) => audio.push(out),
            Converted::Nothing => {}
            Converted::Failed(e) => errors.push(e),
        }
    }
    let mut tracks = Vec::new();
    for (section, endpoint, spool) in &job.tracks {
        let mut meta = conversion.meta.clone();
        meta.metadata.insert("track".to_owned(), endpoint.clone());
        match convert_one(
            spool,
            (*section, start(*section)),
            job,
            &conversion.settings,
            &meta,
        ) {
            Converted::Made(out, json) => {
                keep.push(out.clone());
                keep.push(json);
                tracks.push((endpoint.clone(), out.display().to_string()));
            }
            Converted::Before(out) => tracks.push((endpoint.clone(), out.display().to_string())),
            Converted::Nothing => {}
            Converted::Failed(e) => errors.push(e),
        }
    }
    let left = store.keep(&keep, &conversion.meta);
    let uploaded = store.uploads().then_some(left.is_empty());
    let Some(ev) = events else {
        return;
    };
    let subject = Subject::Recording(job.recording_id.clone());
    match audio.first() {
        Some(first) => ev.emit(
            subject,
            MediaEventKind::RecordingDone {
                file: Some(first.display().to_string()),
                uploaded,
                tracks,
                errors,
            },
        ),
        None => ev.emit(
            subject,
            MediaEventKind::Failed {
                what: "recording",
                reason: if errors.is_empty() {
                    "no audio was recorded".to_owned()
                } else {
                    errors.join("; ")
                },
            },
        ),
    }
}

/// The spool of section `section` of a recording named `base` in `dir`:
/// `<base>.mixpcm`, or a free numbered name when a file of that name (any
/// recording extension) exists.
#[must_use]
pub fn spool_path(dir: &Path, base: &str) -> PathBuf {
    let taken = |p: &Path| {
        [SPOOL, "wav", "flac", "opus", "mp3", "json", "pcap"]
            .iter()
            .any(|x| p.with_extension(x).exists())
    };
    let mut n = 1u32;
    loop {
        let name = if n == 1 {
            format!("{base}.{SPOOL}")
        } else {
            format!("{base}-{n}.{SPOOL}")
        };
        let p = dir.join(name);
        if !taken(&p) || n >= 10_000 {
            return p;
        }
        n += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rtpflux-mixrec-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn block(tick: u64, v: i16) -> MixBlock {
        MixBlock {
            tick,
            pcm: [v; BLOCK_SAMPLES],
            tracks: Vec::new(),
        }
    }

    /// Lost periods are silence at their place; the job goes when the
    /// queue closes, and only if one was set.
    #[test]
    fn gaps_are_silence_and_the_job_goes_at_the_end() {
        let d = dir("gaps");
        let path = d.join("m.mixpcm");
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        let written = Arc::new(Written::default());
        let (jobs_tx, jobs_rx) = std::sync::mpsc::channel();
        let finish: Finish = Arc::default();
        spawn_writer(&path, rx, Arc::clone(&written), Arc::clone(&finish), None).unwrap();
        tx.send(block(0, 100)).unwrap();
        tx.send(block(3, 300)).unwrap();
        let job = super::super::Job {
            pcap: path.clone(),
            conversion: super::super::Conversion {
                settings: Settings::default(),
                meta: super::super::Meta {
                    call_id: "mixer-1".into(),
                    from_tag: "rec-x".into(),
                    to_tag: None,
                    section: 1,
                    left_port: 0,
                    opus_pts: Vec::new(),
                    amr_pts: Vec::new(),
                    amr_wb_pts: Vec::new(),
                    metadata: std::collections::BTreeMap::new(),
                    mixer_id: Some(1),
                },
            },
            last: true,
            mix: None,
        };
        hand_over(&finish, job, jobs_tx).unwrap();
        drop(tx);
        jobs_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the job, once the queue closed");
        assert_eq!(written.periods.load(Ordering::Relaxed), 4);
        let pcm: Vec<i16> = std::fs::read(&path)
            .unwrap()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| i16::from_le_bytes(*b))
            .collect();
        assert_eq!(pcm.len(), 4 * BLOCK_SAMPLES);
        let firsts: Vec<i16> = pcm.chunks(BLOCK_SAMPLES).map(|c| c[0]).collect();
        assert_eq!(firsts, [100, 0, 0, 300], "two lost periods: silence");
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// A full disk: every period fails, is counted, and nothing half
    /// written stays; the job still goes at the end.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_full_disk_is_counted_and_leaves_no_partial_period() {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap();
        let mut out = Out::new(file, PathBuf::from("/dev/full"));
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        for t in [0, 1, 4] {
            tx.send(block(t, 7)).unwrap();
        }
        drop(tx);
        let written = Written::default();
        let finish: Finish = Arc::default();
        write(&mut out, &rx, &written, &finish, None);
        assert_eq!(out.periods, 0);
        assert_eq!(
            written.failed.load(Ordering::Relaxed),
            3,
            "three periods of the mix not written (the lost ones are the mixer's)"
        );
        assert!(finish.lock().unwrap().writer_done);
    }

    /// A track whose file name is taken is given up: the other file is
    /// never written into.
    #[test]
    fn a_taken_track_name_is_left_alone() {
        let d = dir("taken");
        let taken = d.join("t.mixpcm");
        std::fs::write(&taken, b"someone else's").unwrap();
        assert!(Track::open(taken.clone(), 3).is_none());
        assert_eq!(std::fs::read(&taken).unwrap(), b"someone else's");
        let fresh = Track::open(d.join("u.mixpcm"), 2).unwrap();
        assert!(fresh.finish());
        assert_eq!(
            std::fs::metadata(d.join("u.mixpcm")).unwrap().len(),
            2 * PERIOD_BYTES
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// The hand-over to a converter that is gone fails, never silently.
    #[test]
    fn a_hand_over_with_no_converter_fails() {
        let finish: Finish = Arc::default();
        finish.lock().unwrap().writer_done = true;
        let (jobs, gone) = std::sync::mpsc::channel();
        drop(gone);
        let job = super::super::Job {
            pcap: PathBuf::new(),
            conversion: super::super::Conversion {
                settings: Settings::default(),
                meta: super::super::Meta {
                    call_id: "mixer-1".into(),
                    from_tag: "rec-x".into(),
                    to_tag: None,
                    section: 1,
                    left_port: 0,
                    opus_pts: Vec::new(),
                    amr_pts: Vec::new(),
                    amr_wb_pts: Vec::new(),
                    metadata: std::collections::BTreeMap::new(),
                    mixer_id: Some(1),
                },
            },
            last: true,
            mix: None,
        };
        assert!(hand_over(&finish, job, jobs).is_err());
    }

    /// A section converted before (its spool gone, its audio there) counts
    /// as converted: converting again after a restart does not fail it.
    #[test]
    fn a_section_converted_before_counts() {
        let d = dir("before");
        let spool = d.join("m.mixpcm");
        std::fs::write(spool.with_extension("wav"), b"RIFF").unwrap();
        let job = MixJob {
            recording_id: "rec-1".into(),
            spools: vec![spool.clone()],
            starts: vec![0],
            tracks: Vec::new(),
        };
        let settings = Settings {
            format: Format::Wav,
            ..Settings::default()
        };
        let meta = super::super::Meta {
            call_id: "mixer-1".into(),
            from_tag: "rec-1".into(),
            to_tag: None,
            section: 1,
            left_port: 0,
            opus_pts: Vec::new(),
            amr_pts: Vec::new(),
            amr_wb_pts: Vec::new(),
            metadata: std::collections::BTreeMap::new(),
            mixer_id: Some(1),
        };
        assert!(matches!(
            convert_one(&spool, (1, 0), &job, &settings, &meta),
            Converted::Before(_)
        ));
        assert!(matches!(
            convert_one(&d.join("none.mixpcm"), (1, 0), &job, &settings, &meta),
            Converted::Nothing
        ));
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// A spool becomes a WAV of the asked rate and channels, of its
    /// length; a pcap is refused.
    #[test]
    fn a_spool_is_converted_at_the_asked_rate() {
        let d = dir("convert");
        let spool = d.join("mixer-1.mixpcm");
        // One second of a ramp at 16 kHz.
        let raw: Vec<u8> = (0..16_000i32)
            .flat_map(|i| i16::try_from(i % 1000).unwrap().to_le_bytes())
            .collect();
        std::fs::write(&spool, raw).unwrap();
        let job = MixJob {
            recording_id: "rec-1".into(),
            spools: vec![spool.clone()],
            starts: vec![1_795_000_000_000],
            tracks: Vec::new(),
        };
        let meta = super::super::Meta {
            call_id: "mixer-1".into(),
            from_tag: "rec-1".into(),
            to_tag: None,
            section: 1,
            left_port: 0,
            opus_pts: Vec::new(),
            amr_pts: Vec::new(),
            amr_wb_pts: Vec::new(),
            metadata: std::collections::BTreeMap::new(),
            mixer_id: Some(1),
        };
        let settings = Settings {
            format: Format::Wav,
            channels: super::super::Channels::Stereo,
            sample_rate: 48_000,
            ..Settings::default()
        };
        let (out, json) =
            convert_section(&spool, (1, 1_795_000_000_000), &job, &settings, &meta).unwrap();
        let wav = std::fs::read(&out).unwrap();
        assert_eq!(&wav[..4], b"RIFF");
        assert_eq!(u16::from_le_bytes([wav[22], wav[23]]), 2, "stereo");
        assert_eq!(
            u32::from_le_bytes([wav[24], wav[25], wav[26], wav[27]]),
            48_000
        );
        let data = u32::from_le_bytes([wav[40], wav[41], wav[42], wav[43]]);
        // One second, two channels, 16 bits (the resampler's delay aside).
        assert!((190_000..=192_000).contains(&data), "{data}");
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(json).unwrap()).unwrap();
        assert_eq!(report["recording_id"], "rec-1");
        assert_eq!(report["mixer_id"], 1);
        let pcap = Settings {
            format: Format::Pcap,
            ..settings
        };
        assert!(convert_section(&spool, (1, 1_795_000_000_000), &job, &pcap, &meta).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
