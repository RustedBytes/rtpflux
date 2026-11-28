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
    /// The spools, section after section.
    pub spools: Vec<PathBuf>,
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
pub fn hand_over(finish: &Finish, job: super::Job, jobs: Sender<super::Job>) {
    let Ok(mut h) = finish.lock() else {
        return;
    };
    if h.writer_done {
        drop(h);
        let _ = jobs.send(job);
    } else {
        h.job = Some((job, jobs));
    }
}

/// Counters a writer keeps: periods written (silence included).
#[derive(Debug, Default)]
pub struct Written {
    pub periods: AtomicU64,
}

/// Start the writer of one section: the blocks from `blocks` into the
/// spool at `path` (created; appended to if it exists), until the queue
/// closes; then the job in `finish`, if any, goes to the converter.
///
/// # Errors
///
/// When the spool cannot be opened or the thread started.
pub fn spawn_writer(
    path: &Path,
    blocks: Receiver<MixBlock>,
    written: Arc<Written>,
    finish: Finish,
    tracks: Option<TrackPath>,
) -> std::io::Result<()> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let path = path.to_owned();
    std::thread::Builder::new()
        .name("rtpflux-mixrec".to_owned())
        .spawn(move || write(&path, file, &blocks, &written, &finish, tracks.as_ref()))?;
    Ok(())
}

/// A period's samples as little-endian bytes.
fn le(pcm: &[i16; BLOCK_SAMPLES], out: &mut [u8; BLOCK_SAMPLES * 2]) {
    for (b, s) in out.as_chunks_mut::<2>().0.iter_mut().zip(pcm) {
        *b = s.to_le_bytes();
    }
}

/// Write `data`, logging the first failure only (the timeline goes on).
fn put(file: &mut impl std::io::Write, data: &[u8], path: &Path, failed: &mut bool) {
    if let Err(e) = file.write_all(data)
        && !*failed
    {
        log::warn!("recording: {}: {e}", path.display());
        *failed = true;
    }
}

fn write(
    path: &Path,
    mut file: File,
    blocks: &Receiver<MixBlock>,
    written: &Written,
    finish: &Finish,
    track_path: Option<&TrackPath>,
) {
    let silence = [0u8; BLOCK_SAMPLES * 2];
    let mut bytes = [0u8; BLOCK_SAMPLES * 2];
    let mut next = 0u64;
    let mut failed = false;
    // The tracks open so far: their files, and whether they had this
    // period.
    let mut tracks: HashMap<Arc<str>, (BufWriter<File>, PathBuf)> = HashMap::new();
    for block in blocks {
        // Periods lost on the way: silence in their place, on every track.
        while next < block.tick {
            put(&mut file, &silence, path, &mut failed);
            for (t, p) in tracks.values_mut() {
                put(t, &silence, p, &mut failed);
            }
            next += 1;
        }
        le(&block.pcm, &mut bytes);
        put(&mut file, &bytes, path, &mut failed);
        if let Some(track_path) = track_path {
            for (key, pcm) in &block.tracks {
                if !tracks.contains_key(key) {
                    let p = track_path(key);
                    match File::create(&p) {
                        Ok(f) => {
                            // Silence from the section's start.
                            let mut w = BufWriter::with_capacity(64 * 1024, f);
                            for _ in 0..block.tick {
                                put(&mut w, &silence, &p, &mut failed);
                            }
                            tracks.insert(Arc::clone(key), (w, p));
                        }
                        Err(e) => {
                            if !failed {
                                log::warn!("recording: {}: {e}", p.display());
                                failed = true;
                            }
                            continue;
                        }
                    }
                }
                if let Some((t, p)) = tracks.get_mut(key) {
                    le(pcm, &mut bytes);
                    put(t, &bytes, p, &mut failed);
                }
            }
            // Those that left (or were not in this period): silence.
            for (key, (t, p)) in &mut tracks {
                if !block.tracks.iter().any(|(k, _)| k == key) {
                    put(t, &silence, p, &mut failed);
                }
            }
        }
        next = block.tick + 1;
        written.periods.store(next, Ordering::Relaxed);
    }
    let _ = file.sync_data();
    drop(file);
    for (mut t, p) in tracks.into_values() {
        if let Err(e) = t.flush().and_then(|()| t.get_ref().sync_data()) {
            log::warn!("recording: {}: {e}", p.display());
        }
    }
    let job = finish.lock().ok().and_then(|mut h| {
        h.writer_done = true;
        h.job.take()
    });
    if let Some((job, jobs)) = job
        && jobs.send(job).is_err()
    {
        log::warn!(
            "recording: {}: no converter left, not converted",
            path.display()
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
                Ok(0) | Err(_) => break,
                Ok(n) => got += n,
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
    section: usize,
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
    let started = std::fs::metadata(spool)
        .and_then(|m| m.created().or_else(|_| m.modified()))
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0));
    let tags = super::naming::tags(&meta, started);
    let mut src = Spool::open(spool, settings.sample_rate, settings.channels.count())?;
    if let Err(e) = super::encode::encode(&mut src, settings, &tags, &part) {
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

/// Convert every section of `job`, keep the files in `store`, and report
/// the outcome as recording `job.recording_id`'s: the first section's
/// file (and every section's, in order), whether it was all uploaded.
/// The spools go once converted; a failed section keeps its spool.
pub(super) fn run(
    job: &MixJob,
    conversion: &super::Conversion,
    store: &super::store::Store,
    events: Option<&crate::relay::media_events::MediaEvents>,
) {
    use crate::relay::media_events::{MediaEventKind, Subject};
    let mut audio = Vec::new();
    let mut keep = Vec::new();
    let mut failure = None;
    for (i, spool) in job.spools.iter().enumerate() {
        if !spool.exists() {
            continue;
        }
        match convert_section(spool, i + 1, job, &conversion.settings, &conversion.meta) {
            Ok((out, json)) => {
                log::info!(
                    "recording: {} written ({})",
                    out.display(),
                    job.recording_id
                );
                let _ = std::fs::remove_file(spool);
                keep.push(out.clone());
                keep.push(json);
                audio.push(out);
            }
            Err(e) => {
                log::warn!(
                    "recording: converting {}: {e}; the spool is kept",
                    spool.display()
                );
                failure = Some(e.to_string());
            }
        }
    }
    let mut tracks = Vec::new();
    for (section, endpoint, spool) in &job.tracks {
        if !spool.exists() {
            continue;
        }
        let mut meta = conversion.meta.clone();
        meta.metadata.insert("track".to_owned(), endpoint.clone());
        match convert_section(spool, *section, job, &conversion.settings, &meta) {
            Ok((out, json)) => {
                let _ = std::fs::remove_file(spool);
                keep.push(out.clone());
                keep.push(json);
                tracks.push((endpoint.clone(), out.display().to_string()));
            }
            Err(e) => {
                log::warn!(
                    "recording: converting {}: {e}; the spool is kept",
                    spool.display()
                );
            }
        }
    }
    let left = store.keep(&keep, &conversion.meta);
    let uploaded = store.uploads().then_some(left.is_empty());
    let Some(ev) = events else {
        return;
    };
    let subject = Subject::Recording(job.recording_id.clone());
    match (audio.first(), failure) {
        (Some(first), _) => ev.emit(
            subject,
            MediaEventKind::RecordingDone {
                file: Some(first.display().to_string()),
                uploaded,
                tracks,
            },
        ),
        (None, failure) => ev.emit(
            subject,
            MediaEventKind::Failed {
                what: "recording",
                reason: failure.unwrap_or_else(|| "no audio was recorded".to_owned()),
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
        hand_over(&finish, job, jobs_tx);
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
        let (out, json) = convert_section(&spool, 1, &job, &settings, &meta).unwrap();
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
        assert!(convert_section(&spool, 1, &job, &pcap, &meta).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
