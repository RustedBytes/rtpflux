//! Converting a finished recording: its pcap is read back, the two parties'
//! audio aligned (`recording::mix`) and written in the chosen format
//! (`recording::encode`), next to the pcap with the format's extension, with a
//! JSON file of what was recorded. Conversions run on one background thread,
//! never on the media path.

use super::mix::{Mixer, SideStats};
use super::settings::{Format, Settings};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender};
use std::thread::JoinHandle;

/// Who and what a recording is of.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub call_id: String,
    pub from_tag: String,
    pub to_tag: Option<String>,
    /// The media section, from 1.
    pub section: usize,
    /// The relay port the caller sends to: its packets are the left
    /// channel.
    pub left_port: u16,
    /// The payload types that carry Opus (G.711, G.722 and G.729 ones are
    /// static).
    pub opus_pts: Vec<u8>,
    /// … AMR and AMR-WB.
    #[serde(default)]
    pub amr_pts: Vec<u8>,
    #[serde(default)]
    pub amr_wb_pts: Vec<u8>,
    /// The user's metadata (`[recording.metadata]`, `start recording`'s
    /// `metadata`): in the JSON and the audio file's tags.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub metadata: std::collections::BTreeMap<String, String>,
}

impl Meta {
    /// The dynamic payload types and their codecs.
    #[must_use]
    pub fn dynamic(&self) -> Vec<(rtpflux_core::rtp::Pt, rtpflux_core::sdp::Codec)> {
        use rtpflux_core::sdp::Codec;
        [
            (&self.opus_pts, Codec::Opus),
            (&self.amr_pts, Codec::Amr),
            (&self.amr_wb_pts, Codec::AmrWb),
        ]
        .into_iter()
        .flat_map(|(pts, c)| {
            pts.iter()
                .copied()
                .filter_map(rtpflux_core::rtp::Pt::new)
                .map(move |p| (p, c))
        })
        .collect()
    }
}

/// How to convert one recording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversion {
    pub settings: Settings,
    pub meta: Meta,
}

/// A recording that ended (`last`: for good, not just because the relay
/// stopped) and is to be converted.
#[derive(Debug)]
pub struct Job {
    pub pcap: PathBuf,
    pub conversion: Conversion,
    pub last: bool,
}

/// One party, in the JSON file.
#[derive(Debug, Serialize)]
struct Party {
    packets: u64,
    lost: u64,
    streams: usize,
}

impl From<SideStats> for Party {
    fn from(s: SideStats) -> Self {
        Party {
            packets: s.packets,
            lost: s.lost,
            streams: s.streams,
        }
    }
}

/// The JSON file written next to the audio.
#[derive(Debug, Serialize)]
struct Report<'a> {
    #[serde(flatten)]
    meta: &'a Meta,
    file: String,
    format: Format,
    channels: super::settings::Channels,
    sample_rate: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    bitrate: Option<u32>,
    /// Unix time of the first recorded audio, in milliseconds.
    started_ms: u64,
    duration_ms: u64,
    caller: Party,
    callee: Party,
}

/// The audio file of the recording at `pcap`.
#[must_use]
pub fn output_path(pcap: &Path, format: Format) -> PathBuf {
    pcap.with_extension(format.extension())
}

/// Convert the recording at `pcap`; returns the audio file's path.
///
/// # Errors
///
/// When the pcap cannot be read, or the audio or JSON file written.
pub fn convert(pcap: &Path, c: &Conversion) -> std::io::Result<PathBuf> {
    let settings = &c.settings;
    let out = output_path(pcap, settings.format);
    if settings.format == Format::Pcap {
        return Ok(out);
    }
    let frames = super::read::frames(pcap)?;
    // A call encrypted end to end (ZRTP) holds ciphertext the relay cannot
    // decode: converting it would only make noise. It fails, so the pcap
    // stays (with the reason in the log).
    if frames.iter().any(super::read::Frame::is_zrtp) {
        return Err(std::io::Error::other(
            "encrypted end to end (ZRTP): not converted, the pcap is kept",
        ));
    }
    let mut mixer = Mixer::new(
        std::fs::File::open(pcap)?,
        frames,
        c.meta.left_port,
        &c.meta.dynamic(),
        settings.channels,
        settings.sample_rate,
    );
    if mixer.is_empty() {
        return Err(std::io::Error::other(
            "no audio of a codec the relay decodes (G.711, Opus)",
        ));
    }
    let part = out.with_extension(format!("{}.part", settings.format.extension()));
    let tags = super::naming::tags(&c.meta, mixer.start_us / 1000);
    let written = super::encode::encode(&mut mixer, settings, &tags, &part);
    if let Err(e) = written {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    let report = Report {
        meta: &c.meta,
        file: out
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
        format: settings.format,
        channels: settings.channels,
        sample_rate: settings.sample_rate,
        bitrate: settings.format.lossy().then_some(settings.bitrate),
        started_ms: mixer.start_us / 1000,
        duration_ms: mixer.position() * 1000 / u64::from(settings.sample_rate),
        caller: mixer.stats[0].into(),
        callee: mixer.stats[1].into(),
    };
    // The report first, then the audio, each appearing whole (written
    // aside, then renamed): whoever sees the audio file finds its report.
    let json = serde_json::to_vec_pretty(&report).map_err(std::io::Error::other)?;
    let json_part = pcap.with_extension("json.part");
    if let Err(e) = std::fs::write(&json_part, json)
        .and_then(|()| std::fs::rename(&json_part, pcap.with_extension("json")))
    {
        let _ = std::fs::remove_file(&json_part);
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    std::fs::rename(&part, &out)?;
    Ok(out)
}

/// Convert each job that arrives until every sender is gone, then hand the
/// finished recording's files to `store`. The pcap is removed after a
/// successful conversion of a recording that ended for good, unless it is
/// to be kept; it always stays when the conversion fails. A recording ended
/// only because the relay stopped stays local with its pcap, to be
/// continued: with `resumable` (a state file, so the call comes back) it is
/// not converted now, which would be redone when it ends and only holds
/// up the shutdown; without, it is converted, as it will not come back.
pub fn run(
    jobs: &Receiver<Job>,
    store: &super::store::Store,
    resumable: bool,
    activity: &super::activity::Activity,
    events: Option<&crate::relay::media_events::MediaEvents>,
) {
    use crate::relay::media_events::{MediaEventKind, Subject};
    // A finished recording (its last job) is reported to the control
    // thread's subscribers: its file, and whether it was uploaded.
    let report = |job: &Job, file: Option<String>, uploaded: Option<bool>| {
        if let Some(ev) = events.filter(|_| job.last) {
            let m = &job.conversion.meta;
            ev.emit(
                Subject::Dialog {
                    call_id: m.call_id.clone(),
                    from_tag: m.from_tag.clone(),
                    section: m.section,
                },
                MediaEventKind::RecordingDone { file, uploaded },
            );
        }
    };
    for job in jobs {
        if !job.last && resumable {
            log::debug!("recording: {} kept, to be continued", job.pcap.display());
            continue;
        }
        let settings = job.conversion.settings;
        // A conversion that panics (a codec on odd input) loses this
        // recording's audio file, not the relay: the pcap is kept.
        let converted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            convert(&job.pcap, &job.conversion)
        }))
        .unwrap_or_else(|_| Err(std::io::Error::other("the conversion panicked")));
        match converted {
            Ok(out) => {
                activity
                    .converted
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let mut files = Vec::new();
                if settings.format == Format::Pcap {
                    files.push(job.pcap.clone());
                } else {
                    log::info!(
                        "recording: {} written ({})",
                        out.display(),
                        job.conversion.meta.call_id
                    );
                    files.push(out);
                    files.push(job.pcap.with_extension("json"));
                    if settings.keep_pcap {
                        files.push(job.pcap.clone());
                    } else if job.last
                        && let Err(e) = std::fs::remove_file(&job.pcap)
                    {
                        log::warn!("recording: removing {}: {e}", job.pcap.display());
                    }
                }
                if job.last {
                    let left = store.keep(&files, &job.conversion.meta);
                    let uploaded = store.uploads().then_some(left.is_empty());
                    let file = files.first().map(|f| f.display().to_string());
                    report(&job, file, uploaded);
                }
            }
            Err(e) => {
                activity
                    .conversions_failed
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                log::warn!(
                    "recording: converting {}: {e}; the pcap is kept",
                    job.pcap.display()
                );
                report(&job, None, None);
            }
        }
    }
}

/// Remove the partly written audio and report files (`*.part`) in `dir`
/// (and its `recording-path` subdirectories) that a conversion cut short
/// by a crash or power loss left; returns how many. Their recordings are
/// converted again when they end.
#[must_use]
pub fn remove_partial(dir: &Path) -> usize {
    super::naming::walk(dir)
        .into_iter()
        .filter(|(_, path, _)| path.extension().is_some_and(|x| x == "part"))
        .filter(|(_, path, _)| std::fs::remove_file(path).is_ok())
        .count()
}

/// Start the conversion thread, keeping finished recordings in `store`;
/// `resumable`: calls are saved across restarts (see [`run`]).
///
/// # Errors
///
/// When the thread cannot be started.
pub fn spawn(
    store: super::store::Store,
    resumable: bool,
    activity: std::sync::Arc<super::activity::Activity>,
    events: Option<crate::relay::media_events::MediaEvents>,
) -> std::io::Result<(Sender<Job>, JoinHandle<()>)> {
    let (tx, rx) = std::sync::mpsc::channel();
    let thread = std::thread::Builder::new()
        .name("rtpflux-recording".to_owned())
        .spawn(move || run(&rx, &store, resumable, &activity, events.as_ref()))?;
    Ok((tx, thread))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A recording interrupted by the relay stopping: converted only when
    /// its call will not come back (no state file), its pcap kept anyway.
    #[test]
    fn an_interrupted_recording_is_converted_only_if_not_resumable() {
        let dir = std::env::temp_dir().join(format!("rtpflux-resume-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pcap = dir.join("call.pcap");
        let mut r = super::super::Recorder::open(&pcap).unwrap();
        for seq in 0..50u8 {
            let mut p = std::vec![0x80, 0, 0, seq, 0, 0, 0, 0, 0, 0, 0, 7];
            p[4..8].copy_from_slice(&(u32::from(seq) * 160).to_be_bytes());
            p.extend_from_slice(&[0xd5; 160]);
            r.packet(
                "192.0.2.1:4000".parse().unwrap(),
                "192.0.2.9:30000".parse().unwrap(),
                &p,
            );
        }
        r.flush();
        drop(r);
        let job = || Job {
            pcap: pcap.clone(),
            conversion: Conversion {
                settings: Settings {
                    format: Format::Wav,
                    ..Settings::default()
                },
                meta: Meta {
                    call_id: "c".to_owned(),
                    from_tag: "f".to_owned(),
                    to_tag: None,
                    section: 1,
                    left_port: 30_000,
                    opus_pts: Vec::new(),
                    amr_pts: Vec::new(),
                    amr_wb_pts: Vec::new(),
                    metadata: std::collections::BTreeMap::new(),
                },
            },
            last: false,
        };
        let wav = output_path(&pcap, Format::Wav);
        for (resumable, converted) in [(true, false), (false, true)] {
            let (tx, rx) = std::sync::mpsc::channel();
            tx.send(job()).unwrap();
            drop(tx);
            run(
                &rx,
                &super::super::store::Store::Local,
                resumable,
                &super::super::activity::Activity::default(),
                None,
            );
            assert_eq!(wav.exists(), converted, "resumable {resumable}");
            assert!(pcap.exists(), "the pcap stays, to be continued");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A call encrypted end to end (ZRTP in the recording) is not
    /// converted, even when it ends for good: its audio is ciphertext.
    /// The pcap stays.
    #[test]
    fn a_zrtp_recording_is_not_converted() {
        let dir = std::env::temp_dir().join(format!("rtpflux-zrtp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pcap = dir.join("zrtp.pcap");
        let mut r = super::super::Recorder::open(&pcap).unwrap();
        let (from, to) = (
            "192.0.2.1:4000".parse().unwrap(),
            "192.0.2.9:30000".parse().unwrap(),
        );
        // The ZRTP Hello, then SRTP the relay cannot read (as PCMU).
        r.packet(from, to, b"\x10\x00\x00\x01ZRTP\x00\x00\x00\x07\x50\x5a");
        for seq in 0..50u8 {
            let mut p = std::vec![0x80, 0, 0, seq, 0, 0, 0, 0, 0, 0, 0, 7];
            p.extend_from_slice(&[0x5a; 170]);
            r.packet(from, to, &p);
        }
        r.flush();
        drop(r);
        let c = Conversion {
            settings: Settings {
                format: Format::Wav,
                ..Settings::default()
            },
            meta: Meta {
                call_id: "c".to_owned(),
                from_tag: "f".to_owned(),
                to_tag: None,
                section: 1,
                left_port: 30_000,
                opus_pts: Vec::new(),
                amr_pts: Vec::new(),
                amr_wb_pts: Vec::new(),
                metadata: std::collections::BTreeMap::new(),
            },
        };
        let e = convert(&pcap, &c).unwrap_err();
        assert!(e.to_string().contains("ZRTP"), "{e}");
        assert!(!output_path(&pcap, Format::Wav).exists());
        assert!(pcap.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn partial_files_are_removed_and_nothing_else() {
        let dir = std::env::temp_dir().join(format!("rtpflux-part-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub.part")).unwrap();
        for f in ["a.wav.part", "b.flac.part", "c.pcap", "d.wav", "e.json"] {
            std::fs::write(dir.join(f), b"x").unwrap();
        }
        assert_eq!(remove_partial(&dir), 2);
        let mut left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, ["c.pcap", "d.wav", "e.json", "sub.part"]);
        assert_eq!(remove_partial(&dir.join("missing")), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
