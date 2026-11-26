//! Recordings converted to audio files: a call where the caller talks for
//! the first half second and the callee for the second is recorded, the
//! recording ended (`stop recording`, or the call deleted), and the file the
//! relay writes is decoded independently (Symphonia; Ogg Opus through its
//! Ogg reader and opus-rs) and checked: rate, channels, length, which
//! channel carries whom, the JSON file, and whether the pcap was kept.

#[path = "support/logging.rs"]
mod logging;

use rtpflux::config::Config;
use rtpflux::control::Control;
use rtpflux::relay::Relay;
use rtpflux_core::g711::linear_to_ulaw;
use rtpflux_core::sdp::{MAX_MEDIA, Media, read_media};
use rtpflux_ng::bencode::{Encoder, Value, decode};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static COOKIE: AtomicUsize = AtomicUsize::new(0);

fn request(pairs: &[(&str, &[u8])]) -> Vec<u8> {
    let mut sorted = pairs.to_vec();
    sorted.sort_by_key(|(k, _)| *k);
    let mut buf = vec![0u8; 8192];
    let mut e = Encoder::new(&mut buf);
    let cookie = format!("r{} ", COOKIE.fetch_add(1, Ordering::Relaxed));
    e.raw(cookie.as_bytes()).unwrap();
    e.dict().unwrap();
    for (k, v) in sorted {
        e.bytes(k.as_bytes()).unwrap();
        e.bytes(v).unwrap();
    }
    e.end().unwrap();
    let n = e.len();
    buf.truncate(n);
    buf
}

/// Send a request; the reply's SDP (panics on an error reply).
fn ng(c: &mut Control, pairs: &[(&str, &[u8])]) -> Vec<u8> {
    let raw = c.handle(&request(pairs)).unwrap().to_vec();
    let space = raw.iter().position(|&b| b == b' ').unwrap();
    let Ok(Value::Dict(d)) = decode(&raw[space + 1..]) else {
        panic!()
    };
    assert_eq!(
        d.get_bytes(b"result"),
        Some(&b"ok"[..]),
        "{}",
        String::from_utf8_lossy(&raw)
    );
    d.get_bytes(b"sdp").unwrap_or_default().to_vec()
}

fn endpoint() -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_nonblocking(true).unwrap();
    s
}

fn relay_port(sdp: &[u8]) -> SocketAddr {
    let mut m = [Media::EMPTY; MAX_MEDIA];
    read_media(sdp, &mut m).unwrap();
    SocketAddr::new("127.0.0.1".parse().unwrap(), m[0].port)
}

fn sdp(port: u16, opus: bool) -> String {
    let (formats, rtpmap) = if opus {
        ("111", "a=rtpmap:111 opus/48000/2\r\n")
    } else {
        ("0", "")
    };
    format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {port} RTP/AVP {formats}\r\n{rtpmap}"
    )
}

/// 20 ms of a 600 Hz tone at 8 kHz.
fn tone(k: usize) -> Vec<i16> {
    (0..160)
        .map(|i| {
            #[allow(clippy::cast_precision_loss)]
            let t = (k * 160 + i) as f64 / 8000.0;
            #[allow(clippy::cast_possible_truncation)]
            let s = (12_000.0 * (2.0 * std::f64::consts::PI * 600.0 * t).sin()) as i16;
            s
        })
        .collect()
}

/// A call `id` between two endpoints: the caller talks for 25 packets,
/// then the callee for 25 (20 ms apart), recorded with `options`; the
/// recording ends with `stop recording`, or with the call deleted when
/// `delete` is set. Returns the recording's pcap path.
#[allow(clippy::many_single_char_names)]
fn record_call(
    c: &mut Control,
    dir: &Path,
    id: &str,
    opus: bool,
    options: &[(&str, &[u8])],
    delete: bool,
) -> PathBuf {
    let (a, b) = (endpoint(), endpoint());
    let call = id.as_bytes();
    let offer = sdp(a.local_addr().unwrap().port(), opus);
    let answer = sdp(b.local_addr().unwrap().port(), opus);
    let off = ("endpoint-learning", &b"off"[..]);
    let to_b = ng(
        c,
        &[
            ("command", b"offer"),
            ("call-id", call),
            ("from-tag", b"f"),
            ("sdp", offer.as_bytes()),
            off,
        ],
    );
    let to_a = ng(
        c,
        &[
            ("command", b"answer"),
            ("call-id", call),
            ("from-tag", b"f"),
            ("to-tag", b"t"),
            ("sdp", answer.as_bytes()),
            off,
        ],
    );
    let (for_a, for_b) = (relay_port(&to_a), relay_port(&to_b));
    let mut start = vec![("command", &b"start recording"[..]), ("call-id", call)];
    start.extend_from_slice(options);
    ng(c, &start);
    std::thread::sleep(Duration::from_millis(50));
    let mut encoder = opus_rs::OpusEncoder::new(48_000, 1, opus_rs::Application::Voip).unwrap();
    let mut buf = [0u8; 2048];
    let t0 = Instant::now();
    for k in 0..50u16 {
        // One packet every 20 ms, on schedule.
        let due = t0 + Duration::from_millis(20 * u64::from(k));
        std::thread::sleep(due.saturating_duration_since(Instant::now()));
        let (from, to) = if k < 25 { (&a, for_a) } else { (&b, for_b) };
        let mut p = vec![0x80, if opus { 111 } else { 0 }];
        p.extend_from_slice(&k.to_be_bytes());
        let samples = tone(usize::from(k));
        if opus {
            p.extend_from_slice(&(u32::from(k) * 960).to_be_bytes());
            p.extend_from_slice(&0xA0A0u32.to_be_bytes());
            let wide: Vec<i16> = samples.iter().flat_map(|&s| [s; 6]).collect();
            let mut out = [0u8; 1275];
            let n = encoder.encode_i16(&wide, 960, &mut out).unwrap();
            p.extend_from_slice(&out[..n]);
        } else {
            p.extend_from_slice(&(u32::from(k) * 160).to_be_bytes());
            p.extend_from_slice(&0xA0A0u32.to_be_bytes());
            p.extend(samples.iter().map(|&s| linear_to_ulaw(s)));
        }
        // Different SSRCs per side.
        if k >= 25 {
            p[8..12].copy_from_slice(&0xB0B0u32.to_be_bytes());
        }
        from.send_to(&p, to).unwrap();
        while a.recv(&mut buf).is_ok() || b.recv(&mut buf).is_ok() {}
    }
    std::thread::sleep(Duration::from_millis(20));
    if delete {
        ng(c, &[("command", b"delete"), ("call-id", call)]);
    } else {
        ng(c, &[("command", b"stop recording"), ("call-id", call)]);
    }
    dir.join(format!("{id}-f-1.pcap"))
}

/// Wait for `path` to appear (the conversion runs in the background; it
/// writes the report, then the audio, each whole). A minute: encoding in a
/// debug build on a loaded machine is slow.
fn wait_for(path: &Path) {
    let end = Instant::now() + Duration::from_secs(60);
    while !path.exists() {
        assert!(Instant::now() < end, "{} never appeared", path.display());
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Decode an audio file: (rate, channels, interleaved samples in ±1.0).
fn decoded(path: &Path) -> (u32, usize, Vec<f32>) {
    use symphonia::core::codecs::audio::AudioDecoderOptions;
    use symphonia::core::formats::FormatOptions;
    use symphonia::core::formats::TrackType;
    use symphonia::core::formats::probe::Hint;
    use symphonia::core::io::{MediaSourceStream, MediaSourceStreamOptions};
    use symphonia::core::meta::MetadataOptions;
    let file = Box::new(std::fs::File::open(path).unwrap());
    let mss = MediaSourceStream::new(file, MediaSourceStreamOptions::default());
    let mut format = symphonia::default::get_probe()
        .probe(
            &Hint::new(),
            mss,
            FormatOptions::default(),
            MetadataOptions::default(),
        )
        .unwrap();
    let track = format.default_track(TrackType::Audio).unwrap();
    let params = track
        .codec_params
        .as_ref()
        .unwrap()
        .audio()
        .unwrap()
        .clone();
    let (id, rate) = (track.id, params.sample_rate.unwrap());
    let channels = params.channels.as_ref().unwrap().count();
    let opus = path.extension().is_some_and(|e| e == "opus");
    let mut samples = Vec::new();
    if opus {
        // Symphonia reads the Ogg pages; opus-rs decodes.
        let mut d = opus_rs::OpusDecoder::new(48_000, channels).unwrap();
        let mut pcm = vec![0f32; 5760 * channels];
        while let Ok(Some(packet)) = format.next_packet() {
            if packet.track_id == id {
                let n = d.decode(&packet.data, 5760, &mut pcm).unwrap();
                samples.extend_from_slice(&pcm[..n * channels]);
            }
        }
        return (48_000, channels, samples);
    }
    let mut decoder = symphonia::default::get_codecs()
        .make_audio_decoder(&params, &AudioDecoderOptions::default())
        .unwrap();
    while let Ok(Some(packet)) = format.next_packet() {
        if packet.track_id != id {
            continue;
        }
        if let Ok(buf) = decoder.decode(&packet) {
            let mut chunk = vec![0f32; buf.samples_interleaved()];
            buf.copy_to_slice_interleaved(&mut chunk);
            samples.extend_from_slice(&chunk);
        }
    }
    (rate, channels, samples)
}

/// Root-mean-square of channel `ch` over the frames `from..to` (fractions
/// of the whole).
fn level(samples: &[f32], channels: usize, ch: usize, from: f64, to: f64) -> f64 {
    let frames = samples.len() / channels;
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let (a, b) = (
        (frames as f64 * from) as usize,
        (frames as f64 * to) as usize,
    );
    let sum: f64 = (a..b)
        .map(|f| f64::from(samples[f * channels + ch]).powi(2))
        .sum();
    #[allow(clippy::cast_precision_loss)]
    (sum / (b - a).max(1) as f64).sqrt()
}

fn control(dir: &Path, port: u16) -> Control {
    logging::init();
    let config = Config::from_toml(&format!(
        "[[interface]]\nname = \"lo\"\naddress = \"127.0.0.1\"\n[ports]\nmin = {port}\nmax = {}\n\
         [sessions]\nmax = 8\n[runtime]\nworkers = 1\n",
        port + 63
    ))
    .unwrap();
    let mut c = Control::new(Relay::start(&config).unwrap(), config.interfaces.clone());
    c.set_recording_dir(Some(dir.to_path_buf()));
    c
}

fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rtpflux-rec-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The caller is heard on the left in the first half, the callee on the
/// right in the second.
fn assert_stereo(samples: &[f32], file: &Path) {
    let l1 = level(samples, 2, 0, 0.1, 0.4);
    let r1 = level(samples, 2, 1, 0.1, 0.4);
    let l2 = level(samples, 2, 0, 0.6, 0.9);
    let r2 = level(samples, 2, 1, 0.6, 0.9);
    let f = file.display();
    assert!(l1 > 0.1 && r2 > 0.1, "{f}: talk heard: {l1} {r2}");
    assert!(
        r1 < 0.02 && l2 < 0.02,
        "{f}: silence where nobody talks: {r1} {l2}"
    );
}

#[test]
fn wav_stereo_then_flac_mono_kept() {
    let dir = temp_dir("wav");
    let mut c = control(&dir, 55_000);
    let pcap = record_call(
        &mut c,
        &dir,
        "wav",
        false,
        &[
            ("format", b"wav"),
            ("channels", b"stereo"),
            ("sample-rate", b"16000"),
        ],
        false,
    );
    let wav = pcap.with_extension("wav");
    wait_for(&wav);
    let (rate, channels, samples) = decoded(&wav);
    assert_eq!((rate, channels), (16_000, 2));
    #[allow(clippy::cast_precision_loss)]
    let seconds = samples.len() as f64 / 2.0 / 16_000.0;
    assert!((0.9..1.2).contains(&seconds), "{seconds} s");
    assert_stereo(&samples, &wav);
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(pcap.with_extension("json")).unwrap())
            .unwrap();
    assert_eq!(json["call_id"], "wav");
    assert_eq!(json["caller"]["packets"], 25);
    assert_eq!(json["callee"]["packets"], 25);
    assert_eq!(json["format"], "wav");
    // The pcap is removed last, after the audio and JSON files.
    let end = Instant::now() + Duration::from_secs(10);
    while pcap.exists() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!pcap.exists(), "the pcap goes once converted");

    // FLAC, mono, the pcap kept, ended by deleting the call.
    let pcap = record_call(
        &mut c,
        &dir,
        "flac",
        false,
        &[
            ("format", b"flac"),
            ("channels", b"mono"),
            ("keep-pcap", b"yes"),
        ],
        true,
    );
    let flac = pcap.with_extension("flac");
    wait_for(&flac);
    let (rate, channels, samples) = decoded(&flac);
    assert_eq!((rate, channels), (8000, 1));
    assert!(level(&samples, 1, 0, 0.1, 0.4) > 0.1 && level(&samples, 1, 0, 0.6, 0.9) > 0.1);
    assert!(pcap.exists(), "kept as asked");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn an_opus_call_as_ogg_opus_and_mp3() {
    let dir = temp_dir("opus");
    let mut c = control(&dir, 55_100);
    let pcap = record_call(
        &mut c,
        &dir,
        "opus",
        true,
        &[
            ("format", b"opus"),
            ("sample-rate", b"48000"),
            ("bitrate", b"48"),
        ],
        false,
    );
    let ogg = pcap.with_extension("opus");
    wait_for(&ogg);
    let (_, channels, samples) = decoded(&ogg);
    assert_eq!(channels, 2);
    assert_stereo(&samples, &ogg);
    if cfg!(feature = "mp3") {
        let pcap = record_call(
            &mut c,
            &dir,
            "mp3",
            false,
            &[
                ("format", b"mp3"),
                ("sample-rate", b"16000"),
                ("bitrate", b"64"),
            ],
            false,
        );
        let mp3 = pcap.with_extension("mp3");
        wait_for(&mp3);
        let (rate, channels, samples) = decoded(&mp3);
        assert_eq!((rate, channels), (16_000, 2));
        assert_stereo(&samples, &mp3);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn bad_recording_options_are_refused() {
    let dir = temp_dir("bad");
    let mut c = control(&dir, 55_200);
    let a = endpoint();
    let offer = sdp(a.local_addr().unwrap().port(), false);
    ng(
        &mut c,
        &[
            ("command", b"offer"),
            ("call-id", b"x"),
            ("from-tag", b"f"),
            ("sdp", offer.as_bytes()),
        ],
    );
    for (key, value, needle) in [
        ("format", &b"aiff"[..], "unknown recording format aiff"),
        ("channels", b"quad", "stereo or mono"),
        ("sample-rate", b"44100", "sample_rate 44100"),
        ("sample-rate", b"fast", "not a number"),
    ] {
        let raw = c
            .handle(&request(&[
                ("command", b"start recording"),
                ("call-id", b"x"),
                (key, value),
            ]))
            .unwrap()
            .to_vec();
        let text = String::from_utf8_lossy(&raw);
        assert!(text.contains(needle), "{key}: {text}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// End to end against a real S3-compatible server (see the store's test
/// for the variables): a WAV recording ends up in the bucket, and leaves
/// the local directory.
#[cfg(feature = "s3")]
#[test]
#[ignore = "needs an S3-compatible server"]
fn recordings_are_uploaded_to_s3() {
    use rusty_s3::S3Action as _;
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} is not set"));
    let (endpoint, bucket_name) = (
        env("RTPFLUX_S3_TEST_ENDPOINT"),
        env("RTPFLUX_S3_TEST_BUCKET"),
    );
    let dir = temp_dir("s3");
    logging::init();
    let config = Config::from_toml(&format!(
        "[[interface]]\nname = \"lo\"\naddress = \"127.0.0.1\"\n[ports]\nmin = 55300\nmax = 55363\n\
         [sessions]\nmax = 8\n[runtime]\nworkers = 1\n\
         [recording]\ndir = \"{}\"\nformat = \"wav\"\nstorage = \"s3\"\n\
         [recording.s3]\nbucket = \"{bucket_name}\"\nregion = \"us-east-1\"\nendpoint = \"{endpoint}\"\n\
         prefix = \"e2e/\"\npath_style = true\n",
        dir.display()
    ))
    .unwrap();
    let mut c = Control::new(Relay::start(&config).unwrap(), config.interfaces.clone());
    c.set_recording_dir(config.recording.dir.clone());
    c.set_recording_settings(config.recording.settings());
    let pcap = record_call(&mut c, &dir, "s3call", false, &[], false);
    // Uploaded, then removed locally.
    let wav = pcap.with_extension("wav");
    let json = pcap.with_extension("json");
    let end = Instant::now() + Duration::from_secs(15);
    while wav.exists() || json.exists() || pcap.exists() {
        assert!(Instant::now() < end, "never uploaded");
        std::thread::sleep(Duration::from_millis(100));
    }
    let creds = rusty_s3::Credentials::new(env("AWS_ACCESS_KEY_ID"), env("AWS_SECRET_ACCESS_KEY"));
    let bucket = rusty_s3::Bucket::new(
        endpoint.parse().unwrap(),
        rusty_s3::UrlStyle::Path,
        bucket_name,
        "us-east-1",
    )
    .unwrap();
    let get = |key: &str| {
        let url = bucket
            .get_object(Some(&creds), key)
            .sign(Duration::from_secs(60));
        ureq::get(url.as_str())
            .call()
            .unwrap()
            .body_mut()
            .read_to_vec()
            .unwrap()
    };
    let audio = get("e2e/s3call-f-1.wav");
    let local = dir.join("downloaded.wav");
    std::fs::write(&local, &audio).unwrap();
    let (rate, channels, samples) = decoded(&local);
    assert_eq!((rate, channels), (8000, 2));
    assert_stereo(&samples, &local);
    let json = String::from_utf8(get("e2e/s3call-f-1.json")).unwrap();
    assert!(json.contains("\"call_id\": \"s3call\""), "{json}");
    drop(c);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `[recording] file_name` and metadata: names come from the template (a
/// repeated name gets `-2`, never another recording's file), and the
/// configured and per-call metadata end up in the JSON and the FLAC's
/// Vorbis comments, which a decoder still plays.
#[test]
fn file_names_and_metadata() {
    let dir = temp_dir("naming");
    let mut c = control(&dir, 55_400);
    c.set_recording_naming(
        "rec-{section}",
        std::collections::BTreeMap::from([("company".to_owned(), "Acme Corp".to_owned())]),
    );
    let opts: &[(&str, &[u8])] = &[("format", b"flac"), ("metadata", b"VIP customer")];
    record_call(&mut c, &dir, "named-1", false, opts, false);
    record_call(&mut c, &dir, "named-2", false, opts, false);
    let (first, second) = (dir.join("rec-1.flac"), dir.join("rec-1-2.flac"));
    wait_for(&first);
    wait_for(&second);
    let raw = std::fs::read(&first).unwrap();
    let text = String::from_utf8_lossy(&raw);
    for tag in [
        "CALL_ID=named-1",
        "COMPANY=Acme Corp",
        "COMMENT=VIP customer",
        "SECTION=1",
    ] {
        assert!(text.contains(tag), "{tag} in the FLAC's Vorbis comments");
    }
    assert!(String::from_utf8_lossy(&std::fs::read(&second).unwrap()).contains("CALL_ID=named-2"));
    let (rate, channels, samples) = decoded(&first);
    assert_eq!((rate, channels), (8000, 2));
    assert_stereo(&samples, &first);
    let json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("rec-1.json")).unwrap()).unwrap();
    assert_eq!(json["metadata"]["company"], "Acme Corp");
    assert_eq!(json["metadata"]["comment"], "VIP customer");
    drop(c);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Per-call output: `recording-path` (a subdirectory, made on demand),
/// `recording-file` (a fixed name, its extension dropped) and
/// `recording-pattern` (a template); anything that would leave the
/// recording directory is refused.
#[test]
fn per_call_paths_and_names() {
    let dir = temp_dir("per-call");
    let mut c = control(&dir, 55_500);
    let wav: (&str, &[u8]) = ("format", b"wav");
    record_call(
        &mut c,
        &dir,
        "p-1",
        false,
        &[
            wav,
            ("recording-path", b"acme/agents"),
            ("recording-file", b"call-42.wav"),
        ],
        false,
    );
    record_call(
        &mut c,
        &dir,
        "p-2",
        false,
        &[wav, ("recording-pattern", b"x-{call_id}-{section}")],
        false,
    );
    record_call(
        &mut c,
        &dir,
        "p-3",
        false,
        &[wav, ("output-destination", b"team/out.flac")],
        false,
    );
    for f in ["acme/agents/call-42.wav", "x-p-2-1.wav", "team/out.wav"] {
        wait_for(&dir.join(f));
        decoded(&dir.join(f));
    }
    // Refused, with the reason, and nothing is created outside.
    let mut reply = |pairs: &[(&str, &[u8])]| {
        let raw = c.handle(&request(pairs)).unwrap().to_vec();
        String::from_utf8_lossy(&raw).into_owned()
    };
    for (key, value, why) in [
        (
            "recording-path",
            &b"../escape"[..],
            "recording-path: \"..\"",
        ),
        ("recording-path", b"/etc", "recording-path: \"\""),
        ("recording-file", b"../../x", "recording-file: \"..\""),
        (
            "recording-file",
            b"a b",
            "recording-file: ' ' is not allowed",
        ),
        (
            "recording-pattern",
            b"{nope}",
            "recording-pattern: unknown placeholder",
        ),
    ] {
        let r = reply(&[
            ("command", b"start recording"),
            ("call-id", b"p-1"),
            (key, value),
        ]);
        assert!(
            r.contains("error") && r.contains(why),
            "{key} {}: {r}",
            String::from_utf8_lossy(value)
        );
    }
    assert!(!dir.parent().unwrap().join("escape").exists());
    drop(c);
    std::fs::remove_dir_all(&dir).unwrap();
}
