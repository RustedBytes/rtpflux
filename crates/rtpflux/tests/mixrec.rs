//! Recording a conference mixer end to end (`recording.*` with
//! `mixer_id`): the file holds what a listener hears (the participants'
//! tones, not the muted, listening or whispering ones unless asked), on a
//! continuous timeline as participants come and go; pauses hold nothing;
//! sensitive participants pause it; `mixer.destroy` finishes it; a restart
//! goes on in a new section; the same key gives the same recording.
//!
//! Content is checked by tone: each party sends its own frequency, and the
//! WAV is searched for each with a Goertzel filter, window by window.

#[path = "support/logging.rs"]
mod logging;

use rtpflux::config::Config;
use rtpflux::daemon::Daemon;
use rtpflux_client::Client;
use serde_json::{Value, json};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(10);

fn temp_dir(name: &str) -> PathBuf {
    logging::init();
    let d = std::env::temp_dir().join(format!("rtpflux-mixrec-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("rec")).unwrap();
    d
}

fn relay(dir: &Path, min: u16) -> (Daemon, PathBuf) {
    let sock = dir.join("api.sock");
    let config = Config::from_toml(&format!(
        r#"
        [control]
        listen = ["127.0.0.1:0"]
        native_socket = "{}"
        [[interface]]
        name = "lo"
        address = "127.0.0.1"
        [ports]
        min = {min}
        max = {}
        [sessions]
        max = 16
        state_file = "{}"
        [runtime]
        workers = 2
        [recording]
        dir = "{}"
        "#,
        sock.display(),
        min + 63,
        dir.join("state.json").display(),
        dir.join("rec").display(),
    ))
    .unwrap();
    (Daemon::start(&config).unwrap(), sock)
}

/// A party sending a tone of `hz` (PCMU, every 20 ms) while it is on.
struct Party {
    id: String,
    on: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Party {
    fn new(api: &mut Client, hz: f64) -> Self {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = sock.local_addr().unwrap().port();
        let sdp = format!(
            "v=0\r\no=- 7 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"
        );
        let ep = api
            .call(
                "endpoint.create",
                json!({"remote_sdp": sdp, "options": {"flags": ["trust-address"], "endpoint-learning": "off"}}),
            )
            .unwrap();
        let relay_port: u16 = ep["sdp"]
            .as_str()
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("m=audio "))
            .and_then(|l| l.split(' ').next())
            .unwrap()
            .parse()
            .unwrap();
        let to = SocketAddr::from(([127, 0, 0, 1], relay_port));
        let (on, stop) = (
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicBool::new(false)),
        );
        let (on2, stop2) = (Arc::clone(&on), Arc::clone(&stop));
        let thread = std::thread::spawn(move || {
            let mut seq = 0u16;
            let mut n = 0u64;
            let mut next = Instant::now();
            while !stop2.load(Ordering::Relaxed) {
                let mut p = vec![0x80, 0];
                p.extend_from_slice(&seq.to_be_bytes());
                p.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
                p.extend_from_slice(&u32::from(port).to_be_bytes());
                let loud = on2.load(Ordering::Relaxed);
                for _ in 0..160 {
                    #[allow(clippy::cast_precision_loss)]
                    let t = n as f64 / 8000.0;
                    #[allow(clippy::cast_possible_truncation)]
                    let v = if loud {
                        (8000.0 * (2.0 * std::f64::consts::PI * hz * t).sin()) as i16
                    } else {
                        0
                    };
                    p.push(rtpflux_core::g711::linear_to_ulaw(v));
                    n += 1;
                }
                let _ = sock.send_to(&p, to);
                seq = seq.wrapping_add(1);
                next += Duration::from_millis(20);
                std::thread::sleep(next.saturating_duration_since(Instant::now()));
            }
        });
        Party {
            id: ep["endpoint_id"].as_str().unwrap().to_owned(),
            on,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Party {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// A mono 16-bit WAV's samples and rate.
fn wav(path: &Path) -> (Vec<i16>, u32) {
    let b = std::fs::read(path).unwrap();
    assert_eq!(&b[..4], b"RIFF", "{}", path.display());
    assert_eq!(u16::from_le_bytes([b[22], b[23]]), 1, "mono");
    let rate = u32::from_le_bytes([b[24], b[25], b[26], b[27]]);
    let len = u32::from_le_bytes([b[40], b[41], b[42], b[43]]) as usize;
    let samples = b[44..44 + len]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| i16::from_le_bytes(*c))
        .collect();
    (samples, rate)
}

/// The power of `hz` in `x` (Goertzel), normalized by length.
fn tone(x: &[i16], rate: u32, hz: f64) -> f64 {
    let w = 2.0 * std::f64::consts::PI * hz / f64::from(rate);
    let c = 2.0 * w.cos();
    let (mut s1, mut s2) = (0.0f64, 0.0f64);
    for &v in x {
        let s = f64::from(v) + c * s1 - s2;
        s2 = s1;
        s1 = s;
    }
    #[allow(clippy::cast_precision_loss)]
    let n = x.len() as f64;
    (s1 * s1 + s2 * s2 - c * s1 * s2) / (n * n)
}

/// Whether `hz` is clearly in `x`.
fn has(x: &[i16], rate: u32, hz: f64) -> bool {
    tone(x, rate, hz) > 1.0e5
}

/// The next event named `name`.
fn event(api: &mut Client, name: &str) -> Value {
    api.wait_event(name, WAIT)
        .unwrap()
        .unwrap_or_else(|| panic!("no {name}"))
}

#[test]
#[allow(clippy::too_many_lines)] // Who is heard, as they come and go.
fn the_mix_a_listener_hears() {
    let dir = temp_dir("who");
    let (daemon, sock) = relay(&dir, 63_100);
    let mut api = Client::connect(&sock).unwrap();
    let mixer = api.call("mixer.create", Value::Null).unwrap()["mixer_id"]
        .as_u64()
        .unwrap();
    // Two participants, a muted one, a listener, a whisperer (to a).
    let a = Party::new(&mut api, 440.0);
    let b = Party::new(&mut api, 1300.0);
    let muted = Party::new(&mut api, 1900.0);
    let listener = Party::new(&mut api, 700.0);
    let whisperer = Party::new(&mut api, 2500.0);
    for (p, extra) in [
        (&a, json!({})),
        (&b, json!({})),
        (&muted, json!({})),
        (&listener, json!({"role": "listen"})),
        (&whisperer, json!({"role": "whisper", "whisper_to": a.id})),
    ] {
        let mut body = json!({"mixer_id": mixer, "endpoint_id": p.id});
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        api.call("mixer.add", body).unwrap();
    }
    api.call(
        "mixer.set",
        json!({"mixer_id": mixer, "endpoint_id": muted.id, "muted": true}),
    )
    .unwrap();
    api.call(
        "events.subscribe",
        json!({"types": ["recording.completed", "recording.failed", "mixer.destroyed"]}),
    )
    .unwrap();

    // Refused: both ids, a pcap, another option, an unknown mixer.
    let code =
        |r: Result<Value, rtpflux_client::ClientError>| r.unwrap_err().code().map(str::to_owned);
    assert_eq!(
        code(api.call(
            "recording.start",
            json!({"mixer_id": mixer, "endpoint_id": a.id})
        )),
        Some("invalid".into())
    );
    assert_eq!(
        code(api.call(
            "recording.start",
            json!({"mixer_id": mixer, "options": {"format": "pcap"}})
        )),
        Some("invalid".into())
    );
    assert_eq!(
        code(api.call(
            "recording.start",
            json!({"mixer_id": mixer, "options": {"loud": 1}})
        )),
        Some("invalid".into())
    );
    assert_eq!(
        code(api.call("recording.start", json!({"mixer_id": 999}))),
        Some("not_found".into())
    );

    std::thread::sleep(Duration::from_millis(300));
    let asked = Instant::now();
    let rec = api
        .call("recording.start", json!({"mixer_id": mixer}))
        .unwrap();
    let started = Instant::now();
    let rid = rec["recording_id"].as_str().unwrap().to_owned();
    assert_eq!(rec["mixer_id"], mixer);
    let again = api
        .call("recording.start", json!({"mixer_id": mixer}))
        .unwrap();
    assert_eq!(again["recording_id"], rid.as_str(), "the same recording");
    std::thread::sleep(Duration::from_millis(1500));
    // b leaves; a goes quiet then speaks again.
    api.call(
        "mixer.remove",
        json!({"mixer_id": mixer, "endpoint_id": b.id}),
    )
    .unwrap();
    a.on.store(false, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(700));
    a.on.store(true, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(800));
    let q = api
        .call("recording.query", json!({"recording_id": rid}))
        .unwrap();
    assert_eq!(q["state"], "active");
    assert_eq!(q["mixer_id"], mixer);
    assert!(q.get("endpoint_id").is_none(), "{q}");
    let inv = api
        .call("inventory.list", json!({"kind": "recordings"}))
        .unwrap();
    let listed = inv["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == rid.as_str())
        .unwrap_or_else(|| panic!("listed: {inv}"));
    assert_eq!(listed["mixer_id"], mixer);
    let stopping = Instant::now();
    let stop = api
        .call("recording.stop", json!({"mixer_id": mixer}))
        .unwrap();
    let stopped = Instant::now();
    assert_eq!(stop["recording_id"], rid.as_str());
    let done = event(&mut api, "recording.completed");
    assert_eq!(done["mixer_id"], mixer);
    assert!(done.get("endpoint_id").is_none());
    assert_eq!(done["data"]["recording_id"], rid.as_str());
    assert_eq!(done["data"]["lost_ms"], 0);

    // Its length: start to stop, within a period or two.
    let duration = done["data"]["duration_ms"].as_u64().unwrap();
    let shortest = u64::try_from((stopping - started).as_millis()).unwrap();
    let longest = u64::try_from((stopped - asked).as_millis()).unwrap();
    assert!(
        duration + 40 >= shortest && duration <= longest + 40,
        "{duration} ms, between {shortest} and {longest}"
    );
    let (x, rate) = wav(Path::new(done["data"]["file"].as_str().unwrap()));
    assert_eq!(rate, 8000, "[recording]'s rate");
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let ms = |t: f64| (t * f64::from(rate) / 1000.0) as usize;
    // 0.3–1.3 s: a and b; nobody else.
    let first = &x[ms(300.0)..ms(1300.0)];
    assert!(has(first, rate, 440.0) && has(first, rate, 1300.0));
    for hz in [1900.0, 700.0, 2500.0] {
        assert!(!has(first, rate, hz), "{hz} Hz is not heard by everyone");
    }
    // After b left, a quiet: silence (the timeline goes on).
    let quiet = &x[ms(1750.0)..ms(2050.0)];
    assert!(!has(quiet, rate, 440.0) && !has(quiet, rate, 1300.0));
    // Then a again, alone.
    let last = &x[ms(2400.0)..ms(2900.0)];
    assert!(has(last, rate, 440.0) && !has(last, rate, 1300.0));

    // Who was there, and when.
    let q = api
        .call("recording.query", json!({"recording_id": rid}))
        .unwrap();
    assert_eq!(q["state"], "completed", "{q}");
    let parts = q["participants"].as_array().unwrap();
    assert_eq!(parts.len(), 5, "{q}");
    let of = |id: &str| parts.iter().find(|p| p["endpoint_id"] == id).unwrap()["intervals"].clone();
    assert!(of(&b.id)[0][1].as_u64().is_some(), "b left");
    assert!(of(&a.id)[0][1].as_u64().is_some(), "closed at the stop");

    // With whispers, then the mixer destroyed while it records.
    let rec2 = api
        .call(
            "recording.start",
            json!({"mixer_id": mixer, "options": {"include_whispers": true, "sample_rate": 16000}}),
        )
        .unwrap();
    let rid2 = rec2["recording_id"].as_str().unwrap().to_owned();
    assert_ne!(rid2, rid);
    std::thread::sleep(Duration::from_millis(1000));
    api.call("mixer.destroy", json!({"mixer_id": mixer}))
        .unwrap();
    let destroyed = api.next_event(WAIT).unwrap().unwrap();
    assert_eq!(destroyed["event"], "mixer.destroyed", "first: {destroyed}");
    let done = event(&mut api, "recording.completed");
    assert_eq!(done["data"]["recording_id"], rid2.as_str());
    let (x, rate) = wav(Path::new(done["data"]["file"].as_str().unwrap()));
    assert_eq!(rate, 16_000);
    let body = &x[ms(200.0) * 2..ms(800.0) * 2];
    assert!(
        has(body, rate, 440.0) && has(body, rate, 2500.0),
        "the whisperer too"
    );
    assert!(!has(body, rate, 700.0) && !has(body, rate, 1900.0));
    assert_eq!(
        api.call("recording.query", json!({"recording_id": rid2}))
            .unwrap()["state"],
        "completed"
    );
    drop((a, b, muted, listener, whisperer));
    drop(api);
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
#[allow(clippy::too_many_lines, clippy::many_single_char_names)] // One recording's life.
fn pauses_sensitivity_restart_and_keys() {
    let dir = temp_dir("life");
    let (daemon, sock) = relay(&dir, 63_200);
    let mut api = Client::connect(&sock).unwrap();
    let mixer = api.call("mixer.create", Value::Null).unwrap()["mixer_id"]
        .as_u64()
        .unwrap();
    let a = Party::new(&mut api, 440.0);
    let b = Party::new(&mut api, 1300.0);
    for p in [&a, &b] {
        api.call("mixer.add", json!({"mixer_id": mixer, "endpoint_id": p.id}))
            .unwrap();
    }

    // The same key twice: one recording, among the operation's resources.
    let start = json!({"mixer_id": mixer, "idempotency_key": "rec-k1"});
    let r1 = api.call("recording.start", start.clone()).unwrap();
    let began = Instant::now();
    let r2 = api.call("recording.start", start).unwrap();
    let rid = r1["recording_id"].as_str().unwrap().to_owned();
    assert_eq!(r2["recording_id"], rid.as_str());
    let op = api
        .call("operation.query", json!({"idempotency_key": "rec-k1"}))
        .unwrap();
    assert!(
        op["resources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == rid.as_str()),
        "{op}"
    );

    // A pause: confirmed, holds nothing.
    std::thread::sleep(Duration::from_millis(600));
    let p = api
        .call("recording.pause", json!({"mixer_id": mixer}))
        .unwrap();
    assert_eq!(
        (p["state"].as_str(), p["changed"].as_bool()),
        (Some("paused"), Some(true))
    );
    std::thread::sleep(Duration::from_millis(800));
    let r = api
        .call("recording.resume", json!({"mixer_id": mixer}))
        .unwrap();
    assert_eq!(r["state"], "active");
    let pause = (
        r["pauses"][0][0].as_u64().unwrap(),
        r["pauses"][0][1].as_u64().unwrap(),
    );
    assert!(pause.1 - pause.0 >= 750, "{pause:?}");

    // A sensitive participant pauses it; no longer sensitive, it goes on.
    std::thread::sleep(Duration::from_millis(400));
    api.call(
        "endpoint.sensitive",
        json!({"endpoint_id": a.id, "sensitive": true}),
    )
    .unwrap();
    let q = api
        .call("recording.query", json!({"recording_id": rid}))
        .unwrap();
    assert_eq!(q["state"], "paused", "while a is sensitive: {q}");
    api.call(
        "endpoint.sensitive",
        json!({"endpoint_id": a.id, "sensitive": false}),
    )
    .unwrap();
    let q = api
        .call("recording.query", json!({"recording_id": rid}))
        .unwrap();
    assert_eq!(q["state"], "active", "{q}");
    // Paused by the controller: sensitivity going away does not resume it.
    api.call("recording.pause", json!({"mixer_id": mixer}))
        .unwrap();
    api.call(
        "endpoint.sensitive",
        json!({"endpoint_id": b.id, "sensitive": true}),
    )
    .unwrap();
    api.call(
        "endpoint.sensitive",
        json!({"endpoint_id": b.id, "sensitive": false}),
    )
    .unwrap();
    let q = api
        .call("recording.query", json!({"recording_id": rid}))
        .unwrap();
    assert_eq!(q["state"], "paused", "the controller's pause holds: {q}");
    let pauses = q["pauses"].as_array().unwrap().len();
    assert_eq!(pauses, 3, "{q}");
    let last = api
        .call("recording.resume", json!({"mixer_id": mixer}))
        .unwrap();
    let paused_ms: u64 = last["pauses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p[1].as_u64().unwrap() - p[0].as_u64().unwrap())
        .sum();
    std::thread::sleep(Duration::from_millis(500));
    let wall_ms = u64::try_from(began.elapsed().as_millis()).unwrap();

    // A restart: the mixer back, the recording goes on in a new section.
    drop(api);
    daemon.stop();
    let (daemon, sock) = relay(&dir, 63_200);
    let mut api = Client::connect(&sock).unwrap();
    let report = api.call("recovery.report", Value::Null).unwrap();
    assert!(
        report["restored_mixer_recordings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == rid.as_str()),
        "{report}"
    );
    let q = api
        .call("recording.query", json!({"recording_id": rid}))
        .unwrap();
    assert_eq!(
        (q["state"].as_str(), q["section"].as_u64()),
        (Some("active"), Some(2)),
        "{q}"
    );
    std::thread::sleep(Duration::from_millis(700));
    api.call(
        "events.subscribe",
        json!({"types": ["recording.completed", "recording.failed"], "mixer_ids": [mixer]}),
    )
    .unwrap();
    api.call("recording.stop", json!({"mixer_id": mixer}))
        .unwrap();
    let done = event(&mut api, "recording.completed");
    let files = done["data"]["files"].as_array().unwrap();
    assert_eq!(files.len(), 2, "a file per section: {done}");
    assert_eq!(done["data"]["section"], 2);
    // The sections: tones both, the pause left out of the first.
    let (one, rate) = wav(Path::new(files[0].as_str().unwrap()));
    let (two, _) = wav(Path::new(files[1].as_str().unwrap()));
    assert!(has(&two, rate, 440.0) && has(&two, rate, 1300.0));
    #[allow(clippy::cast_precision_loss)]
    let first_ms = one.len() as f64 * 1000.0 / f64::from(rate);
    // The wall time from start to restart, less the confirmed pauses
    // (the stop and its last periods aside).
    #[allow(clippy::cast_precision_loss)]
    let expected = (wall_ms - paused_ms) as f64;
    assert!(
        (first_ms - expected).abs() < 250.0,
        "{first_ms} ms recorded, {expected} expected ({wall_ms} less {paused_ms} paused)"
    );
    let total = done["data"]["duration_ms"].as_u64().unwrap();
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let second_ms = (two.len() as f64 * 1000.0 / f64::from(rate)) as u64;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let summed = first_ms as u64 + second_ms;
    assert!(total.abs_diff(summed) <= 60, "{total} against {summed}");
    drop((a, b));
    drop(api);
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}
