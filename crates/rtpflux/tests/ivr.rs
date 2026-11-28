//! The native API's IVR primitives end to end:
//! - keys and tones to an endpoint (`dtmf.send`, `tone.start`,
//!   `tone.stop`);
//! - detectors without a service (`stream.start` with no socket,
//!   `stream.detect`);
//! - DTMF source policies (`dtmf.policy`);
//! - sensitive digits (`endpoint.sensitive`);
//! - playback queues and barge-in (`playback.start` with `queue` and
//!   `stop_on`).

#[path = "support/logging.rs"]
mod logging;

use rtpflux::config::Config;
use rtpflux::daemon::Daemon;
use rtpflux_client::Client;
use serde_json::{Value, json};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(3);

fn temp_dir(name: &str) -> PathBuf {
    logging::init();
    let d = std::env::temp_dir().join(format!("rtpflux-ivr-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn relay(dir: &Path, min: u16, extra: &str) -> (Daemon, PathBuf) {
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
        max = 12
        [runtime]
        workers = 1
        {extra}
        "#,
        sock.display(),
        min + 63,
    ))
    .unwrap();
    (Daemon::start(&config).unwrap(), sock)
}

/// An endpoint answering `caller` (PCMU and telephone events), and where
/// the relay takes the caller's media.
fn endpoint(api: &mut Client, caller: &UdpSocket) -> (String, SocketAddr) {
    let port = caller.local_addr().unwrap().port();
    let sdp = format!(
        "v=0\r\no=- 7 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\na=sendrecv\r\n"
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
    (
        ep["endpoint_id"].as_str().unwrap().to_owned(),
        SocketAddr::from(([127, 0, 0, 1], relay_port)),
    )
}

fn rtp(pt: u8, seq: u16, ts: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x80, pt | if marker { 0x80 } else { 0 }];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&ts.to_be_bytes());
    p.extend_from_slice(&0x1234_5678u32.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

/// The payload types of what `s` receives within `ms`, and the mean level
/// of the PCMU audio among it.
fn received(s: &UdpSocket, ms: u64) -> (Vec<u8>, u64) {
    let end = Instant::now() + Duration::from_millis(ms);
    s.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    let mut buf = [0u8; 2048];
    let (mut pts, mut sum, mut n) = (Vec::new(), 0u64, 0u64);
    while Instant::now() < end {
        if let Ok((len, _)) = s.recv_from(&mut buf)
            && len >= 12
        {
            let pt = buf[1] & 0x7f;
            pts.push(pt);
            if pt == 0 {
                for &c in &buf[12..len] {
                    sum += u64::from(rtpflux_core::g711::ulaw_to_linear(c).unsigned_abs());
                    n += 1;
                }
            }
        }
    }
    (pts, sum / n.max(1))
}

/// Events as they come, kept until taken in any order.
struct Events {
    api: Client,
    kept: Vec<Value>,
}

impl Events {
    fn new(sock: &Path, filter: &Value) -> Self {
        let mut api = Client::connect(sock).unwrap();
        api.call("events.subscribe", filter.clone()).unwrap();
        Events {
            api,
            kept: Vec::new(),
        }
    }

    /// Everything that comes within `ms`.
    fn gather(&mut self, ms: u64) {
        let end = Instant::now() + Duration::from_millis(ms);
        loop {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            if let Some(e) = self.api.next_event(left).unwrap() {
                self.kept.push(e);
            }
        }
    }

    /// The first event named `name` whose data `matches`, waiting for it.
    fn take(&mut self, name: &str, matches: impl Fn(&Value) -> bool) -> Value {
        let end = Instant::now() + WAIT;
        loop {
            if let Some(i) = self
                .kept
                .iter()
                .position(|e| e["event"] == name && matches(&e["data"]))
            {
                return self.kept.remove(i);
            }
            let left = end.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "no {name}: {:?}", self.kept);
            if let Some(e) = self.api.next_event(left).unwrap() {
                self.kept.push(e);
            }
        }
    }

    /// The events named `name` (taken).
    fn all(&mut self, name: &str) -> Vec<Value> {
        let (out, rest) = std::mem::take(&mut self.kept)
            .into_iter()
            .partition(|e| e["event"] == name);
        self.kept = rest;
        out
    }
}

fn code(r: Result<Value, rtpflux_client::ClientError>) -> String {
    r.unwrap_err().code().unwrap_or("none").to_owned()
}

/// The caller presses key 5: in-band tones (`inband`, 200 ms, then
/// silence), then RFC 4733 events (`event`, 200 ms, with no audio meanwhile:
/// audio during an event ends it), then silence. `seq` goes on from call to
/// call.
fn press(caller: &UdpSocket, to: SocketAddr, seq: &mut u16, inband: bool, event: bool) {
    let audio = |frames: u16, tone: bool, seq: &mut u16| {
        for k in 0..frames {
            let ts = u32::from(*seq) * 160;
            let payload: Vec<u8> = (0..160u32)
                .map(|i| {
                    if !tone {
                        return 0xff;
                    }
                    let t = f64::from(u32::from(k) * 160 + i) / 8000.0;
                    let v = 6000.0 * (2.0 * std::f64::consts::PI * 770.0 * t).sin()
                        + 6000.0 * (2.0 * std::f64::consts::PI * 1336.0 * t).sin();
                    #[allow(clippy::cast_possible_truncation)]
                    let s = v as i16;
                    rtpflux_core::g711::linear_to_ulaw(s)
                })
                .collect();
            caller
                .send_to(&rtp(0, *seq, ts, false, &payload), to)
                .unwrap();
            *seq = seq.wrapping_add(1);
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    audio(10, inband, seq);
    audio(4, false, seq);
    if event {
        let ts0 = u32::from(*seq) * 160;
        for k in 0u16..13 {
            let end = k >= 10;
            let dur = u16::try_from((u32::from(k.min(9)) + 1) * 160).unwrap();
            let mut ev = vec![5u8, if end { 0x80 | 0x0a } else { 0x0a }];
            ev.extend_from_slice(&dur.to_be_bytes());
            caller
                .send_to(&rtp(101, *seq, ts0, k == 0, &ev), to)
                .unwrap();
            *seq = seq.wrapping_add(1);
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    audio(6, false, seq);
}

/// Keys and tones to an endpoint.
#[test]
fn keys_and_tones_to_an_endpoint() {
    let dir = temp_dir("send");
    let (daemon, sock) = relay(&dir, 62_100, "");
    let mut api = Client::connect(&sock).unwrap();
    let caller = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (id, _) = endpoint(&mut api, &caller);

    // Telephone events, as it takes them; the keys are not echoed.
    let r = api
        .call("dtmf.send", json!({"endpoint_id": id, "digits": "12#"}))
        .unwrap();
    assert_eq!(
        (r["keys"].as_u64(), r["mode"].as_str()),
        (Some(3), Some("rfc4733"))
    );
    assert!(r.get("digits").is_none());
    let (pts, _) = received(&caller, 800);
    assert!(
        pts.iter().map(|&p| usize::from(p == 101)).sum::<usize>() >= 6,
        "events: {pts:?}"
    );
    // In-band, if asked.
    let r = api
        .call(
            "dtmf.send",
            json!({"endpoint_id": id, "digits": "5", "mode": "inband", "duration_ms": 200}),
        )
        .unwrap();
    assert_eq!(r["mode"], "inband");
    let (pts, level) = received(&caller, 500);
    assert!(!pts.contains(&101) && pts.len() >= 8, "{pts:?}");
    assert!(level > 1000, "tones: {level}");
    assert_eq!(
        code(api.call("dtmf.send", json!({"endpoint_id": id, "digits": "1X"}))),
        "invalid"
    );
    assert_eq!(
        code(api.call("dtmf.send", json!({"endpoint_id": id, "digits": ""}))),
        "invalid"
    );

    // A tone with a cadence; stopped early.
    let r = api
        .call(
            "tone.start",
            json!({"endpoint_id": id, "frequency_hz": 425, "on_ms": 400, "off_ms": 100, "repeat": 10}),
        )
        .unwrap();
    assert_eq!(r["duration_ms"], 5000);
    let (pts, level) = received(&caller, 300);
    assert!(
        pts.len() >= 10 && level > 1000,
        "the tone: {} packets, level {level}",
        pts.len()
    );
    api.call("tone.stop", json!({"endpoint_id": id})).unwrap();
    std::thread::sleep(Duration::from_millis(150));
    let (pts, _) = received(&caller, 600);
    assert!(pts.len() <= 2, "stopped: {} packets", pts.len());
    assert_eq!(
        code(api.call(
            "tone.start",
            json!({"endpoint_id": id, "frequency_hz": 9000})
        )),
        "invalid"
    );
    drop(api);
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Detectors without a service, DTMF policies, and sensitive digits.
#[test]
#[allow(clippy::too_many_lines)] // One caller's keys under each policy.
fn detectors_policies_and_sensitive_digits() {
    let dir = temp_dir("detect");
    let rec = dir.join("rec");
    std::fs::create_dir_all(&rec).unwrap();
    let (daemon, sock) = relay(
        &dir,
        62_300,
        &format!("[recording]\ndir = \"{}\"", rec.display()),
    );
    let mut api = Client::connect(&sock).unwrap();
    let mut plain = Events::new(&sock, &json!({}));
    let mut trusted = Events::new(&sock, &json!({"sensitive": true}));
    let caller = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (id, to) = endpoint(&mut api, &caller);
    let mut seq = 0u16;

    // In-band DTMF only, no service, no pcm_dir.
    let d = api
        .call("stream.start", json!({"endpoint_id": id, "vad": false}))
        .unwrap();
    assert_eq!(d["service"], false);
    assert_eq!(d["detect"], json!({"vad": false, "dtmf": true}));
    let stream = d["stream_id"].clone();

    // A press both in-band and as events: reported once (dedup, the
    // default).
    press(&caller, to, &mut seq, true, true);
    plain.gather(1200);
    let keys = plain.all("dtmf.detected");
    assert_eq!(keys.len(), 1, "one press, one report: {keys:?}");
    assert_eq!(keys[0]["data"]["digit"], "5");
    assert!(plain.all("speech.started").is_empty(), "VAD is off");
    // Every report.
    api.call("dtmf.policy", json!({"endpoint_id": id, "policy": "both"}))
        .unwrap();
    press(&caller, to, &mut seq, true, true);
    plain.gather(1200);
    let keys = plain.all("dtmf.detected");
    let mut sources: Vec<&str> = keys
        .iter()
        .map(|k| k["data"]["source"].as_str().unwrap())
        .collect();
    sources.sort_unstable();
    assert_eq!(sources, ["inband", "rfc4733"]);
    // Events only.
    api.call(
        "dtmf.policy",
        json!({"endpoint_id": id, "policy": "rfc4733"}),
    )
    .unwrap();
    press(&caller, to, &mut seq, true, true);
    plain.gather(1200);
    let keys = plain.all("dtmf.detected");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["data"]["source"], "rfc4733");
    assert_eq!(
        code(api.call("dtmf.policy", json!({"endpoint_id": id, "policy": "x"}))),
        "invalid"
    );

    // Sensitive digits, while recording: the recording pauses; only the
    // subscriber that asked sees the digit.
    api.call("recording.start", json!({"endpoint_id": id}))
        .unwrap();
    let s = api
        .call(
            "endpoint.sensitive",
            json!({"endpoint_id": id, "sensitive": true}),
        )
        .unwrap();
    assert_eq!(s["recording_paused"], true);
    trusted.gather(100);
    trusted.kept.clear();
    press(&caller, to, &mut seq, false, true);
    let seen = trusted.take("dtmf.detected", |_| true);
    assert_eq!(seen["data"]["digit"], "5");
    assert_eq!(seen["data"]["sensitive"], true);
    let masked = plain.take("dtmf.detected", |_| true);
    assert_eq!(masked["data"]["digit"], Value::Null);
    assert_eq!(masked["data"]["code"], Value::Null);
    assert_eq!(masked["data"]["redacted"], true);
    // A replay from a cursor is redacted the same way.
    let mut late = Client::connect(&sock).unwrap();
    let cursor = format!(
        "{}:{}",
        masked["boot_id"].as_str().unwrap(),
        masked["global_seq"].as_u64().unwrap() - 1
    );
    late.call(
        "events.subscribe",
        json!({"cursor": cursor, "types": ["dtmf.detected"]}),
    )
    .unwrap();
    let replayed = late.wait_event("dtmf.detected", WAIT).unwrap().unwrap();
    assert_eq!(replayed["data"]["redacted"], true);
    let s = api
        .call(
            "endpoint.sensitive",
            json!({"endpoint_id": id, "sensitive": false}),
        )
        .unwrap();
    assert_eq!(s["recording_paused"], false);
    press(&caller, to, &mut seq, false, true);
    let clear = plain.take("dtmf.detected", |_| true);
    assert_eq!(clear["data"]["digit"], "5", "no longer sensitive");

    // Detectors switched at run time: VAD on, a caller speaking.
    api.call("stream.detect", json!({"stream_id": stream, "vad": true}))
        .unwrap();
    let loud: Vec<u8> = (0..160)
        .map(|i| {
            let x = (f64::from(i) * 2.0 * std::f64::consts::PI * 400.0 / 8000.0).sin();
            #[allow(clippy::cast_possible_truncation)]
            let v = (x * 12000.0) as i16;
            rtpflux_core::g711::linear_to_ulaw(v)
        })
        .collect();
    for _ in 0..40 {
        caller
            .send_to(&rtp(0, seq, u32::from(seq) * 160, false, &loud), to)
            .unwrap();
        seq = seq.wrapping_add(1);
        std::thread::sleep(Duration::from_millis(20));
    }
    plain.take("speech.started", |_| true);
    drop((api, plain, trusted, late));
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A short WAV file: 8 kHz, 16-bit mono, `ms` long.
fn wav(path: &Path, ms: u32) {
    let samples = 8 * ms;
    let data = samples * 2;
    let mut w = Vec::new();
    w.extend_from_slice(b"RIFF");
    w.extend_from_slice(&(36 + data).to_le_bytes());
    w.extend_from_slice(b"WAVEfmt ");
    w.extend_from_slice(&16u32.to_le_bytes());
    w.extend_from_slice(&1u16.to_le_bytes());
    w.extend_from_slice(&1u16.to_le_bytes());
    w.extend_from_slice(&8000u32.to_le_bytes());
    w.extend_from_slice(&16000u32.to_le_bytes());
    w.extend_from_slice(&2u16.to_le_bytes());
    w.extend_from_slice(&16u16.to_le_bytes());
    w.extend_from_slice(b"data");
    w.extend_from_slice(&data.to_le_bytes());
    for i in 0..samples {
        let v = i16::try_from((i % 40) * 400).unwrap();
        w.extend_from_slice(&v.to_le_bytes());
    }
    std::fs::write(path, w).unwrap();
}

/// Playbacks queued behind each other, and a playback a key interrupts
/// (with what was queued behind it).
#[test]
fn playback_queues_and_barge_in() {
    let dir = temp_dir("queue");
    let (daemon, sock) = relay(&dir, 62_500, "");
    let mut api = Client::connect(&sock).unwrap();
    let mut ev = Events::new(
        &sock,
        &json!({"types": ["playback.completed", "playback.stopped"]}),
    );
    let caller = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (id, to) = endpoint(&mut api, &caller);
    let (short, long) = (dir.join("short.wav"), dir.join("long.wav"));
    wav(&short, 300);
    wav(&long, 3000);
    let file = |p: &Path| p.display().to_string();

    let p1 = api
        .call(
            "playback.start",
            json!({"endpoint_id": id, "file": file(&short)}),
        )
        .unwrap();
    let p2 = api
        .call(
            "playback.start",
            json!({"endpoint_id": id, "file": file(&short), "queue": true}),
        )
        .unwrap();
    assert_eq!(
        (p2["queued"].as_bool(), p2["position"].as_u64()),
        (Some(true), Some(1))
    );
    let done1 = ev.take("playback.completed", |_| true);
    assert_eq!(done1["data"]["playback_id"], p1["playback_id"]);
    let done2 = ev.take("playback.completed", |_| true);
    assert_eq!(
        done2["data"]["playback_id"], p2["playback_id"],
        "then the queued one"
    );

    // A key stops the announcement, and what waits behind it.
    let p3 = api
        .call(
            "playback.start",
            json!({"endpoint_id": id, "file": file(&long), "stop_on": ["dtmf"]}),
        )
        .unwrap();
    let p4 = api
        .call(
            "playback.start",
            json!({"endpoint_id": id, "file": file(&short), "queue": true}),
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let mut seq = 100u16;
    press(&caller, to, &mut seq, false, true);
    let stopped = ev.take("playback.stopped", |d| {
        d["playback_id"] == p3["playback_id"]
    });
    assert_eq!(stopped["data"]["reason"], "dtmf");
    let dropped = ev.take("playback.stopped", |d| {
        d["playback_id"] == p4["playback_id"]
    });
    assert_eq!(dropped["data"]["reason"], "interrupted");
    assert_eq!(
        code(api.call(
            "playback.start",
            json!({"endpoint_id": id, "file": file(&short), "stop_on": ["noise"]})
        )),
        "invalid"
    );
    drop((api, ev));
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// How each playback ended stays queryable (`playback.query`), for a
/// controller that missed the event; an endpoint destroyed mid-playback
/// stops it, and what was queued, before `endpoint.destroyed`.
#[test]
fn playback_ends_are_kept() {
    let dir = temp_dir("ends");
    let (daemon, sock) = relay(&dir, 62_600, "");
    let mut api = Client::connect(&sock).unwrap();
    let mut ev = Events::new(
        &sock,
        &json!({"types": ["playback.completed", "playback.stopped", "endpoint.destroyed"]}),
    );
    let caller = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (id, _) = endpoint(&mut api, &caller);
    let (short, long) = (dir.join("short.wav"), dir.join("long.wav"));
    wav(&short, 300);
    wav(&long, 5000);
    let file = |p: &Path| p.display().to_string();
    let query = |api: &mut Client, pb: &Value| {
        api.call("playback.query", json!({"playback_id": pb["playback_id"]}))
            .unwrap()
    };

    let p1 = api
        .call(
            "playback.start",
            json!({"endpoint_id": id, "file": file(&short)}),
        )
        .unwrap();
    ev.take("playback.completed", |d| {
        d["playback_id"] == p1["playback_id"]
    });
    let q = query(&mut api, &p1);
    assert_eq!(
        (q["state"].as_str(), q["endpoint_id"].as_str()),
        (Some("completed"), Some(id.as_str())),
        "{q}"
    );
    assert!(q["ended_unix_ms"].as_u64().is_some());

    let p2 = api
        .call(
            "playback.start",
            json!({"endpoint_id": id, "file": file(&long)}),
        )
        .unwrap();
    let p3 = api
        .call(
            "playback.start",
            json!({"endpoint_id": id, "file": file(&short), "queue": true}),
        )
        .unwrap();
    assert_eq!(query(&mut api, &p2)["state"], "playing");
    let q = query(&mut api, &p3);
    assert_eq!(
        (q["state"].as_str(), q["position"].as_u64()),
        (Some("queued"), Some(1))
    );

    // Destroyed while it plays: both stop first.
    api.call("endpoint.destroy", json!({"endpoint_id": id}))
        .unwrap();
    let stopped = ev.take("playback.stopped", |d| {
        d["playback_id"] == p2["playback_id"]
    });
    assert_eq!(stopped["data"]["reason"], "endpoint_destroyed");
    let dropped = ev.take("playback.stopped", |d| {
        d["playback_id"] == p3["playback_id"]
    });
    assert_eq!(dropped["data"]["reason"], "endpoint_destroyed");
    let destroyed = ev.take("endpoint.destroyed", |_| true);
    assert!(
        destroyed["seq"].as_u64() > dropped["seq"].as_u64(),
        "after them"
    );
    let q = query(&mut api, &p2);
    assert_eq!(
        (q["state"].as_str(), q["reason"].as_str()),
        (Some("stopped"), Some("endpoint_destroyed"))
    );
    let q = query(&mut api, &p3);
    assert_eq!(
        (q["state"].as_str(), q["queued"].as_bool()),
        (Some("stopped"), Some(true))
    );
    assert_eq!(
        code(api.call("playback.query", json!({"playback_id": "pb-none"}))),
        "not_found"
    );
    drop((api, ev));
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}
