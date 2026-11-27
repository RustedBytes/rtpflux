//! PCM streams on the shared shards: flush generations (protocol 2) with
//! late audio, a flush racing a mark, acknowledgments; and, with many
//! streams on two shard threads, a service too slow to read, one flooding
//! the relay, and one reconnecting, none of them disturbing the others.

#[path = "support/logging.rs"]
mod logging;

use rtpflux::config::Config;
use rtpflux::daemon::Daemon;
use rtpflux_client::Client;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(3);

fn temp_dir(name: &str) -> PathBuf {
    logging::init();
    let d = std::env::temp_dir().join(format!("rtpflux-pcm-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn relay(dir: &Path, min: u16) -> (Daemon, PathBuf) {
    let sock = dir.join("api.sock");
    let config = Config::from_toml(&format!(
        r#"
        [control]
        listen = ["127.0.0.1:0"]
        native_socket = "{}"
        pcm_dir = "{}"
        [[interface]]
        name = "lo"
        address = "127.0.0.1"
        [ports]
        min = {min}
        max = {}
        [sessions]
        max = 20
        [runtime]
        workers = 2
        pcm_shards = 2
        "#,
        sock.display(),
        dir.display(),
        min + 99,
    ))
    .unwrap();
    (Daemon::start(&config).unwrap(), sock)
}

/// A frame of the stream protocol.
#[derive(Debug, Clone)]
struct Frame {
    version: u8,
    kind: u8,
    generation: u8,
    seq: u32,
    timestamp_ms: u64,
    samples: usize,
}

fn read_frame(r: &mut UnixStream) -> Option<Frame> {
    let mut h = [0u8; 32];
    r.read_exact(&mut h).ok()?;
    assert_eq!(&h[..4], b"RFPC");
    let samples = usize::from(u16::from_le_bytes([h[30], h[31]]));
    let mut body = vec![0u8; if h[5] == 2 { samples * 2 } else { 0 }];
    r.read_exact(&mut body).ok()?;
    Some(Frame {
        version: h[4],
        kind: h[5],
        generation: h[7],
        seq: u32::from_le_bytes(h[12..16].try_into().unwrap()),
        timestamp_ms: u64::from_le_bytes(h[16..24].try_into().unwrap()),
        samples,
    })
}

/// A frame to the relay: `kind`, `seq`, generation `generation`, and (for
/// audio) 20 ms of a tone at 8 kHz.
fn send(w: &mut UnixStream, version: u8, kind: u8, seq: u32, generation: u8) {
    let audio = kind == 2;
    let mut f = Vec::with_capacity(32 + 320);
    f.extend_from_slice(b"RFPC");
    f.extend_from_slice(&[version, kind, 0, generation]);
    f.extend_from_slice(&0u32.to_le_bytes());
    f.extend_from_slice(&seq.to_le_bytes());
    f.extend_from_slice(&0u64.to_le_bytes());
    f.extend_from_slice(&(if audio { 8000u32 } else { 0 }).to_le_bytes());
    f.extend_from_slice(&[1, 1]);
    f.extend_from_slice(&(if audio { 160u16 } else { 0 }).to_le_bytes());
    if audio {
        for i in 0..160u32 {
            let x = (f64::from(i) * 2.0 * std::f64::consts::PI * 500.0 / 8000.0).sin();
            #[allow(clippy::cast_possible_truncation)]
            let v = (x * 9000.0) as i16;
            f.extend_from_slice(&v.to_le_bytes());
        }
    }
    w.write_all(&f).unwrap();
}

/// An endpoint answering a caller at `caller`, and where the relay takes
/// the caller's media.
fn endpoint(api: &mut Client, caller: &UdpSocket) -> (String, SocketAddr) {
    let port = caller.local_addr().unwrap().port();
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
    (
        ep["endpoint_id"].as_str().unwrap().to_owned(),
        SocketAddr::from(([127, 0, 0, 1], relay_port)),
    )
}

/// RTP packets `s` receives within `ms`.
fn packets(s: &UdpSocket, ms: u64) -> usize {
    let end = Instant::now() + Duration::from_millis(ms);
    let mut buf = [0u8; 2048];
    s.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    let mut n = 0;
    while Instant::now() < end {
        if s.recv_from(&mut buf).is_ok() {
            n += 1;
        }
    }
    n
}

/// Events as they come, kept until taken in any order.
struct Events {
    api: Client,
    kept: Vec<Value>,
}

impl Events {
    /// The first event named `name` whose data `matches`.
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

    fn mark(&mut self, id: u64) -> Value {
        self.take("stream.mark", |d| d["mark"] == id)
    }
}

/// Protocol 2: a flush starts a new generation. Marks waiting are
/// answered as flushed. The service is told, with the audio sent before
/// the flush. Late audio of the old generation is never played; the new
/// generation's is.
#[test]
#[allow(clippy::too_many_lines)] // One service's barge-in, step by step.
fn flush_generations() {
    let dir = temp_dir("gen");
    let (daemon, sock) = relay(&dir, 63_700);
    let service = UnixListener::bind(dir.join("bot.sock")).unwrap();
    let mut api = Client::connect(&sock).unwrap();
    api.call("events.subscribe", json!({})).unwrap();
    let caller = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (id, _) = endpoint(&mut api, &caller);
    let mut ev = Events {
        api: Client::connect(&sock).unwrap(),
        kept: Vec::new(),
    };
    ev.api.call("events.subscribe", json!({})).unwrap();
    let bad = api.call(
        "stream.start",
        json!({"endpoint_id": id, "socket": "bot.sock", "protocol": 3}),
    );
    assert!(bad.is_err());
    let st = api
        .call(
            "stream.start",
            json!({"endpoint_id": id, "socket": "bot.sock", "rate": 8000, "protocol": 2}),
        )
        .unwrap();
    assert_eq!(st["protocol"], 2);
    let stream = st["stream_id"].clone();
    let (mut bot, _) = service.accept().unwrap();
    bot.set_read_timeout(Some(WAIT)).unwrap();
    let hello = read_frame(&mut bot).unwrap();
    assert_eq!((hello.version, hello.kind), (2, 1));
    // What the relay sends the service, but audio, on a channel.
    let (tx, frames) = std::sync::mpsc::channel::<Frame>();
    let mut reader = bot.try_clone().unwrap();
    std::thread::spawn(move || {
        while let Some(f) = read_frame(&mut reader) {
            if f.kind != 2 && tx.send(f).is_err() {
                return;
            }
        }
    });

    // A long answer (1 s), then mark 1: only 5 frames fit in the worker's
    // queue, the rest waits.
    for k in 0..50 {
        send(&mut bot, 2, 2, k, 0);
    }
    send(&mut bot, 2, 3, 1, 0);
    assert!(packets(&caller, 200) > 0, "the answer plays");
    // Barge-in.
    api.call("stream.flush", json!({"stream_id": stream}))
        .unwrap();
    let flushed = ev.take("stream.flushed", |_| true);
    assert_eq!(flushed["data"]["generation"], 1);
    let played_ms = flushed["data"]["played_ms"].as_u64().unwrap();
    assert!((20..1000).contains(&played_ms), "{flushed}");
    let ack = frames.recv_timeout(WAIT).unwrap();
    assert_eq!(
        (ack.kind, ack.seq, ack.version),
        (4, 1, 2),
        "the flush, acknowledged"
    );
    assert_eq!(ack.timestamp_ms, played_ms);
    // The rest of the flushed answer stops at once.
    std::thread::sleep(Duration::from_millis(100));
    let _ = packets(&caller, 60);
    assert_eq!(
        packets(&caller, 300),
        0,
        "nothing of the old generation plays"
    );
    // Mark 1 (read only now: it waited behind the answer) never plays.
    let mark = ev.mark(1);
    assert_eq!(mark["data"]["flushed"], true, "never played: {mark}");
    assert_eq!(mark["data"]["generation"], 0);

    // Late TTS audio of generation 0 (and a mark): dropped, never played.
    for k in 50..60 {
        send(&mut bot, 2, 2, k, 0);
    }
    send(&mut bot, 2, 3, 2, 0);
    assert_eq!(packets(&caller, 400), 0, "late audio is dropped");
    assert_eq!(ev.mark(2)["data"]["flushed"], true);

    // Generation 1's audio plays; its mark is answered once sent as RTP.
    for k in 0..5 {
        send(&mut bot, 2, 2, k, 1);
    }
    send(&mut bot, 2, 3, 3, 1);
    assert!(packets(&caller, 300) >= 3, "the new generation plays");
    let mark = ev.mark(3);
    assert_eq!(mark["data"]["flushed"], false);
    assert_eq!(mark["data"]["generation"], 1);
    assert_eq!(mark["data"]["boundary"], "rtp_sent");
    assert!(mark["data"]["played_ms"].as_u64().unwrap() >= played_ms + 100);

    // A flush from the service, at the same time as a mark: the mark is
    // answered flushed, the flush acknowledged (generation 2).
    for k in 5..30 {
        send(&mut bot, 2, 2, k, 1);
    }
    send(&mut bot, 2, 3, 4, 1);
    send(&mut bot, 2, 4, 0, 1);
    assert_eq!(ev.mark(4)["data"]["flushed"], true);
    let ack = frames.recv_timeout(WAIT).unwrap();
    assert_eq!((ack.kind, ack.seq, ack.generation), (4, 2, 2));
    assert_eq!(
        ev.take("stream.flushed", |d| d["generation"] == 2)["data"]["generation"],
        2
    );

    api.call("stream.stop", json!({"stream_id": stream}))
        .unwrap();
    assert_eq!(
        ev.take("stream.ended", |_| true)["data"]["stream_id"],
        stream
    );
    drop((api, ev));
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The threads named `rtpflux-pcm-*` in this process.
fn pcm_threads() -> Vec<String> {
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(|t| std::fs::read_to_string(t.ok()?.path().join("comm")).ok())
        .map(|c| c.trim().to_owned())
        .filter(|c| c.starts_with("rtpflux-pcm"))
        .collect()
}

/// Many streams on two shard threads. A service that does not read loses
/// frames (told by a gap) and costs the others nothing. A service that
/// floods the relay is held back, and the others' marks still come. A
/// service that goes away ends its stream, and a new stream on the same
/// endpoint works.
#[test]
#[allow(clippy::too_many_lines)] // Several services side by side.
fn many_streams_share_two_threads() {
    let dir = temp_dir("shards");
    let (daemon, sock) = relay(&dir, 63_900);
    let mut api = Client::connect(&sock).unwrap();
    let mut ev = Events {
        api: Client::connect(&sock).unwrap(),
        kept: Vec::new(),
    };
    ev.api.call("events.subscribe", json!({})).unwrap();
    let mut services = Vec::new();
    let mut ids = Vec::new();
    for k in 0..8 {
        let name = format!("svc{k}.sock");
        let listener = UnixListener::bind(dir.join(&name)).unwrap();
        let caller = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (id, to_relay) = endpoint(&mut api, &caller);
        // Service 0 at 48 kHz: its frames outgrow the socket's buffer
        // sooner.
        let rate = if k == 0 { 48_000 } else { 8000 };
        let st = api
            .call(
                "stream.start",
                json!({"endpoint_id": id, "socket": name, "rate": rate}),
            )
            .unwrap();
        let (bot, _) = listener.accept().unwrap();
        bot.set_read_timeout(Some(WAIT)).unwrap();
        services.push((bot, caller, to_relay, st["stream_id"].clone()));
        ids.push(id);
    }
    let threads = pcm_threads();
    assert_eq!(
        threads.len(),
        2,
        "two shards for eight streams: {threads:?}"
    );

    // Every caller talks for a second, caller 0 for four (more than its
    // service's socket holds at 48 kHz). Service 0 does not read
    // meanwhile.
    let talkers: Vec<_> = services
        .iter()
        .enumerate()
        .map(|(i, (_, caller, to_relay, _))| {
            let (c, to) = (caller.try_clone().unwrap(), *to_relay);
            let n = if i == 0 { 200u16 } else { 50 };
            std::thread::spawn(move || {
                for k in 0u16..n {
                    let mut p = vec![0x80, 0];
                    p.extend_from_slice(&k.to_be_bytes());
                    p.extend_from_slice(&(u32::from(k) * 160).to_be_bytes());
                    p.extend_from_slice(&0x0bad_cafe_u32.to_be_bytes());
                    p.extend_from_slice(&[0x55; 160]);
                    c.send_to(&p, to).unwrap();
                    std::thread::sleep(Duration::from_millis(20));
                }
            })
        })
        .collect();
    // The others read along.
    let readers: Vec<_> = services
        .iter()
        .skip(1)
        .map(|(bot, ..)| {
            let mut r = bot.try_clone().unwrap();
            std::thread::spawn(move || {
                let mut audio = 0;
                let deadline = Instant::now() + Duration::from_millis(1500);
                while Instant::now() < deadline {
                    match read_frame(&mut r) {
                        Some(f) if f.kind == 2 => audio += 1,
                        Some(_) => {}
                        None => break,
                    }
                }
                audio
            })
        })
        .collect();
    // Service 1 floods the relay with 2 s of audio, written as fast as it
    // can: held back (its writes wait), the relay's memory stays bounded.
    let flood = {
        let mut w = services[1].0.try_clone().unwrap();
        std::thread::spawn(move || {
            for k in 0..100 {
                send(&mut w, 1, 2, k, 0);
            }
        })
    };
    // Meanwhile service 2's mark is answered promptly.
    let started = Instant::now();
    send(&mut services[2].0, 1, 2, 0, 0);
    send(&mut services[2].0, 1, 3, 42, 0);
    let mark = ev.mark(42);
    assert_eq!(mark["data"]["stream_id"], services[2].3);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "fair: {:?}",
        started.elapsed()
    );
    for t in talkers {
        t.join().unwrap();
    }
    for r in readers {
        assert!(
            r.join().unwrap() >= 30,
            "the others got their caller's audio"
        );
    }
    flood.join().unwrap();

    // Service 0 reads at last (after more than its socket holds): what did
    // not fit was dropped, and a gap frame says how many.
    let mut gap = None;
    let deadline = Instant::now() + WAIT;
    while gap.is_none() && Instant::now() < deadline {
        match read_frame(&mut services[0].0) {
            Some(f) if f.kind == 5 => gap = Some(f),
            Some(f) => assert!(f.kind == 1 || f.samples == 960, "{f:?}"),
            None => break,
        }
    }
    let gap = gap.expect("a gap frame");
    assert!(gap.seq > 0, "{gap:?}");

    // Service 3 goes away: its stream ends. A new one on the same endpoint
    // works.
    let (bot, ..) = services.remove(3);
    drop(bot);
    let ended = ev.take("stream.ended", |_| true);
    assert!(ended["data"]["stream_id"].is_u64());
    let listener = UnixListener::bind(dir.join("again.sock")).unwrap();
    let again = api
        .call(
            "stream.start",
            json!({"endpoint_id": ids[3], "socket": "again.sock", "rate": 8000}),
        )
        .unwrap();
    let (mut bot, _) = listener.accept().unwrap();
    bot.set_read_timeout(Some(WAIT)).unwrap();
    assert_eq!(read_frame(&mut bot).unwrap().kind, 1, "hello");
    assert_ne!(again["stream_id"], ended["data"]["stream_id"]);
    assert_eq!(pcm_threads().len(), 2, "still two threads");

    drop((api, ev, services, bot));
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// CPU time (clock ticks) and number of the threads named `rtpflux-pcm*`.
fn pcm_cpu() -> (u64, usize) {
    let mut ticks = 0;
    let mut n = 0;
    for t in std::fs::read_dir("/proc/self/task").unwrap().flatten() {
        let comm = std::fs::read_to_string(t.path().join("comm")).unwrap_or_default();
        if !comm.starts_with("rtpflux-pcm") {
            continue;
        }
        let stat = std::fs::read_to_string(t.path().join("stat")).unwrap_or_default();
        // After the command's closing parenthesis: fields 3.. ; utime and
        // stime are fields 14 and 15.
        let rest = stat.rsplit_once(')').map_or("", |(_, r)| r);
        let f: Vec<&str> = rest.split_whitespace().collect();
        ticks += f.get(11).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0)
            + f.get(12).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        n += 1;
    }
    (ticks, n)
}

/// A load test (run by hand: `cargo test --release -p rtpflux --test pcm
/// load -- --ignored --nocapture`): 100 streams, both ways, for 5 s; the
/// PCM threads' CPU time and number.
#[test]
#[ignore = "a measurement"]
fn load() {
    const STREAMS: usize = 100;
    let dir = temp_dir("load");
    let sock = dir.join("api.sock");
    let config = Config::from_toml(&format!(
        r#"
        [control]
        listen = ["127.0.0.1:0"]
        native_socket = "{}"
        pcm_dir = "{}"
        [[interface]]
        name = "lo"
        address = "127.0.0.1"
        [ports]
        min = 40000
        max = 40999
        [sessions]
        max = 200
        [runtime]
        workers = 2
        "#,
        sock.display(),
        dir.display(),
    ))
    .unwrap();
    let daemon = Daemon::start(&config).unwrap();
    let mut api = Client::connect(&sock).unwrap();
    let mut legs = Vec::new();
    for k in 0..STREAMS {
        let name = format!("s{k}.sock");
        let listener = UnixListener::bind(dir.join(&name)).unwrap();
        let caller = UdpSocket::bind("127.0.0.1:0").unwrap();
        caller.set_nonblocking(true).unwrap();
        let (id, to) = endpoint(&mut api, &caller);
        api.call(
            "stream.start",
            json!({"endpoint_id": id, "socket": name, "rate": 16000}),
        )
        .unwrap();
        let (mut bot, _) = listener.accept().unwrap();
        // 5 s of the service's audio, at 8 kHz, ahead.
        for f in 0..250 {
            send(&mut bot, 1, 2, f, 0);
        }
        legs.push((bot, caller, to));
    }
    let (t0, threads) = pcm_cpu();
    let started = Instant::now();
    let mut buf = [0u8; 2048];
    for k in 0u16..250 {
        for (_, caller, to) in &legs {
            let mut p = vec![0x80, 0];
            p.extend_from_slice(&k.to_be_bytes());
            p.extend_from_slice(&(u32::from(k) * 160).to_be_bytes());
            p.extend_from_slice(&0x0bad_cafe_u32.to_be_bytes());
            p.extend_from_slice(&[0x55; 160]);
            let _ = caller.send_to(&p, to);
            while caller.recv_from(&mut buf).is_ok() {}
        }
        let due = Duration::from_millis(20 * (u64::from(k) + 1));
        std::thread::sleep(due.saturating_sub(started.elapsed()));
    }
    let (t1, _) = pcm_cpu();
    let hz = 100.0; // USER_HZ
    #[allow(clippy::cast_precision_loss)]
    let cpu = (t1 - t0) as f64 / hz / started.elapsed().as_secs_f64() * 100.0;
    eprintln!("PCM LOAD: {STREAMS} streams, {threads} threads, {cpu:.1}% of a CPU");
    drop((api, legs));
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}
