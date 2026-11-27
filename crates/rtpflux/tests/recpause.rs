//! Recording pause and resume with a boundary the media workers confirm:
//! the finished pcap holds nothing inside the confirmed pauses, a pause
//! survives a restart of the relay, and the recording's outcomes (file,
//! upload) are reported apart.

#[path = "support/logging.rs"]
mod logging;

use rtpflux::config::Config;
use rtpflux::daemon::Daemon;
use rtpflux_client::Client;
use serde_json::{Value, json};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(5);

fn temp_dir(name: &str) -> PathBuf {
    logging::init();
    let d = std::env::temp_dir().join(format!("rtpflux-recpause-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn relay(dir: &Path) -> (Daemon, PathBuf) {
    let sock = dir.join("api.sock");
    let rec = dir.join("rec");
    std::fs::create_dir_all(&rec).unwrap();
    let config = Config::from_toml(&format!(
        r#"
        [control]
        listen = ["127.0.0.1:0"]
        native_socket = "{}"
        [[interface]]
        name = "lo"
        address = "127.0.0.1"
        [ports]
        min = 62700
        max = 62763
        [sessions]
        max = 12
        state_file = "{}"
        [runtime]
        workers = 1
        [recording]
        dir = "{}"
        format = "pcap"
        "#,
        sock.display(),
        dir.join("state.json").display(),
        rec.display(),
    ))
    .unwrap();
    (Daemon::start(&config).unwrap(), sock)
}

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// The packets' times (ms) in a pcap file.
fn pcap_times(path: &Path) -> Vec<u64> {
    let b = std::fs::read(path).unwrap();
    let magic = u32::from_le_bytes(b[..4].try_into().unwrap());
    let nanos = match magic {
        0xa1b2_c3d4 => false,
        0xa1b2_3c4d => true,
        m => panic!("not a little-endian pcap: {m:#x}"),
    };
    let mut at = 24;
    let mut out = Vec::new();
    while at + 16 <= b.len() {
        let sec = u64::from(u32::from_le_bytes(b[at..at + 4].try_into().unwrap()));
        let frac = u64::from(u32::from_le_bytes(b[at + 4..at + 8].try_into().unwrap()));
        let len = u32::from_le_bytes(b[at + 8..at + 12].try_into().unwrap()) as usize;
        out.push(sec * 1000 + if nanos { frac / 1_000_000 } else { frac / 1000 });
        at += 16 + len;
    }
    out
}

/// A caller sending audio every 20 ms to wherever `to` says, until told
/// to stop.
fn talker(
    caller: UdpSocket,
    to: Arc<AtomicU16>,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut seq = 0u16;
        while !stop.load(Ordering::Relaxed) {
            let mut p = vec![0x80, 0];
            p.extend_from_slice(&seq.to_be_bytes());
            p.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
            p.extend_from_slice(&0x0bad_cafe_u32.to_be_bytes());
            p.extend_from_slice(&[0x55; 160]);
            let port = to.load(Ordering::Relaxed);
            let _ = caller.send_to(&p, SocketAddr::from(([127, 0, 0, 1], port)));
            seq = seq.wrapping_add(1);
            std::thread::sleep(Duration::from_millis(20));
        }
    })
}

#[test]
#[allow(clippy::too_many_lines)] // One recording's life, through a restart.
fn pauses_are_confirmed_and_hold_nothing() {
    let dir = temp_dir("pause");
    let (daemon, sock) = relay(&dir);
    let mut api = Client::connect(&sock).unwrap();
    let caller = UdpSocket::bind("127.0.0.1:0").unwrap();
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
    let id = ep["endpoint_id"].as_str().unwrap().to_owned();
    let relay_port: u16 = ep["sdp"]
        .as_str()
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("m=audio "))
        .and_then(|l| l.split(' ').next())
        .unwrap()
        .parse()
        .unwrap();
    // Bridged to a callee, so its media is relayed (and recorded).
    let callee = UdpSocket::bind("127.0.0.1:0").unwrap();
    let cport = callee.local_addr().unwrap().port();
    let csdp = sdp.replace(&format!("m=audio {port} "), &format!("m=audio {cport} "));
    let peer = api
        .call(
            "endpoint.create",
            json!({"remote_sdp": csdp, "options": {"flags": ["trust-address"], "endpoint-learning": "off"}}),
        )
        .unwrap();
    api.call(
        "bridge.attach",
        json!({"endpoint_id": id, "peer_endpoint_id": peer["endpoint_id"]}),
    )
    .unwrap();
    let (to, stop) = (
        Arc::new(AtomicU16::new(relay_port)),
        Arc::new(AtomicBool::new(false)),
    );
    let talking = talker(
        caller.try_clone().unwrap(),
        Arc::clone(&to),
        Arc::clone(&stop),
    );

    // Not recording: nothing to pause.
    let e = api
        .call("recording.pause", json!({"endpoint_id": id}))
        .unwrap_err();
    assert_eq!(e.code(), Some("conflict"));
    let rec = api
        .call("recording.start", json!({"endpoint_id": id}))
        .unwrap();
    let rid = rec["recording_id"].as_str().unwrap().to_owned();
    std::thread::sleep(Duration::from_millis(400));

    // Pause: confirmed, with its boundary.
    let p = api
        .call("recording.pause", json!({"endpoint_id": id}))
        .unwrap();
    assert_eq!(
        (p["state"].as_str(), p["changed"].as_bool()),
        (Some("paused"), Some(true))
    );
    let paused1 = p["pauses"][0][0].as_u64().unwrap();
    assert_eq!(p["pauses"][0][1], Value::Null);
    // Again: nothing changes.
    let again = api
        .call("recording.pause", json!({"endpoint_id": id}))
        .unwrap();
    assert_eq!(
        (again["state"].as_str(), again["changed"].as_bool()),
        (Some("paused"), Some(false))
    );
    std::thread::sleep(Duration::from_millis(600));
    let resume1_asked = now_ms();
    let r = api
        .call("recording.resume", json!({"endpoint_id": id}))
        .unwrap();
    assert_eq!(r["state"], "active");
    assert!(r["pauses"][0][1].as_u64().unwrap() >= resume1_asked);
    std::thread::sleep(Duration::from_millis(400));

    // Paused across a restart of the relay.
    let p = api
        .call("recording.pause", json!({"endpoint_id": id}))
        .unwrap();
    let paused2 = p["pauses"][1][0].as_u64().unwrap();
    drop(api);
    daemon.stop();
    let (daemon, sock) = relay(&dir);
    let mut api = Client::connect(&sock).unwrap();
    let q = api
        .call("recording.query", json!({"recording_id": rid}))
        .unwrap();
    assert_eq!(q["state"], "paused", "still paused after the restart: {q}");
    assert_eq!(q["upload"], "pending");
    std::thread::sleep(Duration::from_millis(400));
    let resume2_asked = now_ms();
    let r = api
        .call("recording.resume", json!({"endpoint_id": id}))
        .unwrap();
    assert_eq!(r["state"], "active");
    std::thread::sleep(Duration::from_millis(400));

    api.call(
        "events.subscribe",
        json!({"types": ["recording.completed", "recording.failed"]}),
    )
    .unwrap();
    api.call("recording.stop", json!({"endpoint_id": id}))
        .unwrap();
    let done = api
        .wait_event("recording.completed", WAIT)
        .unwrap()
        .expect("completed");
    assert_eq!(done["data"]["recording_id"], rid.as_str());
    stop.store(true, Ordering::Relaxed);
    talking.join().unwrap();
    let q = api
        .call("recording.query", json!({"recording_id": rid}))
        .unwrap();
    assert_eq!(q["state"], "completed");
    assert_eq!(
        (q["finalized"].as_bool(), q["upload"].as_str()),
        (Some(true), Some("none"))
    );
    assert_eq!(q["pauses"].as_array().unwrap().len(), 2);

    // The recording: audio before, between and after the pauses, nothing
    // inside them.
    let times = pcap_times(Path::new(q["file"].as_str().unwrap()));
    let inside = |from: u64, to: u64| times.iter().filter(|&&t| t > from + 2 && t < to).count();
    assert_eq!(
        inside(paused1, resume1_asked),
        0,
        "nothing in the first pause"
    );
    assert_eq!(
        inside(paused2, resume2_asked),
        0,
        "nothing in the second, across the restart"
    );
    let before = times.iter().filter(|&&t| t <= paused1).count();
    let between = inside(resume1_asked, paused2);
    let after = times.iter().filter(|&&t| t >= resume2_asked).count();
    assert!(
        before >= 10 && between >= 10 && after >= 10,
        "{before} {between} {after}"
    );
    drop(api);
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}
