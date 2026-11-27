//! The native control API, end to end: a running relay, its Unix socket,
//! and a softswitch's client (`rtpflux-client`) managing two independent
//! media endpoints: negotiation both ways, a bridge, events (DTMF,
//! playback, bridges, the end of endpoints), renegotiation with commit
//! and abort, idempotency, generations, tombstones, tenants and leases.

#[path = "support/logging.rs"]
mod logging;

use rtpflux::config::Config;
use rtpflux::daemon::Daemon;
use rtpflux_client::Client;
use serde_json::{Value, json};
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(3);

fn temp_dir(name: &str) -> PathBuf {
    logging::init();
    let d = std::env::temp_dir().join(format!("rtpflux-native-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A relay with the native API on `dir/api.sock`, on ports from `min`.
fn relay(dir: &std::path::Path, min: u16, workers: usize) -> (Daemon, PathBuf) {
    relay_with(dir, min, workers, "")
}

/// [`relay`] with more `[sessions]` settings.
fn relay_with(
    dir: &std::path::Path,
    min: u16,
    workers: usize,
    sessions: &str,
) -> (Daemon, PathBuf) {
    let sock = dir.join("api.sock");
    let config = Config::from_toml(&format!(
        r#"
        [control]
        listen = ["127.0.0.1:0"]
        native_socket = "{}"
        native_max_endpoints = 6
        pcm_dir = "{}"
        native_listen = ["127.0.0.1:0"]
        native_tokens = {{ default = "token-of-default-0", b = "token-of-tenant-b" }}
        [[interface]]
        name = "lo"
        address = "127.0.0.1"
        [ports]
        min = {min}
        max = {}
        [sessions]
        max = 12
        {sessions}
        [runtime]
        workers = {workers}
        "#,
        sock.display(),
        dir.display(),
        min + 63
    ))
    .unwrap();
    (Daemon::start(&config).unwrap(), sock)
}

fn endpoint() -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    s
}

fn port(s: &UdpSocket) -> u16 {
    s.local_addr().unwrap().port()
}

/// An offer (or answer) from `s`: PCMU and telephone events.
fn sdp(s: &UdpSocket, version: u32, direction: &str) -> String {
    format!(
        "v=0\r\no=- 7 {version} IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\na={direction}\r\n",
        port(s)
    )
}

/// The relay's address in an SDP.
fn relay_addr(sdp: &str) -> SocketAddr {
    let port = sdp
        .lines()
        .find_map(|l| l.strip_prefix("m=audio "))
        .and_then(|l| l.split(' ').next())
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap();
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn rtp(pt: u8, seq: u16, ts: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x80, pt | if marker { 0x80 } else { 0 }];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&ts.to_be_bytes());
    p.extend_from_slice(&0x1234_5678u32.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

fn receives(s: &UdpSocket) -> bool {
    let mut buf = [0u8; 2048];
    s.recv_from(&mut buf).is_ok()
}

/// Drain what `s` received so far.
fn drain(s: &UdpSocket) {
    s.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 2048];
    while s.recv_from(&mut buf).is_ok() {}
    s.set_nonblocking(false).unwrap();
}

/// A short WAV file: 8 kHz, 16-bit mono, `ms` long.
fn wav(path: &std::path::Path, ms: u32) {
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

/// The options every negotiation here takes: addresses as written.
fn opts() -> Value {
    json!({"flags": ["trust-address"], "endpoint-learning": "off"})
}

fn code(e: &rtpflux_client::ClientError) -> &str {
    e.code().unwrap_or("none")
}

#[test]
#[allow(clippy::too_many_lines)] // One softswitch's session, step by step.
fn a_softswitch_manages_two_legs() {
    let dir = temp_dir("legs");
    let (daemon, sock) = relay(&dir, 50_300, 2);
    let mut api = Client::connect(&sock).unwrap();
    let hello = api.call("hello", Value::Null).unwrap();
    assert_eq!(hello["versions"], json!([1]));
    assert!(
        hello["operations"]
            .as_array()
            .unwrap()
            .contains(&json!("bridge.attach"))
    );
    api.call("events.subscribe", json!({})).unwrap();

    let (caller, ivr) = (endpoint(), endpoint());
    // The inbound leg: the caller's offer, answered by the relay alone.
    let inbound = api
        .call(
            "endpoint.create",
            json!({"remote_sdp": sdp(&caller, 1, "sendrecv"), "label": "caller", "options": opts()}),
        )
        .unwrap();
    assert_eq!(inbound["sdp_type"], "answer");
    assert_eq!(inbound["state"], "ready");
    let answer = inbound["sdp"].as_str().unwrap();
    assert!(
        answer.contains("a=sendrecv") && answer.contains(" RTP/AVP 0 101"),
        "{answer}"
    );
    let (a_id, a_gen) = (
        inbound["endpoint_id"].as_str().unwrap().to_owned(),
        inbound["generation"].clone(),
    );
    let for_caller = relay_addr(answer);
    let ready = api.wait_event("endpoint.ready", WAIT).unwrap().unwrap();
    assert_eq!(ready["endpoint_id"], a_id.as_str());

    // The outbound leg: the relay's offer, the IVR's answer.
    let outbound = api
        .call(
            "endpoint.create",
            json!({"codecs": ["PCMU", "telephone-event"]}),
        )
        .unwrap();
    assert_eq!(outbound["sdp_type"], "offer");
    assert_eq!(outbound["state"], "offered");
    let b_id = outbound["endpoint_id"].as_str().unwrap().to_owned();
    assert_ne!(
        outbound["session_id"], inbound["session_id"],
        "independent sessions"
    );
    let for_ivr = relay_addr(outbound["sdp"].as_str().unwrap());
    api.call(
        "endpoint.apply_answer",
        json!({"endpoint_id": b_id, "sdp": sdp(&ivr, 1, "sendrecv"), "options": opts()}),
    )
    .unwrap();
    // Answering twice is a conflict.
    let again = api
        .call(
            "endpoint.apply_answer",
            json!({"endpoint_id": b_id, "sdp": sdp(&ivr, 1, "sendrecv")}),
        )
        .unwrap_err();
    assert_eq!(code(&again), "conflict");

    // Parked: nothing flows.
    std::thread::sleep(Duration::from_millis(50));
    caller
        .send_to(&rtp(0, 1, 0, false, &[0xff; 160]), for_caller)
        .unwrap();
    assert!(!receives(&ivr));

    // Bridged (the two sessions on different workers): media both ways.
    let br = api
        .call(
            "bridge.attach",
            json!({"endpoint_id": a_id, "peer_endpoint_id": b_id, "expected_generation": a_gen}),
        )
        .unwrap();
    assert_eq!(br["bridged_to"], b_id.as_str());
    let changed = api.wait_event("bridge.changed", WAIT).unwrap().unwrap();
    assert_eq!(changed["data"]["reason"], "attached");
    // The reply came once the workers applied it: no wait needed.
    caller
        .send_to(&rtp(0, 2, 160, false, &[0xff; 160]), for_caller)
        .unwrap();
    assert!(receives(&ivr), "the IVR hears the caller");
    ivr.send_to(&rtp(0, 1, 0, false, &[0xff; 160]), for_ivr)
        .unwrap();
    assert!(receives(&caller), "the caller hears the IVR");

    // A key press (RFC 4733, its end sent three times): one event.
    for (seq, dur, end) in [
        (3, 400, false),
        (4, 800, false),
        (5, 1200, true),
        (6, 1200, true),
        (7, 1200, true),
    ] {
        let mut ev = vec![5u8, if end { 0x80 | 0x0a } else { 0x0a }];
        ev.extend_from_slice(&u16::to_be_bytes(dur));
        caller
            .send_to(&rtp(101, seq, 320, seq == 3, &ev), for_caller)
            .unwrap();
    }
    let dtmf = api.wait_event("dtmf.detected", WAIT).unwrap().unwrap();
    assert_eq!(dtmf["endpoint_id"], a_id.as_str());
    assert_eq!(dtmf["data"]["digit"], "5");
    assert_eq!(dtmf["data"]["duration_ms"], 150);
    assert_eq!(dtmf["data"]["source"], "rfc4733");
    // No second one for the repeated ends.
    assert!(
        api.wait_event("dtmf.detected", Duration::from_millis(1500))
            .unwrap()
            .is_none()
    );
    drain(&ivr);

    // An announcement to the caller: it plays out, and says so.
    let file = dir.join("prompt.wav");
    wav(&file, 200);
    let pb = api
        .call(
            "playback.start",
            json!({"endpoint_id": a_id, "file": file.display().to_string(), "operation_id": "play-1"}),
        )
        .unwrap();
    let done = api.wait_event("playback.completed", WAIT).unwrap().unwrap();
    assert_eq!(done["data"]["playback_id"], pb["playback_id"]);
    assert_eq!(done["operation_id"], "play-1");
    drain(&caller);

    // The caller's re-INVITE (hold), prepared, then aborted: revision 1.
    let prep = api
        .call(
            "endpoint.prepare",
            json!({"endpoint_id": a_id, "remote_sdp": sdp(&caller, 2, "sendonly"), "options": opts()}),
        )
        .unwrap();
    assert_eq!(prep["pending_revision"], 2);
    let held = prep["sdp"].as_str().unwrap();
    assert!(held.contains("a=recvonly"), "{held}");
    assert_eq!(relay_addr(held), for_caller, "the same port");
    let twice = api
        .call(
            "endpoint.prepare",
            json!({"endpoint_id": a_id, "remote_sdp": sdp(&caller, 3, "sendonly")}),
        )
        .unwrap_err();
    assert_eq!(code(&twice), "conflict");
    let ab = api
        .call(
            "endpoint.abort",
            json!({"endpoint_id": a_id, "revision": 2}),
        )
        .unwrap();
    assert_eq!(ab["revision"], 1);
    // The bridge is still there.
    caller
        .send_to(&rtp(0, 8, 480, false, &[0xff; 160]), for_caller)
        .unwrap();
    assert!(receives(&ivr), "still bridged after the abort");

    // The relay's re-offer to the IVR, committed with its answer.
    let prep = api
        .call(
            "endpoint.prepare",
            json!({"endpoint_id": b_id, "codecs": ["PCMU"]}),
        )
        .unwrap();
    assert_eq!(prep["sdp_type"], "offer");
    let stale = api
        .call(
            "endpoint.commit",
            json!({"endpoint_id": b_id, "revision": 7, "sdp": sdp(&ivr, 2, "sendrecv")}),
        )
        .unwrap_err();
    assert_eq!(code(&stale), "conflict");
    let cm = api
        .call(
            "endpoint.commit",
            json!({"endpoint_id": b_id, "revision": 2, "sdp": sdp(&ivr, 2, "sendrecv"), "options": opts()}),
        )
        .unwrap();
    assert_eq!(cm["revision"], 2);
    let snap = api
        .call("endpoint.query", json!({"endpoint_id": b_id}))
        .unwrap();
    assert_eq!(snap["revision"], 2);
    assert_eq!(snap["bridged_to"], a_id.as_str());
    assert!(snap["media"]["medias"].is_array(), "{snap}");

    // A stale generation, another tenant.
    let stale = api
        .call(
            "endpoint.query",
            json!({"endpoint_id": a_id, "expected_generation": 999}),
        )
        .unwrap_err();
    assert_eq!(code(&stale), "conflict");
    let other = api
        .call(
            "endpoint.query",
            json!({"endpoint_id": a_id, "tenant": "other"}),
        )
        .unwrap_err();
    assert_eq!(code(&other), "unauthorized");

    // Detached: nothing flows; both are told.
    api.call("bridge.detach", json!({"endpoint_id": a_id}))
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    drain(&ivr);
    caller
        .send_to(&rtp(0, 9, 640, false, &[0xff; 160]), for_caller)
        .unwrap();
    assert!(!receives(&ivr), "detached");
    let snap = api
        .call("endpoint.query", json!({"endpoint_id": b_id}))
        .unwrap();
    assert_eq!(snap["bridged_to"], Value::Null);

    // Destroyed, once: then a tombstone.
    let gone_now = api
        .call("endpoint.destroy", json!({"endpoint_id": a_id}))
        .unwrap();
    assert_eq!(gone_now["destroyed"], true);
    let gone = api.wait_event("endpoint.destroyed", WAIT).unwrap().unwrap();
    assert_eq!(gone["endpoint_id"], a_id.as_str());
    let gone_now = api
        .call("endpoint.destroy", json!({"endpoint_id": a_id}))
        .unwrap();
    assert_eq!(gone_now["already"], true);
    let late = api
        .call("endpoint.query", json!({"endpoint_id": a_id}))
        .unwrap_err();
    assert_eq!(code(&late), "not_found");
    assert!(late.to_string().contains("destroyed"), "{late}");
    let list = api.call("endpoint.list", Value::Null).unwrap();
    assert_eq!(list["endpoints"].as_array().unwrap().len(), 1);
    assert_eq!(list["destroyed"][0]["endpoint_id"], a_id.as_str());
    caller
        .send_to(&rtp(0, 10, 800, false, &[0xff; 160]), for_caller)
        .unwrap();
    assert!(!receives(&caller) && !receives(&ivr));

    api.call("endpoint.destroy", json!({"endpoint_id": b_id}))
        .unwrap();
    drop(api);
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn requests_are_idempotent_leased_and_limited() {
    let dir = temp_dir("limits");
    let (daemon, sock) = relay(&dir, 50_500, 1);
    let mut api = Client::connect(&sock).unwrap();
    api.call("events.subscribe", json!({"types": ["endpoint.destroyed"]}))
        .unwrap();
    let caller = endpoint();
    // A retried create: the same endpoint, made once.
    let req = json!({"remote_sdp": sdp(&caller, 1, "sendrecv"), "idempotency_key": "k-1", "options": opts()});
    let first = api.call("endpoint.create", req.clone()).unwrap();
    let second = api.call("endpoint.create", req).unwrap();
    assert_eq!(first["endpoint_id"], second["endpoint_id"]);
    let list = api.call("endpoint.list", Value::Null).unwrap();
    assert_eq!(list["endpoints"].as_array().unwrap().len(), 1);

    // A lease not renewed: destroyed.
    let leased = api
        .call(
            "endpoint.create",
            json!({"lease_ms": 1000, "codecs": ["PCMA"]}),
        )
        .unwrap();
    let id = leased["endpoint_id"].as_str().unwrap().to_owned();
    std::thread::sleep(Duration::from_millis(600));
    api.call("endpoint.renew", json!({"endpoint_id": id}))
        .unwrap();
    std::thread::sleep(Duration::from_millis(600));
    assert!(
        api.call("endpoint.query", json!({"endpoint_id": id}))
            .is_ok(),
        "renewed"
    );
    let ev = api.wait_event("endpoint.destroyed", WAIT).unwrap().unwrap();
    assert_eq!(ev["endpoint_id"], id.as_str());
    assert_eq!(ev["data"]["reason"], "lease");

    // Bad requests: typed errors.
    let e = api.call("endpoint.frobnicate", Value::Null).unwrap_err();
    assert_eq!(code(&e), "unsupported");
    let e = api
        .call("endpoint.create", json!({"remote_sdp": "nonsense"}))
        .unwrap_err();
    assert_eq!(code(&e), "invalid");
    let e = api
        .call("endpoint.create", json!({"deadline_unix_ms": 1}))
        .unwrap_err();
    assert_eq!(code(&e), "timeout");
    let e = api
        .call("endpoint.create", json!({"options": {"call-id": "x"}}))
        .unwrap_err();
    assert_eq!(code(&e), "invalid");

    // At most 6 endpoints for a tenant.
    let mut made = 1;
    let refused = loop {
        match api.call("endpoint.create", json!({"codecs": ["PCMU"]})) {
            Ok(_) => made += 1,
            Err(e) => break e,
        }
        assert!(made <= 6);
    };
    assert_eq!(code(&refused), "exhausted");
    // Another tenant has its own.
    api.call(
        "endpoint.create",
        json!({"tenant": "b", "codecs": ["PCMU"]}),
    )
    .unwrap();

    // An `ng` delete of the session ends the endpoint too.
    let s = first["session_id"].as_str().unwrap();
    let ng = UdpSocket::bind("127.0.0.1:0").unwrap();
    let msg = format!("c1 d7:call-id{}:{s}7:command6:deletee", s.len());
    ng.send_to(msg.as_bytes(), daemon.control_addrs()[0])
        .unwrap();
    let mut buf = [0u8; 512];
    ng.set_read_timeout(Some(WAIT)).unwrap();
    ng.recv_from(&mut buf).unwrap();
    let ev = api.wait_event("endpoint.destroyed", WAIT).unwrap().unwrap();
    assert_eq!(ev["endpoint_id"], first["endpoint_id"]);
    assert_eq!(ev["data"]["reason"], "ended");

    drop(api);
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Endpoints survive a restart of the relay (with a state file): the same
/// ids, generations and bridge, on the same ports, and media flows again.
#[test]
fn endpoints_survive_a_restart() {
    let dir = temp_dir("restart");
    let state = format!("state_file = \"{}\"", dir.join("state.json").display());
    let (daemon, sock) = relay_with(&dir, 50_700, 1, &state);
    let mut api = Client::connect(&sock).unwrap();
    let (caller, ivr) = (endpoint(), endpoint());
    let inbound = api
        .call(
            "endpoint.create",
            json!({"remote_sdp": sdp(&caller, 1, "sendrecv"), "options": opts()}),
        )
        .unwrap();
    let outbound = api
        .call("endpoint.create", json!({"codecs": ["PCMU"]}))
        .unwrap();
    let (a, b) = (
        inbound["endpoint_id"].as_str().unwrap().to_owned(),
        outbound["endpoint_id"].as_str().unwrap().to_owned(),
    );
    api.call(
        "endpoint.apply_answer",
        json!({"endpoint_id": b, "sdp": sdp(&ivr, 1, "sendrecv"), "options": opts()}),
    )
    .unwrap();
    api.call(
        "bridge.attach",
        json!({"endpoint_id": a, "peer_endpoint_id": b}),
    )
    .unwrap();
    let for_caller = relay_addr(inbound["sdp"].as_str().unwrap());
    let for_ivr = relay_addr(outbound["sdp"].as_str().unwrap());
    drop(api);
    daemon.stop();

    let (daemon, sock) = relay_with(&dir, 50_700, 1, &state);
    let mut api = Client::connect(&sock).unwrap();
    let list = api.call("endpoint.list", Value::Null).unwrap();
    let eps = list["endpoints"].as_array().unwrap();
    assert_eq!(eps.len(), 2, "{list}");
    let snap = api
        .call("endpoint.query", json!({"endpoint_id": a}))
        .unwrap();
    assert_eq!(snap["generation"], inbound["generation"]);
    assert_eq!(snap["bridged_to"], b.as_str());
    std::thread::sleep(Duration::from_millis(100));
    caller
        .send_to(&rtp(0, 1, 0, false, &[0xff; 160]), for_caller)
        .unwrap();
    assert!(receives(&ivr), "the IVR hears the caller after the restart");
    ivr.send_to(&rtp(0, 1, 0, false, &[0xff; 160]), for_ivr)
        .unwrap();
    assert!(receives(&caller), "and the other way");
    // A new endpoint gets a generation not given before.
    let c = api
        .call("endpoint.create", json!({"codecs": ["PCMU"]}))
        .unwrap();
    assert!(c["generation"].as_u64() > outbound["generation"].as_u64());
    drop(api);
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// One frame of the PCM stream protocol from `r`: (kind, seq, rate,
/// samples).
fn pcm_frame(r: &mut std::os::unix::net::UnixStream) -> (u8, u32, u32, Vec<i16>) {
    use std::io::Read;
    let mut h = [0u8; 32];
    r.read_exact(&mut h).unwrap();
    assert_eq!(&h[..4], b"RFPC");
    let seq = u32::from_le_bytes(h[12..16].try_into().unwrap());
    let rate = u32::from_le_bytes(h[24..28].try_into().unwrap());
    let n = usize::from(u16::from_le_bytes([h[30], h[31]]));
    let mut body = vec![0u8; if h[5] == 2 { n * 2 } else { 0 }];
    r.read_exact(&mut body).unwrap();
    let pcm = body
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| i16::from_le_bytes(*b))
        .collect();
    (h[5], seq, rate, pcm)
}

/// A frame of the PCM stream protocol to the relay.
fn pcm_send(w: &mut std::os::unix::net::UnixStream, kind: u8, seq: u32, rate: u32, pcm: &[i16]) {
    use std::io::Write;
    let mut f = Vec::new();
    f.extend_from_slice(b"RFPC");
    f.extend_from_slice(&[1, kind, 0, 0]);
    f.extend_from_slice(&0u32.to_le_bytes());
    f.extend_from_slice(&seq.to_le_bytes());
    f.extend_from_slice(&0u64.to_le_bytes());
    f.extend_from_slice(&rate.to_le_bytes());
    f.extend_from_slice(&[1, 1]);
    f.extend_from_slice(&u16::try_from(pcm.len()).unwrap().to_le_bytes());
    for s in pcm {
        f.extend_from_slice(&s.to_le_bytes());
    }
    w.write_all(&f).unwrap();
}

/// A tone at 16 kHz, 20 ms, from sample `at`.
fn tone16(at: usize) -> Vec<i16> {
    (at..at + 320)
        .map(|i| {
            let x =
                f64::from(u32::try_from(i).unwrap()) * 2.0 * std::f64::consts::PI * 440.0 / 16000.0;
            #[allow(clippy::cast_possible_truncation)]
            let v = (x.sin() * 8000.0) as i16;
            v
        })
        .collect()
}

/// A PCM stream to an external service: the caller's audio arrives
/// decoded at 16 kHz (speech is detected), the service's audio reaches the
/// caller in G.711, a mark is answered once played, and stopping it ends
/// it.
#[test]
#[allow(clippy::too_many_lines)] // A service's session, step by step.
fn audio_streams_to_and_from_a_service() {
    let dir = temp_dir("pcm");
    let (daemon, sock) = relay(&dir, 50_900, 1);
    let service = std::os::unix::net::UnixListener::bind(dir.join("bot.sock")).unwrap();
    let mut api = Client::connect(&sock).unwrap();
    api.call("events.subscribe", json!({})).unwrap();
    let caller = endpoint();
    let inbound = api
        .call(
            "endpoint.create",
            json!({"remote_sdp": sdp(&caller, 1, "sendrecv"), "options": opts()}),
        )
        .unwrap();
    let id = inbound["endpoint_id"].as_str().unwrap().to_owned();
    let for_caller = relay_addr(inbound["sdp"].as_str().unwrap());
    // Outside the directory: refused.
    let e = api
        .call("stream.start", json!({"endpoint_id": id, "socket": "../x"}))
        .unwrap_err();
    assert_eq!(code(&e), "invalid");
    let st = api
        .call(
            "stream.start",
            json!({"endpoint_id": id, "socket": "bot.sock", "rate": 16000}),
        )
        .unwrap();
    let stream = st["stream_id"].clone();
    assert_eq!(st["inject"], true);
    let (mut bot, _) = service.accept().unwrap();
    bot.set_read_timeout(Some(WAIT)).unwrap();
    let (kind, _, rate, _) = pcm_frame(&mut bot);
    assert_eq!((kind, rate), (1, 16000), "hello");

    // The caller speaks (a loud tone in G.711 μ-law): 16 kHz frames reach
    // the service, and speech is detected.
    let loud: Vec<u8> = (0..160)
        .map(|i| {
            let x = (f64::from(i) * 2.0 * std::f64::consts::PI * 400.0 / 8000.0).sin();
            #[allow(clippy::cast_possible_truncation)]
            let s = (x * 12000.0) as i16;
            rtpflux_core::g711::linear_to_ulaw(s)
        })
        .collect();
    let sender = std::thread::spawn({
        let caller = caller.try_clone().unwrap();
        move || {
            for k in 0u16..40 {
                caller
                    .send_to(&rtp(0, k, u32::from(k) * 160, k == 0, &loud), for_caller)
                    .unwrap();
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    });
    let mut frames = 0;
    let mut energy = 0u64;
    while frames < 10 {
        let (kind, _, rate, pcm) = pcm_frame(&mut bot);
        if kind == 2 {
            assert_eq!((rate, pcm.len()), (16000, 320));
            energy += pcm
                .iter()
                .map(|&s| u64::from(s.unsigned_abs()))
                .sum::<u64>();
            frames += 1;
        }
    }
    assert!(
        energy > 10 * 320 * 1000,
        "the caller's audio, decoded: {energy}"
    );
    let speech = api.wait_event("speech.started", WAIT).unwrap().unwrap();
    assert_eq!(speech["endpoint_id"], id.as_str());
    sender.join().unwrap();

    // A key in the audio (in-band DTMF, 5: 770 + 1336 Hz), then silence.
    let keyed = std::thread::spawn({
        let caller = caller.try_clone().unwrap();
        move || {
            for k in 40u16..70 {
                let payload: Vec<u8> = (0..160u32)
                    .map(|i| {
                        if k >= 50 {
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
                    .send_to(&rtp(0, k, u32::from(k) * 160, false, &payload), for_caller)
                    .unwrap();
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    });
    // The service keeps reading meanwhile.
    let reader = {
        let mut bot = bot.try_clone().unwrap();
        std::thread::spawn(move || {
            for _ in 0..40 {
                let _ = pcm_frame(&mut bot);
            }
        })
    };
    let key = api.wait_event("dtmf.detected", WAIT).unwrap().unwrap();
    assert_eq!(key["data"]["digit"], "5");
    assert_eq!(key["data"]["source"], "inband");
    keyed.join().unwrap();
    reader.join().unwrap();

    // The service answers: 10 frames, then a mark.
    let mut writer = bot.try_clone().unwrap();
    for k in 0..10 {
        pcm_send(&mut writer, 2, k, 16000, &tone16(k as usize * 320));
    }
    pcm_send(&mut writer, 3, 77, 0, &[]);
    let mut got = 0;
    let mut buf = [0u8; 2048];
    caller.set_read_timeout(Some(WAIT)).unwrap();
    while got < 5 {
        let (n, _) = caller.recv_from(&mut buf).unwrap();
        assert!(
            n == 12 + 160 && (buf[1] == 0 || buf[1] == 0x80),
            "G.711 frames to the caller"
        );
        got += 1;
    }
    let mark = api.wait_event("stream.mark", WAIT).unwrap().unwrap();
    assert_eq!(mark["data"]["mark"], 77);
    assert_eq!(mark["data"]["stream_id"], stream);

    // A flush is taken; stopping the stream ends it.
    api.call("stream.flush", json!({"stream_id": stream}))
        .unwrap();
    api.call("stream.stop", json!({"stream_id": stream}))
        .unwrap();
    let ended = api.wait_event("stream.ended", WAIT).unwrap().unwrap();
    assert_eq!(ended["data"]["stream_id"], stream);
    drop(api);
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The mean absolute level of the μ-law audio `s` receives within `ms`
/// (packets from the relay), and how many packets.
fn heard(s: &UdpSocket, ms: u64) -> (u64, usize) {
    let end = std::time::Instant::now() + Duration::from_millis(ms);
    let mut buf = [0u8; 2048];
    let (mut sum, mut samples, mut packets) = (0u64, 0u64, 0);
    s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    while std::time::Instant::now() < end {
        if let Ok((n, _)) = s.recv_from(&mut buf)
            && n > 12
        {
            packets += 1;
            for &c in &buf[12..n] {
                sum += u64::from(rtpflux_core::g711::ulaw_to_linear(c).unsigned_abs());
                samples += 1;
            }
        }
    }
    (sum / samples.max(1), packets)
}

/// A conference: three endpoints in a mixer; each hears the others, not
/// itself; the talker is the active speaker; muting silences it; the
/// mixer's end stops the audio.
#[test]
#[allow(clippy::too_many_lines)] // A conference, step by step.
fn a_mixer_mixes_everyone_but_oneself() {
    let dir = temp_dir("mixer");
    let (daemon, sock) = relay(&dir, 51_300, 2);
    let mut api = Client::connect(&sock).unwrap();
    api.call("events.subscribe", json!({"types": ["mixer.speaker"]}))
        .unwrap();
    let mixer = api.call("mixer.create", Value::Null).unwrap()["mixer_id"].clone();
    let parties: Vec<UdpSocket> = (0..3).map(|_| endpoint()).collect();
    let mut joined = Vec::new();
    for p in &parties {
        let ep = api
            .call(
                "endpoint.create",
                json!({"remote_sdp": sdp(p, 1, "sendrecv"), "options": opts()}),
            )
            .unwrap();
        let id = ep["endpoint_id"].as_str().unwrap().to_owned();
        api.call("mixer.add", json!({"mixer_id": mixer, "endpoint_id": id}))
            .unwrap();
        joined.push((id, relay_addr(ep["sdp"].as_str().unwrap())));
    }
    // Twice: a conflict.
    let e = api
        .call(
            "mixer.add",
            json!({"mixer_id": mixer, "endpoint_id": joined[0].0}),
        )
        .unwrap_err();
    assert_eq!(code(&e), "conflict");
    // Party 0 talks (a loud tone); 1 and 2 are silent (μ-law 0xff).
    let loud: Vec<u8> = (0..160)
        .map(|i| {
            let x = (f64::from(i) * 2.0 * std::f64::consts::PI * 400.0 / 8000.0).sin();
            #[allow(clippy::cast_possible_truncation)]
            let v = (x * 12000.0) as i16;
            rtpflux_core::g711::linear_to_ulaw(v)
        })
        .collect();
    let talk = |packets: u16, loud: Vec<u8>| {
        let socks: Vec<UdpSocket> = parties.iter().map(|p| p.try_clone().unwrap()).collect();
        let to: Vec<SocketAddr> = joined.iter().map(|j| j.1).collect();
        std::thread::spawn(move || {
            for k in 0..packets {
                for (i, s) in socks.iter().enumerate() {
                    let payload = if i == 0 {
                        loud.clone()
                    } else {
                        vec![0xff; 160]
                    };
                    s.send_to(&rtp(0, k, u32::from(k) * 160, k == 0, &payload), to[i])
                        .unwrap();
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        })
    };
    let t = talk(60, loud.clone());
    std::thread::sleep(Duration::from_millis(300));
    let (l1, n1) = heard(&parties[1], 400);
    let (l0, n0) = heard(&parties[0], 400);
    t.join().unwrap();
    assert!(n1 > 5 && n0 > 5, "frames to everyone: {n0} {n1}");
    assert!(l1 > 3000, "party 1 hears party 0: {l1}");
    assert!(l0 < 100, "party 0 does not hear itself: {l0}");
    let speaker = api.wait_event("mixer.speaker", WAIT).unwrap().unwrap();
    assert_eq!(speaker["endpoint_id"], joined[0].0.as_str());
    assert_eq!(speaker["data"]["mixer_id"], mixer);

    // Muted: nobody hears it.
    api.call(
        "mixer.set",
        json!({"mixer_id": mixer, "endpoint_id": joined[0].0, "muted": true}),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(200));
    for p in &parties {
        drain(p);
    }
    let t = talk(30, loud);
    std::thread::sleep(Duration::from_millis(200));
    let (l2, _) = heard(&parties[2], 300);
    t.join().unwrap();
    assert!(l2 < 100, "muted: {l2}");

    // The mixer ends: no more frames.
    api.call("mixer.destroy", json!({"mixer_id": mixer}))
        .unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let _ = heard(&parties[1], 100);
    let (_, after) = heard(&parties[1], 300);
    assert_eq!(after, 0, "nothing after the mixer ends");
    drop(api);
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// An offer of G.722 only from `s`.
fn sdp_g722(s: &UdpSocket) -> String {
    format!(
        "v=0\r\no=- 9 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/AVP 9\r\na=rtpmap:9 G722/8000\r\na=sendrecv\r\n",
        port(s)
    )
}

/// A mixer of a G.722 participant and a PCMU one: each hears the other in
/// its own codec (the G.722 one wideband, in 160-octet G.722 payloads).
#[test]
fn a_mixer_mixes_wideband_and_narrowband() {
    let dir = temp_dir("mixer-wb");
    let (daemon, sock) = relay(&dir, 51_500, 1);
    let mut api = Client::connect(&sock).unwrap();
    let mixer = api.call("mixer.create", Value::Null).unwrap()["mixer_id"].clone();
    let (wide, narrow) = (endpoint(), endpoint());
    let mut to = Vec::new();
    for (s, offer) in [
        (&wide, sdp_g722(&wide)),
        (&narrow, sdp(&narrow, 1, "sendrecv")),
    ] {
        let ep = api
            .call(
                "endpoint.create",
                json!({"remote_sdp": offer, "options": opts()}),
            )
            .unwrap();
        api.call(
            "mixer.add",
            json!({"mixer_id": mixer, "endpoint_id": ep["endpoint_id"]}),
        )
        .unwrap();
        to.push(relay_addr(ep["sdp"].as_str().unwrap()));
        let _ = s;
    }
    // The G.722 participant talks: a loud 16 kHz tone, encoded.
    let mut enc = rtpflux_core::g722::Encoder::new();
    let talker = wide.try_clone().unwrap();
    let dst = to[0];
    let t = std::thread::spawn(move || {
        let mut payload = [0u8; 160];
        for k in 0u16..50 {
            let pcm: Vec<i16> = (0..320)
                .map(|i| {
                    let n = f64::from(u32::from(k) * 320 + i);
                    let x = (n * 2.0 * std::f64::consts::PI * 700.0 / 16000.0).sin();
                    #[allow(clippy::cast_possible_truncation)]
                    let v = (x * 12000.0) as i16;
                    v
                })
                .collect();
            let n = enc.encode(&pcm, &mut payload);
            talker
                .send_to(&rtp(9, k, u32::from(k) * 160, k == 0, &payload[..n]), dst)
                .unwrap();
            std::thread::sleep(Duration::from_millis(20));
        }
    });
    std::thread::sleep(Duration::from_millis(300));
    let (level, packets) = heard(&narrow, 400);
    t.join().unwrap();
    assert!(packets > 5, "frames to the PCMU participant");
    assert!(level > 2000, "it hears the G.722 one: {level}");
    // The G.722 participant gets G.722.
    drain(&wide);
    let mut buf = [0u8; 2048];
    wide.set_read_timeout(Some(WAIT)).unwrap();
    let (n, _) = wide.recv_from(&mut buf).unwrap();
    assert_eq!((n, buf[1] & 0x7f), (12 + 160, 9), "G.722 frames");
    drop(api);
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Over TCP: a connection authenticates first, with a tenant's token, and
/// then is that tenant's (naming another is refused); a bad token is
/// refused, and three close the connection.
#[test]
fn tcp_connections_authenticate() {
    use std::io::{Read, Write};
    let dir = temp_dir("tcp");
    let (daemon, _) = relay(&dir, 51_700, 1);
    let addr = daemon.native_addrs()[0];
    let refused = Client::connect_tcp(addr, "wrong-token-wrong").unwrap_err();
    assert_eq!(code(&refused), "unauthorized");
    // Unauthenticated: nothing but auth.
    let mut raw = std::net::TcpStream::connect(addr).unwrap();
    let hello = br#"{"v":1,"op":"hello"}"#;
    let mut msg = u32::try_from(hello.len()).unwrap().to_be_bytes().to_vec();
    msg.extend_from_slice(hello);
    raw.write_all(&msg).unwrap();
    let mut len = [0u8; 4];
    raw.read_exact(&mut len).unwrap();
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    raw.read_exact(&mut body).unwrap();
    assert!(String::from_utf8_lossy(&body).contains("unauthorized"));
    // Tenant b's connection.
    let mut b = Client::connect_tcp(addr, "token-of-tenant-b").unwrap();
    let ep = b
        .call("endpoint.create", json!({"codecs": ["PCMU"]}))
        .unwrap();
    let e = b
        .call("endpoint.list", json!({"tenant": "default"}))
        .unwrap_err();
    assert_eq!(code(&e), "unauthorized");
    // The default tenant does not see it.
    let mut d = Client::connect_tcp(addr, "token-of-default-0").unwrap();
    let e = d
        .call("endpoint.query", json!({"endpoint_id": ep["endpoint_id"]}))
        .unwrap_err();
    assert_eq!(code(&e), "unauthorized");
    assert_eq!(
        b.call("endpoint.list", Value::Null).unwrap()["endpoints"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    drop((b, d));
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A failure inside a media worker reaches the client: a recording whose
/// file cannot be opened gives `recording.failed`.
#[test]
fn a_worker_failure_is_reported() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("fail");
    let rec = dir.join("rec");
    std::fs::create_dir_all(&rec).unwrap();
    let extra = format!("[recording]\ndir = \"{}\"", rec.display());
    let (daemon, sock) = relay_with(&dir, 52_500, 1, &extra);
    let mut api = Client::connect(&sock).unwrap();
    api.call("events.subscribe", json!({"types": ["recording.failed"]}))
        .unwrap();
    let caller = endpoint();
    let ep = api
        .call(
            "endpoint.create",
            json!({"remote_sdp": sdp(&caller, 1, "sendrecv"), "options": opts()}),
        )
        .unwrap();
    // Nothing can be written there any more.
    std::fs::set_permissions(&rec, std::fs::Permissions::from_mode(0o500)).unwrap();
    api.call("recording.start", json!({"endpoint_id": ep["endpoint_id"]}))
        .unwrap();
    let failed = api.wait_event("recording.failed", WAIT).unwrap();
    std::fs::set_permissions(&rec, std::fs::Permissions::from_mode(0o700)).unwrap();
    let failed = failed.expect("recording.failed");
    assert_eq!(failed["endpoint_id"], ep["endpoint_id"]);
    assert_eq!(failed["data"]["reason"], "recording");
    drop(api);
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// One party of `parties` talks (a loud tone) for `packets` × 20 ms, the
/// others send silence.
fn talk_from(
    parties: &[UdpSocket],
    to: &[SocketAddr],
    talker: usize,
    packets: u16,
    seq0: u16,
) -> std::thread::JoinHandle<()> {
    let socks: Vec<UdpSocket> = parties.iter().map(|p| p.try_clone().unwrap()).collect();
    let to = to.to_vec();
    std::thread::spawn(move || {
        let loud: Vec<u8> = (0..160)
            .map(|i| {
                let x = (f64::from(i) * 2.0 * std::f64::consts::PI * 400.0 / 8000.0).sin();
                #[allow(clippy::cast_possible_truncation)]
                let v = (x * 12000.0) as i16;
                rtpflux_core::g711::linear_to_ulaw(v)
            })
            .collect();
        for k in seq0..seq0 + packets {
            for (i, s) in socks.iter().enumerate() {
                let payload = if i == talker {
                    loud.clone()
                } else {
                    vec![0xff; 160]
                };
                s.send_to(&rtp(0, k, u32::from(k) * 160, false, &payload), to[i])
                    .unwrap();
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    })
}

/// What `who` hear while `talker` talks: their levels.
fn round(parties: &[UdpSocket], to: &[SocketAddr], talker: usize, seq0: u16) -> Vec<u64> {
    for p in parties {
        drain(p);
    }
    let t = talk_from(parties, to, talker, 30, seq0);
    std::thread::sleep(Duration::from_millis(200));
    for p in parties {
        drain(p);
    }
    let levels = parties.iter().map(|p| heard(p, 200).0).collect();
    t.join().unwrap();
    levels
}

/// A supervisor in a conference: listening (hears, unheard), whispering to
/// the agent (only the agent hears), then barging in (everyone hears).
#[test]
fn a_supervisor_listens_whispers_and_barges_in() {
    let dir = temp_dir("supervisor");
    let (daemon, sock) = relay(&dir, 52_700, 1);
    let mut api = Client::connect(&sock).unwrap();
    let mixer = api.call("mixer.create", Value::Null).unwrap()["mixer_id"].clone();
    // 0 the caller, 1 the agent, 2 the supervisor.
    let parties: Vec<UdpSocket> = (0..3).map(|_| endpoint()).collect();
    let (mut ids, mut to) = (Vec::new(), Vec::new());
    for (i, p) in parties.iter().enumerate() {
        let ep = api
            .call(
                "endpoint.create",
                json!({"remote_sdp": sdp(p, 1, "sendrecv"), "options": opts()}),
            )
            .unwrap();
        let mut add = json!({"mixer_id": mixer, "endpoint_id": ep["endpoint_id"]});
        if i == 2 {
            add["role"] = json!("listen");
        }
        api.call("mixer.add", add).unwrap();
        ids.push(ep["endpoint_id"].clone());
        to.push(relay_addr(ep["sdp"].as_str().unwrap()));
    }
    // Listening: the supervisor hears the caller; no one hears it.
    let l = round(&parties, &to, 0, 0);
    assert!(l[2] > 2000, "the supervisor hears the caller: {l:?}");
    let l = round(&parties, &to, 2, 100);
    assert!(l[0] < 100 && l[1] < 100, "no one hears a listener: {l:?}");
    // Whispering to the agent.
    let bad = api
        .call(
            "mixer.set",
            json!({"mixer_id": mixer, "endpoint_id": ids[2], "role": "whisper", "whisper_to": "ep-none"}),
        )
        .unwrap_err();
    assert_eq!(code(&bad), "not_found");
    api.call(
        "mixer.set",
        json!({"mixer_id": mixer, "endpoint_id": ids[2], "role": "whisper", "whisper_to": ids[1]}),
    )
    .unwrap();
    let l = round(&parties, &to, 2, 200);
    assert!(
        l[1] > 2000 && l[0] < 100,
        "only the agent hears a whisper: {l:?}"
    );
    // Barging in.
    api.call(
        "mixer.set",
        json!({"mixer_id": mixer, "endpoint_id": ids[2], "role": "participant"}),
    )
    .unwrap();
    let l = round(&parties, &to, 2, 300);
    assert!(
        l[0] > 2000 && l[1] > 2000,
        "everyone hears a barge-in: {l:?}"
    );
    drop(api);
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Churn: endpoints created, bridged, detached and destroyed (some twice)
/// over and over, across two workers; a retried create after its destroy
/// does not bring it back. Afterwards nothing is left: the relay takes as
/// many endpoints as at the start (no port or worker state leaked).
#[test]
fn churn_leaves_nothing_behind() {
    let dir = temp_dir("churn");
    let (daemon, sock) = relay(&dir, 52_900, 2);
    let mut api = Client::connect(&sock).unwrap();
    let (caller, answerer) = (endpoint(), endpoint());
    for i in 0..100u32 {
        let a = api
            .call(
                "endpoint.create",
                json!({"remote_sdp": sdp(&caller, i + 1, "sendrecv"), "options": opts(),
                       "idempotency_key": format!("a-{i}")}),
            )
            .unwrap();
        let b = api
            .call("endpoint.create", json!({"codecs": ["PCMU"]}))
            .unwrap();
        api.call(
            "endpoint.apply_answer",
            json!({"endpoint_id": b["endpoint_id"], "sdp": sdp(&answerer, 1, "sendrecv"), "options": opts()}),
        )
        .unwrap();
        api.call(
            "bridge.attach",
            json!({"endpoint_id": a["endpoint_id"], "peer_endpoint_id": b["endpoint_id"]}),
        )
        .unwrap();
        if i % 3 == 0 {
            api.call("bridge.detach", json!({"endpoint_id": b["endpoint_id"]}))
                .unwrap();
        }
        for ep in [&a, &b] {
            api.call(
                "endpoint.destroy",
                json!({"endpoint_id": ep["endpoint_id"]}),
            )
            .unwrap();
        }
        if i % 4 == 0 {
            let again = api
                .call("endpoint.destroy", json!({"endpoint_id": a["endpoint_id"]}))
                .unwrap();
            assert_eq!(again["already"], true);
            // A retry of its create: the earlier outcome, nothing made.
            let retry = api
                .call(
                    "endpoint.create",
                    json!({"remote_sdp": sdp(&caller, i + 1, "sendrecv"), "options": opts(),
                           "idempotency_key": format!("a-{i}")}),
                )
                .unwrap();
            assert_eq!(retry["endpoint_id"], a["endpoint_id"]);
            let gone = api
                .call("endpoint.query", json!({"endpoint_id": a["endpoint_id"]}))
                .unwrap_err();
            assert_eq!(code(&gone), "not_found");
        }
    }
    let list = api.call("endpoint.list", Value::Null).unwrap();
    assert!(list["endpoints"].as_array().unwrap().is_empty(), "{list}");
    // The ports are all back: as many endpoints as the relay takes (12
    // sessions; each endpoint one), every one of them made.
    std::thread::sleep(Duration::from_millis(200));
    for k in 0..12 {
        api.call(
            "endpoint.create",
            json!({"codecs": ["PCMU"], "tenant": format!("t{}", k / 6)}),
        )
        .unwrap_or_else(|e| panic!("endpoint {k} after the churn: {e}"));
    }
    drop(api);
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}
