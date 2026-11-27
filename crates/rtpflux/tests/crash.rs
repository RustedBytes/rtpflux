//! Keyed native operations across a crash (SIGKILL) of the relay, at each
//! boundary of the durable protocol: after the intent is written
//! (`after_pending`), after the operation ran (`after_apply`), after its
//! state was written (`after_state`), and after its outcome was recorded,
//! before the reply (`after_outcome`). After the restart, a retry with the
//! same key gives the first outcome or says it is unknown, and the client
//! reconciles by the endpoint's external id: in the end there is exactly
//! one endpoint, never two.
//!
//! Needs the `fault-injection` feature (the relay kills itself at the
//! point `RTPFLUX_FAULT` names): `cargo test -p rtpflux --features
//! fault-injection --test crash`.

#![cfg(feature = "fault-injection")]

use rtpflux_client::{Client, ClientError};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Relay(Child);

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rtpflux-crash-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The relay binary on `dir`'s state, state file and ledger, killing
/// itself at `fault` if given; and a client once it answers.
fn start(dir: &Path, min: u16, fault: Option<&str>) -> (Relay, Client) {
    let sock = dir.join("api.sock");
    let config = dir.join("rtpflux.toml");
    std::fs::write(
        &config,
        format!(
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
            state_file = "{}"
            ledger = "{}"
            ledger_retention = 3600
            [runtime]
            workers = 2
            "#,
            sock.display(),
            min + 63,
            dir.join("state.json").display(),
            dir.join("ledger.jsonl").display(),
        ),
    )
    .unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rtpflux"));
    cmd.arg("-c")
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(f) = fault {
        cmd.env("RTPFLUX_FAULT", f);
    }
    let relay = Relay(cmd.spawn().unwrap());
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(mut c) = Client::connect(&sock)
            && c.call("hello", Value::Null).is_ok()
        {
            return (relay, c);
        }
        assert!(Instant::now() < end, "the relay did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
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

fn code(e: &ClientError) -> &str {
    e.code().unwrap_or("none")
}

/// The keyed create of endpoint `x`.
fn create(c: &mut Client, key: &str, x: &str, first: u64) -> Result<Value, ClientError> {
    c.call(
        "endpoint.create",
        json!({"codecs": ["PCMU"], "external_id": x, "idempotency_key": key,
               "first_attempt_unix_ms": first}),
    )
}

#[test]
fn a_crash_at_each_boundary_leaves_one_endpoint_or_an_explicit_unknown() {
    for point in [
        "after_pending",
        "after_apply",
        "after_state",
        "after_outcome",
    ] {
        let dir = temp_dir(point);
        let first = now_ms();
        let (x, key) = (format!("call-{point}/a"), format!("k-{point}"));
        // The relay dies in the middle of it: the client loses the reply.
        {
            let (mut relay, mut c) = start(&dir, 61_100, Some(point));
            let e = create(&mut c, &key, &x, first).unwrap_err();
            assert!(matches!(e, ClientError::Io(_)), "{point}: {e}");
            let status = relay.0.wait().unwrap();
            assert!(!status.success(), "{point}: killed");
        }
        // Restarted: the same request again.
        let (_relay, mut c) = start(&dir, 61_100, None);
        let retry = create(&mut c, &key, &x, first);
        let op = c
            .call("operation.query", json!({"idempotency_key": key}))
            .unwrap();
        let lookup = c.call("endpoint.lookup", json!({"external_id": x}));
        if point == "after_outcome" {
            // The outcome was recorded: the first reply, nothing run again.
            let r = retry.unwrap();
            assert_eq!(op["status"], "applied", "{point}");
            assert_eq!(lookup.unwrap()["endpoint_id"], r["endpoint_id"], "{point}");
        } else {
            // The outcome was not recorded: unknown, said so, never run again.
            let e = retry.unwrap_err();
            assert_eq!(code(&e), "unknown_outcome", "{point}: {e}");
            assert_eq!(op["status"], "unknown", "{point}");
            // The state was written: the endpoint is there.
            if point == "after_state" {
                assert!(lookup.is_ok(), "{point}: the endpoint is restored");
            }
            // Nothing was created yet.
            if point == "after_pending" {
                assert_eq!(code(&lookup.unwrap_err()), "not_found", "{point}");
            }
        }
        // Reconciled by the external id: made (with a new key) only if it
        // is not there. Exactly one endpoint has it.
        if c.call("endpoint.lookup", json!({"external_id": x}))
            .is_err()
        {
            create(&mut c, &format!("{key}-again"), &x, now_ms()).unwrap();
        }
        let list = c.call("endpoint.list", Value::Null).unwrap();
        let with_x = list["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["external_id"] == x.as_str())
            .count();
        assert_eq!(with_x, 1, "{point}: {list}");
        drop(c);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// Without a crash: a retry gets the first outcome, across a clean restart
/// too; another intent under the same key is a conflict; a first attempt
/// older than the ledger keeps is refused; a destroyed external id needs
/// `replaces_generation`.
#[test]
fn keys_and_external_ids_are_durable() {
    let dir = temp_dir("durable");
    let first = now_ms();
    let (relay, mut c) = start(&dir, 61_300, None);
    let a = create(&mut c, "k1", "ext-1", first).unwrap();
    let again = create(&mut c, "k1", "ext-1", first).unwrap();
    assert_eq!(again["endpoint_id"], a["endpoint_id"]);
    let other = c
        .call(
            "endpoint.create",
            json!({"codecs": ["PCMA"], "external_id": "ext-1", "idempotency_key": "k1"}),
        )
        .unwrap_err();
    assert_eq!(code(&other), "conflict");
    let old = create(&mut c, "k-old", "ext-old", first - 2 * 3_600_000).unwrap_err();
    assert_eq!(code(&old), "expired");
    // Another key, the same external id: the live endpoint's.
    let dup = create(&mut c, "k2", "ext-1", first).unwrap_err();
    assert_eq!(code(&dup), "conflict");
    // Destroyed, then a clean restart.
    c.call(
        "endpoint.destroy",
        json!({"endpoint_id": a["endpoint_id"], "idempotency_key": "k-destroy"}),
    )
    .unwrap();
    drop((relay, c));
    let (_relay, mut c) = start(&dir, 61_300, None);
    let replay = create(&mut c, "k1", "ext-1", first).unwrap();
    assert_eq!(replay["endpoint_id"], a["endpoint_id"], "the first outcome");
    let gone = c
        .call("endpoint.lookup", json!({"external_id": "ext-1"}))
        .unwrap();
    assert_eq!(gone["state_of_id"], "destroyed");
    // A new endpoint under it: only named as replacing that generation.
    let refused = create(&mut c, "k3", "ext-1", now_ms()).unwrap_err();
    assert_eq!(code(&refused), "conflict");
    let b = c
        .call(
            "endpoint.create",
            json!({"codecs": ["PCMU"], "external_id": "ext-1", "idempotency_key": "k4",
                   "replaces_generation": a["generation"]}),
        )
        .unwrap();
    assert_ne!(b["endpoint_id"], a["endpoint_id"]);
    assert!(b["generation"].as_u64() > a["generation"].as_u64());
    let op = c
        .call("operation.query", json!({"idempotency_key": "k4"}))
        .unwrap();
    assert_eq!(op["status"], "applied");
    assert_eq!(op["resources"][0], b["endpoint_id"]);
    let hello = c.call("hello", Value::Null).unwrap();
    assert_eq!(hello["guarantees"]["idempotency"], "durable");
    drop(c);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A bridge across two workers whose second end fails (the first worker
/// took its end, detaching its endpoint's former peer): the attach fails,
/// every endpoint involved (the former peer too) is detached in the
/// records as on the media workers, and media flows neither way. No
/// half-bridge is left behind a reply, and no bridge is reported that the
/// media do not have.
#[test]
fn a_half_made_bridge_is_compensated() {
    use std::net::UdpSocket;
    let dir = temp_dir("half");
    let (_relay, mut c) = start(&dir, 61_500, Some("connect_half"));
    let party = || {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        s
    };
    let (ua_x, ua_y, ua_z) = (party(), party(), party());
    let offer = |s: &UdpSocket| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP 0\r\na=sendrecv\r\n",
            s.local_addr().unwrap().port()
        )
    };
    let opts = json!({"flags": ["trust-address"], "endpoint-learning": "off"});
    let a = c
        .call(
            "endpoint.create",
            json!({"remote_sdp": offer(&ua_x), "options": opts}),
        )
        .unwrap();
    let b = c
        .call(
            "endpoint.create",
            json!({"remote_sdp": offer(&ua_y), "options": opts}),
        )
        .unwrap();
    // Calls alternate between the two workers: a and z share one.
    let peer = c
        .call(
            "endpoint.create",
            json!({"remote_sdp": offer(&ua_z), "options": opts}),
        )
        .unwrap();
    c.call(
        "bridge.attach",
        json!({"endpoint_id": a["endpoint_id"], "peer_endpoint_id": peer["endpoint_id"]}),
    )
    .unwrap();
    let e = c
        .call(
            "bridge.attach",
            json!({"endpoint_id": a["endpoint_id"], "peer_endpoint_id": b["endpoint_id"]}),
        )
        .unwrap_err();
    assert_eq!(code(&e), "exhausted", "{e}");
    for ep in [&a, &b, &peer] {
        let snap = c
            .call("endpoint.query", json!({"endpoint_id": ep["endpoint_id"]}))
            .unwrap();
        assert_eq!(snap["bridged_to"], Value::Null, "{snap}");
    }
    let port = |sdp: &Value| {
        sdp.as_str()
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("m=audio "))
            .and_then(|l| l.split(' ').next())
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap()
    };
    let rtp = [0x80u8, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7, 0xff, 0xff];
    let mut buf = [0u8; 64];
    ua_x.send_to(&rtp, ("127.0.0.1", port(&a["sdp"]))).unwrap();
    assert!(ua_y.recv_from(&mut buf).is_err(), "nothing x → y");
    ua_y.send_to(&rtp, ("127.0.0.1", port(&b["sdp"]))).unwrap();
    assert!(ua_x.recv_from(&mut buf).is_err(), "nothing y → x");
    ua_z.send_to(&rtp, ("127.0.0.1", port(&peer["sdp"])))
        .unwrap();
    assert!(
        ua_x.recv_from(&mut buf).is_err(),
        "nothing from the former peer"
    );
    drop(c);
    std::fs::remove_dir_all(&dir).unwrap();
}
