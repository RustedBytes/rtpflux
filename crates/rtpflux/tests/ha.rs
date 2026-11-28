//! Exclusive controller ownership (`[ha]`) end to end: grants signed by an
//! ownership authority, fencing of every native mutation by epoch and
//! lease, a stale controller after a handoff, a restart, an expired lease,
//! a replayed grant, another tenant, a bridge across calls, and `ng`
//! kept off the calls the native API owns.

#[path = "support/logging.rs"]
mod logging;

use rtpflux::config::Config;
use rtpflux::control::ownership::{sign, signed_text, token_text};
use rtpflux::daemon::Daemon;
use rtpflux_client::{Client, ClientError};
use serde_json::{Value, json};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::time::Duration;

const KEY: &str = "authority-key-0123456789abcdef-k1";

fn temp_dir(name: &str) -> PathBuf {
    logging::init();
    let d = std::env::temp_dir().join(format!("rtpflux-ha-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn relay(dir: &Path, min: u16) -> (Daemon, PathBuf) {
    relay_with(dir, min, "")
}

/// A relay with `extra` configuration at the end.
fn relay_with(dir: &Path, min: u16, extra: &str) -> (Daemon, PathBuf) {
    let sock = dir.join("api.sock");
    let config = Config::from_toml(&format!(
        r#"
        [control]
        listen = ["127.0.0.1:0"]
        native_socket = "{sock}"
        native_listen = ["127.0.0.1:0"]
        native_tokens = {{ default = "token-of-default-0", b = "token-of-tenant-b" }}
        [[interface]]
        name = "lo"
        address = "127.0.0.1"
        [ports]
        min = {min}
        max = {max}
        [sessions]
        max = 12
        state_file = "{state}"
        ledger = "{ledger}"
        [ha]
        enabled = true
        state = "{ha}"
        authority_keys = {{ k1 = "{KEY}" }}
        [runtime]
        workers = 2
        {extra}
        "#,
        sock = sock.display(),
        max = min + 63,
        state = dir.join("state.json").display(),
        ledger = dir.join("ledger.jsonl").display(),
        ha = dir.join("ownership.json").display(),
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

/// The authority's grant of `group` to `owner` at `epoch`, for `tenant`.
fn grant(tenant: &str, group: &str, epoch: u64, owner: &str, lease_ms: u64) -> Value {
    let sig = sign(
        KEY.as_bytes(),
        &signed_text(tenant, group, epoch, owner, lease_ms),
    );
    json!({"group": group, "epoch": epoch, "owner": owner,
        "lease_expires_unix_ms": lease_ms, "key_id": "k1", "signature": sig})
}

fn code(r: Result<Value, ClientError>) -> String {
    match r {
        Err(ClientError::Refused { code, .. }) => code,
        other => panic!("not refused: {other:?}"),
    }
}

/// The proof that `owner` acts on `group` at `epoch` (its token from the
/// authority), for tenant `default`.
fn proof(group: &str, epoch: u64, owner: &str) -> Value {
    let token = sign(KEY.as_bytes(), &token_text("default", group, epoch, owner));
    json!({"group": group, "epoch": epoch, "token": token})
}

fn with(mut v: Value, group: &str, epoch: u64, owner: &str) -> Value {
    v["ownership"] = proof(group, epoch, owner);
    v
}

fn offer() -> Value {
    json!({"codecs": ["PCMU"]})
}

#[test]
#[allow(
    clippy::too_many_lines,
    clippy::many_single_char_names,
    reason = "one story: controllers a and b, handoff, restart"
)]
fn fencing_by_authority_epochs() {
    let dir = temp_dir("fencing");
    let (daemon, sock) = relay(&dir, 63_500);
    let mut a = Client::connect(&sock).unwrap();
    let hello = a.call("hello", Value::Null).unwrap();
    assert_eq!(hello["guarantees"]["fencing"], "authority_epochs");
    let lease = now_ms() + 60_000;

    // Nothing changes without a claim (fail closed).
    assert_eq!(code(a.call("endpoint.create", offer())), "fenced");
    assert_eq!(
        code(a.call("endpoint.create", with(offer(), "call-1", 1, "ctl-a"))),
        "fenced"
    );
    // A grant the authority did not sign is refused.
    let mut forged = grant("default", "call-1", 1, "ctl-a", lease);
    forged["signature"] = json!("00".repeat(32));
    assert_eq!(code(a.call("ownership.claim", forged)), "unauthorized");

    // Controller A owns call-1 at epoch 1.
    let r = a
        .call(
            "ownership.claim",
            grant("default", "call-1", 1, "ctl-a", lease),
        )
        .unwrap();
    assert_eq!(r["epoch"], 1);
    assert_eq!(r["previous_epoch"], Value::Null);
    let e1 = a
        .call("endpoint.create", with(offer(), "call-1", 1, "ctl-a"))
        .unwrap();
    let e1 = e1["endpoint_id"].as_str().unwrap().to_owned();
    // Another group's proof does not cover call-1's endpoint.
    a.call(
        "ownership.claim",
        grant("default", "call-2", 5, "ctl-a", lease),
    )
    .unwrap();
    let renew = json!({"endpoint_id": e1, "lease_ms": 30_000});
    assert_eq!(
        code(a.call("endpoint.renew", with(renew.clone(), "call-2", 5, "ctl-a"))),
        "fenced"
    );
    a.call("endpoint.renew", with(renew.clone(), "call-1", 1, "ctl-a"))
        .unwrap();

    // The authority hands call-1 to controller B (epoch 2): A is stale,
    // even with the right generation and revision.
    let mut b = Client::connect(&sock).unwrap();
    let r = b
        .call(
            "ownership.claim",
            grant("default", "call-1", 2, "ctl-b", lease),
        )
        .unwrap();
    assert_eq!(r["previous_epoch"], 1);
    assert_eq!(r["drained"], true);
    let mut stale = with(renew.clone(), "call-1", 1, "ctl-a");
    stale["expected_generation"] = json!(1);
    assert_eq!(code(a.call("endpoint.renew", stale)), "fenced");
    // Guessing the new epoch is not enough: A has no token for it.
    assert_eq!(
        code(a.call("endpoint.renew", with(renew.clone(), "call-1", 2, "ctl-a"))),
        "fenced"
    );
    // A cannot promote itself back: an old grant, or the same epoch.
    assert_eq!(
        code(a.call(
            "ownership.claim",
            grant("default", "call-1", 1, "ctl-a", lease)
        )),
        "fenced"
    );
    assert_eq!(
        code(a.call(
            "ownership.claim",
            grant("default", "call-1", 2, "ctl-a", lease)
        )),
        "conflict"
    );
    b.call("endpoint.renew", with(renew.clone(), "call-1", 2, "ctl-b"))
        .unwrap();

    // A bridge across calls needs both groups' current epochs.
    let e2 = b.call("endpoint.create", with(offer(), "call-2", 5, "ctl-b"));
    assert_eq!(code(e2), "fenced", "call-2 is A's: B has no token for it");
    let e2 = a
        .call("endpoint.create", with(offer(), "call-2", 5, "ctl-a"))
        .unwrap();
    let e2 = e2["endpoint_id"].as_str().unwrap().to_owned();
    // (Both answered, so they can be bridged.)
    for (c, id, g, ep, owner) in [
        (&mut b, &e1, "call-1", 2, "ctl-b"),
        (&mut a, &e2, "call-2", 5, "ctl-a"),
    ] {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = peer.local_addr().unwrap().port();
        let sdp = format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
        );
        c.call(
            "endpoint.apply_answer",
            with(json!({"endpoint_id": id, "sdp": sdp}), g, ep, owner),
        )
        .unwrap();
    }
    let attach = json!({"endpoint_id": e1, "peer_endpoint_id": e2});
    assert_eq!(
        code(b.call("bridge.attach", with(attach.clone(), "call-1", 2, "ctl-b"))),
        "fenced"
    );
    let mut both = with(attach.clone(), "call-1", 2, "ctl-b");
    both["peer_ownership"] = proof("call-2", 4, "ctl-b");
    assert_eq!(
        code(b.call("bridge.attach", both.clone())),
        "fenced",
        "a stale peer epoch"
    );
    // B gets call-2 too, then bridges.
    b.call(
        "ownership.claim",
        grant("default", "call-2", 6, "ctl-b", lease),
    )
    .unwrap();
    both["peer_ownership"] = proof("call-2", 6, "ctl-b");
    b.call("bridge.attach", both).unwrap();

    // Another tenant cannot use this tenant's grant, nor touch its calls.
    let mut t = Client::connect_tcp(daemon.native_addrs()[0], "token-of-tenant-b").unwrap();
    assert_eq!(
        code(t.call(
            "ownership.claim",
            grant("default", "call-1", 3, "ctl-x", lease)
        )),
        "unauthorized"
    );
    t.call("ownership.claim", grant("b", "call-1", 1, "ctl-x", lease))
        .unwrap();
    let theirs = with(
        json!({"endpoint_id": e1, "lease_ms": 30_000}),
        "call-1",
        1,
        "ctl-a",
    );
    assert_ne!(
        t.call("endpoint.renew", theirs)
            .map(|_| ())
            .map_err(|e| format!("{e}")),
        Ok(())
    );

    // ng cannot change a call the native API owns (it can still read).
    let session = b
        .call("endpoint.query", json!({"endpoint_id": e1}))
        .unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let ng = UdpSocket::bind("127.0.0.1:0").unwrap();
    ng.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut buf = [0u8; 1024];
    for (cookie, cmd) in [("c1", "delete"), ("c2", "query")] {
        let msg = format!(
            "{cookie} d7:call-id{}:{session}7:command{}:{cmd}e",
            session.len(),
            cmd.len()
        );
        ng.send_to(msg.as_bytes(), daemon.control_addrs()[0])
            .unwrap();
        let n = ng.recv(&mut buf).unwrap();
        let text = String::from_utf8_lossy(&buf[..n]).into_owned();
        if cmd == "delete" {
            assert!(
                text.contains("error") && text.contains("native API"),
                "{text}"
            );
        } else {
            assert!(text.contains("6:result2:ok"), "{text}");
        }
    }
    assert!(
        b.call("endpoint.query", json!({"endpoint_id": e1})).is_ok(),
        "still there"
    );
    drop((a, b, t));
    daemon.stop();

    // Restarted: the epochs are as they were; the stale controller is
    // still refused, the current one goes on.
    let (daemon, sock) = relay(&dir, 63_500);
    let mut a = Client::connect(&sock).unwrap();
    assert_eq!(
        code(a.call(
            "ownership.claim",
            grant("default", "call-1", 1, "ctl-a", lease)
        )),
        "fenced"
    );
    assert_eq!(
        code(a.call("endpoint.renew", with(renew.clone(), "call-1", 1, "ctl-a"))),
        "fenced"
    );
    let mut b = Client::connect(&sock).unwrap();
    b.call("endpoint.renew", with(renew.clone(), "call-1", 2, "ctl-b"))
        .unwrap();

    // A lease that ran out: fail closed until the authority renews it.
    // Room for a loaded machine before it ends; then past its end.
    let short = now_ms() + 4_000;
    b.call(
        "ownership.claim",
        grant("default", "call-3", 1, "ctl-b", short),
    )
    .unwrap();
    let e3 = b
        .call("endpoint.create", with(offer(), "call-3", 1, "ctl-b"))
        .unwrap();
    std::thread::sleep(Duration::from_millis(
        (short + 100).saturating_sub(now_ms()),
    ));
    let destroy = with(
        json!({"endpoint_id": e3["endpoint_id"]}),
        "call-3",
        1,
        "ctl-b",
    );
    assert_eq!(code(b.call("endpoint.destroy", destroy.clone())), "fenced");
    // The same epoch, a later lease: a renewal.
    b.call(
        "ownership.claim",
        grant("default", "call-3", 1, "ctl-b", now_ms() + 60_000),
    )
    .unwrap();
    b.call("endpoint.destroy", destroy).unwrap();
    // A grant whose lease is over cannot be replayed.
    assert_eq!(
        code(b.call(
            "ownership.claim",
            grant("default", "call-9", 1, "ctl-b", short)
        )),
        "fenced"
    );

    drop((a, b));
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A mixer's recording is a change of the mixer: it needs the mixer's
/// group's current epoch, like every mixer operation.
#[test]
fn mixer_recordings_are_fenced() {
    let dir = temp_dir("mixrec");
    std::fs::create_dir_all(dir.join("rec")).unwrap();
    let (daemon, sock) = relay_with(
        &dir,
        63_600,
        &format!("[recording]\ndir = \"{}\"", dir.join("rec").display()),
    );
    let mut a = Client::connect(&sock).unwrap();
    let lease = now_ms() + 60_000;
    for (group, epoch) in [("conf-1", 1), ("conf-2", 1)] {
        a.call(
            "ownership.claim",
            grant("default", group, epoch, "ctl-a", lease),
        )
        .unwrap();
    }
    let mixer = a
        .call("mixer.create", with(json!({}), "conf-1", 1, "ctl-a"))
        .unwrap()["mixer_id"]
        .clone();
    let start = json!({"mixer_id": mixer});
    assert_eq!(code(a.call("recording.start", start.clone())), "fenced");
    assert_eq!(
        code(a.call("recording.start", with(start.clone(), "conf-2", 1, "ctl-a"))),
        "fenced",
        "another group's proof"
    );
    let rec = a
        .call("recording.start", with(start.clone(), "conf-1", 1, "ctl-a"))
        .unwrap();
    assert_eq!(rec["recording"], true);

    // Handed to controller b: a is stale for the recording too.
    let mut b = Client::connect(&sock).unwrap();
    b.call(
        "ownership.claim",
        grant("default", "conf-1", 2, "ctl-b", lease),
    )
    .unwrap();
    let stop = json!({"mixer_id": mixer});
    for op in ["recording.pause", "recording.stop"] {
        assert_eq!(
            code(a.call(op, with(stop.clone(), "conf-1", 1, "ctl-a"))),
            "fenced",
            "{op} with a stale epoch"
        );
    }
    let done = b
        .call("recording.stop", with(stop, "conf-1", 2, "ctl-b"))
        .unwrap();
    assert_eq!(done["recording_id"], rec["recording_id"]);
    drop((a, b));
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}
