//! `endpoint.echo` end to end: an endpoint gets its own RTP back, as it
//! sent it; the echo survives a renegotiation and a restart of the relay;
//! it stops; and it never combines with a bridge.

#[path = "support/logging.rs"]
mod logging;

use rtpflux::config::Config;
use rtpflux::daemon::Daemon;
use rtpflux_client::Client;
use serde_json::{Value, json};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn temp_dir(name: &str) -> PathBuf {
    logging::init();
    let d = std::env::temp_dir().join(format!("rtpflux-echo-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn relay(dir: &Path) -> (Daemon, PathBuf) {
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
        min = 63000
        max = 63063
        [sessions]
        max = 12
        state_file = "{}"
        [runtime]
        workers = 1
        "#,
        sock.display(),
        dir.join("state.json").display(),
    ))
    .unwrap();
    (Daemon::start(&config).unwrap(), sock)
}

fn sdp(s: &UdpSocket, version: u32) -> String {
    let port = s.local_addr().unwrap().port();
    format!(
        "v=0\r\no=- 7 {version} IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"
    )
}

fn opts() -> Value {
    json!({"flags": ["trust-address"], "endpoint-learning": "off"})
}

fn relay_addr(sdp: &str) -> SocketAddr {
    let port: u16 = sdp
        .lines()
        .find_map(|l| l.strip_prefix("m=audio "))
        .and_then(|l| l.split(' ').next())
        .unwrap()
        .parse()
        .unwrap();
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn rtp(seq: u16) -> Vec<u8> {
    let mut p = vec![0x80, 0];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
    p.extend_from_slice(&0x0bad_cafe_u32.to_be_bytes());
    p.extend((0..160u8).map(|i| i ^ 0x55));
    p
}

/// Whether `s`, sending to `to`, gets its packets back unchanged.
fn echoed(s: &UdpSocket, to: SocketAddr, seq: &mut u16) -> bool {
    s.set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    let mut buf = [0u8; 2048];
    while s.recv(&mut buf).is_ok() {}
    for _ in 0..10 {
        *seq += 1;
        let sent = rtp(*seq);
        s.send_to(&sent, to).unwrap();
        if let Ok((n, from)) = s.recv_from(&mut buf) {
            assert_eq!(from, to, "from the relay's port");
            assert_eq!(&buf[..n], &sent[..], "as it was sent");
            return true;
        }
    }
    false
}

#[test]
fn an_endpoint_hears_itself() {
    let dir = temp_dir("all");
    let (daemon, sock) = relay(&dir);
    let mut api = Client::connect(&sock).unwrap();
    let caller = UdpSocket::bind("127.0.0.1:0").unwrap();
    let ep = api
        .call(
            "endpoint.create",
            json!({"remote_sdp": sdp(&caller, 1), "options": opts()}),
        )
        .unwrap();
    let id = ep["endpoint_id"].as_str().unwrap().to_owned();
    let to = relay_addr(ep["sdp"].as_str().unwrap());
    let mut seq = 0;
    assert!(!echoed(&caller, to, &mut seq), "parked: nothing comes back");

    let on = api
        .call("endpoint.echo", json!({"endpoint_id": id, "echo": true}))
        .unwrap();
    assert_eq!(
        (on["echo"].as_bool(), on["changed"].as_bool()),
        (Some(true), Some(true))
    );
    assert!(echoed(&caller, to, &mut seq));
    let q = api
        .call("endpoint.query", json!({"endpoint_id": id}))
        .unwrap();
    assert_eq!(q["echo"], true);
    let again = api
        .call("endpoint.echo", json!({"endpoint_id": id, "echo": true}))
        .unwrap();
    assert_eq!(again["changed"], false);

    // Never with a bridge.
    let other = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer = api
        .call(
            "endpoint.create",
            json!({"remote_sdp": sdp(&other, 1), "options": opts()}),
        )
        .unwrap();
    let e = api
        .call(
            "bridge.attach",
            json!({"endpoint_id": id, "peer_endpoint_id": peer["endpoint_id"]}),
        )
        .unwrap_err();
    assert_eq!(e.code(), Some("conflict"));
    let e = api
        .call("endpoint.echo", json!({"endpoint_id": id, "echo": "yes"}))
        .unwrap_err();
    assert_eq!(e.code(), Some("invalid"));

    // A re-INVITE: still echoing.
    api.call(
        "endpoint.prepare",
        json!({"endpoint_id": id, "remote_sdp": sdp(&caller, 2), "options": opts()}),
    )
    .unwrap();
    api.call("endpoint.commit", json!({"endpoint_id": id, "revision": 2}))
        .unwrap();
    assert!(echoed(&caller, to, &mut seq), "after the renegotiation");

    // A restart: still echoing.
    drop(api);
    daemon.stop();
    let (daemon, sock) = relay(&dir);
    let mut api = Client::connect(&sock).unwrap();
    assert!(echoed(&caller, to, &mut seq), "after the restart");
    assert_eq!(
        api.call("endpoint.query", json!({"endpoint_id": id}))
            .unwrap()["echo"],
        true
    );

    // Off: parked again; then it can be bridged.
    let off = api
        .call("endpoint.echo", json!({"endpoint_id": id, "echo": false}))
        .unwrap();
    assert_eq!(off["changed"], true);
    assert!(!echoed(&caller, to, &mut seq), "stopped");
    api.call(
        "bridge.attach",
        json!({"endpoint_id": id, "peer_endpoint_id": peer["endpoint_id"]}),
    )
    .unwrap();
    let e = api
        .call("endpoint.echo", json!({"endpoint_id": id, "echo": true}))
        .unwrap_err();
    assert_eq!(e.code(), Some("conflict"), "bridged");
    drop(api);
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}
