//! The native API's access controls end to end:
//! - tokens rotated through their file, a revoked token's connection
//!   refused;
//! - per-tenant rate limits;
//! - remote listening refused unless allowed;
//! - `ng` kept off native calls.

#[path = "support/logging.rs"]
mod logging;

use rtpflux::config::Config;
use rtpflux::daemon::Daemon;
use rtpflux_client::Client;
use serde_json::{Value, json};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn temp_dir(name: &str) -> PathBuf {
    logging::init();
    let d = std::env::temp_dir().join(format!("rtpflux-security-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn relay(dir: &Path, extra: &str) -> (Daemon, PathBuf) {
    let sock = dir.join("api.sock");
    let config = Config::from_toml(&format!(
        r#"
        [control]
        listen = ["127.0.0.1:0"]
        native_socket = "{}"
        native_listen = ["127.0.0.1:0"]
        native_tokens_file = "{}"
        {extra}
        [[interface]]
        name = "lo"
        address = "127.0.0.1"
        [ports]
        min = 62900
        max = 62963
        [sessions]
        max = 12
        [runtime]
        workers = 1
        "#,
        sock.display(),
        dir.join("tokens").display(),
    ))
    .unwrap();
    (Daemon::start(&config).unwrap(), sock)
}

fn code(r: Result<Value, rtpflux_client::ClientError>) -> String {
    match r {
        Err(e) => e.code().unwrap_or("io").to_owned(),
        Ok(v) => panic!("not refused: {v}"),
    }
}

#[test]
fn tokens_rate_limits_remote_listening_and_ng() {
    let dir = temp_dir("all");
    std::fs::write(
        dir.join("tokens"),
        "a old-token-of-a-0001\nb token-of-tenant-b-01\n",
    )
    .unwrap();
    let (daemon, sock) = relay(&dir, "native_rate_limit = 20\nng_protect_native = true");
    let addr = daemon.native_addrs()[0];

    // A connection with the old token works; the token is rotated (the new
    // one added, then the old one removed); the connection is refused at
    // its next request, and closed.
    let mut old = Client::connect_tcp(addr, "old-token-of-a-0001").unwrap();
    assert!(old.call("hello", Value::Null).is_ok());
    std::fs::write(
        dir.join("tokens"),
        "a old-token-of-a-0001\na new-token-of-a-0002\nb token-of-tenant-b-01\n",
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    let mut new = Client::connect_tcp(addr, "new-token-of-a-0002").unwrap();
    assert!(new.call("hello", Value::Null).is_ok());
    assert!(
        old.call("hello", Value::Null).is_ok(),
        "both, while they overlap"
    );
    std::fs::write(
        dir.join("tokens"),
        "a new-token-of-a-0002\nb token-of-tenant-b-01\n",
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    assert_eq!(code(old.call("hello", Value::Null)), "unauthorized");
    assert!(old.call("hello", Value::Null).is_err(), "closed");
    assert!(Client::connect_tcp(addr, "old-token-of-a-0001").is_err());
    assert!(new.call("hello", Value::Null).is_ok());

    // 20 requests a second per tenant: a burst beyond is refused; another
    // tenant is not affected; a second later it goes again.
    std::thread::sleep(Duration::from_millis(1100));
    let refused = (0..40)
        .map(|_| new.call("hello", Value::Null))
        .filter(|r| r.as_ref().is_err_and(|e| e.code() == Some("exhausted")))
        .count();
    assert!(refused >= 15, "over the rate: {refused} refused");
    let mut b = Client::connect_tcp(addr, "token-of-tenant-b-01").unwrap();
    assert!(
        b.call("hello", Value::Null).is_ok(),
        "tenant b has its own rate"
    );
    std::thread::sleep(Duration::from_millis(1100));
    assert!(new.call("hello", Value::Null).is_ok());

    // ng cannot change a call the native API holds; it can read it.
    let mut api = Client::connect(&sock).unwrap();
    let caller = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = caller.local_addr().unwrap().port();
    let sdp = format!(
        "v=0\r\no=- 7 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"
    );
    let ep = api
        .call("endpoint.create", json!({"remote_sdp": sdp}))
        .unwrap();
    let session = ep["session_id"].as_str().unwrap();
    let ng = UdpSocket::bind("127.0.0.1:0").unwrap();
    ng.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut buf = [0u8; 1024];
    for (cookie, cmd, refused) in [("c1", "delete", true), ("c2", "query", false)] {
        let msg = format!(
            "{cookie} d7:call-id{}:{session}7:command{}:{cmd}e",
            session.len(),
            cmd.len()
        );
        ng.send_to(msg.as_bytes(), daemon.control_addrs()[0])
            .unwrap();
        let n = ng.recv(&mut buf).unwrap();
        let text = String::from_utf8_lossy(&buf[..n]).into_owned();
        assert_eq!(text.contains("native API"), refused, "{cmd}: {text}");
    }
    assert!(
        api.call("endpoint.query", json!({"endpoint_id": ep["endpoint_id"]}))
            .is_ok()
    );
    drop((old, new, b, api));
    daemon.stop();

    // Listening on the network needs an explicit choice.
    let remote = |allow: bool| {
        Config::from_toml(&format!(
            r#"
            [control]
            listen = ["127.0.0.1:0"]
            native_listen = ["0.0.0.0:0"]
            native_tokens = {{ a = "a-token-of-16-chars" }}
            native_allow_remote = {allow}
            [[interface]]
            name = "lo"
            address = "127.0.0.1"
            "#
        ))
    };
    let refused = remote(false).unwrap_err().to_string();
    assert!(refused.contains("TLS proxy"), "{refused}");
    assert!(remote(true).is_ok());
    std::fs::remove_dir_all(&dir).unwrap();
}
