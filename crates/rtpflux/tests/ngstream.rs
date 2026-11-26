//! `ng` over TCP, HTTP and WebSocket through the daemon.

#[path = "support/logging.rs"]
mod logging;

use rtpflux::config::Config;
use rtpflux::daemon::Daemon;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

fn daemon(first_port: u16) -> Daemon {
    logging::init();
    let config = Config::from_toml(&format!(
        r#"
        [control]
        listen = ["127.0.0.1:0"]
        listen_tcp = ["127.0.0.1:0"]
        listen_http = ["127.0.0.1:0"]
        [[interface]]
        name = "lo"
        address = "127.0.0.1"
        [ports]
        min = {first_port}
        max = {}
        [sessions]
        max = 8
        [runtime]
        workers = 1
        "#,
        first_port + 63
    ))
    .unwrap();
    Daemon::start(&config).unwrap()
}

fn connect(at: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(at).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

/// Read until `n` bytes arrived.
fn read_n(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    s.read_exact(&mut out).unwrap();
    out
}

#[test]
fn ng_over_tcp() {
    let d = daemon(53_400);
    let mut s = connect(d.stream_addrs()[0]);
    // Two messages in one write.
    s.write_all(b"a1 d7:command4:pingea2 d7:command4:pinge")
        .unwrap();
    let r = read_n(&mut s, 2 * b"a1 d6:result4:ponge".len());
    assert_eq!(r, b"a1 d6:result4:pongea2 d6:result4:ponge");
    // One message in pieces.
    s.write_all(b"b1 d7:comm").unwrap();
    std::thread::sleep(Duration::from_millis(100));
    s.write_all(b"and4:pinge").unwrap();
    assert_eq!(
        read_n(&mut s, b"b1 d6:result4:ponge".len()),
        b"b1 d6:result4:ponge"
    );
    // An offer over TCP.
    let sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n";
    let offer = format!(
        "c1 d7:call-id3:tcp7:command5:offer8:from-tag1:f3:sdp{}:{sdp}e",
        sdp.len()
    );
    s.write_all(offer.as_bytes()).unwrap();
    let mut buf = [0u8; 4096];
    let n = s.read(&mut buf).unwrap();
    let reply = String::from_utf8_lossy(&buf[..n]);
    assert!(
        reply.starts_with("c1 d") && reply.contains("6:result2:ok"),
        "{reply}"
    );
    // Not ng: the connection is closed.
    s.write_all(b"junk {}").unwrap();
    assert_eq!(s.read(&mut buf).unwrap_or(0), 0);
    d.stop();
}

/// One HTTP request; the status line and body.
fn http(at: SocketAddr, request: &str) -> (String, String) {
    let mut s = connect(at);
    s.write_all(request.as_bytes()).unwrap();
    let mut all = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = s.read(&mut buf).unwrap();
        all.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&all).into_owned();
        if let Some(i) = text.find("\r\n\r\n") {
            let len: usize = text
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .unwrap()
                .parse()
                .unwrap();
            if all.len() >= i + 4 + len {
                let status = text.lines().next().unwrap().to_owned();
                return (status, text[i + 4..i + 4 + len].to_owned());
            }
        }
        assert!(n > 0, "closed early");
    }
}

fn post(path: &str, ct: &str, body: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[test]
fn ng_over_http() {
    let d = daemon(53_500);
    let at = d.stream_addrs()[1];
    let ng = "application/x-rtpengine-ng";
    assert_eq!(
        http(at, &post("/ng", ng, "5323_1 d7:command4:pinge")),
        (
            "HTTP/1.1 200 OK".to_owned(),
            "5323_1 d6:result4:ponge".to_owned()
        )
    );
    // JSON in, JSON out.
    assert_eq!(
        http(at, &post("/ng", ng, r#"j1 {"command":"ping"}"#)).1,
        r#"j1 {"result":"pong"}"#
    );
    assert_eq!(
        http(
            at,
            &post("/ng-plain", "application/json", r#"{"command":"ping"}"#)
        )
        .1,
        r#"{"result":"pong"}"#
    );
    assert_eq!(
        http(at, &post("/ng-plain", ng, "d7:command4:pinge")).1,
        "d6:result4:ponge"
    );
    assert_eq!(http(at, "GET /ping HTTP/1.1\r\nHost: x\r\n\r\n").1, "pong");
    assert!(
        http(at, &post("/ng", "text/plain", "x d7:command4:pinge"))
            .0
            .contains("404")
    );
    // An offer as JSON: the SDP comes back as a string.
    let offer = serde_json::json!({
        "command": "offer", "call-id": "json-call", "from-tag": "f",
        "sdp": "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n",
        "flags": ["trust-address"]
    });
    let reply = http(
        at,
        &post("/ng-plain", "application/json", &offer.to_string()),
    )
    .1;
    let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(v["result"], "ok");
    assert!(v["sdp"].as_str().unwrap().contains("m=audio "));
    d.stop();
}

/// A masked client frame.
fn frame(op: u8, payload: &[u8]) -> Vec<u8> {
    let mask = [1u8, 2, 3, 4];
    let mut f = vec![0x80 | op];
    if payload.len() < 126 {
        f.push(0x80 | u8::try_from(payload.len()).unwrap());
    } else {
        f.push(0x80 | 0x7e);
        f.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    }
    f.extend_from_slice(&mask);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    f
}

/// A server frame: opcode and payload.
fn read_frame(s: &mut TcpStream) -> (u8, Vec<u8>) {
    let h = read_n(s, 2);
    let len = match h[1] & 0x7f {
        126 => usize::from(u16::from_be_bytes(read_n(s, 2).try_into().unwrap())),
        n => usize::from(n),
    };
    (h[0] & 0x0f, read_n(s, len))
}

fn ws(at: SocketAddr, protocol: &str) -> (TcpStream, String) {
    let mut s = connect(at);
    write!(
        s,
        "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Protocol: {protocol}\r\n\r\n"
    )
    .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.extend(read_n(&mut s, 1));
    }
    (s, String::from_utf8(head).unwrap())
}

#[test]
fn ng_over_websocket() {
    let d = daemon(53_600);
    let at = d.stream_addrs()[1];
    let (mut s, head) = ws(at, "chat, ng.rtpengine.com");
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert!(
        head.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
        "{head}"
    );
    assert!(
        head.contains("Sec-WebSocket-Protocol: ng.rtpengine.com"),
        "{head}"
    );
    s.write_all(&frame(1, b"w1 d7:command4:pinge")).unwrap();
    assert_eq!(read_frame(&mut s), (2, b"w1 d6:result4:ponge".to_vec()));
    // A ping frame is answered with a pong.
    s.write_all(&frame(9, b"hi")).unwrap();
    assert_eq!(read_frame(&mut s), (10, b"hi".to_vec()));
    s.write_all(&frame(8, &[3, 232])).unwrap();
    assert_eq!(read_frame(&mut s).0, 8);

    let (mut s, head) = ws(at, "ng-plain.rtpengine.com");
    assert!(
        head.contains("Sec-WebSocket-Protocol: ng-plain.rtpengine.com"),
        "{head}"
    );
    s.write_all(&frame(1, br#"{"command":"ping"}"#)).unwrap();
    assert_eq!(read_frame(&mut s), (2, br#"{"result":"pong"}"#.to_vec()));

    let (_, head) = ws(at, "chat");
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");

    // A fragmented request; a control frame in between is answered.
    let (mut s, _) = ws(at, "ng.rtpengine.com");
    let mut first = frame(1, b"f1 d7:comm");
    first[0] &= 0x7f;
    s.write_all(&first).unwrap();
    s.write_all(&frame(9, b"p")).unwrap();
    assert_eq!(read_frame(&mut s), (10, b"p".to_vec()));
    s.write_all(&frame(0, b"and4:pinge")).unwrap();
    assert_eq!(read_frame(&mut s), (2, b"f1 d6:result4:ponge".to_vec()));

    // A continuation with no message started: closed with 1002.
    let (mut s, _) = ws(at, "ng.rtpengine.com");
    s.write_all(&frame(0, b"x")).unwrap();
    assert_eq!(read_frame(&mut s), (8, 1002u16.to_be_bytes().to_vec()));

    // An unmasked frame from a client fails the connection (§5.1): a
    // Close frame with 1002 (§7.1.7), then the connection is closed.
    let (mut s, _) = ws(at, "ng.rtpengine.com");
    s.write_all(&[0x81, 0x05, b'h', b'e', b'l', b'l', b'o'])
        .unwrap();
    assert_eq!(read_frame(&mut s), (8, 1002u16.to_be_bytes().to_vec()));
    let mut buf = [0u8; 16];
    assert_eq!(s.read(&mut buf).unwrap_or(0), 0);
    // So does a reserved bit.
    let (mut s, _) = ws(at, "ng.rtpengine.com");
    let mut bad = frame(2, b"x");
    bad[0] |= 0x40;
    s.write_all(&bad).unwrap();
    assert_eq!(read_frame(&mut s), (8, 1002u16.to_be_bytes().to_vec()));
    d.stop();
}
