//! The web UI as an operator uses it: the daemon started with `[webui]`,
//! a call made over ng, then the login, the API, the app's files and the
//! read-only rules over real HTTP.

#[path = "support/logging.rs"]
mod logging;

use rtpflux::config::Config;
use rtpflux::daemon::Daemon;
use rtpflux::webui::auth::make_hash;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

/// "admin:secret".
const LOGIN: &str = "Basic YWRtaW46c2VjcmV0";

/// One HTTP request on its own connection: (status, headers, body).
fn http(addr: SocketAddr, request: &str) -> (u16, String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(request.as_bytes()).unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let code = head[9..12].parse().unwrap();
    (code, head, raw[split + 4..].to_vec())
}

fn get(addr: SocketAddr, path: &str, auth: Option<&str>) -> (u16, String, Vec<u8>) {
    let auth = auth.map_or(String::new(), |a| format!("Authorization: {a}\r\n"));
    http(
        addr,
        &format!("GET {path} HTTP/1.1\r\nHost: x\r\n{auth}Connection: close\r\n\r\n"),
    )
}

fn json(addr: SocketAddr, path: &str) -> serde_json::Value {
    let (code, _, body) = get(addr, path, Some(LOGIN));
    assert_eq!(code, 200, "{path}: {}", String::from_utf8_lossy(&body));
    serde_json::from_slice(&body).unwrap()
}

fn ng(to: SocketAddr, request: &[u8]) -> String {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.send_to(request, to).unwrap();
    let mut buf = vec![0u8; 65_535];
    let n = s.recv(&mut buf).expect("ng reply");
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

#[test]
fn the_web_ui_shows_the_relay_read_only() {
    logging::init();
    let rec = std::env::temp_dir().join(format!("rtpflux-webui-rec-{}", std::process::id()));
    std::fs::create_dir_all(&rec).unwrap();
    let config = Config::from_toml(&format!(
        r#"
        [control]
        listen = ["127.0.0.1:0"]
        [[interface]]
        name = "lo"
        address = "127.0.0.1"
        [ports]
        min = 54200
        max = 54263
        [sessions]
        max = 8
        [runtime]
        workers = 1
        [webui]
        listen = "127.0.0.1:0"
        user = "admin"
        password_hash = "{}"
        refresh_ms = 1000
        [recording]
        dir = "{}"
        "#,
        make_hash(b"secret"),
        rec.display()
    ))
    .unwrap();
    let daemon = Daemon::start(&config).unwrap();
    let ui = daemon.webui_addr().expect("the web UI runs");
    login_files_and_rules(ui);
    api(ui, daemon.control_addrs()[0]);
    parties(ui, daemon.control_addrs()[0]);
    recordings(ui, &rec);
    daemon.stop();
    std::fs::remove_dir_all(&rec).unwrap();
}

/// An ng request from string options (`flags` as a list), its reply.
fn ng_dict(control: SocketAddr, cookie: &str, pairs: &[(&str, &str)], flags: &[&str]) -> String {
    let b = |s: &str| format!("{}:{s}", s.len());
    let mut items: Vec<(String, String)> =
        pairs.iter().map(|(k, v)| ((*k).to_owned(), b(v))).collect();
    if !flags.is_empty() {
        items.push((
            "flags".to_owned(),
            format!("l{}e", flags.iter().map(|f| b(f)).collect::<String>()),
        ));
    }
    items.sort();
    let body = items.iter().fold(String::new(), |mut out, (k, v)| {
        out.push_str(&b(k));
        out.push_str(v);
        out
    });
    let reply = ng(control, format!("{cookie} d{body}e").as_bytes());
    assert!(reply.contains("6:result2:ok"), "{pairs:?}: {reply}");
    reply
}

/// A conference, a transfer and monitoring as the Calls page shows them:
/// one call's parties and dialogs, the links to other calls, and its
/// subscriptions (`calls/parties`), with badges in the list.
#[allow(clippy::too_many_lines)] // Four calls, then everything the UI reads of them.
fn parties(ui: SocketAddr, control: SocketAddr) {
    let sdp = |port: u16| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {port} RTP/AVP 0\r\n"
        )
    };
    let offer = |c: &str, call: &str, from: &str, port: u16, extra: &[(&str, &str)]| {
        let s = sdp(port);
        let mut p = vec![
            ("command", "offer"),
            ("call-id", call),
            ("from-tag", from),
            ("sdp", s.as_str()),
        ];
        p.extend_from_slice(extra);
        ng_dict(control, c, &p, &["trust-address"]);
    };
    let answer = |c: &str, call: &str, from: &str, to: &str, port: u16, extra: &[(&str, &str)]| {
        let s = sdp(port);
        let mut p = vec![
            ("command", "answer"),
            ("call-id", call),
            ("from-tag", from),
            ("to-tag", to),
            ("sdp", s.as_str()),
        ];
        p.extend_from_slice(extra);
        ng_dict(control, c, &p, &["trust-address"]);
    };
    // A three-way call in one call-id: Alice with Bob, Carol's leg with Alice.
    offer("p1", "conf", "a", 5000, &[("label", "host")]);
    answer("p2", "conf", "a", "b", 5002, &[]);
    offer("p3", "conf", "c", 5004, &[("label", "second")]);
    answer("p4", "conf", "c", "a", 5006, &[]);
    // Dave (another call) joined with Bob: a transfer.
    offer("p5", "other", "d", 5008, &[]);
    answer("p6", "other", "d", "e", 5010, &[]);
    ng_dict(
        control,
        "p7",
        &[
            ("command", "connect"),
            ("call-id", "conf"),
            ("from-tag", "b"),
            ("to-call-id", "other"),
            ("to-tag", "d"),
        ],
        &[],
    );
    // Erin's call copied to Carol (a supervisor listening, say).
    offer("p8", "mon", "s", 5012, &[]);
    answer("p9", "mon", "s", "t", 5014, &[]);
    ng_dict(
        control,
        "pa",
        &[
            ("command", "connect"),
            ("call-id", "mon"),
            ("from-tag", "s"),
            ("to-call-id", "conf"),
            ("to-tag", "c"),
        ],
        &["directional"],
    );
    // A recorder subscribed to Alice.
    ng_dict(
        control,
        "pb",
        &[
            ("command", "subscribe request"),
            ("call-id", "conf"),
            ("from-tag", "a"),
            ("to-tag", "srs"),
        ],
        &[],
    );

    let p = json(ui, "/api/v1/calls/parties?call_id=conf");
    let tags: Vec<&str> = p["parties"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["tag"].as_str().unwrap())
        .collect();
    assert_eq!(tags, ["a", "b", "c"], "{p}");
    let a = &p["parties"][0];
    assert_eq!(
        (a["label"].as_str(), a["codec"].as_str()),
        (Some("host"), Some("PCMU"))
    );
    assert_eq!(a["in_dialogue_with"], serde_json::json!(["b", "c"]));
    assert_eq!(p["dialogs"].as_array().unwrap().len(), 2);
    let links = p["links"].as_array().unwrap();
    let joined = links
        .iter()
        .find(|l| l["kind"] == "joined")
        .expect("the transfer");
    assert_eq!(
        (
            &joined["from"]["tag"],
            &joined["to"]["call_id"],
            &joined["to"]["here"]
        ),
        (
            &serde_json::json!("b"),
            &serde_json::json!("other"),
            &serde_json::json!(false)
        )
    );
    let copy = links
        .iter()
        .find(|l| l["kind"] == "copy")
        .expect("the copy");
    assert_eq!(
        (&copy["from"]["call_id"], &copy["to"]["tag"], &copy["both"]),
        (
            &serde_json::json!("mon"),
            &serde_json::json!("c"),
            &serde_json::json!(false)
        )
    );
    assert!(copy["convert"].is_null(), "PCMU to PCMU: as sent");
    let sub = &p["subscriptions"][0];
    assert_eq!(
        (&sub["tag"], &sub["sources"], &sub["answered"]),
        (
            &serde_json::json!("srs"),
            &serde_json::json!(["a"]),
            &serde_json::json!(false)
        )
    );
    // The links are counted (for /metrics and the Statistics page).
    let stats = json(ui, "/api/v1/stats");
    let gauge = |name: &str| {
        stats["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["group"] == "links" && r["name"] == name)
            .map(|r| r["value"].as_u64().unwrap())
    };
    assert_eq!(
        (
            gauge("connections"),
            gauge("copies"),
            gauge("subscriptions")
        ),
        (Some(1), Some(1), Some(1)),
        "{stats}"
    );
    // A section's negotiation and its legs' state, in detail.
    let d = json(ui, "/api/v1/calls/detail?call_id=conf&from_tag=a");
    let m = &d["media"][0];
    assert_eq!(m["a"]["codec"], "PCMU (0)", "{m}");
    assert_eq!(m["a"]["direction"], "sendrecv");
    assert!(m["a"]["latching"].is_string() && m["a"]["strict_source"].is_boolean());
    assert!(m["a"]["rtp"]["settled"].is_boolean());
    assert!(
        m["a"]["rtp"]["dtls"].is_null() && m["a"]["rtp"]["ice"].is_null(),
        "plain RTP"
    );
    assert_eq!(m["in_kernel"], false);
    assert!(d["timers"]["unanswered_ends_in_s"].is_null(), "answered");
    // The other call sees the transfer from its side.
    let other = json(ui, "/api/v1/calls/parties?call_id=other");
    assert_eq!(other["links"][0]["kind"], "joined");
    // Badges in the list; the offerer's tag, not a storage key. (The list
    // is cached for a second.)
    std::thread::sleep(Duration::from_millis(1100));
    let rows = json(ui, "/api/v1/calls?q=conf&limit=50");
    let row = rows["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["call_id"] == "conf" && r["from_tag"] == "a")
        .unwrap();
    assert_eq!(
        row["links"],
        serde_json::json!(["multi-party", "joined", "copies", "subscribed"]),
        "{row}"
    );
    assert_eq!(
        get(ui, "/api/v1/calls/parties?call_id=nope", Some(LOGIN)).0,
        404
    );
    assert_eq!(get(ui, "/api/v1/calls/parties", Some(LOGIN)).0, 400);
    ng_dict(
        control,
        "pz",
        &[("command", "delete"), ("call-id", "conf")],
        &[],
    );
}

/// The Recordings page: a pcap listed, read back, and downloaded as it is.
fn recordings(ui: SocketAddr, dir: &std::path::Path) {
    let pcap = dir.join("call-a-1.pcap");
    let mut r = rtpflux::recording::Recorder::open(&pcap).unwrap();
    for seq in 0..10u8 {
        let mut p = vec![0x80, 0, 0, seq, 0, 0, 0, 0, 0, 0, 0, 7];
        p.extend_from_slice(&[0xd5; 160]);
        r.packet(
            "192.0.2.1:4000".parse().unwrap(),
            "192.0.2.9:30000".parse().unwrap(),
            &p,
        );
    }
    r.flush();
    drop(r);
    assert!(json(ui, "/api/v1/meta")["sections"]["recordings"].is_array());
    let list = json(ui, "/api/v1/recordings");
    assert_eq!(list["rows"][0]["file"], "call-a-1.pcap", "{list}");
    let s = json(ui, "/api/v1/recordings/streams?file=call-a-1.pcap");
    assert_eq!(s["streams"][0]["packets"], 10, "{s}");
    let p = json(ui, "/api/v1/recordings/packets?file=call-a-1.pcap&limit=3");
    assert_eq!(
        (p["total"].as_u64(), p["rows"][2]["seq"].as_u64()),
        (Some(10), Some(2))
    );
    let (code, head, body) = get(
        ui,
        "/api/v1/recordings/download?file=call-a-1.pcap",
        Some(LOGIN),
    );
    assert_eq!(code, 200);
    assert!(
        head.contains("Content-Type: application/vnd.tcpdump.pcap"),
        "{head}"
    );
    assert!(
        head.contains("Content-Disposition: attachment; filename=\"call-a-1.pcap\""),
        "{head}"
    );
    assert_eq!(body, std::fs::read(&pcap).unwrap());
    // Only the recording's own files, and only with the login.
    assert_eq!(
        get(ui, "/api/v1/recordings/download?file=call-a-1.pcap", None).0,
        401
    );
    for bad in ["x.toml", "%2Fetc%2Fpasswd", "none.pcap"] {
        let code = get(
            ui,
            &format!("/api/v1/recordings/download?file={bad}"),
            Some(LOGIN),
        )
        .0;
        assert!(code == 400 || code == 404, "{bad}: {code}");
    }
}

/// The login, the app's files and headers, and the read-only rules.
fn login_files_and_rules(ui: SocketAddr) {
    // The login is required, and wrong ones are refused.
    let (code, head, _) = get(ui, "/", None);
    assert_eq!(code, 401);
    assert!(
        head.contains("WWW-Authenticate: Basic realm=\"rtpflux\""),
        "{head}"
    );
    assert_eq!(
        get(ui, "/api/v1/meta", Some("Basic YWRtaW46d3Jvbmc=")).0,
        401
    );

    // The app, with its security headers; gzip when accepted.
    let (code, head, body) = get(ui, "/", Some(LOGIN));
    assert_eq!(code, 200);
    assert!(String::from_utf8_lossy(&body).contains("<div id=\"app\">"));
    assert!(
        head.contains("Content-Security-Policy: default-src 'self'"),
        "{head}"
    );
    assert!(head.contains("X-Frame-Options: DENY"));
    let (code, head, js) = http(
        ui,
        &format!(
            "GET /app.js HTTP/1.1\r\nAuthorization: {LOGIN}\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n"
        ),
    );
    assert_eq!(code, 200);
    assert!(head.contains("Content-Encoding: gzip") && js.starts_with(&[0x1f, 0x8b]));
    assert_eq!(get(ui, "/nothing", Some(LOGIN)).0, 404);

    // Read-only: nothing but GET and HEAD.
    let (code, head, _) = http(
        ui,
        &format!(
            "POST /api/v1/calls HTTP/1.1\r\nAuthorization: {LOGIN}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ),
    );
    assert_eq!(code, 405);
    assert!(head.contains("Allow: GET, HEAD"));
    // With a body too (the connection closes: the body is not read).
    let (code, head, _) = http(
        ui,
        &format!(
            "POST /api/v1/calls HTTP/1.1\r\nAuthorization: {LOGIN}\r\nContent-Length: 2\r\n\r\n{{}}"
        ),
    );
    assert_eq!(code, 405);
    assert!(head.contains("Allow: GET, HEAD"));
    // A GET with a body is a bad request.
    let (code, _, _) = http(
        ui,
        &format!(
            "GET /api/v1/calls HTTP/1.1\r\nAuthorization: {LOGIN}\r\nContent-Length: 2\r\n\r\n{{}}"
        ),
    );
    assert_eq!(code, 400);
}

/// The API, with a call made over ng.
fn api(ui: SocketAddr, control: SocketAddr) {
    let meta = json(ui, "/api/v1/meta");
    assert_eq!(meta["refresh_ms"], 1000);
    for section in ["overview", "calls", "statistics"] {
        assert!(meta["sections"][section].is_array(), "{section}: {meta}");
    }
    // `main` installs the log ring; without it there is no Logs page.
    assert!(meta["sections"]["logs"].is_null(), "{meta}");
    let info = json(ui, "/api/v1/info");
    assert_eq!(info["pid"], std::process::id());
    assert_eq!(info["interfaces"][0]["name"], "lo");
    assert_eq!(info["ports"], "54200-54263");
    // Runtime facts: how each worker receives (io_uring, or recvmmsg and
    // why: a container may refuse io_uring), timeouts, ICE, warnings.
    assert_eq!(info["receive"], "io_uring");
    assert_eq!(info["worker_stats"].as_array().unwrap().len(), 1);
    assert!(info["worker_stats"][0]["calls"].is_u64());
    // No XDP here: no such page.
    assert!(meta["sections"]["xdp"].is_null());
    assert_eq!(get(ui, "/api/v1/xdp", Some(LOGIN)).0, 404);
    let w = info["worker_stats"][0]["receive"].as_str().unwrap();
    assert!(
        w == "io_uring" || w.starts_with("recvmmsg (io_uring: "),
        "{w}"
    );
    assert_eq!(info["timeouts"]["media_s"], 60);
    assert_eq!(info["ice"]["mode"], "full");
    assert_eq!(info["control_tcp"], serde_json::json!([]));
    assert!(info["warnings"].is_array());
    assert_eq!(
        info["srflx"],
        serde_json::json!([]),
        "no STUN server: nothing learned"
    );

    // A call made over ng appears, with its legs in detail.
    let sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n";
    let offer = format!(
        "1 d7:call-id6:ui-one7:command5:offer8:from-tag5:alice3:sdp{}:{sdp}e",
        sdp.len()
    );
    assert!(ng(control, offer.as_bytes()).contains("6:result2:ok"));
    let calls = json(ui, "/api/v1/calls?q=ui-one");
    assert_eq!(calls["total"], 1, "{calls}");
    let row = &calls["rows"][0];
    assert_eq!(
        (
            &row["call_id"],
            &row["from_tag"],
            &row["state"],
            &row["security"]
        ),
        (
            &serde_json::json!("ui-one"),
            &serde_json::json!("alice"),
            &serde_json::json!("offered"),
            &serde_json::json!("plain")
        )
    );
    let detail = json(ui, "/api/v1/calls/detail?call_id=ui-one&from_tag=alice");
    // Unanswered: it ends at the offer timeout unless answered.
    assert!(
        detail["timers"]["unanswered_ends_in_s"].as_u64().is_some(),
        "{detail}"
    );
    let media = &detail["media"][0];
    assert_eq!(media["a"]["protocol"], "RTP/AVP");
    assert_eq!(media["a"]["rtp"]["packets"], 0);
    assert_eq!(media["a"]["rtp"]["peer"], "127.0.0.1:4000");
    assert_eq!(
        get(ui, "/api/v1/calls/detail?call_id=x&from_tag=y", Some(LOGIN)).0,
        404
    );
    assert_eq!(get(ui, "/api/v1/calls/detail", Some(LOGIN)).0, 400);

    // The counters, as /metrics has them.
    let stats = json(ui, "/api/v1/stats");
    let offers = stats["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["group"] == "ng_requests" && r["name"] == "offer")
        .unwrap();
    assert_eq!(
        (offers["value"].as_u64(), offers["kind"].as_str()),
        (Some(1), Some("counter"))
    );

    // The log ring is not installed by this test (main does it): a clear
    // error, not a crash.
    assert_eq!(get(ui, "/api/v1/logs", Some(LOGIN)).0, 404);
}
