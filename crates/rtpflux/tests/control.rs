//! The control plane without the network: requests handed to `Control`
//! directly, for the replies to bad requests and the state file's edge
//! cases.

#[path = "support/logging.rs"]
mod logging;

use rtpflux::config::Config;
use rtpflux::control::Control;
use rtpflux::relay::Relay;
use rtpflux_ng::bencode::{Encoder, Value, decode};

fn control(first_port: u16) -> Control {
    logging::init();
    let config = Config::from_toml(&format!(
        r#"
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
    Control::new(Relay::start(&config).unwrap(), config.interfaces.clone())
}

/// Each request its own cookie: a repeated one is a retransmission.
static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A request entry: key, and a byte-string or a list value.
type Entry<'a> = (&'a str, Option<&'a [u8]>, Option<&'a [&'a [u8]]>);

/// A bencoded request; `lists` values are lists of byte strings.
fn request(pairs: &[(&str, &[u8])], lists: &[(&str, &[&[u8]])]) -> Vec<u8> {
    let mut all: Vec<Entry<'_>> = pairs
        .iter()
        .map(|(k, v)| (*k, Some(*v), None))
        .chain(lists.iter().map(|(k, v)| (*k, None, Some(*v))))
        .collect();
    all.sort_by_key(|(k, _, _)| *k);
    let cookie = format!(
        "c{} ",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let mut buf = vec![0u8; 8192];
    let mut e = Encoder::new(&mut buf);
    e.raw(cookie.as_bytes()).unwrap();
    e.dict().unwrap();
    for (k, v, l) in all {
        e.bytes(k.as_bytes()).unwrap();
        if let Some(v) = v {
            e.bytes(v).unwrap();
        } else if let Some(l) = l {
            e.list().unwrap();
            for item in l {
                e.bytes(item).unwrap();
            }
            e.end().unwrap();
        }
    }
    e.end().unwrap();
    let n = e.len();
    buf.truncate(n);
    buf
}

/// `result`, and `error-reason` or `sdp`.
fn send(c: &mut Control, req: &[u8]) -> (String, String) {
    let raw = c.handle(req).expect("a reply").to_vec();
    let space = raw.iter().position(|&b| b == b' ').unwrap();
    let Ok(Value::Dict(d)) = decode(&raw[space + 1..]) else {
        panic!("not a reply: {raw:?}")
    };
    let text = |k: &[u8]| String::from_utf8_lossy(d.get_bytes(k).unwrap_or_default()).into_owned();
    let other = if d.get_bytes(b"error-reason").is_some() {
        text(b"error-reason")
    } else {
        text(b"sdp")
    };
    (text(b"result"), other)
}

fn error(c: &mut Control, pairs: &[(&str, &[u8])]) -> String {
    let (result, reason) = send(c, &request(pairs, &[]));
    assert_eq!(result, "error", "{reason}");
    reason
}

const SDP: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n";

fn offer(c: &mut Control, call: &[u8]) {
    let (r, sdp) = send(
        c,
        &request(
            &[
                ("command", b"offer"),
                ("call-id", call),
                ("from-tag", b"f"),
                ("sdp", SDP.as_bytes()),
            ],
            &[],
        ),
    );
    assert_eq!(r, "ok", "{sdp}");
}

#[test]
fn bad_requests_get_clear_errors() {
    let mut c = control(54_000);
    assert!(c.handle(b"no-space-here").is_none(), "not ng: no reply");
    assert!(c.handle(b"c i5e").is_none(), "not a dictionary: no reply");
    assert_eq!(
        error(&mut c, &[("command", b"start forwarding")]),
        "unknown command start forwarding"
    );
    assert!(error(&mut c, &[("command", b"offer"), ("sdp", SDP.as_bytes())]).contains("call-id"));
    let (r, reason) = send(
        &mut c,
        &request(
            &[
                ("command", b"offer"),
                ("call-id", b"x"),
                ("from-tag", b"f"),
                ("sdp", SDP.as_bytes()),
            ],
            &[("direction", &[b"lo", b"nowhere"])],
        ),
    );
    assert_eq!(
        (r.as_str(), reason.as_str()),
        ("error", "unknown interface nowhere")
    );
    let answer = |c: &mut Control, call: &[u8], sdp: &str| {
        error(
            c,
            &[
                ("command", b"answer"),
                ("call-id", call),
                ("from-tag", b"f"),
                ("to-tag", b"t"),
                ("sdp", sdp.as_bytes()),
            ],
        )
    };
    assert_eq!(answer(&mut c, b"never", SDP), "unknown call (no offer)");
    offer(&mut c, b"one");
    let two = format!("{SDP}m=video 4002 RTP/AVP 96\r\n");
    assert_eq!(
        answer(&mut c, b"one", &two),
        "answer has 2 media sections, the offer had 1"
    );
    // `delete` of an unknown call: `ok` with a warning (rtpengine's
    // default), an error with `fatal`.
    let raw = c
        .handle(&request(
            &[("command", b"delete"), ("call-id", b"never")],
            &[],
        ))
        .unwrap()
        .to_vec();
    let text = String::from_utf8_lossy(&raw);
    assert!(
        text.contains("6:result2:ok") && text.contains("Call-ID not found or tags didn't match"),
        "{text}"
    );
    let (result, reason) = send(
        &mut c,
        &request(
            &[("command", b"delete"), ("call-id", b"never")],
            &[("flags", &[b"fatal"])],
        ),
    );
    assert_eq!(
        (result.as_str(), reason.as_str()),
        ("error", "unknown call")
    );
    for command in [&b"query"[..], b"block media", b"start recording"] {
        let reason = error(&mut c, &[("command", command), ("call-id", b"never")]);
        assert!(
            reason.starts_with("unknown call") || reason.contains("recording"),
            "{reason}"
        );
    }
    assert!(c.relay().totals().active_calls >= 1);
}

#[test]
fn feature_requests_are_checked() {
    let mut c = control(54_100);
    offer(&mut c, b"call");
    let play = |c: &mut Control, pairs: &[(&str, &[u8])]| {
        let mut all = vec![("command", &b"play media"[..]), ("call-id", b"call")];
        all.extend_from_slice(pairs);
        error(c, &all)
    };
    assert_eq!(
        play(&mut c, &[]),
        "play media needs from-tag (the listener)"
    );
    assert_eq!(
        play(&mut c, &[("from-tag", b"nobody")]),
        "unknown call or tag"
    );
    assert!(play(&mut c, &[("from-tag", b"f")]).contains("file"));
    assert!(
        play(&mut c, &[("from-tag", b"f"), ("file", b"/nonexistent.wav")])
            .starts_with("/nonexistent.wav: ")
    );
    let dir = std::env::temp_dir().join(format!("rtpflux-control-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let junk = dir.join("junk.wav");
    std::fs::write(&junk, b"RIFF....WAVEjunk").unwrap();
    let junk = junk.to_str().unwrap().as_bytes();
    // Unanswered: the offerer does not receive G.711 yet.
    assert_eq!(
        play(
            &mut c,
            &[("from-tag", b"f"), ("file", junk), ("repeat-times", b"3")]
        ),
        "the listener receives no G.711 audio"
    );
    // Stopping needs no tag, and stops nothing harmlessly.
    let (r, _) = send(
        &mut c,
        &request(&[("command", b"stop media"), ("call-id", b"call")], &[]),
    );
    assert_eq!(r, "ok");
    // Recording needs a directory.
    assert!(
        error(
            &mut c,
            &[("command", b"start recording"), ("call-id", b"call")]
        )
        .contains("[recording] dir")
    );
    c.set_recording_dir(Some(dir.clone()));
    assert_eq!(
        error(
            &mut c,
            &[
                ("command", b"start recording"),
                ("call-id", b"call"),
                ("from-tag", b"other")
            ]
        ),
        "unknown call or tag"
    );
    assert_eq!(
        error(
            &mut c,
            &[
                ("command", b"block DTMF"),
                ("call-id", b"call"),
                ("from-tag", b"x")
            ]
        ),
        "unknown call or tag"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn unusable_state_files_restore_nothing() {
    let dir = std::env::temp_dir().join(format!("rtpflux-state-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("state.json");
    let restore = |text: &str, port: u16| {
        std::fs::write(&state, text).unwrap();
        let mut c = control(port);
        c.set_state_file(Some(state.clone()));
        c.restore()
    };
    // Unusable files are kept aside as state.json.bad, for a human.
    let bad = dir.join("state.json.bad");
    assert_eq!(restore("not json", 54_200), 0);
    assert_eq!(std::fs::read_to_string(&bad).unwrap(), "not json");
    assert!(!state.exists());
    let newer = r#"{"version": 99, "sessions": []}"#;
    assert_eq!(restore(newer, 54_300), 0);
    assert_eq!(std::fs::read_to_string(&bad).unwrap(), newer);

    // A good state file, from a real call.
    let mut c = control(54_400);
    c.set_state_file(Some(state.clone()));
    offer(&mut c, b"saved");
    c.save();
    drop(c);
    let good = std::fs::read_to_string(&state).unwrap();
    // A broken entry next to it is skipped; the good one is restored.
    let mut saved: serde_json::Value = serde_json::from_str(&good).unwrap();
    let mut broken = saved["sessions"][0].clone();
    broken["call_id"] = "not hex".into();
    saved["sessions"].as_array_mut().unwrap().push(broken);
    assert_eq!(restore(&saved.to_string(), 54_400), 1);
    // A port taken meanwhile: that call cannot come back.
    let port = saved["sessions"][0]["media"][0]["port_a"].as_u64().unwrap();
    let _taken = std::net::UdpSocket::bind(("127.0.0.1", u16::try_from(port).unwrap())).unwrap();
    assert_eq!(restore(&good, 54_400), 0);
    // Saving into a directory that does not exist is reported, not fatal.
    let mut c = control(54_500);
    c.set_state_file(Some(dir.join("missing").join("state.json")));
    offer(&mut c, b"unsaved");
    c.save();
    std::fs::remove_dir_all(&dir).unwrap();
}

type Keys = std::sync::Arc<std::sync::Mutex<std::collections::HashMap<Vec<u8>, Vec<u8>>>>;

/// A RESP server keeping one database in memory (`SET` and `GET` only).
fn fake_redis() -> (std::net::SocketAddr, Keys) {
    use std::io::{BufRead as _, Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let data = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let store = std::sync::Arc::clone(&data);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let store = std::sync::Arc::clone(&store);
            std::thread::spawn(move || {
                let mut out = stream.try_clone().unwrap();
                let mut input = std::io::BufReader::new(stream);
                let mut line = String::new();
                loop {
                    line.clear();
                    if input.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    let n: usize = line.trim_end()[1..].parse().unwrap();
                    let mut args: Vec<Vec<u8>> = Vec::new();
                    for _ in 0..n {
                        line.clear();
                        input.read_line(&mut line).unwrap();
                        let len: usize = line.trim_end()[1..].parse().unwrap();
                        let mut v = vec![0; len + 2];
                        input.read_exact(&mut v).unwrap();
                        v.truncate(len);
                        args.push(v);
                    }
                    let reply = match args[0].as_slice() {
                        b"SET" => {
                            store
                                .lock()
                                .unwrap()
                                .insert(args[1].clone(), args[2].clone());
                            b"+OK\r\n".to_vec()
                        }
                        b"GET" => match store.lock().unwrap().get(&args[1]) {
                            Some(v) => {
                                [format!("${}\r\n", v.len()).as_bytes(), v, b"\r\n"].concat()
                            }
                            None => b"$-1\r\n".to_vec(),
                        },
                        _ => b"-ERR unknown command\r\n".to_vec(),
                    };
                    out.write_all(&reply).unwrap();
                }
            });
        }
    });
    (addr, data)
}

#[test]
fn calls_come_back_from_redis_and_the_newer_snapshot_wins() {
    let (addr, data) = fake_redis();
    let target =
        rtpflux::redis::Target::parse(&format!("redis://{addr}"), "rtpflux:state").unwrap();
    let writer = || rtpflux::redis::Writer::spawn(target.clone()).unwrap();
    let dir = std::env::temp_dir().join(format!("rtpflux-redis-state-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("state.json");

    // Redis only: a call saved there comes back on a host without a file.
    let mut c = control(54_600);
    c.set_state_redis(Some(writer()));
    offer(&mut c, b"in-redis");
    c.save();
    drop(c); // the writer writes the last snapshot before it goes
    assert!(data.lock().unwrap().contains_key(&b"rtpflux:state"[..]));
    let mut c = control(54_600);
    c.set_state_redis(Some(writer()));
    assert_eq!(c.restore(), 1);
    drop(c);

    // Both: an older file (the call in Redis is newer) loses to Redis…
    let mut c = control(54_700);
    c.set_state_file(Some(file.clone()));
    offer(&mut c, b"file-a");
    offer(&mut c, b"file-b");
    c.save();
    drop(c);
    std::thread::sleep(std::time::Duration::from_millis(5));
    let mut c = control(54_800);
    c.set_state_redis(Some(writer()));
    offer(&mut c, b"newer-in-redis");
    c.save();
    drop(c);
    let mut c = control(54_800);
    c.set_state_file(Some(file.clone()));
    c.set_state_redis(Some(writer()));
    assert_eq!(c.restore(), 1, "Redis' one call, not the file's two");
    // … and a save writes both.
    c.save();
    drop(c);
    let file_saved = rtpflux::state::read(&file).unwrap().unwrap();
    let redis_saved =
        rtpflux::state::Saved::decode(&data.lock().unwrap()[&b"rtpflux:state"[..]]).unwrap();
    assert_eq!(file_saved, redis_saved);

    // Redis unreachable: the file still restores, nothing hangs.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let gone = rtpflux::redis::Target::parse(&format!("redis://127.0.0.1:{port}"), "k").unwrap();
    let mut c = control(54_800);
    c.set_state_file(Some(file.clone()));
    c.set_state_redis(Some(rtpflux::redis::Writer::spawn(gone).unwrap()));
    assert_eq!(c.restore(), 1);
    std::fs::remove_dir_all(&dir).unwrap();
}
