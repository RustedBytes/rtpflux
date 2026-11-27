//! Conferences composed and recovered:
//! - mixed codecs with N − 1 isolation;
//! - deafen, output gain, mute;
//! - a PCM tap (speech recognition) on a participant, while the mix goes
//!   on;
//! - many attaches and detaches, the plan kept consistent;
//! - a restart: the mixer back with the same id and its participants'
//!   settings.

#[path = "support/logging.rs"]
mod logging;

use rtpflux::config::Config;
use rtpflux::daemon::Daemon;
use rtpflux_client::Client;
use serde_json::{Value, json};
use std::io::Read;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(3);

fn temp_dir(name: &str) -> PathBuf {
    logging::init();
    let d = std::env::temp_dir().join(format!("rtpflux-conf-{name}-{}", std::process::id()));
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
        max = 16
        state_file = "{}"
        [runtime]
        workers = 2
        "#,
        sock.display(),
        dir.display(),
        min + 63,
        dir.join("state.json").display(),
    ))
    .unwrap();
    (Daemon::start(&config).unwrap(), sock)
}

/// A participant: its socket, payload type, and the relay's address for it.
struct Party {
    sock: UdpSocket,
    pt: u8,
    to: SocketAddr,
    id: String,
}

fn party(api: &mut Client, pt: u8) -> Party {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    let name = match pt {
        0 => "PCMU/8000",
        8 => "PCMA/8000",
        _ => "G722/8000",
    };
    let sdp = format!(
        "v=0\r\no=- 7 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP {pt}\r\na=rtpmap:{pt} {name}\r\na=sendrecv\r\n"
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
    Party {
        sock,
        pt,
        to: SocketAddr::from(([127, 0, 0, 1], relay_port)),
        id: ep["endpoint_id"].as_str().unwrap().to_owned(),
    }
}

/// `talker` (G.711) speaks a loud tone for `ms`; the others send silence.
/// Meanwhile every party's received level (G.711) or packet count (G.722)
/// is measured: one value each.
fn round(parties: &[&Party], talker: Option<usize>, ms: u64, seq: &mut u16) -> Vec<u64> {
    let socks: Vec<UdpSocket> = parties
        .iter()
        .map(|p| p.sock.try_clone().unwrap())
        .collect();
    let listeners: Vec<_> = parties
        .iter()
        .map(|p| {
            let s = p.sock.try_clone().unwrap();
            let pt = p.pt;
            std::thread::spawn(move || {
                let end = Instant::now() + Duration::from_millis(ms + 200);
                s.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
                let mut buf = [0u8; 2048];
                let (mut sum, mut n, mut packets) = (0u64, 0u64, 0u64);
                // The first 200 ms are the jitter buffers filling.
                let from = Instant::now() + Duration::from_millis(200);
                while Instant::now() < end {
                    if let Ok((len, _)) = s.recv_from(&mut buf)
                        && len > 12
                        && Instant::now() > from
                    {
                        packets += 1;
                        for &c in &buf[12..len] {
                            let v = match pt {
                                0 => rtpflux_core::g711::ulaw_to_linear(c),
                                8 => rtpflux_core::g711::alaw_to_linear(c),
                                _ => 0,
                            };
                            sum += u64::from(v.unsigned_abs());
                            n += 1;
                        }
                    }
                }
                if pt == 9 { packets } else { sum / n.max(1) }
            })
        })
        .collect();
    let frames = ms / 20;
    for k in 0..frames {
        for (i, (p, s)) in parties.iter().zip(&socks).enumerate() {
            let loud = talker == Some(i);
            let payload: Vec<u8> = (0..160u32)
                .map(|j| {
                    let x = if loud {
                        (f64::from(u32::try_from(k).unwrap() * 160 + j)
                            * 2.0
                            * std::f64::consts::PI
                            * 400.0
                            / 8000.0)
                            .sin()
                            * 12000.0
                    } else {
                        0.0
                    };
                    #[allow(clippy::cast_possible_truncation)]
                    let v = x as i16;
                    match p.pt {
                        8 => rtpflux_core::g711::linear_to_alaw(v),
                        9 => 0,
                        _ => rtpflux_core::g711::linear_to_ulaw(v),
                    }
                })
                .collect();
            let mut pkt = vec![0x80, p.pt];
            pkt.extend_from_slice(&seq.to_be_bytes());
            pkt.extend_from_slice(&(u32::from(*seq) * 160).to_be_bytes());
            pkt.extend_from_slice(&(0x1000 + u32::try_from(i).unwrap()).to_be_bytes());
            pkt.extend_from_slice(&payload);
            s.send_to(&pkt, p.to).unwrap();
        }
        *seq = seq.wrapping_add(1);
        std::thread::sleep(Duration::from_millis(20));
    }
    listeners.into_iter().map(|t| t.join().unwrap()).collect()
}

/// A PCM frame's kind and its samples' mean level.
fn pcm_frame(r: &mut std::os::unix::net::UnixStream) -> Option<(u8, u64)> {
    let mut h = [0u8; 32];
    r.read_exact(&mut h).ok()?;
    let n = usize::from(u16::from_le_bytes([h[30], h[31]]));
    let mut body = vec![0u8; if h[5] == 2 { n * 2 } else { 0 }];
    r.read_exact(&mut body).ok()?;
    let sum: u64 = body
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u64::from(i16::from_le_bytes(*b).unsigned_abs()))
        .sum();
    Some((h[5], sum / u64::try_from(n.max(1)).unwrap()))
}

#[test]
#[allow(clippy::too_many_lines)] // One conference, its controls one by one.
fn composition_and_controls() {
    let dir = temp_dir("compose");
    let (daemon, sock) = relay(&dir, 61_900);
    let service = std::os::unix::net::UnixListener::bind(dir.join("asr.sock")).unwrap();
    let mut api = Client::connect(&sock).unwrap();
    api.call("events.subscribe", json!({"types": ["stream.ended"]}))
        .unwrap();
    let (a, b, c) = (party(&mut api, 0), party(&mut api, 8), party(&mut api, 9));
    let mixer = api.call("mixer.create", Value::Null).unwrap()["mixer_id"].clone();
    for p in [&a, &b, &c] {
        api.call("mixer.add", json!({"mixer_id": mixer, "endpoint_id": p.id}))
            .unwrap();
    }
    let all = [&a, &b, &c];
    let mut seq = 0u16;

    // A speaks: B (PCMA) and C (G.722) hear it, A does not hear itself.
    let r = round(&all, Some(0), 1000, &mut seq);
    assert!(r[1] > 1500, "B hears A: {r:?}");
    assert!(r[2] >= 30, "C gets the mix in G.722: {r:?}");
    assert!(r[0] < 200, "N − 1: A does not hear itself: {r:?}");
    let b_level = r[1];

    // B's output gain down 20 dB; A deafened (it hears silence, its packets
    // still flow).
    api.call(
        "mixer.set",
        json!({"mixer_id": mixer, "endpoint_id": b.id, "output_gain_db": -20}),
    )
    .unwrap();
    api.call(
        "mixer.set",
        json!({"mixer_id": mixer, "endpoint_id": a.id, "deafened": true}),
    )
    .unwrap();
    let r = round(&all, Some(0), 1000, &mut seq);
    assert!(
        r[1] * 4 < b_level && r[1] > 50,
        "B hears A quieter: {} then {}",
        b_level,
        r[1]
    );
    // A deafened: B speaking is not heard by A, C still gets it.
    let r = round(&all, Some(1), 1000, &mut seq);
    assert!(r[0] < 100, "A deafened: {r:?}");
    api.call(
        "mixer.set",
        json!({"mixer_id": mixer, "endpoint_id": a.id, "deafened": false, "muted": true}),
    )
    .unwrap();
    api.call(
        "mixer.set",
        json!({"mixer_id": mixer, "endpoint_id": b.id, "output_gain_db": 0}),
    )
    .unwrap();
    // A muted: no one hears it.
    let r = round(&all, Some(0), 1000, &mut seq);
    assert!(r[1] < 200, "A muted: {r:?}");
    api.call(
        "mixer.set",
        json!({"mixer_id": mixer, "endpoint_id": a.id, "muted": false}),
    )
    .unwrap();

    // A tap on A for speech recognition: no injection into a participant.
    let refused = api
        .call(
            "stream.start",
            json!({"endpoint_id": a.id, "socket": "asr.sock", "inject": true}),
        )
        .unwrap_err();
    assert_eq!(refused.code(), Some("conflict"));
    let tap = api
        .call(
            "stream.start",
            json!({"endpoint_id": a.id, "socket": "asr.sock"}),
        )
        .unwrap();
    assert_eq!(tap["inject"], false);
    let (mut asr, _) = service.accept().unwrap();
    asr.set_read_timeout(Some(WAIT)).unwrap();
    let reader = std::thread::spawn(move || {
        let mut loud = 0;
        let end = Instant::now() + Duration::from_millis(1500);
        while Instant::now() < end {
            match pcm_frame(&mut asr) {
                Some((2, level)) if level > 1000 => loud += 1,
                Some(_) => {}
                None => break,
            }
        }
        (loud, asr)
    });
    let r = round(&all, Some(0), 1000, &mut seq);
    let (loud, asr) = reader.join().unwrap();
    assert!(loud >= 20, "the tap gets A's voice: {loud} loud frames");
    assert!(r[1] > 1500, "and the mix goes on: {r:?}");
    // A leaves the mixer: its tap ends.
    api.call(
        "mixer.remove",
        json!({"mixer_id": mixer, "endpoint_id": a.id}),
    )
    .unwrap();
    let ended = api
        .wait_event("stream.ended", WAIT)
        .unwrap()
        .expect("the tap ends");
    assert_eq!(ended["data"]["stream_id"], tap["stream_id"]);
    drop((api, asr));
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Many attaches and detaches, then a restart: the mixer comes back with
/// the same id, its participants and their settings.
#[test]
fn attach_detach_and_a_restart() {
    let dir = temp_dir("restart");
    let (daemon, sock) = relay(&dir, 60_100);
    let mut api = Client::connect(&sock).unwrap();
    let (a, b, c) = (party(&mut api, 0), party(&mut api, 8), party(&mut api, 0));
    let mixer = api.call("mixer.create", Value::Null).unwrap()["mixer_id"].clone();
    // Clients adding and removing at once: every request answered, the
    // mixer as the last one left it.
    let workers: Vec<_> = [&a, &b, &c]
        .iter()
        .map(|p| {
            let (id, sock, mixer) = (p.id.clone(), sock.clone(), mixer.clone());
            std::thread::spawn(move || {
                let mut api = Client::connect(&sock).unwrap();
                for _ in 0..15 {
                    api.call("mixer.add", json!({"mixer_id": mixer, "endpoint_id": id}))
                        .unwrap();
                    api.call(
                        "mixer.remove",
                        json!({"mixer_id": mixer, "endpoint_id": id}),
                    )
                    .unwrap();
                }
                api.call("mixer.add", json!({"mixer_id": mixer, "endpoint_id": id}))
                    .unwrap();
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    let inv = api
        .call("inventory.list", json!({"kind": "mixers"}))
        .unwrap();
    assert_eq!(inv["items"][0]["participants"].as_array().unwrap().len(), 3);
    // B deafened, C muted with an input gain.
    api.call(
        "mixer.set",
        json!({"mixer_id": mixer, "endpoint_id": b.id, "deafened": true}),
    )
    .unwrap();
    api.call(
        "mixer.set",
        json!({"mixer_id": mixer, "endpoint_id": c.id, "muted": true, "gain_db": 6}),
    )
    .unwrap();
    drop(api);
    daemon.stop();

    let (daemon, sock) = relay(&dir, 60_100);
    let mut api = Client::connect(&sock).unwrap();
    let report = api.call("recovery.report", Value::Null).unwrap();
    assert_eq!(report["restored_mixers"], json!([mixer]), "{report}");
    assert!(report["lost"].as_array().unwrap().is_empty(), "{report}");
    let inv = api
        .call("inventory.list", json!({"kind": "mixers"}))
        .unwrap();
    assert_eq!(inv["items"][0]["mixer_id"], mixer);
    assert_eq!(inv["items"][0]["participants"].as_array().unwrap().len(), 3);
    let mut seq = 1000u16;
    let all = [&a, &b, &c];
    // A speaks: C hears it, B (deafened) does not.
    let r = round(&all, Some(0), 1000, &mut seq);
    assert!(r[2] > 1500 && r[1] < 100, "after the restart: {r:?}");
    // C speaks (muted): no one hears it.
    let r = round(&all, Some(2), 1000, &mut seq);
    assert!(r[0] < 200, "C still muted: {r:?}");
    // A new mixer does not take the restored one's id.
    let next = api.call("mixer.create", Value::Null).unwrap()["mixer_id"].clone();
    assert!(next.as_u64() > mixer.as_u64());
    drop(api);
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}
