//! `runtime.receive`: calls relay the same with `io_uring` (the default,
//! which the whole suite uses unless `RTPFLUX_TEST_RECEIVE=recvmmsg`) and
//! with `recvmmsg`; here, always, both: media both ways on two workers, and
//! a slot reused after its call ended.

use crate::common::*;
use std::time::Duration;

#[test]
fn calls_relay_with_io_uring() {
    calls_relay(43_000, "io_uring");
}

#[test]
fn calls_relay_with_recvmmsg() {
    calls_relay(43_200, "recvmmsg");
}

fn calls_relay(port: u16, receive: &str) {
    let srv = server_receiving(
        port,
        "[[interface]]\nname = \"pub\"\naddress = \"127.0.0.1\"",
        "",
        (2, receive),
    );
    // The workers did take io_uring (it falls back to recvmmsg quietly
    // otherwise): their rings are files of this process.
    let rings = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
        .filter(|l| l.to_string_lossy().contains("io_uring"))
        .count();
    if receive == "io_uring" {
        assert!(rings >= 2, "{rings} io_uring rings");
    }
    let client = endpoint();
    for (round, call_id) in [(0u16, &b"uring-1"[..]), (1, b"uring-2"), (2, b"uring-1")] {
        let (a, b) = (endpoint(), endpoint());
        let send = |cookie: &str,
                    cmd: &'static [u8],
                    tags: (&'static [u8], Option<&'static [u8]>),
                    s: &std::net::UdpSocket| {
            let sdp = sdp_for(s.local_addr().unwrap().port());
            let mut p = vec![
                ("command", V::S(cmd)),
                ("call-id", V::S(call_id)),
                ("from-tag", V::S(tags.0)),
                ("sdp", V::S(&sdp)),
                ("flags", V::L(&[b"trust-address"])),
                ("endpoint-learning", V::S(b"off")),
            ];
            if let Some(t) = tags.1 {
                p.push(("to-tag", V::S(t)));
            }
            let (r, out, _) = call(&client, srv.addr, &request(cookie, &p));
            assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&out));
            relay_addr(&out)
        };
        let for_b = send(&format!("o{round}"), b"offer", (b"f", None), &a);
        let for_a = send(&format!("a{round}"), b"answer", (b"f", Some(b"t")), &b);
        std::thread::sleep(Duration::from_millis(50));
        for seq in 0..20 {
            both_ways(&a, for_a, &b, for_b, round * 100 + seq);
        }
        // The call ends; the next round's slots may be these.
        let (r, _, _) = call(
            &client,
            srv.addr,
            &request(
                &format!("d{round}"),
                &[("command", V::S(b"delete")), ("call-id", V::S(call_id))],
            ),
        );
        assert_eq!(r, "ok");
        std::thread::sleep(Duration::from_millis(50));
    }
}
