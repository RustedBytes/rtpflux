//! Calls with more than two parties: several dialogs in one call-id, a
//! party in two of them at once, labels as selectors, `query` per party.

use crate::common::*;
use rtpflux_ng::bencode::Value;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

const CALL: &[u8] = b"three@example";

/// An `ng` client with its cookie counter.
struct Ng {
    client: UdpSocket,
    srv: SocketAddr,
    n: std::cell::Cell<u32>,
}

impl Ng {
    fn new(srv: SocketAddr) -> Self {
        Ng {
            client: endpoint(),
            srv,
            n: std::cell::Cell::new(0),
        }
    }

    /// Send `pairs` (with `call-id`); (result, sdp or error, raw reply).
    fn raw(&self, command: &[u8], pairs: &[(&str, V<'_>)]) -> (String, Vec<u8>, Vec<u8>) {
        self.n.set(self.n.get() + 1);
        let mut all = vec![("command", V::S(command)), ("call-id", V::S(CALL))];
        all.extend(pairs.iter().map(|(k, v)| (*k, *v)));
        call(
            &self.client,
            self.srv,
            &request(&format!("p{}", self.n.get()), &all),
        )
    }

    /// As [`Ng::raw`], which must succeed: the SDP, or the raw reply.
    fn ok(&self, command: &[u8], pairs: &[(&str, V<'_>)]) -> Vec<u8> {
        let (r, out, raw) = self.raw(command, pairs);
        assert_eq!(
            r,
            "ok",
            "{}: {}",
            String::from_utf8_lossy(command),
            String::from_utf8_lossy(&out)
        );
        if out.is_empty() { raw } else { out }
    }

    /// An offer (`from` → `to`, if in a dialog) or answer of `s`'s SDP,
    /// with more options; the relay's address in the SDP returned.
    fn sdp(
        &self,
        command: &[u8],
        (from, to): (&[u8], Option<&[u8]>),
        s: &UdpSocket,
        more: &[(&str, V<'_>)],
    ) -> SocketAddr {
        let sdp = sdp_for(s.local_addr().unwrap().port());
        let mut p = vec![
            ("from-tag", V::S(from)),
            ("sdp", V::S(&sdp)),
            ("flags", V::L(&[b"trust-address"])),
            ("endpoint-learning", V::S(b"off")),
        ];
        if let Some(t) = to {
            p.push(("to-tag", V::S(t)));
        }
        p.extend(more.iter().copied());
        relay_addr(&self.ok(command, &p))
    }
}

/// Whether a packet `x` sends to `to` reaches `y`.
fn reaches(x: &UdpSocket, to: SocketAddr, y: &UdpSocket, seq: u16) -> bool {
    let mut buf = [0u8; 2048];
    x.send_to(&rtp(seq), to).unwrap();
    y.recv_from(&mut buf)
        .is_ok_and(|(n, _)| buf[..n] == rtp(seq)[..])
}

fn quick(sockets: &[&UdpSocket]) {
    for s in sockets {
        s.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
    }
}

/// A party's entry in a `query` reply.
fn party<'a>(reply: Value<'a>, tag: &[u8]) -> Value<'a> {
    at(reply, &[b"tags", tag]).unwrap_or_else(|| panic!("{}", String::from_utf8_lossy(tag)))
}

fn text<'a>(v: Value<'a>, path: &[&[u8]]) -> &'a [u8] {
    match at(v, path) {
        Some(Value::Bytes(b)) => b,
        other => panic!("{path:?}: {other:?}"),
    }
}

fn count(v: Value<'_>, path: &[&[u8]]) -> usize {
    match at(v, path) {
        Some(Value::List(l)) => l.iter().count(),
        other => panic!("{path:?}: {other:?}"),
    }
}

/// Alice calls Bob; Carol calls Alice in the same call-id. Alice is in two
/// dialogs: re-offers name theirs by `to-tag`, each keeps its ports and
/// media; labels select parties (and one flow) in `block media`; `query`
/// has each party once, with its label and all its media.
#[test]
#[allow(clippy::too_many_lines)] // One call, step by step.
fn a_party_in_two_dialogs() {
    let srv = server(62_600);
    let ng = Ng::new(srv.addr);
    let (alice, bob, carol) = (endpoint(), endpoint(), endpoint());
    // A second socket of Alice's for her dialog with Carol.
    let alice2 = endpoint();
    let label = |l: &'static [u8]| [("label", V::S(l))];
    let bob_to = ng.sdp(b"offer", (b"a", None), &alice, &label(b"caller"));
    let alice_to_bob = ng.sdp(b"answer", (b"a", Some(b"b")), &bob, &label(b"callee"));
    let alice_to = ng.sdp(b"offer", (b"c", None), &carol, &label(b"consult"));
    let carol_to = ng.sdp(b"answer", (b"c", Some(b"a")), &alice2, &[]);
    std::thread::sleep(Duration::from_millis(50));
    quick(&[&alice, &bob, &carol, &alice2]);
    let talk = |seq: u16| {
        assert!(reaches(&alice, alice_to_bob, &bob, seq), "alice -> bob");
        assert!(reaches(&bob, bob_to, &alice, seq), "bob -> alice");
        assert!(reaches(&alice2, alice_to, &carol, seq), "alice -> carol");
        assert!(reaches(&carol, carol_to, &alice2, seq), "carol -> alice");
    };
    talk(1);

    // Alice re-offers to Carol: their dialog (roles swapped), same ports.
    let to_carol = ng.sdp(b"offer", (b"a", Some(b"c")), &alice2, &[]);
    assert_eq!(to_carol, carol_to, "Carol keeps the relay's port");
    let to_alice = ng.sdp(b"answer", (b"a", Some(b"c")), &carol, &[]);
    assert_eq!(to_alice, alice_to);
    // And to Bob: theirs.
    assert_eq!(ng.sdp(b"offer", (b"a", Some(b"b")), &alice, &[]), bob_to);
    assert_eq!(
        ng.sdp(b"answer", (b"a", Some(b"b")), &bob, &[]),
        alice_to_bob
    );
    // Carol re-offers to Alice.
    assert_eq!(ng.sdp(b"offer", (b"c", Some(b"a")), &carol, &[]), alice_to);
    assert_eq!(
        ng.sdp(b"answer", (b"c", Some(b"a")), &alice2, &[]),
        carol_to
    );
    std::thread::sleep(Duration::from_millis(50));
    talk(2);

    // `query`: each party once, its label, its peers, all its media.
    let raw = ng.ok(b"query", &[]);
    let q = reply_dict(&raw);
    let tags = match at(q, &[b"tags"]) {
        Some(Value::Dict(d)) => d.iter().count(),
        other => panic!("{other:?}"),
    };
    assert_eq!(tags, 3, "{}", String::from_utf8_lossy(&raw));
    let a = party(q, b"a");
    assert_eq!(text(a, &[b"label"]), b"caller");
    assert_eq!(count(a, &[b"medias"]), 2, "a medias");
    assert_eq!(count(a, &[b"subscriptions"]), 2, "a's peers");
    assert_eq!(text(party(q, b"b"), &[b"label"]), b"callee");
    assert_eq!(text(party(q, b"b"), &[b"in dialogue with"]), b"a");
    assert_eq!(text(party(q, b"c"), &[b"label"]), b"consult");
    assert_eq!(text(party(q, b"c"), &[b"in dialogue with"]), b"a");
    // Limited to a party, by label: its dialogs only.
    let raw = ng.ok(b"query", &[("label", V::S(b"callee"))]);
    assert!(at(reply_dict(&raw), &[b"tags", b"c"]).is_none());

    // `block media` from the caller to the callee only, by labels.
    ng.ok(
        b"block media",
        &[("label", V::S(b"caller")), ("to-label", V::S(b"callee"))],
    );
    std::thread::sleep(Duration::from_millis(30));
    assert!(!reaches(&alice, alice_to_bob, &bob, 3), "blocked to bob");
    assert!(reaches(&alice2, alice_to, &carol, 3), "not to carol");
    assert!(reaches(&bob, bob_to, &alice, 3), "nor bob's");
    ng.ok(b"unblock media", &[("from-label", V::S(b"caller"))]);
    std::thread::sleep(Duration::from_millis(30));
    talk(4);

    // An unknown label is refused, by name.
    let (r, why, _) = ng.raw(b"block media", &[("label", V::S(b"nobody"))]);
    assert_eq!(
        (r.as_str(), why.as_slice()),
        ("error", &b"no party with label nobody"[..])
    );
    // `play DTMF` needs a party (by tag, label or `all`).
    let (r, why, _) = ng.raw(b"play DTMF", &[("code", V::S(b"1"))]);
    assert_eq!(r, "error", "{}", String::from_utf8_lossy(&why));

    // Ending Alice's dialog with Bob leaves hers with Carol.
    ng.ok(b"delete", &[("from-tag", V::S(b"b"))]);
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        !reaches(&alice, alice_to_bob, &bob, 5),
        "bob's dialog ended"
    );
    assert!(reaches(&alice2, alice_to, &carol, 5), "carol's goes on");
    assert!(reaches(&carol, carol_to, &alice2, 5));
}

/// A B2BUA joins two parties that are each in a dialog of the call
/// (`from-tag` Alice, `to-tag` Carol): a new dialog between them, the
/// others left as they are; a re-offer from Carol finds it.
#[test]
fn a_dialog_between_two_parties_of_other_dialogs() {
    let srv = server(62_800);
    let ng = Ng::new(srv.addr);
    let (alice, bob, carol, dave) = (endpoint(), endpoint(), endpoint(), endpoint());
    let (alice2, carol2) = (endpoint(), endpoint());
    let bob_to = ng.sdp(b"offer", (b"a", None), &alice, &[]);
    let alice_to_bob = ng.sdp(b"answer", (b"a", Some(b"b")), &bob, &[]);
    let dave_to = ng.sdp(b"offer", (b"c", None), &carol, &[]);
    let carol_to_dave = ng.sdp(b"answer", (b"c", Some(b"d")), &dave, &[]);
    // Alice and Carol: a dialog of their own.
    let carol_to = ng.sdp(b"offer", (b"a", Some(b"c")), &alice2, &[]);
    let alice_to = ng.sdp(b"answer", (b"a", Some(b"c")), &carol2, &[]);
    assert!(
        ![bob_to, alice_to_bob, dave_to, carol_to_dave].contains(&carol_to),
        "new ports"
    );
    std::thread::sleep(Duration::from_millis(50));
    quick(&[&alice, &bob, &carol, &dave, &alice2, &carol2]);
    both_ways(&alice, alice_to_bob, &bob, bob_to, 1);
    both_ways(&carol, carol_to_dave, &dave, dave_to, 1);
    both_ways(&alice2, alice_to, &carol2, carol_to, 1);
    // Carol re-offers to Alice: that dialog, its ports.
    assert_eq!(ng.sdp(b"offer", (b"c", Some(b"a")), &carol2, &[]), alice_to);
    assert_eq!(
        ng.sdp(b"answer", (b"c", Some(b"a")), &alice2, &[]),
        carol_to
    );
    // And to Dave: theirs.
    assert_eq!(ng.sdp(b"offer", (b"c", Some(b"d")), &carol, &[]), dave_to);
    std::thread::sleep(Duration::from_millis(50));
    both_ways(&alice2, alice_to, &carol2, carol_to, 2);
    both_ways(&alice, alice_to_bob, &bob, bob_to, 2);
    // `query`: four parties, Alice and Carol in two dialogs each.
    let raw = ng.ok(b"query", &[]);
    let q = reply_dict(&raw);
    for (tag, medias) in [(&b"a"[..], 2), (b"b", 1), (b"c", 2), (b"d", 1)] {
        assert_eq!(count(party(q, tag), &[b"medias"]), medias);
    }
    // `play media` to every party (`all`): no G.711 file here, so the
    // error is about the file, not about the parties.
    let (r, why, _) = ng.raw(
        b"play media",
        &[
            ("flags", V::L(&[b"all"])),
            ("file", V::S(b"/nonexistent.wav")),
        ],
    );
    assert_eq!(r, "error");
    assert!(
        !String::from_utf8_lossy(&why).contains("listener"),
        "{}",
        String::from_utf8_lossy(&why)
    );
}

/// `subscribe request`: the source by `label`, the subscriber labelled by
/// `set-label`; `query` shows it under its label.
#[test]
fn subscriptions_by_label() {
    let srv = server(63_000);
    let ng = Ng::new(srv.addr);
    let (alice, bob) = (endpoint(), endpoint());
    ng.sdp(
        b"offer",
        (b"a", None),
        &alice,
        &[("label", V::S(b"caller"))],
    );
    ng.sdp(
        b"answer",
        (b"a", Some(b"b")),
        &bob,
        &[("label", V::S(b"callee"))],
    );
    let (r, _, raw) = ng.raw(
        b"subscribe request",
        &[
            ("label", V::S(b"callee")),
            ("set-label", V::S(b"recorder")),
            ("to-tag", V::S(b"rec")),
        ],
    );
    assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&raw));
    let reply = reply_dict(&raw);
    assert_eq!(text(reply, &[b"from-tags", b"0"]), b"b");
    let raw = ng.ok(b"query", &[]);
    let q = reply_dict(&raw);
    assert_eq!(
        text(party(q, b"rec"), &[b"label"]),
        b"recorder",
        "{}",
        String::from_utf8_lossy(&raw)
    );
    // The recorder's label selects it, as any party's.
    let raw = ng.ok(b"query", &[("label", V::S(b"recorder"))]);
    assert!(at(reply_dict(&raw), &[b"tags", b"rec"]).is_some());
}

/// `connect` with `directional`: Alice's and Bob's media are copied to
/// Carol, who keeps hearing Dave; nobody is detached. `unsubscribe` naming
/// Carol stops the copies; `bidirectional` copies Carol back to Alice. On
/// one worker and across two (dialogs go to workers in turn).
#[test]
#[allow(clippy::too_many_lines)] // One call, step by step.
fn directional_connect_copies() {
    for (port, workers) in [(63_200, 1), (63_400, 2)] {
        let srv = server_full(
            port,
            "[[interface]]\nname = \"pub\"\naddress = \"127.0.0.1\"",
            "",
            workers,
        );
        let ng = Ng::new(srv.addr);
        let (alice, bob, carol, dave) = (endpoint(), endpoint(), endpoint(), endpoint());
        let bob_to = ng.sdp(b"offer", (b"a", None), &alice, &[]);
        let alice_to = ng.sdp(b"answer", (b"a", Some(b"b")), &bob, &[]);
        let dave_to = ng.sdp(b"offer", (b"c", None), &carol, &[]);
        let carol_to = ng.sdp(b"answer", (b"c", Some(b"d")), &dave, &[]);
        std::thread::sleep(Duration::from_millis(50));
        quick(&[&alice, &bob, &carol, &dave]);
        // Several sources need `directional`.
        let (r, why, _) = ng.raw(
            b"connect",
            &[("from-tags", V::L(&[b"a", b"b"])), ("to-tag", V::S(b"c"))],
        );
        assert_eq!(r, "error", "{}", String::from_utf8_lossy(&why));
        ng.ok(
            b"connect",
            &[
                ("from-tags", V::L(&[b"a", b"b"])),
                ("to-tag", V::S(b"c")),
                ("flags", V::L(&[b"directional"])),
            ],
        );
        std::thread::sleep(Duration::from_millis(50));
        let mut buf = [0u8; 2048];
        let got = |s: &UdpSocket, buf: &mut [u8]| s.recv_from(buf).ok().map(|(n, _)| n);
        // Alice: to Bob, and a copy to Carol.
        alice.send_to(&rtp(1), alice_to).unwrap();
        assert!(got(&bob, &mut buf).is_some(), "{workers}: bob hears alice");
        assert_eq!(
            got(&carol, &mut buf),
            Some(rtp(1).len()),
            "{workers}: carol too"
        );
        // Bob: to Alice, and a copy to Carol.
        bob.send_to(&rtp(2), bob_to).unwrap();
        assert!(
            got(&alice, &mut buf).is_some(),
            "{workers}: alice hears bob"
        );
        assert!(
            got(&carol, &mut buf).is_some(),
            "{workers}: carol hears bob"
        );
        // Carol keeps Dave, and is copied to nobody.
        both_ways(&carol, carol_to, &dave, dave_to, 3);
        assert!(got(&alice, &mut buf).is_none() && got(&bob, &mut buf).is_none());

        // `unsubscribe` naming Carol: the copies stop.
        ng.ok(b"unsubscribe", &[("to-tag", V::S(b"c"))]);
        std::thread::sleep(Duration::from_millis(50));
        alice.send_to(&rtp(4), alice_to).unwrap();
        assert!(got(&bob, &mut buf).is_some());
        assert!(got(&carol, &mut buf).is_none(), "{workers}: no copy");

        // `bidirectional`: Carol hears Alice, Alice hears Carol (and Bob).
        ng.ok(
            b"connect",
            &[
                ("from-tag", V::S(b"a")),
                ("to-tag", V::S(b"c")),
                ("flags", V::L(&[b"directional", b"bidirectional"])),
            ],
        );
        std::thread::sleep(Duration::from_millis(50));
        alice.send_to(&rtp(5), alice_to).unwrap();
        assert!(got(&bob, &mut buf).is_some() && got(&carol, &mut buf).is_some());
        carol.send_to(&rtp(6), carol_to).unwrap();
        assert!(
            got(&dave, &mut buf).is_some(),
            "{workers}: dave hears carol"
        );
        assert!(got(&alice, &mut buf).is_some(), "{workers}: alice too");
        // Alice and Bob's dialog ends, and its copies with it; Carol and
        // Dave go on.
        ng.ok(b"delete", &[("from-tag", V::S(b"b"))]);
        std::thread::sleep(Duration::from_millis(50));
        carol.send_to(&rtp(7), carol_to).unwrap();
        assert!(got(&dave, &mut buf).is_some());
        assert!(
            got(&alice, &mut buf).is_none(),
            "{workers}: no copy to alice"
        );
        both_ways(&carol, carol_to, &dave, dave_to, 8);
        ng.ok(b"delete", &[]);
    }
}

/// `all` of block and silence: `except-offer-answer` acts on a party's
/// copies only (Carol's copy of Alice), `offer-answer` (and none) on what
/// it sends its dialog's other party, `flows` on both, `all` on the whole
/// call.
#[test]
#[allow(clippy::too_many_lines)] // One call, step by step.
fn block_scopes_flows_and_copies() {
    let srv = server(65_100);
    let ng = Ng::new(srv.addr);
    let (alice, bob, carol, dave) = (endpoint(), endpoint(), endpoint(), endpoint());
    ng.sdp(b"offer", (b"a", None), &alice, &[]);
    let alice_to = ng.sdp(b"answer", (b"a", Some(b"b")), &bob, &[]);
    ng.sdp(b"offer", (b"c", None), &carol, &[]);
    let carol_to = ng.sdp(b"answer", (b"c", Some(b"d")), &dave, &[]);
    ng.ok(
        b"connect",
        &[
            ("from-tag", V::S(b"a")),
            ("to-tag", V::S(b"c")),
            ("flags", V::L(&[b"directional"])),
        ],
    );
    std::thread::sleep(Duration::from_millis(50));
    quick(&[&alice, &bob, &carol, &dave]);
    // What bob and carol get of a packet of alice's (its payload's first
    // octet).
    let send = |seq: u16| {
        let pkt = rtp_with(0, seq, &[0x11; 160]);
        alice.send_to(&pkt, alice_to).unwrap();
        let got = |s: &UdpSocket| {
            let mut buf = [0u8; 2048];
            s.recv_from(&mut buf).ok().map(|_| buf[12])
        };
        (got(&bob), got(&carol))
    };
    let mut buf = [0u8; 2048];
    assert_eq!(send(1), (Some(0x11), Some(0x11)));
    let block = |cmd: &'static [u8], all: &'static [u8]| {
        ng.ok(cmd, &[("from-tag", V::S(b"a")), ("all", V::S(all))]);
        std::thread::sleep(Duration::from_millis(30));
    };
    block(b"block media", b"except-offer-answer");
    assert_eq!(send(2), (Some(0x11), None), "the copy only");
    block(b"unblock media", b"except-offer-answer");
    assert_eq!(send(3), (Some(0x11), Some(0x11)));
    block(b"block media", b"offer-answer");
    assert_eq!(send(4), (None, Some(0x11)), "its own media only");
    block(b"unblock media", b"offer-answer");
    block(b"block media", b"flows");
    assert_eq!(send(5), (None, None), "both");
    block(b"unblock media", b"flows");
    assert_eq!(send(6), (Some(0x11), Some(0x11)));
    // Silenced copies (μ-law silence is 0xff).
    block(b"silence media", b"except-offer-answer");
    assert_eq!(send(7), (Some(0x11), Some(0xff)), "the copy silenced");
    block(b"unsilence media", b"except-offer-answer");
    assert_eq!(send(8), (Some(0x11), Some(0x11)));
    // `all: all` is the whole call, whatever the tag.
    block(b"block media", b"all");
    carol.send_to(&rtp(9), carol_to).unwrap();
    assert!(dave.recv_from(&mut buf).is_err(), "carol blocked too");
    block(b"unblock media", b"all");
    assert_eq!(send(10), (Some(0x11), Some(0x11)));
    // Values that are none are refused; telephone events have no copies.
    let (r, why, _) = ng.raw(b"block media", &[("all", V::S(b"frob"))]);
    assert_eq!(r, "error", "{}", String::from_utf8_lossy(&why));
    let (r, _, _) = ng.raw(
        b"block DTMF",
        &[("from-tag", V::S(b"a")), ("all", V::S(b"flows"))],
    );
    assert_eq!(r, "error");
}
