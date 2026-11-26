#!/usr/bin/env python3
"""Call transfer with `connect`: an SBC or B2BUA completes a transfer by
joining the transferred party with the transfer target, through the
relay ports each already knows, so neither needs a re-INVITE. The
transferor's legs are detached. Attended and blind transfers, codec
conversion, SRTP on one side, a transfer of a transferred call, many
transfers across workers, restarts, and the refusals."""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import (  # noqa: E402
    Endpoint, NgError, Relay, Sdp, alaw_to_pcm, base_config, crypto_line, main, parse_crypto, parse_rtp,
    pcm_to_alaw, pcm_to_ulaw, rms, rtp, sdp, tone, ulaw_to_pcm,
)

NG = 20327
PORTS = (21400, 21799)
TONE = tone(1000, amp=8000)


class Leg:
    """One party of a call: its socket and the relay address it sends to."""

    def __init__(self, tag, pt=0):
        self.tag, self.pt = tag, pt
        self.ep = Endpoint()
        self.dst = None

    def send(self, payload=b"\x11" * 160, n=3):
        self.ep.send_rtp(self.dst, pt=self.pt, payload=payload, n=n)

    def got(self, timeout=0.3):
        return [(parse_rtp(d), src) for d, src in self.ep.recv_all(timeout)]


def call(relay, cid, caller, callee, offer_extra=None, answer_extra=None):
    """caller offers, callee answers; sets each leg's relay address."""
    o = Sdp(relay.ok("offer", call_id=cid, from_tag=caller.tag, flags=["trust-address"],
                     sdp=sdp("127.0.0.1", caller.ep.port, pts=(caller.pt,)), **(offer_extra or {}))["sdp"])
    a = Sdp(relay.ok("answer", call_id=cid, from_tag=caller.tag, to_tag=callee.tag, flags=["trust-address"],
                     sdp=sdp("127.0.0.1", callee.ep.port, pts=(callee.pt,)), **(answer_extra or {}))["sdp"])
    caller.dst, callee.dst = a.dest(), o.dest()
    return o, a


def talks(x: Leg, y: Leg, mark: int) -> bool:
    """x's packet reaches y, from the relay port y sends to."""
    x.ep.drain()
    y.ep.drain()
    payload = bytes([mark]) * 160
    x.send(payload, n=1)
    return any(p and p["ssrc"] == x.ep.ssrc and src == y.dst for p, src in y.got())


def silent(leg: Leg) -> bool:
    return not leg.got(0.2)


def attended(relay, r):
    # Alice called Bob (an agent); Bob consults Carol on a second call, then
    # completes the transfer: Alice and Carol talk, Bob is out.
    alice, bob, bob2, carol = Leg("alice"), Leg("bob"), Leg("bob-c"), Leg("carol")
    call(relay, "xfer-1", alice, bob)
    call(relay, "consult-1", bob2, carol)
    time.sleep(0.05)
    r.check(talks(alice, bob, 1) and talks(bob, alice, 2), "before: Alice and Bob talk")
    r.check(talks(bob2, carol, 3) and talks(carol, bob2, 4), "before: Bob consults Carol")

    rep = relay.ok("connect", call_id="xfer-1", from_tag="alice", to_call_id="consult-1", to_tag="carol")
    r.check("warning" not in rep, "connect of two PCMU parties needs no warning", rep.get("warning", ""))
    time.sleep(0.05)
    r.check(talks(alice, carol, 5), "after connect Alice reaches Carol, from the port Carol already knows")
    r.check(talks(carol, alice, 6), "and Carol reaches Alice, from the port Alice already knows")
    alice.ep.drain()
    alice.ep.send_rtp(alice.dst, payload=b"\x42" * 160)
    got = carol.got()
    r.check(len(got) == 1 and got[0][0]["payload"] == b"\x42" * 160 and got[0][0]["ssrc"] == alice.ep.ssrc,
            "same codec: Alice's packet reaches Carol unchanged (payload, SSRC)")
    bob.ep.drain()
    bob2.ep.drain()
    alice.send(n=2)
    carol.send(n=2)
    r.check(silent(bob) and silent(bob2), "the transferor's two legs get nothing")
    alice.ep.drain()
    carol.ep.drain()
    bob.send(n=2)
    bob2.send(n=2)
    r.check(silent(alice) and silent(carol), "and what he still sends reaches nobody")
    return alice, carol


def blind_with_conversion(relay, r):
    # A blind transfer: the SBC calls Dave (PCMA) itself and joins Erin
    # (PCMU) with him; the relay converts each one's audio for the other.
    erin, frank = Leg("erin", 0), Leg("frank", 0)
    sbc, dave = Leg("sbc", 8), Leg("dave", 8)
    call(relay, "xfer-2", erin, frank)
    call(relay, "target-2", sbc, dave)
    time.sleep(0.05)
    rep = relay.ok("connect", call_id="xfer-2", from_tag="erin", to_call_id="target-2", to_tag="dave")
    r.check("warning" not in rep, "PCMU joined with PCMA needs no warning (converted)", rep.get("warning", ""))
    time.sleep(0.05)
    erin.ep.drain()
    dave.ep.drain()
    erin.ep.send_rtp(erin.dst, pt=0, payload=pcm_to_ulaw(TONE), n=5, interval=0.02)
    got = [p for p, _ in dave.got()]
    want = rms(TONE)
    levels = [rms(alaw_to_pcm(p["payload"])) for p in got if p and p["pt"] == 8]
    r.check(len(got) >= 4 and all(p["pt"] == 8 for p in got), "Dave gets Erin's audio as PCMA",
            str([p["pt"] for p in got]))
    r.check(levels and all(abs(v - want) < want * 0.15 for v in levels[1:]), "at the level she sent it",
            f"{levels[:3]} vs {want}")
    dave.ep.send_rtp(dave.dst, pt=8, payload=pcm_to_alaw(TONE), n=5, interval=0.02)
    got = [p for p, _ in erin.got()]
    levels = [rms(ulaw_to_pcm(p["payload"])) for p in got if p and p["pt"] == 0]
    r.check(len(got) >= 4 and all(p["pt"] == 0 for p in got), "and Erin gets Dave's as PCMU")
    r.check(levels and all(abs(v - want) < want * 0.15 for v in levels[1:]), "at his level",
            f"{levels[:3]} vs {want}")
    return erin, dave


def into_srtp(relay, r):
    # Grace (plain RTP) is transferred to Heidi, whose phone uses SDES-SRTP
    # towards the relay: Grace's audio reaches Heidi encrypted with the
    # relay's key, Heidi's reaches Grace in the clear.
    grace, ivan, judy = Leg("grace"), Leg("ivan"), Leg("judy")
    call(relay, "xfer-3", grace, ivan)
    heidi = Leg("heidi")
    line, heidi_tx = crypto_line(1)
    o = Sdp(relay.ok("offer", call_id="target-3", from_tag="heidi", flags=["trust-address"],
                     transport_protocol="RTP/AVP",
                     sdp=sdp("127.0.0.1", heidi.ep.port, proto="RTP/SAVP", extra=[line]))["sdp"])
    a = Sdp(relay.ok("answer", call_id="target-3", from_tag="heidi", to_tag="judy", flags=["trust-address"],
                     sdp=sdp("127.0.0.1", judy.ep.port))["sdp"])
    heidi.dst, judy.dst = a.dest(), o.dest()
    _, _, relay_tx = parse_crypto(a.media[0].attr("crypto")[0])
    time.sleep(0.05)
    relay.ok("connect", call_id="xfer-3", from_tag="grace", to_call_id="target-3", to_tag="heidi")
    time.sleep(0.05)
    grace.ep.send_rtp(grace.dst, payload=b"\x33" * 160, n=3)
    dec = [relay_tx.unprotect(d) for d, _ in heidi.ep.recv_all(0.3)]
    r.check(len(dec) == 3 and all(d and parse_rtp(d)["payload"] == b"\x33" * 160 for d in dec),
            "a plain party joined with an SRTP one: its audio arrives encrypted with the relay's key",
            f"{sum(1 for d in dec if d)}/{len(dec)}")
    for _ in range(3):
        heidi.ep.send(heidi_tx.protect(rtp(0, heidi.ep.seq, heidi.ep.ts, heidi.ep.ssrc, b"\x44" * 160)), heidi.dst)
        heidi.ep.seq += 1
        heidi.ep.ts += 160
    got = [p for p, _ in grace.got()]
    r.check(len(got) == 3 and all(p["payload"] == b"\x44" * 160 for p in got),
            "and the SRTP party's audio reaches the plain one decrypted")


def transfer_again(relay, r, alice, carol):
    # Carol transfers Alice on to Mallory: Alice's second transfer.
    carol2, mallory = Leg("carol-m"), Leg("mallory")
    call(relay, "consult-2", carol2, mallory)
    time.sleep(0.05)
    relay.ok("connect", call_id="xfer-1", from_tag="alice", to_call_id="consult-2", to_tag="mallory")
    time.sleep(0.05)
    r.check(talks(alice, mallory, 7) and talks(mallory, alice, 8), "a transferred party can be transferred again")
    carol.ep.drain()
    alice.send(n=2)
    r.check(silent(carol), "and the previous target is detached: Alice no longer reaches her")
    alice.ep.drain()
    carol.send(n=2)
    r.check(silent(alice), "nor does she reach Alice")
    return mallory


def many(relay, r, n=10):
    """Ten transfers at once: with two media workers some pairs of calls
    are on the same worker and some across both."""
    pairs = []
    for i in range(n):
        a, b, c, d = Leg(f"a{i}"), Leg(f"b{i}"), Leg(f"c{i}"), Leg(f"d{i}")
        call(relay, f"many-x{i}", a, b)
        call(relay, f"many-t{i}", c, d)
        pairs.append((a, d))
    time.sleep(0.05)
    for i, (a, d) in enumerate(pairs):
        relay.ok("connect", call_id=f"many-x{i}", from_tag=a.tag, to_call_id=f"many-t{i}", to_tag=d.tag)
    time.sleep(0.1)
    ok = sum(1 for a, d in pairs if talks(a, d, 9) and talks(d, a, 10))
    r.check(ok == n, f"{n} transfers at once all connect, both ways", f"{ok}/{n}")
    return pairs


def restart(relay, r, joined):
    relay.stop()
    relay.start()
    time.sleep(0.2)
    ok = sum(1 for a, d in joined if talks(a, d, 11) and talks(d, a, 12))
    r.check(ok == len(joined), "after a restart every transferred pair still talks", f"{ok}/{len(joined)}")


def endings(relay, r, erin, dave):
    relay.ok("delete", call_id="target-2")
    time.sleep(0.05)
    erin.ep.drain()
    erin.send(n=2)
    r.check(silent(dave), "when the target's call ends nothing reaches the target any more")
    r.check(silent(erin), "and the transferred party is left alone (no media echoes back)")
    q = relay.ok("query", call_id="xfer-2")
    r.check(q.get("result") == "ok", "the transferred party's call still exists after the target's ends")


def refusals(relay, r):
    for what, opts, want in [
        ("connect to an unknown call", dict(call_id="xfer-1", from_tag="alice", to_call_id="nope", to_tag="x"), ""),
        ("connect to an unknown party", dict(call_id="xfer-1", from_tag="alice", to_call_id="consult-2",
                                             to_tag="nobody"), ""),
        ("connect from an unknown call", dict(call_id="nope", from_tag="alice", to_call_id="consult-2",
                                              to_tag="mallory"), ""),
        ("connect without a to-tag", dict(call_id="xfer-1", from_tag="alice", to_call_id="consult-2"), ""),
        ("several sources without directional", dict(call_id="xfer-1", from_tags=["alice", "bob"],
                                                     to_call_id="consult-2", to_tag="mallory"), ""),
    ]:
        try:
            relay.ok("connect", **opts)
            r.check(False, f"{what} is refused")
        except NgError as e:
            r.check(want in str(e), f"{what} is refused", str(e))
    try:
        relay.ok("connect", call_id="xfer-1", from_tag="alice", to_call_id="xfer-1", to_tag="alice")
        r.finding("connect of a party to itself is accepted")
    except NgError as e:
        r.check(True, "connect of a party to itself is refused", str(e))


def scenario(r):
    relay = Relay(base_config(NG, ports=PORTS, sessions='state_file = "STATE"'), NG, "transfer")
    state = os.path.join(relay.dir, "state.json")
    with open(relay.config_path) as f:
        text = f.read()
    with open(relay.config_path, "w") as f:
        f.write(text.replace("STATE", state))
    try:
        relay.start()
        alice, carol = attended(relay, r)
        erin, dave = blind_with_conversion(relay, r)
        into_srtp(relay, r)
        mallory = transfer_again(relay, r, alice, carol)
        pairs = many(relay, r)
        time.sleep(1.2)  # the state file is written at most once a second
        restart(relay, r, [(alice, mallory), (erin, dave)] + pairs)
        refusals(relay, r)
        endings(relay, r, erin, dave)
    finally:
        relay.cleanup()


if __name__ == "__main__":
    main(scenario)
