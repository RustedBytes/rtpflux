#!/usr/bin/env python3
"""Callers behind NAT: the SDP carries an address media never comes
from; the relay must learn ("latch") the real source. Also: the
endpoint-learning modes, strict-source, a NAT that rebinds mid-call, and
a third party injecting packets."""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import Endpoint, Relay, Sdp, base_config, main, sdp  # noqa: E402

NG = 20302
# What a NATed phone writes into its SDP: an address the relay can send to
# but where nobody listens (kept on loopback so nothing leaves the host).
PRIVATE = "127.0.0.250"


def call(relay, cid, alice_sdp_addr, alice_sdp_port, bob, learning=None, flags=(), received_from=None):
    opts = {}
    if learning:
        opts["endpoint_learning"] = learning
    if flags:
        opts["flags"] = list(flags)
    if received_from:
        opts["received_from"] = ["IP4", received_from]
    o = Sdp(relay.ok("offer", call_id=cid, from_tag="alice", sdp=sdp(alice_sdp_addr, alice_sdp_port), **opts)["sdp"])
    a = Sdp(relay.ok("answer", call_id=cid, from_tag="alice", to_tag="bob", sdp=sdp("127.0.0.1", bob.port),
                     flags=["trust-address"])["sdp"])
    return o, a


def scenario(r):
    with Relay(base_config(NG, ports=(22000, 22399)), NG, "nat") as relay:
        # --- received-from replaces the private SDP address
        o = relay.ok("offer", call_id="rf", from_tag="a", sdp=sdp("192.168.1.20", 4000),
                     received_from=["IP4", "198.51.100.7"])
        relay.ok("answer", call_id="rf", from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", 4002),
                 flags=["trust-address"])
        q = relay.ok("query", call_id="rf")
        ep = q["tags"]["a"]["medias"][0]["streams"][0].get("endpoint", {})
        r.check(ep.get("address") == "198.51.100.7",
                "without trust-address, received-from replaces the SDP's private address", str(ep))
        relay.ok("delete", call_id="rf")

        # --- heuristic (default): alice's packets come from her NAT's
        # public side, not from the SDP address; bob's audio must follow.
        alice, bob = Endpoint(), Endpoint()
        o, a = call(relay, "heur", PRIVATE, 4000, bob, flags=["trust-address"])
        # alice sends to the port the relay gave her (the answer's).
        alice.send_rtp(a.dest(), n=3, interval=0.02)
        got = bob.recv_all(0.4)
        r.check(len(got) == 3, "alice's media reaches bob before latching", str(len(got)))
        bob.send_rtp(o.dest(), n=5, interval=0.02)
        got = alice.recv_all(0.5)
        r.check(len(got) == 5, "heuristic: bob's media follows alice's real (NATed) source", str(len(got)))

        # A NAT rebinding after the 3 s learning window: a new source port.
        time.sleep(3.2)
        alice2 = Endpoint()  # the same phone, a new NAT mapping
        alice2.ssrc = alice.ssrc
        alice2.send_rtp(a.dest(), n=5, interval=0.02)
        got_bob = bob.recv_all(0.4)
        bob.send_rtp(o.dest(), n=5, interval=0.02)
        old, new = alice.recv_all(0.4), alice2.recv_all(0.4)
        r.check(len(got_bob) == 5, "after a NAT rebinding, alice's media still reaches bob", str(len(got_bob)))
        if len(new) == 0 and len(old) == 5:
            r.finding("heuristic: after the 3 s learning window a NAT rebinding (new source port) is NOT "
                      "followed: bob's audio keeps going to the old mapping, so the call turns one-way "
                      "(the default: 'after that, the choice is fixed'; the media-handover flag follows it, "
                      "checked next)")
        elif len(new) == 5:
            r.check(True, "heuristic: a NAT rebinding is followed")
        relay.ok("delete", call_id="heur")

        # --- media-handover: the same rebinding is followed
        alice, bob = Endpoint(), Endpoint()
        o, a = call(relay, "handover", PRIVATE, 4000, bob, flags=["trust-address", "media-handover"])
        alice.send_rtp(a.dest(), n=3, interval=0.02)
        bob.recv_all(0.3)
        time.sleep(3.2)
        alice2 = Endpoint()
        alice2.ssrc = alice.ssrc
        alice2.send_rtp(a.dest(), n=5, interval=0.02)
        got_bob = bob.recv_all(0.4)
        bob.send_rtp(o.dest(), n=5, interval=0.02)
        old, new = alice.recv_all(0.4), alice2.recv_all(0.4)
        r.check(len(got_bob) == 5 and len(new) == 5 and len(old) == 0,
                "media-handover: after a NAT rebinding bob's audio follows alice's new mapping",
                f"bob got {len(got_bob)}, new mapping {len(new)}, old {len(old)}")
        relay.ok("delete", call_id="handover")

        # --- a third party injects media into a latched call (no strict-source)
        alice, bob, mallory = Endpoint(), Endpoint(), Endpoint("127.0.0.3")
        o, a = call(relay, "inject", PRIVATE, 4000, bob, flags=["trust-address"], learning="immediate")
        alice.send_rtp(a.dest(), n=3)
        bob.recv_all(0.3)
        mallory.send_rtp(a.dest(), n=5, payload=b"\x00" * 160)
        injected = bob.recv_all(0.4)
        if injected:
            r.finding(f"without strict-source, a third party's packets to a latched port are relayed "
                      f"({len(injected)}/5 reached bob): use strict-source where injection matters")
        else:
            r.check(True, "packets from an unknown source are dropped once latched")
        relay.ok("delete", call_id="inject")

        # --- strict-source drops them
        alice, bob, mallory = Endpoint(), Endpoint(), Endpoint("127.0.0.3")
        o, a = call(relay, "strict", PRIVATE, 4000, bob, flags=["trust-address", "strict-source"],
                    learning="immediate")
        alice.send_rtp(a.dest(), n=3)
        r.check(len(bob.recv_all(0.3)) == 3, "strict-source: the first source is relayed")
        mallory.send_rtp(a.dest(), n=5, payload=b"\x00" * 160)
        r.check(len(bob.recv_all(0.4)) == 0, "strict-source: another source is dropped")
        bob.send_rtp(o.dest(), n=3)
        r.check(len(alice.recv_all(0.3)) == 3 and len(mallory.recv_all(0.2)) == 0,
                "strict-source: bob's media still goes to alice, never to the injector")
        relay.ok("delete", call_id="strict")

        # --- immediate: the very first packet wins, even a wrong one
        alice, bob, early = Endpoint(), Endpoint(), Endpoint("127.0.0.4")
        o, a = call(relay, "imm", "127.0.0.1", alice.port, bob, flags=["trust-address"], learning="immediate")
        early.send_rtp(a.dest(), n=1)
        alice.send_rtp(a.dest(), n=2)
        bob.recv_all(0.3)
        bob.send_rtp(o.dest(), n=3)
        r.check(len(early.recv_all(0.3)) == 3 and len(alice.recv_all(0.2)) == 0,
                "immediate: latches onto the first packet's source, even when the SDP named another")
        relay.ok("delete", call_id="imm")

        # --- heuristic prefers the SDP's own address and port over a stranger
        alice, bob, early = Endpoint(), Endpoint(), Endpoint("127.0.0.4")
        o, a = call(relay, "pref", "127.0.0.1", alice.port, bob, flags=["trust-address"])
        early.send_rtp(a.dest(), n=1)
        time.sleep(0.05)
        alice.send_rtp(a.dest(), n=2)
        bob.recv_all(0.3)
        bob.send_rtp(o.dest(), n=3)
        r.check(len(alice.recv_all(0.3)) == 3 and len(early.recv_all(0.2)) == 0,
                "heuristic: the source matching the SDP wins over an earlier stranger")
        relay.ok("delete", call_id="pref")

        # --- off: always the SDP address; a NATed phone hears nothing
        alice, bob = Endpoint(), Endpoint()
        o, a = call(relay, "off", PRIVATE, 4000, bob, flags=["trust-address"], learning="off")
        alice.send_rtp(a.dest(), n=3)
        bob.recv_all(0.3)
        bob.send_rtp(o.dest(), n=3)
        r.check(len(alice.recv_all(0.3)) == 0, "learning off: media goes to the SDP address, not the source")
        relay.ok("delete", call_id="off")

        # --- before alice sends anything, bob's media goes to the SDP address
        alice, bob = Endpoint(), Endpoint()
        o, a = call(relay, "early", "127.0.0.1", alice.port, bob, flags=["trust-address"])
        bob.send_rtp(o.dest(), n=3)
        r.check(len(alice.recv_all(0.3)) == 3, "before any packet from alice, media goes to her SDP address")
        relay.ok("delete", call_id="early")

        # --- RTCP latches on its own port (no rtcp-mux)
        alice, bob = Endpoint(), Endpoint()
        alice_rtcp = Endpoint()
        o, a = call(relay, "rtcp", PRIVATE, 4000, bob, flags=["trust-address"])
        from harness import rtcp_sr
        alice_rtcp.send(rtcp_sr(alice.ssrc), (a.addr(), a.media[0].port + 1))
        # bob's RTCP port is his SDP port + 1 (no a=rtcp)
        bob_rtcp_default = Endpoint("127.0.0.1", bob.port + 1)
        got = bob_rtcp_default.recv_all(0.4)
        r.check(len(got) == 1, "alice's RTCP reaches bob's RTCP port (SDP port + 1)", str(len(got)))
        bob_rtcp_default.send(rtcp_sr(bob.ssrc), (o.addr(), o.media[0].port + 1))
        r.check(len(alice_rtcp.recv_all(0.4)) == 1, "bob's RTCP follows alice's latched RTCP source")
        relay.ok("delete", call_id="rtcp")

        # --- symmetric NAT on both sides at once
        alice, bob = Endpoint(), Endpoint()
        o = Sdp(relay.ok("offer", call_id="both", from_tag="alice", sdp=sdp(PRIVATE, 4000),
                         flags=["trust-address"])["sdp"])
        a = Sdp(relay.ok("answer", call_id="both", from_tag="alice", to_tag="bob", sdp=sdp(PRIVATE, 4002),
                         flags=["trust-address"])["sdp"])
        alice.send_rtp(a.dest(), n=2)
        bob.send_rtp(o.dest(), n=2)
        time.sleep(0.1)
        alice.drain()
        bob.drain()
        alice.send_rtp(a.dest(), n=5, interval=0.01)
        bob.send_rtp(o.dest(), n=5, interval=0.01)
        r.check(len(bob.recv_all(0.4)) == 5 and len(alice.recv_all(0.3)) == 5,
                "both parties behind NAT: media flows both ways once each has sent")
        relay.ok("delete", call_id="both")

    # --- the same protection for every call, from the configuration
    cfg = base_config(NG, ports=(22400, 22799), sessions="strict_source = true")
    with Relay(cfg, NG, "nat-strict") as relay:
        alice, bob, mallory = Endpoint(), Endpoint(), Endpoint("127.0.0.3")
        o, a = call(relay, "cfg-strict", "127.0.0.1", alice.port, bob, flags=["trust-address"])
        alice.send_rtp(a.dest(), n=3)
        r.check(len(bob.recv_all(0.3)) == 3, "[sessions] strict_source = true: the real party's media passes")
        mallory.send_rtp(a.dest(), n=5, payload=b"\x00" * 160)
        r.check(not bob.recv_all(0.4), "and once its address is learned, a third party's packets are dropped "
                                       "without the proxy's flag")


if __name__ == "__main__":
    main(scenario)
