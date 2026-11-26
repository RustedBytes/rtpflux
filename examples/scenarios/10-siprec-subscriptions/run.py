#!/usr/bin/env python3
"""SIPREC recording through subscriptions, as OpenSIPS's `siprec` module
drives it: `subscribe request` with `flags: [all, siprec]`, the
recording server's answer through `subscribe answer`, `unsubscribe`.
The recorder must get exact copies of each party on its own section,
nothing before its answer, and keep getting them across a restart."""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import (  # noqa: E402
    Endpoint, Relay, Sdp, base_config, crypto_line, main, parse_crypto, parse_rtp, sdp,
)

NG = 20310
PORTS = (29400, 29599)


def call(relay, cid):
    alice, bob = Endpoint(), Endpoint()
    o = Sdp(relay.ok("offer", call_id=cid, from_tag="alice", sdp=sdp("127.0.0.1", alice.port, pts=(0, 101)),
                     flags=["trust-address"])["sdp"])
    a = Sdp(relay.ok("answer", call_id=cid, from_tag="alice", to_tag="bob",
                     sdp=sdp("127.0.0.1", bob.port, pts=(0, 101)), flags=["trust-address"])["sdp"])
    return alice, bob, o, a


def talk(alice, a, bob, o, n=5):
    alice.send_rtp(a.dest(), n=n, payload=b"\x11" * 160)
    bob.send_rtp(o.dest(), n=n, payload=b"\x22" * 160)
    time.sleep(0.05)


def recorder_answer(offer: Sdp, ports, proto="RTP/AVP", extra=None):
    secs = []
    for i, m in enumerate(offer.media):
        x = ["a=recvonly"] + [f"a=label:{v}" for v in m.attr("label")] + (extra[i] if extra else [])
        secs.append(dict(port=ports[i], pts=tuple(int(f) for f in m.fmts), proto=proto, extra=x))
    return sdp("127.0.0.1", 0, sections=secs)


def scenario(r):
    state = None
    relay = Relay(base_config(NG, ports=PORTS, sessions='state_file = "STATE"'), NG, "siprec")
    state = os.path.join(relay.dir, "state.json")
    with open(relay.config_path) as f:
        text = f.read()
    with open(relay.config_path, "w") as f:
        f.write(text.replace("STATE", state))
    try:
        relay.start()
        alice, bob, o, a = call(relay, "rec@call")
        talk(alice, a, bob, o)

        # --- the subscription offer
        rep = relay.ok("subscribe request", call_id="rec@call", flags=["all", "siprec"], to_tag="srs-1")
        offer = Sdp(rep["sdp"])
        r.check(len(offer.media) == 2 and all(m.has("sendonly") for m in offer.media),
                "the recorder is offered one sendonly section per party", str(offer.media))
        r.check([m.attr("label") for m in offer.media] == [["1"], ["2"]], "sections are labelled 1 and 2")
        r.check(rep.get("from-tags") == ["alice", "bob"] and rep.get("to-tag") == "srs-1",
                "from-tags and to-tag in the reply")
        labels = rep.get("media-labels", {})
        r.check(labels.get("1", {}).get("tag") == "alice" and labels.get("2", {}).get("tag") == "bob",
                "media-labels map label 1 to the caller, 2 to the callee", str(labels)[:200])
        tm = rep.get("tag-medias", [])
        r.check([t["tag"] for t in tm] == ["alice", "bob"], "tag-medias lists both parties in order")
        r.check(offer.media[0].fmts == ["0", "101"], "the formats the party negotiated are offered",
                str(offer.media[0].fmts))
        lst = relay.ok("list")
        r.check(lst["subscriptions"] == [{"call-id": "rec@call", "from-tags": ["alice", "bob"], "to-tag": "srs-1"}],
                "list shows the subscription", str(lst["subscriptions"]))

        # --- nothing before the recorder answers
        rec1, rec2 = Endpoint(), Endpoint()
        talk(alice, a, bob, o)
        r.check(not rec1.recv_all(0.3) and not rec2.recv_all(0.1), "no copies before subscribe answer")

        # --- the answer: copies start, each party on its own section
        relay.ok("subscribe answer", call_id="rec@call", to_tag="srs-1",
                 sdp=recorder_answer(offer, [rec1.port, rec2.port]), flags=["trust-address"])
        alice.seq0, bob.seq0 = alice.seq, bob.seq
        alice.drain(), bob.drain()
        talk(alice, a, bob, o, n=10)
        got1 = [parse_rtp(d) for d, _ in rec1.recv_all(0.4)]
        got2 = [parse_rtp(d) for d, _ in rec2.recv_all(0.2)]
        r.check(len(got1) == 10 and all(p["payload"] == b"\x11" * 160 and p["ssrc"] == alice.ssrc for p in got1),
                "section 1 gets exact copies of the caller", f"{len(got1)} packets")
        r.check(len(got2) == 10 and all(p["payload"] == b"\x22" * 160 and p["ssrc"] == bob.ssrc for p in got2),
                "section 2 gets exact copies of the callee", f"{len(got2)} packets")
        r.check([p["seq"] for p in got1] == [(alice.seq0 + i) & 0xFFFF for i in range(10)],
                "copies keep the sender's sequence numbers")
        r.check(len(bob.recv_all(0.2)) == 10, "the call itself goes on: bob still gets alice's 10 packets")
        q = relay.ok("query", call_id="rec@call")
        subs = q["tags"].get("srs-1", {})
        r.check({s["tag"] for s in subs.get("subscriptions", [])} == {"alice", "bob"},
                "query: the recorder's subscriptions are both parties", str(subs.get("subscriptions")))
        r.check(any(s.get("tag") == "srs-1" for s in q["tags"]["alice"].get("subscribers", [])),
                "query: the caller lists the recorder as a subscriber")
        # The recorder sending something back is not relayed into the call.
        rec1.send_rtp(Sdp(rep["sdp"]).dest(0), n=3)
        alice.drain(), bob.drain()
        r.check(not alice.recv_all(0.2) and not bob.recv_all(0.1), "what the recorder sends is not relayed")

        # --- across a restart
        time.sleep(1.2)  # the state is written within a second
        relay.stop()
        relay.start()
        talk(alice, a, bob, o, n=5)
        r.check(len(rec1.recv_all(0.4)) == 5 and len(rec2.recv_all(0.2)) == 5,
                "after a restart the subscription is back and copying")

        # --- unsubscribe stops the copies, the call goes on
        relay.ok("unsubscribe", call_id="rec@call", to_tag="srs-1")
        talk(alice, a, bob, o)
        r.check(not rec1.recv_all(0.3) and len(bob.recv_all(0.2)) >= 5, "unsubscribe: copies stop, the call goes on")
        r.check(relay.ok("list")["subscriptions"] == [], "the subscription is gone from list")

        # --- a recorder taking only one section
        rep = relay.ok("subscribe request", call_id="rec@call", flags=["all", "siprec"], to_tag="srs-2")
        offer = Sdp(rep["sdp"])
        rec1, rec2 = Endpoint(), Endpoint()
        relay.ok("subscribe answer", call_id="rec@call", to_tag="srs-2",
                 sdp=recorder_answer(offer, [rec1.port, 0]), flags=["trust-address"])
        talk(alice, a, bob, o)
        r.check(len(rec1.recv_all(0.3)) == 5 and not rec2.recv_all(0.1),
                "a section the recorder rejects (port 0) gets nothing")
        relay.ok("unsubscribe", call_id="rec@call", to_tag="srs-2")

        # --- one source, by from-tag; and the inactive flag
        rep = relay.ok("subscribe request", call_id="rec@call", from_tag="bob", to_tag="srs-3")
        offer = Sdp(rep["sdp"])
        r.check(len(offer.media) == 1 and rep.get("from-tag") == "bob", "from-tag subscribes to one party")
        rep = relay.ok("subscribe request", call_id="rec@call", flags=["all", "inactive"], to_tag="srs-4")
        r.check(all(m.has("inactive") for m in Sdp(rep["sdp"]).media), "flags: inactive offers inactive sections")
        for t in ("srs-3", "srs-4"):
            relay.ng("unsubscribe", call_id="rec@call", to_tag=t)

        # --- an SDES-SRTP recorder: copies encrypted with the relay's key
        rep = relay.ok("subscribe request", call_id="rec@call", from_tag="alice", to_tag="srs-5",
                       transport_protocol="RTP/SAVP")
        offer = Sdp(rep["sdp"])
        cr = offer.media[0].attr("crypto")
        r.check(offer.media[0].proto == "RTP/SAVP" and bool(cr), "an SRTP recorder is offered RTP/SAVP with a key")
        tag, suite, relay_tx = parse_crypto(cr[0])
        rec = Endpoint()
        line, _ = crypto_line(tag, suite)
        relay.ok("subscribe answer", call_id="rec@call", to_tag="srs-5",
                 sdp=recorder_answer(offer, [rec.port], proto="RTP/SAVP", extra=[[line]]), flags=["trust-address"])
        talk(alice, a, bob, o)
        dec = [relay_tx.unprotect(d) for d, _ in rec.recv_all(0.4)]
        r.check(len(dec) == 5 and all(p and parse_rtp(p)["payload"] == b"\x11" * 160 for p in dec),
                "the SRTP recorder decrypts the caller's audio with the relay's key", f"{sum(1 for p in dec if p)}/{len(dec)}")
        # An answer that refuses SRTP is refused.
        rep = relay.ok("subscribe request", call_id="rec@call", from_tag="alice", to_tag="srs-6",
                       transport_protocol="RTP/SAVP")
        bad = relay.ng("subscribe answer", call_id="rec@call", to_tag="srs-6",
                       sdp=recorder_answer(Sdp(rep["sdp"]), [Endpoint().port]))
        r.check(bad.get("result") == "error", "a plain answer to an SRTP subscription offer is refused",
                str(bad)[:140])

        # --- formats the recorder does not take
        rep = relay.ok("subscribe request", call_id="rec@call", from_tag="alice", to_tag="srs-7")
        bad_ans = sdp("127.0.0.1", Endpoint().port, pts=(8,), extra=["a=recvonly"])
        bad = relay.ng("subscribe answer", call_id="rec@call", to_tag="srs-7", sdp=bad_ans)
        r.check(bad.get("result") == "error" and "formats" in bad.get("error-reason", ""),
                "an answer keeping none of the offered formats is refused", str(bad)[:140])

        # --- errors
        for what, cmd, opts in [
            ("an unknown call", "subscribe request", {"call_id": "nope", "flags": ["all"]}),
            ("an unknown party", "subscribe request", {"call_id": "rec@call", "from_tag": "mallory"}),
            ("no source", "subscribe request", {"call_id": "rec@call"}),
            ("an answer for an unknown subscription", "subscribe answer",
             {"call_id": "rec@call", "to_tag": "nope", "sdp": sdp("127.0.0.1", 5000)}),
            ("unsubscribe of an unknown subscription", "unsubscribe", {"call_id": "rec@call", "to_tag": "nope"}),
        ]:
            rep = relay.ng(cmd, **opts)
            r.check(rep.get("result") == "error", f"{cmd} with {what} is an error", str(rep)[:120])

        # --- deleting the call ends its subscriptions
        relay.ok("delete", call_id="rec@call")
        r.check(relay.ok("list")["subscriptions"] == [], "delete ends the call's subscriptions")
        talk(alice, a, bob, o)
        r.check(not rec.recv_all(0.3), "and their copies")
    finally:
        relay.cleanup()


if __name__ == "__main__":
    main(scenario)
