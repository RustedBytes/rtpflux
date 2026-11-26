#!/usr/bin/env python3
"""One-to-many: a party that only sends (`publish`, as a WebRTC client
publishing its microphone) and several subscribers, each in its own
profile. The publisher here uses SDES-SRTP (DTLS needs a browser:
scripts/webrtc-firefox.py --subscribe covers a DTLS subscriber), so the
relay must decrypt for plain subscribers and re-encrypt for SRTP ones."""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import (  # noqa: E402
    ROOT, Endpoint, Relay, Sdp, base_config, crypto_line, main, parse_crypto, parse_rtp, rtp, sdp,
)

NG = 20311
PORTS = (29600, 29799)


def send(pub, tx, dst, n, payload=b"\x33" * 160):
    for _ in range(n):
        pub.send(tx.protect(rtp(0, pub.seq, pub.ts, pub.ssrc, payload)), dst)
        pub.seq = (pub.seq + 1) & 0xFFFF
        pub.ts += 160
    time.sleep(0.05)


def subscribe(relay, tag, proto=None):
    """A subscriber: its endpoint and, for SRTP, the relay's key to it."""
    opts = {"transport_protocol": proto} if proto else {}
    rep = relay.ok("subscribe request", call_id="room", from_tag="pub", to_tag=tag, **opts)
    offer = Sdp(rep["sdp"])
    ep = Endpoint()
    extra, key = ["a=recvonly"], None
    if proto == "RTP/SAVP":
        t, suite, key = parse_crypto(offer.media[0].attr("crypto")[0])
        extra.append(crypto_line(t, suite)[0])
    relay.ok("subscribe answer", call_id="room", to_tag=tag, flags=["trust-address"],
             sdp=sdp("127.0.0.1", ep.port, pts=(0,), proto=proto or "RTP/AVP", extra=extra))
    return ep, key


def scenario(r):
    with Relay(base_config(NG, ports=PORTS), NG, "broadcast") as relay:
        pub = Endpoint()
        line, tx = crypto_line(1)
        rep = relay.ok("publish", call_id="room", from_tag="pub", flags=["trust-address"],
                       sdp=sdp("127.0.0.1", pub.port, proto="RTP/SAVP", extra=[line, "a=sendonly"]))
        ans = Sdp(rep["sdp"])
        r.check(ans.media[0].has("recvonly") and ans.media[0].proto == "RTP/SAVP",
                "publish answers the publisher recvonly, in its own profile")
        _, _, relay_rx = parse_crypto(ans.media[0].attr("crypto")[0])
        dst = ans.dest()
        send(pub, tx, dst, 5)
        r.check(not pub.recv_all(0.2), "nothing is sent back to a publisher")

        # three subscribers: plain, SRTP, plain
        subs = {tag: subscribe(relay, tag, proto) for tag, proto in
                [("plain-1", None), ("srtp-1", "RTP/SAVP"), ("plain-2", None)]}
        send(pub, tx, dst, 10)
        for tag, (ep, key) in subs.items():
            got = ep.recv_all(0.4)
            if key:
                pkts = [parse_rtp(key.unprotect(d) or b"") for d, _ in got]
            else:
                pkts = [parse_rtp(d) for d, _ in got]
            r.check(len(pkts) == 10 and all(p and p["payload"] == b"\x33" * 160 for p in pkts),
                    f"{tag} gets the publisher's audio ({'re-encrypted' if key else 'decrypted'})",
                    f"{len(pkts)} packets")
        lst = relay.ok("list")["subscriptions"]
        r.check(len(lst) == 3, f"list shows the 3 subscriptions ({len(lst)})")

        # a subscriber leaves; the others keep receiving
        relay.ok("unsubscribe", call_id="room", to_tag="plain-1")
        send(pub, tx, dst, 5)
        r.check(not subs["plain-1"][0].recv_all(0.3), "the one who left gets nothing")
        r.check(len(subs["plain-2"][0].recv_all(0.2)) == 5, "the others are not affected")

        # a late joiner gets what is sent from then on
        late, _ = subscribe(relay, "late", None)
        send(pub, tx, dst, 5)
        r.check(len(late.recv_all(0.3)) == 5, "a late subscriber gets the stream from its answer on")

        # tampered SRTP from the publisher reaches nobody
        bad = bytearray(tx.protect(rtp(0, pub.seq, pub.ts, pub.ssrc, b"\x33" * 160)))
        pub.seq += 1
        bad[-1] ^= 1
        pub.send(bytes(bad), dst)
        r.check(not late.recv_all(0.3), "a tampered publisher packet is copied to no one")

        # 20 subscribers at once
        many = [subscribe(relay, f"m{i}", None)[0] for i in range(20)]
        send(pub, tx, dst, 3)
        counts = [len(ep.recv_all(0.2)) for ep in many]
        r.check(counts == [3] * 20, f"20 more subscribers each get every packet: {set(counts)}")
        r.check(relay.ok("query", call_id="room")["result"] == "ok", "query works with 23 subscriptions")

        # the publisher re-publishes (new key): subscribers keep getting it
        line2, tx2 = crypto_line(1)
        rep = relay.ng("publish", call_id="room", from_tag="pub", flags=["trust-address"],
                       sdp=sdp("127.0.0.1", pub.port, proto="RTP/SAVP", extra=[line2, "a=sendonly"]))
        r.check(rep.get("result") == "ok", "a re-publish (new key) is accepted", str(rep)[:120])
        if rep.get("result") == "ok":
            late.drain()
            send(pub, tx2, Sdp(rep["sdp"]).dest(), 5)
            r.check(len(late.recv_all(0.3)) == 5, "subscribers keep receiving after the publisher re-keys")

        # delete ends the publication and every subscription
        relay.ok("delete", call_id="room")
        r.check(relay.ok("list") == {"calls": [], "result": "ok", "subscriptions": []},
                "delete ends the publication and all its subscriptions")
        send(pub, tx2, dst, 3)
        r.check(not late.recv_all(0.3), "and nothing is copied any more")

        # errors
        rep = relay.ng("subscribe request", call_id="room", from_tag="pub", to_tag="x")
        r.check(rep.get("result") == "error", "subscribing to an ended publication is an error")
        rep = relay.ng("publish", call_id="p2", from_tag="pub", sdp="hello")
        r.check(rep.get("result") == "error", "publish with a body that is not SDP is refused")

    if "--browser" in sys.argv:
        import subprocess
        res = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "webrtc-firefox.py"), "--subscribe"],
                             capture_output=True, text=True, timeout=180)
        r.check(res.returncode == 0, "a DTLS (browser) subscriber, headless Firefox", (res.stdout + res.stderr)[-300:])
    else:
        r.skip("a DTLS subscriber needs a browser: run with --browser")


if __name__ == "__main__":
    main(scenario)
