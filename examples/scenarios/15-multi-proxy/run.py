#!/usr/bin/env python3
"""Several SIP proxies on one relay: identical cookies from different
proxies (Kamailio builds cookies from server id, pid and a counter, so
identical containers send identical ones), retransmissions answered per
sender, concurrent requests for the same call, forking (one offer, two
answers with different to-tags), two dialogs under one Call-ID, and a
load of concurrent call set-ups from many proxies."""

import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import Endpoint, Relay, Sdp, base_config, bdec, benc, main, sdp  # noqa: E402

NG = 20315
PORTS = (30400, 30599)


class Proxy:
    """One proxy: its own socket, so the relay tells them apart."""

    def __init__(self, relay):
        self.relay = relay
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(3)

    def ng(self, cookie, **msg):
        body = {k.replace("_", "-"): v for k, v in msg.items()}
        self.sock.sendto(cookie.encode() + b" " + benc(body), self.relay.ng_addr)
        data, _ = self.sock.recvfrom(65535)
        sp = data.index(b" ")
        assert data[:sp].decode() == cookie, data[:40]
        return bdec(data, sp + 1)[0]


def scenario(r):
    with Relay(base_config(NG, ports=PORTS, max_sessions=50), NG, "proxies") as relay:
        p1, p2 = Proxy(relay), Proxy(relay)

        # --- the same cookie from two proxies: two requests, two replies
        cookie = "1_4242_7"
        d1 = cookie.encode() + b" " + benc({"command": "offer", "call-id": "from-p1", "from-tag": "a",
                                           "sdp": sdp("127.0.0.1", 5000)})
        d2 = cookie.encode() + b" " + benc({"command": "offer", "call-id": "from-p2", "from-tag": "a",
                                           "sdp": sdp("127.0.0.1", 5002)})

        def send(px, datagram):
            px.sock.sendto(datagram, relay.ng_addr)
            data, _ = px.sock.recvfrom(65535)
            return data
        rep1, rep2 = send(p1, d1), send(p2, d2)
        calls = relay.ok("list")["calls"]
        r.check({"from-p1", "from-p2"} <= set(calls), "the same cookie from two proxies runs both requests")
        r.check(rep1 != rep2, "and each gets its own reply")
        stats = lambda: relay.ok("statistics")["statistics"]["controlstatistics"]["retransmissions"]  # noqa: E731
        before = stats()
        # Each proxy's retransmission (the same datagram) gets its own reply.
        r.check(send(p2, d2) == rep2 and send(p1, d1) == rep1,
                "each proxy's retransmission is answered with its own cached reply")
        r.check(stats() - before == 2, f"two retransmissions counted ({stats() - before})")

        # --- two dialogs under one Call-ID (a forked INVITE's two branches
        # offered separately, or a call transferred)
        for tag in ("x1", "x2"):
            relay.ok("offer", call_id="shared", from_tag=tag, sdp=sdp("127.0.0.1", 5100))
        q = relay.ok("query", call_id="shared")
        r.check({"x1", "x2"} <= set(q["tags"]), "two dialogs under one Call-ID, both in query", str(list(q["tags"])))
        relay.ok("delete", call_id="shared", from_tag="x1")
        q = relay.ng("query", call_id="shared")
        r.check(q.get("result") == "ok" and "x1" not in q.get("tags", {}) and "x2" in q.get("tags", {}),
                "delete with from-tag ends only that dialog", str(list(q.get("tags", {}))))
        relay.ok("delete", call_id="shared")
        r.check("shared" not in relay.ok("list")["calls"], "delete without from-tag ends all of them")

        # --- forking: one offer, answers from two branches (to-tags)
        alice, bob1, bob2 = Endpoint(), Endpoint(), Endpoint()
        relay.ok("offer", call_id="fork", from_tag="alice", sdp=sdp("127.0.0.1", alice.port),
                 flags=["trust-address"])
        a1 = relay.ng("answer", call_id="fork", from_tag="alice", to_tag="bob-1", sdp=sdp("127.0.0.1", bob1.port),
                      flags=["trust-address"])
        a2 = relay.ng("answer", call_id="fork", from_tag="alice", to_tag="bob-2", sdp=sdp("127.0.0.1", bob2.port),
                      flags=["trust-address"])
        r.check(a1["result"] == "ok" and a2["result"] == "ok", "two answers (forked branches) are both accepted")
        alice.send_rtp(Sdp(a2["sdp"]).dest(), n=3)
        g1, g2 = len(bob1.recv_all(0.3)), len(bob2.recv_all(0.2))
        if g2 == 3 and g1 == 0:
            r.check(True, "the later answer (the branch that answered last) gets the media")
        else:
            r.finding(f"forking: after answers from two branches, media went to branch 1: {g1}, branch 2: {g2}")
        q = relay.ok("query", call_id="fork")
        tags = set(q["tags"])
        if "bob-1" in tags and "bob-2" in tags:
            r.finding("forking: both branches stay in the dialog after the second answer")
        else:
            r.check(tags == {"alice", "bob-2"}, f"forking: the dialog is the caller and the last branch: {sorted(tags)}")

        # --- concurrent requests for the same call from two proxies
        res = []

        def reoffer(px, n):
            for i in range(n):
                rep = px.ng(f"re{id(px)}-{i}", command="offer", call_id="race", from_tag="a",
                            sdp=sdp("127.0.0.1", 5200))
                res.append(rep["result"])
        th = [threading.Thread(target=reoffer, args=(px, 50)) for px in (p1, p2)]
        [t.start() for t in th]
        [t.join() for t in th]
        q = relay.ok("query", call_id="race")
        ports = [s["local port"] for s in q["tags"]["a"]["medias"][0]["streams"]]
        r.check(res.count("ok") == 100 and len(ports) == 2,
                f"100 interleaved re-offers of one call from two proxies: all ok, one dialog ({res.count('ok')})")

        # --- load: 8 proxies set up and tear down calls at once
        relay.ok("delete", call_id="race")
        for c in list(relay.ok("list")["calls"]):
            relay.ok("delete", call_id=c)
        errors, done = [], [0]

        def churn(k):
            px = Proxy(relay)
            for i in range(60):
                cid = f"load-{k}-{i}"
                for cmd, extra in [("offer", {"from_tag": "a", "sdp": sdp("127.0.0.1", 6000)}),
                                   ("answer", {"from_tag": "a", "to_tag": "b", "sdp": sdp("127.0.0.1", 6002)}),
                                   ("delete", {})]:
                    try:
                        rep = px.ng(f"{k}_{i}_{cmd}", command=cmd, call_id=cid, **extra)
                    except (socket.timeout, AssertionError) as e:
                        errors.append(f"{cid} {cmd}: {e!r}")
                        continue
                    if rep.get("result") != "ok":
                        errors.append(f"{cid} {cmd}: {rep.get('error-reason')}")
                done[0] += 1
        t0 = time.time()
        th = [threading.Thread(target=churn, args=(k,)) for k in range(8)]
        [t.start() for t in th]
        [t.join() for t in th]
        dt = time.time() - t0
        r.check(not errors, f"8 proxies x 60 calls ({done[0]} calls, {3 * done[0] / dt:.0f} requests/s): no errors",
                "; ".join(errors[:3]))
        r.check(relay.ok("list")["calls"] == [], "no call left behind")
        # sessions.max = 50 holds across proxies
        made = 0
        for k in range(60):
            px = p1 if k % 2 else p2
            if px.ng(f"cap{k}", command="offer", call_id=f"cap{k}", from_tag="a",
                     sdp=sdp("127.0.0.1", 6100))["result"] == "ok":
                made += 1
        r.check(made == 50, f"sessions.max = 50 is one limit for all proxies ({made} set up)")


if __name__ == "__main__":
    main(scenario)
