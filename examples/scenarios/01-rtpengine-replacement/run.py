#!/usr/bin/env python3
"""rtpflux in place of rtpengine: the ng protocol as Kamailio/OpenSIPS
speak it, over UDP, TCP and HTTP, with the replies the modules expect,
and the protocol's rough edges (retransmissions, bad requests)."""

import json
import os
import socket
import sys
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import Endpoint, Relay, Sdp, base_config, benc, exchange, main, sdp  # noqa: E402

NG = 20301


def scenario(r):
    cfg = base_config(
        NG, ports=(21000, 21399),
        extra="",
    ).replace(
        f'listen = ["127.0.0.1:{NG}"]',
        f'listen = ["127.0.0.1:{NG}"]\nlisten_tcp = ["127.0.0.1:{NG}"]\nlisten_http = ["127.0.0.1:{NG + 1}"]',
    )
    with Relay(cfg, NG, "ng") as relay:
        r.check(relay.ng("ping") == {"result": "pong"}, "ping answers pong")

        # --- a basic call, as rtpengine_manage() drives it
        alice, bob = Endpoint(), Endpoint()
        offer = relay.ok("offer", call_id="c1@ex", from_tag="alice", sdp=sdp("127.0.0.1", alice.port),
                         flags=["trust-address"], replace=["origin"])
        o = Sdp(offer["sdp"])
        r.check(o.addr() == "127.0.0.1" and 21000 <= o.media[0].port <= 21399,
                "offer rewritten to the relay's address and a port from the range", o.text)
        r.check(o.origin == "127.0.0.1", "replace-origin rewrites o=")
        r.check(o.media[0].port % 2 == 0, "RTP port is even")
        answer = relay.ok("answer", call_id="c1@ex", from_tag="alice", to_tag="bob",
                          sdp=sdp("127.0.0.1", bob.port), flags=["trust-address"])
        a = Sdp(answer["sdp"])
        r.check(a.media[0].port != o.media[0].port, "each side gets its own relay port")
        at_bob, at_alice = exchange(alice, a.dest(), bob, o.dest(), n=20)
        r.check(len(at_bob) == 20 and len(at_alice) == 20, "media relayed both ways",
                f"bob got {len(at_bob)}, alice got {len(at_alice)}")
        r.check(all(src == o.dest() for _, src in at_bob), "bob receives from the port he was offered")

        q = relay.ok("query", call_id="c1@ex")
        r.check(set(q.get("tags", {})) == {"alice", "bob"}, "query lists both tags")
        totals = q.get("totals", {}).get("RTP", {})
        r.check(totals.get("packets", 0) >= 40, "query totals count the relayed packets", str(totals))
        lst = relay.ok("list")
        r.check(lst.get("calls") == ["c1@ex"], "list shows the call", str(lst))

        # --- retransmission: same cookie => same reply, no second call
        cookie = "retrans-1"
        body = sdp("127.0.0.1", 5000)  # a retransmission is the same datagram
        r1 = relay.ng("offer", cookie=cookie, call_id="c2@ex", from_tag="a2", sdp=body)
        r2 = relay.ng("offer", cookie=cookie, call_id="c2@ex", from_tag="a2", sdp=body)
        r.check(r1 == r2, "a retransmitted request gets the same reply")
        st = relay.ok("statistics")["statistics"]
        r.check(st["controlstatistics"].get("retransmissions", 0) >= 1, "retransmissions are counted",
                str(st["controlstatistics"]))
        # Same cookie, different request: a new request (a proxy whose
        # counter restarted), not a retransmission.
        r3 = relay.ng("offer", cookie=cookie, call_id="c3@ex", from_tag="a3", sdp=sdp("127.0.0.1", 5002))
        calls = relay.ok("list")["calls"]
        r.check(r3 != r1 and "c3@ex" in calls, "a reused cookie with a different request runs that request")
        r.check("c2@ex" in calls, "the retransmitted offer created one call")

        # --- errors the modules must see as errors
        for what, cmd, opts, needle in [
            ("unknown command", "frobnicate", {}, ""),
            ("offer without sdp", "offer", {"call_id": "x", "from_tag": "y"}, "sdp"),
            ("offer without call-id", "offer", {"from_tag": "y", "sdp": sdp("127.0.0.1", 5000)}, "call-id"),
            ("answer for an unknown call", "answer", {"call_id": "nope", "from_tag": "a", "to_tag": "b",
                                                      "sdp": sdp("127.0.0.1", 5000)}, ""),
            ("query for an unknown call", "query", {"call_id": "nope"}, ""),
            ("start forwarding (unsupported)", "start forwarding", {"call_id": "c1@ex"}, ""),
        ]:
            rep = relay.ng(cmd, **opts)
            ok = rep.get("result") == "error" and needle in rep.get("error-reason", "")
            r.check(ok, f"error reply: {what}", str(rep))
        # --- SDP that is not really SDP. rtpengine refuses non-SDP; an SDP
        # without media is valid (RFC 3264), and c= may carry a host name
        # (RFC 8866 §5.7), which 999.1.1.1 is read as.
        for what, call, body, want in [
            ("text that is not SDP", "g1", "hello", "error"),
            ("no m= line", "g2", "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\ns=-\r\nc=IN IP4 1.2.3.4\r\nt=0 0\r\n", "ok"),
            ("no c= line anywhere", "g3", "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\nm=audio 5000 RTP/AVP 0\r\n", "error"),
            ("a host name in c=", "g4", "v=0\r\nc=IN IP4 999.1.1.1\r\nm=audio 5000 RTP/AVP 0\r\n", "ok"),
            ("m= port above 65535", "g5", "v=0\r\nc=IN IP4 1.2.3.4\r\nm=audio 99999 RTP/AVP 0\r\n", "error"),
        ]:
            rep = relay.ng("offer", call_id=call, from_tag="y", sdp=body)
            r.check(rep.get("result") == want,
                    f"offer with {what}: {'accepted' if want == 'ok' else 'refused'}",
                    str(rep)[:160])
            if want == "error" and rep.get("result") == "error":
                r.check(call not in relay.ok("list")["calls"], "  and no call is left for it")
            relay.ng("delete", call_id=call)

        # As rtpengine: ok with a warning, an error with the `fatal` flag.
        rep = relay.ng("delete", call_id="never-existed")
        r.check(rep.get("result") == "ok" and "tags didn't match" in str(rep.get("warning", "")),
                "delete of an unknown call: ok with rtpengine's warning", str(rep))
        rep = relay.ng("delete", call_id="never-existed", flags=["fatal"])
        r.check(rep.get("result") == "error", "with the fatal flag it is an error", str(rep))

        # Offer with an SDP that has no m= line at all: rtpengine accepts
        # it (nothing to relay). Already covered above; see what came back.

        # --- malformed datagrams: the relay must stay up and answer
        for raw in [b"", b"nospace", b"c1 ", b"c1 d7:command", b"c1 i5e", b"c1 d7:command4:pingee",
                    b"c1 " + b"l" * 200 + b"e" * 200, b"x" * 70000]:
            try:
                relay.sock.sendto(raw[:65507], relay.ng_addr)
            except OSError:
                pass
        relay.sock.settimeout(0.3)
        replies = []
        try:
            while True:
                replies.append(relay.sock.recvfrom(65535)[0])
        except socket.timeout:
            pass
        r.check(relay.ng("ping") == {"result": "pong"}, "still alive after malformed datagrams")
        r.check(all(b"error" in x for x in replies), "malformed requests that are answered get an error",
                str(replies))

        # A huge but valid message, over max_message (65535) is not
        # possible over UDP; a 60 KB SDP is.
        big = sdp("127.0.0.1", 5000, extra=[f"a=x-pad:{'p' * 1000}"] * 58)
        rep = relay.ng("offer", call_id="big", from_tag="a", sdp=big)
        r.check(rep.get("result") in ("ok", "error"), "a 60 KB offer gets an answer", rep.get("result", "?"))
        if rep.get("result") == "ok":
            relay.ok("delete", call_id="big")

        # --- TCP: messages back to back on one connection
        t = socket.create_connection(("127.0.0.1", NG), timeout=3)
        t.sendall(b"t1 " + benc({"command": "ping"}) + b"t2 " + benc({"command": "list"}))
        buf = b""
        while buf.count(b"result") < 2:
            chunk = t.recv(4096)
            if not chunk:
                break
            buf += chunk
        r.check(buf.startswith(b"t1 ") and b"t2 " in buf and b"pong" in buf,
                "ng over TCP: two pipelined requests, two replies", repr(buf[:120]))
        # Garbage closes the TCP connection, the relay stays up.
        t.sendall(b"no-space-in-the-first-256-bytes" * 20)
        t.settimeout(2)
        try:
            closed = t.recv(10) == b""
        except (ConnectionResetError, socket.timeout):
            closed = True
        r.check(closed, "TCP connection closed after garbage")
        t.close()

        # --- HTTP: /ng-plain with JSON, as rtpengine's HTTP interface
        req = urllib.request.Request(f"http://127.0.0.1:{NG + 1}/ng-plain", data=b'{"command":"ping"}',
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=3) as resp:
            body = json.loads(resp.read())
        r.check(body == {"result": "pong"}, "ng over HTTP with JSON", str(body))
        offer_json = {"command": "offer", "call-id": "http-call", "from-tag": "h1",
                      "sdp": sdp("127.0.0.1", 6000), "flags": ["trust-address"]}
        req = urllib.request.Request(f"http://127.0.0.1:{NG + 1}/ng-plain", data=json.dumps(offer_json).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=3) as resp:
            body = json.loads(resp.read())
        r.check(body.get("result") == "ok" and "m=audio" in body.get("sdp", ""), "offer over HTTP/JSON")
        with urllib.request.urlopen(f"http://127.0.0.1:{NG + 1}/ping", timeout=3) as resp:
            r.check(resp.read().strip() == b"pong", "GET /ping")

        # --- delete and its effect
        relay.ok("delete", call_id="c1@ex")
        r.check("c1@ex" not in relay.ok("list")["calls"], "deleted call is gone from list")
        alice.send_rtp(a.dest(), n=3)
        r.check(len(bob.recv_all(0.3)) == 0, "no media relayed after delete")
        rep = relay.ng("query", call_id="c1@ex")
        r.check(rep.get("result") == "error", "query after delete is an error")

        # --- delete-delay keeps media flowing for a moment
        alice2, bob2 = Endpoint(), Endpoint()
        o = Sdp(relay.ok("offer", call_id="dd", from_tag="a", sdp=sdp("127.0.0.1", alice2.port),
                         flags=["trust-address"])["sdp"])
        a = Sdp(relay.ok("answer", call_id="dd", from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", bob2.port),
                         flags=["trust-address"])["sdp"])
        relay.ok("delete", call_id="dd", delete_delay=2)
        at_bob, _ = exchange(alice2, a.dest(), bob2, o.dest(), n=5)
        r.check(len(at_bob) == 5, "delete-delay: media still flows right after delete", str(len(at_bob)))
        time.sleep(2.6)
        alice2.drain()
        bob2.drain()
        at_bob, _ = exchange(alice2, a.dest(), bob2, o.dest(), n=5)
        r.check(len(at_bob) == 0, "delete-delay: the call ends after the delay", str(len(at_bob)))

        errors = [ln for ln in relay.log().splitlines() if " ERROR " in ln or "panicked" in ln]
        r.check(not errors, "no ERROR or panic in the relay's log", "\n".join(errors[:5]))


if __name__ == "__main__":
    main(scenario)
