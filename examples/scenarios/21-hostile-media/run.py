#!/usr/bin/env python3
"""Hostile traffic at the media ports: floods from strangers, datagrams
larger than the packet buffer, every first octet, RTCP with lying length
fields, STUN that does not authenticate. The relay must drop and count
it, stay up, never amplify, and leave other calls untouched; the relay's
CPU per hostile packet is measured."""

import os
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import (  # noqa: E402
    Endpoint, Relay, Sdp, base_config, binding_request, http_get, main, rtp, sdp,
)

NG = 20321
METRICS = NG + 100
PORTS = (31600, 31799)
FLOOD = 50_000


def cpu_seconds(pid):
    with open(f"/proc/{pid}/stat") as f:
        fields = f.read().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def metric(name):
    _, body = http_get(f"http://127.0.0.1:{METRICS}/metrics")
    total = 0.0
    for ln in body.splitlines():
        if ln.startswith(name + " ") or ln.startswith(name + "{"):
            total += float(ln.split()[-1])
    return total


def call(relay, cid, flags=(), extra=()):
    alice, bob = Endpoint(), Endpoint()
    o = Sdp(relay.ok("offer", call_id=cid, from_tag="a", sdp=sdp("127.0.0.1", alice.port, extra=list(extra)),
                     flags=["trust-address", *flags], endpoint_learning="immediate")["sdp"])
    a = Sdp(relay.ok("answer", call_id=cid, from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", bob.port),
                     flags=["trust-address", *flags])["sdp"])
    return alice, bob, o, a


class Victim:
    """A call measured while the other one is attacked: 50 packets/s."""

    def __init__(self, relay):
        self.alice, self.bob, self.o, self.a = call(relay, "victim")
        self.sent = 0
        self.stop = False
        self.t = threading.Thread(target=self.run, daemon=True)

    def run(self):
        while not self.stop:
            self.alice.send_rtp(self.a.dest())
            self.sent += 1
            time.sleep(0.02)

    def received(self):
        return len(self.bob.recv_all(0.5))


def scenario(r):
    cfg = base_config(NG, ports=PORTS, runtime="workers = 1",
                      extra=f'[metrics]\nlisten = ["127.0.0.1:{METRICS}"]\n')
    with Relay(cfg, NG, "hostile") as relay:
        pid = relay.proc.pid
        alice, bob, o, a = call(relay, "target", flags=["strict-source"])
        alice.send_rtp(a.dest(), n=2)  # latch the real caller
        bob.recv_all(0.2)
        victim = Victim(relay)  # same worker (workers = 1): the hardest case
        victim.t.start()
        time.sleep(0.3)

        # --- a flood from a stranger at a strict-source call
        mallory = Endpoint("127.0.0.3")
        dropped0 = metric("rtpflux_packets_dropped_total")
        cpu0 = cpu_seconds(pid)
        t0 = time.time()
        pkt = rtp(0, 1, 0, 0xBADBAD, b"\x00" * 160)
        for _ in range(FLOOD):
            mallory.sock.sendto(pkt, a.dest())
        dt = time.time() - t0
        time.sleep(0.5)
        cpu = cpu_seconds(pid) - cpu0
        dropped = metric("rtpflux_packets_dropped_total") - dropped0
        leaked = len(bob.recv_all(0.3))
        r.check(leaked == 0, f"{FLOOD} packets from a stranger at a strict-source call: none relayed ({leaked})")
        r.check(dropped >= FLOOD * 0.9, f"they are counted as dropped ({dropped:.0f}; some may be lost in the socket buffer)")
        r.check(True, f"flood at {FLOOD / dt:.0f} packets/s cost the relay {cpu * 1e6 / FLOOD:.2f} µs of CPU per packet")
        r.check(relay.ng("ping")["result"] == "pong", "ng answers during and after the flood")

        # --- datagrams larger than the packet buffer (2048)
        for size in (2049, 9000, 65_000):
            try:
                mallory.sock.sendto(b"\x80" + b"\x00" * (size - 1), a.dest())
            except OSError:
                pass
            alice.sock.sendto(rtp(0, 1, 0, alice.ssrc, b"\x00" * (size - 12)), a.dest())
        r.check(not bob.recv_all(0.3), "datagrams over the packet buffer are dropped, even from the real caller")
        alice.send_rtp(a.dest(), n=2)
        r.check(len(bob.recv_all(0.3)) == 2, "and normal packets pass right after")

        # --- every first octet, in every length up to 40
        for first in range(256):
            for n in (1, 2, 11, 12, 13, 40):
                mallory.sock.sendto(bytes([first]) + os.urandom(n - 1), a.dest())
                alice.sock.sendto(bytes([first]) + os.urandom(n - 1), a.dest())
        time.sleep(0.3)
        bob.drain()
        alice.send_rtp(a.dest(), n=2)
        r.check(len(bob.recv_all(0.3)) == 2 and relay.ng("ping")["result"] == "pong",
                "256 first octets x 6 lengths of garbage: the relay stays up and the call goes on")

        # --- RTCP with lying length fields, from the real caller
        rtcp_port = (a.addr(), a.media[0].port + 1)
        alice_rtcp = Endpoint("127.0.0.1", alice.port + 1)
        lies = [
            struct.pack("!BBH", 0x80, 200, 0xFFFF) + b"\x00" * 24,          # length far past the end
            struct.pack("!BBH", 0x81, 201, 1) + b"\x00" * 4,               # a report block that is not there
            struct.pack("!BBHI", 0x9F, 201, 7, 1) + b"\x00" * 8,           # 31 report blocks claimed
            struct.pack("!BBH", 0x80, 202, 0) * 50,                        # 50 empty SDES chunks
            struct.pack("!BBHI", 0x80, 200, 6, 1) + b"\x00" * 20 + struct.pack("!BBH", 0x80, 203, 0xFFFF),
        ]
        for p in lies * 20:
            alice_rtcp.sock.sendto(p, rtcp_port)
        time.sleep(0.2)
        q = relay.ng("query", call_id="target")
        r.check(q.get("result") == "ok", "RTCP with lying lengths: query still works (no bogus report crashes it)")

        # --- STUN on a non-ICE call, and bad STUN on an ICE call: no amplification
        req, _ = binding_request("x:y", "wrongwrongwrongwrongwr")
        for _ in range(200):
            mallory.sock.sendto(req, a.dest())
        answers = mallory.recv_all(0.4)
        r.check(not answers, f"STUN at a call without ICE is not answered ({len(answers)})")
        ia, ib, io, ia_sdp = call(relay, "ice", extra=["a=ice-ufrag:abcd", "a=ice-pwd:abcdefghijklmnopqrstuvwx",
                                                       "a=candidate:1 1 UDP 2122260223 127.0.0.1 5 typ host"])
        sent_bytes = 0
        for _ in range(200):
            mallory.sock.sendto(req, ia_sdp.dest())
            sent_bytes += len(req)
        answers = mallory.recv_all(0.5)
        got_bytes = sum(len(d) for d, _ in answers)
        r.check(not any(d[:2] == b"\x01\x01" for d, _ in answers),
                "unauthenticated checks at an ICE call never get a success response")
        r.check(got_bytes <= sent_bytes, f"and the relay never sends back more than it got ({got_bytes} <= {sent_bytes} bytes)")

        # --- packets to ports of the range that no call uses
        for port in range(PORTS[0] + 150, PORTS[0] + 199, 2):
            mallory.sock.sendto(pkt, ("127.0.0.1", port))
        time.sleep(0.2)
        r.check(relay.ng("ping")["result"] == "pong", "packets to unused ports of the range change nothing")

        # --- the victim call, on the same worker, through all of it
        victim.stop = True
        victim.t.join()
        got = victim.received()
        r.check(got >= victim.sent * 0.99, f"the other call on the same worker lost nothing: {got}/{victim.sent}")


if __name__ == "__main__":
    main(scenario)
