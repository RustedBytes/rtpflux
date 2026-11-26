#!/usr/bin/env python3
"""A relay behind NAT without a fixed public address: with
`ice.stun_server`, it asks a STUN server for its public address (per
interface without `advertise`) and offers ICE endpoints a
server-reflexive candidate (`typ srflx`) besides its host one. The STUN
server here is a few lines of Python that answers with a made-up public
address, as a real NAT would make it."""

import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import MAGIC, Endpoint, Relay, Sdp, base_config, main, sdp, stun_message, stun_parse  # noqa: E402

NG = 20319
PORTS = (31200, 31399)
STUN_PORT = NG + 100
PUBLIC = "203.0.113.77"


class StunServer:
    """Answers Binding requests with XOR-MAPPED-ADDRESS = PUBLIC and the
    source port (what a NAT in front of the relay would show)."""

    def __init__(self, port, answer=True):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.sock.settimeout(0.2)
        self.answer = answer
        self.requests = []
        self.stop = False
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while not self.stop:
            try:
                data, src = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            msg = stun_parse(data)
            if not msg or msg["type"] != 0x0001:
                continue
            self.requests.append(src)
            if not self.answer:
                continue
            ip = struct.unpack("!I", socket.inet_aton(PUBLIC))[0] ^ MAGIC
            xma = struct.pack("!xBHI", 1, src[1] ^ (MAGIC >> 16), ip)
            self.sock.sendto(stun_message(0x0101, msg["txid"], [(0x0020, xma)], None), src)

    def close(self):
        self.stop = True
        self.sock.close()


def ice_offer(port):
    return sdp("127.0.0.1", port, extra=["a=ice-ufrag:abcd", "a=ice-pwd:abcdefghijklmnopqrstuvwx",
                                         f"a=candidate:1 1 UDP 2122260223 127.0.0.1 {port} typ host", "a=rtcp-mux"])


def candidates(s: Sdp):
    return [c for m in s.media for c in m.attr("candidate")]


def scenario(r):
    stun = StunServer(STUN_PORT)
    ifaces = [("nat", "127.0.0.1", None), ("fixed", "127.0.0.2", "198.51.100.9")]
    cfg = base_config(NG, ports=PORTS, interfaces=ifaces, extra=f'[ice]\nstun_server = "127.0.0.1:{STUN_PORT}"\n')
    try:
        with Relay(cfg, NG, "srflx") as relay:
            time.sleep(1.0)  # the first discovery runs at start
            srcs = {s[0] for s in stun.requests}
            r.check("127.0.0.1" in srcs, "the relay asks the STUN server from the interface without advertise")
            r.check("127.0.0.2" not in srcs, "but not from the one with advertise (its address is known)")

            ep = Endpoint()
            o = Sdp(relay.ok("offer", call_id="s1", from_tag="a", sdp=ice_offer(ep.port), direction=["nat", "nat"],
                             flags=["trust-address"])["sdp"])
            c = candidates(o)
            host = [x for x in c if "typ host" in x]
            refl = [x for x in c if "typ srflx" in x]
            r.check(len(host) >= 1 and "127.0.0.1" in host[0], "the relay offers its host candidate", str(c))
            r.check(len(refl) >= 1 and PUBLIC in refl[0], f"and a server-reflexive one with the public address {PUBLIC}",
                    str(c))
            if refl and host:
                f = refl[0].split()
                port_host = host[0].split()[5]
                r.check(f[5] == port_host and "raddr 127.0.0.1" in refl[0] and f"rport {port_host}" in refl[0],
                        "on the media port, with raddr/rport the host candidate (RFC 8445 §5.1.1.2)", refl[0])
                pri = lambda x: int(x.split()[3])  # noqa: E731
                r.check(pri(host[0]) > pri(refl[0]), "host preferred over srflx (priority)")
            r.check(o.addr() == "127.0.0.1", "c= keeps the interface's own address (the candidates carry the public one)")
            a = Sdp(relay.ok("answer", call_id="s1", from_tag="a", to_tag="b", sdp=ice_offer(Endpoint().port),
                             flags=["trust-address"])["sdp"])
            r.check(any(PUBLIC in x for x in candidates(a)), "the answer to the caller carries it too")

            # the interface with advertise: no STUN, no srflx
            o = Sdp(relay.ok("offer", call_id="s2", from_tag="a", sdp=ice_offer(ep.port), direction=["fixed", "fixed"],
                             flags=["trust-address"])["sdp"])
            c = candidates(o)
            r.check(not any("srflx" in x for x in c) and any("198.51.100.9" in x for x in c),
                    "an interface with advertise offers its advertised address, no srflx", str(c))

            # non-ICE endpoints never see candidates
            o = Sdp(relay.ok("offer", call_id="s3", from_tag="a", sdp=sdp("127.0.0.1", ep.port), direction=["nat", "nat"],
                             flags=["trust-address"])["sdp"])
            r.check(not candidates(o), "an endpoint without ICE gets no candidates")

        # --- a STUN server that never answers
        stun.answer = False
        with Relay(cfg, NG, "srflx-silent") as relay:
            time.sleep(4.0)  # a 3 s discovery timeout
            o = Sdp(relay.ok("offer", call_id="s4", from_tag="a", sdp=ice_offer(Endpoint().port),
                             direction=["nat", "nat"], flags=["trust-address"])["sdp"])
            r.check(not any("srflx" in x for x in candidates(o)), "no answer from STUN: only the host candidate")
            r.check(any(f"no answer from 127.0.0.1:{STUN_PORT}" in ln for ln in relay.log().splitlines()),
                    "and the log says the STUN server did not answer")
            r.check(relay.ng("ping")["result"] == "pong", "the relay works on without it")
    finally:
        stun.close()

    # --- an invalid stun_server is refused at start
    bad = Relay(base_config(NG, ports=PORTS, extra='[ice]\nstun_server = ":3478"\n'), NG, "srflx-bad")
    res = bad.check_config()
    r.check(res.returncode != 0 and "stun_server" in res.stderr, "ice.stun_server ':3478' is refused by --check",
            res.stderr[-200:])
    bad.cleanup()


if __name__ == "__main__":
    main(scenario)
