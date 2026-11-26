#!/usr/bin/env python3
"""ZRTP softphones (RFC 6189: Linphone, Jitsi, Zoiper, Acrobits): the
phones agree SRTP keys end to end inside the media stream. When the
relay only relays, ZRTP packets and `a=zrtp-hash` must pass untouched;
when the relay changes the media (SDES termination, transcoding), end-
to-end keys cannot work, so both are removed and the phones see ZRTP is
unavailable instead of failing half-way."""

import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import Endpoint, Relay, Sdp, base_config, crypto_line, http_get, main, sdp  # noqa: E402

NG = 20317
METRICS = NG + 100
PORTS = (30800, 30999)
HASH = "a=zrtp-hash:1.10 " + "ab" * 32


def zrtp(seq: int, ssrc: int, msg: bytes) -> bytes:
    """A ZRTP packet (RFC 6189 §5): 0x10, seq, the 'ZRTP' magic cookie,
    the source id, a message, and the CRC-32C… here plain CRC-32 (the
    relay never checks it; only the first octet tells ZRTP apart)."""
    body = bytes([0x10, 0x00]) + struct.pack("!H", seq) + b"ZRTP" + struct.pack("!I", ssrc) + msg
    return body + struct.pack("!I", zlib.crc32(body))


HELLO = b"\x50\x5a\x00\x1dHello   1.10" + b"\x00" * 64


def call(relay, cid, a_extra=(), b_extra=(), proto="RTP/AVP", **opts):
    alice, bob = Endpoint(), Endpoint()
    o = Sdp(relay.ok("offer", call_id=cid, from_tag="a", flags=["trust-address"],
                     sdp=sdp("127.0.0.1", alice.port, proto=proto, extra=[*a_extra]), **opts)["sdp"])
    a = Sdp(relay.ok("answer", call_id=cid, from_tag="a", to_tag="b", flags=["trust-address"],
                     sdp=sdp("127.0.0.1", bob.port, pts=tuple(int(f) for f in o.media[0].fmts[:1]),
                             extra=[*b_extra]))["sdp"])
    return alice, bob, o, a


def metric(name):
    _, body = http_get(f"http://127.0.0.1:{METRICS}/metrics")
    for ln in body.splitlines():
        if ln.startswith(name + " ") or ln.startswith(name + "{"):
            return float(ln.split()[-1])
    return 0.0


def scenario(r):
    cfg = base_config(NG, ports=PORTS, extra=f'[metrics]\nlisten = ["127.0.0.1:{METRICS}"]\n')
    with Relay(cfg, NG, "zrtp") as relay:
        # --- plain relaying: ZRTP passes, a=zrtp-hash is kept
        alice, bob, o, a = call(relay, "e2e", a_extra=[HASH], b_extra=[HASH])
        r.check(o.media[0].attr("zrtp-hash") == [HASH.split(":", 1)[1]], "a=zrtp-hash reaches the callee unchanged")
        r.check(a.media[0].has("zrtp-hash"), "and the callee's comes back to the caller")
        before = metric("rtpflux_zrtp_forwarded_total")
        hello_a = [zrtp(i, alice.ssrc, HELLO) for i in range(3)]
        for p in hello_a:
            alice.send(p, a.dest())
        r.check([d for d, _ in bob.recv_all(0.4)] == hello_a, "the caller's ZRTP Hello packets reach the callee byte for byte")
        hello_b = [zrtp(i, bob.ssrc, HELLO) for i in range(2)]
        for p in hello_b:
            bob.send(p, o.dest())
        r.check([d for d, _ in alice.recv_all(0.4)] == hello_b, "and the callee's reach the caller")
        # then the phones switch to SRTP with their own keys: opaque to the relay
        srtp_like = [bytes([0x80, 0x00]) + struct.pack("!HII", i, i * 160, alice.ssrc) + os.urandom(170) for i in range(5)]
        for p in srtp_like:
            alice.send(p, a.dest())
        r.check([d for d, _ in bob.recv_all(0.4)] == srtp_like, "their end-to-end SRTP is relayed untouched")
        after = metric("rtpflux_zrtp_forwarded_total")
        r.check(after - before == 5, f"rtpflux_zrtp_forwarded_total counts the 5 ZRTP packets ({after - before:.0f})")
        st = relay.ok("statistics")["statistics"]["totalstatistics"]
        r.check(st.get("zrtppackets", 0) >= 5, f"statistics: zrtppackets ({st.get('zrtppackets')})")
        relay.ok("delete", call_id="e2e")

        # --- the relay terminates SDES on one side: ZRTP is dropped, the hash removed
        line, _ = crypto_line(1)
        alice, bob, o, a = call(relay, "sdes", a_extra=[HASH, line], b_extra=[HASH], proto="RTP/SAVP",
                                transport_protocol="RTP/AVP")
        r.check(not o.media[0].has("zrtp-hash") and not a.media[0].has("zrtp-hash"),
                "with SDES terminated by the relay, a=zrtp-hash is removed both ways")
        alice.send(zrtp(0, alice.ssrc, HELLO), a.dest())
        bob.send(zrtp(0, bob.ssrc, HELLO), o.dest())
        r.check(not bob.recv_all(0.3) and not alice.recv_all(0.2), "and ZRTP packets are dropped both ways")
        relay.ok("delete", call_id="sdes")

        # --- transcoding: the relay rewrites the audio, so no ZRTP
        alice, bob, o, a = call(relay, "xcode", a_extra=[HASH], b_extra=[HASH],
                                codec={"transcode": ["PCMA"], "mask": ["PCMU"]})
        r.check(not o.media[0].has("zrtp-hash"), "a transcoded call drops a=zrtp-hash")
        alice.send(zrtp(0, alice.ssrc, HELLO), a.dest())
        r.check(not bob.recv_all(0.3), "and ZRTP packets")
        relay.ok("delete", call_id="xcode")

        # --- only one phone does ZRTP: the hash passes, the other ignores it
        alice, bob, o, a = call(relay, "one", a_extra=[HASH])
        r.check(o.media[0].has("zrtp-hash") and not a.media[0].has("zrtp-hash"),
                "one ZRTP phone: its hash passes, the plain phone answers without one")
        alice.send(zrtp(0, alice.ssrc, HELLO), a.dest())
        r.check(len(bob.recv_all(0.3)) == 1, "its Hello still reaches the other phone (which ignores it)")
        relay.ok("delete", call_id="one")

        # --- every first octet 16..19 is ZRTP (RFC 7983), 20..63 DTLS, 128..191 RTP
        alice, bob, o, a = call(relay, "demux")
        for first in (16, 17, 18, 19):
            alice.send(bytes([first]) + b"\x00" * 30, a.dest())
        got = [d[0] for d, _ in bob.recv_all(0.4)]
        r.check(got == [16, 17, 18, 19], f"first octets 16..19 are relayed as ZRTP on a plain call ({got})")
        alice.send(bytes([20]) + b"\x00" * 30, a.dest())
        r.check(not bob.recv_all(0.3), "a DTLS-looking datagram (20) on a non-DTLS call is not relayed")


if __name__ == "__main__":
    main(scenario)
