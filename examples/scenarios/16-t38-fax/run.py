#!/usr/bin/env python3
"""Fax over IP (T.38, ITU-T T.38 / RFC 3362): a call starts as audio and
is re-INVITEd to `m=image <port> udptl t38`. The relay must keep the
T38 attributes, relay every UDPTL datagram unchanged (they are not RTP),
latch on them, and switch back to audio. It is not a fax gateway: both
ends must speak T.38."""

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import Endpoint, Relay, Sdp, base_config, main, parse_rtp, sdp  # noqa: E402

NG = 20316
PORTS = (30600, 30799)
T38 = ["a=T38FaxVersion:0", "a=T38MaxBitRate:14400", "a=T38FaxRateManagement:transferredTCF",
       "a=T38FaxMaxBuffer:262", "a=T38FaxMaxDatagram:316", "a=T38FaxUdpEC:t38UDPRedundancy"]


def image(port, extra=()):
    return sdp("127.0.0.1", 0, sections=[dict(port=port, media="image", proto="udptl", pts=("t38",),
                                              extra=[*T38, *extra])])


def udptl(seq: int, ifp: bytes) -> bytes:
    """A UDPTL packet (T.38 §9.1): sequence number, primary IFP, and an
    empty redundancy list. Not RTP: its first octet is the sequence's."""
    return struct.pack("!H", seq) + bytes([len(ifp)]) + ifp + b"\x00"


def scenario(r):
    with Relay(base_config(NG, ports=PORTS), NG, "fax") as relay:
        fax_a, fax_b = Endpoint(), Endpoint()
        # an ordinary audio call first
        relay.ok("offer", call_id="fax", from_tag="a", sdp=sdp("127.0.0.1", fax_a.port), flags=["trust-address"])
        relay.ok("answer", call_id="fax", from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", fax_b.port),
                 flags=["trust-address"])

        # the fax tone is detected: re-INVITE to T.38
        o = Sdp(relay.ok("offer", call_id="fax", from_tag="a", to_tag="b", sdp=image(fax_a.port),
                         flags=["trust-address"])["sdp"])
        m = o.media[0]
        r.check(m.kind == "image" and m.proto == "udptl" and m.fmts == ["t38"], "the re-INVITE is offered as udptl t38",
                str(m))
        kept = [a for a in m.attrs if a.startswith("T38")]
        r.check(len(kept) == len(T38), f"every a=T38… attribute is kept ({len(kept)} of {len(T38)})")
        r.check(not any(a.startswith(("rtpmap", "rtcp", "crypto")) for a in m.attrs),
                "no RTP attributes are added to the image section", str(m.attrs))
        a = Sdp(relay.ok("answer", call_id="fax", from_tag="a", to_tag="b", sdp=image(fax_b.port),
                         flags=["trust-address"])["sdp"])
        r.check(a.media[0].kind == "image" and a.media[0].port != 0, "the answer comes back as T.38")

        # UDPTL both ways, byte for byte, including datagrams that look like
        # nothing the relay knows
        pages = [udptl(i, bytes([0x06, 0xD0]) + bytes(range(i % 200)) * 1) for i in range(30)]
        for p in pages:
            fax_a.send(p, a.dest())
        got = [d for d, _ in fax_b.recv_all(0.6)]
        r.check(got == pages, f"30 UDPTL datagrams reach the other fax unchanged ({len(got)})")
        back = [udptl(i, b"\x00\x01") for i in range(10)]
        for p in back:
            fax_b.send(p, o.dest())
        r.check([d for d, _ in fax_a.recv_all(0.5)] == back, "and the other way")
        odd = [b"\x80" * 12, b"\x00", b"\xff" * 400, bytes([0x16, 0xfe, 0xfd]) + b"\x00" * 20]
        for p in odd:
            fax_a.send(p, a.dest())
        r.check([d for d, _ in fax_b.recv_all(0.4)] == odd,
                "datagrams that look like RTP, DTLS or nothing are relayed as they are on a T.38 section")
        q = relay.ok("query", call_id="fax")
        st = q["tags"]["a"]["medias"][0]["streams"][0]["stats"]
        r.check(st["packets"] == 34, f"query counts the 34 UDPTL datagrams fax A sent ({st['packets']})")

        # latching works on UDPTL: a fax machine behind NAT whose SDP names
        # a private address nothing sends from
        nat, peer = Endpoint(), Endpoint()
        on = Sdp(relay.ok("offer", call_id="nat-fax", from_tag="a", flags=["trust-address"],
                          sdp=image(4000).replace("127.0.0.1", "127.0.0.250"))["sdp"])
        an = Sdp(relay.ok("answer", call_id="nat-fax", from_tag="a", to_tag="b", sdp=image(peer.port),
                          flags=["trust-address"])["sdp"])
        for p in pages[:3]:
            nat.send(p, an.dest())
        r.check(len(peer.recv_all(0.3)) == 3, "a NATed fax's UDPTL reaches the other side")
        peer.send(back[0], on.dest())
        r.check(len(nat.recv_all(0.3)) == 1, "and the relay latches onto its real source for the way back")
        relay.ok("delete", call_id="nat-fax")

        # back to audio after the fax
        o2 = Sdp(relay.ok("offer", call_id="fax", from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", fax_a.port),
                          flags=["trust-address"])["sdp"])
        a2 = Sdp(relay.ok("answer", call_id="fax", from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", fax_b.port),
                          flags=["trust-address"])["sdp"])
        r.check(o2.media[0].kind == "audio" and o2.media[0].proto == "RTP/AVP", "a re-INVITE back to audio")
        fax_a.drain(), fax_b.drain()
        fax_a.send_rtp(a2.dest(), n=3)
        got = [parse_rtp(d) for d, _ in fax_b.recv_all(0.3)]
        r.check(len(got) == 3 and all(p and p["pt"] == 0 for p in got), "RTP flows again after the fax")

        # audio and T.38 in one offer (some gateways offer both)
        both = sdp("127.0.0.1", 0, sections=[
            dict(port=fax_a.port, pts=(0,)),
            dict(port=fax_a.port + 2, media="image", proto="udptl", pts=("t38",), extra=T38)])
        rep = relay.ng("offer", call_id="fax2", from_tag="a", sdp=both, flags=["trust-address"])
        r.check(rep.get("result") == "ok" and [m.kind for m in Sdp(rep["sdp"]).media] == ["audio", "image"],
                "an offer with audio and T.38 sections relays both")
        relay.ng("delete", call_id="fax2")

        # transcoding asked on a T.38 call: nothing to transcode, the section passes
        rep = relay.ng("offer", call_id="fax3", from_tag="a", sdp=image(5000), codec={"transcode": ["PCMA"]})
        r.check(rep.get("result") == "ok" and Sdp(rep["sdp"]).media[0].fmts == ["t38"],
                "codec transcode on a T.38-only offer leaves the image section alone", str(rep)[:120])
        relay.ng("delete", call_id="fax3")

        # T.38 to G.711 fax is not converted: a T.38 offer answered with
        # audio is a mismatch the relay does not bridge
        relay.ok("offer", call_id="fax4", from_tag="a", sdp=image(5000), flags=["trust-address"])
        rep = relay.ng("answer", call_id="fax4", from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", 5002))
        r.check(rep.get("result") == "error",
                "a T.38 offer answered with G.711 audio is refused (no fax gateway; RFC 3264 keeps the media type)",
                str(rep)[:140])


if __name__ == "__main__":
    main(scenario)
