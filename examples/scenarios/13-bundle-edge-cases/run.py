#!/usr/bin/env python3
"""BUNDLE (RFC 8843) between a browser-like party that bundles audio and
video on one port and a phone with a port per stream: sorting by payload
type and RTCP by SSRC, bundle-only (max-bundle), re-INVITEs from either
side, streams added and removed, and packets no section claims. Plain
RTP/AVPF here (DTLS needs a browser: webrtc-firefox.py --video covers
it), with SDES keys per section in one case."""

import os
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import (  # noqa: E402
    Endpoint, Relay, Sdp, base_config, crypto_line, main, parse_crypto, parse_rtp, rtcp_sr, rtp, sdp,
)

NG = 20313
PORTS = (30000, 30199)


def bundled(port, bundle_only=False, extra_video=(), sections=2, proto="RTP/AVPF", crypto=None):
    """The browser's offer: audio (mid 0) and video (mid 1) on one port."""
    common = ["a=rtcp-mux", "a=sendrecv"]
    secs = [dict(port=port, pts=(0,), proto=proto, extra=["a=mid:0", *common] + ([crypto[0]] if crypto else []))]
    if sections >= 2:
        vport = 0 if bundle_only else port
        secs.append(dict(port=vport, media="video", pts=(96,), proto=proto,
                         extra=["a=mid:1", *common, "a=rtpmap:96 VP8/90000", *extra_video,
                                *(["a=bundle-only"] if bundle_only else []), *([crypto[1]] if crypto else [])]))
    if sections >= 3:
        secs.append(dict(port=port, media="video", pts=(97,), proto=proto,
                         extra=["a=mid:2", *common, "a=rtpmap:97 VP8/90000"]))
    mids = " ".join(str(i) for i in range(sections))
    return sdp("127.0.0.1", port, sections=secs, session_extra=[f"a=group:BUNDLE {mids}"])


def phone_answer(ports, proto="RTP/AVP", pts=((0,), (96,), (97,)), crypto=None):
    secs = []
    for i, p in enumerate(ports):
        secs.append(dict(port=p, media="audio" if i == 0 else "video", pts=pts[i], proto=proto,
                         extra=([f"a=rtpmap:{pts[i][0]} VP8/90000"] if i else []) + ([crypto[i]] if crypto else [])))
    return sdp("127.0.0.1", 0, sections=secs)


def scenario(r):
    with Relay(base_config(NG, ports=PORTS), NG, "bundle") as relay:
        br, ph_a, ph_v = Endpoint(), Endpoint(), Endpoint()
        o = Sdp(relay.ok("offer", call_id="b1", from_tag="br", sdp=bundled(br.port), flags=["trust-address"],
                         transport_protocol="RTP/AVP")["sdp"])
        r.check(len({m.port for m in o.media}) == 2 and not o.session_attr("group"),
                "the phone is offered a port per stream, no BUNDLE group")
        a = Sdp(relay.ok("answer", call_id="b1", from_tag="br", to_tag="ph",
                         sdp=phone_answer([ph_a.port, ph_v.port]), flags=["trust-address"])["sdp"])
        r.check(len({m.port for m in a.media}) == 1 and a.session_attr("group") == ["BUNDLE 0 1"],
                "the browser is answered one shared port and its BUNDLE group", str(a.session_attr("group")))
        shared = a.dest(0)

        # browser -> phone: one port in, sorted by payload type
        br.send_rtp(shared, pt=0, n=4, payload=b"\xa0" * 160)
        br.send_rtp(shared, pt=96, n=3, payload=b"\x96" * 500)
        got_a = [parse_rtp(d) for d, _ in ph_a.recv_all(0.4)]
        got_v = [parse_rtp(d) for d, _ in ph_v.recv_all(0.2)]
        r.check([p["pt"] for p in got_a] == [0] * 4 and [p["pt"] for p in got_v] == [96] * 3,
                "bundled audio goes to the phone's audio port, video to its video port",
                f"audio {[p['pt'] for p in got_a]}, video {[p['pt'] for p in got_v]}")
        # phone -> browser: two ports in, one out
        ph_a.send_rtp(o.dest(0), pt=0, n=3)
        ph_v.send_rtp(o.dest(1), pt=96, n=2, payload=b"\x96" * 500)
        got = br.recv_all(0.4)
        r.check(sorted(parse_rtp(d)["pt"] for d, _ in got) == [0, 0, 0, 96, 96] and {s for _, s in got} == {shared},
                "the phone's two streams reach the browser from the one shared port")
        # RTCP on the bundled port, sorted by the sender's SSRC
        rtcp_a, rtcp_v = Endpoint("127.0.0.1", ph_a.port + 1), Endpoint("127.0.0.1", ph_v.port + 1)
        br.send(rtcp_sr(0x0A0A0A0A), shared)
        br.send(rtcp_sr(0x0B0B0B0B), shared)
        # The relay learns which SSRC is which from the RTP it saw: send one of each first.
        br.send(rtp(0, 1, 0, 0x0A0A0A0A, b"\xa0" * 160), shared)
        br.send(rtp(96, 1, 0, 0x0B0B0B0B, b"\x96" * 100), shared)
        time.sleep(0.1)
        ph_a.drain(), ph_v.drain(), rtcp_a.drain(), rtcp_v.drain()
        br.send(rtcp_sr(0x0A0A0A0A), shared)
        br.send(rtcp_sr(0x0B0B0B0B), shared)
        ra = [struct.unpack("!I", d[4:8])[0] for d, _ in rtcp_a.recv_all(0.3)]
        rv = [struct.unpack("!I", d[4:8])[0] for d, _ in rtcp_v.recv_all(0.2)]
        r.check(ra == [0x0A0A0A0A] and rv == [0x0B0B0B0B], "bundled RTCP is sorted to the stream of its SSRC",
                f"audio RTCP {ra}, video RTCP {rv}")
        # A payload type no section has: dropped
        ph_a.drain(), ph_v.drain()
        br.send_rtp(shared, pt=111, n=3)
        r.check(not ph_a.recv_all(0.2) and not ph_v.recv_all(0.1), "a payload type no bundled section has is dropped")

        # the phone re-INVITEs: the browser is offered its group again on the same port
        # Without transport-protocol the browser would be offered the phone's
        # RTP/AVP: a bundled side must keep its profile, so that is refused.
        o2 = relay.ng("offer", call_id="b1", from_tag="ph", to_tag="br",
                      sdp=phone_answer([ph_a.port, ph_v.port]), flags=["trust-address"])
        if o2.get("result") == "error":
            r.finding("a phone's re-INVITE to a bundled browser must repeat the browser's profile "
                      "(transport-protocol): without it the relay would re-offer the browser the phone's "
                      f"RTP/AVP, and refuses: {o2.get('error-reason')}")
        o2 = relay.ng("offer", call_id="b1", from_tag="ph", to_tag="br", transport_protocol="RTP/AVPF",
                      sdp=phone_answer([ph_a.port, ph_v.port]), flags=["trust-address"])
        ok = r.check(o2.get("result") == "ok", "a re-INVITE from the phone side (with the browser's profile)",
                     str(o2)[:120])
        if ok:
            s2 = Sdp(o2["sdp"])
            r.check(s2.session_attr("group") == ["BUNDLE 0 1"] and {m.port for m in s2.media} == {shared[1]},
                    "the browser is re-offered BUNDLE on the same shared port", f"{s2.session_attr('group')} {s2.media}")
            relay.ok("answer", call_id="b1", from_tag="ph", to_tag="br", sdp=bundled(br.port), flags=["trust-address"])
            ph_a.drain()
            br.send_rtp(shared, pt=0, n=2)
            r.check(len(ph_a.recv_all(0.3)) == 2, "media flows on after the phone's re-INVITE")

        # the browser removes video (port 0), then brings it back
        o3 = relay.ng("offer", call_id="b1", from_tag="br", to_tag="ph",
                      sdp=bundled(br.port).replace(f"m=video {br.port}", "m=video 0"), flags=["trust-address"],
                      transport_protocol="RTP/AVP")
        r.check(o3.get("result") == "ok", "the browser drops video from the bundle", str(o3)[:140])
        if o3.get("result") == "ok":
            s3 = Sdp(o3["sdp"])
            r.check(s3.media[1].port == 0, "the phone is offered video port 0")
            a3 = Sdp(relay.ok("answer", call_id="b1", from_tag="br", to_tag="ph",
                              sdp=phone_answer([ph_a.port, 0]), flags=["trust-address"])["sdp"])
            if a3.dest(0) != shared or s3.dest(0) != o.dest(0):
                r.finding("dropping a stream from a bundle replaces the whole session: new ports on both sides "
                          f"(browser {shared[1]} -> {a3.media[0].port}, phone {o.media[0].port} -> "
                          f"{s3.media[0].port}); valid RFC 3264, but a browser must redo ICE and DTLS")
            ph_a.drain(), ph_v.drain()
            # The browser now sends audio only (a group of one is no bundle:
            # an ordinary call, whose payload types pass as they are).
            br.send_rtp(a3.dest(0), pt=0, n=2)
            ga, gv = len(ph_a.recv_all(0.3)), len(ph_v.recv_all(0.1))
            r.check(ga == 2 and gv == 0, "audio goes on (to the ports the new SDP gives), video stops",
                    f"audio {ga}, video {gv}")
        o4 = relay.ng("offer", call_id="b1", from_tag="br", to_tag="ph", sdp=bundled(br.port), flags=["trust-address"],
                      transport_protocol="RTP/AVP")
        if o4.get("result") == "ok":
            r.check(True, "video brought back into the bundle")
        else:
            r.finding(f"bringing video back into a bundle (port 0 -> shared port) is refused: {o4.get('error-reason')}")
        # adding a third section to the bundle
        o5 = relay.ng("offer", call_id="b1", from_tag="br", to_tag="ph", sdp=bundled(br.port, sections=3),
                      flags=["trust-address"], transport_protocol="RTP/AVP")
        if o5.get("result") == "ok":
            r.check(len(Sdp(o5["sdp"]).media) == 3, "a third stream added to the bundle reaches the phone")
        else:
            r.finding(f"adding a stream to a bundled call is refused: {o5.get('error-reason')} "
                      "(documented: with BUNDLE the media stay as they were)")
        relay.ok("delete", call_id="b1")

        # bundle-only: max-bundle, the video section has port 0
        br, ph_a, ph_v = Endpoint(), Endpoint(), Endpoint()
        o = Sdp(relay.ok("offer", call_id="b2", from_tag="br", sdp=bundled(br.port, bundle_only=True),
                         flags=["trust-address"], transport_protocol="RTP/AVP")["sdp"])
        r.check(len(o.media) == 2 and o.media[1].port != 0, "a bundle-only section is offered to the phone with a port")
        a = Sdp(relay.ok("answer", call_id="b2", from_tag="br", to_tag="ph",
                         sdp=phone_answer([ph_a.port, ph_v.port]), flags=["trust-address"])["sdp"])
        br.send_rtp(a.dest(0), pt=96, n=2, payload=b"\x96" * 100)
        r.check(len(ph_v.recv_all(0.3)) == 2, "bundle-only video flows over the shared port")
        relay.ok("delete", call_id="b2")

        # a bundle of one is no bundle
        br = Endpoint()
        o = Sdp(relay.ok("offer", call_id="b3", from_tag="br", sdp=bundled(br.port, sections=1),
                         flags=["trust-address"], transport_protocol="RTP/AVP")["sdp"])
        a = Sdp(relay.ok("answer", call_id="b3", from_tag="br", to_tag="ph", sdp=phone_answer([Endpoint().port]),
                         flags=["trust-address"])["sdp"])
        r.check(not a.session_attr("group"), "a BUNDLE group of one section is answered without a group")
        relay.ok("delete", call_id="b3")

        # SDES: each bundled section keeps its own key
        br, ph_a, ph_v = Endpoint(), Endpoint(), Endpoint()
        la, txa = crypto_line(1)
        lv, txv = crypto_line(1)
        o = Sdp(relay.ok("offer", call_id="b4", from_tag="br", flags=["trust-address"], transport_protocol="RTP/AVP",
                         sdp=bundled(br.port, proto="RTP/SAVPF", crypto=(la, lv)))["sdp"])
        a = Sdp(relay.ok("answer", call_id="b4", from_tag="br", to_tag="ph", flags=["trust-address"],
                         sdp=phone_answer([ph_a.port, ph_v.port]))["sdp"])
        keys = [parse_crypto(m.attr("crypto")[0])[2] for m in a.media]
        r.check(len(keys) == 2 and a.media[0].attr("crypto") != a.media[1].attr("crypto"),
                "SDES bundle: the browser gets a relay key per section")
        br.send(txa.protect(rtp(0, 1, 0, 0x1111, b"\xa0" * 160)), a.dest(0))
        br.send(txv.protect(rtp(96, 1, 0, 0x2222, b"\x96" * 100)), a.dest(0))
        got_a = [parse_rtp(d)["pt"] for d, _ in ph_a.recv_all(0.3)]
        got_v = [parse_rtp(d)["pt"] for d, _ in ph_v.recv_all(0.2)]
        r.check(got_a == [0] and got_v == [96], "each section's SRTP, sorted by payload type, decrypts with its own key",
                f"{got_a} {got_v}")
        ph_v.send_rtp(o.dest(1), pt=96, n=1, payload=b"\x96" * 100)
        d = br.recv_all(0.3)
        r.check(len(d) == 1 and keys[1].unprotect(d[0][0]) is not None, "video to the browser uses the video key")
        relay.ok("delete", call_id="b4")

        # a bundled re-offer from the side that did not bundle is refused, the call stays
        br, ph_a, ph_v = Endpoint(), Endpoint(), Endpoint()
        relay.ok("offer", call_id="b5", from_tag="br", sdp=bundled(br.port), flags=["trust-address"],
                 transport_protocol="RTP/AVP")
        relay.ok("answer", call_id="b5", from_tag="br", to_tag="ph", sdp=phone_answer([ph_a.port, ph_v.port]),
                 flags=["trust-address"])
        rep = relay.ng("offer", call_id="b5", from_tag="ph", to_tag="br", sdp=bundled(ph_a.port))
        r.check(rep.get("result") == "error", "a bundled re-offer from the phone is refused", str(rep)[:120])
        r.check(relay.ok("query", call_id="b5")["result"] == "ok", "and the call goes on")


if __name__ == "__main__":
    main(scenario)
