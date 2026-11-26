#!/usr/bin/env python3
"""A browser (WebRTC: ICE, DTLS-SRTP, rtcp-mux, BUNDLE) calling a plain
SIP phone (RTP/AVP). This script plays the browser's SDP and ICE side
in Python and checks the SDP translation and the relay's ICE agent;
DTLS needs a real browser: pass --browser to also run
scripts/webrtc-firefox.py (headless Firefox) for the full media path."""

import hashlib
import hmac
import os
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import (  # noqa: E402
    ROOT, Endpoint, Relay, Sdp, base_config, binding_request, binding_success, main, sdp, stun_parse,
    xor_address,
)

NG = 20303
FINGERPRINT = "sha-256 " + ":".join(f"{b:02X}" for b in hashlib.sha256(b"fake browser cert").digest())


def browser_offer(port, ufrag="brUf", pwd="browserpassword1234567", video=True, bundle=True):
    common = [f"a=ice-ufrag:{ufrag}", f"a=ice-pwd:{pwd}", f"a=fingerprint:{FINGERPRINT}", "a=setup:actpass",
              "a=rtcp-mux", "a=sendrecv"]
    cand = f"a=candidate:1 1 UDP 2122260223 127.0.0.1 {port} typ host"
    secs = [dict(port=port, pts=(111, 0, 101), proto="UDP/TLS/RTP/SAVPF",
                 extra=common + ["a=mid:0", cand, "a=end-of-candidates", "a=ssrc:1111 cname:x"])]
    if video:
        secs.append(dict(port=port, media="video", pts=(96,), proto="UDP/TLS/RTP/SAVPF",
                         extra=common + ["a=mid:1", "a=rtpmap:96 VP8/90000", cand, "a=ssrc:2222 cname:x"]))
    sess = ["a=group:BUNDLE 0 1" if video else "a=group:BUNDLE 0"] if bundle else []
    sess.append("a=msid-semantic: WMS *")
    return sdp("127.0.0.1", port, sections=secs, session_extra=sess)


def integrity_ok(data: bytes, key: bytes) -> bool:
    """Check MESSAGE-INTEGRITY of a STUN message."""
    i = 20
    length = struct.unpack("!H", data[2:4])[0]
    while i + 4 <= 20 + length:
        t, n = struct.unpack("!HH", data[i:i + 4])
        if t == 0x0008:
            head = data[:2] + struct.pack("!H", i + 24 - 20) + data[4:20]
            want = hmac.new(key, head + data[20:i], hashlib.sha1).digest()
            return hmac.compare_digest(want, data[i + 4:i + 24])
        i += 4 + n + (-n % 4)
    return False


def scenario(r):
    cfg = base_config(NG, ports=(23000, 23399))
    with Relay(cfg, NG, "webrtc") as relay:
        browser, phone, phone_video = Endpoint(), Endpoint(), Endpoint()
        offer = relay.ok("offer", call_id="w1", from_tag="browser", sdp=browser_offer(browser.port),
                         transport_protocol="RTP/AVP", flags=["trust-address"])
        o = Sdp(offer["sdp"])
        r.check(len(o.media) == 2 and all(m.proto == "RTP/AVP" for m in o.media),
                "the phone is offered RTP/AVP for audio and video", str(o.media))
        r.check(o.media[0].port != o.media[1].port, "the phone gets a port per stream (no BUNDLE)")
        dtls = [a for m in o.media for a in m.attrs if a.split(":")[0] in ("fingerprint", "setup")]
        r.check(not dtls and not o.session_attr("group"), "no DTLS or BUNDLE attributes towards the phone", str(dtls))
        ice = sorted({a.split(":")[0] for m in o.media for a in m.attrs
                      if a.split(":")[0] in ("ice-ufrag", "ice-pwd", "candidate", "mid", "rtcp-mux")})
        r.check(not {"ice-ufrag", "ice-pwd", "candidate"} & set(ice),
                "a phone bridged from WebRTC with RTP/AVP is offered no ICE", str(ice))
        r.check(not any(m.has("crypto") for m in o.media), "no SDES keys towards a RTP/AVP phone")

        ans = sdp("127.0.0.1", 0, sections=[
            dict(port=phone.port, pts=(0, 101), extra=["a=sendrecv"]),
            dict(port=phone_video.port, media="video", pts=(96,), extra=["a=rtpmap:96 VP8/90000", "a=sendrecv"]),
        ])
        answer = relay.ok("answer", call_id="w1", from_tag="browser", to_tag="phone", sdp=ans,
                          flags=["trust-address"])
        a = Sdp(answer["sdp"])
        r.check(all(m.proto == "UDP/TLS/RTP/SAVPF" for m in a.media), "the browser is answered UDP/TLS/RTP/SAVPF")
        r.check(len({m.port for m in a.media}) == 1, "both sections share one bundled port towards the browser")
        r.check(a.session_attr("group") and "BUNDLE" in a.session_attr("group")[0], "a=group:BUNDLE in the answer")
        m0 = a.media[0]
        fp = m0.attr("fingerprint") or a.session_attr("fingerprint")
        r.check(bool(fp) and fp[0].startswith("sha-256 "), "the relay's DTLS fingerprint (sha-256)")
        setup = m0.attr("setup") or a.session_attr("setup")
        r.check(setup == ["passive"], "answers an actpass offer as DTLS server (setup:passive)", str(setup))
        ufrag = (m0.attr("ice-ufrag") or a.session_attr("ice-ufrag"))[0]
        pwd = (m0.attr("ice-pwd") or a.session_attr("ice-pwd"))[0]
        cands = m0.attr("candidate")
        r.check(bool(cands) and "typ host" in cands[0], "relay offers a host candidate", str(cands))
        r.check(m0.has("rtcp-mux"), "rtcp-mux towards the browser")
        r.check("127.0.0.1" not in " ".join(c for c in cands if str(browser.port) in c),
                "the browser's own candidates are not echoed back")
        ice_opts = m0.attr("ice-options") or a.session_attr("ice-options")
        r.check(any("ice2" in x for x in ice_opts), "full ICE agent: a=ice-options:ice2", str(ice_opts))
        r.check(a.media[0].attr("rtpmap") and any(x.startswith("0 ") for x in a.media[0].attr("rtpmap")),
                "the browser's answer keeps PCMU (the phone picked it)")

        # --- before ICE and DTLS: nothing goes to the browser but STUN
        phone.send_rtp(o.dest(0), n=5, interval=0.01)
        got = browser.recv_all(0.6)
        rtp_like = [d for d, _ in got if d and 128 <= d[0] <= 191]
        r.check(not rtp_like, "no media to the browser before ICE/DTLS complete", f"{len(rtp_like)} RTP packets")
        stun = [stun_parse(d) for d, _ in got if stun_parse(d)]
        r.check(any(s["type"] == 0x0001 for s in stun), "the relay (full agent) sends its own checks to the browser")
        # Answer the relay's checks, as a browser would.
        for d, src in got:
            s = stun_parse(d)
            if s and s["type"] == 0x0001:
                user = s["attrs"].get(0x0006, b"").decode()
                r.check(user == f"brUf:{ufrag}", "relay's check USERNAME is <browser ufrag>:<relay ufrag>", user)
                r.check(integrity_ok(d, b"browserpassword1234567"), "relay's check is signed with the browser's pwd")
                browser.send(binding_success(s["txid"], src, "browserpassword1234567"), src)
                break

        # --- the browser's check to the relay (nominating: it is controlling)
        relay_addr = (a.addr(), a.media[0].port)
        req, txid = binding_request(f"{ufrag}:brUf", pwd, controlling=True, use_candidate=True)
        browser.send(req, relay_addr)
        resp = None
        for d, _ in browser.recv_all(0.6):
            s = stun_parse(d)
            if s and s["txid"] == txid:
                resp = (d, s)
        r.check(resp is not None and resp[1]["type"] == 0x0101, "the relay answers the browser's check with success")
        if resp:
            r.check(integrity_ok(resp[0], pwd.encode()), "the success response is signed with the relay's pwd")
            mapped = xor_address(resp[1]["attrs"].get(0x0020, b"\0" * 8))
            r.check(mapped == (browser.addr, browser.port), "XOR-MAPPED-ADDRESS is the browser's address", str(mapped))

        # Wrong password: no success.
        req, txid = binding_request(f"{ufrag}:brUf", "wrong-password-wrong-password", controlling=True)
        browser.send(req, relay_addr)
        replies = [stun_parse(d) for d, _ in browser.recv_all(0.5)]
        succ = [s for s in replies if s and s["txid"] == txid and s["type"] == 0x0101]
        r.check(not succ, "a check with the wrong password is not answered with success")
        errs = [s for s in replies if s and s["txid"] == txid and s["type"] == 0x0111]
        if not errs:
            r.finding("a check with a wrong MESSAGE-INTEGRITY gets no reply at all "
                      "(RFC 8489 §9.1.3 suggests 401; silence is what many agents do)")
        # Unknown username fragment
        req, txid = binding_request("nope:brUf", pwd, controlling=True)
        browser.send(req, relay_addr)
        succ = [s for s in (stun_parse(d) for d, _ in browser.recv_all(0.4)) if s and s["txid"] == txid and s["type"] == 0x0101]
        r.check(not succ, "a check with an unknown ufrag is not answered with success")

        # ICE done, DTLS not: media still held back (and keys don't exist).
        phone.send_rtp(o.dest(0), n=5, interval=0.01)
        got = [d for d, _ in browser.recv_all(0.4) if d and 128 <= d[0] <= 191]
        r.check(not got, "after ICE but before DTLS, still no media to the browser", f"{len(got)} packets")
        relay.ok("delete", call_id="w1")

        # --- ICE-lite towards the browser
        browser = Endpoint()
        relay.ok("offer", call_id="w2", from_tag="browser", sdp=browser_offer(browser.port, video=False),
                 transport_protocol="RTP/AVP", **{"ICE-lite": "backward"})
        a = Sdp(relay.ok("answer", call_id="w2", from_tag="browser", to_tag="phone",
                         sdp=sdp("127.0.0.1", phone.port))["sdp"])
        lite = a.session_attr("ice-lite") or a.media[0].attr("ice-lite")
        r.check(bool(lite), "ICE-lite: backward puts a=ice-lite in the browser's answer")
        got = [stun_parse(d) for d, _ in browser.recv_all(0.5)]
        r.check(not any(s and s["type"] == 0x0001 for s in got), "an ICE-lite relay sends no checks of its own")

        # --- trickle ICE: a late candidate in an sdpfrag
        frag = ("a=ice-ufrag:brUf\r\na=ice-pwd:browserpassword1234567\r\nm=audio 9 RTP/AVP 0\r\na=mid:0\r\n"
                "a=candidate:2 1 UDP 1694498815 127.0.0.1 40404 typ srflx raddr 127.0.0.1 rport 40404\r\n"
                "a=end-of-candidates\r\n")
        rep = relay.ng("offer", call_id="w2", from_tag="browser", sdp=frag, flags=["fragment"])
        # The phone (bridged to RTP/AVP) has no ICE: nothing to trickle to it.
        r.check(rep.get("result") == "ok" and rep.get("sdp") == "",
                "a trickle-ICE fragment is accepted; nothing to forward to a phone without ICE", str(rep)[:200])
        stale = frag.replace("brUf", "oldU")
        rep = relay.ng("offer", call_id="w2", from_tag="browser", sdp=stale, flags=["fragment"])
        r.check(rep.get("result") in ("ok", "error"), "a fragment of another ICE generation is handled",
                str(rep)[:200])
        rep = relay.ng("offer", call_id="nope", from_tag="browser", sdp=frag, flags=["fragment"])
        r.check(rep.get("result") == "error", "a fragment for an unknown call is an error", str(rep)[:200])
        relay.ok("delete", call_id="w2")

        # --- edge: DTLS offer without a fingerprint
        browser = Endpoint()
        nofp = browser_offer(browser.port, video=False).replace(f"a=fingerprint:{FINGERPRINT}\r\n", "")
        rep = relay.ng("offer", call_id="w3", from_tag="browser", sdp=nofp, transport_protocol="RTP/AVP")
        if rep.get("result") == "ok":
            r.finding("a UDP/TLS/RTP/SAVPF offer WITHOUT a=fingerprint is accepted: the DTLS handshake can "
                      "never be verified, so the call will fail later instead of at offer time")
            relay.ng("delete", call_id="w3")
        else:
            r.check(True, "a DTLS offer without a fingerprint is refused")

        # --- edge: the phone answers with a codec the browser never offered
        browser, phone = Endpoint(), Endpoint()
        relay.ok("offer", call_id="w4", from_tag="browser", sdp=browser_offer(browser.port, video=False),
                 transport_protocol="RTP/AVP")
        rep = relay.ng("answer", call_id="w4", from_tag="browser", to_tag="phone", sdp=sdp("127.0.0.1", phone.port, pts=(18,)))
        r.check(rep.get("result") == "error" and "none of its formats was offered" in rep.get("error-reason", ""),
                "an answer with only a codec never offered (G.729 to Opus/PCMU) is refused", str(rep)[:160])
        relay.ng("delete", call_id="w4")

        # --- edge: a bundled re-offer from the phone side is refused
        browser, phone, phone_v = Endpoint(), Endpoint(), Endpoint()
        relay.ok("offer", call_id="w5", from_tag="browser", sdp=browser_offer(browser.port),
                 transport_protocol="RTP/AVP")
        relay.ok("answer", call_id="w5", from_tag="browser", to_tag="phone", sdp=sdp("127.0.0.1", 0, sections=[
            dict(port=phone.port, pts=(0,)), dict(port=phone_v.port, media="video", pts=(96,),
                                                  extra=["a=rtpmap:96 VP8/90000"])]))
        rep = relay.ng("offer", call_id="w5", from_tag="phone", to_tag="browser", sdp=browser_offer(phone.port))
        r.check(rep.get("result") == "error", "a BUNDLE re-offer from the side that did not bundle is refused",
                str(rep)[:160])
        r.check(relay.ok("query", call_id="w5")["result"] == "ok", "and the call goes on")
        relay.ok("delete", call_id="w5")
        # The same with one section (a BUNDLE group of one, profile switched
        # to UDP/TLS/RTP/SAVPF):
        browser, phone = Endpoint(), Endpoint()
        relay.ok("offer", call_id="w6", from_tag="browser", sdp=browser_offer(browser.port, video=False),
                 transport_protocol="RTP/AVP")
        relay.ok("answer", call_id="w6", from_tag="browser", to_tag="phone", sdp=sdp("127.0.0.1", phone.port))
        rep = relay.ng("offer", call_id="w6", from_tag="phone", to_tag="browser",
                       sdp=browser_offer(phone.port, video=False))
        # A BUNDLE group of one is no BUNDLE (rtpflux ignores groups of
        # fewer than two): an ordinary re-offer, which may change the profile.
        r.check(rep.get("result") == "ok",
                "a one-section 'BUNDLE' re-offer is an ordinary re-offer (a group of one is not bundling)",
                str(rep)[:160])
        relay.ng("delete", call_id="w6")

        # --- a SIP phone with ICE (no DTLS) calling a phone without ICE:
        # the ICE-less side gets media at once, the ICE side after its checks.
        ice_phone, plain = Endpoint(), Endpoint()
        off = sdp("127.0.0.1", ice_phone.port, extra=[
            "a=ice-ufrag:abcd", "a=ice-pwd:abcdefghijklmnopqrstuvwx",
            f"a=candidate:1 1 UDP 2122260223 127.0.0.1 {ice_phone.port} typ host"])
        o = Sdp(relay.ok("offer", call_id="w7", from_tag="a", sdp=off, flags=["trust-address"])["sdp"])
        a = Sdp(relay.ok("answer", call_id="w7", from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", plain.port),
                         flags=["trust-address"])["sdp"])
        ice_phone.send_rtp(a.dest(), n=5, interval=0.01)
        r.check(len(plain.recv_all(0.4)) == 5, "a phone that answered without ICE gets media at once")
        plain.send_rtp(o.dest(), n=5, interval=0.01)
        got = ice_phone.recv_all(0.5)
        r.check(not [d for d, _ in got if 128 <= d[0] <= 191], "the ICE side gets no media before its checks")
        for d, src in got:
            st = stun_parse(d)
            if st and st["type"] == 0x0001:
                ice_phone.send(binding_success(st["txid"], src, "abcdefghijklmnopqrstuvwx"), src)
        aufrag = a.media[0].attr("ice-ufrag")[0]
        apwd = a.media[0].attr("ice-pwd")[0]
        req, _ = binding_request(f"{aufrag}:abcd", apwd, controlling=True, use_candidate=True)
        ice_phone.send(req, a.dest())
        time.sleep(0.2)
        ice_phone.drain()
        plain.send_rtp(o.dest(), n=5, interval=0.01)
        got = [d for d, _ in ice_phone.recv_all(0.5) if 128 <= d[0] <= 191]
        r.check(len(got) == 5, "after a nominated check succeeds, the ICE side gets media", str(len(got)))
        relay.ok("delete", call_id="w7")

    # --- optional: the whole path with a real browser
    if "--browser" in sys.argv:
        script = os.path.join(ROOT, "scripts", "webrtc-firefox.py")
        for args in ([], ["--video"], ["--lite"]):
            res = subprocess.run([sys.executable, script, *args], capture_output=True, text=True, timeout=180)
            r.check(res.returncode == 0, f"headless Firefox <-> plain RTP phone {' '.join(args) or '(audio)'}",
                    (res.stdout + res.stderr)[-400:])
    else:
        r.skip("real browser path (DTLS + SRTP media): run with --browser")


if __name__ == "__main__":
    main(scenario)
