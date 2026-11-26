#!/usr/bin/env python3
"""Encryption at the boundary: SDES-SRTP on one side, plain RTP on the
other (both ways round), and SRTP on both sides with different keys.
The SRTP here is a separate implementation (RFC 3711, in Python), so a
packet that decrypts proves interoperability, not self-consistency."""

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import (  # noqa: E402
    Endpoint, Relay, Sdp, base_config, crypto_line, main, parse_crypto, parse_rtp, rtcp_sr, rtp, sdp,
)

NG = 20304


def send_srtp(ep, ctx, dst, n, pt=0, payload=b"\x55" * 160, start_seq=None):
    if start_seq is not None:
        ep.seq = start_seq
    for _ in range(n):
        ep.send(ctx.protect(rtp(pt, ep.seq, ep.ts, ep.ssrc, payload)), dst)
        ep.seq = (ep.seq + 1) & 0xFFFF
        ep.ts = (ep.ts + 160) & 0xFFFFFFFF


def decrypt_all(ctx, got):
    out = []
    for d, _ in got:
        p = ctx.unprotect(d)
        out.append(parse_rtp(p) if p else None)
    return out


def srtp_to_plain(r, relay, suite, cid, params=""):
    alice, bob = Endpoint(), Endpoint()
    line, alice_tx = crypto_line(1, suite, params=params)
    o = Sdp(relay.ok("offer", call_id=cid, from_tag="a", sdp=sdp("127.0.0.1", alice.port, proto="RTP/SAVP", extra=[line]),
                     transport_protocol="RTP/AVP", flags=["trust-address"])["sdp"])
    r.check(o.media[0].proto == "RTP/AVP" and not o.media[0].has("crypto"),
            f"{suite}: the plain phone is offered RTP/AVP without keys", str(o.media[0].attrs))
    a = Sdp(relay.ok("answer", call_id=cid, from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", bob.port),
                     flags=["trust-address"])["sdp"])
    cr = a.media[0].attr("crypto")
    r.check(a.media[0].proto == "RTP/SAVP" and len(cr) == 1, f"{suite}: alice is answered RTP/SAVP with one key")
    tag, rsuite, relay_tx = parse_crypto(cr[0])
    r.check(tag == 1 and rsuite == suite, f"{suite}: the answer keeps alice's tag and suite", cr[0])
    send_srtp(alice, alice_tx, a.dest(), 10, payload=b"\x55" * 160)
    got = [parse_rtp(d) for d, _ in bob.recv_all(0.5)]
    r.check(len(got) == 10 and all(p and p["payload"] == b"\x55" * 160 for p in got),
            f"{suite}: alice's SRTP reaches bob decrypted", f"{len(got)} packets")
    bob.send_rtp(o.dest(), n=10, payload=b"\x66" * 160)
    dec = decrypt_all(relay_tx, alice.recv_all(0.5))
    r.check(len(dec) == 10 and all(p and p["payload"] == b"\x66" * 160 for p in dec),
            f"{suite}: bob's RTP reaches alice encrypted with the relay's key", f"{sum(1 for p in dec if p)}/{len(dec)}")
    return alice, bob, alice_tx, relay_tx, o, a


def scenario(r):
    with Relay(base_config(NG, ports=(24000, 24399)), NG, "srtp") as relay:
        for i, suite in enumerate(["AES_CM_128_HMAC_SHA1_80", "AES_CM_128_HMAC_SHA1_32",
                                   "AES_256_CM_HMAC_SHA1_80", "AES_256_CM_HMAC_SHA1_32"]):
            srtp_to_plain(r, relay, suite, f"s{i}")
            relay.ok("delete", call_id=f"s{i}")

        alice, bob, alice_tx, relay_tx, o, a = srtp_to_plain(r, relay, "AES_CM_128_HMAC_SHA1_80", "main")
        before = relay.ok("statistics")["statistics"]["totalstatistics"].get("srtprejected", 0)

        # --- a tampered packet is dropped and counted
        pkt = bytearray(alice_tx.protect(rtp(0, alice.seq, alice.ts, alice.ssrc, b"\x55" * 160)))
        alice.seq += 1
        pkt[20] ^= 1
        alice.send(bytes(pkt), a.dest())
        r.check(not bob.recv_all(0.3), "a tampered SRTP packet is dropped")
        # --- a replayed packet too
        good = alice_tx.protect(rtp(0, alice.seq, alice.ts, alice.ssrc, b"\x55" * 160))
        alice.seq += 1
        alice.send(good, a.dest())
        r.check(len(bob.recv_all(0.3)) == 1, "the original is relayed")
        alice.send(good, a.dest())
        r.check(not bob.recv_all(0.3), "its replay is dropped")
        # --- plain RTP sent to the SRTP side is not relayed
        alice.send_rtp(a.dest(), n=2)
        r.check(not bob.recv_all(0.3), "plain RTP on the SRTP side is dropped")
        after = relay.ok("statistics")["statistics"]["totalstatistics"].get("srtprejected", 0)
        r.check(after - before >= 4, "rejections are counted (srtprejected)", f"{before} -> {after}")

        # --- rollover: sequence numbers wrap around 65535
        send_srtp(alice, alice_tx, a.dest(), 6, start_seq=65533)
        got = bob.recv_all(0.5)
        r.check(len(got) == 6, "SRTP across a sequence-number wrap (ROC 0 -> 1) is decrypted", str(len(got)))
        bob.seq = 65533
        bob.send_rtp(o.dest(), n=6)
        dec = decrypt_all(relay_tx, alice.recv_all(0.5))
        r.check(len(dec) == 6 and all(dec), "the relay's own SRTP keeps its ROC across the wrap",
                f"{sum(1 for p in dec if p)}/{len(dec)}")

        # --- SRTCP: alice's encrypted RTCP reaches bob as plain RTCP
        bob_rtcp = Endpoint("127.0.0.1", bob.port + 1)
        alice.send(alice_tx.protect_rtcp(rtcp_sr(alice.ssrc)), (a.addr(), a.media[0].port + 1))
        got = bob_rtcp.recv_all(0.4)
        r.check(len(got) == 1 and got[0][0][1] == 200 and struct.unpack("!I", got[0][0][4:8])[0] == alice.ssrc,
                "SRTCP from alice reaches bob decrypted", str([d[:8] for d, _ in got]))

        # --- keys never reach the log
        log = relay.log()
        leaked = [ln for ln in log.splitlines() if "inline:" in ln or "a=crypto" in ln]
        r.check(not leaked, "no SDES key material in the relay's log", leaked[:1] and leaked[0][:120])
        relay.ok("delete", call_id="main")

        # --- plain offerer, SRTP answerer (the other way round)
        alice, bob = Endpoint(), Endpoint()
        o = Sdp(relay.ok("offer", call_id="rev", from_tag="a", sdp=sdp("127.0.0.1", alice.port),
                         transport_protocol="RTP/SAVP", flags=["trust-address"])["sdp"])
        cr = o.media[0].attr("crypto")
        r.check(o.media[0].proto == "RTP/SAVP" and cr, "a plain caller's offer reaches the callee as RTP/SAVP with keys",
                str(o.media[0].attrs))
        offered = [parse_crypto(c) for c in cr if c.split()[1] in ("AES_CM_128_HMAC_SHA1_80",)]
        tag, suite, relay_tx = offered[0]
        line, bob_tx = crypto_line(tag, suite)
        a = Sdp(relay.ok("answer", call_id="rev", from_tag="a", to_tag="b",
                         sdp=sdp("127.0.0.1", bob.port, proto="RTP/SAVP", extra=[line]), flags=["trust-address"])["sdp"])
        r.check(a.media[0].proto == "RTP/AVP" and not a.media[0].has("crypto"), "the plain caller is answered RTP/AVP")
        send_srtp(bob, bob_tx, o.dest(), 5, payload=b"\x77" * 160)
        got = [parse_rtp(d) for d, _ in alice.recv_all(0.5)]
        r.check(len(got) == 5 and all(p["payload"] == b"\x77" * 160 for p in got), "callee's SRTP reaches the caller decrypted")
        alice.send_rtp(a.dest(), n=5, payload=b"\x11" * 160)
        dec = decrypt_all(relay_tx, bob.recv_all(0.5))
        r.check(len(dec) == 5 and all(dec), "caller's RTP reaches the callee with the key the relay offered")
        if len(cr) > 1:
            r.check(True, f"the relay offers {len(cr)} suites: {', '.join(c.split()[1] for c in cr)}")
        relay.ok("delete", call_id="rev")

        # --- SRTP on both sides, different keys
        alice, bob = Endpoint(), Endpoint()
        line_a, alice_tx = crypto_line(1)
        o = Sdp(relay.ok("offer", call_id="both", from_tag="a",
                         sdp=sdp("127.0.0.1", alice.port, proto="RTP/SAVP", extra=[line_a]), flags=["trust-address"])["sdp"])
        tag, suite, relay_to_bob = parse_crypto(o.media[0].attr("crypto")[0])
        r.check(o.media[0].attr("crypto")[0].split("inline:")[1] != line_a.split("inline:")[1],
                "SRTP both sides: the callee gets the relay's key, not the caller's")
        line_b, bob_tx = crypto_line(tag, suite)
        a = Sdp(relay.ok("answer", call_id="both", from_tag="a", to_tag="b",
                         sdp=sdp("127.0.0.1", bob.port, proto="RTP/SAVP", extra=[line_b]), flags=["trust-address"])["sdp"])
        _, _, relay_to_alice = parse_crypto(a.media[0].attr("crypto")[0])
        send_srtp(alice, alice_tx, a.dest(), 5)
        dec = decrypt_all(relay_to_bob, bob.recv_all(0.5))
        r.check(len(dec) == 5 and all(dec), "SRTP both sides: alice -> bob re-encrypted")
        send_srtp(bob, bob_tx, o.dest(), 5)
        dec = decrypt_all(relay_to_alice, alice.recv_all(0.5))
        r.check(len(dec) == 5 and all(dec), "SRTP both sides: bob -> alice re-encrypted")
        # A re-INVITE keeps the relay's keys.
        o2 = Sdp(relay.ok("offer", call_id="both", from_tag="a", to_tag="b",
                          sdp=sdp("127.0.0.1", alice.port, proto="RTP/SAVP", extra=[line_a]), flags=["trust-address"])["sdp"])
        # It offers the suite bob took, with the same key (the other suites
        # of the first offer are not offered again).
        r.check(o2.media[0].attr("crypto") == o.media[0].attr("crypto")[:1],
                "a re-INVITE keeps the relay's key towards bob", str(o2.media[0].attr("crypto")))
        relay.ok("delete", call_id="both")

        # --- odd a=crypto lines
        alice = Endpoint()
        lines = ["a=crypto:1 F8_128_HMAC_SHA1_80 inline:" + "A" * 40, crypto_line(2)[0]]
        rep = relay.ng("offer", call_id="odd1", from_tag="a", transport_protocol="RTP/AVP",
                       sdp=sdp("127.0.0.1", alice.port, proto="RTP/SAVP", extra=lines))
        r.check(rep.get("result") == "ok", "an unsupported suite first, a supported one second: accepted")
        if rep.get("result") == "ok":
            a = Sdp(relay.ok("answer", call_id="odd1", from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", 5000))["sdp"])
            r.check(a.media[0].attr("crypto")[0].startswith("2 "), "the first usable line (tag 2) is chosen",
                    a.media[0].attr("crypto")[0][:40])
        relay.ng("delete", call_id="odd1")

        cases = [
            ("an MKI on the only key", [crypto_line(1, params="|2^31|1:4")[0]]),
            ("a lifetime on the only key", [crypto_line(1, params="|2^20")[0]]),
            ("an invalid base64 key", ["a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:!!!notbase64!!!"]),
            ("a key that is too short", ["a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QUJD"]),
            ("no a=crypto at all", []),
            ("two keys in one line (several inline:)", [crypto_line(1)[0] + " " + crypto_line(1)[0].split(" ", 2)[2]]),
        ]
        for what, lines in cases:
            rep = relay.ng("offer", call_id="odd", from_tag="a", transport_protocol="RTP/AVP",
                           sdp=sdp("127.0.0.1", alice.port, proto="RTP/SAVP", extra=lines))
            res = rep.get("result")
            if res == "ok" and what == "a lifetime on the only key":
                r.check("lifetime: not enforced" in rep.get("warning", ""),
                        "a key with a lifetime is accepted, and the reply warns it is not enforced",
                        str(rep.get("warning")))
            elif res == "ok":
                r.check(False, f"RTP/SAVP offer with {what}: refused", "accepted")
            else:
                r.check(res == "error", f"RTP/SAVP offer with {what}: refused ({rep.get('error-reason')})")
            relay.ng("delete", call_id="odd")


if __name__ == "__main__":
    main(scenario)
