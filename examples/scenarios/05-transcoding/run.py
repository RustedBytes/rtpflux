#!/usr/bin/env python3
"""Codec transcoding when the parties share no codec: G.711 u-law <->
A-law (checked sample by sample), G.722, G.729 and Opus (checked by
packet shape), DTMF events <-> in-band tones (checked with a Goertzel
filter), and odd packets (other ptimes, empty payloads, unknown PTs)."""

import math
import os
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import (  # noqa: E402
    Endpoint, Relay, Sdp, alaw_to_pcm, base_config, main, parse_rtp, pcm_to_alaw, pcm_to_ulaw, rms, rtp, sdp,
    tone, ulaw_to_pcm,
)

NG = 20305


def goertzel(pcm: bytes, freq: float, rate: int = 8000) -> float:
    n = len(pcm) // 2
    if n == 0:
        return 0.0
    samples = struct.unpack(f"<{n}h", pcm)
    k = 2 * math.cos(2 * math.pi * freq / rate)
    s1 = s2 = 0.0
    for x in samples:
        s1, s2 = x + k * s1 - s2, s1
    return math.sqrt(max(s1 * s1 + s2 * s2 - k * s1 * s2, 0.0)) / n


def setup(relay, cid, a_pts, b_pts, codec=None, flags=()):
    alice, bob = Endpoint(), Endpoint()
    opts = {"flags": ["trust-address", *flags]}
    if codec:
        opts["codec"] = codec
    o = Sdp(relay.ok("offer", call_id=cid, from_tag="a", sdp=sdp("127.0.0.1", alice.port, pts=a_pts), **opts)["sdp"])
    a = Sdp(relay.ok("answer", call_id=cid, from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", bob.port, pts=b_pts),
                     flags=["trust-address"])["sdp"])
    return alice, bob, o, a


def stream(ep, dst, pt, frames, ts_step=160, interval=0.02):
    for f in frames:
        ep.send_rtp(dst, pt=pt, payload=f, ts_step=ts_step)
        if interval:
            time.sleep(interval)


def scenario(r):
    with Relay(base_config(NG, ports=(25000, 25399), runtime="workers = 2"), NG, "transcode") as relay:
        # --- PCMU caller, PCMA-only callee
        alice, bob, o, a = setup(relay, "ua", (0,), (8,), codec={"transcode": ["PCMA"], "mask": ["PCMU"]})
        r.check(o.media[0].fmts == ["8"], "with mask PCMU + transcode PCMA the callee is offered only PCMA",
                str(o.media[0].fmts))
        r.check(a.media[0].fmts == ["0"], "the caller is answered with its own PCMU", str(a.media[0].fmts))
        pcm = b"".join(tone(1000, 20, phase=i * 160) for i in range(25))
        frames = [pcm_to_ulaw(pcm[i:i + 320]) for i in range(0, len(pcm), 320)]
        stream(alice, a.dest(), 0, frames)
        got = [parse_rtp(d) for d, _ in bob.recv_all(0.6)]
        r.check(len(got) == 25 and all(p["pt"] == 8 and len(p["payload"]) == 160 for p in got),
                "u-law in, A-law out: 25 packets of PT 8, 160 bytes", f"{len(got)} {[p['pt'] for p in got[:3]]}")
        if got:
            out = b"".join(alaw_to_pcm(p["payload"]) for p in got)
            ref = b"".join(ulaw_to_pcm(f) for f in frames)
            # Both are 1 kHz tones of the same level; the law change costs < 1 dB.
            r.check(abs(rms(out) - rms(ref)) / rms(ref) < 0.1, "the tone keeps its level through u-law -> A-law",
                    f"{rms(ref)} vs {rms(out)}")
            r.check(goertzel(out, 1000) > 10 * goertzel(out, 1500), "and stays a 1 kHz tone")
        frames_b = [pcm_to_alaw(tone(440, 20, phase=i * 160)) for i in range(10)]
        stream(bob, o.dest(), 8, frames_b)
        got = [parse_rtp(d) for d, _ in alice.recv_all(0.6)]
        r.check(len(got) == 10 and all(p["pt"] == 0 for p in got), "A-law back to the caller as u-law (PT 0)")
        st = relay.ok("statistics")["statistics"]["currentstatistics"]
        r.check(st.get("transcodedmedia", 0) >= 1, "statistics count the transcoded section", str(st))

        # --- ptime 10 ms and 30 ms into the transcoder
        for ms in (10, 30):
            alice.drain(), bob.drain()
            frames = [pcm_to_ulaw(tone(1000, ms, phase=i * 8 * ms)) for i in range(10)]
            stream(alice, a.dest(), 0, frames, ts_step=8 * ms, interval=ms / 1000)
            got = [parse_rtp(d) for d, _ in bob.recv_all(0.6)]
            total = sum(len(p["payload"]) for p in got)
            r.check(total >= 8 * ms * 10 * 0.8, f"{ms} ms packets are transcoded ({len(got)} packets, {total} bytes "
                    f"of {8 * ms * 10})")
            if got and len({len(p["payload"]) for p in got}) == 1 and len(got[0]["payload"]) != 8 * ms:
                r.finding(f"{ms} ms u-law packets come out as {len(got[0]['payload']) // 8} ms A-law packets "
                          "(the transcoder repacketises to its own ptime)")

        # --- odd packets into the transcoder: the relay must survive
        alice.drain(), bob.drain()
        for payload, pt in [(b"", 0), (b"\xff", 0), (b"\xff" * 1500, 0), (b"\xff" * 160, 99), (b"\xff" * 160, 8)]:
            alice.send(rtp(pt, alice.seq, alice.ts, alice.ssrc, payload), a.dest())
            alice.seq += 1
            alice.ts += 160
        got = [parse_rtp(d) for d, _ in bob.recv_all(0.5)]
        wrong_pt = [p for p in got if p["pt"] not in (8, 101, 13)]
        r.check(not wrong_pt, "a payload type nobody negotiated (PT 99) never reaches the PCMA-only callee",
                str([(p["pt"], len(p["payload"])) for p in wrong_pt]))
        sizes = [len(p["payload"]) for p in got if p["pt"] == 8]
        r.check(0 not in sizes, "an empty u-law payload is dropped, not sent on as an empty A-law packet",
                str(sizes))
        r.check(relay.ng("ping")["result"] == "pong", "the relay survives odd packets in the transcoder")
        relay.ok("delete", call_id="ua")

        # --- transcode offered but not needed: no conversion
        alice, bob, o, a = setup(relay, "noconv", (0,), (0,), codec={"transcode": ["PCMA"]})
        r.check(o.media[0].fmts[:1] == ["0"] and "8" in o.media[0].fmts, "transcode PCMA adds PCMA after PCMU")
        stream(alice, a.dest(), 0, [b"\x12" * 160] * 5, interval=0)
        got = [parse_rtp(d) for d, _ in bob.recv_all(0.4)]
        r.check(len(got) == 5 and all(p["payload"] == b"\x12" * 160 for p in got),
                "callee picked PCMU: packets pass untouched (bit-exact)")
        relay.ok("delete", call_id="noconv")

        # --- G.722, G.729 and Opus, by packet shape
        for name, pt, payload, ts_step, size_check in [
            ("G722", 9, bytes(range(160)), 160, lambda n: n == 160),
            ("G729", 18, bytes(20), 160, lambda n: n in (20, 22, 2)),
            ("opus", 111, b"\xf8\xff\xfe", 960, lambda n: 1 <= n <= 400),
        ]:
            # PCMU caller -> codec-only callee
            alice, bob, o, a = setup(relay, f"t-{name}", (0,), (pt,), codec={"transcode": [name], "mask": ["PCMU"]})
            r.check(str(pt) in o.media[0].fmts, f"{name}: the callee is offered {name}", str(o.media[0].fmts))
            stream(alice, a.dest(), 0, [pcm_to_ulaw(tone(800, 20, phase=i * 160)) for i in range(15)])
            got = [parse_rtp(d) for d, _ in bob.recv_all(0.8)]
            r.check(len(got) >= 10 and all(p["pt"] == pt and size_check(len(p["payload"])) for p in got),
                    f"PCMU -> {name}: {len(got)} packets, PT {pt}", str([(p['pt'], len(p['payload'])) for p in got[:3]]))
            stream(bob, o.dest(), pt, [payload] * 15, ts_step=ts_step)
            got = [parse_rtp(d) for d, _ in alice.recv_all(0.8)]
            r.check(len(got) >= 10 and all(p["pt"] == 0 and len(p["payload"]) == 160 for p in got),
                    f"{name} -> PCMU: {len(got)} packets of 160 bytes", str([(p['pt'], len(p['payload'])) for p in got[:3]]))
            # garbage in the codec's stream must not crash a decoder
            for junk in (b"", b"\xff" * 3, os.urandom(1000)):
                bob.send(rtp(pt, bob.seq, bob.ts, bob.ssrc, junk), o.dest())
                bob.seq += 1
                bob.ts += ts_step
            time.sleep(0.2)
            r.check(relay.ng("ping")["result"] == "pong", f"{name}: garbage frames do not crash the decoder")
            relay.ok("delete", call_id=f"t-{name}")

        # --- unknown codec name in transcode
        rep = relay.ng("offer", call_id="bogus", from_tag="a", sdp=sdp("127.0.0.1", 5000),
                       codec={"transcode": ["FOO"]})
        r.check(rep.get("result") == "ok" and "codec transcode FOO: unknown" in rep.get("warning", ""),
                "an unknown transcode codec is ignored, and the reply's warning says so", str(rep.get("warning")))
        relay.ng("delete", call_id="bogus")

        # --- masking every codec the caller has, with nothing to transcode to
        rep = relay.ng("offer", call_id="empty", from_tag="a", sdp=sdp("127.0.0.1", 5000), codec={"mask": ["PCMU"]})
        r.check(rep.get("result") == "ok" and "codec mask: ignored" in rep.get("warning", ""),
                "a mask without a codec to transcode to is ignored, and the reply's warning says so",
                str(rep.get("warning")))
        relay.ng("delete", call_id="empty")

        # --- DTMF transcoding: the callee sends RFC 4733 events, the caller
        # (no telephone-event) must hear the tones of '1' (697 + 1209 Hz).
        alice, bob, o, a = setup(relay, "dtmf", (0,), (0, 101), codec={"transcode": ["telephone-event"]})
        r.check("101" in o.media[0].fmts and "101" not in a.media[0].fmts,
                "telephone-event offered to the callee, hidden from the caller", f"{o.media[0].fmts} / {a.media[0].fmts}")
        # keep audio flowing from bob, with a key press in the middle
        for _ in range(10):
            bob.send_rtp(o.dest(), pt=0, payload=b"\xff" * 160)
            time.sleep(0.02)
        ts = bob.ts
        for i in range(10):
            dur = 160 * (i + 1)
            end = 0x80 if i >= 7 else 0
            bob.send(rtp(101, bob.seq, ts, bob.ssrc, struct.pack("!BBH", 1, end | 10, dur), marker=(i == 0)), o.dest())
            bob.seq += 1
            time.sleep(0.02)
        bob.ts = ts + 1600
        for _ in range(10):
            bob.send_rtp(o.dest(), pt=0, payload=b"\xff" * 160)
            time.sleep(0.02)
        got = [parse_rtp(d) for d, _ in alice.recv_all(0.6)]
        pcm = b"".join(ulaw_to_pcm(p["payload"]) for p in got if p and p["pt"] == 0)
        low, high, off = goertzel(pcm, 697), goertzel(pcm, 1209), goertzel(pcm, 941)
        r.check(not any(p["pt"] == 101 for p in got), "the caller receives no telephone-event packets")
        r.check(low > 5 * off and high > 5 * off, "the event reaches the caller as the in-band tones of '1'",
                f"697 Hz {low:.0f}, 1209 Hz {high:.0f}, 941 Hz {off:.0f}")
        q = relay.ok("query", call_id="dtmf")
        dtmf = [e for s in q["tags"]["b"]["medias"][0]["streams"] for e in s.get("DTMF", [])]
        r.check([e["event"] for e in dtmf] == ["1"], "the key press is detected once", str(dtmf))
        relay.ok("delete", call_id="dtmf")


if __name__ == "__main__":
    main(scenario)
