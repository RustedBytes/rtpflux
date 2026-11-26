#!/usr/bin/env python3
"""How good does audio sound through the relay's transcoders? A G.711
(PCMU) caller sends pure tones; the relay encodes them into codec X for
the callee, which echoes X back; the relay decodes X into PCMU for the
caller. So every codec is encoded and decoded once. Per codec and
frequency: the level change (dB) and the tone-to-everything-else ratio
(SINAD, dB), from Goertzel filters (no alignment needed)."""

import math
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import (  # noqa: E402
    Endpoint, Relay, Sdp, base_config, main, parse_rtp, pcm_to_ulaw, rtp, sdp, tone, ulaw_to_pcm,
)

NG = 20324
PORTS = (32000, 32199)
FREQS = (300, 1000, 3000)
SECONDS = 1.0
# The least each codec must keep (level: within ±dB of the input; SINAD:
# at least dB), set a few dB under what this build measured (2026-11-25:
# PCMA 40-55, G.722 37-42, G.729 25-30, Opus 24-35 dB SINAD; levels
# within 0.7 dB), so that a regression shows. G.711 is exact up to its
# quantisation; the others are lossy.
LIMITS = {
    "PCMA": dict(level=0.5, sinad=37.0),
    "G722": dict(level=1.0, sinad=33.0),
    "G729": dict(level=1.5, sinad=21.0),
    "opus": dict(level=1.5, sinad=20.0),
}
PTS = {"PCMA": 8, "G722": 9, "G729": 18, "opus": 111}


def goertzel_power(x, freq, rate=8000):
    k = 2 * math.cos(2 * math.pi * freq / rate)
    s1 = s2 = 0.0
    for v in x:
        s1, s2 = v + k * s1 - s2, s1
    return (s1 * s1 + s2 * s2 - k * s1 * s2) / len(x) ** 2 * 2  # mean power of the tone


def measure(samples, freq):
    """(level in dBFS-ish, SINAD in dB) of a tone at `freq` in `samples`."""
    total = sum(v * v for v in samples) / len(samples)
    tone_p = goertzel_power(samples, freq)
    rest = max(total - tone_p, 1e-9)
    return 10 * math.log10(max(tone_p, 1e-9)), 10 * math.log10(tone_p / rest)


def scenario(r):
    with Relay(base_config(NG, ports=PORTS), NG, "quality") as relay:
        ref = {}
        for f in FREQS:
            pcm = b"".join(tone(f, 20, amp=8000, phase=i * 160) for i in range(int(SECONDS * 50)))
            dec = ulaw_to_pcm(pcm_to_ulaw(pcm))
            ref[f] = measure(struct.unpack(f"<{len(dec) // 2}h", dec), f)
        rows = []
        for name, pt in PTS.items():
            alice, bob = Endpoint(), Endpoint()
            o = Sdp(relay.ok("offer", call_id=name, from_tag="a", sdp=sdp("127.0.0.1", alice.port, pts=(0,)),
                             flags=["trust-address"], codec={"transcode": [name], "mask": ["PCMU"]})["sdp"])
            a = Sdp(relay.ok("answer", call_id=name, from_tag="a", to_tag="b",
                             sdp=sdp("127.0.0.1", bob.port, pts=(pt,)), flags=["trust-address"])["sdp"])
            bob.sock.settimeout(0.2)
            for f in FREQS:
                alice.drain()
                n = int(SECONDS * 50)
                for i in range(n):
                    frame = pcm_to_ulaw(tone(f, 20, amp=8000, phase=i * 160))
                    alice.send(rtp(0, alice.seq, alice.ts, alice.ssrc, frame), a.dest())
                    alice.seq = (alice.seq + 1) & 0xFFFF
                    alice.ts += 160
                    try:  # the callee echoes what it gets, as its own stream
                        data, _ = bob.sock.recvfrom(4096)
                        p = parse_rtp(data)
                        if p:
                            bob.send(rtp(p["pt"], bob.seq, bob.ts, bob.ssrc, p["payload"]), o.dest())
                            bob.seq = (bob.seq + 1) & 0xFFFF
                            bob.ts += 960 if name == "opus" else 160
                    except socket.timeout:
                        pass
                    time.sleep(0.005)
                got = [parse_rtp(d) for d, _ in alice.recv_all(0.6)]
                pcm = b"".join(ulaw_to_pcm(p["payload"]) for p in got if p and p["pt"] == 0)
                samples = struct.unpack(f"<{len(pcm) // 2}h", pcm)[1600:]  # skip 200 ms of start-up
                if len(samples) < 2000:
                    r.check(False, f"{name} {f} Hz: enough audio came back", f"{len(samples)} samples")
                    continue
                level, sinad = measure(samples, f)
                d_level = level - ref[f][0]
                rows.append((name, f, d_level, sinad))
                lim = LIMITS[name]
                r.check(abs(d_level) <= lim["level"] and sinad >= lim["sinad"],
                        f"{name:4} {f:4} Hz: level {d_level:+5.1f} dB, SINAD {sinad:5.1f} dB "
                        f"(limits ±{lim['level']} dB, >= {lim['sinad']} dB)")
            relay.ok("delete", call_id=name)
        print("\n        codec   freq   level   SINAD   (G.711 reference: SINAD "
              + ", ".join(f"{ref[f][1]:.1f}" for f in FREQS) + " dB)")
        for name, f, dl, s in rows:
            print(f"        {name:6} {f:5}  {dl:+5.1f}   {s:5.1f}")


if __name__ == "__main__":
    main(scenario)
