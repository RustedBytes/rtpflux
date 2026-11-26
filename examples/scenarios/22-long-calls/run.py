#!/usr/bin/env python3
"""Long calls, compressed: what happens only after hours. RTP sequence
numbers wrap every 65 536 packets (22 min at 50 packets/s), SRTP's
rollover counter with them; timestamps wrap at 2^32 (and a sender may
start anywhere, close to it). Checks plain, SRTP and transcoded calls
across wraps, DTMF on a wrapping timestamp, and a 10-minute recording
made from its timestamps."""

import glob
import json
import os
import struct
import sys
import time
import wave

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import (  # noqa: E402
    Endpoint, Relay, Sdp, base_config, crypto_line, main, parse_crypto, parse_rtp, pcm_to_ulaw, rtp, sdp, tone,
)

NG = 20322
PORTS = (31800, 31999)
QUICK = "--quick" in sys.argv


def call(relay, cid, a_pts=(0,), b_pts=(0,), a_extra=(), proto="RTP/AVP", **opts):
    alice, bob = Endpoint(), Endpoint()
    o = Sdp(relay.ok("offer", call_id=cid, from_tag="a", flags=["trust-address"],
                     sdp=sdp("127.0.0.1", alice.port, pts=a_pts, proto=proto, extra=list(a_extra)), **opts)["sdp"])
    a = Sdp(relay.ok("answer", call_id=cid, from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", bob.port, pts=b_pts),
                     flags=["trust-address"])["sdp"])
    return alice, bob, o, a


def burst(ep, dst, n, seq, ts, ssrc, pt=0, payload=b"\xd5" * 160, ts_step=160, tx=None, pace=500):
    """n packets from (seq, ts), `pace` per pause, so socket buffers keep up."""
    for i in range(n):
        p = rtp(pt, (seq + i) & 0xFFFF, (ts + i * ts_step) & 0xFFFFFFFF, ssrc, payload)
        ep.send(tx.protect(p) if tx else p, dst)
        if i % pace == pace - 1:
            time.sleep(0.01)


def scenario(r):
    rec = None
    with Relay(base_config(NG, ports=PORTS), NG, "long") as relay:
        rec = os.path.join(relay.dir, "rec")
        relay.stop()
        with open(relay.config_path, "a") as f:
            f.write(f'\n[recording]\ndir = "{rec}"\nformat = "wav"\nchannels = "mono"\n')
        relay.start()

        # --- plain: sequence and timestamp wrap at once, relayed untouched
        alice, bob, o, a = call(relay, "plain")
        bob.sock.setsockopt(1, 8, 4 << 20)  # SO_RCVBUF: hold a burst
        burst(alice, a.dest(), 400, 65_400, 0xFFFF_FF00, 0x1234)
        got = [parse_rtp(d) for d, _ in bob.recv_all(1.0)]
        seqs = [p["seq"] for p in got]
        r.check(len(got) == 400 and seqs[135] == 65_535 and seqs[136] == 0,
                f"plain: 400 packets across the sequence wrap arrive in order ({len(got)})")
        ts = [p["ts"] for p in got]
        r.check(all(((b - a) & 0xFFFFFFFF) == 160 for a, b in zip(ts, ts[1:])), "and across the timestamp wrap, untouched")
        relay.ok("delete", call_id="plain")

        # --- SRTP: two rollovers of the sequence number (ROC 0 -> 2)
        n = 3_000 if QUICK else 132_000
        line, tx = crypto_line(1)
        alice, bob, o, a = call(relay, "srtp", a_extra=[line], proto="RTP/SAVP", transport_protocol="RTP/AVP")
        bob.sock.setsockopt(1, 8, 8 << 20)
        start = 65_536 - 1_000
        t0 = time.time()
        received = 0
        sent = 0
        chunk = 5_000
        seq = start
        while sent < n:
            k = min(chunk, n - sent)
            burst(alice, a.dest(), k, seq, sent * 160, 0x5555, tx=tx)
            seq += k
            sent += k
            received += len(bob.recv_all(0.3))
        dt = time.time() - t0
        rolls = (start + n) // 65_536
        r.check(received >= n * 0.995,
                f"SRTP: {n} packets across {rolls} rollover(s) of the sequence number decrypt ({received}, {dt:.1f} s)")
        st = relay.ok("statistics")["statistics"]["totalstatistics"]
        r.check(st.get("srtprejected", 0) == 0, f"none rejected for a wrong rollover counter ({st.get('srtprejected')})")
        # and the relay's own SRTP towards the caller rolls over too
        _, _, relay_tx = parse_crypto(a.media[0].attr("crypto")[0])
        alice.sock.setsockopt(1, 8, 4 << 20)
        burst(bob, o.dest(), 2_000, 65_536 - 500, 0, 0x7777)
        dec = [relay_tx.unprotect(d) for d, _ in alice.recv_all(1.0)]
        r.check(len(dec) == 2_000 and all(dec), f"the relay's SRTP towards the caller across its own wrap ({sum(1 for d in dec if d)})")
        relay.ok("delete", call_id="srtp")

        # --- transcoding: output timestamps step evenly across the input's wrap
        for name, pt, step_out in [("PCMA", 8, 160), ("opus", 111, 960)]:
            alice, bob, o, a = call(relay, f"x-{name}", b_pts=(pt,), codec={"transcode": [name], "mask": ["PCMU"]})
            frames = [pcm_to_ulaw(tone(600, 20, phase=i * 160)) for i in range(60)]
            for i, f in enumerate(frames):
                alice.send(rtp(0, (65_510 + i) & 0xFFFF, (0xFFFF_FD00 + i * 160) & 0xFFFFFFFF, 0x99, f), a.dest())
                time.sleep(0.004)
            got = [parse_rtp(d) for d, _ in bob.recv_all(0.8)]
            steps = {(b["ts"] - a_["ts"]) & 0xFFFFFFFF for a_, b in zip(got, got[1:])}
            seqs = [p["seq"] for p in got]
            seq_ok = all(((b - a_) & 0xFFFF) == 1 for a_, b in zip(seqs, seqs[1:]))
            r.check(len(got) >= 55 and steps == {step_out} and seq_ok,
                    f"PCMU -> {name}: timestamps step by {step_out} and sequence numbers by 1 across both wraps",
                    f"{len(got)} packets, steps {sorted(steps)[:5]}")
            relay.ok("delete", call_id=f"x-{name}")

        # --- a key press whose timestamp wraps mid-event
        alice, bob, o, a = call(relay, "dtmf", a_pts=(0, 101), b_pts=(0, 101))
        ts0 = 0xFFFF_FFC0  # the event starts 64 ticks before the wrap
        for i in range(8):
            end = 0x80 if i >= 5 else 0
            alice.send(rtp(101, 100 + i, ts0, 0x42, struct.pack("!BBH", 7, end | 10, 160 * (i + 1)), marker=(i == 0)),
                       a.dest())
            time.sleep(0.02)
        alice.send(rtp(0, 108, (ts0 + 1280) & 0xFFFFFFFF, 0x42, b"\xff" * 160), a.dest())
        time.sleep(0.3)
        q = relay.ok("query", call_id="dtmf")
        ev = [e for s in q["tags"]["a"]["medias"][0]["streams"] for e in s.get("DTMF", [])]
        r.check([e["event"] for e in ev] == ["7"], f"a key press on a wrapping timestamp is detected once: {ev}")
        relay.ok("delete", call_id="dtmf")

        # --- a 10-minute recording from timestamps (sent faster than real time,
        # paced: the recorder places packets by timestamp)
        minutes = 1 if QUICK else 10
        alice, bob, o, a = call(relay, "rec-long")
        relay.ok("start recording", call_id="rec-long")
        n = minutes * 60 * 50
        frame = pcm_to_ulaw(tone(440, 20))
        t0 = time.time()
        for i in range(n):
            alice.send(rtp(0, (60_000 + i) & 0xFFFF, (0xFFF0_0000 + i * 160) & 0xFFFFFFFF, 0x77, frame), a.dest())
            # real time / 30: enough to keep arrival and timestamps apart
            if i % 50 == 49:
                time.sleep(max(0.0, t0 + (i + 1) * 0.02 / 30 - time.time()))
        relay.ok("stop recording", call_id="rec-long")
        deadline = time.time() + 30
        wavs = []
        while time.time() < deadline and not wavs:
            wavs = [f for f in glob.glob(os.path.join(rec, "rec-long-*.wav"))]
            time.sleep(0.2)
        ok = r.check(len(wavs) == 1, f"a {minutes}-minute recording (timestamps and sequence numbers wrap) is converted")
        if ok:
            with wave.open(wavs[0]) as w:
                secs = w.getnframes() / w.getframerate()
            meta = json.load(open(wavs[0][:-4] + ".json"))
            r.check(abs(secs - minutes * 60) < 2, f"its length follows the timestamps: {secs:.1f} s of {minutes * 60}")
            r.check(meta["caller"]["packets"] == n and meta["caller"]["lost"] == 0,
                    f"the JSON counts {n} packets, none lost: {meta['caller']}")


if __name__ == "__main__":
    main(scenario)
