#!/usr/bin/env python3
"""Recordings from real-world networks: packets that arrive reordered,
duplicated, late (jitter) or never, a party that stops sending in
silences (DTX), one that starts late, one that changes SSRC mid-call,
an SRTP caller. Each 20 ms packet carries a different loudness, so the
WAV can be checked window by window: every packet in its place, silence
where one was lost."""

import glob
import json
import math
import os
import random
import struct
import sys
import threading
import time
import wave

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import (  # noqa: E402
    Endpoint, Relay, Sdp, base_config, crypto_line, main, pcm_to_ulaw, rtp, sdp, tone,
)

NG = 20325
PORTS = (32200, 32399)
N = 150  # 3 s per party


def level(i):
    """The loudness of packet i: 10 distinct steps, never silent."""
    return 1000 + (i * 7 % 10) * 1200


def frame(i, freq):
    return pcm_to_ulaw(tone(freq, 20, amp=level(i), phase=i * 160))


def rms_windows(samples, start=0):
    out = []
    for k in range(start, len(samples) - 159, 160):
        w = samples[k:k + 160]
        out.append(math.sqrt(sum(v * v for v in w) / 160))
    return out


def record(relay, rec, cid, send_a, send_b, a_extra=(), proto="RTP/AVP", **opts):
    alice, bob = Endpoint(), Endpoint()
    relay.ok("offer", call_id=cid, from_tag="a", sdp=sdp("127.0.0.1", alice.port, proto=proto, extra=list(a_extra)),
             flags=["trust-address"], transport_protocol="RTP/AVP", **opts)
    a = Sdp(relay.ok("answer", call_id=cid, from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", bob.port),
                     flags=["trust-address"])["sdp"])
    relay.ok("start recording", call_id=cid, channels="stereo", format="wav")
    b_dst = (a.addr(), int(relay.ok("query", call_id=cid)["tags"]["b"]["medias"][0]["streams"][0]["local port"]))
    # Both parties talk at once, as in a call.
    tb = threading.Thread(target=send_b, args=(bob, b_dst))
    tb.start()
    send_a(alice, a.dest())
    tb.join()
    time.sleep(0.2)
    relay.ok("stop recording", call_id=cid)
    deadline = time.time() + 10
    while time.time() < deadline:
        wavs = glob.glob(os.path.join(rec, f"{cid}-*.wav"))
        if wavs:
            with wave.open(wavs[0]) as w:
                raw = w.readframes(w.getnframes())
                rate = w.getframerate()
            s = struct.unpack(f"<{len(raw) // 2}h", raw)
            return s[0::2], s[1::2], json.load(open(wavs[0][:-4] + ".json")), rate
        time.sleep(0.1)
    return None


def paced(order, freq, ssrc=0x1111, seq0=1000, ts0=0, ts_of=None, tx=None, dup=(), jitter=0.0):
    """A sender: packets in `order` (their indexes), each paced 20 ms
    from the first, with optional jitter and duplicates."""
    def send(ep, dst):
        t0 = time.time()
        for k, i in enumerate(order):
            ts = ts_of(i) if ts_of else ts0 + i * 160
            p = rtp(0, (seq0 + i) & 0xFFFF, ts & 0xFFFFFFFF, ssrc, frame(i, freq))
            p = tx.protect(p) if tx else p
            ep.send(p, dst)
            if i in dup:
                ep.send(p, dst)
            target = t0 + (k + 1) * 0.02 + random.uniform(0, jitter)
            time.sleep(max(0.0, target - time.time()))
    return send


def check_channel(r, what, samples, expected):
    """`expected`: per 20 ms window, the packet index heard there (None:
    silence). Compares loudness window by window, on the window grid
    that fits best: a party's audio starts where its first packet arrived,
    which need not be a multiple of 160 samples into the file."""
    best = None
    for start in range(160):
        win = rms_windows(samples, start)
        bad = _compare(win, expected)
        if best is None or len(bad) < len(best):
            best = bad
    bad = best
    r.check(not bad, f"{what}: every 20 ms window holds the right packet ({len(expected)} windows)",
            f"{len(bad)} wrong, first {bad[:4]}")


def _compare(win, expected):
    bad = []
    for k, i in enumerate(expected):
        if k >= len(win):
            bad.append((k, "missing"))
            continue
        want = 0 if i is None else level(i) / math.sqrt(2)
        got = win[k]
        if (i is None and got > 30) or (i is not None and abs(got - want) > 0.12 * want):
            bad.append((k, round(got), round(want)))
    return bad


def scenario(r):
    random.seed(7)
    with Relay(base_config(NG, ports=PORTS), NG, "fidelity") as relay:
        rec = os.path.join(relay.dir, "rec")
        relay.stop()
        with open(relay.config_path, "a") as f:
            f.write(f'\n[recording]\ndir = "{rec}"\nformat = "wav"\n')
        relay.start()

        # --- reordered, duplicated, lost and jittered packets
        order = list(range(N))
        for k in range(10, N - 1, 13):          # swap neighbours: reordering
            order[k], order[k + 1] = order[k + 1], order[k]
        lost = set(range(60, 70))                # 200 ms never arrive
        order = [i for i in order if i not in lost]
        res = record(relay, rec, "net", paced(order, 440, dup={20, 21, 90}, jitter=0.015),
                     paced(range(N), 880, ssrc=0x2222))
        ok = r.check(res is not None, "the recording of a lossy, jittery call is converted")
        if ok:
            left, right, meta, rate = res
            r.check(rate == 8000, "8 kHz stereo")
            check_channel(r, "caller (reordered, duplicated, jittered, 10 lost)", left,
                          [None if i in lost else i for i in range(N)])
            check_channel(r, "callee", right, list(range(N)))
            r.check(meta["caller"]["lost"] == 10, f"the JSON counts the 10 lost packets ({meta['caller']['lost']})")
            r.check(meta["caller"]["packets"] == N - 10,
                    f"and the caller's packets once each, duplicates not twice ({meta['caller']['packets']})")

        # --- silence suppression (DTX): a 1 s gap in timestamps, nothing sent
        def dtx(ep, dst):
            # 1.5 s of speech, 1 s of silence suppressed (nothing sent, the
            # timestamp jumps by 8000), then the rest.
            paced(range(75), 880, ssrc=0x2222)(ep, dst)
            time.sleep(1.0)
            paced(range(75, N), 880, ssrc=0x2222, ts_of=lambda i: i * 160 + 8000)(ep, dst)
        res = record(relay, rec, "dtx", paced(range(N + 50), 440), dtx)
        if res:
            left, right, meta, _ = res
            exp = list(range(75)) + [None] * 50 + list(range(75, N))
            check_channel(r, "a party pausing 1 s (DTX): silence in its place, then the rest", right, exp)

        # --- a callee who starts sending 0.6 s late
        def late(ep, dst):
            time.sleep(0.6)
            paced(range(N - 30), 880, ssrc=0x3333)(ep, dst)
        res = record(relay, rec, "late", paced(range(N), 440), late)
        if res:
            left, right, meta, _ = res
            win = rms_windows(right)
            silent = sum(1 for w in win[:40] if w < 30)
            r.check(26 <= silent <= 34, f"a late starter is placed by its first packet's arrival: "
                                        f"{silent * 20} ms of silence first (~600)")

        # --- a new SSRC mid-call (the phone restarted its stream)
        def two_ssrcs(ep, dst):
            paced(range(70), 880, ssrc=0x4444)(ep, dst)
            paced(range(70, N), 880, ssrc=0x5555, seq0=30_000, ts0=999_000 - 70 * 160)(ep, dst)
        res = record(relay, rec, "ssrc", paced(range(N), 440), two_ssrcs)
        if res:
            left, right, meta, _ = res
            r.check(meta["callee"]["streams"] == 2, f"the JSON sees 2 streams for the callee ({meta['callee']})")
            win = rms_windows(right)
            heard = sum(1 for w in win if w > 300)
            r.check(heard >= N - 5, f"both of its streams are in the audio ({heard} of {N} windows)")

        # --- an SRTP caller: recorded after decryption
        line, tx = crypto_line(1)
        res = record(relay, rec, "srtp", paced(range(N), 440, tx=tx), paced(range(N), 880),
                     a_extra=[line], proto="RTP/SAVP")
        if res:
            left, right, meta, _ = res
            check_channel(r, "an SRTP caller, recorded decrypted", left, list(range(N)))

        # --- a ZRTP call (end-to-end encrypted): the pcap is kept, no audio file
        relay.ok("offer", call_id="zrtp", from_tag="a", sdp=sdp("127.0.0.1", 5000), flags=["trust-address"])
        a = Sdp(relay.ok("answer", call_id="zrtp", from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", 5002),
                         flags=["trust-address"])["sdp"])
        relay.ok("start recording", call_id="zrtp", format="wav")
        ep = Endpoint()
        # The phones' ZRTP handshake, then their SRTP (keys the relay never had).
        for i in range(4):
            hello = bytes([0x10, 0]) + struct.pack("!H", i) + b"ZRTP" + struct.pack("!I", 0x6666) + b"\x50\x5a" + b"\x00" * 80
            ep.send(hello, a.dest())
        for i in range(50):
            ep.send(bytes([0x80, 0]) + struct.pack("!HII", i, i * 160, 0x6666) + os.urandom(170), a.dest())
        time.sleep(0.2)
        relay.ok("stop recording", call_id="zrtp")
        time.sleep(1.5)
        files = sorted(os.path.basename(f) for f in glob.glob(os.path.join(rec, "zrtp-*")))
        if any(f.endswith(".pcap") for f in files) and not any(f.endswith(".wav") for f in files):
            r.check(True, f"a ZRTP call keeps its pcap and is not converted ({files})")
        else:
            r.finding(f"a ZRTP call's recording is converted to audio, which is the noise of its ciphertext "
                      f"({files}); the docs say it 'cannot be converted' and the pcap is kept")


if __name__ == "__main__":
    main(scenario)
