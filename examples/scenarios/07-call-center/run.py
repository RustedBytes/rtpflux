#!/usr/bin/env python3
"""Call-centre features: recording (stereo WAV, checked per channel),
announcements, DTMF detection and injection, blocking and silencing a
party (the PIN-prompt case), and hostile Call-IDs in recording file
names."""

import glob
import json
import math
import os
import struct
import sys
import time
import wave

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import (  # noqa: E402
    Endpoint, Relay, Sdp, base_config, main, parse_rtp, pcm_to_ulaw, rtp, sdp, tone, ulaw_to_pcm, write_wav,
)

NG = 20307


def goertzel(samples, freq, rate=8000):
    n = len(samples)
    if not n:
        return 0.0
    k = 2 * math.cos(2 * math.pi * freq / rate)
    s1 = s2 = 0.0
    for x in samples:
        s1, s2 = x + k * s1 - s2, s1
    return math.sqrt(max(s1 * s1 + s2 * s2 - k * s1 * s2, 0.0)) / n


def pcm_samples(pcm):
    return struct.unpack(f"<{len(pcm) // 2}h", pcm)


def call(relay, cid, a_pts=(0, 101), b_pts=(0, 101), **opts):
    alice, bob = Endpoint(), Endpoint()
    o = Sdp(relay.ok("offer", call_id=cid, from_tag="alice", sdp=sdp("127.0.0.1", alice.port, pts=a_pts),
                     flags=["trust-address"], **opts)["sdp"])
    a = Sdp(relay.ok("answer", call_id=cid, from_tag="alice", to_tag="bob", sdp=sdp("127.0.0.1", bob.port, pts=b_pts),
                     flags=["trust-address"])["sdp"])
    return alice, bob, o, a


def talk(alice, a_dst, bob, b_dst, secs=1.0, fa=440, fb=880):
    n = int(secs * 50)
    for i in range(n):
        alice.send_rtp(a_dst, payload=pcm_to_ulaw(tone(fa, 20, phase=i * 160)))
        bob.send_rtp(b_dst, payload=pcm_to_ulaw(tone(fb, 20, phase=i * 160)))
        time.sleep(0.02)


def send_event(ep, dst, event, packets=8, end_repeats=3, volume=10):
    ts = ep.ts
    for i in range(packets):
        ep.send(rtp(101, ep.seq, ts, ep.ssrc, struct.pack("!BBH", event, volume, 160 * (i + 1)), marker=(i == 0)), dst)
        ep.seq += 1
        time.sleep(0.02)
    for _ in range(end_repeats):  # the end packet, sent three times (RFC 4733)
        ep.send(rtp(101, ep.seq, ts, ep.ssrc, struct.pack("!BBH", event, 0x80 | volume, 160 * packets)), dst)
        ep.seq += 1
    ep.ts = ts + 160 * packets


def wait_for(pattern, secs=8.0):
    deadline = time.time() + secs
    while time.time() < deadline:
        found = [f for f in glob.glob(pattern) if not f.endswith(".part")]
        if found:
            return found
        time.sleep(0.1)
    return []


def scenario(r):
    with Relay(base_config(NG, ports=(27000, 27399)), NG, "callcenter") as relay:
        rec = os.path.join(relay.dir, "rec")
        relay.stop()
        with open(relay.config_path, "a") as f:
            f.write(f'\n[recording]\ndir = "{rec}"\nformat = "wav"\nchannels = "stereo"\n')
        relay.start()

        # ---------------------------------------------------------- recording
        alice, bob, o, a = call(relay, "rec-1@cc", )
        relay.ok("start recording", call_id="rec-1@cc")
        talk(alice, a.dest(), bob, o.dest(), secs=1.0)
        relay.ok("stop recording", call_id="rec-1@cc")
        wavs = wait_for(os.path.join(rec, "rec-1@cc-*.wav"))
        r.check(len(wavs) == 1, "stop recording produces one WAV", str(os.listdir(rec) if os.path.isdir(rec) else "no dir"))
        if wavs:
            with wave.open(wavs[0]) as w:
                ch, rate, frames = w.getnchannels(), w.getframerate(), w.readframes(w.getnframes())
            r.check(ch == 2 and rate == 8000, "stereo, 8 kHz", f"{ch} ch, {rate} Hz")
            s = pcm_samples(frames)
            left, right = s[0::2], s[1::2]
            secs = len(left) / rate
            r.check(0.8 <= secs <= 1.4, f"about a second of audio ({secs:.2f} s)")
            r.check(goertzel(left, 440) > 5 * goertzel(left, 880), "left channel is the caller (440 Hz)")
            r.check(goertzel(right, 880) > 5 * goertzel(right, 440), "right channel is the callee (880 Hz)")
            meta = json.load(open(wavs[0][:-4] + ".json"))
            r.check(meta.get("caller", {}).get("packets") == 50 and meta.get("callee", {}).get("packets") == 50,
                    "the JSON counts 50 packets per party", str({k: meta.get(k) for k in ("caller", "callee")}))
            r.check(not glob.glob(os.path.join(rec, "rec-1@cc-*.pcap")), "the pcap is removed after conversion")
        # started again: a new file, the first one untouched
        relay.ok("start recording", call_id="rec-1@cc")
        talk(alice, a.dest(), bob, o.dest(), secs=0.3)
        relay.ok("delete", call_id="rec-1@cc")
        r.check(bool(wait_for(os.path.join(rec, "rec-1@cc-*-2.wav"))), "a second recording goes to a -2 file")

        # bad options
        alice, bob, o, a = call(relay, "rec-2")
        for opts, what in [({"sample-rate": 44100}, "sample-rate 44100"), ({"format": "aiff"}, "format aiff"),
                           ({"format": "opus", "bitrate": 5}, "opus bitrate 5"), ({"channels": "quad"}, "channels quad")]:
            rep = relay.ng("start recording", call_id="rec-2", **opts)
            r.check(rep.get("result") == "error", f"start recording refuses {what}", str(rep)[:120])
        rep = relay.ng("start recording", call_id="no-such-call")
        r.check(rep.get("result") == "error", "start recording on an unknown call is an error")
        relay.ok("delete", call_id="rec-2")

        # record-call in the offer
        alice, bob, o, a = call(relay, "rec-3", record_call="yes")
        talk(alice, a.dest(), bob, o.dest(), secs=0.3)
        relay.ok("delete", call_id="rec-3")
        r.check(bool(wait_for(os.path.join(rec, "rec-3-*.wav"))), "record-call: yes in the offer records the call")

        # hostile Call-IDs: file names must stay inside the directory
        for cid in ["../../escape", "/etc/passwd", "a" * 400, "x\x00y", "con:nul|*?<>"]:
            rep = relay.ng("offer", call_id=cid, from_tag="t/../..", sdp=sdp("127.0.0.1", 5000),
                           flags=["trust-address"], record_call="yes")
            if rep.get("result") != "ok":
                r.check(True, f"hostile call-id {cid[:20]!r}: refused ({rep.get('error-reason')})")
                continue
            relay.ng("answer", call_id=cid, from_tag="t/../..", to_tag="b", sdp=sdp("127.0.0.1", 5002),
                     flags=["trust-address"])
            relay.ng("delete", call_id=cid)
        time.sleep(1.0)
        outside = [p for p in glob.glob(os.path.join(relay.dir, "**"), recursive=True)
                   if os.path.isfile(p) and not p.startswith(rec + os.sep) and not p.endswith((".toml", ".log"))]
        r.check(not outside, "hostile call-ids and tags never write outside the recording dir", str(outside))
        long_names = [f for f in os.listdir(rec) if len(f) > 255]
        r.check(not long_names, "a 400-character call-id gives a valid file name")

        # ---------------------------------------------------------- announcements
        ann = os.path.join(relay.dir, "hold.wav")
        write_wav(ann, b"".join(tone(1000, 20, amp=6000, phase=i * 160) for i in range(50)))  # 1 s
        alice, bob, o, a = call(relay, "ann")
        rep = relay.ok("play media", call_id="ann", from_tag="bob", file=ann)
        r.check(rep.get("duration") == 1000, "play media reports the duration (1000 ms)", str(rep))
        # alice keeps talking; bob should hear the announcement, not alice
        for i in range(40):
            alice.send_rtp(a.dest(), payload=pcm_to_ulaw(tone(440, 20, phase=i * 160)))
            time.sleep(0.02)
        got = [parse_rtp(d) for d, _ in bob.recv_all(0.4)]
        ssrcs = {p["ssrc"] for p in got}
        r.check(alice.ssrc not in ssrcs, "while it plays, alice's audio to bob is held back")
        pcm = b"".join(ulaw_to_pcm(p["payload"]) for p in got if p["pt"] == 0)
        r.check(len(got) >= 35 and goertzel(pcm_samples(pcm), 1000) > 5 * goertzel(pcm_samples(pcm), 440),
                f"bob hears the 1 kHz announcement ({len(got)} packets)")
        time.sleep(0.5)
        alice.send_rtp(a.dest(), n=3)
        got = [parse_rtp(d) for d, _ in bob.recv_all(0.4)]
        r.check(any(p["ssrc"] == alice.ssrc for p in got), "after it ends, alice is heard again")
        for what, opts in [("a missing file", {"file": "/nonexistent.wav"}), ("a directory", {"file": "/tmp"}),
                           ("a device", {"file": "/dev/zero"}), ("not audio", {"file": relay.config_path}),
                           ("no file or blob", {}), ("a garbage blob", {"blob": b"RIFFnope"})]:
            rep = relay.ng("play media", call_id="ann", from_tag="bob", **opts)
            r.check(rep.get("result") == "error", f"play media refuses {what}", str(rep)[:120])
        blob = open(ann, "rb").read()
        rep = relay.ng("play media", call_id="ann", from_tag="bob", blob=blob, repeat_times=2)
        r.check(rep.get("result") == "ok", "play media from a blob, twice", str(rep)[:120])
        relay.ok("stop media", call_id="ann")
        bob.drain()
        time.sleep(0.2)
        alice.send_rtp(a.dest(), n=3)
        got = [parse_rtp(d) for d, _ in bob.recv_all(0.4)]
        r.check(any(p["ssrc"] == alice.ssrc for p in got), "stop media hands the line back to alice")
        relay.ok("delete", call_id="ann")
        # opus-only listener
        alice, bob, o, a = call(relay, "ann-opus", a_pts=(111,), b_pts=(111,))
        rep = relay.ng("play media", call_id="ann-opus", from_tag="bob", file=ann)
        r.check(rep.get("result") == "error", "play media to an Opus-only listener is refused (documented)",
                str(rep)[:120])
        relay.ok("delete", call_id="ann-opus")

        # ---------------------------------------------------------- DTMF
        alice, bob, o, a = call(relay, "dtmf")
        send_event(alice, a.dest(), 5)
        time.sleep(0.2)
        send_event(alice, a.dest(), 11)  # '#'
        time.sleep(0.2)
        q = relay.ok("query", call_id="dtmf")
        ev = [e["event"] for s in q["tags"]["alice"]["medias"][0]["streams"] for e in s.get("DTMF", [])]
        r.check(ev == ["5", "#"], "each key press is detected once despite the repeated end packets", str(ev))
        got = [parse_rtp(d) for d, _ in bob.recv_all(0.3)]
        r.check(sum(1 for p in got if p["pt"] == 101) == 22, "the events are passed on unchanged",
                str(sum(1 for p in got if p["pt"] == 101)))

        # block DTMF (the PIN prompt): audio flows, keys do not, still detected
        relay.ok("block DTMF", call_id="dtmf", from_tag="alice")
        alice.send_rtp(a.dest(), n=3)
        send_event(alice, a.dest(), 1)
        time.sleep(0.2)
        got = [parse_rtp(d) for d, _ in bob.recv_all(0.3)]
        r.check(sum(1 for p in got if p["pt"] == 0) == 3 and not any(p["pt"] == 101 for p in got),
                "block DTMF: audio reaches bob, the key press does not")
        q = relay.ok("query", call_id="dtmf")
        ev = [e["event"] for s in q["tags"]["alice"]["medias"][0]["streams"] for e in s.get("DTMF", [])]
        r.check(ev[-1:] == ["1"], "a blocked key press is still detected", str(ev))
        relay.ok("unblock DTMF", call_id="dtmf", from_tag="alice")

        # block media / unblock
        relay.ok("block media", call_id="dtmf", from_tag="alice")
        alice.send_rtp(a.dest(), n=5)
        bob.send_rtp(o.dest(), n=5)
        r.check(not bob.recv_all(0.3) and len(alice.recv_all(0.3)) == 5,
                "block media mutes alice only; bob is still heard")
        relay.ok("unblock media", call_id="dtmf", from_tag="alice")
        alice.send_rtp(a.dest(), n=5)
        r.check(len(bob.recv_all(0.3)) == 5, "unblock media resumes")

        # silence media: the stream goes on, the audio is silent
        relay.ok("silence media", call_id="dtmf", from_tag="alice")
        seq0 = alice.seq
        alice.send_rtp(a.dest(), n=5, payload=pcm_to_ulaw(tone(1000, 20)))
        got = [parse_rtp(d) for d, _ in bob.recv_all(0.3)]
        r.check(len(got) == 5 and [p["seq"] for p in got] == [(seq0 + i) & 0xFFFF for i in range(5)],
                "silence media keeps the packets and their sequence numbers")
        r.check(all(max(abs(x) for x in pcm_samples(ulaw_to_pcm(p["payload"]))) < 50 for p in got),
                "and replaces the audio with silence")
        relay.ok("unsilence media", call_id="dtmf", from_tag="alice")

        # play DTMF: bob negotiated telephone-event -> RFC 4733 events
        bob.drain()
        rep = relay.ok("play DTMF", call_id="dtmf", from_tag="alice", code="12#", duration=100)
        time.sleep(1.2)
        got = [parse_rtp(d) for d, _ in bob.recv_all(0.3)]
        evs = [p for p in got if p["pt"] == 101]
        keys = []
        for p in evs:
            e, flags, _ = struct.unpack("!BBH", p["payload"][:4])
            if flags & 0x80 and (not keys or keys[-1][1] != p["ts"]):
                keys.append((e, p["ts"]))
        r.check([k for k, _ in keys] == [1, 2, 11], "play DTMF 12# arrives as events 1, 2, #",
                str([k for k, _ in keys]))
        r.check(sum(1 for p in evs if p["marker"]) == 3, "one marker bit per key")
        for code, what in [("X", "an invalid key"), ("", "no keys"), (99, "event 99")]:
            rep = relay.ng("play DTMF", call_id="dtmf", from_tag="alice", code=code)
            r.check(rep.get("result") == "error", f"play DTMF refuses {what}", str(rep)[:100])
        # Out-of-range duration: refused, or clamped to 40-5000 ms?
        bob.drain()
        rep = relay.ng("play DTMF", call_id="dtmf", from_tag="alice", code="1", duration=5)
        if rep.get("result") == "ok":
            evs = [parse_rtp(d) for d, _ in bob.recv_all(0.6)]
            durs = [struct.unpack("!BBH", p["payload"][:4])[2] for p in evs if p and p["pt"] == 101]
            r.check(durs and max(durs) == 320, "play DTMF with duration 5 is clamped to 40 ms (documented, as rtpengine)",
                    str(durs[-1:]))
            time.sleep(0.3)
            for key in ("duration", "pause", "volume"):
                rep = relay.ng("play DTMF", call_id="dtmf", from_tag="alice", code="1", **{key: "loud"})
                r.check(rep.get("result") == "error" and "not a number" in rep.get("error-reason", ""),
                        f"play DTMF refuses {key} that is not a number", str(rep)[:100])
        else:
            r.check(True, "play DTMF refuses a 5 ms key")
        relay.ok("delete", call_id="dtmf")

        # play DTMF without telephone-event: in-band tones
        alice, bob, o, a = call(relay, "dtmf-ib", a_pts=(0,), b_pts=(0,))
        alice.send_rtp(a.dest(), n=3)  # some audio first, so the relay knows the stream
        bob.drain()
        relay.ok("play DTMF", call_id="dtmf-ib", from_tag="alice", code="9", duration=200)
        time.sleep(0.5)
        got = [parse_rtp(d) for d, _ in bob.recv_all(0.3)]
        pcm = pcm_samples(b"".join(ulaw_to_pcm(p["payload"]) for p in got if p["pt"] == 0))
        hi, lo, off = goertzel(pcm, 1477), goertzel(pcm, 852), goertzel(pcm, 697)
        r.check(hi > 5 * off and lo > 5 * off, "without telephone-event, '9' is played as 852 + 1477 Hz tones",
                f"852 {lo:.0f} 1477 {hi:.0f} 697 {off:.0f}")
        relay.ok("delete", call_id="dtmf-ib")

        # commands on unknown calls/tags
        for cmd in ["block media", "silence media", "play DTMF", "stop media", "pause recording"]:
            rep = relay.ng(cmd, call_id="nope", from_tag="x", code="1")
            r.check(rep.get("result") == "error", f"{cmd} on an unknown call is an error")
        alice, bob, o, a = call(relay, "tags")
        rep = relay.ng("block media", call_id="tags", from_tag="mallory")
        r.check(rep.get("result") == "error", "block media with a tag that is not in the call is an error",
                str(rep)[:100])
        relay.ok("delete", call_id="tags")

        errors = [ln for ln in relay.log().splitlines() if " ERROR " in ln or "panicked" in ln]
        r.check(not errors, "no ERROR or panic in the relay's log", "\n".join(errors[:5]))


if __name__ == "__main__":
    main(scenario)
