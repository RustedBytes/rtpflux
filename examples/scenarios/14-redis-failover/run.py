#!/usr/bin/env python3
"""Calls in Redis, taken over by another relay: relay A writes its
dialogs to Redis, dies (kill -9), and relay B, configured like A and
pointed at A's key, recreates the calls on the same ports, SRTP keys
included. Also: Redis down while relaying, a wrong password, separate
keys per relay, the newer of state file and Redis. Uses redis-server
when installed, else the stand-in in lib/fakeredis.py."""

import json
import os
import shutil
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from fakeredis import FakeRedis, wait_for  # noqa: E402
from harness import (  # noqa: E402
    Endpoint, Relay, Sdp, base_config, crypto_line, main, parse_crypto, parse_rtp, rtp, sdp,
)

NG = 20314
PORTS = (30200, 30399)
REDIS_PORT = 20414
PASSWORD = "s3cret"


class RealRedis:
    """redis-server on a scratch port, with the same small interface."""

    def __init__(self, port, password):
        self.port, self.password = port, password
        self.proc = None

    def start(self):
        self.proc = subprocess.Popen(["redis-server", "--port", str(self.port), "--requirepass", self.password,
                                      "--save", "", "--appendonly", "no"], stdout=subprocess.DEVNULL)
        time.sleep(0.3)  # redis-server is up well within this
        return self

    def stop(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait()

    def get(self, key, db=0):
        out = subprocess.run(["redis-cli", "-p", str(self.port), "-a", self.password, "-n", str(db),
                              "--no-auth-warning", "GET", key], capture_output=True)
        v = out.stdout.rstrip(b"\n")
        return v or None


def relay_config(key, password=PASSWORD, extra_sessions=""):
    url = f"redis://:{password}@127.0.0.1:{REDIS_PORT}/2"
    return base_config(NG, ports=PORTS,
                       sessions=f'redis = "{url}"\nredis_key = "{key}"\n{extra_sessions}')


def srtp_call(relay, cid):
    alice, bob = Endpoint(), Endpoint()
    line, tx = crypto_line(1)
    o = Sdp(relay.ok("offer", call_id=cid, from_tag="a", sdp=sdp("127.0.0.1", alice.port, proto="RTP/SAVP",
                                                                  extra=[line]),
                     transport_protocol="RTP/AVP", flags=["trust-address"])["sdp"])
    a = Sdp(relay.ok("answer", call_id=cid, from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", bob.port),
                     flags=["trust-address"])["sdp"])
    return dict(alice=alice, bob=bob, tx=tx, rx=parse_crypto(a.media[0].attr("crypto")[0])[2], o=o, a=a)


def saved_calls(redis, key, db=2):
    """The Call-IDs in the snapshot under `key` (saved in hex)."""
    raw = redis.get(key, db)
    try:
        return sorted(bytes.fromhex(x["call_id"]).decode() for x in json.loads(raw or b"{}").get("sessions", []))
    except (ValueError, KeyError):
        return []


def flows(c, n=5):
    alice, bob = c["alice"], c["bob"]
    alice.drain(), bob.drain()
    for _ in range(n):
        alice.send(c["tx"].protect(rtp(0, alice.seq, alice.ts, alice.ssrc, b"\x44" * 160)), c["a"].dest())
        alice.seq += 1
        alice.ts += 160
    bob.send_rtp(c["o"].dest(), n=n)
    to_bob = [parse_rtp(d) for d, _ in bob.recv_all(0.5)]
    to_alice = [c["rx"].unprotect(d) for d, _ in alice.recv_all(0.5)]
    return sum(1 for p in to_bob if p and p["payload"] == b"\x44" * 160), sum(1 for p in to_alice if p)


def scenario(r):
    real = shutil.which("redis-server") and shutil.which("redis-cli")
    redis = (RealRedis if real else FakeRedis)(REDIS_PORT, PASSWORD).start()
    r.check(True, f"Redis: {'redis-server' if real else 'the lib/fakeredis.py stand-in'} on port {REDIS_PORT}")
    a = b = None
    try:
        # --- relay A: calls go to Redis (database 2, its own key)
        a = Relay(relay_config("rtpflux:state:relay-a"), NG, "redis-a").start()
        plain_alice, plain_bob = Endpoint(), Endpoint()
        o = Sdp(a.ok("offer", call_id="plain", from_tag="a", sdp=sdp("127.0.0.1", plain_alice.port),
                     flags=["trust-address"])["sdp"])
        an = Sdp(a.ok("answer", call_id="plain", from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", plain_bob.port),
                      flags=["trust-address"])["sdp"])
        secure = srtp_call(a, "secure")
        r.check(flows(secure) == (5, 5), "relay A relays an SDES-SRTP call")
        # latch the plain caller onto a NATed source, to check that learned
        # addresses travel too
        plain_alice.send_rtp(an.dest(), n=2)
        time.sleep(0.1)
        r.check(wait_for(lambda: saved_calls(redis, "rtpflux:state:relay-a") == ["plain", "secure"], 3),
                "the dialogs reach Redis within a few seconds, under A's key in database 2")
        snap = redis.get("rtpflux:state:relay-a", 2) or b"{}"
        try:
            saved = json.loads(snap)
            r.check(len(saved.get("sessions", [])) == 2, f"the snapshot holds both calls ({len(saved.get('sessions', []))})")
        except ValueError:
            r.check(False, "the snapshot is JSON", snap[:80].decode(errors="replace"))
        r.check(redis.get("rtpflux:state:relay-a", 0) is None, "nothing in database 0 (the URL's /2 is used)")

        # --- A dies without a goodbye; B takes over from A's key
        time.sleep(1.2)
        a.stop(sig=signal.SIGKILL)
        b = Relay(relay_config("rtpflux:state:relay-a"), NG, "redis-b")
        b.start()
        calls = sorted(b.ok("list")["calls"])
        r.check(calls == ["plain", "secure"], "relay B restores A's calls from Redis", str(calls))
        r.check(flows(secure) == (5, 5), "the SRTP call goes on through B with the same ports and keys")
        plain_bob.send_rtp(o.dest(), n=3)
        r.check(len(plain_alice.recv_all(0.4)) == 3, "the plain call goes on, to the address A had learned")
        log = b.log()
        r.check(PASSWORD not in log and "s3cret" not in log, "the Redis password never reaches the log")

        # --- B keeps writing the same key: a delete reaches Redis
        b.ok("delete", call_id="plain")
        r.check(wait_for(lambda: saved_calls(redis, "rtpflux:state:relay-a") == ["secure"], 3),
                "B's delete reaches Redis", str(saved_calls(redis, "rtpflux:state:relay-a")))

        # --- Redis goes down: media goes on, ng commands are not delayed
        redis.stop()
        t0 = time.time()
        for i in range(20):
            b.ok("offer", call_id=f"down{i}", from_tag="a", sdp=sdp("127.0.0.1", 5000))
        dt = time.time() - t0
        r.check(dt < 1.0, f"20 offers while Redis is down take {dt * 1000:.0f} ms (writes never block ng)")
        r.check(flows(secure) == (5, 5), "media goes on while Redis is down")
        time.sleep(1.5)
        warn = [ln for ln in b.log().splitlines() if "redis" in ln.lower() and ("WARN" in ln or "ERROR" in ln)]
        r.check(1 <= len(warn) <= 3, f"the outage is logged once or twice, not per write ({len(warn)} lines)")
        # Redis back: the newest snapshot is written
        if not real:
            redis.start()
        else:
            redis = RealRedis(REDIS_PORT, PASSWORD).start()
        ok = wait_for(lambda: "down19" in saved_calls(redis, "rtpflux:state:relay-a"), 5)
        r.check(ok, "after Redis comes back, B writes the newest snapshot")
        b.stop()  # a clean stop flushes the last snapshot
        b = None

        # --- another relay's key is not ours
        c = Relay(relay_config("rtpflux:state:relay-c"), NG, "redis-c").start()
        r.check(c.ok("list")["calls"] == [], "a relay with its own key restores nothing of A's")
        c.cleanup()

        # --- a wrong password: the relay starts, says why, restores nothing
        d = Relay(relay_config("rtpflux:state:relay-a", password="wrong"), NG, "redis-d").start()
        r.check(d.ok("list")["calls"] == [], "with a wrong password nothing is restored, and the relay runs")
        r.check(any("redis" in ln.lower() and ("auth" in ln.lower() or "pass" in ln.lower() or "WRONGPASS" in ln)
                    for ln in d.log().splitlines()), "and the log says the password was refused")
        r.check("wrong" not in "".join(ln for ln in d.log().splitlines() if "redis://" in ln),
                "the logged URL hides the password")
        d.cleanup()

        # --- both a state file and Redis: the newer wins
        e = Relay(relay_config("rtpflux:state:relay-e", extra_sessions='state_file = "STATE"'), NG, "redis-e")
        state = os.path.join(e.dir, "state.json")
        with open(e.config_path) as f:
            text = f.read()
        with open(e.config_path, "w") as f:
            f.write(text.replace("STATE", state))
        e.start()
        e.ok("offer", call_id="old", from_tag="a", sdp=sdp("127.0.0.1", 5000))
        time.sleep(1.3)
        e.stop()
        old_file = open(state).read()
        e.start()
        e.ok("offer", call_id="new", from_tag="a", sdp=sdp("127.0.0.1", 5002))
        time.sleep(1.3)
        e.stop()
        with open(state, "w") as f:  # the file goes back in time
            f.write(old_file)
        e.start()
        calls = sorted(e.ok("list")["calls"])
        r.check(calls == ["new", "old"], f"with an older file, the newer Redis snapshot is restored: {calls}")
        e.cleanup()
    finally:
        for x in (a, b):
            if x:
                x.cleanup()
        redis.stop()


if __name__ == "__main__":
    main(scenario)
