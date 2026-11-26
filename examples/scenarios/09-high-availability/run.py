#!/usr/bin/env python3
"""Keeping calls through restarts and watching the relay: a state file
(SIGTERM restart, and a kill -9 crash), SRTP keys and recordings across
a restart, a corrupt state file, media timeouts, Prometheus metrics and
the read-only web UI API. Redis is used when redis-server is installed."""

import base64
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import (  # noqa: E402
    DAEMON, Endpoint, Relay, Sdp, base_config, crypto_line, http_get, main, parse_crypto, rtp, sdp,
)

NG = 20309
METRICS = NG + 100
WEBUI = NG + 101


def make_call(relay, cid, srtp=False):
    alice, bob = Endpoint(), Endpoint()
    extra, proto, alice_tx = [], "RTP/AVP", None
    if srtp:
        line, alice_tx = crypto_line(1)
        extra, proto = [line], "RTP/SAVP"
    o = Sdp(relay.ok("offer", call_id=cid, from_tag="a", sdp=sdp("127.0.0.1", alice.port, proto=proto, extra=extra),
                     flags=["trust-address"], transport_protocol="RTP/AVP")["sdp"])
    a = Sdp(relay.ok("answer", call_id=cid, from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", bob.port),
                     flags=["trust-address"])["sdp"])
    relay_tx = parse_crypto(a.media[0].attr("crypto")[0])[2] if srtp else None
    return dict(alice=alice, bob=bob, o=o, a=a, alice_tx=alice_tx, relay_tx=relay_tx)


def media_ok(c, n=5):
    alice, bob, o, a = c["alice"], c["bob"], c["o"], c["a"]
    alice.drain(), bob.drain()
    for _ in range(n):
        pkt = rtp(0, alice.seq, alice.ts, alice.ssrc, b"\x55" * 160)
        alice.send(c["alice_tx"].protect(pkt) if c["alice_tx"] else pkt, a.dest())
        alice.seq += 1
        alice.ts += 160
    bob.send_rtp(o.dest(), n=n)
    to_bob = bob.recv_all(0.5)
    to_alice = alice.recv_all(0.5)
    if c["relay_tx"]:
        to_alice = [x for x in to_alice if c["relay_tx"].unprotect(x[0])]
    return len(to_bob), len(to_alice)


def scenario(r):
    hash_ = subprocess.run([DAEMON, "--webui-hash"], input="secret\n", capture_output=True, text=True).stdout.strip()
    work = None
    cfg = base_config(
        NG, ports=(29000, 29399), sessions='state_file = "STATE"\ntimeout = 60',
        extra=f'[metrics]\nlisten = ["127.0.0.1:{METRICS}"]\n\n'
              f'[webui]\nlisten = "127.0.0.1:{WEBUI}"\nuser = "admin"\npassword_hash = "{hash_}"\n',
    )
    relay = Relay(cfg, NG, "ha")
    work = relay.dir
    state = os.path.join(work, "state.json")
    with open(relay.config_path, "w") as f:
        f.write(cfg.replace("STATE", state))
    try:
        relay.start()
        plain = make_call(relay, "ha-plain")
        secure = make_call(relay, "ha-srtp", srtp=True)
        r.check(media_ok(plain) == (5, 5) and media_ok(secure) == (5, 5), "two calls (plain, SDES-SRTP) relay media")

        # --- metrics and web UI while calls run
        code, body = http_get(f"http://127.0.0.1:{METRICS}/metrics")
        r.check(code == 200 and "rtpflux_" in body, "Prometheus metrics on /metrics")
        names = sorted({ln.split("{")[0].split()[0] for ln in body.splitlines() if ln and not ln.startswith("#")})
        r.check(len(names) >= 10, f"{len(names)} metric names, e.g. {names[:4]}")
        code, _ = http_get(f"http://127.0.0.1:{WEBUI}/api/v1/calls")
        r.check(code == 401, "web UI without login: 401", str(code))
        code, _ = http_get(f"http://127.0.0.1:{WEBUI}/api/v1/calls", auth=("admin", "wrong"))
        r.check(code == 401, "web UI with a wrong password: 401", str(code))
        code, body = http_get(f"http://127.0.0.1:{WEBUI}/api/v1/calls", auth=("admin", "secret"))
        r.check(code == 200 and "ha-plain" in body and "ha-srtp" in body, "the calls API lists both calls")
        code, body = http_get(f"http://127.0.0.1:{WEBUI}/api/v1/calls/detail?call_id=ha-srtp&from_tag=a",
                              auth=("admin", "secret"))
        key_b64 = secure["a"].media[0].attr("crypto")[0].split("inline:")[1]
        r.check(code == 200 and key_b64 not in body and "inline:" not in body,
                "a call's detail never shows SRTP keys", str(code))
        req = urllib.request.Request(f"http://127.0.0.1:{WEBUI}/api/v1/calls", data=b"{}", method="POST")
        req.add_header("Authorization", "Basic " + base64.b64encode(b"admin:secret").decode())
        try:
            urllib.request.urlopen(req, timeout=3)
            code = 200
        except urllib.error.HTTPError as e:
            code = e.code
        r.check(code == 405, "the API refuses POST with a body: 405 Method Not Allowed", str(code))
        code, body = http_get(f"http://127.0.0.1:{WEBUI}/api/v1/calls?q=%00%ff&sort=-nope&page=-1",
                              auth=("admin", "secret"))
        r.check(code in (200, 400), f"odd query parameters are handled ({code})")

        # --- restart (SIGTERM): same ports, same keys, media goes on
        r.check(os.path.exists(state), "the state file is written")
        relay.stop()
        relay.start()
        r.check(sorted(relay.ok("list")["calls"]) == ["ha-plain", "ha-srtp"], "both calls are back after a restart")
        r.check(media_ok(plain) == (5, 5), "plain call: media flows on the same ports after the restart")
        r.check(media_ok(secure) == (5, 5), "SRTP call: same keys after the restart (no re-INVITE needed)")
        q = relay.ok("query", call_id="ha-plain")
        r.check(q["tags"]["a"]["medias"][0]["streams"][0]["local port"] == plain["a"].media[0].port,
                "the restored call reports the same relay port")

        # --- crash (kill -9): how much is lost?
        relay.ok("delete", call_id="ha-srtp")
        fresh = make_call(relay, "ha-new")
        time.sleep(1.5)
        relay.stop(sig=signal.SIGKILL)
        relay.start()
        calls = sorted(relay.ok("list")["calls"])
        r.check(calls == ["ha-new", "ha-plain"],
                "after kill -9 (1.5 s after the last change): the new call is back, the deleted one is not", str(calls))
        r.check(media_ok(fresh) == (5, 5), "and its media flows")
        lost = []
        for wait in (0.0, 0.3, 0.6):
            make_call(relay, f"crash-{wait}")
            time.sleep(wait)
            relay.stop(sig=signal.SIGKILL)
            relay.start()
            if f"crash-{wait}" not in relay.ok("list")["calls"]:
                lost.append(int(wait * 1000))
        if lost:
            r.finding(f"documented: the state file is written at most once a second, so a kill -9 {lost} ms "
                      "after a call was answered loses that call")

        # --- a corrupt state file
        relay.stop()
        with open(state, "w") as f:
            f.write("{ not json")
        try:
            relay.start()
            calls = relay.ok("list")["calls"]
            r.check(calls == [], "a corrupt state file: the relay starts with no calls", str(calls))
            warn = [ln for ln in relay.log().splitlines()[-30:] if "state" in ln.lower() and ("WARN" in ln or "ERROR" in ln)]
            r.check(bool(warn), "and says why in the log", relay.log()[-300:])
            bad = os.path.join(work, "state.json.bad")
            r.check(os.path.exists(bad) and open(bad).read() == "{ not json",
                    "the corrupt state file is kept aside as state.json.bad")
        except RuntimeError as e:
            r.finding(f"a corrupt state file stops the relay from starting: {str(e).splitlines()[0]}")
            os.remove(state)
            relay.start()

        # --- media timeout: no media for `timeout` seconds ends the call
        relay.stop()
        with open(relay.config_path) as f:
            text = f.read()
        with open(relay.config_path, "w") as f:
            f.write(text.replace("timeout = 60", "timeout = 2\noffer_timeout = 2"))
        relay.start()
        make_call(relay, "idle")
        busy = make_call(relay, "busy")
        unanswered = Endpoint()
        relay.ok("offer", call_id="ring", from_tag="a", sdp=sdp("127.0.0.1", unanswered.port))
        for _ in range(20):  # 4 s of media on "busy" only (one direction)
            busy["alice"].send_rtp(busy["a"].dest())
            time.sleep(0.2)
        calls = relay.ok("list")["calls"]
        r.check("idle" not in calls, "a call without media ends after the timeout")
        r.check("busy" in calls, "a call with media in one direction stays up")
        r.check("ring" not in calls, "an unanswered offer ends after offer_timeout")
        st = relay.ok("statistics")["statistics"]["totalstatistics"]
        r.check(st.get("timeoutsessions", 0) >= 1, "timeouts are counted", str(st.get("timeoutsessions")))
        # hold with a=inactive and no media: silent_timeout (an hour), not timeout
        hold = make_call(relay, "hold")
        relay.ok("offer", call_id="hold", from_tag="a", to_tag="b",
                 sdp=sdp("127.0.0.1", hold["alice"].port, extra=["a=inactive"]), flags=["trust-address"])
        relay.ok("answer", call_id="hold", from_tag="a", to_tag="b",
                 sdp=sdp("127.0.0.1", hold["bob"].port, extra=["a=inactive"]), flags=["trust-address"])
        time.sleep(3.5)
        r.check("hold" in relay.ok("list")["calls"],
                "a call on hold (a=inactive, no media) outlives timeout: silent_timeout applies")

        # --- Redis
        if shutil.which("redis-server"):
            r.skip("Redis: redis-server found, but this scenario only covers the state file so far")
        else:
            r.skip("Redis state: redis-server is not installed")

        errors = [ln for ln in relay.log().splitlines() if "panicked" in ln]
        r.check(not errors, "no panic in the relay's log", "\n".join(errors[:5]))
    finally:
        relay.cleanup()


if __name__ == "__main__":
    main(scenario)
