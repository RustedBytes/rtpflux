#!/usr/bin/env python3
"""An upgrade under traffic: 40 calls stream audio (50 packets/s each,
2000 packets/s in all) while the relay is
stopped (SIGTERM) and started again, as `systemctl restart` does with a
new binary. Measures how long media stops, what is lost, and checks that
every call (plain and SDES-SRTP) comes back on its ports with its keys."""

import os
import select
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import Endpoint, Relay, Sdp, base_config, crypto_line, main, parse_rtp, rtp, sdp  # noqa: E402

NG = 20320
PORTS = (31400, 31599)
CALLS = 40
SRTP_CALLS = 5
RUN_S = 8.0
RESTART_AT = 3.0


def scenario(r):
    relay = Relay(base_config(NG, ports=PORTS, sessions='state_file = "STATE"', runtime="workers = 2"), NG, "upgrade")
    state = os.path.join(relay.dir, "state.json")
    with open(relay.config_path) as f:
        text = f.read()
    with open(relay.config_path, "w") as f:
        f.write(text.replace("STATE", state))
    try:
        relay.start()
        calls = []
        for i in range(CALLS):
            alice, bob = Endpoint(), Endpoint()
            extra, proto, tx = [], "RTP/AVP", None
            if i < SRTP_CALLS:
                line, tx = crypto_line(1)
                extra, proto = [line], "RTP/SAVP"
            relay.ok("offer", call_id=f"u{i}", from_tag="a", flags=["trust-address"], transport_protocol="RTP/AVP",
                     sdp=sdp("127.0.0.1", alice.port, proto=proto, extra=extra))
            a = Sdp(relay.ok("answer", call_id=f"u{i}", from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", bob.port),
                             flags=["trust-address"])["sdp"])
            calls.append(dict(alice=alice, bob=bob, dst=a.dest(), tx=tx, sent=0, got=[]))
        time.sleep(1.2)  # the state file is written within a second

        stop = [False]
        socks = {c["bob"].sock.fileno(): c for c in calls}

        def receive():
            while not stop[0]:
                ready, _, _ = select.select([c["bob"].sock for c in calls], [], [], 0.05)
                now = time.time()
                for s in ready:
                    c = socks[s.fileno()]
                    try:
                        while True:
                            s.setblocking(False)
                            data = s.recv(4096)
                            p = parse_rtp(data)
                            if p:
                                c["got"].append((now, p["seq"]))
                    except (BlockingIOError, ConnectionRefusedError):
                        pass

        rx = threading.Thread(target=receive, daemon=True)
        rx.start()
        t0 = time.time()
        restart = {}

        def restarter():
            time.sleep(RESTART_AT)
            s0 = time.time()
            relay.stop()
            s1 = time.time()
            relay.start()
            restart.update(stop_ms=(s1 - s0) * 1000, start_ms=(time.time() - s1) * 1000, at=s0, back=time.time())

        threading.Thread(target=restarter, daemon=True).start()
        tick = 0
        while time.time() - t0 < RUN_S:
            for c in calls:
                al = c["alice"]
                pkt = rtp(0, al.seq, al.ts, al.ssrc, b"\xd5" * 160)
                if c["tx"]:
                    pkt = c["tx"].protect(pkt)
                try:
                    al.send(pkt, c["dst"])
                except OSError:
                    pass
                al.seq = (al.seq + 1) & 0xFFFF
                al.ts += 160
                c["sent"] += 1
            tick += 1
            time.sleep(max(0.0, t0 + tick * 0.02 - time.time()))
        time.sleep(0.4)
        stop[0] = True
        rx.join()

        r.check("back" in restart, "the relay was restarted mid-stream",
                str(restart))
        if "back" not in restart:
            return
        r.check(True, f"SIGTERM to exit: {restart['stop_ms']:.0f} ms; start to answering ng: {restart['start_ms']:.0f} ms")
        restored = sorted(relay.ok("list")["calls"])
        r.check(len(restored) == CALLS, f"all {CALLS} calls are back after the restart ({len(restored)})")
        sent = sum(c["sent"] for c in calls)
        got = sum(len(c["got"]) for c in calls)
        loss = 100.0 * (sent - got) / sent
        gaps = []
        resumed = 0
        for c in calls:
            times = [t for t, _ in c["got"]]
            if any(t > restart["back"] for t in times):
                resumed += 1
            gaps.append(max((b - a for a, b in zip(times, times[1:])), default=RUN_S) * 1000)
        r.check(resumed == CALLS, f"media resumes on every call ({resumed}/{CALLS}), SRTP ones included")
        worst = max(gaps)
        outage = (restart["back"] - restart["at"]) * 1000
        r.check(worst < outage + 300, f"the longest silence per call is {worst:.0f} ms (the restart took {outage:.0f} ms)")
        r.check(loss < 100.0 * (outage + 300) / (RUN_S * 1000),
                f"{sent} packets sent, {got} received: {loss:.1f}% lost, all within the restart")
        dup = sum(len(c["got"]) - len({s for _, s in c["got"]}) for c in calls)
        r.check(dup == 0, f"no packet delivered twice ({dup})")
    finally:
        relay.cleanup()


if __name__ == "__main__":
    main(scenario)
