#!/usr/bin/env python3
"""A carrier-sized relay: capacity limits (ports, sessions.max), port
reuse after many calls, the control plane's call rate, and media load
with the repository's load generator (rtpflux-bench: real RTP/SRTP from
many sockets, loss and the relay's CPU). The XDP fast path needs root:
run scripts/xdp-e2e.sh for it."""

import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import ROOT, Endpoint, Relay, Sdp, base_config, main, sdp  # noqa: E402

NG = 20308
BENCH = os.path.join(ROOT, "target", "release", "rtpflux-bench")
QUICK = "--quick" in sys.argv


def cpu_seconds(pid: int) -> float:
    with open(f"/proc/{pid}/stat") as f:
        fields = f.read().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def rss_mb(pid: int) -> float:
    with open(f"/proc/{pid}/status") as f:
        for ln in f:
            if ln.startswith("VmRSS:"):
                return int(ln.split()[1]) / 1024
    return 0.0


def scenario(r):
    # --- capacity: 40 ports = 20 pairs = 10 calls (two pairs per call)
    cfg = base_config(NG, ports=(28000, 28039))
    with Relay(cfg, NG, "capacity") as relay:
        ok = 0
        err = None
        for i in range(12):
            rep = relay.ng("offer", call_id=f"cap{i}", from_tag="a", sdp=sdp("127.0.0.1", 5000 + 2 * i))
            if rep.get("result") == "ok":
                ok += 1
            else:
                err = rep.get("error-reason")
                break
        r.check(ok == 10, f"a 40-port range holds 10 calls ({ok} set up)")
        r.check(err is not None, f"the 11th call is refused: {err!r}")
        relay.ok("delete", call_id="cap3")
        rep = relay.ng("offer", call_id="cap-new", from_tag="a", sdp=sdp("127.0.0.1", 6000))
        r.check(rep.get("result") == "ok", "after a delete, its ports serve a new call", str(rep)[:100])
        # a re-INVITE in a full relay must not need new ports
        rep = relay.ng("offer", call_id="cap0", from_tag="a", sdp=sdp("127.0.0.1", 5000, pts=(0, 8)))
        r.check(rep.get("result") == "ok", "a re-offer of an existing call works when the relay is full", str(rep)[:100])
        # adding a stream needs ports: refused, and the call stays as it was
        two = sdp("127.0.0.1", 0, sections=[dict(port=5000), dict(port=5010, media="video", pts=(96,))])
        rep = relay.ng("offer", call_id="cap1", from_tag="a", sdp=two)
        if rep.get("result") == "ok":
            r.finding(f"adding a video stream to a call in a full relay is accepted: {Sdp(rep['sdp']).media}")
        else:
            r.check(True, f"adding a stream in a full relay is refused: {rep.get('error-reason')}")
            r.check(relay.ng("query", call_id="cap1").get("result") == "ok", "and the call goes on")

    # --- sessions.max below what the ports allow
    cfg = base_config(NG, ports=(28000, 28399)).replace("max = 100", "max = 5")
    with Relay(cfg, NG, "sessions") as relay:
        n = 0
        for i in range(30):
            alice, bob = Endpoint(), Endpoint()
            rep = relay.ng("offer", call_id=f"s{i}", from_tag="a", sdp=sdp("127.0.0.1", alice.port),
                           flags=["trust-address"])
            if rep.get("result") != "ok":
                break
            o = Sdp(rep["sdp"])
            a = Sdp(relay.ok("answer", call_id=f"s{i}", from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", bob.port),
                             flags=["trust-address"])["sdp"])
            alice.send_rtp(a.dest(), n=3)
            bob.send_rtp(o.dest(), n=3)
            if len(bob.recv_all(0.3)) == 3 and len(alice.recv_all(0.3)) == 3:
                n += 1
        r.check(n == 5, f"sessions.max = 5 caps the calls ({n} set up, the ports allow 100)")
        rep = relay.ng("offer", call_id="s-extra", from_tag="a", sdp=sdp("127.0.0.1", 5000))
        r.check("session limit" in rep.get("error-reason", ""), "the next new call is refused: "
                f"{rep.get('error-reason')!r}")
        rep = relay.ng("offer", call_id="s0", from_tag="a", sdp=sdp("127.0.0.1", 5000, pts=(0, 8)))
        r.check(rep.get("result") == "ok", "a re-offer of an existing call still passes at the limit")

    # --- churn: many set-ups and tear-downs, no port leak, control rate
    cfg = base_config(NG, ports=(28000, 28399))
    with Relay(cfg, NG, "churn") as relay:
        n = 300 if QUICK else 2000
        t0 = time.time()
        for i in range(n):
            relay.ok("offer", call_id=f"churn{i}", from_tag="a", sdp=sdp("127.0.0.1", 5000), flags=["trust-address"])
            relay.ok("answer", call_id=f"churn{i}", from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", 5002),
                     flags=["trust-address"])
            relay.ok("delete", call_id=f"churn{i}")
        dt = time.time() - t0
        r.check(True, f"{n} offer/answer/delete cycles in {dt:.2f} s: {n / dt:.0f} calls/s "
                      f"({3 * n / dt:.0f} ng requests/s, one at a time)")
        r.check(relay.ok("list")["calls"] == [], "no call left after the churn")
        ok = sum(relay.ng("offer", call_id=f"full{i}", from_tag="a", sdp=sdp("127.0.0.1", 5000)).get("result") == "ok"
                 for i in range(100))
        r.check(ok == 100, f"after {n} calls, the full capacity (100) is still available ({ok})")
        st = relay.ok("statistics")["statistics"]
        r.check(st["currentstatistics"]["sessionstotal"] >= 100, "statistics see the calls",
                str(st["currentstatistics"]))

    # --- media load with rtpflux-bench
    if not os.path.exists(BENCH):
        r.skip("media load: build it first (cargo build --release -p rtpflux-bench)")
        return
    cfg = base_config(NG, ports=(30000, 60000), runtime="workers = 0")
    with Relay(cfg, NG, "load", ) as relay:
        steps = "100,500" if QUICK else "250,1000,2000"
        for srtp in ("none", "both"):
            out = subprocess.run(
                [BENCH, "--ng", f"127.0.0.1:{NG}", "--pid", str(relay.proc.pid), "--calls", steps,
                 "--warmup", "1", "--duration", "3" if QUICK else "5", "--srtp", srtp, "--name", f"rtpflux-{srtp}"],
                capture_output=True, text=True, timeout=600)
            ok = r.check(out.returncode == 0, f"rtpflux-bench --srtp {srtp} ran", out.stderr[-300:])
            if ok:
                print("\n".join("        " + ln for ln in out.stdout.strip().splitlines()))
                rows = [ln.split() for ln in out.stdout.splitlines() if ln.strip()[:1].isdigit()]
                head = next((ln.split() for ln in out.stdout.splitlines() if "loss" in ln.lower()), None)
                if head and rows:
                    li = [i for i, h in enumerate(head) if "loss" in h.lower()][0]
                    for row in rows:
                        try:
                            loss = float(row[li].rstrip("%"))
                        except (ValueError, IndexError):
                            continue
                        r.check(loss < 1.0, f"srtp {srtp}, {row[0]} calls: loss {loss}% (< 1%)")
        r.check(True, f"relay RSS after the load: {rss_mb(relay.proc.pid):.0f} MB, CPU {cpu_seconds(relay.proc.pid):.1f} s")

    r.skip("XDP fast path: needs root; run ./scripts/xdp-e2e.sh (and bench/fastpath.sh)")


if __name__ == "__main__":
    main(scenario)
