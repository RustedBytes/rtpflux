#!/usr/bin/env python3
"""ICE over a call's lifetime (RFC 8445, RFC 7675): a SIP phone that does
ICE (played here by a small Python agent) nominates a pair, the relay
checks consent every few seconds, the phone restarts ICE mid-call (new
ufrag and password), and at last goes silent: after 30 s without
consent the relay stops sending to it."""

import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import (  # noqa: E402
    Endpoint, Relay, Sdp, base_config, binding_request, binding_success, http_get, main, sdp, stun_parse,
)

NG = 20318
METRICS = NG + 100
PORTS = (31000, 31199)
QUICK = "--quick" in sys.argv


class Agent:
    """The phone's ICE agent (controlling: it offers): answers the relay's
    checks with its current password, nominates, counts media."""

    def __init__(self):
        self.ep = Endpoint()
        self.ufrag, self.pwd = "aaaa", "aaaaaaaaaaaaaaaaaaaaaa"
        self.answering = True
        self.checks = []      # (time, username) of the relay's checks
        self.rtp = 0
        self.stop = False
        self.ep.sock.settimeout(0.1)
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while not self.stop:
            try:
                data, src = self.ep.sock.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            msg = stun_parse(data)
            if msg and msg["type"] == 0x0001:
                user = msg["attrs"].get(0x0006, b"").decode()
                self.checks.append((time.time(), user))
                if self.answering and user.startswith(self.ufrag + ":"):
                    self.ep.send(binding_success(msg["txid"], src, self.pwd), src)
            elif data and 128 <= data[0] <= 191:
                self.rtp += 1

    def offer_sdp(self):
        p = self.ep.port
        return sdp("127.0.0.1", p, extra=[f"a=ice-ufrag:{self.ufrag}", f"a=ice-pwd:{self.pwd}",
                                          f"a=candidate:1 1 UDP 2122260223 127.0.0.1 {p} typ host", "a=rtcp-mux"])

    def nominate(self, relay_sdp: Sdp):
        ru, rp = relay_sdp.media[0].attr("ice-ufrag")[0], relay_sdp.media[0].attr("ice-pwd")[0]
        req, _ = binding_request(f"{ru}:{self.ufrag}", rp, controlling=True, use_candidate=True)
        self.ep.send(req, relay_sdp.dest())


def metric(name):
    _, body = http_get(f"http://127.0.0.1:{METRICS}/metrics")
    for ln in body.splitlines():
        if ln.startswith(name + " ") or ln.startswith(name + "{"):
            return float(ln.split()[-1])
    return 0.0


def media_to_agent(phone, o, agent, n=10):
    before = agent.rtp
    phone.send_rtp(o.dest(), n=n, interval=0.01)
    time.sleep(0.3)
    return agent.rtp - before


def scenario(r):
    cfg = base_config(NG, ports=PORTS, extra=f'[metrics]\nlisten = ["127.0.0.1:{METRICS}"]\n')
    with Relay(cfg, NG, "ice") as relay:
        agent, phone = Agent(), Endpoint()
        agent.answering = False  # not yet: no check of the relay's succeeds
        o = Sdp(relay.ok("offer", call_id="ice", from_tag="a", sdp=agent.offer_sdp(), flags=["trust-address"])["sdp"])
        a = Sdp(relay.ok("answer", call_id="ice", from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", phone.port),
                         flags=["trust-address"])["sdp"])
        relay_ufrag = a.media[0].attr("ice-ufrag")[0]
        r.check(media_to_agent(phone, o, agent) == 0, "before any check succeeds, no media goes to the ICE phone")
        r.check(any(u == f"{agent.ufrag}:{relay_ufrag}" for _, u in agent.checks),
                "the relay (a full agent) checks the phone's candidate with the right credentials")
        # The phone answers: the relay's own check succeeds, and media goes
        # to the best pair that works, before any nomination.
        agent.answering = True
        time.sleep(1.0)
        r.check(media_to_agent(phone, o, agent) == 10, "once a check succeeds, media flows (before a nomination)")
        agent.nominate(a)
        time.sleep(0.3)
        r.check(media_to_agent(phone, o, agent) == 10, "after the phone nominates the pair, media flows to it")

        # --- consent freshness: a check on the pair every 4-6 s
        t0 = len(agent.checks)
        time.sleep(11)
        consent = [t for t, _ in agent.checks[t0:]]
        r.check(2 <= len(consent) <= 4, f"consent checks every 4-6 s ({len(consent)} in 11 s)")
        r.check(media_to_agent(phone, o, agent) == 10, "media goes on while consent is answered")

        # --- ICE restart: new ufrag and password from the phone
        agent.ufrag, agent.pwd = "bbbb", "bbbbbbbbbbbbbbbbbbbbbb"
        ans = Sdp(relay.ok("offer", call_id="ice", from_tag="a", to_tag="b", sdp=agent.offer_sdp(),
                           flags=["trust-address"])["sdp"])
        a_new = Sdp(relay.ok("answer", call_id="ice", from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", phone.port),
                             flags=["trust-address"])["sdp"])
        new_ufrag = a_new.media[0].attr("ice-ufrag")[0]
        r.check(new_ufrag != relay_ufrag, "an ICE restart gets new relay credentials too (RFC 8839 §4.4.1.1.1)")
        r.check(a_new.dest() == a.dest(), "on the same relay port")
        # The phone now answers only the new generation; the relay keeps
        # sending on the old pair until a new one works.
        r.check(media_to_agent(phone, ans, agent) == 10, "during the restart, media keeps going to the old pair")
        agent.nominate(a_new)
        time.sleep(0.5)
        r.check(media_to_agent(phone, ans, agent) == 10, "after the new nomination, media flows on the new pair")
        r.check(any(u == f"bbbb:{new_ufrag}" for _, u in agent.checks), "the relay checks with the new credentials")

        # --- consent lost: the phone stops answering
        if QUICK:
            r.skip("consent loss (30 s): without --quick")
            return
        lost_before = metric("rtpflux_ice_consent_lost_total")
        agent.answering = False
        time.sleep(15)
        r.check(media_to_agent(phone, ans, agent) == 10, "15 s without consent answers: media still flows (30 s limit)")
        time.sleep(18)
        r.check(media_to_agent(phone, ans, agent) == 0, "after 30 s without consent, the relay stops sending (RFC 7675)")
        lost = metric("rtpflux_ice_consent_lost_total") - lost_before
        r.check(lost >= 1, f"rtpflux_ice_consent_lost_total counts it ({lost:.0f})")
        # the call itself stays (the phone may restart ICE)
        r.check(relay.ok("query", call_id="ice")["result"] == "ok", "the call stays, for an ICE restart to revive it")
        agent.answering = True
        agent.ufrag, agent.pwd = "cccc", "cccccccccccccccccccccc"
        relay.ok("offer", call_id="ice", from_tag="a", to_tag="b", sdp=agent.offer_sdp(), flags=["trust-address"])
        a3 = Sdp(relay.ok("answer", call_id="ice", from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", phone.port),
                          flags=["trust-address"])["sdp"])
        agent.nominate(a3)
        time.sleep(0.5)
        r.check(media_to_agent(phone, ans, agent) == 10, "an ICE restart after consent loss brings media back")
        agent.stop = True


if __name__ == "__main__":
    main(scenario)
