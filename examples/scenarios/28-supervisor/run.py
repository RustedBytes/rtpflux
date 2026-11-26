#!/usr/bin/env python3
"""A call-centre supervisor: silent monitoring (directional `connect`:
copies of the customer and the agent to the supervisor), whispering to
the agent only (`inject start`/`inject stop`), barging in (copies both
ways), pausing what the supervisor hears (block or silence the copies
only), across codecs, across a restart, and the end of either call."""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import (  # noqa: E402
    Endpoint, NgError, Relay, Sdp, alaw_to_pcm, base_config, main, parse_rtp, pcm_to_ulaw, rms, sdp, tone,
    ulaw_to_pcm,
)

NG = 20328
PORTS = (23400, 23799)
CALL, SUP = "cust-1@cc", "sup-1@cc"
TONE = tone(1000, amp=8000)


class Party:
    def __init__(self, tag, pt=0):
        self.tag, self.pt = tag, pt
        self.ep = Endpoint()
        self.dst = None
        self.ssrc = self.ep.ssrc

    def say(self, n=3, payload=None):
        self.ep.send_rtp(self.dst, pt=self.pt, payload=payload or pcm_to_ulaw(TONE), n=n, interval=0.01)

    def heard(self, timeout=0.3) -> dict:
        """What arrived, by SSRC: [(rtp, src)]."""
        out: dict[int, list] = {}
        for d, src in self.ep.recv_all(timeout):
            p = parse_rtp(d)
            if p:
                out.setdefault(p["ssrc"], []).append((p, src))
        return out


def call(relay, cid, caller, callee):
    o = Sdp(relay.ok("offer", call_id=cid, from_tag=caller.tag, flags=["trust-address"],
                     sdp=sdp("127.0.0.1", caller.ep.port, pts=(caller.pt,)))["sdp"])
    a = Sdp(relay.ok("answer", call_id=cid, from_tag=caller.tag, to_tag=callee.tag, flags=["trust-address"],
                     sdp=sdp("127.0.0.1", callee.ep.port, pts=(callee.pt,)))["sdp"])
    caller.dst, callee.dst = a.dest(), o.dest()


def everyone_speaks(parties):
    """Each speaks in turn; what each heard, by tag then SSRC."""
    for p in parties:
        p.ep.drain()
    for p in parties:
        p.say()
    time.sleep(0.05)
    return {p.tag: p.heard() for p in parties}


def scenario(r):
    relay = Relay(base_config(NG, ports=PORTS, sessions='state_file = "STATE"'), NG, "supervisor")
    state = os.path.join(relay.dir, "state.json")
    with open(relay.config_path) as f:
        text = f.read()
    with open(relay.config_path, "w") as f:
        f.write(text.replace("STATE", state))
    try:
        relay.start()
        run(relay, r)
    finally:
        relay.cleanup()


def run(relay, r):
    # The customer called in (PCMU) and talks to an agent; the supervisor's
    # phone (PCMA) is in a call of its own with the call centre's focus.
    customer, agent = Party("customer", 0), Party("agent", 0)
    sup, focus = Party("supervisor", 8), Party("focus", 8)
    call(relay, CALL, customer, agent)
    call(relay, SUP, sup, focus)
    time.sleep(0.05)
    talk = [customer, agent, sup, focus]
    h = everyone_speaks(talk)
    r.check(set(h["agent"]) == {customer.ssrc} and set(h["customer"]) == {agent.ssrc},
            "before: the customer and the agent hear each other only")
    r.check(set(h["supervisor"]) == {focus.ssrc}, "and the supervisor hears only the focus")

    # --- silent monitoring: both parties copied to the supervisor
    rep = relay.ok("connect", call_id=CALL, from_tags=["customer", "agent"], to_call_id=SUP, to_tag="supervisor",
                   flags=["directional"])
    r.check("warning" not in rep, "monitoring a PCMU call from a PCMA phone needs no warning (converted)",
            rep.get("warning", ""))
    time.sleep(0.05)
    h = everyone_speaks(talk)
    r.check(set(h["supervisor"]) == {customer.ssrc, agent.ssrc, focus.ssrc},
            "monitoring: the supervisor hears the customer and the agent (two streams) and still the focus",
            str(sorted(h["supervisor"])))
    copies = [x for s in (customer.ssrc, agent.ssrc) for x in h["supervisor"].get(s, [])]
    r.check(copies and all(p["pt"] == 8 and src == sup.dst for p, src in copies),
            "the copies come as PCMA, from the relay port the supervisor sends to",
            str(sorted({(p['pt'], src) for p, src in copies})))
    levels = [rms(alaw_to_pcm(p["payload"])) for p, _ in h["supervisor"].get(customer.ssrc, [])]
    want = rms(TONE)
    r.check(levels and all(abs(v - want) < want * 0.15 for v in levels[1:]),
            "the customer's voice reaches the supervisor at its level", f"{levels[:3]} vs {want}")
    r.check(sup.ssrc not in h["customer"] and sup.ssrc not in h["agent"],
            "silent: neither the customer nor the agent hears the supervisor")
    r.check(set(h["agent"]) == {customer.ssrc} and set(h["customer"]) == {agent.ssrc},
            "and their own call is unchanged")

    # --- whisper: the supervisor coaches the agent; the customer hears nothing
    relay.ok("inject start", call_id=CALL, to_tag="agent", source_call_id=SUP, source_tag="supervisor")
    time.sleep(0.05)
    h = everyone_speaks(talk)
    r.check(sup.ssrc in h["agent"], "whisper: the agent hears the supervisor")
    pts = {p["pt"] for p, _ in h["agent"].get(sup.ssrc, [])}
    r.check(pts == {0}, "converted to the agent's PCMU", str(pts))
    r.check(sup.ssrc not in h["customer"], "and the customer does not")
    r.check(customer.ssrc in h["agent"], "the agent still hears the customer")
    r.check({customer.ssrc, agent.ssrc} <= set(h["supervisor"]), "the supervisor still monitors both")

    # --- barge-in: the customer hears the supervisor too
    relay.ok("inject start", call_id=CALL, to_tag="customer", source_call_id=SUP, source_tag="supervisor")
    time.sleep(0.05)
    h = everyone_speaks(talk)
    r.check(sup.ssrc in h["customer"] and sup.ssrc in h["agent"], "barge-in: both now hear the supervisor")
    r.check(set(h["customer"]) == {agent.ssrc, sup.ssrc}, "the customer hears the agent and the supervisor",
            str(sorted(h["customer"])))

    # --- back to whispering, then to listening only
    relay.ok("inject stop", call_id=CALL, to_tag="customer", source_call_id=SUP, source_tag="supervisor")
    time.sleep(0.05)
    h = everyone_speaks(talk)
    r.check(sup.ssrc not in h["customer"] and sup.ssrc in h["agent"],
            "inject stop to the customer: back to whispering to the agent")
    relay.ok("inject stop", call_id=CALL, to_tag="agent", source_call_id=SUP, source_tag="supervisor")
    time.sleep(0.05)
    h = everyone_speaks(talk)
    r.check(sup.ssrc not in h["agent"] and sup.ssrc not in h["customer"], "inject stop to the agent: silent again")
    r.check({customer.ssrc, agent.ssrc} <= set(h["supervisor"]), "monitoring goes on")
    try:
        relay.ok("inject stop", call_id=CALL, to_tag="agent", source_call_id=SUP, source_tag="supervisor")
        r.check(False, "inject stop with no injection is refused")
    except NgError as e:
        r.check(True, "inject stop with no injection is refused", str(e))

    # --- the customer reads out a card number: the supervisor's copy of
    # the customer is paused, the agent still hears everything
    relay.ok("block media", call_id=CALL, from_tag="customer", all="except-offer-answer")
    time.sleep(0.05)
    h = everyone_speaks(talk)
    r.check(customer.ssrc not in h["supervisor"] and agent.ssrc in h["supervisor"],
            "blocking the customer's copies pauses the supervisor's view of the customer only")
    r.check(customer.ssrc in h["agent"], "while the agent still hears the customer")
    relay.ok("unblock media", call_id=CALL, from_tag="customer", all="except-offer-answer")
    relay.ok("silence media", call_id=CALL, from_tag="customer", all="except-offer-answer")
    time.sleep(0.05)
    h = everyone_speaks(talk)
    sil = [rms(alaw_to_pcm(p["payload"])) for p, _ in h["supervisor"].get(customer.ssrc, [])]
    r.check(sil and max(sil) < 50, "silencing the copies: the supervisor gets the stream, as silence", str(sil[:3]))
    heard = [rms(ulaw_to_pcm(p["payload"])) for p, _ in h["agent"].get(customer.ssrc, [])]
    r.check(heard and min(heard) > want * 0.8, "and the agent still hears the customer's voice", str(heard[:3]))
    relay.ok("unsilence media", call_id=CALL, from_tag="customer", all="except-offer-answer")

    # --- restart: monitoring comes back
    time.sleep(1.2)  # the state file is written at most once a second
    relay.stop()
    relay.start()
    time.sleep(0.2)
    h = everyone_speaks(talk)
    r.check({customer.ssrc, agent.ssrc} <= set(h["supervisor"]), "after a restart the supervisor still monitors both")
    r.check(set(h["agent"]) == {customer.ssrc} and set(h["customer"]) == {agent.ssrc},
            "and the call itself is unchanged")

    # --- stop monitoring
    relay.ok("unsubscribe", call_id=SUP, to_tag="supervisor")
    time.sleep(0.05)
    h = everyone_speaks(talk)
    r.check(set(h["supervisor"]) == {focus.ssrc}, "unsubscribe naming the supervisor ends the copies",
            str(sorted(h["supervisor"])))
    r.check(set(h["agent"]) == {customer.ssrc}, "and the call goes on")

    # --- monitor the next call; it ends while monitored
    relay.ok("connect", call_id=CALL, from_tags=["customer", "agent"], to_call_id=SUP, to_tag="supervisor",
             flags=["directional"])
    time.sleep(0.05)
    relay.ok("delete", call_id=CALL)
    time.sleep(0.05)
    h = everyone_speaks([sup, focus])
    r.check(set(h["supervisor"]) == {focus.ssrc}, "when the monitored call ends the supervisor's call goes on")
    r.check(set(h["focus"]) == {sup.ssrc}, "both ways")

    # --- the supervisor's call ends while monitoring another
    c2, a2 = Party("customer2"), Party("agent2")
    call(relay, "cust-2@cc", c2, a2)
    relay.ok("connect", call_id="cust-2@cc", flags=["directional", "all"], to_call_id=SUP, to_tag="supervisor")
    time.sleep(0.05)
    h = everyone_speaks([c2, a2, sup])
    r.check({c2.ssrc, a2.ssrc} <= set(h["supervisor"]), "flags all: every party of the call is monitored")
    relay.ok("delete", call_id=SUP)
    time.sleep(0.05)
    h = everyone_speaks([c2, a2])
    r.check(set(h["agent2"]) == {c2.ssrc} and set(h["customer2"]) == {a2.ssrc},
            "when the supervisor hangs up, the monitored call is unaffected")

    # --- refusals
    for what, cmd, opts in [
        ("inject start without a source", "inject start", dict(call_id="cust-2@cc", to_tag="agent2")),
        ("inject start of a party into itself", "inject start",
         dict(call_id="cust-2@cc", to_tag="agent2", source_tag="agent2")),
        ("inject start from an unknown call", "inject start",
         dict(call_id="cust-2@cc", to_tag="agent2", source_call_id="nope", source_tag="x")),
        ("monitoring several sources without directional", "connect",
         dict(call_id="cust-2@cc", from_tags=["customer2", "agent2"], to_call_id="cust-2@cc", to_tag="agent2")),
    ]:
        try:
            relay.ok(cmd, **opts)
            r.check(False, f"{what} is refused")
        except NgError as e:
            r.check(True, f"{what} is refused", str(e))


if __name__ == "__main__":
    main(scenario)
