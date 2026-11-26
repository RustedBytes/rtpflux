#!/usr/bin/env python3
"""Two networks, one relay: a public interface (behind a 1:1 NAT, so it
advertises another address) and a private core. Each side must see only
its own interface's address in the SDP, and media must leave from the
interface that side was given. Also IPv4 <-> IPv6 bridging, and what of
the caller's internal topology still leaks through the SDP."""

import os
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import Endpoint, Relay, Sdp, base_config, main, sdp  # noqa: E402

NG = 20306
PUBLIC_ADV = "198.51.100.1"  # what the outside world is told (1:1 NAT)


def has_ipv6_loopback() -> bool:
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.bind(("::1", 0))
        s.close()
        return True
    except OSError:
        return False


def scenario(r):
    ifaces = [("external", "127.0.0.1", PUBLIC_ADV), ("internal", "127.0.0.2", None)]
    v6 = has_ipv6_loopback()
    if v6:
        ifaces.append(("v6", "::1", None))
    with Relay(base_config(NG, ports=(26000, 26399), interfaces=ifaces), NG, "topo") as relay:
        # Alice is outside, Bob is in the core.
        alice, bob = Endpoint("127.0.0.1"), Endpoint("127.0.0.2")
        offer_sdp = sdp("127.0.0.1", alice.port, origin_addr="127.0.0.1",
                        extra=[f"a=rtcp:{alice.port + 1} IN IP4 127.0.0.1"])
        o = Sdp(relay.ok("offer", call_id="t1", from_tag="a", sdp=offer_sdp, direction=["external", "internal"],
                         flags=["trust-address"], replace=["origin"])["sdp"])
        r.check(o.addr() == "127.0.0.2", "the core side is offered the internal interface's address", o.addr())
        r.check(o.origin == "127.0.0.2", "replace-origin puts the internal address in o= too", str(o.origin))
        rt = o.media[0].attr("rtcp")
        r.check(not rt or "127.0.0.2" in rt[0] or rt[0].split()[0] == str(o.media[0].port + 1),
                "a=rtcp is rewritten to the relay's port/address", str(rt))
        a = Sdp(relay.ok("answer", call_id="t1", from_tag="a", to_tag="b",
                         sdp=sdp("127.0.0.2", bob.port, origin_addr="127.0.0.2"), flags=["trust-address"],
                         replace=["origin"])["sdp"])
        r.check(a.addr() == PUBLIC_ADV, "the outside is answered with the advertised (NAT) address", a.addr())
        r.check(a.origin == PUBLIC_ADV, "o= carries the advertised address too", str(a.origin))
        r.check("127.0.0.2" not in a.text, "nothing of the core's addresses reaches the outside")

        # media: alice reaches the relay on its real address (the NAT would
        # map PUBLIC_ADV to it); bob on the internal one.
        alice.send_rtp(("127.0.0.1", a.media[0].port), n=5)
        got = bob.recv_all(0.4)
        r.check(len(got) == 5 and all(src[0] == "127.0.0.2" for _, src in got),
                "bob receives from the internal interface", str({s for _, s in got}))
        bob.send_rtp(o.dest(), n=5)
        got = alice.recv_all(0.4)
        r.check(len(got) == 5 and all(src[0] == "127.0.0.1" for _, src in got),
                "alice receives from the external interface", str({s for _, s in got}))
        # Sending to the advertised address's port on the wrong interface
        bob.send_rtp(("127.0.0.2", a.media[0].port), n=2)
        r.check(not alice.recv_all(0.3), "the outside port is not open on the internal interface")
        relay.ok("delete", call_id="t1")

        # --- across interfaces, o= is replaced even without replace-origin
        o = Sdp(relay.ok("offer", call_id="t2", from_tag="a", sdp=sdp("127.0.0.1", 5000, origin_addr="10.9.8.7"),
                         direction=["external", "internal"], flags=["trust-address"])["sdp"])
        r.check(o.origin == "127.0.0.2", "a call across interfaces gets o= replaced without replace-origin",
                str(o.origin))
        relay.ok("delete", call_id="t2")

        # --- other things that can leak
        leaky = sdp("127.0.0.1", 5000, origin_addr="127.0.0.1", extra=[
            "a=rtcp:5001 IN IP4 10.9.8.7",
            "a=candidate:1 1 UDP 2122260223 10.9.8.7 5000 typ host",
            "a=x-internal:10.9.8.7",
        ], session_extra=["a=tool:internal-pbx 10.9.8.7"])
        o = Sdp(relay.ok("offer", call_id="t3", from_tag="a", sdp=leaky, direction=["external", "internal"],
                         flags=["trust-address"], replace=["origin"])["sdp"])
        leaks = [ln for ln in o.lines if "10.9.8.7" in ln]
        if leaks:
            r.finding(f"addresses inside other attributes pass through unchanged: {leaks} "
                      "(a=rtcp and a=candidate are handled; free-form attributes are the proxy's job)")
        r.check(not any(ln.startswith("a=rtcp:") and "10.9.8.7" in ln for ln in o.lines),
                "a=rtcp with the caller's address is rewritten")
        r.check(not any(ln.startswith("a=candidate") and "10.9.8.7" in ln for ln in o.lines),
                "the caller's ICE candidates are not passed on")
        relay.ok("delete", call_id="t3")

        # The proxy removes them with sdp-attr (rtpengine's option).
        o = Sdp(relay.ok("offer", call_id="t3b", from_tag="a", sdp=leaky, direction=["external", "internal"],
                         flags=["trust-address"], replace=["origin"],
                         sdp_attr={"global": {"remove": ["tool"]}, "audio": {"remove": ["x-internal"]}})["sdp"])
        leaks = [ln for ln in o.lines if "10.9.8.7" in ln]
        r.check(not leaks, "sdp-attr: the proxy removes the free-form attributes; nothing internal is left",
                str(leaks))
        relay.ok("delete", call_id="t3b")

        # --- direction errors
        rep = relay.ng("offer", call_id="t4", from_tag="a", sdp=sdp("127.0.0.1", 5000), direction=["external", "dmz"])
        r.check(rep.get("result") == "error", "an unknown interface name in direction is refused",
                str(rep)[:120])
        rep = relay.ng("offer", call_id="t5", from_tag="a", sdp=sdp("127.0.0.1", 5000), direction=["internal"])
        callee_addr = Sdp(rep["sdp"]).addr() if rep.get("result") == "ok" else None
        r.check(callee_addr == "127.0.0.2",
                "direction with one name ['internal'] keeps both sides on it (the callee is offered 127.0.0.2)",
                str(callee_addr or rep))
        relay.ng("delete", call_id="t5")
        rep = relay.ng("offer", call_id="t6", from_tag="a", sdp=sdp("127.0.0.1", 5000), direction=[])
        r.check(rep.get("result") in ("ok", "error"), f"empty direction list: {rep.get('result')}")
        relay.ng("delete", call_id="t6")

        # --- IPv4 caller, IPv6 callee
        if v6:
            alice, bob = Endpoint("127.0.0.1"), Endpoint("::1")
            o = Sdp(relay.ok("offer", call_id="t7", from_tag="a", sdp=sdp("127.0.0.1", alice.port),
                             direction=["external", "v6"], flags=["trust-address"])["sdp"])
            r.check(o.addr() == "::1" and "IN IP6" in o.text, "an IPv6 callee is offered c=IN IP6", o.addr())
            a = Sdp(relay.ok("answer", call_id="t7", from_tag="a", to_tag="b", sdp=sdp("::1", bob.port),
                             flags=["trust-address"])["sdp"])
            r.check(a.addr() == PUBLIC_ADV and "IN IP4" in a.text, "the IPv4 caller is answered c=IN IP4")
            alice.send_rtp(("127.0.0.1", a.media[0].port), n=5)
            bob.send_rtp(o.dest(), n=5)
            r.check(len(bob.recv_all(0.4)) == 5 and len(alice.recv_all(0.4)) == 5, "media flows IPv4 <-> IPv6")
            relay.ok("delete", call_id="t7")
            # an IPv6 SDP on an IPv4-only direction
            alice, bob = Endpoint("::1"), Endpoint("127.0.0.2")
            rep = relay.ng("offer", call_id="t8", from_tag="a", sdp=sdp("::1", alice.port),
                           direction=["internal", "internal"], flags=["trust-address"])
            r.check(rep.get("result") == "error" and "IPv6" in rep.get("error-reason", ""),
                    "an IPv6 caller on an IPv4-only interface is refused at offer time", str(rep)[:160])
            relay.ng("delete", call_id="t8")
            # and an IPv4 callee answering on the IPv6 interface
            relay.ok("offer", call_id="t9", from_tag="a", sdp=sdp("127.0.0.1", 5000),
                     direction=["external", "v6"], flags=["trust-address"])
            rep = relay.ng("answer", call_id="t9", from_tag="a", to_tag="b", sdp=sdp("127.0.0.2", 5002),
                           flags=["trust-address"])
            r.check(rep.get("result") == "error" and "IPv4" in rep.get("error-reason", ""),
                    "an IPv4 answer on the IPv6 side is refused", str(rep)[:160])
            relay.ng("delete", call_id="t9")
        else:
            r.skip("IPv6 loopback not available")


if __name__ == "__main__":
    main(scenario)
