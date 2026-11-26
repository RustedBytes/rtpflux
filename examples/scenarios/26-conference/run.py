#!/usr/bin/env python3
"""Conference calls without a mixer: a dial-out room whose participants
are `create`d parties joined with `mesh` (each hears the others as
streams of their own, converted to its codec), callers moved from a lobby
into a room across several calls (`mesh` with `unsubscribe`), and a
three-way call a B2BUA makes inside one call-id (a party in two dialogs,
labels)."""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import (  # noqa: E402
    Endpoint, NgError, Relay, Sdp, alaw_to_pcm, base_config, main, parse_rtp, pcm_to_ulaw, rms, sdp, tone,
    ulaw_to_pcm,
)

NG = 20326
PORTS = (32400, 32599)
ROOM = "room-1@conf"
TONE = tone(1000, amp=8000)
CODECS = {"PCMU": 0, "PCMA": 8, "G722": 9}


class Participant:
    """One conference participant: its socket, the relay's address it
    sends to, and the codec it agreed."""

    def __init__(self, tag: str, codec: str):
        self.tag, self.codec, self.pt = tag, codec, CODECS[codec]
        self.ep = Endpoint()
        self.dst = None

    def speak(self, n: int = 5, interval: float = 0.02):
        payload = pcm_to_ulaw(TONE) if self.pt == 0 else b"\xd5" * 160
        self.ep.send_rtp(self.dst, pt=self.pt, payload=payload, n=n, interval=interval)

    def heard(self, timeout: float = 0.4) -> dict:
        """The packets received, by SSRC: [(rtp, src)]."""
        out: dict[int, list] = {}
        for data, src in self.ep.recv_all(timeout):
            p = parse_rtp(data)
            if p:
                out.setdefault(p["ssrc"], []).append((p, src))
        return out


def dial_out(relay, r, cid, tag, codec, label=None):
    """The focus calls a participant: `create` makes the relay's offer,
    the participant's answer goes back with `create answer`."""
    p = Participant(tag, codec)
    opts = dict(call_id=cid, from_tag=tag, codec={"offer": [codec]})
    if label:
        opts["label"] = label
    offer = Sdp(relay.ok("create", **opts)["sdp"])
    relay.ok("create answer", call_id=cid, from_tag=tag, sdp=sdp("127.0.0.1", p.ep.port, pts=(p.pt,)),
             flags=["trust-address"])
    p.dst = offer.dest()
    return p, offer


def full_mesh(parts):
    return [{"from": a.tag, "to": [b.tag for b in parts if b is not a]} for a in parts]


def round_robin(parts, n=5):
    """Each participant speaks in turn; what everyone heard, by listener."""
    for p in parts:
        p.ep.drain()
    for p in parts:
        p.speak(n)
    time.sleep(0.1)
    return {p.tag: p.heard() for p in parts}


def dial_out_room(relay, r):
    # --- four participants, three codecs
    alice, a_offer = dial_out(relay, r, ROOM, "alice", "PCMU", label="host")
    bob, _ = dial_out(relay, r, ROOM, "bob", "PCMU")
    carol, c_offer = dial_out(relay, r, ROOM, "carol", "PCMA")
    dave, d_offer = dial_out(relay, r, ROOM, "dave", "G722")
    parts = [alice, bob, carol, dave]
    ssrc = {p.tag: p.ep.ssrc for p in parts}
    r.check(a_offer.media[0].fmts == ["0"] and c_offer.media[0].fmts == ["8"] and d_offer.media[0].fmts == ["9"],
            "create offers each participant the codec asked for",
            str([a_offer.media[0].fmts, c_offer.media[0].fmts, d_offer.media[0].fmts]))
    r.check(len({p.dst for p in parts}) == 4, "each participant gets relay ports of its own")
    q = relay.ok("query", call_id=ROOM)
    r.check(sorted(q.get("tags", {})) == ["alice", "bob", "carol", "dave"],
            "query lists the four created parties", str(sorted(q.get("tags", {}))))
    r.check(q["tags"]["alice"].get("label") == "host", "the host's label is reported")

    heard = round_robin(parts)
    r.check(not any(heard.values()), "before mesh nobody hears anyone (a created party's media goes nowhere)",
            str({k: len(v) for k, v in heard.items()}))

    # --- everyone hears everyone
    rep = relay.ok("mesh", calls=[ROOM], tags=full_mesh(parts))
    r.check("warning" not in rep, "mesh between PCMU, PCMA and G.722 needs no warning (all converted)",
            rep.get("warning", ""))
    time.sleep(0.05)
    heard = round_robin(parts)
    for p in parts:
        others = {ssrc[o.tag] for o in parts if o is not p}
        got = heard[p.tag]
        r.check(set(got) == others, f"{p.tag} hears the three others as three streams (their SSRCs)",
                f"got {sorted(got)}, want {sorted(others)}")
        r.check(ssrc[p.tag] not in got, f"{p.tag} does not hear itself")
        pkts = [x for v in got.values() for x in v]
        r.check(pkts and all(x[0]["pt"] == p.pt for x in pkts),
                f"every stream reaches {p.tag} in its own codec ({p.codec}, PT {p.pt})",
                str(sorted({x[0]['pt'] for x in pkts})))
        r.check(pkts and all(x[1] == p.dst for x in pkts),
                f"{p.tag} receives every stream from the one relay port it sends to",
                str(sorted({x[1] for x in pkts}))[:120])
        r.check(all(len(v) >= 4 for v in got.values()), f"{p.tag} gets (almost) every packet of each speaker",
                str({k: len(v) for k, v in got.items()}))

    # The audio survives the conversion: Alice's PCMU tone at Bob (as
    # sent) and at Carol (converted to PCMA) has the same level.
    level_bob = [rms(ulaw_to_pcm(x[0]["payload"])) for x in heard["bob"].get(ssrc["alice"], [])]
    level_carol = [rms(alaw_to_pcm(x[0]["payload"])) for x in heard["carol"].get(ssrc["alice"], [])]
    want = rms(TONE)
    r.check(level_bob and all(abs(v - want) < want * 0.1 for v in level_bob),
            "Bob (PCMU) hears Alice's tone at its level", f"{level_bob[:3]} vs {want}")
    r.check(level_carol and all(abs(v - want) < want * 0.15 for v in level_carol[1:]),
            "Carol (PCMA) hears Alice's tone converted, at its level", f"{level_carol[:3]} vs {want}")
    g722 = heard["dave"].get(ssrc["alice"], [])
    r.check(g722 and all(len(x[0]["payload"]) == 160 for x in g722),
            "Dave (G.722) gets Alice's audio as 20 ms G.722 frames")

    # Each copy is a stream of its own: sequence numbers without gaps.
    seqs = [x[0]["seq"] for x in heard["carol"].get(ssrc["bob"], [])]
    r.check(all((b - a) & 0xFFFF == 1 for a, b in zip(seqs, seqs[1:])),
            "a converted copy keeps consecutive sequence numbers", str(seqs))

    # --- mute: Bob's copies blocked, Bob still hears the room
    relay.ok("block media", call_id=ROOM, from_tag="bob", all="except-offer-answer")
    time.sleep(0.05)
    heard = round_robin(parts)
    r.check(not any(ssrc["bob"] in heard[p.tag] for p in parts),
            "block media (all: except-offer-answer) mutes Bob for everyone")
    r.check(len(heard["bob"]) == 3, "a muted participant still hears the room", str(len(heard["bob"])))
    relay.ok("unblock media", call_id=ROOM, from_tag="bob", all="except-offer-answer")
    time.sleep(0.05)
    heard = round_robin(parts)
    r.check(all(ssrc["bob"] in heard[p.tag] for p in parts if p is not bob), "unblock media unmutes him")

    # --- an announcement to the whole room is refused only for the file
    try:
        relay.ok("play media", call_id=ROOM, flags=["all"], file="/nonexistent.wav")
        r.check(False, "play media to a missing file is refused")
    except NgError as e:
        r.check("party" not in str(e) and "label" not in str(e),
                "play media with all reaches every created party (refused for the file only)", str(e))

    return parts, ssrc


def leave_and_join(relay, r, parts, ssrc):
    alice, bob, carol, dave = parts
    # --- Dave leaves
    relay.ok("delete", call_id=ROOM, from_tag="dave")
    time.sleep(0.05)
    stay = [alice, bob, carol]
    heard = round_robin(parts)
    r.check(not any(ssrc["dave"] in heard[p.tag] for p in stay), "after Dave leaves nobody hears him")
    r.check(not heard["dave"], "and he hears nobody")
    r.check(all(len(heard[p.tag]) == 2 for p in stay), "the three others still hear each other",
            str({p.tag: len(heard[p.tag]) for p in stay}))
    q = relay.ok("query", call_id=ROOM)
    r.check("dave" not in q.get("tags", {}), "query no longer lists him")

    # --- Erin joins late, both ways with everyone, in one request
    erin, _ = dial_out(relay, r, ROOM, "erin", "PCMA", label="late")
    ssrc["erin"] = erin.ep.ssrc
    relay.ok("mesh", calls=[ROOM], tags=[{"from": "erin", "to": [p.tag for p in stay]}], flags=["bidirectional"])
    time.sleep(0.05)
    room = stay + [erin]
    heard = round_robin(room)
    r.check(set(heard["erin"]) == {ssrc[p.tag] for p in stay}, "a late joiner hears everyone (bidirectional)",
            str(sorted(heard["erin"])))
    r.check(all(ssrc["erin"] in heard[p.tag] for p in stay), "and everyone hears her")
    r.check(all(len(heard[p.tag]) == 3 for p in room), "four participants, three streams each",
            str({p.tag: len(heard[p.tag]) for p in room}))
    return room


def restart(relay, r, room, ssrc):
    relay.stop()
    relay.start()
    time.sleep(0.2)
    heard = round_robin(room)
    for p in room:
        want = {ssrc[o.tag] for o in room if o is not p}
        r.check(set(heard[p.tag]) == want, f"after a restart {p.tag} still hears the other three",
                f"got {sorted(heard[p.tag])}")
    q = relay.ok("query", call_id=ROOM)
    r.check(q["tags"].get("erin", {}).get("label") == "late", "labels come back with the state file")


def lobby(relay, r):
    """Callers wait in a lobby (each its own call with the focus's music
    endpoint); the focus moves them into a room with one `mesh`."""
    music = [Endpoint(), Endpoint()]
    callers = []
    for i, codec in enumerate(("PCMU", "PCMA")):
        cid = f"lobby-{i}@conf"
        p = Participant(f"caller{i}", codec)
        o = Sdp(relay.ok("offer", call_id=cid, from_tag=p.tag, sdp=sdp("127.0.0.1", p.ep.port, pts=(p.pt,)),
                         flags=["trust-address"])["sdp"])
        a = Sdp(relay.ok("answer", call_id=cid, from_tag=p.tag, to_tag=f"focus{i}",
                         sdp=sdp("127.0.0.1", music[i].port, pts=(p.pt,)), flags=["trust-address"])["sdp"])
        p.dst = a.dest()
        callers.append((p, o.dest()))
    time.sleep(0.05)
    c0, c1 = callers[0][0], callers[1][0]

    def music_plays():
        for i, (p, to_caller) in enumerate(callers):
            p.ep.drain()
            music[i].send_rtp(to_caller, pt=p.pt, n=3, payload=b"\x55" * 160)
        time.sleep(0.1)
        return [bool(p.ep.recv_all(0.2)) for p, _ in callers]

    r.check(music_plays() == [True, True], "in the lobby each caller hears the focus's music")

    # Both callers are `from` parties: `unsubscribe` acts on those only.
    rep = relay.ok("mesh", calls=["lobby-0@conf", "lobby-1@conf"],
                   tags=[{"from": "caller0", "to": ["caller1"]}, {"from": "caller1", "to": ["caller0"]}],
                   flags=["unsubscribe"])
    time.sleep(0.05)
    r.check("warning" not in rep, "mesh across two calls with different codecs", rep.get("warning", ""))
    played = music_plays()
    r.check(played == [False, False], "mesh with unsubscribe stops the lobby music to both callers", str(played))
    heard = round_robin([c0, c1])
    r.check(set(heard["caller1"]) == {c0.ep.ssrc} and set(heard["caller0"]) == {c1.ep.ssrc},
            "the two callers, in different calls, hear each other")
    pts = {x[0]["pt"] for v in heard["caller1"].values() for x in v}
    r.check(pts == {8}, "the PCMA caller hears the PCMU caller converted", str(pts))
    music[0].drain()
    c0.speak(2)
    r.check(bool(music[0].recv_all(0.2)),
            "without bidirectional the focus still hears caller 0 (only what reaches the callers changes)")

    # --- refusals, checked before anything changes
    for what, opts, want in [
        ("mesh without calls", dict(tags=[{"from": "caller0", "to": ["caller1"]}]), ""),
        ("mesh naming an unknown call", dict(calls=["lobby-0@conf", "nope@conf"]), ""),
        ("mesh with a to-tag in none of the calls", dict(calls=["lobby-0@conf"],
                                                         tags=[{"from": "caller0", "to": ["caller1"]}]), "not found"),
    ]:
        try:
            relay.ok("mesh", **opts)
            r.check(False, f"{what} is refused")
        except NgError as e:
            r.check(want in str(e), f"{what} is refused", str(e))
    # The same tag in two listed calls is ambiguous.
    x, y = Endpoint(), Endpoint()
    relay.ok("offer", call_id="lobby-x@conf", from_tag="caller0", sdp=sdp("127.0.0.1", x.port),
             flags=["trust-address"])
    relay.ok("answer", call_id="lobby-x@conf", from_tag="caller0", to_tag="zed", sdp=sdp("127.0.0.1", y.port),
             flags=["trust-address"])
    try:
        relay.ok("mesh", calls=["lobby-0@conf", "lobby-x@conf"], tags=[{"from": "caller0", "to": ["zed"]}])
        r.check(False, "a tag in two listed calls is refused")
    except NgError as e:
        r.check("several calls" in str(e), "a tag in two listed calls is refused", str(e))
    heard = round_robin([c0, c1])
    r.check(set(heard["caller1"]) == {c0.ep.ssrc}, "a refused mesh changes nothing")


def three_way(relay, r):
    """A B2BUA's three-way call in one call-id: Alice talks to Bob,
    consults Carol (a second dialog of hers), then joins Bob and Carol."""
    cid = "3way@b2bua"
    alice, alice2, bob, carol = Endpoint(), Endpoint(), Endpoint(), Endpoint()
    o = Sdp(relay.ok("offer", call_id=cid, from_tag="a", label="host", sdp=sdp("127.0.0.1", alice.port),
                     flags=["trust-address"])["sdp"])
    a = Sdp(relay.ok("answer", call_id=cid, from_tag="a", to_tag="b", label="first", sdp=sdp("127.0.0.1", bob.port),
                     flags=["trust-address"])["sdp"])
    # The consultation is a dialog of its own, on new ports: Carol's leg
    # offers (a new tag) and its answer names Alice.
    o2 = Sdp(relay.ok("offer", call_id=cid, from_tag="c", label="second", sdp=sdp("127.0.0.1", carol.port),
                      flags=["trust-address"])["sdp"])
    a2 = Sdp(relay.ok("answer", call_id=cid, from_tag="c", to_tag="a", sdp=sdp("127.0.0.1", alice2.port),
                      flags=["trust-address"])["sdp"])
    r.check(len({o.dest(), a.dest(), o2.dest(), a2.dest()}) == 4, "the consultation gets ports of its own")
    time.sleep(0.05)
    to_bob, to_alice = o.dest(), a.dest()
    to_alice2, to_carol = o2.dest(), a2.dest()

    def reaches(src, dst_addr, dst):
        dst.drain()
        src.send_rtp(dst_addr, n=2)
        return any(parse_rtp(d) and parse_rtp(d)["ssrc"] == src.ssrc for d, _ in dst.recv_all(0.2))

    r.check(reaches(alice, to_alice, bob) and reaches(bob, to_bob, alice), "Alice and Bob talk")
    r.check(reaches(alice2, to_alice2, carol) and reaches(carol, to_carol, alice2), "Alice and Carol talk")
    r.check(not reaches(bob, to_bob, carol), "Bob and Carol do not hear each other yet")
    q = relay.ok("query", call_id=cid)
    tags = q.get("tags", {})
    r.check(sorted(tags) == ["a", "b", "c"], "one call, three parties", str(sorted(tags)))
    r.check(len(tags.get("a", {}).get("medias", [])) == 2, "Alice, in two dialogs, has the media of both")
    r.check([tags.get(t, {}).get("label") for t in "abc"] == ["host", "first", "second"],
            "labels from offer and answer", str([tags.get(t, {}).get("label") for t in "abc"]))

    # --- join: Bob and Carol hear each other too, by label
    relay.ok("mesh", calls=[cid], tags=[{"from": "b", "to": ["c"]}], flags=["bidirectional"])
    time.sleep(0.05)
    r.check(reaches(bob, to_bob, carol) and reaches(carol, to_carol, bob),
            "after mesh Bob and Carol hear each other: a three-way call")
    r.check(reaches(alice, to_alice, bob) and reaches(alice2, to_alice2, carol), "and both still hear Alice")

    # --- the host mutes herself to the first party only
    relay.ok("block media", call_id=cid, label="host", to_label="first")
    time.sleep(0.05)
    r.check(not reaches(alice, to_alice, bob), "block media by labels: the host is muted to Bob")
    r.check(reaches(alice2, to_alice2, carol), "but not to Carol (her other dialog)")
    relay.ok("unblock media", call_id=cid, from_label="host")
    time.sleep(0.05)
    r.check(reaches(alice, to_alice, bob), "unblock media by label")
    try:
        relay.ok("block media", call_id=cid, label="nobody")
        r.check(False, "an unknown label is refused")
    except NgError as e:
        r.check("nobody" in str(e), "an unknown label is refused by name", str(e))

    # --- the host leaves her dialog with Bob; Bob and Carol go on
    relay.ok("delete", call_id=cid, from_tag="a", to_tag="b")
    time.sleep(0.05)
    r.check(not reaches(alice, to_alice, bob), "the host's dialog with Bob ends")
    r.check(reaches(alice2, to_alice2, carol), "her dialog with Carol goes on")
    # Bob's only relay ports were his dialog's: his copies end with it.
    r.check(not reaches(bob, to_bob, carol), "Bob's copies to Carol end with his dialog")


def consult_from_the_host(relay, r):
    """The other way a B2BUA might send the consultation: an offer from
    the host naming the new party as to-tag. A to-tag that is no party of
    the call is the answerer of the offerer's dialog (as in a two-party
    call), so the new party takes the first party's place."""
    cid = "consult@b2bua"
    alice, alice2, bob, carol = Endpoint(), Endpoint(), Endpoint(), Endpoint()
    relay.ok("offer", call_id=cid, from_tag="a", sdp=sdp("127.0.0.1", alice.port), flags=["trust-address"])
    relay.ok("answer", call_id=cid, from_tag="a", to_tag="b", sdp=sdp("127.0.0.1", bob.port), flags=["trust-address"])
    relay.ok("offer", call_id=cid, from_tag="a", to_tag="c", sdp=sdp("127.0.0.1", alice2.port),
             flags=["trust-address"])
    relay.ok("answer", call_id=cid, from_tag="a", to_tag="c", sdp=sdp("127.0.0.1", carol.port),
             flags=["trust-address"])
    tags = sorted(relay.ok("query", call_id=cid).get("tags", {}))
    if tags == ["a", "c"]:
        r.finding("a consultation offered by the host (from-tag a, to-tag c, c new) replaces the first party: "
                  "Bob's dialog silently becomes Alice-Carol (as documented, an unknown to-tag is the answerer "
                  "of the offerer's dialog). A B2BUA adding a leg must offer from the new party's tag")
    else:
        r.check(tags == ["a", "b", "c"], "a consultation offered by the host adds a dialog", str(tags))
    relay.ok("delete", call_id=cid)


def scenario(r):
    relay = Relay(base_config(NG, ports=PORTS, sessions='state_file = "STATE"'), NG, "conference")
    state = os.path.join(relay.dir, "state.json")
    with open(relay.config_path) as f:
        text = f.read()
    with open(relay.config_path, "w") as f:
        f.write(text.replace("STATE", state))
    try:
        relay.start()
        parts, ssrc = dial_out_room(relay, r)
        room = leave_and_join(relay, r, parts, ssrc)
        time.sleep(1.2)  # the state file is written at most once a second
        restart(relay, r, room, ssrc)
        lobby(relay, r)
        three_way(relay, r)
        consult_from_the_host(relay, r)
        relay.ok("delete", call_id=ROOM)
        heard = round_robin(room)
        r.check(not any(heard.values()), "deleting the room ends every participant's media")
    finally:
        relay.cleanup()


if __name__ == "__main__":
    main(scenario)
