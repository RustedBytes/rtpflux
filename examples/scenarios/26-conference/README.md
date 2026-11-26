# 26: Conference calls without a mixer

**The case.** A conference focus (a B2BUA, or the proxy's conference
logic) puts several parties in one conference. rtpflux has no mixer:
with `mesh`, each participant gets every other participant's audio as a
stream of its own (the speaker's SSRC). Every stream comes from the one
relay port that participant sends to, and is converted to that
participant's codec. Endpoints that play several streams at once
(WebRTC, most softphones, an SFU-style client) hear the whole room. An
endpoint that plays one stream at a time hears one speaker.

Three ways to build one, all checked here:

- **Dial-out room:** the focus calls each participant. `create` makes the
  relay's offer for the new party, and the participant's answer goes back
  with `create answer`. Then one `mesh` joins them all.
- **Lobby to room:** each caller is in a call of its own with the focus
  (hold music, a PIN prompt). One `mesh` with `unsubscribe` across those
  calls moves them into the room: they stop hearing the focus and hear
  each other.
- **Three-way call:** a B2BUA keeps all legs in one call-id. The host is
  in a dialog with each other party, and a `mesh` between those two
  parties joins them.

## Setting it up

No configuration is needed (a `state_file` keeps the room across
restarts). The `ng` sequences:

```text
# dial-out room
create           call-id=room from-tag=alice codec={offer: [PCMU]} label=host  → offer for Alice
create answer    call-id=room from-tag=alice sdp=<Alice's answer>
…                (the same for each participant)
mesh             calls=[room] tags=[{from: alice, to: [bob, carol, dave]}, …]   → everyone hears everyone
block media      call-id=room from-tag=bob all=except-offer-answer              → Bob muted
mesh             calls=[room] tags=[{from: erin, to: [alice, bob, carol]}] flags=[bidirectional]   → late joiner
delete           call-id=room from-tag=dave                                     → Dave leaves

# lobby to room
mesh             calls=[lobby-0, lobby-1]
                 tags=[{from: caller0, to: [caller1]}, {from: caller1, to: [caller0]}]
                 flags=[unsubscribe]

# three-way call in one call-id
offer/answer     call-id=3way from-tag=a … to-tag=b                 (Alice and Bob)
offer/answer     call-id=3way from-tag=c … to-tag=a                 (Carol's leg, a dialog with Alice)
mesh             calls=[3way] tags=[{from: b, to: [c]}] flags=[bidirectional]
```

## What `run.py` checks

- **The room:** `create` offers each participant its codec (PCMU, PCMA,
  G.722) on ports of its own. `query` lists the parties with their
  labels, and nobody hears anyone before `mesh`.
- **Mesh:** each of four participants hears the three others as three
  streams (their SSRCs), never itself, all from its own relay port and in
  its own codec. Alice's 1 kHz PCMU tone arrives at the same level as
  PCMU at Bob and converted to PCMA at Carol, and as 20 ms G.722 frames
  at Dave. Converted copies keep consecutive sequence numbers.
- **Mute:** `block media` with `all: except-offer-answer` mutes one
  participant for everyone while they still hear the room. `unblock
  media` undoes it. `play media` with `all` reaches every created party.
- **Leaving and joining:** a deleted participant stops hearing and being
  heard while the others go on. A late joiner is meshed both ways in one
  request.
- **Restart:** after a restart (state file) every participant still hears
  the other three, and labels are back.
- **Lobby to room:** `mesh` across two calls with different codecs. With
  `unsubscribe` the hold music stops, the callers hear each other
  (converted), and without `bidirectional` the focus still hears them.
- **Refusals:** no calls, an unknown call, a tag in none of the calls, a
  tag in two of them. A refused `mesh` changes nothing.
- **Three-way call:** the consultation gets its own ports. `query` shows
  three parties, the host with the media of both dialogs and labels from
  `offer` and `answer`. After `mesh`, Bob and Carol hear each other and
  both still hear the host. `block media` by labels mutes the host to
  one party only, and an unknown label is refused by name. When the host
  ends one dialog, her other dialog goes on.

## Caveats

- To add a leg to a call, offer from the new party's tag (`from-tag c`)
  and answer with `to-tag a`, as this scenario does. An `offer` from the
  host (`from-tag a, to-tag c`, with `c` new to the call) is a re-offer
  of the host's existing dialog, as in a two-party call: Bob's dialog
  becomes Alice–Carol. See [Calls with more than two
  parties](../../../docs/control-protocol.md#calls-with-more-than-two-parties).
- Copies end with the dialog of either party, and there is no mixer.
