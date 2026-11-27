# Media engine: audit and gaps

rtpflux is growing from an RTP relay driven by a SIP proxy into a media
engine driven by a B2BUA or softswitch (ferrosip, and a softswitch to
come). The proposal behind this work is the *programmable media engine*
specification (P0: independent endpoints, bridges, lifecycle, a native
control API and events; P1: PCM processing; P2: a conference mixer).

This page started as that specification's first milestone (P0a): an
audit of what the code did, against each requirement. It now also records
what was built on it, and what is left. Each line cites the code (paths
under `crates/rtpflux/src/` unless written otherwise). The design of the
native API is in [ADR 0001](adr/0001-native-control-api.md), and its
reference is [Native control API](native-api.md).

Ordinary relaying must not get slower: every step below is judged first on
correctness, then on what it costs the relay path. Features that need
userspace stay off the [XDP fast path](xdp.md), as today.

## What existed before (the audit)

### Endpoints and negotiation

| Requirement | Today | Where |
|---|---|---|
| Local offer, remote answer, with no other party | `create`, `create answer`: a hidden offerer (`rtpflux-create:<tag>`) whose answerer is the party | `control/create.rs` |
| Remote offer, local answer, with no other party | **`create from offer`** (added in P0a): the party is the offerer, the hidden side answers with every offered format, directions mirrored | `control/create.rs`, `publish.rs` (`mirror_answer`) |
| Receive-only answer | `publish` | `control/subscribe.rs` (`publish`) |
| Unbridged endpoint | A created party's media is dropped (`Echo::Discard` on both legs) until `connect` | `control/create.rs` |
| Re-offer, hold, resume, new codecs | `offer` again in the dialog; `create`/`create from offer` again with the same tags | `control/offer.rs` (`reoffer`, `replace_media`) |
| Rejected sections, direction attributes | Port 0 kept; directions passed or mirrored | `rtpflux-core/src/sdp/` |
| Pending vs committed revision | Only with `flags: track-state`: a full clone of the dialog (`Session::checkpoint`), taken back by `rollback`, committed by the answer | `control/offer.rs`, `control/rollback.rs` |
| SRTP (SDES), DTLS-SRTP, ICE, BUNDLE per endpoint | Per media section (`MediaState`) | `control/media.rs` |

### Bridging

`connect` joins two parties of one call or two, on one worker
(`ConnectLocal`) or across two (two bounded queues of 256 packets, one
per direction, dropped and counted when full). It detaches the parties
they leave, and moving a connected party detaches its former peer both
ways (`relay/worker/connect.rs`). Codecs are converted when they differ
(G.711, G.722, G.729, Opus, AMR). Directional copies (`connect` with
`directional`, `inject`, `mesh`) are separate streams, not mixed audio.

### Lifecycle, recovery

- A call belongs to one worker (round-robin over port shards); its ports
  are freed when the worker reports `Event::Closed` (`relay/mod.rs`).
- Teardown releases sockets, SRTP and DTLS state, ICE agents, taps,
  recordings (finished and converted), announcements, tones, BUNDLE,
  connections and the call's XDP flows (`relay/worker/commands.rs`,
  `close_call`).
- Timeouts: `sessions.timeout` (60 s of no media), `silent_timeout`
  (held), `offer_timeout` (unanswered), `final_timeout` (off by default).
- The state file and Redis hold every dialog with its ports, addresses,
  keys, ICE credentials, pending offers, `track-state` checkpoints,
  subscriptions, connections, copies, labels and per-call features
  (`state.rs`, `control/persist.rs`). DTLS associations, announcements
  from a `blob`, `play DTMF` in progress and counters are not kept.
  Redis being down never blocks the control thread.

### Events and observation

- The only push to a controller is the recording **upload** webhook
  (`recording/webhook.rs`): bounded queue (default 1000, dropped and
  counted when full), up to 5 attempts with backoff, a delivery id
  stable across retries, HMAC signature. It fires after S3 uploads only.
- DTMF: RFC 4733 events are deduplicated (a ring of the last 32 finished
  events, `rtpflux-core/src/dtmf.rs`) and listed in `query` (at most 256
  per leg). In-band detection (Goertzel, 40 ms to start and to end,
  `rtpflux-core/src/dtmf_inband.rs`) feeds DTMF transcoding and DTMF
  security only, not `query`.
- `play media` replies with the duration; nothing reports its end.
- Prometheus metrics have no per-call labels (`metrics.rs`).

### Media processing primitives

| Primitive | Today | Live, allocation-free |
|---|---|---|
| Decoders/encoders: G.711, G.722, G.729 (+B), Opus, AMR, AMR-WB | `codec.rs` | yes (AMR encode packs into a `Vec`) |
| Resampling 8↔16 kHz | `codec::Resampler`, half-band FIR | yes |
| Resampling by integer factors | `recording/resample.rs` | no (offline) |
| Repacketisation (`ptime`) | `relay/repack.rs`, preallocated | yes |
| Tone generation (DTMF, in-band) | `relay/worker/tones.rs` | yes |
| Two-party mix | `recording/mix.rs` | no (offline, after the call) |
| Fixed-capacity FIFO | `rtpflux-core/src/ring.rs` | yes (unused by the daemon) |
| Jitter buffer, reordering, PLC, VAD, gain, N-party mixer | none | — |

Announcements are G.711 frames of 20 ms, paced by the worker
(`relay/play.rs`, `relay/worker/features.rs`).

## Defects found, and fixed

The audit found these. Each is fixed, with a regression test where a test
can show it.

1. **Resurrection.** A `delete-delay` was a bare selector: when it fired,
   it deleted a dialog made again under the same Call-ID and tags
   meanwhile. Every dialog now has a generation (`Session::generation`,
   kept by re-offers, new for a new dialog), and a delayed delete ends
   only the generations it selected (`control/mod.rs`, `delete`; test
   `a_delayed_delete_spares_a_dialog_made_again`). Native endpoints add
   their own generations and tombstones (below).
2. **Partial `connect`.** Across workers, the second end of a connection
   could be refused after the first had detached its party's former peer.
   The second end is now offered again for up to 20 ms before the
   connection fails (`relay/calls.rs`, `connect`). A re-offer of a
   connected created party no longer parks it: it is joined again
   (`control/create.rs`, `park_or_rejoin`).
3. **Port leak.** A delete whose worker was gone left the call `ending`
   forever. Its ports are now freed (`relay/calls.rs`, `forget_call`).
4. **Offer stored after a failed render.** A new dialog whose offer cannot
   be written is no longer kept: its calls end (`control/offer.rs`).
5. **`rollback` reported success after a failure.** Media updates that
   fail are now named in the reply's `warning` (`control/rollback.rs`);
   `rolled-back` stays as rtpengine's.
6. **XDP flow after a port is reused.** Not changed. The worker sends the
   flow's `Remove` before it reports the call closed. Both reach their
   threads through FIFO channels, and a new call on the same port is on
   the same worker, so its `Install` comes after the `Remove`. The
   remaining window is the old peer sending to a port reused within the
   XDP thread's latency.
7. **The DTMF list allocated on the packet path.** It is now allocated
   with the leg (`relay/worker/dtmf.rs`).

## What was built

### P0: endpoints, lifecycle, the native API, events

- **Negotiation both ways.** `create` (the relay offers) and
  `create from offer` (the relay answers an endpoint's offer, with no
  second party), both reachable through ng and through the native API's
  `endpoint.create`.
- **The native API** ([reference](native-api.md); `control/native.rs`,
  `native.rs`):
  - a Unix socket with peer-credential checks;
  - endpoint ids, generations and revisions, tombstones, idempotency keys,
    deadlines, tenants and leases;
  - prepare/commit/abort renegotiation;
  - bridges (attach, detach, replace) with `bridge.changed`;
  - typed errors, and `endpoint.list` for reconciliation.
- **One command model.** Native operations build the requests of the ng
  commands they correspond to and run them on the same handlers. The ng
  wire format, warnings and behaviour are unchanged; the ng test suite is
  the check.
- **Events.**
  - Media workers and the recording thread report through one bounded
    queue (`relay/media_events.rs`): key presses, announcements played
    out, DTLS keyed or failed, ICE connected, recordings finished.
    Nothing is sent per packet, and a full queue drops and counts.
  - The control thread delivers events to subscribers through bounded
    queues, with per-endpoint and global sequence numbers and `gap`
    events.
- **Detach.** A new worker command (`Command::Detach`) takes a leg out of
  whatever it is joined to.
- **Restarts.** Endpoints are saved with the dialogs (`state.rs`,
  `SavedEndpoint`) and come back with their media.
- **Client.** `crates/rtpflux-client` (a synchronous Rust client) and
  protocol fixtures.

### P1: PCM processing

- **DSP kernels** (`rtpflux-core/src/dsp/`; `no_std`, no allocation, no
  unchecked arithmetic):
  - a jitter buffer;
  - loss concealment;
  - gain and a limiter;
  - voice activity detection;
  - a polyphase resampler between 8, 16, 24 and 48 kHz;
  - the N − 1 mix;
  - a tone generator.

  Their tests check them against reference implementations.
- **PCM streams** (`pcm/`). An endpoint's audio goes to an external
  service's Unix socket and the service's audio comes back, framed as in
  [PCM streams](native-api.md#pcm-streams). They have backpressure,
  flush (barge-in), playout marks, and speech events. The media worker
  only copies packets, by value into a bounded queue, and plays 20 ms
  frames. The signal processing runs on the stream's threads.
- **Modes.** The packet fast path (XDP) and the transcoding path are
  unchanged. A leg with a stream or in a mixer leaves the XDP fast path
  (`offload_dirs`) before its packets are needed. The ordinary relay
  path's only addition is a check that a worker has no stream.

### P2: conference mixing

- **Mixers** (`pcm/mixer.rs`) do N − 1 mixing on their own threads, for
  up to 64 participants:
  - per-participant jitter buffer, decoder and loss concealment;
  - a 32-bit sum, with each participant's own contribution subtracted
    exactly;
  - a limiter per listener;
  - mute and gain;
  - active-speaker events;
  - participants in any codec the relay converts, mixed at 16 kHz and
    each encoded in its own codec;
  - supervisor roles: listen, whisper to one participant, barge in.
- **Worker failures as events.** A recording that cannot be opened gives
  `recording.failed`, and a socket a worker cannot watch gives
  `endpoint.failed`. Routing changes are confirmed by the workers (a
  barrier after them) before the reply.
- **In-band DTMF.** Key presses in audio a stream or mixer decodes are
  reported with `source: "inband"`.
- **TCP for the native API.** It authenticates each connection with a
  tenant's token, and binds the connection to that tenant.

## What is left

- **Typed requests.** The ng handlers still read bencode. Native
  operations reach them through requests they encode, which is a cost on
  the control path only.
- **AEC/AGC, a general media graph, video, a T.38 gateway.** None of
  these is done.
- **Integration and load.**
  - What exists: a churn test (100 rounds of create, bridge, detach and
    destroy across workers, with retried creates and repeated destroys)
    that checks the relay's full capacity is available afterwards; and
    the relay benchmark of `main` against this work on one machine, with
    no measurable difference in CPU per packet, delivery or p99 latency.
  - What is left: a two-leg scenario against ferrosip's UA engine,
    `tc netem` soak tests, and benchmarks on production hardware
    ([Benchmarks](benchmarks.md)).
