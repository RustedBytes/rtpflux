# Native control API

The native API is for a B2BUA or softswitch that manages media itself.
It creates **endpoints**, negotiates them in either direction, bridges
them, renegotiates them, and destroys them. It can also stream an
endpoint's audio to an external service, or mix endpoints in a
conference. It is served beside the [ng protocol](control-protocol.md),
which stays exactly as it is. Both run on the same handlers, so an
endpoint is also a party that ng commands such as `query` can see. The
design is in [ADR 0001](adr/0001-native-control-api.md).

Two Rust clients are in the workspace:
- [`rtpflux-client-async`](https://github.com/RustedBytes/rtpflux/tree/main/crates/rtpflux-client-async),
  on Tokio, is for a softswitch's call control. It has typed requests and
  replies, a pool of connections, bounded queues, deadlines, cancellation,
  reconnect, and events on a connection of their own.
- [`rtpflux-client`](https://github.com/RustedBytes/rtpflux/tree/main/crates/rtpflux-client)
  is blocking, for tools and prototypes. Its `fixtures/` directory holds
  example sessions, request by request.

## Connecting

```toml
[control]
native_socket = "/run/rtpflux/native.sock"
native_uids = [1001]          # users allowed besides the relay's own and root
native_max_endpoints = 0      # per tenant; 0: up to sessions.max
pcm_dir = "/run/rtpflux/pcm"  # where audio services listen (PCM streams)
native_listen = ["10.0.0.5:2224"]   # also over TCP (put TLS in front)
native_tokens = { switch-a = "a long random token", switch-b = "another one" }
```

The socket is created with mode 0600. Only the relay's own user, root,
and the users in `native_uids` may connect; the peer's credentials are
checked. At most 64 connections are served at once.

**Over TCP** (`native_listen`), a connection's first request must
authenticate, with a tenant's token:
`{"v": 1, "op": "auth", "token": "…"}` → `{"result": {"tenant": "switch-a"}}`.
Tokens are compared in constant time, and must be 16 characters or more.
- Until it authenticates, a connection gets `unauthorized` for anything
  else.
- Three bad tokens close the connection.
- An authenticated connection is that tenant's. A request naming another
  tenant is refused (`unauthorized`).

The relay has no TLS of its own: keep `native_listen` on a private
network, or put a TLS proxy in front. A non-loopback `native_listen` is
warned about at start.

Each message, in either direction, is a 4-octet big-endian length
followed by that many octets of JSON, at most 1 MiB. A connection's
requests are answered in order.

## Requests and replies

```json
{"v": 1, "op": "endpoint.create", "operation_id": "op-7", "remote_sdp": "v=0\r\n…"}
```

| Field | Meaning |
|---|---|
| `v` | The protocol version: 1 |
| `op` | The operation |
| `operation_id` | Chosen by the client. Echoed in the reply and in the events the operation causes |
| `idempotency_key` | Optional: the operation's stable key, per tenant. See [Operation keys and the ledger](#operation-keys-and-the-ledger) |
| `first_attempt_unix_ms` | Optional, with `idempotency_key`: when the operation was first attempted. A key older than the ledger keeps is refused (`expired`), not run again |
| `tenant` | Optional (default `default`). Endpoints, sessions and mixers belong to a tenant; another tenant gets `unauthorized` |
| `endpoint_id` | The endpoint the operation is about |
| `expected_generation`, `expected_revision` | Optional. The request fails with `conflict` when the endpoint's are different |
| `deadline_unix_ms` | Optional. A request that arrives after this time fails with `timeout` and is not run |

A reply is `{"v": 1, "operation_id": …, "ok": true, "result": {…}}`, or
`"ok": false` with `"error": {"code": …, "message": …}`. The error codes
are:

| Code | Meaning |
|---|---|
| `not_found` | No such endpoint, mixer or stream; or it was destroyed (the message says which, with its generation) |
| `conflict` | The wrong generation or revision, a renegotiation already pending, an answer to an endpoint already answered, … |
| `unsupported` | An operation, option, codec or capability the relay does not have |
| `exhausted` | No free ports, the session or endpoint limit is reached, or the relay is busy |
| `timeout` | The deadline has passed |
| `unauthorized` | Another tenant's resource |
| `invalid` | A malformed request or SDP |
| `internal` | Anything else |
| `unavailable` | Durable storage failed. Nothing was done, unless the message says the operation was applied and only its record failed (`detail` names the resources) |
| `expired` | The operation key's first attempt is older than the ledger keeps; it was not run again |
| `unknown_outcome` | The operation began before a restart and its outcome was never recorded: it may or may not have taken effect. Reconcile before acting again |

An error may carry `detail`, typed: the live or destroyed endpoint an
`external_id` conflict is about, the resources of an unknown outcome.

A reply means the change is applied in the control thread and queued to
the media workers, which apply their commands in order. Operations that
change where media goes wait until the workers concerned have applied the
change before they reply: `bridge.attach`, `bridge.detach`,
`stream.start`, `mixer.add`. Each worker confirms with a barrier queued
after the change. If a worker does not confirm within a second, the reply
is `timeout`; the change may still take effect, and `endpoint.query`
tells.
Operations that finish later report their end with an event: an
announcement that played out, a recording, a stream.

### Operation keys and the ledger

A request that changes something and carries `idempotency_key` is
recorded in the ledger:
- A retry with the same key and the same intent gets the first reply,
  marked `replayed: true`. Nothing runs again, whether the first attempt
  succeeded or failed.
- The same key with another intent is a `conflict`.

**The intent** is the request's canonical JSON (keys sorted at every
level) without the fields of a single attempt: `v`, `operation_id`,
`idempotency_key`, `tenant`, `deadline_unix_ms`, `first_attempt_unix_ms`
and `correlation_id`. Its SHA-256 is the fingerprint that is compared.

**What is not recorded.** A request refused for its envelope (protocol
version, tenant, a deadline already past) is definitely not executed. It
is not recorded, so a retry runs normally.

**In memory** (the default), the ledger keeps outcomes for 5 minutes, for
the relay process's lifetime.

**Durable** (`[sessions] ledger`, with a `state_file`):
1. A keyed mutation is written as `pending`, synced to disk, before it
   runs.
2. It runs.
3. Its resources' state is written, synced, to the state file.
4. Its outcome is written, synced, to the ledger.
5. Only then is it acknowledged.

After a crash, an operation written as `pending` and never finished is
`unknown_outcome`: retrying it does not run it again. Instead:
1. Reconcile: `endpoint.lookup` by `external_id`, or `endpoint.list`.
2. Make what is missing with a new key.

The ledger keeps outcomes for `ledger_retention` (a day by default), and
holds at most `ledger_quota` keys per tenant. A new key beyond the quota
is refused (`exhausted`); nothing is evicted early. The file is created
readable by the relay's user only: replies hold SDP, which may carry SRTP
keys.

**What the guarantee is not.** Without a ledger, state reaches the disk
at most once a second, and Redis writes are best effort. `hello` says
which applies (`guarantees`: `idempotency`, `state_commit`). A crash
loses up to a second of unkeyed changes.

| Operation | Fields | Result |
|---|---|---|
| `operation.query` | `idempotency_key`, `first_attempt_unix_ms` (optional) | `status`: `pending`, `applied`, `failed`, `unknown`, `expired` (older than kept), or `not_found`; and `op`, `resources`, `reply`, `at_unix_ms`, `durable` |

## Endpoints

An endpoint is media the relay terminates. It is identified by
`endpoint_id` (`ep-` and 32 hex digits) and belongs to a media session
`session_id` (the ng call: `ms-` and 32 hex digits, or a name the client
gives).
- **Generation:** given when the endpoint is created. It is never reused,
  even after a restart.
- **Revision:** counts the endpoint's committed negotiations, from 1.
- **State:** `offered` until it is answered, then `ready`.
- **Before it is bridged:** its media goes nowhere and nothing is sent to
  it. It is parked, but it can play announcements and stream audio.

| Operation | Fields | Result |
|---|---|---|
| `hello` | | `versions`, `operations`, `events`, `capabilities` (codecs, transports, PCM streaming and its rates, mixer), `limits` |
| `endpoint.create` | `remote_sdp` (the remote side's offer, which the relay answers), or `codecs` (the relay offers these: `PCMU`, `PCMA`, `G722`, `G729`, `opus`, `AMR`, `AMR-WB`, `telephone-event`, `CN`); `session_id`, `label`, `lease_ms`, `options`, `external_id`, `replaces_generation` | `endpoint_id`, `session_id`, `generation`, `revision`, `state`, `sdp_type` (`answer` or `offer`), `sdp`, `warnings` |
| `endpoint.apply_answer` | `endpoint_id`, `sdp`, `options` | `revision`, `state` |
| `endpoint.prepare` | `endpoint_id`; `remote_sdp` (the remote side's re-offer), or `codecs` / `options` (the relay's re-offer), whichever side offered first | `pending_revision`, `sdp_type`, `sdp` |
| `endpoint.commit` | `endpoint_id`, `revision`; after the relay's re-offer, `sdp` (the answer) | `revision` |
| `endpoint.abort` | `endpoint_id`, `revision` | `revision` (the committed one) |
| `endpoint.destroy` | `endpoint_id` | `destroyed`, or `already: true` |
| `endpoint.query` | `endpoint_id` | The endpoint's snapshot, and `media` (its streams, statistics, RTCP, DTMF, as ng `query` reports them) |
| `endpoint.list` | | `endpoints` (snapshots), `destroyed` (recent tombstones), `global_seq` |
| `endpoint.lookup` | `external_id` | The live endpoint's snapshot (`state_of_id: "live"`), or the destroyed one's id, generation and reason (`state_of_id: "destroyed"`) while its tombstone is kept |
| `endpoint.renew` | `endpoint_id`, `lease_ms` (optional) | `lease_ms` |
| `ownership.claim` | `group`, `epoch`, `owner`, `lease_expires_unix_ms`, `key_id`, `signature` (see [Exclusive ownership](#exclusive-ownership-ha)) | `group`, `epoch`, `owner`, `lease_expires_unix_ms`, `previous_epoch`, `drained` |

`options` are ng options for the operation (see
[Options](control-protocol.md#options)), as JSON:
`{"flags": ["trust-address"], "ICE": "remove", "transport-protocol": "RTP/SAVP", "SDES": ["no-AES_CM_128_HMAC_SHA1_32"]}`.
Strings, integers, lists and objects map to their bencode forms, and
`true`/`false` become `yes`/`no`. Keys the operation sets itself are
refused: `call-id`, `from-tag`, `to-tag`, `sdp`, `label`.

**Renegotiation** goes in either direction, whichever side made the
endpoint's first offer. With `remote_sdp`, the remote side re-offers (a
re-INVITE or UPDATE). Without it, the relay re-offers (a delayed offer, a
codec change).
- Both keep the committed media (ports, keys, ICE, roles, bridge) as a
  checkpoint until `endpoint.commit`. The answer to a remote re-offer is
  given at prepare, and its media apply then, but the checkpoint stays.
- `endpoint.abort` puts the checkpoint back exactly
  ([`rollback`](control-protocol.md#rollback)), and the endpoint is
  bridged again as it was. An abort that cannot take it back fails
  (`internal`) and says so; it does not report success.
- A renegotiation that does not change the media keeps the ports, the
  keys and the bridge.

**Inventory and recovery.**

| Operation | Fields | Result |
|---|---|---|
| `inventory.list` | `kind` (`endpoints`, `bridges`, `streams`, `mixers`, `playbacks`, `recordings`), `limit` (1–500, default 100), `cursor` | `items`, `next_cursor`, `total`, `watermark` (`boot_id`, `global_seq`, `topology_epoch`) |
| `recovery.report` | | `boot_id`, `previous_boot_id`, `restored_endpoints`, `lost`, `unknown_operations` |

Inventory pages list one kind in id order. A cursor is valid only while
nothing changes. If any resource or link changes between two pages, the
next page is a `conflict`, and the client starts again without a cursor.
It never gets pages of two different states. Endpoint items also carry
their stream and mixer.

`hello` gives this run's `boot_id`; a restart makes a new one. After a
restart, `recovery.report` says what came back and what did not:
- the endpoints restored, with their media, bridges and recordings, which
  continue in the same files;
- what was lost: PCM streams and mixers are never restored, and neither
  is an announcement from a `blob`. Announcements from a file are;
- the operations whose outcome is unknown.

Nothing is reported as restored that is not. The client reconstructs the
rest: it starts streams again, and creates mixers and adds their
participants.

**External ids.** `external_id` is the client's stable key for an
endpoint, such as a call's UUID and leg. It is unique per tenant:
- Creating a second endpoint under a live endpoint's external id is a
  `conflict`, whose `detail` names the live endpoint.
- Under a destroyed endpoint's external id, a new endpoint needs
  `replaces_generation`: the destroyed one's generation. A retry of the
  destroyed one's creation is therefore never taken for a new logical
  endpoint.
- External ids, tombstones and the counters ids are made from (endpoint
  generations, stream and mixer ids) are saved with the state, so no id
  is given twice across restarts.

**Lifecycle.**
- Destroying an endpoint frees everything it holds: ports, keys, its
  bridge, its announcement, stream and mixer membership, and its kernel
  flows.
- A destroyed endpoint leaves a tombstone for 5 minutes. A late command
  for it fails with `not_found` ("destroyed") and never brings it back.
- An endpoint also ends when its media times out
  (`sessions.timeout`), with `endpoint.timeout` then
  `endpoint.destroyed`. It ends when its lease is not renewed in time
  (reason `lease`), and when ng deletes its session (reason `ended`).
- A client that disconnects destroys nothing. Leases are how a client
  limits what outlives it.

**Restarts.** With a state file or Redis, endpoints come back with their
media: the same ids, generations, revisions and bridges, on the same
ports. A pending renegotiation also comes back. Leases start again at
the restart. A client that reconnects calls `endpoint.list` to
resynchronise. What does not come back:
- PCM streams and mixers, which the client starts again;
- DTLS associations: browser endpoints need a new handshake, as in
  [Operations](operations.md#restarts).

### Exclusive ownership (`[ha]`)

With several controllers, only one may change a call at a time, and one
that lost a call (a partition, a pause) must not change it afterwards.
Under `[ha]`, the relay enforces that with **fencing epochs**. The
epochs are issued by the controllers' **ownership authority**, never by a
controller.

**Groups and grants.** The authority grants an ownership group (a call,
say) to one controller at a time, each grant at a higher epoch. It signs
the grant with a key it shares with the relay:

```text
signature = hex(HMAC-SHA256(key, "rtpflux-ownership-v1\n<tenant>\n<group>\n<epoch>\n<owner>\n<lease_expires_unix_ms>"))
token     = hex(HMAC-SHA256(key, "rtpflux-ownership-token-v1\n<tenant>\n<group>\n<epoch>\n<owner>"))
```

The controller sends the grant as `ownership.claim`. The relay accepts it
only when:
- the signature verifies with the named key (constant-time comparison);
- the lease is still running;
- the epoch is not below the group's highest so far. The same epoch is
  accepted only for the same owner, as a renewal that never shortens the
  lease.

The relay syncs the claim to disk (`[ha] state`) before acknowledging it.
When the epoch rises, the reply says whether the media workers confirmed
the previous owner's commands applied (`drained`). In any case nothing
the previous owner sent can land after the new owner's commands: both go
through the one control thread, and each worker applies its commands in
order.

**Every mutation** carries `"ownership": {"group", "epoch", "token"}`.
The token is only the owner's, so an old controller cannot guess its way
in by sending a higher epoch. A mutation is refused with `fenced`, and
nothing is done, unless:
- the epoch is the group's current one;
- the lease is running;
- the token is the current owner's;
- every resource it touches (`endpoint_id`, `peer_endpoint_id`,
  `mixer_id`, `stream_id`) belongs to a group it proves.

A resource belongs to the group its creation proved (`endpoint.create`,
`mixer.create`, `stream.start`). A bridge across groups (calls) also needs
`"peer_ownership"` for the peer's group. Resources made before `[ha]` was
enabled belong to no group, and no one can change them.

Reads, `events.*` and `ownership.claim` itself need no proof. A refusal
for ownership happens before the ledger, so it is never recorded and a
retry with a fresh claim runs normally.

**Fail closed.** With no claim, a lease that has run out, or a claims file
that cannot be written, mutations are refused (`fenced`, or `unavailable`
for the claim). Media already established keeps flowing.

**After a restart** the relay remembers the epochs and which group owns
each restored endpoint, so a stale controller is still refused.

**Pruning.** A group whose lease is over and that owns nothing is
forgotten. The highest epoch forgotten becomes the tenant's floor: a
grant at or below it, for a group the relay does not know, is refused,
whatever its lease. **The authority must therefore issue epochs from one
rising sequence per tenant**, across all groups.

**`ng`.** In this mode, an `ng` command cannot change a call that holds
native endpoints (`call-id` or `to-call-id`). `ping`, `list`, `query` and
`statistics` still answer. `ng` calls without native endpoints are not
affected: isolate the `ng` port from controllers that must be fenced.

**Tenants.** Grants are signed for a tenant, and a connection
authenticated as another tenant cannot use them.

## Bridges

| Operation | Fields | Result |
|---|---|---|
| `bridge.attach` | `endpoint_id`, `peer_endpoint_id`; optionally `peer_expected_generation`, `peer_expected_revision`, `peer_expected_topology_revision` (with `expected_*` for `endpoint_id`) | `bridged_to`, `replaced` (the former peers, now alone) |
| `bridge.detach` | `endpoint_id` | `detached`, `was_bridged_to` |

**Topology revisions.**
- Every endpoint has a `topology_revision`, which changes whenever what
  it is bridged to changes. Negotiation revisions do not.
- A bridge request may expect both endpoints' topology revisions
  (`expected_topology_revision` and `peer_expected_topology_revision`). A
  stale one is a `conflict`, so a late request never undoes a newer
  bridge.
- The control thread runs every mutation in turn, so concurrent requests
  are ordered, and nothing deadlocks.

**Confirmation.**
- A bridge change replies only once both endpoints' media workers have
  applied it.
- If they do not confirm within a second, the reply is `timeout`, and the
  endpoints' snapshots say `topology_state: "unconfirmed"` until a later
  change is confirmed.

**A failed attach** may have been half applied: one worker took its end,
and its endpoint's former peer was detached. Every endpoint involved is
then detached, on the media workers and in the records, each with
`bridge.changed` (`reason: "attach_failed"`). The error's `detail` says
so (`compensated`). No bridge is ever reported that the media do not
have.

Attaching joins two endpoints with ng's [`connect`](control-protocol.md#connect).
- The two may be in different sessions, and on different media workers.
- Neither side needs a re-INVITE: each keeps the relay port it knows.
- When their codecs differ and the relay converts both, each one's audio
  is converted for the other.
- Attaching an endpoint that is already bridged moves it. Its former peer
  is detached, and told so with `bridge.changed`, reason `replaced`.
- Bridged endpoints enter the XDP fast path once settled, as connected
  calls do.

## Announcements and recordings

| Operation | Fields | Result |
|---|---|---|
| `playback.start` | `endpoint_id`, `file` or `blob_base64`, `repeat_times`, `start_pos`, `duration`, `repeat_duration`, `queue` (wait behind the current one), `stop_on` (`["dtmf", "speech"]`) | `playback_id`, `duration_ms`; queued: `queued`, `position` |
| `playback.stop` | `endpoint_id` | `stopped`, `playback_id` (the queue goes too) |
| `recording.start`, `recording.stop` | `endpoint_id`, `options` (`format`, `channels`, …) | `recording`, `recording_id` (starting again while it records gives the same id) |
| `recording.pause`, `recording.resume` | `endpoint_id` | `recording_id`, `state`, `changed`, `pauses` |
| `recording.query` | `recording_id` | Its `state` (`active`, `paused`, `pausing`, `stopped`, `completed`, `failed`), `pauses`, `file`, `finalized`, `uploaded`, `upload` (`pending`, `none`, `uploaded`, `failed`), `detail`, start and end times |

- An announcement that plays to its end gives `playback.completed`, with
  the `operation_id` of its `playback.start`. One that is stopped, or
  replaced by another, gives `playback.stopped` with the reason.
- **Queues.** With `queue: true`, a playback waits behind the current
  one, 16 at most, and starts when it completes. It gets its
  `playback_id` at once.
- **Interruption.** With `stop_on`, a key the endpoint presses (`dtmf`)
  or speech it starts (`speech`, which needs a VAD detector: see
  [Detectors](#ivr-keys-tones-detectors-and-sensitive-digits)) stops the
  playback at once (`playback.stopped`, `reason: "dtmf"` or `"speech"`).
  What was queued behind it goes too (`reason: "interrupted"`,
  `queued: true`). A `playback.start` without `queue` replaces the
  current playback and drops the queue (`reason: "replaced"`). The relay
  does the stopping, without a round trip to the controller. Digit
  collection and timeouts stay with the controller.

## IVR: keys, tones, detectors and sensitive digits

| Operation | Fields | Result |
|---|---|---|
| `dtmf.send` | `endpoint_id`, `digits` (1–64 of `0-9*#A-D`), `duration_ms` (40–5000, default 100), `pause_ms` (default 50), `volume` (0–63 dBm0 below, default 8), `mode` (`auto`, `rfc4733`, `inband`) | `keys`, `mode`, `duration_ms` (the digits are not echoed) |
| `tone.start` | `endpoint_id`, `frequency_hz` (50–4000), `on_ms` (default 1000), `off_ms` (default 0), `repeat` (1–1000), `volume` | `duration_ms` |
| `tone.stop` | `endpoint_id` | `stopped` |
| `dtmf.policy` | `endpoint_id`, `policy` (`dedup`, `both`, `rfc4733`, `inband`) | `policy` |
| `endpoint.sensitive` | `endpoint_id`, `sensitive` (`true`/`false`) | `sensitive`, `recording_paused` |

- **Sending keys.** `dtmf.send` plays them as telephone events when the
  endpoint negotiated them (`auto`, `rfc4733`), else as tones in its
  audio (`inband`). Tones and keys are refused while an announcement
  plays to the endpoint.
- **Detectors** need no service: `stream.start` without `socket` runs the
  endpoint's audio through the detectors only (`vad`, `dtmf`, both on by
  default), on the PCM shards, and sends it nowhere. `stream.detect`
  switches them at run time.
- **Detection.** RFC 4733 keys are reported for an endpoint even when it
  is not bridged to anyone (an IVR leg).
- **DTMF sources.** With both an in-band detector and telephone events, a
  press can be reported twice. `dtmf.policy` decides what reaches
  `dtmf.detected`:
  - `dedup` (the default): a key reported by one source within a second
    of the same key from the other is dropped;
  - `both`: every report;
  - `rfc4733` or `inband`: one source only.
- **Sensitive digits** (a PIN, a card number). While
  `endpoint.sensitive` is on:
  - the endpoint's `dtmf.detected` events carry `sensitive: true`. Only
    subscribers that asked for them (`events.subscribe` with
    `sensitive: true`) get the digit; the others get `digit` and `code`
    as `null` and `redacted: true`, live and on replay;
  - its recordings are paused, and resumed when it is turned off. One
    the controller paused itself stays paused.

  Digits are never logged, sensitive or not (`log` at any level).

  Not covered:
  - a PCM stream's external service hears in-band tones as audio;
  - a bridged peer still hears in-band tones and gets the events (use
    `ng`'s `block DTMF` if it must not);
  - the in-memory event journal holds the digit, for the subscribers
    entitled to it.
- **Pause and resume** take effect when the media workers confirm them
  (a barrier over the endpoint's calls). Only then is the recording
  `paused`, with the time in `pauses` (`[paused_at, resumed_at]`, in ms
  since the epoch). The recording holds nothing inside a pause. If the
  workers do not confirm within a second, the request fails (`timeout`,
  `detail.state: "pausing"`) and the recording stays `pausing`: the relay
  never says `paused` while capture may go on. A pause survives a restart
  of the relay. `endpoint.sensitive` pauses through the same path.
- **Outcomes** are kept apart in `recording.query`: `finalized` (the file
  is written), `upload` (`none` without uploads, `uploaded`, `failed`,
  `pending` before the end), and `failed` with its `detail` when no file
  could be made. `recording.start` with an `idempotency_key` records the
  `recording_id` among the operation's resources (`operation.query`).
- Only relayed media is recorded: an endpoint bridged to no one records
  nothing.
- A finished recording gives `recording.completed` once its audio file is
  written (`file`), with `uploaded` saying whether the S3 upload worked
  (`null` without uploads). A recording whose conversion failed gives
  `recording.failed`; its pcap is kept.

## PCM streams

A stream sends an endpoint's audio, decoded, to an external service
(speech recognition, a voice bot), and plays the service's audio back to
the endpoint. The service listens on a Unix socket in `[control]
pcm_dir`, and the relay connects to it.

| Operation | Fields | Result |
|---|---|---|
| `stream.start` | `endpoint_id`, `socket` (a file name in `pcm_dir`; none: detectors only), `rate` (8000, 16000, 24000 or 48000; default 16000), `inject` (default `true`), `protocol` (1 or 2, default 1), `vad`, `dtmf` (detectors, default on) | `stream_id`, `rate`, `inject`, `protocol`, `service`, `detect` |
| `stream.flush` | `stream_id` | `flushed`: the audio queued for the endpoint is dropped (barge-in), and a new generation begins |
| `stream.detect` | `stream_id`, `vad`, `dtmf` (`true`/`false`) | `detect` |
| `stream.stop` | `stream_id` | `stopped` |

**Frames.** Each frame on the socket is a 32-octet header followed by its
payload. Integers and samples are little-endian.

| Octets | Field |
|---|---|
| 0–3 | `RFPC` |
| 4 | version: 1, or 2 with `protocol: 2` |
| 5 | kind: 1 hello, 2 audio, 3 mark, 4 flush, 5 gap |
| 6–7 | flags: bit 0, a discontinuity (after a gap or a flush); version 2: bits 8–15, the flush generation (mod 256) |
| 8–11 | the stream id |
| 12–15 | sequence number, per direction (for a mark: its id; for a gap: frames missed) |
| 16–23 | media timestamp, in milliseconds of audio since the stream began |
| 24–27 | sample rate |
| 28 | channels: 1 |
| 29 | encoding: 1 (signed 16-bit PCM) |
| 30–31 | samples in the payload: 10 or 20 ms at the rate |

**What the relay sends** begins with a hello frame, then 20 ms audio
frames of what the endpoint sends, at the stream's rate. On the way the
audio goes through:
- a jitter buffer (40 ms target delay, reordering and duplicates
  handled);
- the endpoint's decoder (any codec the relay converts);
- loss concealment, then resampling to the stream's rate.

A voice activity detector on the same audio gives `speech.started` and
`speech.ended`. Key presses in the audio give `dtmf.detected` with
`source: "inband"`. The relay never waits for a service. One that reads
too slowly misses frames: up to 240 ms waits in the relay's write
buffer, beyond that frames are dropped. A gap frame gives the count as
soon as there is room, and the next audio frame is marked as a
discontinuity.

**What the service sends** is audio frames of 10 or 20 ms at any of the
four rates. The relay resamples them to the rate of the endpoint's codec,
encodes them in that codec, and plays them in 20 ms packets. That codec
is G.711, G.722, G.729, Opus (16 kHz) or AMR. While they come, the
endpoint's bridged peer is held back, as during an announcement. Further
rules:
- **Backpressure:** when more than 100 ms of audio is queued, the relay
  stops reading the socket, so the service's writes wait. Memory stays
  bounded.
- **Flush:** a flush frame, or `stream.flush`, drops what is queued.
  This is barge-in. Frames already on their way to the media worker
  are dropped too: each frame carries the flush count it was made
  under. Marks still waiting are answered as flushed. `stream.flushed`
  reports the new `generation` and `played_ms`, the service's audio sent
  as RTP before it.
- **Marks:** a mark (kind 3, its id in the sequence field) is answered
  with `stream.mark` once the audio sent before it has been sent to the
  endpoint as RTP (`boundary: "rtp_sent"`). The event has `generation`
  and `played_ms`, and `flushed: true` when the audio never will be
  sent. The relay knows what it sent, not what the remote side has
  played out: the endpoint's own jitter buffer adds its delay.
- **Protocol 2 (flush generations):** start the stream with
  `protocol: 2` and the relay's hello says version 2. The service tags
  every frame with the current generation (flags bits 8–15). Each flush
  is acknowledged with a flush frame to the service: its sequence field
  is the new generation, its media timestamp is `played_ms`. Audio and
  marks of an older generation are late audio of what was flushed (TTS
  still arriving after a barge-in, say). They are dropped and never
  played, and a late mark is answered as flushed. Version 1 services are
  unaffected.
- **End:** the stream ends with `stream.ended` when the service closes
  the socket, or with `stream.stop`.

The relay's media workers only copy packets for a stream and play the
frames it sends back. The signal processing and the socket I/O run on a
few shared **PCM shard** threads (`[runtime] pcm_shards`). There are no
threads per stream. A stream stays on one shard, and every 20 ms the
shard runs each of its streams once: at most a few frames are read from
one service, so a busy one does not starve the others. With 100 streams
both ways (`load` in `tests/pcm.rs`), 4 shard threads used 9.2–10.8% of
a core, where two threads per stream (200 threads) used 11.6–12.6%.

## Conference mixers

| Operation | Fields | Result |
|---|---|---|
| `mixer.create` | | `mixer_id`, `max_participants` (64) |
| `mixer.add` | `mixer_id`, `endpoint_id`, `role` (optional) | `participants` |
| `mixer.remove` | `mixer_id`, `endpoint_id` | `removed` |
| `mixer.set` | `mixer_id`, `endpoint_id`, `muted`, `gain_db` (−60 to +24), `role`, `whisper_to` | `set` |
| `mixer.destroy` | `mixer_id` | `destroyed` |

A mixer gives each participant the sum of everyone else (N − 1 mixing),
on a thread of its own. Every 20 ms it does the following:
1. Each participant's audio goes through its own jitter buffer, decoder
   and loss concealment, resampled to 16 kHz. A participant with nothing
   due contributes silence.
2. The mixer sums the participants in 32 bits, each at its gain. A muted
   participant adds nothing.
3. Each participant gets the sum minus its own contribution, through its
   own limiter. Nothing clips before its own voice is taken out.
4. Each mix is encoded in the participant's own codec and played to it.
   Wideband codecs (G.722, Opus, AMR-WB) get it at 16 kHz, narrowband
   ones at 8 kHz.

**Roles.** A participant's `role` decides who hears it:
- `participant` (the default): everyone hears it. A supervisor barging in
  is one.
- `listen`: it hears everyone, and no one hears it. A supervisor listening
  in.
- `whisper` with `whisper_to` (another participant's endpoint id): only
  that participant hears it. Its audio is added to that participant's mix
  alone, never to the sum. A supervisor coaching an agent.

Every role hears the whole conference.

**Active speaker.** The loudest participant whose voice is detected is
reported with `mixer.speaker`. A speaker stays the active one for at
least 500 ms.

**Participants** may use any codec the relay converts, and may differ
from each other. An endpoint in a mixer is not bridged, and has no
stream. In-band key presses of participants give `dtmf.detected`.

## Events

```json
{"v": 1, "op": "events.subscribe", "types": ["dtmf.detected", "endpoint.destroyed"], "endpoint_ids": ["ep-…"]}
```

`events.subscribe` takes these filters, all optional:
- `types`;
- `endpoint_ids`, `session_ids`;
- `all_parties`: also events about ng parties, which are not endpoints;
  these carry `call_id` and `tag` instead of `endpoint_id`;
- `sensitive`: sensitive digits as they are, not redacted (see
  [IVR](#ivr-keys-tones-detectors-and-sensitive-digits)).

The reply has `subscription_id` and the current `global_seq`. Events then
arrive on the same connection, between replies, until the connection
closes or the client calls `events.unsubscribe` (`subscription_id`). A
subscriber sees only its own tenant's events.

```json
{"event": "dtmf.detected", "endpoint_id": "ep-…", "session_id": "ms-…", "tenant": "default",
 "generation": 1, "revision": 1, "seq": 3, "global_seq": 41, "time_unix_ms": 1795509710000,
 "data": {"digit": "5", "code": 5, "duration_ms": 150, "rtp_timestamp": 320, "source": "rfc4733",
          "start_unix_ms": 1795509709850, "end_unix_ms": 1795509710000}}
```

| Event | `data` |
|---|---|
| `endpoint.ready` | |
| `endpoint.failed` | `reason` (`dtls`, or `media` with a `detail`: a media worker could not take the endpoint's socket) |
| `endpoint.timeout` | |
| `endpoint.destroyed` | `reason`: `request`, `lease`, `timeout`, `ended` (ng deleted it) |
| `endpoint.events_lost` | Some of its media events were lost before the journal: what it awaited is indeterminate |
| `bridge.changed` | `bridged_to` (or `null`), `reason`: `attached`, `detached`, `replaced`, `peer_destroyed` |
| `ice.connected`, `dtls.ready` | |
| `dtmf.detected` | `digit`, `code`, `duration_ms`, `rtp_timestamp`, `source`, `start_unix_ms`, `end_unix_ms`; `sensitive`, or `redacted` with `digit` and `code` `null` |
| `playback.completed` | `playback_id` |
| `playback.stopped` | `playback_id`, `reason` (`request`, `replaced`, `dtmf`, `speech`, `interrupted`, `failed`), `queued` |
| `recording.completed`, `recording.failed` | `file`, `uploaded`, `section`; a recording whose file the worker cannot open fails at once, with `reason: "recording"` and a `detail` |
| `speech.started`, `speech.ended` | (an endpoint with a PCM stream) |
| `stream.mark` | `stream_id`, `mark`, `generation`, `played_ms`, `flushed`, `boundary` (`rtp_sent`) |
| `stream.flushed` | `stream_id`, `generation`, `played_ms` |
| `stream.ended` | `stream_id` |
| `mixer.speaker` | `mixer_id` |
| `gap` | `missed` (and `source: "media"` when the relay's own queue overflowed) |

**DTMF.**
- An RFC 4733 key press is reported once, when it ends. Its repeated end
  packets are deduplicated.
- An event that never gets its end packet is reported up to about a
  second late.
- In-band keys (tones in the audio) are found in the audio a PCM stream
  or a mixer decodes. They are reported with `source: "inband"`, about
  40 ms after the key is released (plus the 40 ms jitter buffer). Keys
  shorter than 40 ms are not seen.

**Delivery.** Events can be replayed from a cursor, at least once, in
order, with every loss said:
- **Identity.** Each event carries `event_id` (`<boot_id>:<global_seq>`),
  `boot_id`, `seq` (counts up per endpoint) and `global_seq` (counts up
  across all events). A jump in the `global_seq` of a filtered
  subscription is not a loss: other events are filtered out.
- **The journal.** The relay keeps the last `[control]
  native_event_journal` events (65,536 by default), in memory: they
  outlive the client's connection, not a restart of the relay.
- **Resuming.** `events.subscribe` with `cursor` (an `event_id`, the
  previous subscription's `cursor`, or a page's watermark) first replays
  what came after it, then goes on live. Its reply says `resumed: true`.
- **What cannot be resumed** is said: a cursor older than the journal
  gets a `gap` with `reason: "retention_expired"`, and one of another run
  of the relay gets `reason: "boot_changed"` (`resumed: false`). The
  client then reconciles with `inventory.list` and `recovery.report`.
  Terminal results (recordings, playbacks) are also in the inventory and
  `recording.query`.
- **A subscriber that falls behind** (its queue holds 1024 events) misses
  events. As soon as it has room, it gets a `gap` with `reason:
  "overflow"`, `missed`, and `resume_cursor`. Subscribing again from
  `resume_cursor` gets the missed events back, possibly some twice:
  deduplicate by `event_id`.
- **A snapshot without a race:** take `inventory.list`, then subscribe
  from its watermark (`<boot_id>:<global_seq>`). Nothing between the two
  is missed.
- **Lost before the journal.** When the relay's own queue of media events
  overflows, the events are lost before they reach the journal:
  - the endpoints known to be affected get `endpoint.events_lost`, and
    their snapshots say `events_indeterminate: true`, since a digit
    collection or an announcement's end may be missing;
  - a `gap` with `reason: "media_overflow"` lists them;
  - the count is in `rtpflux_media_events_dropped_total`.
- **No one waits.** A slow subscriber never holds up the relay: neither
  its media workers nor its control thread wait for it.

## Example: two legs

A softswitch answers an inbound call and bridges it to a leg it places
itself:

1. `endpoint.create` with the caller's offer (`remote_sdp`). The reply's
   `sdp` is the answer for the 200 OK. The caller is parked.
2. `endpoint.create` with `codecs`. The reply's `sdp` is the offer for the
   outbound INVITE.
3. `endpoint.apply_answer` with the callee's answer.
4. `bridge.attach`. The two talk.
5. A re-INVITE from the caller: `endpoint.prepare` with its offer, the
   answer back in the 200 OK, then `endpoint.commit` (or
   `endpoint.abort` if the transaction fails).
6. BYE: `endpoint.destroy` for both.

The [tests](https://github.com/RustedBytes/rtpflux/blob/main/crates/rtpflux/tests/native.rs)
run this, and the rest of the API, against a running relay.
