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
| `idempotency_key` | Optional. A request with a key seen in the last 5 minutes (per tenant) gets the earlier outcome, marked `replayed: true`, and nothing runs again |
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
| `endpoint.create` | `remote_sdp` (the remote side's offer, which the relay answers), or `codecs` (the relay offers these: `PCMU`, `PCMA`, `G722`, `G729`, `opus`, `AMR`, `AMR-WB`, `telephone-event`, `CN`); `session_id`, `label`, `lease_ms`, `options` | `endpoint_id`, `session_id`, `generation`, `revision`, `state`, `sdp_type` (`answer` or `offer`), `sdp`, `warnings` |
| `endpoint.apply_answer` | `endpoint_id`, `sdp`, `options` | `revision`, `state` |
| `endpoint.prepare` | `endpoint_id`; for a remote-offer endpoint `remote_sdp` (its re-INVITE); for a local one `codecs`, `options` | `pending_revision`, `sdp_type`, `sdp` |
| `endpoint.commit` | `endpoint_id`, `revision`; for a local endpoint `sdp` (the answer) | `revision` |
| `endpoint.abort` | `endpoint_id`, `revision` | `revision` (the committed one) |
| `endpoint.destroy` | `endpoint_id` | `destroyed`, or `already: true` |
| `endpoint.query` | `endpoint_id` | The endpoint's snapshot, and `media` (its streams, statistics, RTCP, DTMF, as ng `query` reports them) |
| `endpoint.list` | | `endpoints` (snapshots), `destroyed` (recent tombstones), `global_seq` |
| `endpoint.renew` | `endpoint_id`, `lease_ms` (optional) | `lease_ms` |

`options` are ng options for the operation (see
[Options](control-protocol.md#options)), as JSON:
`{"flags": ["trust-address"], "ICE": "remove", "transport-protocol": "RTP/SAVP", "SDES": ["no-AES_CM_128_HMAC_SHA1_32"]}`.
Strings, integers, lists and objects map to their bencode forms, and
`true`/`false` become `yes`/`no`. Keys the operation sets itself are
refused: `call-id`, `from-tag`, `to-tag`, `sdp`, `label`.

**Renegotiation.**
- `endpoint.prepare` leaves the committed media in place until
  `endpoint.commit`.
- `endpoint.abort` puts the committed media back: the same ports, keys
  and bridge.
- For a local endpoint, the relay's new offer is taken back with
  [`rollback`](control-protocol.md#rollback).
- For a remote endpoint, its earlier offer is applied again.
- A renegotiation that does not change the media keeps the ports, the
  keys and the bridge.

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

## Bridges

| Operation | Fields | Result |
|---|---|---|
| `bridge.attach` | `endpoint_id`, `peer_endpoint_id`, `peer_expected_generation` (optional) | `bridged_to`, `replaced` (the former peers, now alone) |
| `bridge.detach` | `endpoint_id` | `detached`, `was_bridged_to` |

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
| `playback.start` | `endpoint_id`, `file` or `blob_base64`, `repeat_times`, `start_pos`, `duration`, `repeat_duration` | `playback_id`, `duration_ms` |
| `playback.stop` | `endpoint_id` | `stopped`, `playback_id` |
| `recording.start`, `recording.stop` | `endpoint_id`, `options` (`format`, `channels`, …) | `recording` |

- An announcement that plays to its end gives `playback.completed`, with
  the `operation_id` of its `playback.start`. One that is stopped, or
  replaced by another, gives `playback.stopped` with the reason.
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
| `stream.start` | `endpoint_id`, `socket` (a file name in `pcm_dir`), `rate` (8000, 16000, 24000 or 48000; default 16000), `inject` (default `true`) | `stream_id`, `rate`, `inject` |
| `stream.flush` | `stream_id` | `flushed`: the audio queued for the endpoint is dropped (barge-in) |
| `stream.stop` | `stream_id` | `stopped` |

**Frames.** Each frame on the socket is a 32-octet header followed by its
payload. Integers and samples are little-endian.

| Octets | Field |
|---|---|
| 0–3 | `RFPC` |
| 4 | version, 1 |
| 5 | kind: 1 hello, 2 audio, 3 mark, 4 flush, 5 gap |
| 6–7 | flags: bit 0, a discontinuity (after a gap or a flush) |
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
`source: "inband"`. A service that reads too slowly misses frames; each
write waits at most 100 ms. The next frame it gets is marked as a
discontinuity, preceded by a gap frame giving the count.

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
  This is barge-in.
- **Marks:** a mark (kind 3, its id in the sequence field) is answered
  with `stream.mark` once the audio sent before it has been played to
  the endpoint, that is, sent in RTP. The relay knows what it sent, not
  what the remote side has played out.
- **End:** the stream ends with `stream.ended` when the service closes
  the socket, or with `stream.stop`.

The relay's media workers only copy packets for a stream and play the
frames it sends back. The signal processing runs on the stream's own two
threads.

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
  these carry `call_id` and `tag` instead of `endpoint_id`.

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
| `bridge.changed` | `bridged_to` (or `null`), `reason`: `attached`, `detached`, `replaced`, `peer_destroyed` |
| `ice.connected`, `dtls.ready` | |
| `dtmf.detected` | `digit`, `code`, `duration_ms`, `rtp_timestamp`, `source`, `start_unix_ms`, `end_unix_ms` |
| `playback.completed` | `playback_id` |
| `playback.stopped` | `playback_id`, `reason` (`request`, `replaced`) |
| `recording.completed`, `recording.failed` | `file`, `uploaded`, `section`; a recording whose file the worker cannot open fails at once, with `reason: "recording"` and a `detail` |
| `speech.started`, `speech.ended` | (an endpoint with a PCM stream) |
| `stream.mark` | `stream_id`, `mark` |
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

**Delivery.** Events are delivered at most once, in order, with
detectable gaps:
- Each event carries `seq`, which counts up per endpoint, and
  `global_seq`, which counts up across all events.
- A subscriber whose queue (1024 events) is full misses events. When it
  has room again it gets a `gap` event first.
- When the relay's own queue of media events overflows, a `gap` event
  with `source: "media"` says so.
- After a gap, the client calls `endpoint.list` and `endpoint.query`.
- A slow subscriber never holds up the relay: neither its media workers
  nor its control thread wait for it.

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
