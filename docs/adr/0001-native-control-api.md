# ADR 0001: a native control API beside ng

- **Status:** accepted, implemented (see the notes at the end)
- **Date:** 2026-11-27
- **Context:** [Media engine: audit and gaps](../media-engine.md)

## Context

A B2BUA or softswitch (ferrosip, and the softswitch that will use it)
drives media differently from a SIP proxy. It names endpoints, not
Call-IDs and tags. It must know whether a change was applied, not just
queued. It needs events (DTMF, the end of an announcement, a recording
finished) and has to reconcile its state with the relay's after it
reconnects. The ng protocol has none of this. Its requests are
fire-and-forget per UDP datagram, identified by SIP identity, and
idempotent only through a 30-second reply cache keyed by cookie.

ng must keep working unchanged: Kamailio, OpenSIPS and ferrosip's `media`
module rely on its wire format, warnings and behaviour.

The audit found that the control thread has no transport-independent
command layer. Handlers read bencode dictionaries directly, and composite
commands re-encode bencode to call `offer` and `answer`.

## Decision

1. **One command model, two adapters.** Each command becomes a typed
   request parsed once, with semantics in handlers that take the typed
   request. The ng adapter maps dictionaries to these requests, and must
   reproduce today's replies and warnings exactly (the ng test suite is
   the check). The native adapter maps native messages to the same
   requests where the semantics match. Native-only semantics (generations,
   revisions, prepare/commit) live in the command layer, not in the
   adapter.
2. **Transport.**
   - Version 1 runs over a **Unix stream socket**
     (`[control] native_socket`, mode 0600, owned by the relay's user).
     Peer credentials (`SO_PEERCRED`) decide who may connect.
   - A network listener (`[control] native_listen`) comes later. It will
     require an authentication token per tenant and is meant to sit
     behind TLS, as the ng HTTP endpoint already does.
   - No gRPC: it would add a large dependency tree, and an async runtime,
     to a daemon that has neither.
   - The control thread owns the socket. Media workers never see it.
3. **Framing and encoding.**
   - Each message is a 4-byte big-endian length followed by a JSON
     object, at most 1 MiB.
   - `serde_json` is already a dependency. The control path is not the
     packet path, and JSON keeps fixtures readable for the softswitch's
     tests.
   - A message carries `"v": 1`. A connection starts with `hello`, which
     returns the protocol versions and the capabilities the relay offers
     (codecs, SRTP, DTLS, ICE, `pcm`, `mixer`, and so on).
4. **Requests.** Each request has:
   - `op`, for example `endpoint.create` or `bridge.attach`;
   - `operation_id`, chosen by the client and echoed in the reply and in
     every event the operation causes;
   - optionally `idempotency_key`, `endpoint_id`, `expected_generation`,
     `deadline_ms` and `tenant`.

   A request whose `idempotency_key` was seen within the retention period
   (5 minutes by default, bounded in number) gets the stored outcome and
   runs nothing. A request past its deadline is refused with `timeout`,
   and is not run.
5. **Replies.** A reply carries `ok` with the result, or `error` with:
   - a `code`, one of `not_found`, `conflict`, `unsupported`, `exhausted`,
     `timeout`, `unauthorized`, `invalid` or `internal`;
   - a human-readable `message`.

   "Accepted" and "completed" are distinct. A reply comes once the change
   is applied in the control state and acknowledged by the workers it
   touches. Long operations (playback, recording) reply when started and
   finish with an event.
6. **Identity.**
   - `MediaSessionId` and `MediaEndpointId` are opaque strings the relay
     makes up: 128 random bits, base32. They are not SIP identifiers, and
     the relay never infers SIP identity from them.
   - Each endpoint has a `generation` that a re-creation under the same
     client-supplied key raises. A deleted endpoint leaves a tombstone for
     the retention period, so a delayed command fails with `conflict` or
     `not_found` rather than resurrecting it.
   - An endpoint made through the native API is also a party of an
     internal call, so ng commands such as `query` keep working on it.
7. **Events.**
   - `events.subscribe` sets a filter by endpoint, session or event type.
     Events then arrive on the same connection as `{"event": …}` messages.
   - Each event carries the endpoint id, generation, operation id where
     there is one, a sequence number per endpoint and a timestamp.
   - Workers write events to a bounded ring per worker. When a ring is
     full, the next event delivered carries `gap: true`. A subscriber that
     falls behind is cut off with a final `gap` event, never waited on.
   - After a gap or a reconnect, the client calls `endpoint.list` or
     `endpoint.query` to resynchronise. Delivery is at most once, with
     gaps that can be detected.
8. **Disconnect policy.** A client disconnecting destroys nothing by
   default. `endpoint.create` may set a lease (`lease_ms`): an endpoint
   whose lease is not renewed is destroyed, with an `endpoint.destroyed`
   event whose reason is `lease`.

## Operations in version 1

| Operation | Built on |
|---|---|
| `endpoint.create` (offer) | `create` |
| `endpoint.create` (answer to `remote_sdp`) | `create from offer` |
| `endpoint.apply_answer` | `create answer` |
| `endpoint.prepare` / `commit` / `abort` | re-offer with a checkpoint (`track-state`), `rollback` |
| `endpoint.destroy` | `delete` of the party, idempotent |
| `endpoint.query` / `list` | `query`, `list` |
| `bridge.attach` / `detach` / `replace` | `connect`, made transactional |
| `playback.start` / `stop` | `play media`, `stop media`, plus a completion event |
| `recording.start` / `stop` | `start recording`, `stop recording`, plus file and upload events |
| `stream.start` / `flush` / `stop` | new: PCM streams to external services |
| `mixer.create` / `add` / `remove` / `set` / `destroy` | new: N − 1 conference mixing |
| `events.subscribe` / `unsubscribe` | new |

## Consequences

- The command-layer refactor comes first. It changes no behaviour, and the
  ng tests show that.
- A Rust client crate (`rtpflux-client`) and JSON fixtures are published
  for the softswitch. They depend on no daemon internals.
- Contract changes are agreed with ferrosip's maintainers before they are
  implemented.
- The packet path is unaffected: commands reach workers through the
  existing bounded queues. Events leave through bounded rings and are
  counted when dropped.

## Implementation notes

The reference is [Native control API](../native-api.md). The
implementation departs from the decisions above in these ways:

- **Command model (decision 1).**
  - What exists: native operations build the requests of the ng commands
    they correspond to, and run them on the same handlers. One model,
    with no second copy of any semantics.
  - What is left: the typed-request refactor of the handlers, which would
    let both adapters skip bencode on the control path. It is a cost
    there, never on the packet path.
- **Completion (decision 5).**
  - What exists: a reply comes once the change is applied in the control
    thread and queued to the media workers. Each worker applies its queue
    in order.
  - Operations that change routing (bridges, streams, mixer membership)
    then wait for a barrier from each worker concerned, so they reply
    once the change is in effect, or with `timeout`.
  - What is left: failures inside a worker are logged, as before, but not
    reported back.
- **Identity (decision 6).** Endpoint ids are the parties' ng tags, and
  session ids the ng call-ids, so ng commands such as `query` still see
  the endpoints. Generations are global and increase across restarts.
- **Events (decision 7).** Workers write to one bounded queue shared by
  all workers (`relay/media_events.rs`), not one ring per worker.
  Overflow is counted, and reported as a `gap`.
- **Network listener.** Built as `native_listen`: a connection's first
  request authenticates with a tenant's token (`auth`), and the
  connection is then that tenant's. TLS is left to a proxy, as for ng's
  HTTP endpoint.
