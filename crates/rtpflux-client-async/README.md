# rtpflux-client-async

An async (Tokio) client of rtpflux's [native control API](../../docs/native-api.md),
for a softswitch's call control. It links nothing of the relay: `tokio`,
`serde`, `serde_json` and `log`.

```rust
use rtpflux_client_async::{
    AttachBridgeRequest, Config, CreateEndpointRequest, DestroyEndpointRequest,
    EventFilter, MediaClient,
};

let media = MediaClient::connect(Config::unix("/run/rtpflux/native.sock")).await?;
let mut events = media.subscribe_events(EventFilter::default()).await?;

let mut inbound = CreateEndpointRequest::answering(offer_sdp);
inbound.idempotency_key = Some(format!("{call_uuid}/a"));
let a = media.create_endpoint(inbound).await?;          // a.sdp: the answer
let b = media.create_endpoint(CreateEndpointRequest::offering(["PCMU", "opus"])).await?;
// … INVITE with b.sdp, apply_answer with the 200 OK's SDP, then:
media.attach_bridge(AttachBridgeRequest::new(&a.endpoint_id, &b.endpoint_id)).await?;
media.destroy_endpoint(DestroyEndpointRequest::new(&a.endpoint_id)).await?;
```

Over TCP: `Config::tcp("10.0.0.5:2224", token)`.

## Semantics

- **Typed.** Requests and replies are structs (`CreateEndpointRequest`,
  `Endpoint`, `AttachBridgeRequest`, `BridgeResult`, …). Errors are a
  `MediaError`: `Refused` (with the relay's `ErrorCode`), `Timeout`,
  `Disconnected`, `Overloaded`, `Protocol` or `Closed`. `call(op, fields,
  deadline)` reaches any other operation.
- **A pool of connections.** Requests are spread over
  `Config::connections` connections. Each is owned by a task, pipelines
  its requests, and matches each reply by `operation_id`.
- **Bounded.**
  - Each connection has a bounded queue (`queue_per_connection`) and a
    bound on the requests written and not answered
    (`in_flight_per_connection`).
  - When every queue is full, a request fails at once with `Overloaded`.
  - The event stream's queue is bounded too (`event_queue`).
- **Deadlines.** Every request has one: its own `deadline`, or
  `Config::default_deadline`. It is sent too (`deadline_unix_ms`), so the
  relay does not run a request that reaches it late. Past it, the
  request fails with `Timeout { sent }`.
- **Cancellation.** Dropping a request's future cancels it, and the
  connection stays usable:
  - a request not written yet is never sent;
  - a request already written may still run on the relay;
  - `MediaError::outcome_unknown()` says when a failed request may have
    taken effect. Retry it with the same `idempotency_key` (the relay
    returns the first attempt's outcome), or reconcile with
    `query_endpoint` and `list_endpoints`.
- **Reconnect.**
  - A broken connection is made again with exponential backoff
    (`backoff_min` to `backoff_max`), and authenticated again over TCP.
  - Requests it had written fail with `Disconnected { sent: true }`.
  - Requests still queued wait for the new connection, within their
    deadlines.
- **Events on a connection of their own.**
  - A burst of events never delays a reply.
  - The stream keeps its position (the last event's `event_id`). After a
    broken connection, a relay-side overflow, or its own consumer falling
    behind (it stops reading until there is room), it subscribes again
    from there. The relay replays from its journal, so each event arrives
    once and in order, and memory stays bounded.
  - Only what the relay cannot replay reaches the consumer as a `Gap`:
    `boot_changed` (the relay restarted), `retention_expired`, or
    `media_overflow`. Reconcile with `inventory_all` and
    `recovery_report`.
- **Reconciliation.** `hello` (typed capabilities and guarantees),
  `inventory` / `inventory_all` (a consistent snapshot and a watermark to
  subscribe from), `operation` (an operation key's state), `lookup` (by
  external id), `renew`, `recovery_report`, `playback` (where a
  playback is, or how it ended: for an end missed while reconnecting).
- **Sensitive digits.** `EventFilter { sensitive: true, .. }` asks for
  the digits of endpoints marked sensitive as they are, for the
  controller collecting them; other subscriptions get them redacted.
- **Ordering.** Requests on different pooled connections may run in any
  order; wait for a reply before sending a request that depends on it.
  Operation ids stay unique across reconnects, and the client never
  retries on its own.

The blocking client, `rtpflux-client`, is for tools and prototypes. Its
requests wait at most `DEFAULT_REQUEST_TIMEOUT` (10 s; `set_request_timeout`
changes it), after which its connection is retired.
