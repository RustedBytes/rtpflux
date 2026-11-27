# Ferroswitch integration: tracking

Work on the *Ferroswitch integration and reliability* specification (a
delta on the media engine): what the checkout had, what each step adds,
the evidence, and what is left. Updated with every step.

## Baseline

- **rtpflux:** `cac94112d993ae1e61614b0c4bbb8e416d45059c` (0.2.0, native API
  v1 and `rtpflux-client-async`). It matches the specification's baseline.
- **ferrosip:** `60b20fc2ee38eba830705ee2e257f6da7b9eaf4a` (0.2.0, with
  `sip-ua`). Cross-repository tests pin this revision.

### What the baseline had

| Area | State at the baseline |
|---|---|
| Endpoints | Created both ways, parked, bridged across workers, renegotiated with prepare/commit/abort, destroyed with 5-minute in-memory tombstones; leases; tenants; generations and revisions |
| Idempotency | An in-memory reply cache keyed by (tenant, `idempotency_key`), 5 minutes. A reused key with a different request got the cached reply: no conflict |
| Recovery | Endpoints and their media saved with the dialogs (state file, at most once a second, or Redis): a crash loses up to a second. Streams, mixers, playback and recordings of endpoints are not tracked across a restart, and nothing reports what was lost |
| Events | Bounded, non-blocking, at most once, with gaps; no replay, no cursor, no boot id |
| Worker confirmation | Barrier after bridge, stream and mixer changes; no topology revision |
| Async SDK | Typed create/apply/attach/detach/destroy/prepare/commit/abort/query/list, pool, deadlines, cancellation, reconnect, events with gaps |
| HA | None |
| PCM | Two OS threads per stream; one thread per mixer |

### Test evidence at the baseline

- `cargo test --workspace`: 581 passed, 0 failed.
- ferrosip at `60b20fc` against the baseline's release binary: `cargo test
  -p sip-ua --test b2bua_rtpflux` passed (ng protocol); `tests/e2e_rtpflux.py`
  35/35; `tests/e2e_scenarios.py --only m15-media-relay` 36/36.

### Deviations from the specification's picture

- `sip-ua` drives rtpflux over ng only; there was no native-API adapter.
- The specification's "five-minute in-memory response cache" is exact; it
  also did not detect a reused key with a different request.

## Plan and status

| Step | Priority | Status |
|---|---|---|
| 1. Durable operation ledger, fingerprints, `operation.query`, `external_id` | P0 | done |
| 2. Inventory, boot id, recovery report | P0 | done |
| 3. Topology revisions, bridge CAS, half-bridge compensation, renegotiation both ways | P0 | done |
| 4. Replayable critical events with cursors | P0 | planned |
| 5. Async SDK: capabilities, inventory, operations, cursors, recovery | P0 | planned |
| 6. Cross-repository test: ferrosip `sip-ua` + async SDK + rtpflux | P0 | planned |
| 7. Fencing epochs issued by an ownership authority | P0-HA | planned |
| 8. PCM on shared I/O and DSP shards; flush generations | P1 | planned |
| 9. Detectors without a stream, DTMF send, tones, sensitive digits | P1 | planned |
| 10. Recording pause/resume with identity and state; ACLs, quotas, token rotation, audit | P1 | planned |
| 11. Media graph, conference recovery | P2 | planned |
| 12. Benchmarks against the baseline | all | planned |

## Step 1: operation ledger and external ids

- `control/ledger.rs`: fingerprints (SHA-256 of the canonical intent), the
  ledger in memory or durable (append-only, synced; torn last line
  skipped; `pending` without an outcome becomes `unknown` at start;
  compaction by rewrite; mode 0600), retention, per-tenant quota without
  early eviction.
- Native requests: envelope checks first (never recorded); a keyed
  mutation runs pending → apply → synced state (`save_durable`) → synced
  outcome → reply; same key and another intent is `conflict`; an old
  first attempt is `expired`; `unknown_outcome` after a crash.
  `operation.query`. New error codes `unavailable`, `expired`,
  `unknown_outcome`, and `detail` on errors. `hello` states the
  guarantees.
- `external_id` on `endpoint.create`, unique per tenant, kept with the
  tombstones (never evicted early); `replaces_generation` for a new
  endpoint under a destroyed one's id; `endpoint.lookup`. Tombstones and
  id counters are saved with the state.
- Feature `fault-injection` (tests only): `RTPFLUX_FAULT` kills the relay
  (SIGKILL) at a boundary.

Evidence: `cargo test -p rtpflux --features fault-injection --test crash`
(CI runs it in the `all-features` test job); `cargo test --workspace`: 584
passed.
- A SIGKILL at `after_pending`, `after_apply`, `after_state` and
  `after_outcome`, then a retry and reconciliation, leaves one endpoint
  per external id; the outcome is either replayed or reported
  `unknown_outcome`.
- Durable keys and external ids work across a clean restart.

Unit tests in `ledger.rs` cover fingerprints, a torn last line,
`pending` turning `unknown` on restart, expiry and the quota.

Residual: mixers, streams, playback and recordings are deduplicated by
operation keys, but have no external id of their own (step 2 reports
those that a restart loses). A ledger costs two `fsync`s and a state-file
write per keyed mutation; this is measured in step 12.

## Step 2: inventory and recovery report

- `control/inventory.rs`: `inventory.list` (six kinds, id order, pages of
  at most 500, a cursor bound to the run and `topology_epoch`, a conflict
  when anything changed between pages, a watermark on every page);
  `recovery.report`; `recording.query`.
- A boot id per run (in `hello`), and the previous one after a restart.
- `topology_epoch` changes with every mutation, endpoint end, recording
  end.
- Recordings have ids and a state (`active`, `stopped`, `completed`,
  `failed`), updated from the media events, saved with the state.
- Saved with the state: the streams, mixers, recordings and each
  endpoint's playback and recording. After a restart, streams and mixers
  are reported lost, and so is a playback the relay did not restore
  (one from a blob).

Evidence: `tests/native.rs` `inventory_and_recovery_report`. It pages
through five endpoints, refuses a stale cursor, lists the bridges, the
recordings and the mixers, then restarts. Afterwards `previous_boot_id`
matches, six endpoints are restored, the mixer is reported lost, the
recording is still active, and the bridge is intact.

Residual: leases start again at a restart (documented). The epoch is
coarse: any mutation invalidates a paged walk.

## Step 3: topology and renegotiation

- **Created parties in either orientation.** `create`, `create answer`
  and `create from offer` find a created party's dialog whoever offered
  last (`created_dialog`), so the relay can re-offer to an endpoint that
  offered first, and an endpoint the relay offered to can re-offer.
- **Prepare in both directions, by what it is given.**
  - `remote_sdp` is answered at once, and its checkpoint is kept by an
    internal flag until the commit.
  - The relay's re-offer is committed by its answer.
  - Abort is an exact `rollback` (it fails visibly if nothing was taken
    back), and the endpoint is bridged again as it was.
- **`topology_revision` per endpoint.** CAS on both endpoints of an
  attach (topology revision, and the peer's generation and revision), and
  `expected_topology_revision` on any request that names an endpoint.
- **A failed attach is compensated:** every endpoint involved, the former
  peers included, is detached on the workers and in the records. A worker
  that does not confirm leaves `topology_state: "unconfirmed"`.
- **Fault injection:** `connect_half` refuses a cross-worker bridge's
  second end after the first was taken.

Evidence:
- `tests/native.rs` `renegotiation_both_ways_and_topology_cas`. The IVR
  leg's own hold re-offer is aborted, then committed; the caller's leg
  gets the relay's re-offer, aborted, then committed. Media flows after
  each step, and a stale topology revision is a conflict.
- `tests/crash.rs` `a_half_made_bridge_is_compensated`. It fails when the
  compensation is removed (mutation check): the former peer is then
  still reported bridged while its media is not.

Residual: worker acknowledgements are synchronous barriers on the control
thread (at most a second), so a late acknowledgement cannot overwrite a
newer intent. Early media and delayed SDP are the existing endpoint
flows, exercised end to end in step 6.
