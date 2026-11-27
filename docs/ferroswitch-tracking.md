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
| 1. Durable operation ledger, fingerprints, `operation.query`, `external_id` | P0 | planned |
| 2. Inventory, boot id, recovery report | P0 | planned |
| 3. Topology revisions, bridge CAS, half-bridge compensation, renegotiation both ways | P0 | planned |
| 4. Replayable critical events with cursors | P0 | planned |
| 5. Async SDK: capabilities, inventory, operations, cursors, recovery | P0 | planned |
| 6. Cross-repository test: ferrosip `sip-ua` + async SDK + rtpflux | P0 | planned |
| 7. Fencing epochs issued by an ownership authority | P0-HA | planned |
| 8. PCM on shared I/O and DSP shards; flush generations | P1 | planned |
| 9. Detectors without a stream, DTMF send, tones, sensitive digits | P1 | planned |
| 10. Recording pause/resume with identity and state; ACLs, quotas, token rotation, audit | P1 | planned |
| 11. Media graph, conference recovery | P2 | planned |
| 12. Benchmarks against the baseline | all | planned |
