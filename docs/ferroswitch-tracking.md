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
| 4. Replayable critical events with cursors | P0 | done |
| 5. Async SDK: capabilities, inventory, operations, cursors, recovery | P0 | done |
| 6. Cross-repository test: ferrosip `sip-ua` + async SDK + rtpflux | P0 | done |
| 7. Fencing epochs issued by an ownership authority | P0-HA | done |
| 8. PCM on shared I/O and DSP shards; flush generations | P1 | done |
| 9. Detectors without a stream, DTMF send, tones, sensitive digits | P1 | done |
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

## Step 4: replayable events

- Every event has `event_id` (`<boot_id>:<global_seq>`) and `boot_id`, and
  goes into a bounded in-memory journal (`[control] native_event_journal`).
- `events.subscribe` takes a `cursor`. It replays what came after, then
  goes live (`resumed: true`). A cursor of another run (`boot_changed`) or
  older than the journal (`retention_expired`) gets an explicit gap. The
  reply's `cursor` and the inventory's watermark are cursors (a snapshot
  and a subscription without a race).
- An overflowing subscriber gets a gap with `resume_cursor` as soon as it
  has room, even when no event follows. Pending gaps are flushed on every
  pass of the control thread.
- Events dropped before the journal (the workers' queue was full) are
  attributed where possible: the endpoints get `endpoint.events_lost` and
  `events_indeterminate: true`, and the gap is `media_overflow`.

Two bugs were found and fixed while testing:
- Destroying an endpoint whose relay offer was never answered deleted
  nothing, leaking its session and ports. Its dialog had no to-tag yet.
- A subscriber's overflow gap was only sent with its next event, so a
  burst followed by quiet left the subscriber unaware.

Evidence (`tests/native.rs`):
- `events_resume_from_a_cursor`: replay in order after a disconnect;
  `boot_changed`; subscribing from a watermark.
- `an_overflowing_subscriber_resumes_without_loss`: 3000 events to a
  subscriber that does not read, resumed from the gaps' cursors, every
  event seen once after deduplication; a cursor older than the journal is
  `retention_expired`.

Residual: the journal is in memory. Events of a run do not survive a
relay restart, which is reported as `boot_changed`, and the terminal
results are reconciled from the saved state. Events are not persisted
across power loss by design.

## Step 5: the async SDK

- Typed `hello` (`Capabilities`, `Guarantees`, keeping unknown fields),
  `inventory` and `inventory_all` (restarting a walk that raced a change),
  `operation` (`OperationState`), `lookup`, `renew`, `recovery_report`;
  `MediaEvent` with `event_id` and `boot_id`; `EventFilter::cursor`; error
  codes `unavailable`, `expired`, `unknown_outcome`.
- Event streams keep a position and resubscribe from it after a broken
  connection, a relay overflow, or the consumer falling behind (they stop
  reading, so memory stays bounded). Repeats are dropped by event number.
  Only unrecoverable losses reach the consumer as gaps.
- Bug found and fixed: events the relay writes while a subscription is
  being made (a replay, a `boot_changed` gap) could come before the
  subscription's reply and were dropped. They are now delivered first.
- Documented: ordering across pooled connections, correlation ids unique
  across reconnects, no automatic retries.

Evidence:
- `rtpflux-client-async/tests/client.rs`: a slow consumer gets every
  event once and in order; after a relay restart, `boot_changed`.
- `tests/typed.rs`: capabilities, operations by key, an external id, a
  lease, the whole inventory and a subscription from its watermark, the
  recovery report.
- `tests/cancel.rs`, against a fake relay:
  - a request cancelled while queued is never written;
  - a cancelled request's late reply is not taken for the next request's;
  - fragmented replies are read;
  - a request in flight when the connection drops is
    `Disconnected { sent: true }`, and the client reconnects with new ids;
  - an unanswered request is `Timeout { sent: true }`, and carries its
    deadline.
- `rtpflux/tests/native.rs` `fragmented_and_oversized_frames`: a request
  written one octet at a time, and a frame over 1 MiB.

## Step 6: cross-repository test

`integration/ferroswitch` is a crate outside the workspace, so the
workspace builds without the private repository. Its pieces:
- `sip-ua` from ferrosip, pinned by `rev` 60b20fc in its Cargo.toml and
  Cargo.lock;
- a B2BUA on simulated SIP engines;
- an in-process rtpflux with a durable ledger, driven through
  `rtpflux-client-async`;
- real RTP between UDP sockets.

The B2BUA creates one endpoint per leg. The relay answers each side's
re-offers itself, and the B2BUA bridges the legs.

The CI job `ferroswitch` checks ferrosip out at the pinned rev using the
`FERROSIP_TOKEN` secret. It runs with `REQUIRE_FERROSIP=1`, and is skipped
without the token.

Evidence (`tests/b2bua.rs`, 4 tests):

| Test | What it covers |
|---|---|
| `early_offer_hold_resume_and_bye` | media both ways; the callee's sendonly/sendrecv re-offers are answered recvonly/sendrecv on the same relay port; media both ways after the resume |
| `delayed_offer_and_bye_from_the_caller` | the relay offers in the 2xx, and the caller's answer arrives in the ACK |
| `a_refused_renegotiation_is_rolled_back` | a PCMA re-offer to the caller is refused; `endpoint.abort` leaves the revision unchanged; media flows |
| `blind_transfer_to_a_third_party` | REFER; the target is bridged to the callee, the referrer's leg is released |

Every test ends with the checks after BYE: each endpoint is destroyed
and reported by event, the inventory is empty, and the recovery report
lists no unknown operations.

Deviation found: the relay does not refuse a re-offer with an unknown
codec, or with no media. It passes them through, as rtpengine does. A
softswitch that must refuse those has to check the SDP itself. Recorded
here; not changed.

Not covered yet: attended transfer (`Replaces`), early media (183), and
UPDATE. These are left for step 11's media graph work, or later.

## Step 7: P0-HA fencing

Design: grants are HMAC-SHA256 signatures from an ownership authority.
The relay keeps the highest epoch per tenant/group, synced to disk. Every
mutation must prove three things: the epoch, a running lease, and the
owner's token, a second signature issued to the owner alone. Each touched
resource must belong to a proven group. See docs/native-api.md
"Exclusive ownership".

Requirement placed on Ferroswitch: one rising epoch sequence per tenant,
across groups. That lets the relay prune old groups safely, through a
per-tenant floor.

Bug found while testing: proofs carried only `{group, epoch}`. A stale
controller could have guessed the next epoch. Proofs now carry the owner
token.

Evidence:
- `control/ownership.rs` unit tests:
  - epochs only rise;
  - same epoch for another owner: conflict;
  - a renewal never shortens the lease;
  - forged signature, unknown key, or another tenant's signature:
    refused;
  - an expired lease is refused;
  - a guessed epoch without the token is refused;
  - claims survive a restart;
  - pruning raises the floor, and an old grant with a running lease
    cannot come back;
  - a corrupt file is an error, and the relay does not start.
- `tests/ha.rs` `fencing_by_authority_epochs`, end to end:
  - with no claim, mutations are refused;
  - a forged grant is refused;
  - another group's proof does not cover an endpoint;
  - after a handoff the stale controller is refused, even with a
    matching generation;
  - a guessed epoch is refused;
  - self-promotion is refused (an old grant, or the same epoch);
  - a bridge across calls needs `peer_ownership` at the current epoch;
  - another tenant cannot use a grant;
  - an `ng` delete on a native call is refused, while `query` works;
  - after a restart the stale controller is still refused and the
    current owner continues;
  - an expired lease fails closed until it is renewed;
  - a replayed expired grant is refused.

Residual gaps:
- The async SDK knows `fenced`, but its typed requests have no
  `ownership` field yet; use `MediaClient::call` in HA mode.
- Mixer and stream membership check only the ids named in a request.
  `mixer.add` names the endpoint, so it is covered; pending worker
  operations are covered by the control-thread ordering argument above.
- Partition is modelled as a stale controller (an old epoch, or no
  token). There is no network-level partition test.

## Step 8: PCM on shared shards; flush generations

- PCM streams no longer have two OS threads each. A few shard threads
  (`[runtime] pcm_shards`; default one per CPU, at most 4) serve every
  stream. A stream stays on one shard, and every 20 ms the shard runs
  each stream once: the DSP towards the service, the service's audio
  towards the worker, marks, and non-blocking writes.
- Buffers are bounded:
  - a 240 ms write buffer per stream (overflow is dropped and counted,
    reported by a gap frame);
  - the worker's 100 ms inject queue (when it is full, the shard stops
    reading that service);
  - at most 8 frames read per stream per tick (fairness).
- The relay workers are untouched apart from flush handling.
- The I/O design was chosen by measurement. `tests/pcm.rs` `load` (100
  streams, both ways, 5 s, release build), share of one core:

  | Engine | Threads | CPU |
  |---|---|---|
  | Baseline: threads per stream | 200 | 12.6%, 11.6% |
  | Shards with an epoll loop on readability | 4 | 18.4% |
  | Shards driven by the 20 ms tick (kept) | 4 | 10.8%, 9.4%, 9.2% |

  The epoll variant lost: its interest changed twice per tick for every
  stream whose service wrote ahead. The baseline also took about 250 s
  to shut down after the load run; the shards stop at once.
- Flush generations, an opt-in protocol version 2 (`stream.start
  protocol: 2`; version 1 services keep working):
  - a flush starts a new generation and is acknowledged with a flush
    frame (the generation, and `played_ms`) and a `stream.flushed`
    event;
  - stale audio and marks are dropped and counted, and a late mark is
    answered as flushed;
  - every injected frame carries the flush count it was made under, and
    the worker drops it if a flush came since. This closes a race in
    which a frame encoded just before a flush was queued just after it.
  - marks carry `generation`, `played_ms` and `boundary: "rtp_sent"`.
    RTP sent is stated explicitly not to be audible playout.
- Bugs fixed on the way:
  - marks pending at a flush could wait forever: the worker drained its
    queue without counting, while mark positions counted every frame.
    The worker now counts frames consumed (played or dropped).
  - a gap frame was written only ahead of the next audio frame, so a
    service that fell behind at the end of speech was never told.

Evidence:
- `tests/pcm.rs` `flush_generations`:
  - the hello says version 2;
  - a flush during a long answer: the old generation stops at once, the
    ack and `stream.flushed` agree on `played_ms`;
  - a mark that waited behind the answer is answered as flushed;
  - late generation-0 TTS plays nothing, and its mark is answered as
    flushed;
  - generation 1 plays, and its mark has `rtp_sent` and its generation;
  - a service flush racing a mark: the mark is flushed and the ack has
    generation 2.
- `tests/pcm.rs` `many_streams_share_two_threads`, 8 streams on 2
  threads:
  - while one service floods the relay, another's mark is answered in
    under a second;
  - the services that read get their audio;
  - a service that does not read gets a gap frame;
  - a service that disconnects ends its stream, and a new stream on the
    same endpoint works;
  - there are still 2 threads.
- The existing `audio_streams_to_and_from_a_service` passes unchanged.
- `frame.rs` unit tests: version 2 round trips, and version 1 never
  carries a generation.

Residual gaps:
- A shard serves its streams in turn within the tick; a stream's DSP is
  not split further.
- Mixers keep their own thread per mixer (not per participant).
- A hung service cannot block a shard: every read and write is
  non-blocking. Only the hello is written blocking, at `stream.start`,
  with a 100 ms timeout.

## Step 9: detectors, DTMF send, tones, playback queues, sensitive digits

- `control/ivr.rs` composes what the relay already had:
  - the worker's tone engine (RFC 4733 events or in-band tones; a sine
    code for cadenced tones);
  - file and blob playback;
  - recording pause;
  - the PCM shards' VAD and in-band DTMF.
- New operations:
  - `dtmf.send`, `tone.start`, `tone.stop`;
  - `dtmf.policy` (`dedup` by default, `both`, `rfc4733`, `inband`);
  - `endpoint.sensitive`;
  - `stream.detect`, with `stream.start` taking no `socket` for
    detectors only (no `pcm_dir` needed).
- `playback.start` gains `queue` and `stop_on` (`dtmf`, `speech`).
  Interruption happens in the relay; digit collection and timeouts stay
  with the controller.
- Sensitive digits. Every output path, and what covers it:

  | Path | Coverage |
  |---|---|
  | Logs | The worker logged every key at `info`; it now logs that a key was pressed, at `debug`, without the digit, sensitive or not |
  | Events | Subscribers without `sensitive: true` get `digit`/`code` `null` and `redacted: true`, live and on cursor replay |
  | Recordings | Paused while sensitive, resumed after (only those it paused) |
  | Bridged peer | Not covered (documented; `ng` `block DTMF` exists) |
  | PCM service | Not covered: it hears the tones as audio (documented) |
  | Event journal | In memory only; holds the digit for entitled subscribers |
- Bug fixed: RFC 4733 keys from an endpoint not bridged to anyone (an IVR
  leg) were never reported, because the worker skipped every dropped
  packet. It now observes authentic packets dropped only for lack of a
  destination, and still ignores unknown legs and wrong sources.

Evidence (`tests/ivr.rs`):
- `keys_and_tones_to_an_endpoint`:
  - events with telephone-event, tones with `inband`;
  - digits are not echoed;
  - bad digits are refused;
  - a cadenced tone plays and `tone.stop` silences it.
- `detectors_policies_and_sensitive_digits`:
  - a detector with no service or `pcm_dir`, VAD off: no speech events;
  - one press, sent both in-band and as events, is reported once under
    `dedup`, twice under `both`, once (`rfc4733`) under `rfc4733`;
  - sensitive mode with a recording running: the recording pauses, the
    trusted subscriber sees the digit, the plain one sees it redacted,
    a cursor replay is redacted, and turning it off resumes;
  - `stream.detect` turns VAD on and speech is detected.
- `playback_queues_and_barge_in`:
  - a queued playback starts after the first completes;
  - a key stops a `stop_on: ["dtmf"]` playback and drops the queue
    behind it.

Residual gaps:
- The test checks a recording's pause through the operation's reply and
  the relay's recording state, not by inspecting the pcap. A
  worker-confirmed pause boundary is step 10.
- Tones and `dtmf.send` have no completion event; their reply gives the
  duration.

## Step 10a: recording pause/resume with a confirmed boundary

- `recording.pause` and `recording.resume` (`control/rec.rs`). The
  recording is `paused` only after a barrier confirms the media workers
  took the pause; the boundary time is recorded in `pauses`. Unconfirmed,
  the recording is `pausing` and the request fails (`timeout`). It is
  never reported paused while capture may go on.
- `endpoint.sensitive` now pauses through the same confirmed path.
- `recording.query` reports outcomes apart: `finalized` (the file is
  written), `upload` (`pending`, `none`, `uploaded`, `failed`), and
  `failed` with its detail.
- Identity: a recording keeps its `recording_id` across pause, resume and
  a restart. A keyed `recording.start` lists it in the operation's
  resources.

Evidence: `tests/recpause.rs` `pauses_are_confirmed_and_hold_nothing`:
- pausing with no recording is refused;
- a pause is confirmed with its boundary; pausing again changes nothing;
- resume;
- a second pause spans a restart of the relay, and the recording is still
  `paused` after it;
- resume, then stop: `completed`, `finalized`, `upload: none`, two
  pauses;
- the finished pcap is parsed: no packet inside either pause window,
  and audio before, between and after them.

The existing `a_worker_failure_is_reported` covers a recording whose file
cannot be written (`recording.failed`).

Deviations and gaps found:
- **Only relayed media is recorded.** An endpoint bridged to no one (an
  IVR leg talking to prompts) records nothing; the test had to bridge
  it. Recording an IVR leg needs the recorder to also take dropped
  authentic packets and injected audio. Recorded, not changed.
- A failed upload is mapped (`upload: failed`) and covered by the store's
  own tests, but there is no end-to-end test: S3 needs the `s3` feature
  and credentials.
- Disk full mid-recording is not simulated; an unwritable directory is.
