# Operations

Running rtpflux in production: monitoring, logs, restarts and the
systemd service.

## Command line

```text
rtpflux [OPTIONS]

  -c, --config <PATH>         Configuration file [default: /etc/rtpflux/rtpflux.toml]
  -l, --log-level <LEVEL>     error, warn, info, debug or trace
      --check                 Validate the configuration and exit
      --print-example-config  Print the documented example configuration and exit
      --webui-hash            Read a password on standard input and print its
                              [webui] password_hash value
  -h, --help                  Print help
  -V, --version               Print version
```

`SIGTERM` or `SIGINT` (Ctrl-C) stops the relay cleanly; with a state file
or Redis, calls are saved first.

## Metrics

Enable the Prometheus endpoint:

```toml
[metrics]
listen = ["127.0.0.1:9101"]
```

and scrape `http://127.0.0.1:9101/metrics`:

```text
# HELP rtpflux_packets_forwarded_total Packets relayed by the userspace workers.
# TYPE rtpflux_packets_forwarded_total counter
rtpflux_packets_forwarded_total 0
...
rtpflux_ng_requests_total{command="offer"} 2
rtpflux_ng_requests_total{command="answer"} 1
```

| Metric | Type | Meaning |
|---|---|---|
| `rtpflux_packets_forwarded_total` | counter | Packets relayed by userspace (the XDP fast path's are in `query`, not here) |
| `rtpflux_packets_dropped_total` | counter | Packets dropped: no call on the port, wrong source, no destination yet, or malformed |
| `rtpflux_send_errors_total` | counter | Packets the kernel refused to send |
| `rtpflux_srtp_rejected_total` | counter | SRTP/SRTCP packets that failed authentication or replay checks, or arrived before keys existed |
| `rtpflux_zrtp_forwarded_total` | counter | ZRTP packets relayed untouched between endpoints (also counted as forwarded) |
| `rtpflux_calls_timed_out_total` | counter | Calls ended because media stopped |
| `rtpflux_ice_checks_total` | counter | ICE connectivity checks and consent requests the relay sent |
| `rtpflux_ice_nominations_total` | counter | Candidate pairs the relay nominated, or accepted as nominated |
| `rtpflux_ice_role_conflicts_total` | counter | ICE role conflicts resolved (both sides claimed the same role) |
| `rtpflux_ice_consent_lost_total` | counter | Pairs whose consent expired (RFC 7675): the relay stopped sending to them |
| `rtpflux_ice_restarts_total` | counter | ICE restarts |
| `rtpflux_bytes_forwarded_total` | counter | Octets (UDP payloads) relayed by userspace |
| `rtpflux_kernel_packets_total`, `rtpflux_kernel_bytes_total` | counter | Packets and octets the XDP fast path relayed in the kernel, as of the relay's last poll (once a second) |
| `rtpflux_dtls_handshakes_total` | counter | DTLS-SRTP handshakes that keyed SRTP |
| `rtpflux_dtls_failures_total` | counter | DTLS-SRTP associations that failed (a wrong certificate, a broken handshake) |
| `rtpflux_offloaded_calls` | gauge | Relay calls the XDP fast path relays now |
| `rtpflux_connections` | gauge | Parties joined with `connect` (transfers) |
| `rtpflux_copies` | gauge | Copies of a party's media to another (directional `connect`, `inject`, `mesh`) |
| `rtpflux_subscriptions` | gauge | Media subscriptions (SIPREC and others) |
| `rtpflux_delayed_deletes` | gauge | Deletes waiting for their `delete-delay` |
| `rtpflux_state_writes_total`, `rtpflux_state_write_failures_total` | counter | State file writes, and the ones that failed |
| `rtpflux_redis_writes_total`, `rtpflux_redis_failures_total` | counter | Snapshots written to Redis, and failed attempts |
| `rtpflux_redis_failing` | gauge | 1 while writing to Redis fails |
| `rtpflux_sessions` | gauge | Dialogs with relayed media |
| `rtpflux_calls` | gauge | Relayed media sections (a dialog with audio and video counts 2) |
| `rtpflux_workers` | gauge | Media worker threads |
| `rtpflux_ng_requests_total{command=…}` | counter | ng requests by command (`other` for unknown commands) |
| `rtpflux_ng_errors_total` | counter | ng requests answered with an error |
| `rtpflux_ng_retransmissions_total` | counter | Repeated ng requests answered from the reply cache |
| `rtpflux_recordings_converted_total` | counter | Recordings converted when they ended (or kept as pcap) |
| `rtpflux_recording_conversions_failed_total` | counter | Recording conversions that failed (the pcap is kept) |
| `rtpflux_recording_uploads_total` | counter | Recording files uploaded to S3 |
| `rtpflux_recording_upload_failures_total` | counter | Recording files not uploaded after every attempt (kept locally) |
| `rtpflux_recording_webhooks_delivered_total` | counter | Upload notifications the webhook answered with 2xx |
| `rtpflux_recording_webhooks_failed_total` | counter | Upload notifications given up on, or refused with a final status |
| `rtpflux_recording_webhooks_dropped_total` | counter | Upload notifications dropped unsent (queue full, or the relay stopping) |

**Worth alerting on:**

- A rising `rtpflux_srtp_rejected_total`: key mismatches, or someone
  sending forged packets.
- A rising `rtpflux_send_errors_total`: network or socket buffer problems.
- `rtpflux_redis_failing` at 1, or a rising
  `rtpflux_state_write_failures_total`: calls would not survive a restart.
- A rising `rtpflux_dtls_failures_total`: browsers whose certificates do
  not match their SDP, or networks breaking the handshake.
- A rising `rtpflux_recording_upload_failures_total` or
  `rtpflux_recording_webhooks_failed_total`: recordings piling up locally,
  or a receiver not hearing about them.
- `rtpflux_ng_errors_total` growing faster than usual: the proxy is
  sending requests the relay rejects.

The endpoint has no authentication; keep it on a private address.

## Logs

Logs go to standard error (and so to the journal under systemd). The
level comes from, in order of precedence: `--log-level`, the `RUST_LOG`
environment variable, then `[log] level` (default `info`).

At `info` you see start-up, every offer, answer and delete with its
Call-ID, detected DTMF, and calls ending on timeout:

```text
INFO rtpflux: ng control on udp 127.0.0.1:2223
INFO rtpflux::control: call call-1@example.com: offer, 1 relayed media section(s)
INFO rtpflux::control: call call-1@example.com: answer, 1 relayed media section(s)
INFO rtpflux::control: ng offer x: missing sdp
INFO rtpflux::relay: call 7 ended: no media for the configured timeout
```

`debug` adds ICE and DTLS progress per call. `RUST_LOG` also accepts
per-module filters, such as `RUST_LOG=info,rtpflux::dtls=debug`: a level,
then `module=level` pairs, comma-separated. A value that is not of that
form is reported at start, and `[log] level` is used instead.

SRTP keys, DTLS secrets and `a=crypto` lines are never logged.

## Restarts

If an internal thread of the relay (a media worker, the ng control thread
or the XDP controller) ever fails, rtpflux logs the error and exits at
once instead of running on with some calls dead, so that systemd (or your
supervisor) restarts it. A failure while converting a recording only loses
that recording's audio file; its pcap is kept.

Set a state file to keep calls through a restart or an upgrade:

```toml
[sessions]
state_file = "/var/lib/rtpflux/state.json"
```

The relay writes all dialogs to this file within a second of a command
that changes a call (at most once a second), and when it stops. Each
write replaces the file atomically and reaches the disk first. If the
relay crashes, up to the last second's changes can be missing. A file
that cannot be used at start (not valid, or of another version) is renamed
to `state.json.bad`, so that the relay's next write does not replace it. The file
holds SRTP keys and ICE passwords, so it is created readable by the
relay's user only (mode 0600). At start it recreates each call **on the
same ports**, with:

- both sides' addresses, including addresses learned by latching;
- SDES keys, ICE credentials, `rtcp-mux` and BUNDLE;
- blocking, transcoding and recording (which continues in the same file);
- announcements, which resume where they would have been, or are dropped
  if they would have finished (an announcement from a `blob` is not kept);
- media subscriptions, on their ports and with the relay's SRTP keys
  towards the subscribers, copying again once their calls are back;
- `media echo`, `connect`ions and the parties' labels;
- for an offer not answered yet, what the offer decided for its answer:
  the relay's keys offered to the answerer (each SDES suite), opportunistic
  and legacy OSRTP, the `rtcp-mux` and DTLS roles, `ptime`, transcoding
  and telephone-event plans, and ICE passed through. An answer that comes
  after the restart is handled as it would have been before it;
- a re-offer made with `track-state` and not answered, which can still be
  rolled back, and parties made by `create`.

Phones keep sending to the same ports during the restart and carry on
when the relay is back. Packets that arrive while it is down are lost.

**Limitation:** DTLS keys are not saved. A WebRTC side has to make a new
DTLS handshake, which browsers do only when renegotiating. In practice,
browser calls do not survive a restart.

### State in Redis

The same state can also go to Redis, so that another host (or this one
after its disk was replaced) can take the calls over:

```toml
[sessions]
state_file = "/var/lib/rtpflux/state.json"   # optional with Redis
redis = "redis://:password@10.0.0.5:6379/0"
redis_key = "rtpflux:state:relay-a"
```

- Every save writes the file (if set) and the key, with the same
  snapshot. Redis is written by a background thread that only keeps the
  newest snapshot, so a slow or unreachable server never delays ng
  commands. While Redis is down, the relay logs it once, retries every
  second, and logs again when writes succeed.
- On shutdown the relay waits up to 3 seconds for the last snapshot to
  reach Redis.
- At start, with both a file and Redis, the **newer** snapshot is
  restored (each records when it was taken). With Redis only, it is read
  from Redis. An unreachable Redis is logged, and the file is used.
- A host taking over another's calls needs the same interfaces and port
  range, and the calls' addresses must reach it (a floating IP, for
  example). Point it at the other relay's key.
- The value holds SRTP keys and ICE passwords. Use a password (`AUTH`,
  with a user for Redis ACLs) and keep Redis on the host or a private
  network: the connection is not encrypted.

## systemd

`contrib/rtpflux.service` is a ready-made unit:

```sh
sudo install -m 755 target/release/rtpflux /usr/bin/rtpflux
sudo install -D -m 644 config/rtpflux.toml /etc/rtpflux/rtpflux.toml   # then edit
sudo cp contrib/rtpflux.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rtpflux
```

What it sets up:

- Runs `rtpflux --check` before every start, so a broken configuration
  never replaces a running relay's settings unnoticed.
- Runs as an unprivileged dynamic user, with a read-only system, private
  `/tmp` and no access to home directories.
- Keeps state in `/var/lib/rtpflux` (use that for `state_file`).
- Raises the open-file limit. Every call holds four sockets, and the usual
  default of 1,024 would cap the relay at about 250 calls.
- Grants only the capabilities the XDP fast path needs (`CAP_BPF`,
  `CAP_NET_ADMIN`, `CAP_PERFMON`). Remove them if you do not use XDP.
- Restarts the relay if it fails.

If you use recording, give the service write access to the recording
directory, for example with `ReadWritePaths=/var/spool/rtpflux` in a
drop-in (`systemctl edit rtpflux`).

## Capacity planning

- **Ports:** two RTP/RTCP pairs per media section. An audio-and-video
  call uses four pairs.
- **File descriptors:** four sockets per media section.
- **CPU:** in the benchmark, four worker threads relayed 200,000 plain
  RTP packets per second (2,000 G.711 calls) using about three CPUs. See
  [Benchmarks](benchmarks.md). SRTP adds a little; Opus transcoding costs
  much more per packet.
- **Memory:** buffers are allocated at start from `[runtime]` and
  `[sessions] max`, so memory use does not grow with traffic.
