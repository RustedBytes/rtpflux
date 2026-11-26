# rtpflux

The daemon: the program you run. It owns the sockets, the threads, the
calls and the configuration, and it moves bytes. Protocol decisions are
made by the pure crates it calls.

## Why it is a crate of its own

Everything that needs the operating system lives here and only here:
sockets, threads, timers, files, the clock, randomness, logging, HTTP and
Redis. Everything else (what a packet means, how SDP is rewritten, how
SRTP is computed) lives in `no_std` crates that cannot do I/O. So the
protocol logic stays testable without a running relay, and this crate
stays about state and plumbing.

- **`#![forbid(unsafe_code)]`.** All `unsafe` is in `rtpflux-uring` and
  `rtpflux-xdp`, behind safe APIs.
- **No allocation per packet.** Buffers and tables are allocated at
  start-up or call set-up; queues are fixed-capacity, and drop and count
  when full.
- **One owner per call.** Each media worker owns a slice of the port range
  and every call in it. No locks on the media path.
- **The only logging backend.** Other crates log through the `log` facade;
  this one installs `tracing-subscriber`, filtered by `RUST_LOG`.

## What is inside

| Module | What it does |
|---|---|
| `daemon`, `lifecycle` | The command line, starting and stopping everything; the state machines of a recording and of deletes put off by `delete-delay` |
| `config` | The TOML configuration, parsed once and validated (problems and warnings) before anything is bound |
| `control` | The `ng` server: every rtpengine command, from `offer` to `mesh` |
| `ngstream`, `ngcache` | `ng` over TCP, HTTP and WebSocket; replies kept for retransmissions |
| `relay` | The media workers: the receive loop, latching, SRTP, transcoding, `connect`, copies, and handing settled calls to XDP |
| `dtls` | DTLS-SRTP handshakes, run by `dimpl` (never on the media path) |
| `codec`, `media_file` | Voice codecs for transcoding (G.711, G.722, G.729, Opus, AMR); WAV, MP3 and FLAC files for `play media` |
| `recording` | pcap recordings, conversion to WAV, FLAC, Opus or MP3, S3 upload and its webhook |
| `subscription`, `publish` | Subscriptions (SIPREC, monitoring) and publishing (WebRTC) |
| `reoffer`, `trickle`, `srflx` | Re-INVITE decisions, trickle ICE, server-reflexive candidates from a STUN server |
| `state`, `redis` | Keeping calls across restarts: the state file, Redis |
| `metrics`, `webui` | Prometheus metrics, and the read-only web UI (its built bundle is embedded) |

## Features

All off by default, so the default build is pure Rust with no C code:

| Feature | Adds |
|---|---|
| `mp3` | MP3 recordings, through LAME (a C library, LGPL) |
| `s3` | Recordings uploaded to S3, and the upload webhook (rustls over ring, which builds C and assembly) |
| `af-xdp` | `AF_XDP` receive sockets for calls the XDP program does not relay (`xdpilone`, EUPL-1.2) |
| `amr` | AMR and AMR-WB transcoding and recording (pure Rust; check AMR's patents where you deploy) |

```sh
cargo build --release
cargo build --release --features mp3,s3
```

## Testing

```sh
cargo test -p rtpflux                      # unit tests and integration tests in tests/
cargo test -p rtpflux --test conformance   # against the reference model's vectors
cargo test -p rtpflux --test robustness    # hostile input, never a panic
```

The scenarios in `examples/scenarios/` check whole deployments against a
release build; see [Testing](../../docs/testing.md).

## Depends on

`rtpflux-core`, `rtpflux-ng`, `rtpflux-srtp`, `rtpflux-uring`,
`rtpflux-xdp` and `rtpflux-xdp-common`. To run it, start with
[Getting started](../../docs/getting-started.md).
