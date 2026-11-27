# Architecture

How rtpflux is organised, and the design choices that make it fast.

## Goals

rtpflux is built to be **as fast as possible**. Every change is judged
first on correctness, then on how much it costs per packet. In practice
this means:

- **No allocation while relaying.** Buffers, tables and codec state are
  created at start-up or when a call is set up, never per packet.
- **No copying.** Packets are parsed in place and sent from the same
  buffer they were received into.
- **No locks between media threads.** Each worker owns its calls
  completely.
- **Batched system calls.** One `recvmmsg` reads up to 32 packets, one
  `sendmmsg` sends them.
- **Optional kernel fast path.** Simple calls skip userspace entirely
  ([XDP](xdp.md)).

## Threads

```text
                   ┌────────────────────────┐
 SIP proxy ──ng──► │ control thread         │  parses commands, rewrites SDP,
                   │ (ng server)            │  allocates ports, saves state
                   └──────────┬─────────────┘
                 bounded queue│+ eventfd wake-up
          ┌───────────────────┼────────────────────┐
          ▼                   ▼                    ▼
   ┌────────────┐      ┌────────────┐       ┌────────────┐
   │ worker 1   │      │ worker 2   │  ...  │ worker N   │   relay media
   │ ports      │      │ ports      │       │ ports      │   (epoll loop)
   │ 30000-…    │      │ …          │       │ …-60000    │
   └─────┬──────┘      └────────────┘       └────────────┘
         │ offload requests                 ┌────────────┐
         └─────────────────────────────────►│ XDP thread │  installs kernel
                                            └────────────┘  flows, polls counters
                                            ┌────────────┐
                                            │ metrics    │  serves /metrics
                                            └────────────┘
```

- **The control thread** answers ng commands. It reads and rewrites SDP,
  picks ports, creates SRTP keys and ICE credentials, and sends each new
  call to its worker.
- **Workers** each own one contiguous slice ("shard") of the port range.
  A call's sockets all come from one shard, so a call belongs to exactly
  one worker and no state is shared. A worker sleeps in `epoll` until
  packets or commands arrive. It also runs DTLS handshakes, DTMF
  detection, recordings and announcements for its calls.
- **The XDP thread** (only with `[xdp] enabled`) installs settled calls
  into the kernel program. Every second it reads the kernel's per-flow
  counters, so those calls do not time out.
- **The native API** (only with `[control] native_socket`) has a
  listener thread and a thread per connection. They hand each request to
  the control thread and write its reply, and the events the connection
  subscribed to. See [Native control API](native-api.md).
- **PCM streams and mixers** each have threads of their own. A worker
  copies an endpoint's packets into a bounded queue for them, and plays
  the 20 ms frames they send back. Decoding, jitter buffering,
  concealment, resampling, voice detection and mixing happen there,
  never on a media worker.
- **Media events** (key presses, announcements played out, DTLS and ICE
  progress, recordings finished) go from the workers to the control
  thread through one bounded queue, which never blocks a worker.
- **The metrics thread** serves Prometheus metrics from counters the
  workers update atomically. Reading them takes no locks.

## The path of a packet

For each datagram a worker receives:

1. **Demultiplex** by its first byte (RFC 5764, RFC 7983): STUN (ICE checks
   and their answers) goes to the side's ICE agent (or the ICE-lite
   responder), DTLS to the handshake, RTP and RTCP onward,
   ZRTP straight to the other side (when the call's media is passed through).
2. **Decrypt** SRTP or SRTCP in place, if this side uses it. A packet
   that fails authentication is dropped here, before it can influence
   anything else.
3. **Decide**: is there a call on this port, is the source acceptable,
   and where does the packet go? This step also does the
   [latching](media.md#nat-and-latching).
4. **Inspect**: record it, read RTCP reports, apply blocking, and
   transcode.
5. **Encrypt** for the destination side, if it uses SRTP.
6. **Send**, batched with the other packets for the same socket.

## Crates

The code is split so that protocol logic can be tested without sockets,
threads or clocks:

| Crate | Role | Constraints |
|---|---|---|
| [`rtpflux-core`](https://github.com/RustedBytes/rtpflux/blob/main/crates/rtpflux-core/README.md) | Protocol logic: RTP and RTCP parsing, SDP reading and rewriting, latching, the relay decision, ICE and STUN, DTMF detection, G.711 and G.722 | `no_std`, no allocation, no I/O |
| [`rtpflux-srtp`](https://github.com/RustedBytes/rtpflux/blob/main/crates/rtpflux-srtp/README.md) | SRTP and SRTCP encryption and decryption, in place, all six suites | `no_std`, no allocation, constant-time tag checks |
| [`rtpflux-ng`](https://github.com/RustedBytes/rtpflux/blob/main/crates/rtpflux-ng/README.md) | The ng protocol: bencode and commands | `no_std`, no allocation, no I/O |
| [`rtpflux-xdp-common`](https://github.com/RustedBytes/rtpflux/blob/main/crates/rtpflux-xdp-common/README.md) | The XDP program's data layout and per-packet arithmetic, with safe reference versions of its logic | `no_std` |
| [`rtpflux-xdp`](https://github.com/RustedBytes/rtpflux/blob/main/crates/rtpflux-xdp/README.md) | Loading the XDP program, managing its flow table, `AF_XDP` sockets, the `xdp-selftest` tool | `std` |
| [`rtpflux-xdp-ebpf`](https://github.com/RustedBytes/rtpflux/blob/main/crates/rtpflux-xdp-ebpf/README.md) | The XDP program itself, built for the BPF target | `no_std`, outside the workspace |
| [`rtpflux-uring`](https://github.com/RustedBytes/rtpflux/blob/main/crates/rtpflux-uring/README.md) | `io_uring` multishot UDP receive for the media workers, with its benchmark | `std` |
| [`rtpflux`](https://github.com/RustedBytes/rtpflux/blob/main/crates/rtpflux/README.md) | The daemon: configuration, sockets, threads, DTLS, recordings, state file and Redis, metrics, web UI | `std` |
| [`rtpflux-client`](https://github.com/RustedBytes/rtpflux/blob/main/crates/rtpflux-client/README.md) | A client of the native control API, for a softswitch | `std`, only `serde_json` |
| [`rtpflux-bench`](https://github.com/RustedBytes/rtpflux/blob/main/crates/rtpflux-bench/README.md) | The load generator used by the benchmarks | `std` |

Each crate's README explains why it is separate and what is in it.

`unsafe` code is forbidden everywhere except the XDP program and three
small, documented modules: `pod` and `xsk` in `rtpflux-xdp`, and `ring`
in `rtpflux-uring`.

## External code

- **dimpl**, a pure-Rust DTLS implementation on the RustCrypto
  libraries, runs the DTLS handshakes only. The relay's self-signed
  certificate is made with the RustCrypto `p256` and `x509-cert` crates.
  Media encryption uses the RustCrypto AES and SHA-1 implementations in
  `rtpflux-srtp`.
- **flacenc** and **ogg** (pure Rust) write FLAC and Ogg Opus recordings;
  Opus audio is encoded and decoded by **opus-rs**.
- **LAME** writes MP3 recordings, only in builds with the `mp3` feature.
  It is a C library under the LGPL.
- **rusty-s3** (request signing) and **ureq** (HTTPS over rustls) upload
  recordings to S3, only in builds with the `s3` feature, which builds
  ring's C and assembly code. The default build links no C code.
- **opus-rs**, a pure-Rust port of libopus, does Opus transcoding.
- **aya** loads the XDP program.

See [AGENTS.md](https://github.com/RustedBytes/rtpflux/blob/main/AGENTS.md) for the full rules contributors follow.
