# Benchmarks

How fast is rtpflux, and how do we measure it?

## Method

The load generator, `rtpflux-bench`, behaves like many phones at once.
It sets up calls over the ng protocol and sends G.711 audio: one
172-byte RTP packet every 20 ms, in both directions, so 100 packets per
second per call. It then reports:

- **delivery**: how many packets arrived, and the loss percentage;
- **latency**: one-way delay through the relay (median, 99th and 99.9th
  percentile);
- **relay CPU**: CPU time used by the relay process, in percent of one
  CPU;
- with the XDP fast path, also **softirq** and **host CPU**, because
  packets forwarded in the kernel do not show up as relay process time.

Each step runs a warm-up, then three 10-second windows, and reports the
median window. The relay and the load generator are pinned to separate
physical cores.

## Results

Reference machine: Intel Xeon E5-1620 v3 (4 cores, 8 threads,
3.5 GHz), Linux 7.0, four relay worker threads on two physical cores,
4 load-generator threads on the other two. rtpengine 13.5.1.16 was run
with the same worker count and flags.

### Userspace, loopback (`bench/compare.sh`)

Measured on 26 November 2026 with all current features: rtpflux with each
`runtime.receive` (`io_uring`, the default, and `recvmmsg`), then
rtpengine. Latency is one way through the relay; CPU is the relay
process, in percent of one CPU.

| Calls | Packets/s | `io_uring`: p99 latency, CPU | `recvmmsg`: p99 latency, CPU | rtpengine: delivered, p99 latency, CPU |
|---|---|---|---|---|
| 250 | 25,000 | 0.32 ms, 101% | 0.31 ms, 110% | 100%, 0.53 ms, 144% |
| 500 | 50,000 | 0.41 ms, 171% | 0.44 ms, 186% | 100%, 0.69 ms, 259% |
| 1,000 | 100,000 | 0.36 ms, 300% | 0.50 ms, 308% | 100%, 0.84 ms, 306% |
| 2,000 | 200,000 | 0.14 ms, 294% | 0.17 ms, 302% | 100%, 0.24 ms, 374% |
| 3,000 | 300,000 | 0.12 ms, 378% | 0.11 ms, 382% | 100%, 47 ms (queueing), 400% |
| 4,000 | 400,000 | 53 ms (queueing), 400% | 50 ms (queueing), 400% | 2.6%, 2.9 ms, 55% |

rtpflux delivered every packet at every step, with either way of
receiving. At 4,000 calls it uses all four worker threads and packets
queue (a median of 35 ms with `io_uring`, 23 ms with `recvmmsg`).
rtpengine queued at 3,000 calls and dropped most packets at 4,000, from
full receive queues. `io_uring` used 3–8% less relay CPU than `recvmmsg`
up to 2,000 calls.

The SRTP and kernel fast path results below were measured earlier, at
the commits in their result files, before the newer call features and
`io_uring` receive.

### SRTP (`bench/srtp.sh`)

At 2,000 calls (200,000 packets/s), with `AES_CM_128_HMAC_SHA1_80`:

| Mode | Delivered | Relay CPU |
|---|---|---|
| Plain RTP | 100% | 303% |
| SRTP on one side (the relay encrypts or decrypts every packet) | 100% | 287% |
| SRTP on both sides (decrypt and re-encrypt every packet) | 100% | 320% |

At this load SRTP added little relay CPU; the differences are close to
the variation between runs.

### Kernel fast paths (`bench/fastpath.sh`)

Over a virtual Ethernet pair between two network namespaces, with
generic-mode XDP:

| Calls | rtpflux userspace: relay CPU | rtpflux XDP: relay CPU | rtpflux XDP: host CPU | rtpengine kernel module: host CPU |
|---|---|---|---|---|
| 1,000 | 300% | 1.9% | 242% | 425% |
| 2,000 | 304% | 3.6% | 306% | 520% |
| 4,000 | 400% | 7.3% | 365% | 723% |

All variants delivered every packet. The result file also records that
rtpengine's kernel table held 0 streams during the first step, so its
kernel forwarding may not have been active in that run; treat the last
column with caution. "Host CPU" counts all CPU time on
the machine, including the kernel's packet processing and the load
generator. Generic XDP runs late in the kernel; native XDP on a physical
NIC should do better.

## Running the benchmarks

```sh
# rtpflux against rtpengine, userspace, loopback (needs podman and an
# rtpengine container image, set with RTPENGINE_IMAGE)
CALLS=250,500,1000,2000 bench/compare.sh

# rtpflux with plain RTP, SRTP on one side and on both sides
bench/srtp.sh

# kernel fast paths: rtpflux XDP against rtpengine's kernel module (root)
bench/fastpath.sh
```

The scripts are configured with environment variables, listed at the top
of each script: `CALLS`, `WARMUP`, `DURATION`, `REPEAT`, `WORKERS`,
`RELAY_CPUS`, `CLIENT_CPUS` and others. Results are printed and saved to
`bench/results/` (not committed: the tables here keep the numbers). Pin the relay and the load generator to different
physical cores (see `lscpu -e`), or the numbers mostly measure the
competition between them.

The cost of one DTLS handshake is measured separately:

```sh
cargo test --release -p rtpflux --lib handshake_cost -- --ignored --nocapture
```
