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

## Against the integration baseline

`bench/baseline.sh` compares HEAD with a pinned commit (`BASELINE`,
default `cac9411`, before the Ferroswitch integration work). It runs on
the same machine and configuration, alternating the two binaries over
two rounds.

The figures below are from an i9-9900K (8 cores, 16 threads) on Linux
7.0, over loopback:
- relay: 2 workers on CPUs 0,1,8,9 (two physical cores);
- load generator on 2,3,10,11; `native-bench` on 4,12.

**Ordinary relaying** (`rtpflux-bench`, G.711 both ways, 10 s windows,
no loss in any run). Each cell is round 1 / round 2:

| Load | Baseline: p50 / p99 µs | Baseline: relay CPU % | HEAD: p50 / p99 µs | HEAD: relay CPU % |
|---|---|---|---|---|
| 500 calls, plain | 93 / 184, 87 / 220 | 38.5, 37.1 | 97 / 189, 94 / 188 | 38.8, 38.5 |
| 1000 calls, plain | 146 / 344, 216 / 354 | 63.1, 71.9 | 157 / 348, 134 / 342 | 66.4, 60.4 |
| 500 calls, SRTP both sides | 110 / 262, 104 / 253 | 46.0, 46.7 | 88 / 254, 76 / 203 | 42.8, 37.8 |
| 1000 calls, SRTP both sides | 213 / 477, 157 / 448 | 90.1, 77.6 | 147 / 451, 134 / 359 | 77.8, 71.9 |

No regression beyond the run-to-run spread, which is itself larger than
the proposed gates (5 % median throughput, 10 % p99). A short window
misleads: a 2 s smoke run at 100 calls showed HEAD at 3.5× the
baseline's CPU, and 6 s windows at 500 calls, in both orders, showed
them equal. Transcoding (no load mode in `rtpflux-bench`) and XDP (root:
`bench/fastpath.sh`) were not compared.

**Native control** (`native-bench`, 2000 create+destroy pairs,
unkeyed). Each cell is round 1 / round 2:

| | Pairs/s | Create p50 / p95 / p99 ms | Destroy p50 / p99 ms | Events/s | RSS growth |
|---|---|---|---|---|---|
| Baseline | 5873 / 6819 | 0.085 / 0.114 / 0.133 | 0.079 / 0.133 | 5884 / 6836 | +8.9 MB |
| HEAD | 8930 / 7779 | 0.069 / 0.075 / 0.102 | 0.041 / 0.075 | 8953 / 7798 | +0.8 MB |

The baseline's memory growth was a leak, fixed during the integration
work ("two leaks fixed").

**Durable operations** (HEAD only, `[sessions] ledger`, keyed, 2000
pairs): 72 pairs/s, create p50 2.6 ms and p99 29.7 ms, destroy p50
3.1 ms and p99 34.0 ms. This is bound by the disk's sync latency (three
to four syncs per operation), and runs of the same build vary from about
35 to 70 pairs/s. The ledger keeps each outcome, its reply included, for
its retention: about 4.6 KB of memory per keyed operation, bounded by
`ledger_quota` per tenant. Lower the quota or the retention where
memory matters.

**Recovery** (500 endpoints; time from the relay's launch until it lists
them all):

| | After SIGINT (graceful) | After SIGKILL |
|---|---|---|
| Baseline | 180, 184 ms | 107, 101 ms |
| HEAD | 136, 133 ms | 120, 106 ms |

## Recording conference mixers

`mixrec::load` (an ignored test: `cargo test --release -p rtpflux --test
mixrec load -- --ignored --nocapture`) runs 50 mixers of 5 participants,
each participant sending a tone, for 5 s without recording, then for 5 s
with all 50 mixers recorded (WAV, 8 kHz, mono). Measured on an
i9-9900K (16 threads), loopback, release build, two runs:

| | Mixer threads | Writer threads | Mix packets/s per participant |
|---|---|---|---|
| Not recorded | 23.0–26.6% of a CPU | | 50.2–50.3 |
| Recorded | 31.8–35.4% of a CPU | under the clock-tick resolution (0.2%) | 50.1–50.2 |

- Recording costs the mixers 5–12 points of one CPU for 50 mixers (about
  0.1–0.25% each): one more sum through a limiter and a copy into the
  queue per 20 ms. The participants' mixes keep their rate: the
  conference is not slowed.
- No period was lost (`lost_ms` 0 for all 50).
- The 50 WAV files were made 0.16–0.17 s after the stop.
- Not measured: latency to the participants as such (the rate is the
  proxy), tracks under load, and lossy formats (Opus, MP3), whose encoding
  runs on the conversion thread after the stop.

## Running the benchmarks

```sh
# rtpflux against rtpengine, userspace, loopback (needs podman and an
# rtpengine container image, set with RTPENGINE_IMAGE)
CALLS=250,500,1000,2000 bench/compare.sh

# rtpflux with plain RTP, SRTP on one side and on both sides
bench/srtp.sh

# kernel fast paths: rtpflux XDP against rtpengine's kernel module (root)
bench/fastpath.sh

# HEAD against a pinned baseline: relaying, native control, durable
# operations, recovery (builds the baseline in a worktree)
BASELINE=cac9411 bench/baseline.sh

# the native API's load alone (native-bench), against a running relay
target/release/native-bench --socket /run/rtpflux/native.sock --pid <pid> --ops 2000
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
