# rtpflux-bench

A load generator for RTP relays controlled over `ng`: rtpflux, or
rtpengine for comparison.

## Why it is a crate of its own

Speed claims in rtpflux need measurements, and the same load has to be
put on rtpflux and on rtpengine to compare them. This tool speaks only
`ng` and RTP, so it works with any relay that a SIP proxy's `rtpengine`
module could drive, and it is kept out of the daemon. It is not published
(`publish = false`).

## What it does

For each step it sets up N calls with `offer` and `answer`. Every call
then sends 172-octet RTP packets (G.711, 20 ms) in both directions:
100 packets a second per call, with staggered start times. After a
warm-up, over a measurement window, it reports:

- **delivery**: how many packets arrived;
- **one-way latency** through the relay (a send timestamp travels in the
  payload);
- **the relay's CPU time**, read from `/proc/<pid>/stat`.

Calls are deleted between steps.

With `--srtp a`, side A uses SDES-SRTP (`AES_CM_128_HMAC_SHA1_80`) and
side B plain RTP, so the relay decrypts or encrypts every packet. With
`--srtp both`, both sides use SRTP with their own keys, so the relay
decrypts and re-encrypts every packet. The tool's own SRTP work costs its
own CPU time, not the relay's.

## Usage

```sh
cargo build --release -p rtpflux -p rtpflux-bench
target/release/rtpflux-bench --help
target/release/rtpflux-bench --ng 127.0.0.1:2223 --pid <relay pid> \
    --calls 250,500,1000 --warmup 2 --duration 10 --threads 4
```

The scripts in `bench/` drive it: `compare.sh` (rtpflux against
rtpengine), `srtp.sh` (plain, one SRTP side, two), and `fastpath.sh` (XDP
against rtpengine's kernel module, in network namespaces). Results go to
`bench/results/` (ignored by git); see [Benchmarks](../../docs/benchmarks.md)
for the published numbers.

## Depends on

`rtpflux-ng` (building requests), `rtpflux-core` (reading the relay's SDP) and
`rtpflux-srtp` (the `--srtp` modes).
