# 08: a carrier-sized relay

**The case.** SIP trunking or a hosted PBX with thousands of concurrent
calls.

## Setting it up

```toml
[ports]
min = 30000
max = 60000            # 15000 pairs: 7500 calls (two pairs per call)

[runtime]
workers = 0            # one per CPU

[xdp]                  # settled plain RTP in the network driver (root)
enabled = true
devices = ["eth0"]
```

## What `run.py` checks

- **Capacity:** a 40-port range holds exactly 10 calls, and the 11th is
  refused with "no free media ports".
- **Port reuse:** a delete frees ports for a new call. A re-offer works
  in a full relay, and adding a stream there is refused while the call
  goes on.
- **`sessions.max`:** with `max = 5`, exactly 5 calls are set up and
  relay media, the 6th new call is refused, and a re-offer still passes.
- **Churn:** 2000 offer/answer/delete cycles (`--quick`: 300) leave no
  calls and no leaked ports. The control-plane rate is reported.
- **Media load:** `rtpflux-bench` runs 250, 1000 and 2000 calls (100 and
  500 with `--quick`), plain and with SRTP on both sides. Loss must stay
  under 1%.

`run.py` prints the load test's delivery, p99 latency and relay CPU per
packet, plain and with SRTP; [Benchmarks](../../../docs/benchmarks.md)
has measured figures.

## Not covered

XDP needs root: run `./scripts/xdp-e2e.sh` and `bench/fastpath.sh` for
it.
