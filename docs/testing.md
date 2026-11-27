# Testing

rtpflux is checked in five ways, from fast unit tests to real browsers,
SIP servers and the kernel. CI (`.github/workflows/ci.yml`) runs all of
them on every push: formatting and Clippy, the test suite with and without
the optional features, the web UI bundle, the XDP program with
`xdp-selftest` and `xdp-e2e` (GitHub's runners allow `sudo`), and the
Kamailio, OpenSIPS and FreeSWITCH bench.

## 1. The test suite

```sh
cargo test --workspace
```

This runs, without root:

- **Unit tests** in every crate: SDP parsing and rewriting, SRTP against
  the RFC test vectors, latching, DTMF detection, RTCP, G.711, G.722
  (bit for bit against another translation of the reference code), G.729,
  Opus and AMR, the PCM kernels (jitter buffer, concealment, resampler,
  VAD, N − 1 mixer, tones; against reference implementations),
  the XDP program's reference logic, and more.
- **Integration tests** in `crates/rtpflux/tests/`. They start a real relay
  on loopback and drive it over the ng protocol with real UDP media:

| File | What it covers |
|---|---|
| `ng/` | The ng commands over UDP: calls, re-INVITEs and `rollback`, hold, BUNDLE, SRTP bridging, blocking and DTMF security, RTCP statistics, transcoding, announcements, subscriptions, calls with more than two parties (labels, `connect`, `mesh`, `inject`), `create` and `create from offer`, delayed deletes, and the options of offers and answers |
| `native.rs` | The [native control API](native-api.md) over its Unix socket, with `rtpflux-client`: two independent endpoints negotiated both ways, bridged across workers, renegotiated (commit and abort), destroyed (tombstones, idempotent destroy); DTMF, playback, bridge and speech events; idempotency keys, generations, tenants, deadlines, leases and the endpoint limit; endpoints surviving a restart; a PCM stream to a service (decoded audio, speech detection, audio back, marks, flush); mixers (N − 1, mute, active speaker; G.722 and PCMU together; a supervisor listening, whispering and barging in); in-band DTMF; the API over TCP with tokens; a worker's failure reported; churn without leaks |
| `rtpflux-client-async/tests/client.rs` | The async client against a running relay: two legs with typed requests and events on their own connection; many concurrent requests; deadlines; cancellation; reconnecting requests and events across a restart; TCP tokens; a slow event consumer (bounded, gap reported) |
| `relay.rs` | The media relay itself: forwarding both ways, RTCP, latching, strict source, batching, port reuse, timeouts |
| `recording.rs` | pcap recordings |
| `restart.rs` | Calls, blocking, DTMF security, recordings, announcements, connections, copies, labels and `media echo` surviving a restart; offers answered, re-offers rolled back and created parties answered after one; parties created from their offer |
| `conformance.rs` | The conformance vectors (below) |
| `ng/uring.rs` | Calls received with `io_uring` and with `recvmmsg` (`runtime.receive`); the rest of `ng/` uses the default (`io_uring`), or `recvmmsg` with `RTPFLUX_TEST_RECEIVE=recvmmsg` |
| `robustness.rs` | No untrusted input panics: RTP, RTCP, STUN, telephone events, SDP, bencode, SRTP and the XDP frame checks get random bytes and mutated valid inputs; the ng control layer gets every command with mutated options and SDP; a live call's ports get mutated media from its parties and a stranger, and still relay afterwards; native API requests of every operation, with fields of every type, and PCM stream frames. Seeded, so reproducible; `RTPFLUX_FUZZ_SCALE=<n>` runs `n` times as many cases (run it in a debug build, where overflow panics) |
| `control.rs` | Error replies to bad requests, state files that cannot be restored, and calls restored from Redis (the newer of file and Redis) |
| `daemon.rs` | The command line, the daemon started, used and stopped, and the `rtpflux` binary itself (SIGTERM) |
| `webui.rs` | The web UI over HTTP: login, the app's files and headers, read-only rules, and the API with a real call |
| `xdp_e2e.rs` | The XDP fast path; run by `scripts/xdp-e2e.sh`, skipped otherwise |

Before sending a change, also run the formatter and the linter (the
project uses Clippy's pedantic set):

```sh
cargo fmt --check
cargo clippy --workspace --all-targets
```

## 2. Conformance vectors

`conformance/media-vectors.txt` holds over 5,000 expected results
computed by an **independent, executable reference model** of the
protocols. They cover SRTP and SRTCP for all six suites, SDES key
selection, ICE (answers, checks, priorities, role conflicts, check
lists, trickled pairs, consent freshness, trickle fragments), DTLS roles
and keying, DTMF detection, RTCP
reports, G.711, BUNDLE answers and the XDP frame rewrite.

```sh
cargo test -p rtpflux --test conformance
```

The test reports every disagreement at once. See
[Conformance](conformance.md) for what each kind of vector checks.

## 3. Real browsers

`scripts/webrtc-firefox.py` makes a real WebRTC call through the relay.
Headless Firefox (with a fake microphone) calls a plain RTP "phone"
played by the script. The script checks that ICE and DTLS complete (with
the relay as a full ICE agent, the browser controlling; `--lite` makes
it ICE-lite), that the relay's SDP says which, and that audio flows both
ways.

```sh
cargo build --release -p rtpflux
python3 scripts/webrtc-firefox.py                       # audio
python3 scripts/webrtc-firefox.py --video               # audio and video, BUNDLE
python3 scripts/webrtc-firefox.py --video --max-bundle  # bundle-only sections
python3 scripts/webrtc-firefox.py --lite                # the relay ICE-lite
python3 scripts/webrtc-firefox.py --chrome /usr/bin/chromium   # Chrome or Chromium
```

It prints `PASS` or exits with an error. Firefox only offers a
non-loopback address, so the script binds the relay to your machine's
LAN address for the run.

## S3

Two tests run against a real S3-compatible server when you point them at
one. For example, with versitygw:

```sh
docker run -d --rm --name s3 -p 127.0.0.1:7070:7070 \
    -e ROOT_ACCESS_KEY=test -e ROOT_SECRET_KEY=testsecret \
    versity/versitygw --port :7070 posix /tmp
RTPFLUX_S3_TEST_ENDPOINT=http://127.0.0.1:7070 RTPFLUX_S3_TEST_BUCKET=recordings \
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=testsecret \
    cargo test -p rtpflux --features s3 -- --ignored s3
```

## Coverage

Line coverage of the whole workspace is measured with
[cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov):

```sh
rustup component add llvm-tools
cargo install cargo-llvm-cov
cargo llvm-cov --workspace --summary-only        # the table
cargo llvm-cov --workspace --html                # browsable, in target/llvm-cov/html
```

It is above 90% of lines. Most of what is not covered is code that needs
root to run: `xdp-selftest` and the XDP program loader (about 400 lines,
exercised by the kernel tests below). Without them, coverage is about 94%.
The tests install a logger that formats every record, so the code that
builds log messages is covered too.

The XDP offload controller does not need a kernel to be tested: the
relay's flow table and the host's network tables sit behind two small
traits, and the tests use in-memory versions of both.

## 4. SIP servers

`integration/run.sh` places real calls through Kamailio (its `rtpengine`
module driving rtpflux) in Docker, to a SIPp callee and to FreeSWITCH,
and through ferrosip's media module, and checks the SDP, the media both
ways and each call's cleanup; then a ZRTP call between two linphones,
checked secure end to end. See [Integration](integration.md#the-test-bench).

```sh
integration/run.sh
```

## 5. The kernel fast path

These need root; see [XDP fast path](xdp.md#testing-it).

```sh
sudo target/debug/xdp-selftest   # the program on generated frames
./scripts/xdp-e2e.sh             # real calls in network namespaces
```

To check the redirect to an AF_XDP socket as well, build the self-test
with the feature:

```sh
cargo build -p rtpflux-xdp --features af-xdp
sudo target/debug/xdp-selftest
```

## 6. Benchmarks

`cargo bench -p rtpflux-uring` compares the two ways the media workers can
receive (`runtime.receive`): epoll + `recvmmsg` and `io_uring` multishot
receive. A sender spreads RTP-sized datagrams over 1 to 4096 sockets at a
steady rate (and floods one socket); the benchmark reports each receiver
thread's CPU time per datagram and how many it received. The results on one
machine are in [Configuration](configuration.md#runtime-threads-and-buffers).
Run it on an idle machine; numbers vary between runs by a few percent.
