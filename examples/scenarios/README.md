# Deployment scenarios

Each folder is one way people deploy rtpflux. It explains how to set the
relay and the SIP proxy up for that case, and has a `run.py` that checks
the case against a real relay. The script also probes the case's edge
cases and reports them as findings.

| Scenario | What it covers |
|---|---|
| [01-rtpengine-replacement](01-rtpengine-replacement/) | The ng protocol as Kamailio/OpenSIPS speak it, over UDP, TCP and HTTP; retransmissions, errors, hostile requests |
| [02-nat-latching](02-nat-latching/) | Callers behind NAT: latching modes, strict-source, NAT rebinding, injection |
| [03-webrtc-sip-bridge](03-webrtc-sip-bridge/) | Browser (ICE, DTLS-SRTP, BUNDLE) to a plain SIP phone; ICE checks; real Firefox with `--browser` |
| [04-srtp-boundary](04-srtp-boundary/) | SDES-SRTP on one side, plain RTP on the other; four suites, tampering, replay, rollover, SRTCP |
| [05-transcoding](05-transcoding/) | G.711 u-law/A-law (checked sample by sample), G.722, G.729, Opus, DTMF events to tones |
| [06-topology-hiding](06-topology-hiding/) | Public and private interfaces, `advertise` behind 1:1 NAT, IPv4/IPv6, what leaks through SDP |
| [07-call-center](07-call-center/) | Recording to stereo WAV, announcements, DTMF detection and injection, block and silence |
| [08-high-volume](08-high-volume/) | Capacity limits, port reuse, control-plane rate, media load with `rtpflux-bench` |
| [09-high-availability](09-high-availability/) | State file across restarts and crashes, timeouts, metrics, the web UI API |
| [10-siprec-subscriptions](10-siprec-subscriptions/) | SIPREC recording through `subscribe request/answer`: labels, exact copies per party, SRTP recorders, restarts |
| [11-webrtc-broadcast](11-webrtc-broadcast/) | `publish` and 23 subscribers in mixed profiles, joining, leaving, re-keying, a DTLS subscriber with `--browser` |
| [12-ng-transports](12-ng-transports/) | ng over pipelined TCP, HTTP (bencode, JSON) and WebSocket, with the RFC 6455 failures |
| [13-bundle-edge-cases](13-bundle-edge-cases/) | BUNDLE sorting by payload type and SSRC, bundle-only, re-INVITEs from either side, streams added and dropped, SDES per section |
| [14-redis-failover](14-redis-failover/) | Relay B takes over relay A's calls from Redis after `kill -9`; Redis outages, passwords, keys |
| [15-multi-proxy](15-multi-proxy/) | Several proxies: colliding cookies, forking, interleaved re-offers, concurrent load, one `sessions.max` |
| [16-t38-fax](16-t38-fax/) | Audio re-INVITEd to T.38: attributes kept, UDPTL relayed byte for byte, latching, back to audio |
| [17-zrtp](17-zrtp/) | ZRTP passes on plain calls and is dropped (with `a=zrtp-hash`) when the relay changes the media |
| [18-ice-restart-consent](18-ice-restart-consent/) | A Python ICE agent: nomination, consent every 4–6 s, ICE restart, consent lost after 30 s |
| [19-stun-srflx](19-stun-srflx/) | `ice.stun_server`: server-reflexive candidates per interface, a silent STUN server |
| [20-rolling-upgrade](20-rolling-upgrade/) | 40 calls streaming through a SIGTERM restart: gap, loss, every call and SRTP key back |
| [21-hostile-media](21-hostile-media/) | Floods, oversized and garbage datagrams, lying RTCP, unauthenticated STUN; no amplification, no harm to other calls |
| [22-long-calls](22-long-calls/) | Sequence and timestamp wraps on plain, SRTP (two rollovers) and transcoded calls; DTMF on a wrap; a 10-minute recording |
| [23-real-sip-stacks](23-real-sip-stacks/) | `--docker`: Kamailio, OpenSIPS, SIPp, FreeSWITCH, G.722, ferrosip and two linphones doing ZRTP, through rtpflux |
| [24-codec-quality](24-codec-quality/) | Level and SINAD through each transcoder (PCMA, G.722, G.729, Opus) at three frequencies |
| [25-recording-fidelity](25-recording-fidelity/) | Recordings from reordered, lost, duplicated, jittered, DTX, late and re-SSRC'd streams, SRTP and ZRTP calls |
| [26-conference](26-conference/) | Conferences without a mixer: a dial-out room of `create`d parties joined with `mesh` (PCMU, PCMA, G.722 converted), mute, join, leave, restart; lobby to room across calls; a B2BUA's three-way call in one call-id |
| [27-call-transfer](27-call-transfer/) | Attended and blind transfers with `connect`: no re-INVITE, the transferor detached, codec conversion, into SRTP, a second transfer, ten at once across workers, restart |
| [28-supervisor](28-supervisor/) | A supervisor monitoring (directional `connect`), whispering to the agent and barging in (`inject start`/`stop`), pausing or silencing the copies, restart, either call ending |

## Running

You need Python 3.10 or later (3.13 and later too: the harness has its
own G.711 code, no `audioop`) and the `cryptography` package (for SRTP).
The harness's own unit tests run with
`python3 -m unittest discover -s examples/scenarios/lib`.
You do not need a SIP proxy or phones: the harness in
[`lib/harness.py`](lib/harness.py) plays the proxy, sending `ng`
commands as the rtpengine modules do, and both phones, sending real
RTP/SRTP over loopback.

```sh
cargo build --release -p rtpflux -p rtpflux-bench
examples/scenarios/run-all.sh             # every scenario, then a summary and the findings
examples/scenarios/run-all.sh --quick     # shorter load test
examples/scenarios/run-all.sh --browser   # also headless Firefox through the relay (03, 11)
examples/scenarios/run-all.sh --docker    # also the real SIP stacks in Docker (23)
python3 examples/scenarios/05-transcoding/run.py   # one scenario
```

Each scenario starts its own relay with a generated configuration, on its
own `ng` port (20301 and up) and media port range (21000–32767; test
endpoints use 10000–19999, all outside the kernel's ephemeral ports). Run
them one at a time:
the load test in 08 uses ports 30000–60000. Set `KEEP=1` to keep each
relay's directory (configuration, log, recordings) in `/tmp`, and
`RTPFLUX_BIN` to test another binary.

Every line of output is one of four kinds:

- `PASS` / `FAIL`: a documented behaviour holds or does not. Any `FAIL`
  makes the script exit non-zero.
- `NOTE`: a **finding**, behaviour worth a human look. It is not wrong by
  the docs, but it is surprising, lenient, or a sharp edge for operators.
- `SKIP`: needs something missing here (root for XDP, `redis-server`, a
  browser).

## Caveats

What these scenarios show an operator must know; each is described in
its scenario's README.

- **Latching (02):** a NAT rebinding after the 3 s learning window is not
  followed unless the proxy sends `media-handover`, and without
  `strict-source` a third party's packets to a latched port are relayed.
- **Free-form SDP attributes (06)** keep internal addresses: remove them
  in the proxy, or with `sdp-attr`.
- **The state file (09)** is written at most once a second: a crash can
  lose the last second of changes.
- **BUNDLE (13):** a phone's re-INVITE to a bundled browser must repeat
  the browser's profile, and dropping a stream from a bundle replaces the
  session's ports.
- **Multi-party calls (26):** a new leg is offered from the new party's
  tag; an offer from an existing party with a new `to-tag` re-offers that
  party's dialog instead.

## Not covered here

- The XDP fast path and AF_XDP need root: run `./scripts/xdp-e2e.sh`.
- Redis is covered by the stand-in in `lib/fakeredis.py` (scenario 14)
  unless `redis-server` is installed. OpenSIPS's `siprec` sequence is
  played by scenario 10 (the Docker bench, scenario 23, places a plain
  call through OpenSIPS).
