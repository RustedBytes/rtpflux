# Getting started

This guide takes you from source code to a running relay. It also walks
through what happens during a call.

## 1. Requirements

- Linux (the relay uses `epoll` and `recvmmsg`/`sendmmsg`).
- Rust. The exact version is pinned in `rust-toolchain.toml`; `rustup`
  installs it automatically the first time you build.

rtpflux is written entirely in Rust, including its cryptography (SRTP,
DTLS, Opus), so it needs no C libraries or C compiler. Two optional
features need a C compiler: `mp3` (MP3 recordings, through LAME) and
`s3` (recordings uploaded to S3, over rustls and ring):
`cargo build --release --features mp3,s3`. The `amr` feature (pure Rust)
adds AMR and AMR-WB transcoding; it is off by default because of AMR's
patents.

The optional XDP fast path has extra requirements; see
[XDP fast path](xdp.md).

## 2. Build

```sh
git clone https://github.com/RustedBytes/rtpflux.git
cd rtpflux
cargo build --release
```

The binary is `target/release/rtpflux`. To make sure everything works on
your machine, run the tests:

```sh
cargo test --workspace
```

## 3. Configure

The configuration is a TOML file. Print the fully commented example and
edit it:

```sh
./target/release/rtpflux --print-example-config > rtpflux.toml
```

Only `[[interface]]` is required. A relay with one public address can be
as short as this:

```toml
[control]
listen = ["127.0.0.1:2223"]

[[interface]]
name = "default"
address = "203.0.113.10"
```

- `[control] listen` is where the SIP proxy sends its commands. Keep it on
  a private address: the ng protocol has no authentication.
- `[[interface]] address` is the local address media uses. If the server
  is behind a 1:1 NAT (common in clouds), also set `advertise` to the
  public address. That is the address written into the SDP.

Check the file before starting:

```sh
./target/release/rtpflux --check -c rtpflux.toml
```

```text
rtpflux.toml: configuration is valid
```

If something is wrong, `--check` lists every problem at once, for example
a port range too small for the number of sessions. See
[Configuration](configuration.md) for all options.

## 4. Run

```sh
./target/release/rtpflux -c rtpflux.toml
```

```text
INFO rtpflux: rtpflux 0.1.0 starting: 1 interface(s), ports 30000-60000, up to 5000 sessions, xdp off
INFO rtpflux::relay: relay: 8 worker(s), 1875 port pairs each
INFO rtpflux: ng control on udp 127.0.0.1:2223
```

Use `-l debug` (or `RUST_LOG=debug`) for more detail. Stop the relay with
Ctrl-C or `SIGTERM`.

## 5. Install as a service

```sh
sudo install -m 755 target/release/rtpflux /usr/bin/rtpflux
sudo mkdir -p /etc/rtpflux
sudo cp rtpflux.toml /etc/rtpflux/rtpflux.toml
sudo cp contrib/rtpflux.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rtpflux
```

The unit checks the configuration before each start, runs the relay as an
unprivileged dynamic user and keeps state in `/var/lib/rtpflux`. See
[Operations](operations.md#systemd).

## 5b. Or run it in a container

The repository has a `Dockerfile` and a `compose.yaml`. The container uses
the **host network**: a relay opens ports from `[ports]` for every call
and writes the host's own address into the SDP, which port mapping cannot
do.

1. Edit `config/docker.toml`. Set `[[interface]] address` to an address
   of the host that phones can reach (it ships as `127.0.0.1`, for a
   local try-out).
2. Build and start:

   ```sh
   docker compose up -d --build        # or: docker-compose up -d --build
   docker compose logs -f rtpflux
   ```

The image is about 90 MB: the relay on Debian slim, running as an
unprivileged user. Two volumes keep data across restarts:

| Volume | Mounted at | Holds |
|---|---|---|
| `rtpflux-state` | `/var/lib/rtpflux` | The state file: calls survive `docker compose restart` |
| `rtpflux-recordings` | `/var/spool/rtpflux` | pcap recordings |

Without compose:

```sh
docker build -t rtpflux .
docker run -d --name rtpflux --network host --ulimit nofile=1048576:1048576 \
    -v "$PWD/config/docker.toml:/etc/rtpflux/rtpflux.toml:ro" \
    -v rtpflux-state:/var/lib/rtpflux rtpflux
```

Docker's default seccomp profile refuses `io_uring`, so in a container
the media workers receive with `recvmmsg`, logging `io_uring: Operation
not permitted; using recvmmsg` at start. Calls work either way; to use
`io_uring` (the default `runtime.receive`, a little less CPU per packet),
run the container with `--security-opt seccomp=unconfined`, or with a
seccomp profile that also allows `io_uring_setup`, `io_uring_enter` and
`io_uring_register`. The commented `security_opt` line in `compose.yaml`
shows where.

To use the [XDP fast path](xdp.md) in a container, grant `CAP_BPF`,
`CAP_NET_ADMIN` and `CAP_PERFMON`, run the container as root (added
capabilities do not reach the image's unprivileged user), and mount the
compiled program. The commented lines in `compose.yaml` show how.

## 6. Connect your SIP proxy

Point the proxy's `rtpengine` module at `[control] listen`. For Kamailio:

```text
loadmodule "rtpengine.so"
modparam("rtpengine", "rtpengine_sock", "udp:127.0.0.1:2223")
```

and call `rtpengine_manage()` for messages that carry SDP. The OpenSIPS
setup is almost the same; see
[Control protocol](control-protocol.md#using-rtpflux-with-a-sip-proxy).

## What happens during a call

Here is a real exchange with the relay, shown in readable form. On the
wire, each command is one *bencoded* UDP datagram.

**Alice calls Bob.** Alice's phone offers audio on `192.0.2.10:40000`.
The proxy sends this offer to rtpflux:

```text
command:  offer
call-id:  call-1@example.com
from-tag: alice-tag
sdp:
  v=0
  o=alice 1 1 IN IP4 192.0.2.10
  s=-
  c=IN IP4 192.0.2.10
  t=0 0
  m=audio 40000 RTP/AVP 0 101
  a=rtpmap:0 PCMU/8000
  a=rtpmap:101 telephone-event/8000
  a=sendrecv
```

rtpflux reserves ports and replies with a rewritten SDP. The address and
port now point at the relay (here `127.0.0.1:30002`):

```text
result: ok
sdp:
  v=0
  o=alice 1 1 IN IP4 192.0.2.10
  s=-
  c=IN IP4 127.0.0.1
  t=0 0
  m=audio 30002 RTP/AVP 0 101
  a=rtpmap:0 PCMU/8000
  a=rtpmap:101 telephone-event/8000
  a=sendrecv
```

The proxy sends this SDP to Bob instead of Alice's original. Bob will
send his audio to the relay.

**Bob answers.** The proxy passes Bob's answer (audio on
`198.51.100.20:50000`) to rtpflux with `command: answer` and both tags.
rtpflux rewrites it to point at another relay port, `30000`, and the
proxy sends that to Alice. Now:

```text
Alice 192.0.2.10:40000  ⇄  relay :30000 │ relay :30002  ⇄  Bob 198.51.100.20:50000
```

**During the call** the proxy can ask how the call is doing with
`command: query`. The reply lists each party's streams with the
relay's port, the peer's address, packet counters, detected DTMF and RTCP
statistics. See [Control protocol](control-protocol.md#query).

**Bob hangs up.** The proxy sends `command: delete` with the Call-ID. The
relay frees the ports.

If a party is behind NAT, the address in its SDP may be wrong. The relay
then *latches* onto the address its packets really come from; see
[Media handling](media.md#nat-and-latching).

## Next steps

- [Configuration](configuration.md): multiple interfaces, timeouts,
  metrics, recording and restarts.
- [Media handling](media.md): WebRTC, SRTP and NAT.
- [Call features](call-features.md): DTMF, recording, announcements and
  transcoding.
