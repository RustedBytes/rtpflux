# Configuration

rtpflux reads one TOML file, by default `/etc/rtpflux/rtpflux.toml`. Pass
another path with `-c`:

```sh
rtpflux -c /path/to/rtpflux.toml           # run
rtpflux --check -c /path/to/rtpflux.toml   # validate and exit
rtpflux --print-example-config             # print the commented example
```

The commented example is also in the repository as
[`config/rtpflux.toml`](https://github.com/RustedBytes/rtpflux/blob/main/config/rtpflux.toml).

## Rules

- Every section is optional except `[[interface]]`. A missing key takes
  its default value (shown below).
- Unknown keys are an error. That catches typos such as `adress`.
- `--check` reports every problem at once, not just the first:

```text
rtpflux: bad.toml: invalid configuration:
  - interface 'a': address must be a concrete address
  - ports.min: must be even and non-zero (RTP on even, RTCP on odd ports)
  - ports: 5 RTP/RTCP pairs cannot serve sessions.max = 100 (two pairs per call)
```

- Besides the per-key ranges below, the check rejects listeners that
  clash (two sockets of one transport on the same port, with the same
  address or a wildcard), a `control.listen` port inside the media port
  range of an interface on the same address, `xdp.devices` entries that
  are not device names, and interface names with whitespace.
- Settings that are valid but probably not what was meant are
  **warnings**: they never stop the relay. `--check` prints them on
  stderr and still reports the file as valid; at start-up they are
  logged at `warn`. They cover `ng` listeners reachable beyond loopback
  and private networks, a web UI not on loopback, Redis without a
  password or on another host, settings that have no effect (for
  example `xdp.devices` with `enabled = false`, `bitrate` for a lossless
  format, `[recording.s3]` with local storage), more `workers` than the
  port range can use, ports below 1024, and relative paths.

```text
rtpflux: rtpflux.toml: warning: webui.listen: 0.0.0.0:8090 is not loopback; the login travels without TLS unless a reverse proxy adds it
rtpflux.toml: configuration is valid
```

## `[control]`: the SIP proxy's connection

```toml
[control]
listen = ["127.0.0.1:2223"]   # default
listen_tcp = []               # ng over TCP (none by default)
listen_http = []              # ng over HTTP and WebSocket (none by default)
max_message = 65535           # largest command, in bytes (512 to 65535)
# native_socket = "/run/rtpflux/native.sock"   # the native API (off by default)
native_uids = []              # user ids allowed on native_socket, besides the relay's and root
native_max_endpoints = 0      # endpoints per tenant on the native API (0: up to sessions.max)
# pcm_dir = "/run/rtpflux/pcm"  # where external audio services listen (PCM streams)
native_listen = []            # the native API over TCP too (needs native_tokens)
native_tokens = {}            # tenant = "token" (16 characters or more), for native_listen
```

`listen` takes one or more `address:port` pairs. The ng protocol has no
authentication, so listen only on loopback or a private network that only
your SIP proxies can reach. `listen_tcp` and `listen_http` serve the same
commands over TCP, and over HTTP (`POST /ng`, `/ng-plain`) and WebSocket
(`ng.rtpengine.com`); see
[Over TCP, HTTP and WebSocket](control-protocol.md#over-tcp-http-and-websocket).

`native_socket` serves the [native control API](native-api.md), for a
B2BUA or softswitch that manages media endpoints itself. It is a Unix
socket, created mode 0600: only the relay's own user, root and the user ids
in `native_uids` may connect (checked with the peer's credentials).
`native_listen` serves the same API over TCP, for a softswitch on another
host. Each connection authenticates with one of `native_tokens` first, and
is then that tenant's. There is no TLS: use a private network or a TLS
proxy. `pcm_dir` is the directory where external audio services listen
for [PCM streams](native-api.md#pcm-streams); a stream names its socket by
its file name there.

## `[[interface]]`: where media flows

Each `[[interface]]` block is a named local address. You need at least
one.

```toml
[[interface]]
name = "external"
address = "203.0.113.10"
```

| Key | Meaning |
|---|---|
| `name` | Name used by the proxy to pick the interface (`direction`). Must be unique. |
| `address` | Local IPv4 or IPv6 address the media sockets bind to. Must be a real address, not `0.0.0.0`. |
| `advertise` | Address written into the SDP. Defaults to `address`. |

**Example: behind a 1:1 NAT.** Many cloud servers have a private address
on the network card and a public address mapped onto it. Bind to the
private one and advertise the public one:

```toml
[[interface]]
name = "public"
address = "10.0.0.5"          # on the network card
advertise = "198.51.100.20"   # what phones must send to
```

**Example: bridging two networks.** A relay with one leg on the internet
and one on an internal network:

```toml
[[interface]]
name = "external"
address = "203.0.113.10"

[[interface]]
name = "internal"
address = "10.0.0.5"
```

The proxy then chooses per call with the `direction` option, for example
`direction=external direction=internal` in Kamailio. The first name is
the offerer's side and the second the answerer's. Without `direction`,
both sides use the first interface. See
[Control protocol](control-protocol.md#offer).

## `[ports]`: the media port range

```toml
[ports]
min = 30000   # default; must be even
max = 60000   # default
```

RTP uses even ports and RTCP the next odd port. Each call needs two
pairs, one for each side, so the range must hold at least
`2 × sessions.max` pairs. The defaults give 15,000 pairs, enough for the
default 5,000 sessions. Open this range in your firewall.

## `[sessions]`: limits and timeouts

```toml
[sessions]
max = 5000             # most calls at once
timeout = 60           # seconds without media before a call ends
silent_timeout = 3600  # the media timeout of calls on hold
final_timeout = 0      # the longest a call may last (0: no limit)
offer_timeout = 3600   # seconds an offer waits for its answer
strict_source = false  # every call as if flagged strict-source
# state_file = "/var/lib/rtpflux/state.json"
# redis = "redis://:password@127.0.0.1:6379/0"
# redis_key = "rtpflux:state"
```

- `timeout` ends an answered call whose media stopped in both directions.
  That protects against proxies that never send `delete`, for example
  after a crash. It counts from the answer, so a call that rang for a
  long time is not ended the moment it is answered.
- `offer_timeout` ends an offer that is never answered, this long after
  the offer, whether or not early media flows. While a call rings, the
  media timeout does not apply. The default (an hour) is rtpengine's.
- When a call ends on its own like this, its dialog is removed too:
  later commands for it get "unknown call", and its ports can serve new
  calls.
- `silent_timeout` replaces `timeout` for a call on hold: a media section
  that either party offered or answered `sendonly`, `recvonly` or
  `inactive`, or with the address `0.0.0.0`. A held call without music on
  hold sends nothing, so it would otherwise end after `timeout`. When the
  call is resumed (`sendrecv` again), `timeout` applies again. It must
  not be shorter than `timeout`.
- `final_timeout` ends a call this many seconds after its first offer,
  whatever its media (0, the default: no limit).
- `strict_source = true` treats every call as if the proxy sent the
  `strict-source` flag: once the relay has learned a side's address from
  its media, media from any other source is dropped, so a third party
  cannot inject audio into a call. The cost: a phone whose NAT mapping changes mid-call is not
  followed. See [NAT and latching](media.md#nat-and-latching).
- `max` is the most calls (dialogs) at once: an offer for a new call
  beyond it is refused with `session limit reached`; re-offers of
  existing calls always pass.
- `state_file` keeps calls across restarts. See
  [Operations](operations.md#restarts).
- `redis` keeps the same state in Redis, as well as or instead of the
  file: `redis://[[user]:password@]host[:port][/db]` (port 6379 and
  database 0 by default; `rediss://` with TLS is not supported).
  `redis_key` is the key (default `rtpflux:state`); give each relay its
  own. See [Operations](operations.md#state-in-redis).

## `[runtime]`: threads and buffers

Everything here is allocated once at start-up; nothing grows while calls
run.

```toml
[runtime]
workers = 0            # media threads; 0 = one per CPU
batch = 32             # packets per receive/send system call (1 to 64)
ring_capacity = 4096   # packet slots per worker (a power of two)
packet_buffer = 2048   # bytes per packet buffer (1500 to 65535)
receive = "io_uring"   # or "recvmmsg"
```

The defaults suit most systems. A smaller `workers` value leaves CPUs for
other services on the same host.

`receive` chooses how the media workers read their sockets:

- `io_uring` (the default; Linux 6.0 or later): one multishot receive per socket keeps
  receiving into a ring of `ring_capacity` buffers per worker (each
  `packet_buffer` plus 144 octets), and the datagrams of every socket are
  read from one completion queue, with no system call per socket or
  packet. A worker whose kernel lacks it, or where it is not allowed,
  logs a warning and uses `recvmmsg`. Docker's default seccomp profile
  does not allow it: in a container, see
  [Getting started](getting-started.md#5b-or-run-it-in-a-container). It costs the buffers' memory (9 MB per worker with the
  defaults).
- `recvmmsg`: epoll says which sockets have datagrams, and each is read in
  batches of up to `batch`, one system call per socket per batch. With
  many calls, each socket has a packet or two at a time, so that is about
  one system call per packet.

On an Intel Xeon E5-1620 v3 (4 cores, 8 threads; Linux 7.0, loopback,
172-octet datagrams),
`cargo bench -p rtpflux-uring` measured the receiving thread's CPU time
per datagram:

| Load | `recvmmsg` | `io_uring` |
|---|---|---|
| 1 socket, flooded | 2.6 µs | 2.2 µs (1.2×) |
| 16 sockets, 100 000 packets/s | 3.1 µs | 2.2 µs (1.4×) |
| 256 sockets, 100 000 packets/s | 3.7 µs | 2.3 µs (1.6×) |
| 1024 sockets, 100 000 packets/s | 3.7 µs | 2.3 µs (1.6×) |
| 4096 sockets, 200 000 packets/s | 3.7 µs | 2.7 µs (1.4×) |

Measure on your own hardware: the gain depends on the
kernel, the NIC and how many calls each worker carries. Sending is
`sendmmsg` either way, and calls in the [XDP fast path](xdp.md) do not
reach the workers at all.

## `[xdp]`: the kernel fast path

```toml
[xdp]
enabled = false                         # default
devices = ["eth0"]                      # required when enabled
mode = "native"                         # or "generic"
object = "/usr/lib/rtpflux/rtpflux-xdp" # the compiled XDP program
af_xdp = false                          # AF_XDP receive path (af-xdp builds)
af_xdp_frames = 2048                    # AF_XDP memory per queue, 4 KiB frames
```

`af_xdp` receives the traffic the kernel does not relay (SRTP, WebRTC,
BUNDLE, calls not settled yet) through AF_XDP sockets on the first device
in `devices`, instead of the kernel's UDP stack. It needs `enabled = true`
and a build with the `af-xdp` cargo feature. `af_xdp_frames` (64 to
65,536) is the memory of each receive queue's socket, in 4 KiB frames:
the default 2,048 frames is 8 MiB per queue.

With XDP enabled, `sessions.max` can be at most 16,384, because the
kernel's flow table holds 65,536 entries and each call uses 4. See
[XDP fast path](xdp.md).

## `[log]`: logging

```toml
[log]
level = "info"    # error, warn, info, debug or trace
format = "full"   # or "compact"
```

The `-l`/`--log-level` option overrides `level`, and so does the
`RUST_LOG` environment variable. See [Operations](operations.md#logs).

## `[metrics]`: Prometheus metrics

```toml
[metrics]
listen = ["127.0.0.1:9101"]   # default: [] (off)
```

Serves `GET /metrics`. See [Operations](operations.md#metrics).

## `[webui]`: the web UI

```toml
[webui]
listen = "127.0.0.1:8090"   # default: none (off)
user = "admin"              # required with listen
password_hash = "sha256:…"  # required with listen: rtpflux --webui-hash
realm = "rtpflux"           # the login prompt's realm
max_connections = 64        # concurrent HTTP connections (1 to 4096)
refresh_ms = 2000           # how often the pages refresh (500 to 60000)
log_buffer = 2000           # log lines kept for the Logs page (0: off)
```

A read-only website showing traffic, calls, statistics and logs. Keep it
on `127.0.0.1` or behind a TLS reverse proxy: the login is sent with
every request. See [Web UI](webui.md).

## `[recording]`: call recordings

```toml
[recording]
dir = "/var/spool/rtpflux"
format = "pcap"       # pcap, wav, flac, opus or mp3
channels = "stereo"   # or mono
sample_rate = 8000    # 8000, 16000, 24000 or 48000
bitrate = 32          # kbit/s, for opus and mp3
keep_pcap = false     # keep the pcap once converted
storage = "local"     # or "s3"
file_name = "{call_id}-{from_tag}-{section}"   # the default

[recording.metadata]  # tags in every recording (optional)
company = "Example Ltd"

[recording.s3]        # with storage = "s3"
bucket = "call-recordings"
region = "eu-west-1"
# endpoint = "https://minio.example.com"   # S3-compatible servers
prefix = "rtpflux/"
path_style = false
keep_local = false

[recording.s3.webhook]  # optional: notify after each upload
url = "https://hooks.example.com/recordings"
timeout_ms = 5000           # each attempt, DNS to response
connect_timeout_ms = 2000
attempts = 5
backoff_ms = 1000           # doubled per retry, jittered
backoff_max_ms = 30000
queue = 1000
```

`dir` is where `start recording` writes. It is created at start; without
it, recording requests are refused. The other keys choose what a
recording becomes when it ends; `start recording` can override each of
them per call. `mp3` needs a build with the `mp3` feature.

`file_name` names the files (without the extension). It is text made of
letters, digits and `. - _ @`, and the placeholders `{call_id}`,
`{from_tag}`, `{to_tag}`, `{section}`, `{date}` (`2026-11-25`), `{time}`
(`142530`, both UTC, when the recording starts) and `{timestamp}` (Unix
seconds). Values are made file-name safe as before. A name that a file
already has is never reused: the next recording of it gets `-2`, `-3`,
…, so even a template without the call-id never mixes two recordings
(`--check` warns about one without `{call_id}` and `{section}`). For
example, `"{date}_{time}-{call_id}-{section}"` sorts by time.

`[recording.metadata]` holds tags every recording carries, in its JSON
and embedded in its audio file; see
[Recording metadata](call-features.md#recording-metadata).

`storage = "s3"` uploads finished recordings to a bucket and removes the
local copies; it needs a build with the `s3` feature, and credentials in
the environment (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`). See
[Storing recordings in S3](call-features.md#storing-recordings-in-s3).
`[recording.s3.webhook]` posts a notification after each upload; see
[Upload notifications](call-features.md#upload-notifications-webhook).

## `[ice]`: ICE towards endpoints that use it

| Key | Default | Meaning |
|---|---|---|
| `mode` | `"full"` | `"full"`: the relay is a full ICE agent (it checks the endpoint's candidates, nominates or accepts a nomination, keeps checking consent); `"lite"`: it only answers checks. The `ICE-lite` option overrides it per call. See [ICE](media.md#ice). |
| `pacing_ms` | `50` | Ta: how often the relay's agents send a new check (5–1000 ms) |
| `stun_server` | none | A STUN server (`host:port`) the relay asks for its public address on each interface without `advertise`, at start and every 5 minutes; it is offered as a server-reflexive candidate |

```toml
[ice]
mode = "full"
pacing_ms = 50
# stun_server = "stun.example.net:3478"
```

The server-reflexive candidate uses the media port itself, so it is right
behind a NAT that keeps ports (a 1:1 NAT, or an endpoint-independent one
that preserves them). Elsewhere it does no harm: the endpoint's checks to
the host candidate still find their way, and the relay learns the address
they come from. With a known public address, set `advertise` on the
interface instead.

## A complete example

A relay on a cloud server behind NAT, with an internal leg, metrics,
restarts and recording:

```toml
[control]
listen = ["10.0.0.5:2223"]

[[interface]]
name = "external"
address = "10.0.0.5"
advertise = "198.51.100.20"

[[interface]]
name = "internal"
address = "10.1.0.5"

[ports]
min = 20000
max = 40000

[sessions]
max = 4000
state_file = "/var/lib/rtpflux/state.json"

[metrics]
listen = ["10.0.0.5:9101"]

[recording]
dir = "/var/spool/rtpflux"
```
