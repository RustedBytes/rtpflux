# XDP fast path

Normally every media packet travels from the network card up to the
rtpflux process and back down again. For simple calls, rtpflux can
instead load a small program into the network driver with **XDP**
(eXpress Data Path). That program rewrites and forwards the call's
packets itself, so they never reach userspace. This saves most of the CPU
time a relay spends per packet.

In a benchmark with 4,000 calls (400,000 packets per second), the relay
process used 7% of one CPU with the fast path and 400% without it. See
[Benchmarks](benchmarks.md).

## Which calls use it

A call moves into the kernel once **both directions are settled**: the
relay knows where each side's media comes from and where to send it.
Until then, and for any call the fast path cannot handle, packets go
through userspace as usual.

The fast path handles plain RTP only. A call stays in userspace if it:

- uses SRTP or DTLS-SRTP (encryption is not done in the kernel);
- uses BUNDLE;
- has transcoding active;
- mixes IPv4 and IPv6 between its two sides.

If a call starts one of these features later (for example a
re-INVITE that needs transcoding), it is taken out of the kernel again.
The relay can still receive such calls through
[AF_XDP](#af_xdp-for-the-other-calls), skipping most of the kernel's
network stack.

Other features keep the call in the kernel and change what the program
does with one side's packets:

- **DTMF detection.** Telephone events (RFC 4733: packets with the
  side's telephone-event payload type) go up to the relay, which detects
  the digits and forwards the events itself. The audio stays in the
  kernel.
- **Blocking media** (`block media`). The kernel drops the side's
  packets. They are still counted, so the media timeout does not end
  the call.
- **Blocking DTMF** (`block DTMF`). The events go up to the relay,
  which drops them; the audio stays in the kernel.
- **Announcements** (`play media`). While an announcement plays to one
  side, the kernel drops the other side's media towards it. The relay
  sends the announcement. When it ends, forwarding resumes.
- **Recording** (`start recording`). The kernel copies each datagram's
  payload (up to 1,504 octets) into a ring buffer shared with the relay,
  then relays it as usual. The relay reads the ring every 10 ms while a
  recorded call is in the kernel and writes the packets into the call's
  recording, with the time the kernel received them. The ring holds
  about 2,700 packets; if it fills up, the kernel skips the copies (the
  packets are still relayed) and the recording has gaps.

These changes take effect while the call stays in the kernel: the relay
updates the call's flows, it does not remove them.

What the program does with each packet:

- **Same network device:** the packet is rewritten (addresses, ports,
  checksums) and sent straight back out of the card it arrived on
  (`XDP_TX`).
- **Another device:** when the two sides of a call use different
  interfaces, the packet is sent out of the other device
  (`XDP_REDIRECT`). Both devices must be listed in `[xdp] devices`.
- **Anything else** (unknown flows, STUN, DTLS, RTCP of other calls,
  malformed packets) is passed up to the kernel's network stack and the
  relay as if XDP were not there.

The kernel counts each forwarded flow's packets. The relay reads these
counters, so `query` shows correct statistics and the media timeout does
not end calls that are busy in the kernel.

## Supported traffic

- IPv4 and IPv6 UDP.
- For IPv6, only packets with UDP directly after the fixed header (no
  extension headers) and a non-zero UDP checksum. IPv4-mapped addresses
  are not offloaded.
- The next hop's MAC address comes from the kernel's tables: the routing
  table and ARP cache for IPv4, and the routing table and a netlink
  neighbour dump for IPv6. Among equally specific routes, the one with
  the lowest metric is used, as the kernel does. Policy routing
  (`ip rule`, routing tables other than `main`) is not followed: if you
  use it, check that offloaded calls leave through the right gateway.
- Every 30 seconds the relay looks the next hops up again and updates the
  calls whose next hop's MAC address changed (a gateway failover, a moved
  address), since offloaded packets never pass through the kernel's
  stack to notice.

> **Status.** IPv4 and IPv6, on one device (`XDP_TX`) and across two
> (`XDP_REDIRECT`), pass the end-to-end kernel tests: real calls through
> virtual Ethernet pairs in generic XDP mode. The IPv4 path on one device
> has also been benchmarked. The per-flow flags (DTMF, blocking,
> announcements) and the recording ring are checked in the kernel by
> `xdp-selftest` on generated frames, not yet by end-to-end calls. Native
> (driver) mode on a real network card has not been tested; run the
> [kernel tests](#testing-it) on your hardware before relying on it.

## AF_XDP for the other calls

The kernel cannot relay encrypted, WebRTC or BUNDLE calls: their keys,
DTLS handshakes and ICE checks live in the relay. With `af_xdp = true`
(and a build with the `af-xdp` cargo feature), their packets still skip
most of the kernel's network stack on the way in:

1. The relay opens one **AF_XDP socket** for each receive queue of the
   first device in `devices`.
2. The XDP program sends every datagram addressed to the relay's port
   range on that device, which no kernel flow relays, straight to the
   socket of the queue it arrived on. Kernel flows (plain calls) come
   first and are not affected.
3. A receive thread per queue checks each datagram as the kernel would
   (IP and UDP checksums, lengths) and hands it to the worker that owns
   the port. The worker handles it exactly as if its UDP socket had
   received it: STUN, DTLS, SRTP, BUNDLE and recording all work the same.
4. Replies and relayed packets leave through the workers' UDP sockets as
   before. Only the receive side changes.

If a queue has no socket, or a datagram arrives on another device, the
program passes it to the kernel's stack as usual, so nothing is lost when
AF_XDP is not available.

Each queue's socket has its own memory (8 MiB by default, see
`af_xdp_frames`), allocated when the relay starts and kept until it exits.
AF_XDP sockets need `CAP_NET_RAW` besides the XDP capabilities, and the
memory counts against the locked-memory limit: under systemd, add
`CAP_NET_RAW` to the unit's capabilities, `AF_XDP` to
`RestrictAddressFamilies`, and raise `LimitMEMLOCK=` (the shipped unit
explains this in a comment).
When a worker falls behind, its queue of received datagrams (1,024
datagrams) fills up and the newest are dropped and counted in the
`dropped` statistic.

> **Licence.** The AF_XDP sockets use the
> [xdpilone](https://crates.io/crates/xdpilone) crate, which is under the
> EUPL-1.2. The EUPL lists the GPL-3.0 as a compatible licence, so it can
> be combined with rtpflux (GPL-3.0-only). The feature is off by default
> and not in the Docker image because it is new and untested on real
> network cards.

> **Status.** In the kernel, `xdp-selftest` (built with `--features
> af-xdp`) checks the steering, including the redirect to a real AF_XDP
> socket on the loopback device. In userspace, tests check that frames
> given to the receive threads are relayed like socket traffic. The whole
> path has not yet carried real calls, on virtual or physical network
> cards, and has not been benchmarked.

## Building the program

The XDP program is a separate crate, `crates/rtpflux-xdp-ebpf`, built
for the BPF target. It needs a nightly Rust toolchain (pinned in that
directory's `rust-toolchain.toml`) and `bpf-linker`:

```sh
cargo binstall bpf-linker      # its release binary (needs cargo-binstall)
cd crates/rtpflux-xdp-ebpf
cargo build --release
```

`cargo install bpf-linker` works too, but builds against your system's
LLVM, which must be the version bpf-linker expects (with its development
files); the release binary carries its own. CI uses `bpf-linker` 0.13.0.

The result is `crates/rtpflux-xdp-ebpf/target/bpfel-unknown-none/release/rtpflux-xdp`.
Install it where the configuration expects it:

```sh
sudo install -D -m 644 target/bpfel-unknown-none/release/rtpflux-xdp \
    /usr/lib/rtpflux/rtpflux-xdp
```

## Enabling it

```toml
[xdp]
enabled = true
devices = ["eth0"]          # every device media can arrive on or leave by
mode = "native"             # "generic" works with any driver, but slower
object = "/usr/lib/rtpflux/rtpflux-xdp"
```

- `native` runs in the network driver and is the fast option. Your
  driver must support XDP; most modern server NICs do.
- `generic` runs a little later in the kernel and works with any device,
  including virtual ones. It is useful for testing.
- The kernel's flow table holds 65,536 entries and each call needs 4, so
  `sessions.max` can be at most 16,384 with XDP enabled.

Loading and attaching the program needs the capabilities `CAP_BPF`,
`CAP_NET_ADMIN` and `CAP_PERFMON`. The [systemd unit](operations.md#systemd)
grants exactly these.

## Testing it

Both tests need root.

**`xdp-selftest`** loads the program into the kernel without attaching it
to any device. It runs it on generated frames and compares every result
with the reference implementation in `rtpflux-xdp-common`: rewrites,
passes, the per-flow flags (events going up, dropping) and the copies
in the recording ring:

```sh
cargo build
sudo target/debug/xdp-selftest
```

**`scripts/xdp-e2e.sh`** runs real calls through the fast path in
network namespaces. It uses two virtual Ethernet pairs and covers IPv4
and IPv6, on one device and across two. It checks that calls are
offloaded once settled, keep flowing intact, stay alive on kernel-only
traffic and time out cleanly:

```sh
./scripts/xdp-e2e.sh                    # generic XDP
XDP_MODE=native ./scripts/xdp-e2e.sh    # driver mode
```

The script builds as your user and calls `sudo` itself for the
namespaces.
