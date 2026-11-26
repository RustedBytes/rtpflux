# rtpflux-xdp

The userspace side of the XDP fast path: it loads the kernel program,
attaches it to network devices, and turns settled media streams into
entries in its flow table.

## Why it is a crate of its own

The fast path lets established plain-RTP calls be relayed inside the
network driver, without ever reaching userspace. Talking to the kernel
for that (BPF maps, netlink, `AF_XDP` sockets) needs `unsafe` code and
Linux-only libraries. Keeping it here confines both:

- **`unsafe` only in two modules**, each `unsafe` with a `// SAFETY:`
  comment: `pod` (the `aya::Pod` impls of the map key and value, whose
  layout is asserted at compile time) and `xsk` (memory shared with the
  kernel by an `AF_XDP` socket). Everything above them is safe code.
- The daemon depends on a safe API and never touches BPF directly.

## What is inside

| Module | What it does |
|---|---|
| `entry` (crate root) | A relayed stream as flow-table entries (one per direction) |
| `loader` | Loads the program (with `aya`), attaches it (native or generic mode), and manages its maps |
| `neigh` | MAC addresses for the rewrite: the interface's own, and the next hop's from the kernel's route and neighbour tables (IPv4 and IPv6) |
| `xsk` | `AF_XDP` receive sockets for calls the program does not relay (encrypted, WebRTC, BUNDLE), with the `af-xdp` feature |
| `testframe` | Builds test frames for `xdp-selftest` |
| `pod` | The `aya::Pod` wrappers of the map types |

## The `xdp-selftest` tool

`src/bin/xdp-selftest.rs` runs the real program in the kernel on generated
frames (`BPF_PROG_TEST_RUN`: nothing is attached and no traffic is
touched). It checks every result, byte for byte, against the safe
reference in `rtpflux-xdp-common`:

```sh
(cd crates/rtpflux-xdp-ebpf && cargo build --release)
cargo build -p rtpflux-xdp --bin xdp-selftest
sudo target/debug/xdp-selftest        # needs root, or CAP_BPF + CAP_NET_ADMIN
```

## Features

- `af-xdp`: `AF_XDP` receive sockets, through `xdpilone` (EUPL-1.2). Off
  by default.

## Used by

The daemon (`rtpflux`), when `[xdp] enabled = true`. See
[XDP fast path](../../docs/xdp.md).
