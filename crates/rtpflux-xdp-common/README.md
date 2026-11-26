# rtpflux-xdp-common

What the XDP fast path's kernel program and its userspace loader must
agree on: the layout of the BPF maps, and the per-packet arithmetic.

## Why it is a crate of its own

The XDP program (`rtpflux-xdp-ebpf`) runs inside the kernel and is built
for the BPF target; the loader (`rtpflux-xdp`) is ordinary userspace
code. They share maps, so a field in the wrong place or the wrong byte
order would silently corrupt packets. Putting the shared definitions in
one `no_std` crate that both build from rules that out.

It also holds **safe reference versions** of the program's logic
(`classify`, `rewrite`, `decide`). The kernel program cannot be unit
tested in the usual way, but these can: their tests check, for example,
that both checksums stay valid after a rewrite. `xdp-selftest` then runs
the real program in the kernel on generated frames and requires its
output to equal the reference's, byte for byte.

- **`no_std`, no `alloc`.** It has to build for the BPF target.
- **Network byte order** in every map field.
- **Panic-free arithmetic and indexing**, denied by Clippy outside tests.

## What is inside

| Item | What it does |
|---|---|
| Map keys and values | The flow table's five-tuple key and its rewrite entry (`repr(C)`, no padding), IPv4 as IPv4-mapped IPv6 so one map serves both |
| `flags` | Per-flow flags: send telephone events up, drop the flow, copy it to the recording ring |
| `record_layout` | The layout of the recording ring's records |
| `offsets` | Header offsets for IPv4 and IPv6 frames |
| `classify`, `rewrite`, `decide` | The safe reference versions of what the program does to a frame |
| Checksum helpers | Incremental checksum updates (RFC 1624), with a simple reference to compare against |

## Used by

The XDP program (`rtpflux-xdp-ebpf`), the loader (`rtpflux-xdp`), and the
daemon (`rtpflux`).

## Testing

```sh
cargo test -p rtpflux-xdp-common
```

Every change to the XDP program needs the matching change here, with
tests that check the result.
