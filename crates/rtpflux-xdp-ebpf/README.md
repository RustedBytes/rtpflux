# rtpflux-xdp-ebpf

The XDP program: rtpflux's kernel fast path. It relays the packets of
established media streams inside the network driver, before the kernel's
network stack sees them.

## Why it is a crate of its own

It is not ordinary Rust. It is built for the BPF target
(`bpfel-unknown-none`), runs in the kernel, and must pass the kernel's
verifier. That needs things the rest of the workspace must not have:

- **Its own toolchain:** a pinned nightly (`rust-toolchain.toml`), because
  the BPF target needs `-Z build-std`. The workspace stays on stable.
- **Outside the workspace**, with its own `Cargo.lock` and
  `.cargo/config.toml` (target, `build-std`, and BTF generation through
  `bpf-linker`).
- **`unsafe` throughout**, as raw packet access requires. Every access is
  bounds-checked against `data_end`, and the raw-pointer helpers are
  `unsafe fn`s whose contract each call site states.

## What it does

For each IPv4/UDP datagram without options or fragments, and each IPv6
datagram with UDP right after the fixed header, whose payload starts like
RTP or RTCP, it looks up the five-tuple in the `RTPFLUX_FLOWS` map. On a
hit it rewrites the MAC addresses, IP addresses and UDP ports, sets a
fresh TTL or hop limit, and updates the checksums incrementally (RFC
1624). It then sends the frame back out of the same device (`XDP_TX`) or
redirects it to another one (`XDP_REDIRECT`). Everything else goes to the
kernel stack (`XDP_PASS`), and so to the userspace relay.

A flow's flags can send its telephone events up to userspace (which
detects them), drop the flow while still counting it, and copy its
payloads into the recording ring (`RTPFLUX_RECORD`). Packets for a
steered relay port that no flow relays go to the relay's `AF_XDP` socket
(`RTPFLUX_STEER`, `RTPFLUX_XSKS`) when it has one.

The decisions come from `rtpflux-xdp-common`, which also holds safe
reference versions of this logic. Every change here needs the matching
change there.

## Building and checking

```sh
cd crates/rtpflux-xdp-ebpf
cargo build --release          # needs bpf-linker
cargo clippy --release         # pedantic, must be warning-free

# Through the kernel verifier (needs root; attaches nothing):
sudo bpftool prog load target/bpfel-unknown-none/release/rtpflux-xdp \
    /sys/fs/bpf/rtpflux_test type xdp && sudo rm /sys/fs/bpf/rtpflux_test
```

Then run `xdp-selftest` (see `rtpflux-xdp`) and `scripts/xdp-e2e.sh`.

Its maps are BTF-defined (`#[btf_map]`), so both `bpftool` and the `aya`
loader can read them.

## Loaded by

`rtpflux-xdp`, for the daemon. See [XDP fast path](../../docs/xdp.md).
