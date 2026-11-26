# AGENTS.md — rtpflux

rtpflux is an RTP media relay for SIP deployments, controlled over the `ng`
protocol (bencoded commands over UDP, as used by the `rtpengine` modules of
Kamailio and OpenSIPS). Its purpose is to be **as fast as possible**: every
change is judged first on correctness, then on per-packet cost.

## 1. Before changing code

1. Read `README.md`, `Cargo.toml`, `rust-toolchain.toml` and the crate you
   are changing, including its tests.
2. Keep the pinned toolchains: the workspace uses Rust **1.100.0**
   (`rust-toolchain.toml`); only `crates/rtpflux-xdp-ebpf` uses its own pinned
   nightly (the BPF target needs `-Z build-std`). Do not change either without
   being asked.
3. Check crates.io for the current version before adding a dependency, pin
   it in `[workspace.dependencies]`, and disable default features you do not
   need.

## 2. Layout and layering

| Crate | Role | Allowed |
|---|---|---|
| `rtpflux-core` | protocol kernels: RTP/RTCP, SDP rewriting (incl. SDES keys), latching | `no_std`, no `alloc`, no I/O, no logging |
| `rtpflux-srtp` | SRTP/SRTCP transforms (RFC 3711), in place | `no_std`, no `alloc`, no I/O, no logging; RustCrypto primitives only, tags compared in constant time, key material never logged |
| `rtpflux-ng` | `ng` control protocol: bencode, commands | `no_std`, no `alloc`, no I/O |
| `rtpflux-xdp-common` | XDP map layout, per-packet arithmetic, safe reference versions of the XDP program | `no_std`, no `alloc` |
| `rtpflux-xdp` | userspace side of the fast path: map entries, loading, `AF_XDP` receive sockets (`af-xdp` feature), `xdp-selftest` | `std`; `unsafe` only in `pod` and `xsk` |
| `rtpflux-uring` | `io_uring` multishot UDP receive with a provided-buffer ring (`runtime.receive = "io_uring"`) and its benchmark | `std`; `unsafe` only in `ring` |
| `rtpflux-xdp-ebpf` | the XDP program (outside the workspace) | `no_std`, `unsafe` allowed throughout |
| `rtpflux` | daemon: sockets, timers, configuration, logging backend, DTLS handshakes | `std`; `dimpl` only for DTLS handshakes (`dtls.rs`), never on the media path; no C dependencies |

Protocol decisions live in the pure crates as functions over borrowed
input; the daemon only moves bytes and owns state. Do not let I/O, clocks,
randomness or global state leak into `rtpflux-core` or `rtpflux-ng`: pass
time and random values in as arguments.

## 3. Performance rules (hot path = anything run per packet)

**Zero-copy.**
- Parse into views that borrow the datagram (`rtp::Packet<'a>`,
  `bencode::Value<'a>`); expose fields through accessors that read the bytes.
  Never copy a payload to inspect or forward it.
- Rewrite in place (`rtp::set_ssrc`, `set_sequence`, …) instead of
  rebuilding packets. Build only when a new packet is unavoidable, and then
  into a caller-provided `&mut [u8]` (`rtp::write`, `bencode::Encoder`).
- Prefer `&[u8]`/`&mut [u8]` APIs over `Vec<u8>`/`String`, and iterators over
  collected vectors.

**Zero allocation.**
- No heap allocation per packet or per control message in steady state: no
  `Vec`, `String`, `Box`, `format!`, `to_vec`, `clone` of owned buffers on
  the hot path. The pure crates are `no_std` without `alloc`, so the
  compiler enforces this there; keep it that way.
- Allocate at startup or session setup (fixed-capacity tables, buffer
  pools), never while relaying.
- Errors are small `Copy` enums, not boxed or string errors.

**Ring buffers and fixed-capacity structures.**
- Use preallocated ring buffers for packet queues, receive/send batches,
  reordering windows and replay windows; use bitmaps for replay detection.
- Size them at startup from configuration; on overflow, drop and count,
  never grow on the hot path.
- Between threads, use single-producer/single-consumer rings; one owner per
  session, one session table shard per core. No locks on the hot path.

**I/O.**
- Batch system calls (`recvmmsg`/`sendmmsg` or `io_uring`); never one syscall
  per packet when a batch is possible.
- Established plain RTP streams belong in the XDP fast path
  (`rtpflux-xdp-ebpf`); userspace handles setup, SRTP, and anything the XDP
  program passes up.
- Crypto on the hot path uses hardware-accelerated, constant-time
  implementations (AES-NI / GCM).

**Measuring.**
- A claimed speed-up needs a measurement (`cargo bench` or a load test);
  keep the benchmark next to the code it measures.
- Mark small per-packet functions `#[inline]` where a benchmark shows it
  helps, not by default.

## 4. Logging

- Every crate logs through the `log` facade (`log::info!`, `log::debug!`, …).
  Only the daemon installs a backend: `tracing-subscriber`, filtered by
  `RUST_LOG` (default `info`), which also receives the `log` records.
- Never log per packet at `info` or above. Per-packet events are counters;
  if a log line is needed, use `trace!`, or rate-limit it.
- The pure crates (`rtpflux-core`, `rtpflux-ng`, `rtpflux-xdp-common`)
  return errors instead of logging; the caller decides what to log.
- Do not log secrets: SRTP keys, DTLS keys, credentials, full SDP with
  `a=crypto` lines.

## 5. Safety and correctness

- `unsafe` is denied in the workspace (`unsafe_code = "deny"`). Four
  exceptions, each with a `// SAFETY:` comment on every `unsafe`:
  - the XDP program (`rtpflux-xdp-ebpf`): every raw access is bounds-checked
    against `data_end`;
  - `rtpflux-xdp`'s `pod` module: the `aya::Pod` impls for the map key and
    value wrappers, whose layout (`repr(C)`, no padding) is asserted at
    compile time;
  - `rtpflux-xdp`'s `xsk` module (`af-xdp` feature): the `AF_XDP` socket's
    memory shared with the kernel. It allocates the area (never freed),
    hands it to xdpilone, and reads a frame only for a descriptor the
    kernel returned, inside the area, before the frame goes back to the
    fill ring. Everything above it (`relay::xsk`) is safe code.
  - `rtpflux-uring`'s `ring` module: the memory `io_uring` shares with
    the kernel. The provided buffers and their ring are allocated once and
    never freed (the kernel may use them until the ring is torn down); a
    received buffer is read only as a slice made for it, while it is out
    of the ring. Submitted entries point only at memory that lives as
    long as the program. Everything above it is safe code.
  Do not add `#[allow(unsafe_code)]` anywhere else. Every other crate has
  `#![forbid(unsafe_code)]` at its root, which no `allow` can undo. In
  `rtpflux-xdp`, `rtpflux-uring` and the XDP program, clippy denies an
  `unsafe` block
  without its `// SAFETY:` comment (and, in `rtpflux-xdp`, one doing more
  than one unsafe operation); the XDP program's raw-pointer helpers are
  `unsafe fn`s whose contract each call site states.
- Untrusted input (packets, `ng` messages, SDP) must never panic: no
  `unwrap`, `expect`, unchecked indexing or arithmetic that can overflow on
  input-derived values. Validate lengths first, use `checked_*` or slicing
  with `get`.
- Bound every recursion and loop driven by input (`bencode::MAX_DEPTH`).
- The pure crates (`rtpflux-ng`, `rtpflux-srtp`, `rtpflux-core`,
  `rtpflux-xdp-common`) deny unchecked indexing and arithmetic
  (`clippy::indexing_slicing`, `arithmetic_side_effects`) outside their
  tests, with no exceptions at run time (only `const fn` tables built at
  compile time may index, where a mistake is a build error). The lint
  misses slicing of const-generic arrays (`[T; N]`): use `get` there too; `tests/robustness.rs` fuzzes every parser of
  untrusted input and the live media path for panics.
- Byte order is explicit at every boundary (`from_be_bytes`,
  `to_be_bytes`); XDP map fields are in network byte order.
- XDP maps are BTF-defined (`#[btf_map]`, `aya_ebpf::btf_maps`), so both
  libbpf tools (`bpftool`) and the aya loader read them; the legacy `#[map]`
  section is rejected by libbpf 1.0+. The BPF build emits BTF
  (`-C debuginfo=2 -C link-arg=--btf`, in the crate's `.cargo/config.toml`).
- Every XDP program change has a matching change in the safe reference
  versions in `rtpflux-xdp-common` (`classify`, `rewrite`), whose tests check
  the result (e.g. both checksums stay valid).

## 6. Testing and checks

Run before reporting a change as done:

    cargo fmt --check
    cargo clippy --all-targets      # pedantic, must be warning-free
    cargo test                      # includes the conformance vectors
    (cd crates/rtpflux-xdp-ebpf && cargo clippy --release)   # when the XDP side changed (pedantic too)

`cargo test -p rtpflux --test conformance` checks SRTP/SRTCP, SDES key
parsing, `a=rtcp` and checksum updates against `conformance/media-vectors.txt`
(an external reference model; see `docs/conformance.md`). A disagreement
is a bug on one side: find which, never edit the vectors to match.

When the XDP program changes, also build it and pass it through the kernel
verifier (needs root; does not attach to any interface):

    (cd crates/rtpflux-xdp-ebpf && cargo build --release)
    sudo bpftool prog load crates/rtpflux-xdp-ebpf/target/bpfel-unknown-none/release/rtpflux-xdp \
        /sys/fs/bpf/rtpflux_test type xdp && sudo rm /sys/fs/bpf/rtpflux_test
    cargo build -p rtpflux-xdp --bin xdp-selftest
    sudo target/debug/xdp-selftest     # kernel output == reference, byte for byte
    ./scripts/xdp-e2e.sh               # namespaces + veth: offload, liveness, timeout

When the web UI's sources (`crates/rtpflux/webui/ui/`) change, rebuild the
embedded bundle and commit `webui/assets/` with them (the build is
reproducible; Rust builds never need Node):

    (cd crates/rtpflux/webui/ui && npm ci && npm run check)

The UI is read-only: its API answers `GET` and `HEAD` only and never
changes a call. Do not add API paths that change state, and never show key
material (SRTP keys, DTLS secrets) in it.

- Test normal cases, boundaries (empty, maximum sizes, 15 CSRCs, `i64::MIN`),
  malformed and hostile input, and round trips (parse ∘ write = id).
- Compare optimized code against a simple reference implementation where one
  exists (see the checksum tests in `rtpflux-xdp-common`).
- Protocol behaviour is also cross-checked against an external reference
  model through differential tests; keep the pure crates' APIs free of I/O
  so they can be driven that way.
- Report the checks you actually ran; say which were not run.

## 7. Change management

- Keep diffs focused; do not reformat or rename unrelated code.
- Update `README.md` and the docs of public items when behaviour changes.
- Commit only when asked.
