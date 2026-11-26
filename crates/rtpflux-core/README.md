# rtpflux-core

The protocol logic of rtpflux: what to do with a packet, an SDP body or an
ICE check, written as plain functions over borrowed bytes and explicit
state.

## Why it is a crate of its own

Everything here runs per packet or per call set-up, so it has to be fast,
must never panic on hostile input, and must be checked independently of
sockets, threads and clocks. Keeping it in its own crate makes the compiler
enforce that:

- **`no_std`, no `alloc`.** The crate cannot allocate: no `Vec`, `String`
  or `Box` can appear on the media path, because they do not exist here.
- **No I/O, no clock, no randomness.** Time and random values are passed in
  as arguments, so every decision is a pure function of its inputs. The
  same functions are driven by the daemon, by unit tests, by the fuzzing in
  `crates/rtpflux/tests/robustness.rs`, and by differential tests against
  an external reference model (`conformance/media-vectors.txt`).
- **Checked arithmetic and indexing.** Clippy's `indexing_slicing` and
  `arithmetic_side_effects` are denied outside tests: input-derived lengths
  are validated and slices taken with `get`.

## What is inside

| Module | What it does |
|---|---|
| `rtp`, `rtcp` | Zero-copy views of RTP and RTCP packets, and in-place rewrites (`set_ssrc`, `set_sequence`, …) |
| `relay` | The relay decision: where a packet on a relay port goes |
| `latch` | Learning and keeping each side's address behind NAT (latching, `strict-source`, media handover) |
| `sdp` | Reading and rewriting SDP: addresses, ports, codecs, `a=crypto` (SDES) keys, ICE attributes, BUNDLE |
| `ice`, `stun` | ICE (RFC 8445) checklists and consent, STUN messages |
| `dtls` | The keying material a DTLS-SRTP handshake exports, turned into SRTP keys |
| `dtmf`, `dtmf_inband` | RFC 4733 telephone events, and DTMF tone detection in audio |
| `g711`, `g722` | G.711 and G.722 codecs |
| `ports`, `ring` | The media port allocator and fixed-capacity ring buffers |

## Depends on

`rtpflux-srtp`, for the SRTP key, suite and SSRC types that SDES and
DTLS-SRTP produce, plus RustCrypto's `hmac` and `sha1` (STUN message
integrity).

## Used by

The daemon (`rtpflux`) and the load generator (`rtpflux-bench`).

## Testing

```sh
cargo test -p rtpflux-core
cargo test -p rtpflux --test conformance   # against the reference model's vectors
```
