# rtpflux-srtp

SRTP and SRTCP (RFC 3711): encrypting and decrypting RTP and RTCP in
place, on the caller's buffer.

## Why it is a crate of its own

This is the cryptography of every encrypted call, and it runs on every
packet of one. Isolating it keeps it small enough to review, and lets the
rules for key material be enforced in one place:

- **`no_std`, no `alloc`, no I/O, no logging.** Keys are expanded once per
  context; protecting and unprotecting never allocate. Key material can
  never reach a log, because the crate cannot log.
- **Constant-time.** Authentication tags are compared in constant time.
- **RustCrypto primitives only**, which use the CPU's AES instructions
  where it has them.
- **Checked against an outside model.** `conformance/media-vectors.txt`
  holds vectors from an independent implementation; a disagreement is a
  bug, never a reason to edit the vectors.

## Suites

| Suite | RFC |
|---|---|
| `AES_CM_128_HMAC_SHA1_80`, `AES_CM_128_HMAC_SHA1_32` | RFC 4568 |
| `AES_256_CM_HMAC_SHA1_80`, `AES_256_CM_HMAC_SHA1_32` | RFC 6188 |
| `AEAD_AES_128_GCM`, `AEAD_AES_256_GCM` | RFC 7714 |

Key derivation (RFC 3711 §4.3), rollover-counter estimation (Appendix A),
a 64-packet replay window per source (§3.3.2), and late binding of new
SSRCs under the same master key (RFC 4568 §6.4), up to `MAX_SOURCES` per
context.

## What is inside

| Module | What it does |
|---|---|
| `suite` | The suites and their key, salt and tag lengths |
| `cipher` | AES-CM and AES-GCM, key derivation |
| `protect`, `unprotect` | SRTP and SRTCP in place: encrypt and append the tag; verify, decrypt and return the shorter length |
| `replay` | The replay window (a bitmap) |
| `ssrc` | Per-SSRC state (rollover counter, highest sequence number) |

## Used by

`rtpflux-core` (key types from SDES and DTLS-SRTP), the daemon (`rtpflux`)
and the load generator (`rtpflux-bench`, for its `--srtp` modes).

## Testing

```sh
cargo test -p rtpflux-srtp
cargo test -p rtpflux --test conformance   # SRTP/SRTCP vectors from the reference model
```
