# Conformance

Protocol code is easy to get almost right. To catch the cases that
ordinary tests miss, rtpflux is checked against an **independent,
executable reference model** of the protocols it implements. The model
was written separately from rtpflux, directly from the RFCs. It computes
the expected result for thousands of inputs. If rtpflux and the model
disagree on any of them, one of the two has a bug.

## How it works

1. The reference model writes its expected results, called **vectors**,
   into [`conformance/media-vectors.txt`](https://github.com/RustedBytes/rtpflux/blob/main/conformance/media-vectors.txt).
   There are over 5,000 of them.
2. The test `crates/rtpflux/tests/conformance.rs` feeds each vector's
   input to rtpflux and compares the output.
3. It reports every disagreement at once, not just the first.

```sh
cargo test -p rtpflux --test conformance
```

A vector looks like one line of a test table. For example, an `srtp-send`
vector gives a key, a plain RTP packet and the exact bytes the encrypted
packet must have.

## What is checked

| Kind | What is checked | Against |
|---|---|---|
| `srtp-send` / `pkt` | `Protect::rtp` output, byte for byte: CSRCs, header extensions, padding, marker, empty payloads, a sequence-number wrap; all six suites | RFC 3711 §3.1–§3.3, §4.1, §4.3; RFC 6188; RFC 7714 §8, §11–§12 |
| `srtp-recv` / `in` | `Unprotect::rtp` accept/drop and plaintext over arrivals with loss, reordering across the wrap, replays, tampering, a large jump right after start, the 64-packet replay window, a forged first packet, and three interleaved SSRCs each wrapping on its own with replays across them | RFC 3711 §3.2.3, §3.3, §3.3.1, §3.3.2, Appendix A; RFC 4568 §6.4 |
| `srtcp-send`, `srtcp-recv` | `Protect::rtcp` / `Unprotect::rtcp`, including E = 0 packets and 80-bit SRTCP tags for the `_32` suites, GCM's tag-then-index trailer | RFC 3711 §3.4, RFC 5764 §4.1.2, RFC 7714 §9 |
| `crypto`, `crypto-select` | which `a=crypto` line is usable and its tag, suite and key | RFC 4568 §6.1, §9.1 with the relay profile below |
| `rtcp` | the RTCP port read from `a=rtcp` | RFC 3605 |
| `csum2`, `csum4` | incremental checksum updates of the XDP path | RFC 1624 Eqn. 3 |
| `rtcp-report`, `rtt` | `rtcp::compound`, `rtcp::Report` (SR/RR, report blocks, signed cumulative loss, short and malformed packets) and `rtcp::rtt` | RFC 3550 §6.1, §6.4, §6.4.1 |
| `g711-code`, `g711-linear` | `g711` decoding of every μ-law and A-law code, the transcoding tables, and encoding of linear samples | RFC 3551 §4.5.14 (ITU-T G.711) |
| `xdp` | `classify` and `rewrite` of the XDP path on IPv4 and IPv6 frames: the lookup key, or `pass`, and the rewritten frame byte for byte, against checksums recomputed in full (including a computed zero sent as all ones and IPv4 without a UDP checksum) | RFC 791, RFC 8200 §8.1, RFC 768, RFC 1071 |
| `demux` | what the first octet of a datagram on a media port is (STUN, ZRTP, DTLS, RTP/RTCP, drop), all 256 values | RFC 5764 §5.1.2, RFC 7983 §7 |
| `ice` | the ICE-lite answer to a datagram, byte for byte: success with XOR-MAPPED-ADDRESS, 400/401/420, and no answer | RFC 8445 §2.5, §7.3; RFC 8489 §6.3, §9.1.3, §14 |
| `priority` | host candidate priorities | RFC 8445 §5.1.2 |
| `ice-cand-priority`, `ice-pair-priority` | candidate priorities of every type, pair priorities seen from either role | RFC 8445 §5.1.2, §6.1.2.3 |
| `ice-check` | a connectivity check byte for byte: USERNAME, PRIORITY, ICE-CONTROLLING/ICE-CONTROLLED with the tie-breaker, USE-CANDIDATE, MESSAGE-INTEGRITY, FINGERPRINT | RFC 8445 §7.2.2, §16.1; RFC 8489 §14.5, §14.7 |
| `ice-role`, `ice-role-reply` | role conflicts: the role after a check claiming a role and whether it is answered 487, and the role after a 487 | RFC 8445 §7.2.5.1, §7.3.1.1 |
| `ice-init`, `ice-next`, `ice-rto` | initial pair states, the next check (triggered queue, then the best Waiting pair), the check RTO | RFC 8445 §6.1.2.6, §6.1.4.2, §14.3 |
| `ice-trickle-state`, `ice-trickle-insert`, `ice-list-state` | the state of a pair formed after checks started, inserting it (redundancy, the pair limit), the checklist state with end-of-candidates | RFC 8838 §8, §11, §12 |
| `consent` | consent freshness over runs of time, pair success, requests and responses, restarts: what is sent, whether data may flow, whether consent is lost | RFC 7675 §5.1 |
| `sdpfrag` | which trickled candidates an `application/trickle-ice-sdpfrag` body delivers to which stream, and end-of-candidates | RFC 8840 §4.4, §8, §9.2; RFC 8839 §5.1 |
| `ice-agent-start`, `ice-agent` | whole runs of the ICE agent (`ice::Agent`): for each input — a remote candidate, end-of-candidates, a check or a response received, time passing, a restart — what it sends (component, destination, transaction id, USE-CANDIDATE, role, credential generation) and then its state (role, media target and nominated pair per component, checklist state, lost consent, next deadline) | RFC 8445 §6–§9, §12; RFC 7675 §5.1; RFC 8838 §11–§14 |
| `setup` | which `a=setup` answers an offer allows, and who is the DTLS client | RFC 4145 §4.1, RFC 5763 §5 |
| `fingerprint` | whether a certificate matches the signalled `a=fingerprint` values of the strongest hash among them (real hashes) | RFC 4572 §5, RFC 8122 §5 |
| `keying` | which half of the exported keying material protects which direction | RFC 5764 §4.2 |
| `exporter` | the 60 octets exported with "EXTRACTOR-dtls_srtp" (TLS 1.2 PRF, SHA-256) | RFC 5705, RFC 5764 §4.2 |
| `group` | which `a=group` lines the relay passes on in an offer (all but BUNDLE) | RFC 5888 §5, §9.4 |
| `dtmf` | which telephone events are detected, with timestamp, duration and timeout extension, from sender streams with loss, duplicates, reordering, media and silence | RFC 4733 §2.3, §2.5.2.2 |
| `bundle-answer` | the BUNDLE group of the relay's answer: the offered tags without the refused sections | RFC 5888 §9, RFC 8843 §7.3 |

## Details

The DTLS handshake itself is outside the reference model (it does not
model the ServerKeyExchange signature or CertificateVerify, so its
handshake does not interoperate with real TLS stacks). In rtpflux it is
run by the `dimpl` library, and `scripts/webrtc-firefox.py` checks it
against a real browser. The `exporter` vectors check rtpflux's own RFC 5705
exporter against the reference; the keys `dimpl` exports are checked by
the two sides of a handshake agreeing and by the browser calls.

Receiver driver: no state until a packet authenticates; the first one is
estimated against ROC 0 and its own sequence number (RFC 3711 §3.3.1).

ICE-lite responder: a datagram without a valid FINGERPRINT is not STUN;
only Binding requests are answered; missing MESSAGE-INTEGRITY or USERNAME
gives 400, a foreign username fragment or a wrong MESSAGE-INTEGRITY 401
(both unauthenticated); an unknown comprehension-required attribute 420;
otherwise success. Understood attributes: USERNAME, MESSAGE-INTEGRITY,
PRIORITY, USE-CANDIDATE.

Whole agent runs: the reference plays the peer — it answers the agent's
checks (sometimes with 400 or 487, unauthenticated, from another address,
late or never), checks the agent from known and unknown addresses with
either role, trickles candidates, restarts ICE, sends end-of-candidates, or
goes silent (consent is lost) or never answers (the checklist fails). The
test drives `ice::Agent` with real STUN messages built from each input
(credentials `L000`/`R000`, the next generation after each restart) and a
random source whose k-th draw is k, and reads what the agent sends back.

Full ICE agent: checks carry the peer-reflexive priority (type preference
110, local preference 65535); a pair's priority is computed from the
controlling agent's candidate as G (RFC 8445 §6.1.2.3). Of Waiting pairs
with equal priority the lowest component goes first, then the first in
the checklist. A trickled pair redundant with an In-Progress, Succeeded or
Failed pair is not added, and making room never evicts In-Progress or
Succeeded pairs (RFC 8838 §11 leaves both open). Consent requests use a
5 s basic period; a response after consent expired is discarded.

Relay profile for DTLS-SRTP fingerprints: SHA-1, SHA-224, SHA-256, SHA-384
and SHA-512, upper-case hex; MD2 and MD5 never match (RFC 8122 §5).

Relay profile for SDES keys: `AES_CM_128_HMAC_SHA1_80`/`_32` (30
octets), `AES_256_CM_HMAC_SHA1_80`/`_32` (46), `AEAD_AES_128_GCM` (28) or
`AEAD_AES_256_GCM` (44); exactly one key of the suite's length in
canonical base64, an optional lifetime of at most 2^48, no MKI, no session parameters. Other offers are valid RFC 4568 but
not used by rtpflux.

For the GCM suites the reference model derives the session key and salt
with the 96-bit master salt zero-padded on the right to 112 bits (the
layout libsrtp and the browsers use; RFC 3711 §4.3.1 read literally would
right-align it).

## Where the model and rtpflux meet

The file is regenerated by the reference model's `media-vectors` program
and committed as is; do not edit it by hand. A disagreement is a bug on
one side: find out which, and never edit the vectors to make rtpflux
pass.
