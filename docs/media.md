# Media handling

This page explains what rtpflux does with the media of a call: where it
sends packets, how it handles encryption and browsers, and what happens
when a call changes.

## Ports

For each media section of the offer (each `m=` line), the relay opens
two port pairs: one facing the offerer and one facing the answerer. Each
pair is an even RTP port and the odd RTCP port above it. When a section
uses `rtcp-mux`, RTCP shares the RTP port.

A rejected section (port `0`) gets no ports and stays rejected in the
rewritten SDP.

## NAT and latching

A phone behind NAT often writes its private address, such as
`192.168.1.20`, into its SDP. Packets sent there would never arrive. The
relay solves this by **latching**: it watches where the phone's packets
actually come from and sends media back to that address. This works
because phones send and receive on the same port (*symmetric RTP*).

Choose how the relay learns with the `endpoint-learning` option:

| Mode | Behaviour |
|---|---|
| `heuristic` (default; `delayed` is a synonym) | For the first 3 seconds of media, prefer the source that best matches the SDP: the same address and port, then the same address, then any. After that, the choice is fixed. |
| `immediate` | Latch onto the source of the very first packet. |
| `off` | Always use the address from the SDP. |

By default the relay trusts the SDP address only if the proxy says so:
without the `trust-address` flag, it uses the address the SIP message came
from (`received-from`, which proxy modules send automatically).

With the `strict-source` flag (or `[sessions] strict_source = true` for
every call), once the relay knows a side's address it drops packets from
any other source. That stops a third party from
injecting media, at the cost of not following a phone that changes its
address mid-call.

With the `media-handover` flag, a learned address is not fixed: a new
source takes it over once it has sent 3 packets in a row with none from
the current address in between, as when a NAT rebinds or a phone moves
from Wi-Fi to mobile data. A stray packet does not move it; under SRTP
only authentic packets count. With `strict-source` as well, the
newcomer's packets are dropped until it takes over. An address an ICE
check confirmed moves only by ICE. Such calls stay off the XDP fast path,
which does not learn.

**Example.** Alice's SDP says `192.168.1.20:4000`, but her router
rewrites her packets to come from `203.0.113.7:61234`. In `heuristic`
mode, the relay sees those packets, latches onto `203.0.113.7:61234`
within the first seconds of the call, and Bob's audio reaches Alice.

## Timeouts

A call whose media has stopped in **both** directions for
`[sessions] timeout` seconds (default 60) after its answer is ended and
its ports freed; an offer never answered ends after `offer_timeout`
(default an hour). This cleans up calls whose `delete` never arrived.

A call on hold (either side `sendonly`, `recvonly`, `inactive` or
`c=0.0.0.0`) uses `silent_timeout` (default an hour) instead, since a hold
without music on hold sends nothing either way; resuming it brings
`timeout` back. `final_timeout`, when set, ends any call that long after
its first offer.

## SRTP (encrypted media)

rtpflux handles encryption separately on each side of a call. It
decrypts what one side sends and encrypts it again with the other side's
keys. So one side can use SRTP while the other uses plain RTP, or the two
sides can use different keys or suites.

### SDES keys (`a=crypto`)

Many SIP phones put their SRTP key into the SDP as an `a=crypto` line
(SDES). rtpflux reads the offerer's key and generates its own key for each
side.

Supported suites:

| Suite | Notes |
|---|---|
| `AES_CM_128_HMAC_SHA1_80` | The most common |
| `AES_CM_128_HMAC_SHA1_32` | Shorter authentication tag |
| `AES_256_CM_HMAC_SHA1_80`, `AES_256_CM_HMAC_SHA1_32` | 256-bit keys (RFC 6188) |
| `AEAD_AES_128_GCM`, `AEAD_AES_256_GCM` | AES-GCM (RFC 7714) |

The relay uses the first usable `a=crypto` line: a supported suite with
one key and no MKI. Towards an answerer it offers SDES to, it offers
every suite, the offerer's first (`AES_CM_128_HMAC_SHA1_80` for a plain
offerer), each with its own key and tag, so that the answerer can take
one it supports; the relay then uses its key of the suite answered (a
re-offer after that offers that suite only, with the same key). The
`SDES` option (`no-<suite>`, `only-<suite>`; see
[Options](control-protocol.md#options)) narrows both what is offered and
which of the offerer's lines is used. By default, lines with session
parameters (`UNENCRYPTED_SRTP`, `UNAUTHENTICATED_SRTP`, …) are not used,
as the reference model the relay is checked against specifies. When the
proxy asks for them (`SDES` values `unencrypted_srtp`,
`unencrypted_srtcp`, `unauthenticated_srtp`), the relay offers the
answerer AES-CM suites declaring them (AEAD suites cannot leave anything
out), accepts lines declaring them from either side, and protects
accordingly: payloads in clear but still authenticated, SRTCP with E = 0,
or RTP without a tag (no integrity at all: only for testing or trusted
networks). Packets that fail authentication, or replay an earlier
packet, are dropped and counted (`rtpflux_srtp_rejected_total`).

### Opportunistic SRTP

An offer in a plain profile (`RTP/AVP`) may still carry `a=crypto` lines
(RFC 8643): SRTP if the answerer can, plain RTP otherwise. The relay
passes such an offer on with its own key; when the answerer answers with
a key, both sides use SRTP (each under its own keys), and the offerer is
answered with the relay's key; otherwise both stay plain. Nothing is
encrypted before the answer agrees it. The `OSRTP` option makes a plain
offer opportunistic towards the answerer (`offer`), or takes the
offerer's SRTP even when the answerer stays plain (`accept`).

### DTLS-SRTP (WebRTC)

Browsers agree their SRTP keys with a DTLS handshake on the media port
instead. rtpflux takes part in that handshake on each side that uses it:

- It has its own self-signed certificate (ECDSA P-256, generated at
  start, valid for 400 days from a day before). Its SHA-256 fingerprint goes into the SDP.
- It speaks DTLS 1.2 (the version WebRTC browsers use with each other),
  with the ECDHE-ECDSA AES-GCM and ChaCha20-Poly1305 cipher suites.
- It checks the peer's certificate against the peer's `a=fingerprint`.
  There is no certificate-authority check; the fingerprint is what
  matters, as in WebRTC.
- It takes the DTLS role the `a=setup` exchange gives it. It answers an
  `actpass` offer as the server (`passive`), and offers `actpass` itself.
  The `DTLS` option changes that: `passive` or `active` in what it offers
  (an answer that does not fit is refused, RFC 4145), and in its answer
  to an `actpass` offerer.
- For SRTP it prefers `AEAD_AES_256_GCM`, then `AEAD_AES_128_GCM`,
  then `AES_CM_128_HMAC_SHA1_80`. (`AES_CM_128_HMAC_SHA1_32` is
  available with SDES keys only.)

### Bridging WebRTC and SIP phones

Because each side is handled separately, a browser can call a desk phone.
Ask for plain RTP towards the phone with
`transport-protocol: RTP/AVP` (in Kamailio, the `RTP/AVP` flag):

```text
Browser ── DTLS-SRTP, ICE, rtcp-mux, BUNDLE ──► rtpflux ── plain RTP ──► desk phone
```

The other profiles work too: `RTP/SAVP` gives the phone SDES-SRTP, and
`UDP/TLS/RTP/SAVPF` offers DTLS-SRTP to a phone that only spoke SDES. If
the two sides also use different codecs, see
[Transcoding](call-features.md#transcoding).

### ZRTP (end-to-end keys)

Some softphones (Linphone, Jitsi, Zoiper, Acrobits and others) agree on
their SRTP keys with ZRTP (RFC 6189): a Diffie-Hellman exchange inside the
media stream, verified by a short string the users can read to each other.
The keys never appear in the SIP messages, so neither the proxies nor the
relay can read the call.

ZRTP packets share the RTP port and start with a byte from 16 to 19 (RFC
7983). rtpflux treats them by call:

- **Plain relaying** (no SRTP terminated by the relay, no transcoding, no
  BUNDLE): ZRTP packets are forwarded as they are, on the same path as the
  RTP, and the SDP's `a=zrtp-hash` lines are kept. The phones encrypt end
  to end through the relay, which only sees ciphertext.
- **The relay changes the media** (it holds SDES or DTLS-SRTP keys on
  either side, transcodes, or sorts a BUNDLE group): end-to-end keys cannot
  cover media the relay decrypts or rewrites, so ZRTP packets are dropped
  and `a=zrtp-hash` is removed from the SDP. The phones see that ZRTP is
  not available rather than failing half-way.

Forwarded ZRTP packets are counted in `rtpflux_zrtp_forwarded_total`.
Recording a ZRTP call stores the encrypted audio, which cannot be
converted.

## Fax (T.38)

A T.38 fax call usually starts as audio and is re-INVITEd to an image
stream: `m=image <port> udptl t38`. rtpflux relays it like any other
section: the SDP gets the relay's address and ports (the `a=T38…`
attributes are kept), and every UDPTL datagram is forwarded as it is,
after latching. A section in any transport rtpflux does not read as RTP
is handled the same way. It does not convert between T.38 and G.711 fax
(no fax gateway): both ends must speak T.38.

## ICE

Browsers will not send media until ICE connectivity checks succeed, and
many SIP phones use ICE too. Towards an endpoint that uses ICE, rtpflux is
a **full ICE agent** (RFC 8445) by default:

- It puts its own credentials and candidates (its interface address,
  `typ host`, and with `[ice] stun_server` its public address, `typ
  srflx`) in the SDP, with `a=ice-options:ice2` and `a=end-of-candidates`;
  the endpoint's candidates are removed (they would steer media around
  the relay).
- It reads the endpoint's candidates and checks them itself, paced every
  `pacing_ms` (Ta), with retransmissions; it answers the endpoint's
  checks, and learns addresses it did not announce from them
  (peer-reflexive candidates).
- Towards the offerer it is the *controlled* agent (the offerer nominates
  the pair), unless the offerer is ICE-lite; towards the answerer it
  offered to, it is the *controlling* one: it nominates the best pair that
  works. Role conflicts are resolved as RFC 8445 §7.3.1.1 says.
- Media goes only to a pair whose check succeeded: the nominated one, or,
  until there is one, the best that works. Before any pair works, media
  towards that endpoint is held back, and so is a DTLS handshake the relay
  starts.
- **Consent freshness** (RFC 7675): the relay checks the pair it sends to
  every 4–6 seconds; with no answer for 30 seconds it stops sending to it
  for good (counted in `rtpflux_ice_consent_lost_total`), until an ICE
  restart.
- **ICE restarts**: an endpoint that re-offers with a new `ice-ufrag` and
  `ice-pwd` restarts ICE (RFC 8839 §4.4.1.1.1); the relay answers with new
  credentials too and checks again, while media keeps going to the old
  pair until a new one works.
- **Trickle ICE** (RFC 8838, RFC 8840): candidates an endpoint sends later,
  in an `application/trickle-ice-sdpfrag` body (a SIP INFO), reach the
  relay through `offer` with the `fragment` flag; see
  [Trickle ICE](control-protocol.md#trickle-ice). When the endpoint
  trickles, the relay's SDP says `a=ice-options:trickle ice2`. The relay
  itself never trickles: all its candidates are in its SDP.

As an **ICE-lite** agent instead (`[ice] mode = "lite"`, or `ICE-lite` per
call), the relay only answers checks and sends media to the address they
come from, as servers with a public address traditionally do. The SDP then
says `a=ice-lite`.

By default the relay uses ICE towards both sides when the offerer does,
except when a WebRTC offer (DTLS-SRTP) is bridged to a SIP profile with
`transport-protocol` (`RTP/AVP`, `RTP/SAVP`, …): the phone then gets
plain SIP media without ICE attributes, while the browser keeps ICE.
The `ICE` option changes that (`remove` or `force`); see
[Options](control-protocol.md#options).

## Packet time (`ptime`)

With the `ptime` option (and `ptime-reverse`) the relay repacketises: it
regroups the audio of G.711, G.722 and G.729 into packets of another
duration, joining several into one or cutting one into several. Opus
cannot be cut: it is decoded and encoded again, in packets of one Opus
frame (the longest of 10, 20, 40 or 60 ms not over the packet time). A
packet made from several goes out when the last arrives; the parts of a
cut packet go out one packet time apart. Sequence numbers are the
relay's own, timestamps follow the audio, and telephone events and
comfort noise pass in order. A gap in the stream (a lost packet, a new
talkspurt) sends what is held as a shorter packet. Calls that are
repacketised stay off the XDP fast path. See
[Options](control-protocol.md#options).

## rtcp-mux

With `rtcp-mux`, RTCP travels on the RTP port. The relay uses it on a
stream when the offerer offers it and the answerer accepts it. Otherwise
RTCP keeps its own port on both sides. A bundled side (see below) always
uses `rtcp-mux`, whatever the other side does.

Each side can differ: the relay joins and splits RTCP between the two
forms. The `rtcp-mux` option (rtpengine's values) chooses:

| Value | Towards the offerer | Offered to the answerer |
|---|---|---|
| (none) | if offered and the answerer accepts | if the offerer offered it |
| `offer` | if offered and the answerer accepts | always |
| `require` | if offered | always, without an RTCP port, and the answerer is taken to accept |
| `demux` | if offered | never |
| `accept` | if offered | if the offerer offered it |
| `reject` | never | never |

The answerer uses it when it was offered it and accepts. With `require`
(meant for WebRTC clients, against RFC 5761) the answerer is offered no
separate RTCP port, and the relay multiplexes towards it from the start,
whatever its answer says.

## BUNDLE

Browsers usually send audio and video on **one** port (BUNDLE). The relay
accepts this from the offerer:

- All bundled sections share one relay port, one ICE session and one
  DTLS handshake.
- Arriving packets are sorted back into their streams: RTP by payload
  type, RTCP by the sender's SSRC.
- The answerer (typically a SIP phone) is offered an ordinary port per
  stream, without BUNDLE.
- `bundle-only` sections (the browser's `max-bundle` policy) are
  supported.

With SDES-SRTP, each bundled section keeps its own key. With DTLS, they
share the keys of the one handshake.

## Re-INVITEs and hold

A call can change after it starts. Each new offer in the same dialog (a
re-INVITE) goes through `offer` and `answer` again. rtpflux keeps
everything that does not need to change:

- **Same ports and keys.** The relay's ports and its SRTP keys towards
  each side stay. A party that did not move sees no change.
- **Either party may re-INVITE.** When the callee re-offers (its tag in
  `from-tag`), the relay swaps the roles for that exchange. `query` and
  `delete` accept either party's tag.
- **Streams on their own.** Without BUNDLE, a re-offer can disable one
  stream (port `0`), add a new one, or bring a disabled one back. The
  other streams are not touched.
- **Hold and resume.** `a=sendonly`, `a=recvonly`, `a=inactive` and the
  older `c=0.0.0.0` hold all pass through. The relay never sends media to
  `0.0.0.0`.
- **BUNDLE and re-INVITEs.** When a SIP phone re-INVITEs a bundled
  browser, the browser is offered its BUNDLE group again on the same
  shared port, and the phone keeps a port per stream. A bundled re-offer
  from the party that did not bundle at first is refused with an error
  (the relay can bundle only one side of a call), and the call continues
  unchanged.

## IPv6

Interfaces can have IPv6 addresses, and the [XDP fast path](xdp.md)
handles IPv6 as well as IPv4.

Without `direction`, an offer is handled on the first interface of the
offerer's address family, so with one IPv4 and one IPv6 interface both
kinds of caller work. To bridge the two families (an IPv4 phone and an
IPv6 one, a carrier's IPv6 core), the `address-family` option (`IP4` or
`IP6`) puts the answerer's side on the first interface of that family:
each side gets SDP of its own family (`c=` and `o=`), and the relay
carries the media between them. Naming the two interfaces in
`direction` does the same. `media-address` writes another address into
the SDP than the interface's (of the same family), as `advertise` does
per interface.
