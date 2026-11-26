# Glossary

Plain-English explanations of the terms used in the rtpflux documents.
Terms in *italics* inside an entry have their own entry.

**A-law, μ-law** — The two variants of *G.711*. A-law (*PCMA*) is used in
Europe and most of the world, μ-law (*PCMU*) in North America and Japan.
Converting between them is a simple table lookup.

**Announcement** — A recorded audio file the relay plays to a participant,
for example "please hold". See [Call features](call-features.md#announcements).

**Answer, answerer** — In *SDP offer/answer*, the reply to an *offer*. The
answerer is the party that replies, usually the person being called.

**AES-CM, AES-GCM** — The encryption methods ("suites") *SRTP* uses.
AES-CM encrypts and adds a separate *HMAC-SHA1* tag to detect tampering.
AES-GCM does both in one step. Browsers now prefer AES-GCM.

**AF_XDP** — A Linux socket type that receives packets straight from
an *XDP* program, skipping most of the kernel's network stack. rtpflux can
use it for the calls the kernel cannot relay itself. See
[XDP fast path](xdp.md#af_xdp-for-the-other-calls).

**BUNDLE** — A *WebRTC* feature that sends audio and video over one port
instead of one port each. The relay sorts the mixed packets back into
streams. Defined in RFC 8843.

**bencode** — The simple text-and-numbers encoding the *ng protocol* uses
for its messages. It was originally invented for BitTorrent.

**Call-ID, from-tag, to-tag** — Identifiers from the SIP messages. Together
they name a *dialog*. The from-tag belongs to the party that sent the
request, the to-tag to the other party.

**Codec** — The method used to compress audio or video. rtpflux can
convert (*transcode*) between *PCMU*, *PCMA* and *Opus*.

**Dialog** — A SIP call between two parties, identified by its *Call-ID*
and the two *tags*.

**DTLS, DTLS-SRTP** — DTLS is TLS (the encryption behind HTTPS) adapted
for UDP. *WebRTC* uses a DTLS handshake to agree the keys for *SRTP*;
this combination is called DTLS-SRTP.

**DTMF, telephone events** — The tones sent when someone presses keys on a
phone keypad ("press 1 for sales"). Over RTP they travel as separate
"telephone event" packets (RFC 4733), which rtpflux detects and reports.

**Endpoint** — A phone, softphone, browser or gateway that sends and
receives media.

**Fast path** — See *XDP*.

**G.711** — The classic telephone audio codec: 8,000 samples per second,
one byte each, 64 kbit/s. Comes in two variants, *A-law* and *μ-law*.

**HMAC-SHA1** — A cryptographic checksum that proves a packet was not
changed in transit. Used by the *AES-CM* suites of *SRTP*.

**Hold** — Pausing a call. The phone sends a *re-INVITE* that marks its
media as send-only or inactive, or (older phones) sets the address to
`0.0.0.0`.

**ICE, ICE-lite** — ICE is how *WebRTC* endpoints find a network path to
each other, by sending connectivity checks (*STUN* messages) to candidate
addresses. A full agent, like rtpflux by default, checks the other side's
candidates and answers its checks; an ICE-lite agent has a public address
and only answers. *Consent freshness* keeps checking the chosen pair, so a
relay stops sending to an endpoint that went away; *trickle ICE* sends
candidates as they are found instead of all at once.

**Interface** — In rtpflux's configuration, a named local address that
media is sent and received on, such as `external` or `internal`.

**Jitter** — How much the arrival time of packets varies. High jitter
makes audio choppy.

**Latching** — Learning where a phone's media really comes from by looking
at the source address of its packets, rather than trusting the address in
the *SDP*. This is how the relay reaches phones behind *NAT*. Also called
"endpoint learning".

**Leg** — One direction or one side of a relayed call. Each relayed stream
has a leg towards each party.

**Media section** — One `m=` line in an *SDP*, describing one stream (for
example audio or video) and everything that follows it until the next
`m=` line.

**NAT** — Network address translation. A home router, for example, hides
many devices behind one public address. The address a phone writes into
its *SDP* is then often unreachable, which *latching* solves.

**ng protocol** — The control protocol between a SIP proxy and the relay:
*bencoded* commands such as `offer`, `answer` and `delete`, sent over UDP.
It comes from rtpengine and is used by the `rtpengine` modules of
Kamailio and OpenSIPS.

**Offer, offerer** — In *SDP offer/answer*, the first description of the
media a party wants. The offerer is usually the caller, but in a
*re-INVITE* it can be either party.

**Opus** — A modern, high-quality audio codec used by *WebRTC*. Its RTP
clock always runs at 48,000 ticks per second.

**pcap** — A standard file format for captured network packets. Tools
like Wireshark can open it and play back the audio.

**PCMU, PCMA** — The names of the two *G.711* variants in *SDP*: PCMU is
*μ-law* (payload type 0), PCMA is *A-law* (payload type 8).

**Payload type** — A number in every *RTP* packet that says which *codec*
it carries. The *SDP* maps numbers to codecs, for example `a=rtpmap:111
opus/48000/2`.

**Re-INVITE** — A new *offer* in an existing call, for example to put it
on *hold*, add video or move to a new network. Either party can send one.

**Relay** — A server that receives media from one party and forwards it to
the other. rtpflux is a relay.

**Round-trip time (RTT)** — How long a packet takes to reach the other
side and come back. rtpflux calculates it from *RTCP* reports.

**RTCP** — The companion protocol of *RTP*. Endpoints use it to report
reception quality: packets lost, *jitter*, timing.

**rtcp-mux** — Sending *RTCP* on the same port as *RTP* instead of the
next port up. Required by *WebRTC*.

**RTP** — Real-time Transport Protocol. Carries audio and video as a
sequence of UDP packets, each with a sequence number, timestamp and
*SSRC*.

**rtpengine** — A widely used open-source media relay by Sipwise. rtpflux
speaks its control protocol (*ng*) so it can be used in its place.

**SDES** — A way to exchange *SRTP* keys inside the *SDP* itself
(`a=crypto` lines), as many SIP phones do. The keys are only as secret as
the signalling.

**SDP** — Session Description Protocol. The text that describes a call's
media: addresses, ports, *codecs*, encryption. Carried inside SIP
messages.

**SDP offer/answer** — The exchange in which one party *offers* the media
it wants and the other *answers* with what it accepts (RFC 3264).

**SIP** — Session Initiation Protocol. Sets up, changes and ends calls.
SIP carries the *SDP*; the media itself travels separately over *RTP*.

**SIP proxy** — A server that routes SIP messages, such as Kamailio or
OpenSIPS. It controls the relay over the *ng protocol*.

**SRTP, SRTCP** — Secure *RTP* and *RTCP*: encrypted and
tamper-protected versions. The keys come from *SDES* or *DTLS*.

**SSRC** — A random number that identifies one media source in *RTP*
packets.

**State file** — A file where rtpflux saves its calls, so that it can
restore them after a restart. The same state can also be kept in Redis.

**STUN** — A small protocol used by *ICE* for connectivity checks.

**Symmetric RTP** — The common practice of sending media from the same
port it is received on (RFC 4961). It is what makes *latching* work.

**Transcoding** — Converting media from one *codec* to another, for
example *Opus* from a browser to *PCMU* for a desk phone.

**WebRTC** — Real-time audio and video in web browsers. It always
encrypts with *DTLS-SRTP*, uses *ICE*, and usually *BUNDLE* and
*rtcp-mux*.

**XDP** — eXpress Data Path, a Linux feature that runs a small program in
the network driver for each arriving packet. rtpflux uses it as a "fast
path" that forwards settled calls without waking the relay process. See
[XDP fast path](xdp.md).
