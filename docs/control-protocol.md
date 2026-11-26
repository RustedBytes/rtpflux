# Control protocol

A SIP proxy controls rtpflux with the **ng protocol**, the protocol of
rtpengine. If your proxy already uses its `rtpengine` module, it can use
rtpflux without changes. This page describes the commands rtpflux
understands and the options it reads.

## How messages look

Each command is one UDP datagram sent to `[control] listen`. It has two
parts:

```text
<cookie> <bencoded dictionary>
```

- The **cookie** is a random string chosen by the proxy. The reply starts
  with the same cookie, so the proxy can match replies to requests.
- The **dictionary** holds the command and its options, in
  [bencode](https://en.wikipedia.org/wiki/Bencode).

For example, a `ping`:

```text
5323_1 d7:command4:pinge
```

and its reply:

```text
5323_1 d6:result4:ponge
```

Every reply has `result`. It is `ok` (or `pong`) on success, or `error`
with an `error-reason`:

```text
result:       error
error-reason: missing sdp
```

A successful reply may also carry a `warning` (as rtpengine's do) when
part of the request was ignored: an option, flag, `replace` or `SDES`
value rtpflux does not implement (`option frobnicate: not supported,
ignored`), a codec name the relay does not know in `codec: transcode`, or
a `codec: mask` with no codec to transcode to. rtpflux also logs each
warning at `debug`.

If the proxy resends a request because the reply was lost, rtpflux
recognises the cookie and sends the same reply again, without running
the command twice. Only the same request counts: a cookie reused for a
different request (a proxy whose counter restarted, say) runs that
request. Replies are kept for 30 seconds, per sender: two
proxies that send the same cookie (Kamailio's are made of its server id,
process id and a counter, so identical containers send identical ones)
each get the reply to their own request.

### Over TCP, HTTP and WebSocket

Besides UDP, rtpflux takes the same messages on streams, as rtpengine
does (`[control] listen_tcp`, `listen_http`):

- **TCP**: messages back to back on a connection, `<cookie>
  <bencoded dictionary>` each, with no length prefix (a message ends where
  its dictionary does); replies the same way. A connection that sends
  something else is closed: no space within the first 256 bytes, an
  empty cookie, a dictionary that is not strict bencode (integers without
  leading zeros or `-0` and within 64 bits, no repeated key, at most 256
  keys, nesting below 32), or a message over 65 535 bytes.
- **HTTP** (`POST /ng`, `Content-Type: application/x-rtpengine-ng`): the
  body is one message and so is the reply. `POST /ng-plain` takes the
  dictionary without a cookie, as `application/x-rtpengine-ng` (bencode)
  or `application/json`. `GET /ping` answers `pong`.
- **WebSocket** (on the HTTP endpoints): subprotocol `ng.rtpengine.com`,
  one message per WebSocket message (`<cookie> <dictionary>`), or
  `ng-plain.rtpengine.com` (no cookie); replies come in binary frames.
  As RFC 6455 requires of a server with no extension, the connection is
  failed on a frame that is not masked, has a reserved bit or opcode, is
  a fragmented or long control frame, has a length not in its shortest
  form, or (rtpflux's limit) carries over 65 535 bytes; a continuation
  frame needs a fragmented message in progress, and a new message must
  wait for the end of one. A failed connection gets a Close frame first
  (RFC 6455 §7.1.7): 1002 (protocol error), or 1009 for a message that
  grows over the limit across fragments.
  Kamailio's rtpengine module connects this way with `rtpengine_sock
  "ws://host:port"` (and `wss://` through a TLS proxy).

On HTTP and WebSocket the dictionary may be JSON instead of bencode (it
starts with `{`); the reply is then JSON too:

```text
POST /ng-plain           {"command":"ping"}
→ 200 application/json   {"result":"pong"}
```

rtpflux does not speak TLS itself: for HTTPS and WSS, put a TLS proxy in
front.

## Commands

| Command | What it does |
|---|---|
| [`ping`](#ping) | Checks that the relay is alive |
| [`offer`](#offer) | Sets up (or changes) a call from an SDP offer |
| [`answer`](#answer) | Completes a call from the SDP answer |
| [`delete`](#delete) | Ends a call |
| [`rollback`](#rollback) | Takes back a re-offer that was not answered |
| [`list`](#list) | Lists active calls |
| [`query`](#query) | Reports one call's streams and statistics |
| [`block media`, `unblock media`](#block-and-unblock) | Stops or resumes relaying a participant's audio |
| [`block DTMF`, `unblock DTMF`](#block-and-unblock) | Stops or resumes relaying a participant's key presses |
| [`start recording`, `stop recording`, `pause recording`](#start-recording-and-stop-recording) | Records a call to pcap files |
| [`play media`, `stop media`](#play-media-and-stop-media) | Plays an announcement to a participant |
| [`play DTMF`](#play-dtmf) | Sends key presses as if a participant had pressed them |
| [`silence media`, `unsilence media`](#silence-and-unsilence-media) | Replaces a participant's audio with silence, keeping the stream |
| [`statistics`](#statistics) | Reports the relay's counters |
| [`subscribe request`, `subscribe answer`, `unsubscribe`](#subscribe-request-subscribe-answer-and-unsubscribe) | Sends copies of parties' media to a third party (a SIPREC recorder) |
| [`publish`](#publish) | Takes media from a party that only sends, for others to subscribe to |
| [`create`, `create answer`](#create-and-create-answer) | Makes an offer for a party of the relay's own, answered by an endpoint such as a media server |
| [`inject start`, `inject stop`](#inject-start-and-inject-stop) | Sends one party's media to another party as well, one way |
| [`mesh`](#mesh) | Sends parties' media to other parties, of one call or several, in one request |
| [`connect`](#connect) | Joins a party of one call with a party of another, or copies parties' media to another |

A call is identified by its SIP **Call-ID** and the **tags** of its two
parties (see the [glossary](glossary.md)).

### `ping`

No options. Replies `result: pong`.

### `offer`

Sends an SDP offer through the relay. rtpflux allocates ports for each
media section and replies with the SDP rewritten to point at the relay.
The proxy forwards that SDP instead of the original.

| Option | Required | Meaning |
|---|---|---|
| `call-id` | yes | The SIP Call-ID |
| `from-tag` | yes | The tag of the party sending the offer |
| `sdp` | yes | The offer |
| `to-tag` | no | Present in a re-INVITE: the dialog with that party (see [Calls with more than two parties](#calls-with-more-than-two-parties)) |
| `label` (or `set-label`) | no | A label for the offerer, which later commands can name it by |
| `via-branch` | no | The branch of a forked INVITE: another branch's offer (an initial one, while the dialog is unanswered) gets media of its own, and the branch whose `answer` names it becomes the dialog |
| other options | no | See [Options](#options) |

The reply has `sdp`, the rewritten offer.

A second `offer` in the same dialog is a **re-INVITE**: hold, resume,
new codecs, a new address, an added or removed stream. The relay keeps
the call's ports and keys, so the other party sees no change it does not
need to see. A re-INVITE can come from either party. If the
`from-tag` is the original answerer's, the relay swaps the roles for
the new exchange. See [Media handling](media.md#re-invites-and-hold).

### `answer`

Passes the SDP answer through the relay and completes the call.

| Option | Required | Meaning |
|---|---|---|
| `call-id` | yes | The SIP Call-ID |
| `from-tag` | yes | The offerer's tag (as in the `offer`) |
| `to-tag` | yes | The answerer's tag |
| `sdp` | yes | The answer |
| `label` (or `set-label`) | no | A label for the answerer |

The reply has `sdp`, the rewritten answer for the offerer. An answer
section whose formats are all static payload types (0–95) that were not
offered, neither by the offerer nor by the relay's transcoding, is refused
(RFC 3264 §6.1); dynamic payload types pass, since an answer may renumber
them.

### `delete`

Ends a call and frees its ports.

| Option | Required | Meaning |
|---|---|---|
| `call-id` | yes | The SIP Call-ID |
| `from-tag` | no | Only the dialog with this tag (either party's) |
| `to-tag` | no | Only if the dialog was answered with this tag (or it is the offerer's): a forked call's losing branch deletes nothing |
| `via-branch` | no | Only that branch of a forked INVITE (a losing branch's media), or a dialog whose offer carried it (or none) |
| `delete-delay` | no | Seconds the call goes on before it ends (default 0: at once), for media still in flight |
| `flags: fatal` | no | Deleting nothing is an error |

When nothing matches (an unknown call, another fork's tag, another
branch), the reply is `ok` with the warning `Call-ID not found or tags
didn't match`, as rtpengine's; with `fatal`, it is the error `unknown
call`.

### `rollback`

Takes back a re-offer that has not been answered (the answerer rejected
the re-INVITE): the dialog returns to its last agreed media (addresses,
ports, codecs, profile, SRTP keys, ICE credentials, DTLS roles), as
rtpengine's `rollback` does. Only a re-offer of an answered dialog that
carried `flags: track-state` can be taken back: it keeps the dialog as
last agreed until its answer (offers before the answer share it), and
the relay calls of sections it removed go on meanwhile. The answer commits
it; a section it removed ends then.

| Option | Required | Meaning |
|---|---|---|
| `call-id` | yes | The SIP Call-ID |
| `from-tag` | yes | Either party's tag |
| `to-tag` | yes (or `via-branch`) | The other party's tag |
| `via-branch` | no | Names the dialog by the branch of its latest offer instead |

The reply's `rolled-back` is 1 when a re-offer was taken back, 0 when
there was none to take back (so a repeated `rollback` is harmless).
Sections the re-offer added end. A rollback names the dialog with the
tags either way round, also after a re-offer by the answerer. A pending
re-offer is kept across a restart of the relay (with the calls of the
sections it removed), so it can be rolled back after one.

### `list`

Lists the Call-IDs of active calls, sorted. `limit` (an integer) returns at
most that many.

```text
result: ok
calls:  [ "call-1@example.com" ]
subscriptions:
  - { call-id: "call-1@example.com", to-tag: rec-1, from-tags: [ alice-tag, bob-tag ] }
```

`subscriptions` lists the [subscriptions](#subscribe-request-subscribe-answer-and-unsubscribe)
of every call (`limit` applies to `calls` only).

### `query`

Reports a call's streams. Options: `call-id`, and optionally a party
(`to-tag` or `to-label`, else `from-tag` or `label`): only the dialogs
that party is in. A shortened real reply:

```text
result:  ok
created: 1795509703                  # Unix time of the offer
totals:
  RTP:  { packets: 1500, bytes: 258000, errors: 0 }
  RTCP: { packets: 12, bytes: 1056, errors: 0 }
tags:
  alice-tag:
    tag: alice-tag
    label: caller                     # if it has one
    created: 1795509703
    in dialogue with: bob-tag
    subscriptions: [ { tag: bob-tag, type: offer/answer } ]   # what it receives
    subscribers:   [ { tag: rec-1, type: pub/sub } ]          # who gets copies of it
    medias:
      - index: 1
        protocol: RTP/AVP
        streams:
          - local port: 30000                       # the relay's RTP port
            endpoint: { family: IPv4, address: 192.0.2.10, port: 40000 }
            stats:    { packets: 750, bytes: 129000, errors: 0 }
            DTMF:     [ { event: "5", timestamp: 3200, duration: 160 } ]
            RTCP:     { reports: 6, SSRC: 1234, fraction lost: 0,
                        packets lost: 0, jitter: 12, RTT: 41, ... }
          - local port: 30001                       # the relay's RTCP port
            ...
  bob-tag:
    ...
  rec-1:                                # a subscription
    tag: rec-1
    created: 1795509710
    answered: 1
    subscriptions: [ { tag: alice-tag, type: pub/sub }, { tag: bob-tag, type: pub/sub } ]
    medias:
      - index: 1
        type: audio
        protocol: RTP/AVP
        streams:
          - local port: 30010
            endpoint: { family: IPv4, address: 192.0.2.50, port: 50000 }
            stats:    { packets: 750, bytes: 129000, errors: 0 }   # copies sent
          - ...
```

- Each party is there once. A party in several dialogs (see [Calls with
  more than two parties](#calls-with-more-than-two-parties)) has the
  media of all of them, numbered on; `in dialogue with` names the first
  party it is in a dialog with, `subscriptions` all of them.
- `stats` counts what the relay received on that port; `errors` counts
  packets it dropped. On a subscription's streams it counts the copies
  sent to the subscriber.
- `subscriptions` and `subscribers` link the tags (rtpengine's form): the
  two parties of a dialog receive from each other (`offer/answer`), a
  subscription from its sources (`pub/sub`). With `from-tag`, a
  subscription is reported when it is that tag's or one of its sources'.
- `DTMF` lists detected key presses; see
  [Call features](call-features.md#dtmf-detection).
- `RTCP` appears once the endpoint has sent RTCP reports; see
  [Call features](call-features.md#rtcp-statistics).

Packets forwarded by the [XDP fast path](xdp.md) are included, as of the
relay's last poll of the kernel counters.

### Block and unblock

`block media`, `unblock media`, `block DTMF` and `unblock DTMF` stop or
resume relaying what one participant sends. Options: `call-id`, and
`from-tag` (or `label`, `from-label`) naming the participant. Without
it, every participant of the call is affected. With `to-tag` (or
`to-label`) too, only what it sends to that party (in a call with more
than two parties: its side of their dialog, not of its others). See
[Call features](call-features.md#blocking-media-and-dtmf).

`all` chooses which of a participant's flows `block media`, `unblock
media`, `silence media` and `unsilence media` act on, as in rtpengine:

| `all` | Flows |
|---|---|
| `none`, `offer-answer` (the default) | What it sends to its dialog's other party (or to the party it is `connect`ed to) |
| `except-offer-answer` | Only the copies of what it sends: subscriptions, directional `connect`, injections (silenced copies: G.711 silence; other audio is not copied while silenced) |
| `flows` | Both |
| `all` (or the flag `all`) | Every participant of the call, whatever the tags |

`block DTMF` and `unblock DTMF` take `all: all` and `none`.

`block DTMF` also takes rtpengine's DTMF security: `DTMF-security`
(`drop`, `silence`, `tone`, `random`, `zero`, `DTMF`, `off`) with
`digit`, `frequency` and `volume`; the triggers `trigger`, `trigger-end`,
`trigger-end-time`, `trigger-end-digits`, `DTMF-security-trigger` and
`DTMF-security-trigger-end`; and `DTMF-delay`. `unblock DTMF` ends it. See
[DTMF security](call-features.md#dtmf-security).

### `start recording` and `stop recording`

Records every stream of a call in `[recording] dir`, and converts each
recording to an audio file when it ends.

| Option | Meaning |
|---|---|
| `call-id` | The SIP Call-ID |
| `from-tag` | Only the dialog with this tag (either party's) |
| `format` | `pcap`, `wav`, `flac`, `opus` or `mp3` |
| `channels` | `stereo` or `mono` |
| `sample-rate` | 8000, 16000, 24000 or 48000 |
| `bitrate` | kbit/s, for `opus` and `mp3` |
| `keep-pcap` | `yes` to keep the packets once converted |
| `metadata` | Tags for this recording: a dictionary of strings (keys of letters, digits, `_ - .`, up to 64; values up to 1024 octets; 32 at most, with the configured ones), or one string, which becomes `comment`. Added to `[recording.metadata]`, in the JSON and the audio file |
| `recording-path`, `recording-file`, `output-destination`, `recording-pattern` | Where this call's files go and what they are called, inside `[recording] dir`; see [Recording](call-features.md#what-you-get) |

Options left out take the `[recording]` defaults. See
[Call features](call-features.md#recording).

`pause recording` (`call-id`, optionally `from-tag`) stops writing
packets but keeps the files open; `start recording` then goes on in the
same files. `start recording` on a call already being recorded changes
nothing. A recording started again after `stop recording` goes to a new
file (`<call>-<tag>-<section>-2.pcap`, then `-3`, …), so the first one's
pcap and audio file are never overwritten. An `offer` or `answer` with `record-call: yes` starts recording
the dialog (when `[recording] dir` is set; the recording options above
apply), and `record-call: no` stops it, as rtpengine's `record-call`.

### `play media` and `stop media`

Plays an audio file (MP3, FLAC or WAV) to one participant.

| Option | Required | Meaning |
|---|---|---|
| `call-id` | yes | The SIP Call-ID |
| `from-tag` | for `play media` (or `label`, `from-label`, `flags: all`) | The participant who hears it (either party's tag); `all` (the flag, or `all: all`): every participant |
| `file` | for `play media`, or `blob` | Path of an MP3, FLAC or WAV file on the relay host |
| `blob` | for `play media`, or `file` | The file itself, in the request |
| `start-pos` | no | Start this many milliseconds into the media |
| `duration` | no | Play only this many milliseconds of it |
| `repeat-times` | no | How many times to play it (default 1) |
| `repeat-duration` | no | Repeat it for this many milliseconds in all (cut there), instead of `repeat-times` |

The reply's `duration` is the media's length in milliseconds (after
`start-pos` and `duration`). An announcement from a `file` goes on after a
restart of the relay; one from a `blob` does not. `stop media` without
`from-tag` stops every announcement in the call. See
[Call features](call-features.md#announcements).

### `play DTMF`

Sends key presses to the other party, as if the participant `from-tag`
names had pressed them (rtpengine's meaning of `from-tag` here).

| Option | Required | Meaning |
|---|---|---|
| `call-id` | yes | The SIP Call-ID |
| `from-tag` | yes (or `label`, `from-label`, `flags: all`) | The participant "pressing" the keys (either party's tag); `all`: every participant |
| `code` | yes | The keys: a string of `0-9`, `*`, `#`, `A-D` (several are played in turn), or one event number 0–15 |
| `duration` | no | Milliseconds per key (default 250; clamped to 40–5000, as rtpengine does) |
| `pause` | no | Milliseconds between keys (default 100; clamped to 0–5000) |
| `volume` | no | The level, in dB below 0 dBm0 (default 8, i.e. −8 dBm0; clamped to 0–63) |

Values of `duration`, `pause` and `volume` that are not numbers are refused.

If the listener negotiated `telephone-event`, the keys are sent as RFC
4733 events; otherwise as in-band tones in the audio it receives: G.711,
or G.722, G.729, Opus (and AMR with the `amr` build), encoded by the
relay (an error if it receives neither events nor such audio). See
[Call features](call-features.md#sending-dtmf).

### `silence media` and `unsilence media`

Like `block media`, but the participant's audio is replaced by silence
instead of being dropped, so the other party keeps receiving a stream.
Same options as [block and unblock](#block-and-unblock).

### `statistics`

No options. The reply's `statistics` dictionary has:

- `currentstatistics`: `sessionsown`, `sessionsforeign` (always 0),
  `sessionstotal`, `transcodedmedia` (media sections being transcoded),
  `calls` (relayed media sections), and the traffic per second over the
  latest second (sampled every second): `packetrate`, `byterate` and
  `errorrate` in all, and the same with `_user` (userspace) and `_kernel`
  (the XDP fast path, as of the relay's last poll of its counters; it
  counts no errors, so `errorrate_kernel` is 0). Errors are packets
  dropped and packets the kernel refused to send. Octets are the UDP
  payloads (RTP and RTCP datagrams);
- `totalstatistics`: `uptime` (seconds), `relayedpackets` and
  `relayedbytes`, `droppedpackets` and `relayedpacketerrors` (the
  userspace path), `relayedpackets_kernel` and `relayedbytes_kernel` (the
  XDP fast path), `timeoutsessions`, `srtprejected` and `zrtppackets`;
- `controlstatistics`: `requests` (per command), `errors` and
  `retransmissions`.

The names follow rtpengine's where the meaning is the same.

### `subscribe request`, `subscribe answer` and `unsubscribe`

A subscription sends a third party (the *subscriber*: a SIPREC recording
server, a monitoring tool) copies of what parties of a call send, as
rtpengine's commands of the same names do. The subscriber only receives.

`subscribe request` takes the call's `call-id` and the sources:

| Key | Meaning |
|---|---|
| `from-tag` | One party, by its tag |
| `label`, `from-label` | One party, by its label |
| `from-tags` | Several parties (a list of tags) |
| `flags: all` | Every party of the call |
| `to-tag` | The subscription's tag (one is made up without it) |
| `set-label`, `to-label` | A label for the subscriber |
| `flags: siprec` | Label the sections for SIPREC metadata (below) |
| `flags: inactive` | Offer the sections inactive: nothing is sent |
| `transport-protocol` | `RTP/AVP` (the default), `RTP/AVPF`; with SRTP (SDES: the offer carries the relay's key, and the answer must take SRTP) `RTP/SAVP`, `RTP/SAVPF`; or for a WebRTC subscriber `UDP/TLS/RTP/SAVP`, `UDP/TLS/RTP/SAVPF` (DTLS-SRTP: the offer carries the relay's fingerprint with `a=setup:actpass`, ICE-lite credentials and host candidates, `a=rtcp-mux` and `a=mid`; the answer must take DTLS-SRTP, and nothing is sent before the handshake) |
| `direction` | list of two interface names | The interface for the offerer's side and for the answerer's side. One name: that interface for both. Default: the first interface of the offerer's address family, for both. |
| `address-family` | `IP4`, `IP6` | The answerer's side uses the first interface of this family: IPv4 and IPv6 bridged. Refused when no interface has it, or `direction` names one that does not. See [IPv6](media.md#ipv6). |
| `media-address` | an IP address | Write this address into the SDP returned (`c=`, candidates), instead of the interface's; of the interface's family. |

The reply's `sdp` is the offer to send the subscriber: one `a=sendonly`
media section per section of each source party (in the order of the
tags, then of the call's sections), with the formats that party offered
or answered with and their `a=rtpmap`/`a=fmtp` lines. It also has
`to-tag` (the subscription's), `from-tags` (the sources) and, with a
single source, `from-tag`. With `siprec`, each section has an
`a=label:<n>` (1, 2, …) and the reply has `tag-medias` (a list, per
source tag, of `{tag, medias}`, where each media is `{index, type,
label, mode}`: its position in the offer counting from 1, `audio` or
another media type, its label, and the source party's direction) and
`media-labels` (a dictionary from each label to the same, with `tag`).

`subscribe answer` takes `call-id`, the subscription's `to-tag` and the
subscriber's `sdp` (and `flags: trust-address`, `received-from` and
`endpoint-learning` as an `answer` does). Copies start then. The
subscriber receives the media as the sources send it, without
transcoding: a section it accepts must keep at least one offered format,
or the answer is refused; a section it rejects (port 0) gets nothing.

`unsubscribe` takes `call-id` and the subscription's `to-tag` (or
`to-label`). Deleting the call (or its timing out) ends its subscriptions
too. Naming the destination of a directional `connect` instead stops its
copies (see [`connect`](#connect)).

### `connect`

Joins a party of one call with a party of another (or the other party of
the same call), as after a transfer: what each sends goes to the other,
from the relay port it already knows, so neither needs a re-INVITE. The
parties they leave are detached: their media is dropped.

| Option | Required | Meaning |
|---|---|---|
| `call-id` | yes | The first party's call |
| `from-tag` | yes (or `label`, `from-label`) | The first party (either tag of the dialog) |
| `to-tag` | yes (or `to-label`) | The second party (a label of the `to-call-id`'s) |
| `to-call-id` | no | The second party's call (default: the same) |
| `flags: directional` | no | Copies instead of a transfer (below) |
| `flags: bidirectional` | no | With `directional`: copies both ways |
| `from-tags`, `flags: all` | no | With `directional`: several sources (a list of tags), or every party of the call but the destination |

Media sections are joined in order (with a `warning` when the counts
differ). The two calls may be on different media workers: each passes
its party's packets to the other through a preallocated queue, which
then encrypts them (SRTP, DTLS) for its own party. When their audio
codecs differ and the relay converts both (G.711, G.722, G.729, Opus,
AMR), each one's audio is converted for the other. When either call
ends, the other party is left alone. Connecting a party that is already
connected (a second transfer) moves it: the party it was connected to is
detached, both ways. Connections are kept in the state
file and made again after a restart. Connected calls enter the XDP fast
path once settled (on one worker or across two: each publishes its
party's settled address for the other); the parties left behind are
dropped in the kernel.

With `flags: directional`, nobody is detached: what each source sends is
also **copied** to the destination, which keeps its own media (so it hears
its own dialog's other party and the sources: a supervisor listening in,
or whispering with `bidirectional`, which copies what the destination
sends back to each source as well). Several sources (`from-tags`, `all`)
are taken only with `directional`, as in rtpengine. Each copy is a stream
of its own (the source's SSRC), sent from the destination's relay port,
encrypted for it if it uses SRTP. Copies are taken as packets arrive
(decrypted, before blocking or the source's own transcoding) and
converted to the destination's audio codec when it differs (G.711, G.722,
G.729, Opus, AMR: as a connection's are); with a codec the relay does not
convert, they go as sent, and the reply's `warning` says so.
Across media workers, copies pass through a preallocated queue, as a
connection's packets do. A source with copies stays in userspace (off the
XDP fast path). Copies end when either party's dialog does, are kept in
the state file, and stop with `unsubscribe` naming the destination
(`call-id` and `to-tag` or `to-label`).

### Calls with more than two parties

One `call-id` may hold more than two parties (tags), each in dialogs with
one or more of the others: a B2BUA that joins its legs within one call,
a consultation before a transfer, a three-way call. Every dialog has
media of its own (its own ports), so a party in two dialogs sends to,
and receives from, two pairs of relay ports.

- An `offer` without `to-tag` from a new tag starts a dialog, as always.
- An `offer` with a `to-tag` is for the dialog between those two
  parties: the one either of them offered, if there is one (a re-INVITE
  from either side). If the offerer is in a dialog with someone else and
  the `to-tag` is another party already in the call, it starts a new
  dialog between the two; its `answer` (same tags) finds it. A `to-tag`
  that is no party of the call is the answerer's tag of the offerer's
  dialog, as in a two-party call.
- Each dialog ends on its own: a `delete` naming one party's tag (and
  optionally the other's in `to-tag`) leaves its other dialogs alone.

**Labels.** `label` (or `set-label`) on an `offer` labels the offerer, on
an `answer` the answerer; on `subscribe request` (`set-label` or
`to-label`) the subscriber; on `publish` the publisher. A label belongs
to one party of the call (labelling another party with it moves it). The
commands that select parties take a label where they take a tag:
`label` or `from-label` for `from-tag`, `to-label` for `to-tag`:
`block`/`unblock media` and `DTMF`, `silence media`, `play media`,
`stop media`, `play DTMF`, `subscribe request`, `connect`, `query`. A
label no party has is an error (`no party with label …`). `query`
reports each party's label. Labels are kept in the state file.

### `create` and `create answer`

`create` makes an SDP offer of the relay's own, for a new party of a call
whose media is at the endpoint that answers it (a media server, a
conference leg), as rtpengine's `create` does. The proxy sends the offer
there and hands the answer back with `create answer`. The party then
exists like any other: join it with [`connect`](#connect), a
subscription, or play media to it. Until then its media goes nowhere.

| Option | Meaning |
|---|---|
| `call-id` | The call (made up, 32 hex digits, when missing) |
| `from-tag` | The new party's tag (made up, 16 hex digits, when missing) |
| `codec: offer` | The formats offered: `PCMU`, `PCMA`, `G722`, `G729`, `CN`, `opus`, `AMR`, `AMR-WB`, `telephone-event` (default `PCMA`, `PCMU`) |
| `medias` | Several sections: a list of dictionaries with `type` (`audio`) and `codecs` (a list of names, else `codec: offer`'s) |
| `label` (or `set-label`) | A label for the party |
| other options | As for an [`offer`](#offer): `transport-protocol` (SRTP with SDES, DTLS-SRTP), `SDES`, `DTLS`, `ICE`, `direction`, `address-family`, `media-address`, … |

The reply has `call-id`, `from-tag` and `sdp` (the offer). `create`
again with the same tags offers the same ports again.

`create answer` takes `call-id`, `from-tag` (the created party's) and
`sdp` (its endpoint's answer), with the options of an
[`answer`](#answer) (`flags: trust-address`, `endpoint-learning`, …).
`query` lists the created party like any other. Deleting it (`delete`
with its tag) ends its media. A created party, answered or not, is kept
across a restart of the relay.

### `inject start` and `inject stop`

`inject start` sends what one party sends to another party as well, one
way (rtpengine's injection): the destination keeps its own media and also
gets the source's. It is a directional [`connect`](#connect) of one
source, with rtpengine's keys:

| Option | Required | Meaning |
|---|---|---|
| `call-id` | yes | The destination's call |
| `to-tag` | yes | The destination party |
| `source-tag` | yes | The source party |
| `source-call-id` | no | The source's call (default: the same) |

`inject stop` (the same keys) ends it; so does `unsubscribe` naming the
destination, or the end of either party's dialog. Other injections and
announcements to the destination go on. rtpengine mixes the injected
audio into the destination's stream; the relay has no mixer, so the
destination gets it as a stream of its own (the source's SSRC, from the
destination's relay port, converted to its codec), which an endpoint may
play instead of the other stream rather than with it.

### `mesh`

Sends what parties send to other parties, of one call or several, in one
request (rtpengine's `mesh`): for a conference without a mixer, each
participant gets the others' streams.

| Option | Meaning |
|---|---|
| `calls` | The call-ids (at least one, all known) |
| `tags` | A list of `{from: <tag>, to: [<tag>, …]}`: each `to` party gets what the `from` party sends |
| `flags: bidirectional` | Each pair both ways |
| `flags: unsubscribe` | First, each `from` party stops hearing anyone: its dialogs' other parties' media to it is blocked (as `block media` of theirs), and copies to it end; with `bidirectional`, nobody hears it either |

Tags are looked up in the listed calls; a tag that is a party of two of
them is refused. Everything is checked before anything changes. The
copies are those of a directional [`connect`](#connect): streams of their
own, converted to the receiver's codec, kept across a restart; `unblock
media` undoes `unsubscribe`'s blocking. rtpengine also merges the listed
calls into one, and `mesh` without `tags` only does that; rtpflux names
parties by call and tag, so it does nothing then.

### `publish`

As rtpengine's: a party that only sends (a WebRTC client publishing its
camera and microphone, say) offers its media with `publish` (`call-id`,
`from-tag`, `sdp`, and the options of an `offer`); the reply's `sdp` is
the relay's answer, receive-only. Others then receive it with
[`subscribe request`](#subscribe-request-subscribe-answer-and-unsubscribe)
naming its tag, each in its own profile (an SRTP or DTLS publisher's
media reaches plain RTP subscribers decrypted). `delete` ends the
publication and its subscriptions.

Each subscribed section takes relay ports of its own; what the
subscriber sends to them (RTCP reports, say) is not relayed. A call with
a subscription leaves the XDP fast path. Subscriptions use RTP, SRTP with
SDES or DTLS-SRTP. They are kept across a restart of the relay (with
the state file or Redis): their ports and keys come back, and an answered
one goes on copying.
Which legs receive copies follows a rule checked against reference
vectors: only a subscription's legs are ever copied to, so a port that
served one and now serves another call never gets them.

## Options

These options are read by `offer` (and `answer` where it makes sense).
Flags go in the `flags` list.

| Option | Values | Meaning |
|---|---|---|
| `direction` | list of two interface names | The interface for the offerer's side and for the answerer's side. One name: that interface for both. Default: the first interface for both. |
| `flags: trust-address` | flag | Use the address in the SDP as is. Without it, the relay uses `received-from` (where the SIP message came from) when the proxy sends it. |
| `received-from` | `["IP4", "192.0.2.10"]` | The address the SIP message came from (sent by proxy modules automatically) |
| `endpoint-learning` | `heuristic` (default), `delayed`, `immediate`, `off` | How the relay learns where media really comes from. See [NAT and latching](media.md#nat-and-latching). |
| `flags: strict-source` | flag | Drop media from any address other than the learned one |
| `flags: asymmetric` | flag | The side does not send from where it receives: nothing is learned from its packets (as `endpoint-learning: off`) |
| `flags: port latching` | flag | Keep the relay's ports across a re-offer whatever the endpoint's port: what rtpflux always does |
| `flags: loop protect` | flag | Mark the SDP the relay writes with `a=rtpflux:<instance>`; an SDP carrying this relay's mark is returned as it is, nothing set up (an SDP loop through the same relay) |
| `flags: track-state` | flag | A re-offer of an answered dialog can be taken back with [`rollback`](#rollback) until its answer |
| `flags: unidirectional` | flag | Media flowing one way may enter the [XDP fast path](xdp.md) (both sides' addresses still settled); otherwise both directions must have carried traffic |
| `media echo` (or `media-echo`) | `forward`, `backwards`, `both`, `blackhole` (`sinkhole`), `off` | For testing: `forward`: the receiver of this message (the answerer for an `offer`, the offerer for an `answer`) hears its own media, the other's is dropped; `backwards`: the sender hears itself; `both`: each hears itself; `blackhole`: all media dropped; `off`: relayed again. Echoed media goes back as it came (the sender's codec, not transcoded); echoed RTCP is dropped. Kept across a restart. |
| `DTMF-delay` | milliseconds | The keys of the party that sent this SDP reach the other party that much later (at most 10 000). See [DTMF security](call-features.md#dtmf-security). |
| `OSRTP` | list of `offer`, `accept` (also `offer-RFC`, `accept-RFC`) | Opportunistic SRTP (RFC 8643): an offer in a plain profile (`RTP/AVP`) with `a=crypto` is passed on as one, with the relay's key, and SRTP is used on both sides when the answerer takes it (plain RTP when it does not). `offer`: a plain offer becomes an opportunistic one to the answerer. `accept`: the offerer's opportunistic SRTP is taken even when the answer is plain (the relay converts). `offer-legacy`: the same in the older form, each stream offered twice (in `RTP/SAVP` with the relay's key, then in `RTP/AVP`), the answerer's choice of the two read back. `accept-legacy`: such a doubled offer is taken as one opportunistic stream (its SRTP accepted), and answered doubled again. |
| `flags: media-handover` | flag | Follow a side whose source changes mid-call (a NAT rebinding): a new source takes the learned address over after 3 packets in a row. See [NAT and latching](media.md#nat-and-latching). |
| `replace` | list of `origin`, `username`, `session-name`, `sdp-version`, `force-increment-sdp-version`, `session-connection`, `zero-address` (or flags `replace-<value>`) | `origin`: also rewrite the `o=` line to the relay's address (a call across two interfaces, two different `direction` names, gets it without asking, so neither network sees the other's addresses). `username`, `session-name`: `-` in `o=` and `s=`. `sdp-version`: the relay sets the `o=` version of what each party gets: the sender's at first, raised by one only when what that party gets changes (a re-INVITE that changes nothing keeps it). `force-increment-sdp-version` (also a flag): raised every time. `origin-full`: the whole `o=` line is the relay's, `o=- <id> <version> IN <family> <relay address>`, its session id the same in every SDP that party gets and its version as with `sdp-version`. `session-connection` and `zero-address` are always done: every `c=` is the relay's. |
| `sdp-attr` | `{<level>: {add: [...], remove: [...], substitute: [[from, to], ...]}}` | Attribute edits, without `a=`: `<level>` is `global` (or `none`) for the session, or a media kind (`audio`, `video`, …) for its sections. `remove` names an attribute (`tool` removes `a=tool:…`) or a whole value; `substitute` replaces a whole value; `add` appends. Edits apply to the input's attributes before the relay's own; the relay's (keys, ICE, `a=rtcp`) are not touched. In `offer` and `answer`. |
| `flags: strip-extmap` | flag | Remove `a=extmap` (RTP header extensions) everywhere |
| `flags: generate-mid` | flag | In an `offer`: give each section without `a=mid` one (its index) |
| `flags: no-rtcp-attribute`, `full-rtcp-attribute` | flag | `a=rtcp`: never written, or always written in full (port, network, address) for a section without `rtcp-mux`. By default the relay rewrites the input's. |
| `transport-protocol` | `RTP/AVP`, `RTP/SAVP`, `RTP/AVPF`, `RTP/SAVPF`, `UDP/TLS/RTP/SAVP`, `UDP/TLS/RTP/SAVPF` | The profile offered to the answerer, for example plain RTP towards a desk phone when the caller is a browser. See [Bridging](media.md#bridging-webrtc-and-sip-phones). |
| `ICE` | `default`, `remove`, `force`, `reject`, `force-relay`, `optional` | `default`: be an ICE agent towards both sides when the offerer uses ICE (but not towards a phone a WebRTC offer is bridged to with a SIP `transport-protocol`); `remove`: no ICE on either side (browsers need ICE, so do not use it for them); `force`: ICE towards both sides; `reject`: the offer's ICE is ignored, so none is answered (as `remove`). `force-relay`: an offer whose sections all use ICE passes as it is (its `m=` and `c=` lines, ICE, keys and DTLS untouched, its own relay candidates dropped) with the relay added as a relay candidate of each section; what reaches the relay's ports is relayed as it is, nothing terminated, so media goes through the relay only when the endpoints' ICE picks it. `optional`: the same, keeping all the endpoints' candidates. Without ICE in the offer, both are `force`. |
| `ICE-lite` | `off`, `forward`, `backward`, `both` | Where the relay is an ICE-lite agent rather than a full one (default: `[ice] mode`): `forward` towards the answerer, `backward` towards the offerer, `both`, or `off` (full on both sides). See [ICE](media.md#ice). |
| `flags: fragment` | flag | With `offer`: the `sdp` is a trickle ICE fragment, not an offer; see [Trickle ICE](#trickle-ice) |
| `codec: transcode` | `["PCMA"]`, `["PCMU"]`, `["G722"]`, `["G729"]`, `["opus"]`, and with the `amr` build feature `["AMR"]` or `["AMR-WB"]`; a name may carry rtpengine's parameters, `opus/48000/2/32000` | Offer this codec too and convert when the answerer picks it. For Opus the fourth field is the bitrate (bit/s, 6000 to 510000) of the relay's Opus encoder. |
| `codec: consume` | list of codec names | As `mask`, and the codec is withheld from the answerer even when there is nothing to transcode to |
| `codec: ignore` | list of codec names | The offerer's codecs treated as never offered: not offered to the answerer, never transcoded from |
| `codec: accept` | a codec name | The offerer's codec the relay transcodes from (by default its first convertible one), so the offerer is answered with it when the answerer takes the transcoded codec |
| `codec: set` | list of codec specifications, `opus/48000/2/24000`, `AMR/8000/1/7950` | Set a codec's parameters where the relay encodes it: Opus's bitrate; AMR's and AMR-WB's mode, by its bitrate (AMR 4750 to 12200, AMR-WB 6600 to 23850), used towards a side whose `mode-set` takes it (else the relay's default mode, 12.2 or 12.65 kbit/s). Other parameters are warned about. |
| `codec: mask` | list of codec names | Withhold the offerer's codec from the answerer |
| `codec: strip` | list of codec names, or `all` | Remove these of the offerer's formats from the offer to the answerer (with their `a=rtpmap`, `a=fmtp` and `a=rtcp-fb` lines). A codec named in `transcode` that the offerer has is kept. An offer that would leave a section without a codec (only telephone events or comfort noise, and nothing to transcode to) is refused. |
| `codec: except` | list of codec names | Keep these whatever `strip` says (`strip: all` with `except` offers only those) |
| `codec: offer` | list of codec names | As `except`, and put them first, in this order |
| `flags: codec-transcode-<name>`, `codec-mask-<name>`, `codec-strip-<name>`, `codec-except-<name>`, `codec-offer-<name>`, `codec-set-<spec>`, `codec-accept-`, `codec-consume-`, `codec-ignore-<name>` | flag | The same as `codec`, as flags |
| `codec: transcode: ["telephone-event"]` | | When the offerer has no telephone events, offer them to the answerer and convert (DTMF transcoding); see [DTMF transcoding](call-features.md#dtmf-transcoding) |
| `flags: always transcode` | flag | Keep the offerer's telephone events and convert should the answerer refuse them (DTMF transcoding) |
| `SDES` | list of `off`, `no-<suite>`, `only-<suite>` (or flags `SDES-<value>`) | The suites used: the answerer is offered every allowed suite, the offerer's first (else the first allowed of `AES_CM_128_HMAC_SHA1_80`, `AES_CM_128_HMAC_SHA1_32`, `AEAD_AES_128_GCM`, `AEAD_AES_256_GCM`, `AES_256_CM_HMAC_SHA1_80`, `AES_256_CM_HMAC_SHA1_32`), and of the offerer's own lines the first allowed one is used. `off`: no SDES; an answerer offered `RTP/SAVP(F)` needs it, so that is refused. Options that leave no suite, on either side, are refused. `unencrypted_srtp`, `unencrypted_srtcp`, `unauthenticated_srtp`: the answerer is offered AES-CM suites declaring them, and lines declaring them are accepted (see [SDES keys](media.md#sdes-keys-acrypto)). `lifetime`: each key with `|2^31`. `pad`: keys keep base64's padding (always so in rtpflux). `static`: an answer to a re-offer keeps the keys agreed. `nonew`: only the offerer's own suites are offered (over `no-`/`only-`). `prefer`: an offer with both DTLS and SDES is taken as SDES (its DTLS refused). `order:<suite>,…`: the order suites are offered in; `offerer_pref:<suite>,…`: which of the offerer's lines is taken; `key-<suite>:<base64>`: the proxy's own key for that suite; `encrypted_srtp`, `encrypted_srtcp`, `authenticated_srtp` undo the corresponding values. Others are warned about. |
| `DTLS` | `off`, `passive`, `active` | `passive` / `active`: the relay's `a=setup` in the SDP it writes: in an `offer`, instead of `actpass` (the answer must fit it, RFC 4145); in an `answer`, towards an offerer that offered `actpass`. `off`: no DTLS-SRTP; refused when the answerer is offered a DTLS profile. |
| `DTLS-reverse` | `passive`, `active` | The relay's role towards DTLS offered to it with `actpass`: `passive` (the default; it waits for the handshake) or `active` (it starts it) |
| `DTLS-fingerprint` | `SHA-1`, `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512` | The hash of the relay's `a=fingerprint` (default: SHA-256 in an offer, the offerer's own hash in an answer) |
| `ptime` | milliseconds (integer or string), a multiple of 10 from 10 to 200 | The packet time of the answerer's leg: its offer gets `a=ptime` with this value, and the relay regroups the offerer's audio into packets of it. The offerer keeps its own packet time (its `a=ptime`, else 20 ms): what the answerer sends is regrouped back. G.711, G.722 and G.729 are repacketised (after any transcoding), and Opus is decoded and encoded again in packets of one frame (the longest of 10, 20, 40 or 60 ms not over the packet time); other codecs pass as they are, with a `warning`. |
| `ptime-reverse` | as `ptime` | The same for the offerer's leg: its answer gets `a=ptime` with this value. |
| `rtcp-mux` | list of `offer`, `require`, `demux`, `accept`, `reject` (or flags `rtcp-mux-<value>`) | Where RTCP is multiplexed on the RTP port; see [rtcp-mux](media.md#rtcp-mux). Read from the `offer`. |

## Using rtpflux with a SIP proxy

### Kamailio

A complete, tested configuration is in
[`contrib/kamailio/kamailio.cfg`](https://github.com/RustedBytes/rtpflux/blob/main/contrib/kamailio/kamailio.cfg); see
[Integration](integration.md). The essentials:

```text
loadmodule "rtpengine.so"
modparam("rtpengine", "rtpengine_sock", "udp:127.0.0.1:2223")

request_route {
    ...
    if (is_method("INVITE|ACK|BYE|CANCEL|UPDATE") || has_body("application/sdp")) {
        rtpengine_manage("trust-address replace-origin");
    }
    ...
}
```

`rtpengine_manage()` sends `offer`, `answer` or `delete` depending on the
message. You can also call `rtpengine_offer()`, `rtpengine_answer()` and
`rtpengine_delete()` yourself. Flags in the string become ng options:

| Kamailio flag | ng option |
|---|---|
| `trust-address` | `flags: [trust-address]` |
| `replace-origin` | `replace: [origin]` |
| `direction=external direction=internal` | `direction: [external, internal]` |
| `RTP/AVP`, `RTP/SAVPF`, … | `transport-protocol` |
| `ICE=remove` | `ICE: remove` |
| `codec-transcode-PCMA` | the transcode option |

**Example: a browser calling a desk phone.** Offer plain RTP to the
phone:

```text
rtpengine_offer("trust-address replace-origin RTP/AVP");
```

The phone gets an ordinary RTP offer with a port per stream. The browser
gets its answer with DTLS-SRTP, ICE and BUNDLE, as it expects. See
[Media handling](media.md#bridging-webrtc-and-sip-phones).

### OpenSIPS

A complete, tested configuration is in
[`contrib/opensips/opensips.cfg`](https://github.com/RustedBytes/rtpflux/blob/main/contrib/opensips/opensips.cfg); see
[Integration](integration.md#opensips). The essentials:

```text
loadmodule "rtpengine.so"
modparam("rtpengine", "rtpengine_sock", "udp:127.0.0.1:2223")

route {
    ...
    if (has_body("application/sdp")) {
        if (is_method("INVITE")) rtpengine_offer("trust-address replace-origin");
    }
    ...
}

onreply_route {
    if (has_body("application/sdp")) rtpengine_answer("trust-address replace-origin");
}
```

and `rtpengine_delete()` on BYE and CANCEL.

OpenSIPS's `siprec` module records a call through
[subscriptions](#subscribe-request-subscribe-answer-and-unsubscribe): it
sends `subscribe request` with `flags: [all, siprec]`, gives the
recording server the offer with the `tag-medias` labels in its metadata,
and passes the server's answer back with `subscribe answer`.

### Trickle ICE

An endpoint that trickles ICE (RFC 8838) sends candidates it finds later in
SIP INFO requests whose body is `application/trickle-ice-sdpfrag` (RFC 8840):

```text
a=ice-ufrag:8hhY
a=ice-pwd:asd88fgpdd777uzjYhagZg
m=audio 9 RTP/AVP 0
a=mid:0
a=candidate:2 1 UDP 1694498815 192.0.2.3 5010 typ srflx raddr 192.0.2.1 rport 8998
a=end-of-candidates
```

The proxy hands such a body to the relay as an `offer` with
`flags: [fragment]`, the dialog's `call-id` and the sender's tag as
`from-tag` (the caller's or the callee's). The relay gives the new
candidates to its agent towards that endpoint, by `a=mid`, if the body's
`ice-ufrag` and `ice-pwd` are the current ones (a body of another ICE
generation is ignored, as RFC 8840 §4.4 says); candidates it already has
are skipped. The reply's `sdp` is the fragment to forward to the other
endpoint: the relay's credentials towards it and `a=end-of-candidates`
for each section (the relay has nothing to trickle).

### What rtpflux does not support (yet)

Commands other than those listed above are answered with an error (among
rtpengine's: `start forwarding` and `stop forwarding`, which feed its own
recording daemon), so the proxy sees a
clear failure rather than a silent no-op. Options, flags and values
rtpflux does not implement are ignored, and named in the reply's
`warning` (see [How messages look](#how-messages-look)). Among them:

- `T.38` gateway options: T.38 is relayed between T.38 endpoints only.
- Mixing the audio of several parties into one stream (a conference
  bridge). `connect` joins two parties, and a subscription to several
  parties delivers each one's media in a section of its own, as
  rtpengine does without its mixer.
- Codec parameters other than Opus's bitrate and AMR's mode.
- `delay-buffer` (all media held back by a time, so that DTMF security
  can take a key's first milliseconds out too): keys are found as they
  arrive, so an in-band key's first frame or two pass.
