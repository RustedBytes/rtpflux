# Call features

Besides relaying media, rtpflux can detect key presses, mute
participants, record calls, play announcements, convert codecs and report
call quality. The SIP proxy triggers each feature with an ng command; see
[Control protocol](control-protocol.md) for the message format.

Calls with DTMF detection, blocking, an announcement or recording can stay
in the [XDP fast path](xdp.md): the kernel drops what is blocked, sends
telephone events up to the relay, and copies recorded packets to it.
Transcoding is done in userspace, so a call that uses it leaves the fast
path.

## DTMF detection

When a side offers telephone events (`a=rtpmap:101 telephone-event/8000`
in its SDP), rtpflux watches its key presses (RFC 4733 *DTMF* events).
Each key press is reported **once**, when it ends. The end is signalled by
the event's end flag, the next key press, ordinary audio, or silence for
three packet intervals. Retransmitted and duplicate event packets are
recognised and not counted again.

Each key press is logged:

```text
INFO rtpflux::relay::worker: dtmf: slot 0: '5' (160 ms)
```

and listed by `query` under the stream that sent it:

```text
DTMF:
  - { event: "5", timestamp: 3200, duration: 160 }   # duration in ms
  - { event: "#", timestamp: 8000, duration: 120 }
```

Events are passed on to the other side unchanged (unless blocked, below).

## Blocking media and DTMF

Mute a participant without ending the call:

| Command | Effect |
|---|---|
| `block media` | Stop relaying everything this participant sends (audio, video and its DTMF) |
| `unblock media` | Relay it again |
| `block DTMF` | Stop relaying only its key presses; audio still flows |
| `unblock DTMF` | Relay its key presses again |

Name the participant with `from-tag` (either party's tag). Without
`from-tag`, the whole call is affected.

**Example: a PIN prompt.** An IVR asks the caller for a PIN. To keep the
PIN away from the agent's phone, block the caller's DTMF towards the
agent. Blocked key presses are still detected and listed by `query`.

```text
command:  block DTMF
call-id:  call-1@example.com
from-tag: alice-tag
```

Blocked media is still received, counted in the statistics and checked
for DTMF; it is just not forwarded. RTCP is never blocked, so quality
reports keep flowing.

### DTMF security

`block DTMF` can do more than drop key presses (rtpengine's
`DTMF-security`). The keys a participant presses, as telephone events or
as in-band tones in its audio, can be:

| `DTMF-security` | What the other party gets for each key |
|---|---|
| `drop` (the default) | Nothing: telephone events are dropped (in-band tones pass) |
| `silence` | Silence in its audio while the key is held |
| `tone` | A sine tone (`frequency`, Hz, default 400) while the key is held |
| `zero` | Key `0` instead |
| `DTMF` | The key `digit` (or `code`) names instead (`0-9 * # A-D`) |
| `random` | Another key, a random one (never the key itself, so it tells nothing of it) |
| `off` | The key itself |

A telephone event's key is rewritten in place (`zero`, `DTMF`,
`random`), or the event is dropped and the replacement played in the
listener's audio. An in-band key is found in the audio (G.711 as it is;
G.722, G.729, Opus and AMR decoded) and, while it is held, the
replacement is played instead of the participant's audio. Finding a tone
takes a frame or two, so its first tens of milliseconds pass. Replacements
are at `volume` (dB below 0 dBm0, default 10). Detected keys are still
listed by `query` as they were pressed.

**Triggers.** With `trigger` (a key sequence such as `*1`), nothing is
blocked until the participant presses it; then `DTMF-security-trigger`
applies (default `drop`). It ends with the key sequence `trigger-end`, or
after `trigger-end-time` milliseconds or `trigger-end-digits` more keys,
switching to `DTMF-security-trigger-end` (default `off`); then the trigger
is watched for again. Keys more than 2.5 s apart start a sequence afresh.

```text
command:                block DTMF
call-id:                call-1@example.com
from-tag:               alice-tag
trigger:                "*1"
DTMF-security-trigger:  random
trigger-end-digits:     16
```

**Delay.** `DTMF-delay` (milliseconds, at most 10 000), on `block DTMF`
or on the `offer` or `answer` of the participant, makes its keys reach the
other party that much later: telephone events are held back and sent
again later (as events if the other party takes them, else as tones in
its audio). An in-band key is replaced by silence while it is held and
played after the delay (or as soon as it is over, if it lasts longer than
the delay). Keys waiting for their delay are kept in a small fixed queue
(eight keys); more are dropped and counted.

`unblock DTMF` ends DTMF security as well. Calls with DTMF security stay
in userspace (off the XDP fast path). The settings are kept across a
restart.

**Silencing** (`silence media`, `unsilence media`) is the gentler form:
the participant's packets keep flowing with their sequence numbers and
timestamps, but G.711 audio is replaced by silence, so the other phone
does not see the stream stop. Audio in other codecs is held back (there is
no silent payload to put in without encoding it), and telephone events
still pass. A silenced call stays out of the XDP fast path while silenced.

## DTMF transcoding

When one side sends DTMF as telephone events (RFC 4733) and the other
only as tones in its audio, rtpflux converts between them, as rtpengine
does:

- **The offerer has no telephone events**: with `codec: {transcode:
  ["telephone-event"]}` (or the flag `codec-transcode-telephone-event`),
  rtpflux offers them to the answerer. If it accepts them, its key presses
  reach the offerer as tones, and tones in the offerer's audio reach the
  answerer as events. The offerer never sees the events in the SDP. An
  answer that takes the events under another payload type than the one
  offered gets no conversion (and the offerer's own formats are never
  touched).
- **The answerer refuses the offerer's telephone events**: with the flag
  `always transcode`, rtpflux keeps them towards the offerer anyway; its
  events reach the answerer as tones, and the answerer's tones reach it as
  events.

Tones are played and detected in the parties' audio: G.711 (μ-law or
A-law) as it is, or G.722, G.729, Opus (and AMR with the `amr` build),
which the relay decodes to look for tones and encodes to play them. A key
lasts as long as the sender holds it: the tones while the events go on,
the events while the tones do (detected 20 ms frame by 20 ms frame, a key
needing two frames to start and two to end). While a key is converted the
sender's own audio towards the other side is held back. Detected keys are
reported by `query` as usual.

## Sending DTMF

`play DTMF` sends key presses to a party, for example to drive an IVR or a
voicemail system on behalf of the other side:

```text
command:  play DTMF
call-id:  call-1@example.com
from-tag: alice-tag        # Alice "presses"; Bob hears it
code:     1234#
duration: 200
```

- If Bob negotiated `telephone-event`, he gets RFC 4733 events: one per
  key, the marker bit on its first packet, a packet every 20 ms with the
  duration so far, and three end packets.
- Otherwise Bob's phone gets the keys as tones (the two ITU-T Q.23 frequencies) in
  the audio it receives: G.711 as it is, or G.722, G.729, Opus (and AMR
  with the `amr` build) encoded by the relay.
- While the keys play, Alice's own audio to Bob is held back, as for an
  announcement; the keys go out on the relay's own RTP stream towards Bob
  (encrypted if Bob uses SRTP).
- An announcement playing to Bob must end first (the request is refused
  otherwise).

## Recording

`start recording` records every packet of a call. When the recording
ends, rtpflux can turn it into an **audio file** in the format you choose,
stereo or mono.

### What you get

For each media section of the call, in `[recording] dir`:

```text
<call-id>-<from-tag>-<section>.pcap    the packets, as recorded
<call-id>-<from-tag>-<section>.wav     the audio (or .flac, .opus, .mp3)
<call-id>-<from-tag>-<section>.json    what was recorded
```

In the Call-ID and tag, characters other than letters, digits and
`. - _ @` become `_`, and each is cut to 128 characters. The name is the
default of `[recording] file_name`, which can put the date, time or
to-tag in it instead (see [Configuration](configuration.md#recording-call-recordings)).

The proxy can choose per call (in `start recording`, or in an `offer` or
`answer` with `record-call`), as with rtpengine:

| Option | What |
|---|---|
| `recording-path` | A subdirectory of `[recording] dir`, made if missing: `acme/agents`. Up to 4 levels of plain names (letters, digits, `. - _ @`, none starting with `.`); never outside the directory, never through a link. |
| `recording-file`, `output-destination` | A fixed name for this call's files: `call-42` (an extension such as `.wav` is dropped; a leading `dir/` is a subdirectory, as above). Another section or a later recording gets `-2`, `-3`. |
| `recording-pattern` | A file-name template for this call, as `[recording] file_name`. |

Anything else is refused with the reason. Recordings in subdirectories
are listed in the web UI by their path, and uploaded to S3 under it
(`prefix` + `acme/agents/call-42.wav`).

### Recording metadata

Each audio file carries tags: `TITLE` (the call-id and section),
`CALL_ID`, `FROM_TAG`, `TO_TAG`, `SECTION`, `DATE` (when the recording
started, UTC) and the encoder, plus your own:

```toml
[recording.metadata]     # in every recording
company = "Example Ltd"
```

```text
command:  start recording
call-id:  call-1@example.com
metadata: { agent: "Jane Doe", queue: "support", ticket: "4711" }
```

The tags go where players and tools read them: Vorbis comments in FLAC
and Ogg Opus (`AGENT=Jane Doe`), an ID3v2.4 tag in MP3 (`TXXX` frames,
with `TIT2`, `TDRC`, `TSSE`), and in WAV the `LIST`/`INFO` chunk: title
(`INAM`), date (`ICRD`), software (`ISFT`), and every tag as
`NAME=value` lines in the comment (`ICMT`), as INFO has no free names.
`ffprobe`, `metaflac`, `exiftool` and most players show them. The JSON
file has them under `metadata`. They are kept across restarts.

Keys are letters, digits, `_`, `-` and `.` (up to 64), upper-cased in
the audio tags; values are up to 1024 octets; a recording has at most
32. A request's own keys override the configured ones. Invalid metadata
is refused with the reason, and the recording does not start.

| Format | What it is | Good for |
|---|---|---|
| `pcap` (default) | The packets themselves; no audio file | Troubleshooting with Wireshark |
| `wav` | 16-bit PCM | Anything; largest files |
| `flac` | Lossless, about half the size of WAV | Archiving |
| `opus` | Ogg Opus at the bitrate you choose | Small files for speech |
| `mp3` | MP3 at the bitrate you choose | Players everywhere; needs a build with the `mp3` feature |

- **Stereo** puts the caller (the party that sent the first offer) on the
  left and the callee on the right. **Mono** mixes both.
- **Sample rate:** 8000, 16000, 24000 or 48000 Hz. G.711 calls carry
  8 kHz audio, so 8000 loses nothing; choose 16000 or more for Opus calls
  from browsers.
- **Bitrate** (Opus and MP3), in kbit/s: Opus takes 6 to 510, MP3 one of
  8, 16, 24, 32, 40, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320.

The `.json` file describes the recording:

```json
{
  "call_id": "call-1@example.com",
  "from_tag": "alice-tag",
  "to_tag": "bob-tag",
  "section": 1,
  "left_port": 30000,
  "opus_pts": [],
  "file": "call-1@example.com-alice-tag-1.wav",
  "format": "wav",
  "channels": "stereo",
  "sample_rate": 16000,
  "started_ms": 1795509703000,
  "duration_ms": 62340,
  "caller": { "packets": 3117, "lost": 0, "streams": 1 },
  "callee": { "packets": 3115, "lost": 2, "streams": 1 }
}
```

### Choosing the format

Set the default in the configuration:

```toml
[recording]
dir = "/var/spool/rtpflux"
format = "flac"        # pcap, wav, flac, opus or mp3
channels = "stereo"    # or mono
sample_rate = 16000
bitrate = 32           # kbit/s, for opus and mp3
keep_pcap = false      # keep the packets once converted
```

and override any of it per call in `start recording`:

```text
command:     start recording
call-id:     call-1@example.com
format:      opus
channels:    mono
sample-rate: 16000
bitrate:     24
keep-pcap:   yes
```

Wrong values are refused with a clear error, such as
`sample_rate 44100: one of [8000, 16000, 24000, 48000] is needed`.

### How the audio is made

The conversion runs on a background thread when the recording ends:
`stop recording`, the call deleted, or the call timing out. It never runs
on the threads that relay media.

- Each party's packets are placed by their RTP timestamps, starting from
  when their first packet arrived. Jitter does not stretch the audio,
  reordered and duplicated packets are handled, and lost packets leave
  silence.
- Each packet is recorded **as its sender sent it**: after SRTP
  decryption, before transcoding or blocking. G.711 (PCMU, PCMA) and Opus
  are decoded; telephone events, comfort noise and other codecs are left
  out of the audio.
- The audio file appears when it is complete (it is written under a
  temporary name first), usually a moment after the call ends.
- The pcap is removed after a successful conversion, unless `keep_pcap`
  is set. If a conversion fails, the pcap always stays, and the reason is
  logged. A section without audio rtpflux decodes (G.711, G.722, G.729,
  Opus, and AMR with the `amr` feature; not a video stream, for example)
  is not converted; its pcap is kept. Wideband audio (G.722, AMR-WB)
  keeps its band at 16 and 48 kHz outputs; at 8 and 24 kHz it goes
  through 8 kHz.
- If rtpflux stops while a call is being recorded, its pcap is kept.
  With a [state file or Redis](operations.md#restarts), the recording continues
  after the restart and is converted once, from the whole recording,
  when it ends (so stopping is not held up by conversions). Without one
  the call does not come back, so the recording is converted as rtpflux
  stops.
- A call encrypted end to end with ZRTP (the phones' own keys, which the
  relay never has) is not converted: its pcap, with the ZRTP handshake in
  it, is kept, and the log says why.
- Audio files left half written (`*.part`) by a crash are removed when
  rtpflux starts.

### Storing recordings in S3

By default recordings stay on the local filesystem, in `[recording] dir`.
With `storage = "s3"`, each finished recording's files (the audio file,
its `.json`, and the pcap when it is kept) are uploaded to an S3 bucket,
then removed from the local directory:

```toml
[recording]
dir = "/var/spool/rtpflux"    # still needed: files are made here first
format = "opus"
storage = "s3"

[recording.s3]
bucket = "call-recordings"
region = "eu-west-1"
prefix = "rtpflux/"           # object keys: rtpflux/<call-id>-<tag>-<n>.opus
```

```sh
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
rtpflux -c rtpflux.toml
```

- **Credentials** come from the environment: `AWS_ACCESS_KEY_ID`,
  `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` for temporary
  credentials. They are never read from the configuration file. Without
  them the relay does not start, and says why.
- **S3-compatible servers** (MinIO, Ceph, Cloudflare R2, versitygw, …):
  set `endpoint` to the server's URL and usually `path_style = true`.
- **Failures:** each file is tried three times. A file that still cannot
  be uploaded stays in the local directory, and the error is logged.
- `keep_local = true` uploads and also keeps the local copies.
- A recording interrupted because rtpflux stopped is uploaded when it
  finally ends, after the restart.
- S3 storage needs a build with the `s3` feature
  (`cargo build --release --features s3`); the Docker image has it.

#### Upload notifications (webhook)

With a `[recording.s3.webhook]` section, the relay sends an HTTP `POST`
after each finished recording is uploaded, so another system (a CRM, a
transcription pipeline) can fetch it without listing the bucket:

```toml
[recording.s3.webhook]
url = "https://hooks.example.com/recordings"
timeout_ms = 5000           # each attempt's deadline, DNS to response (100–60000)
connect_timeout_ms = 2000   # connecting (100–timeout_ms)
attempts = 5                # 1–20
backoff_ms = 1000           # before the first retry, doubled after it
backoff_max_ms = 30000      # the longest wait, Retry-After included
queue = 1000                # notifications waiting to be sent
```

The body is JSON:

```json
{
  "event": "recording.uploaded",
  "delivery": "5f0c…",
  "uploaded_ms": 1795509703120,
  "call_id": "a84b4c76e66710@pc33",
  "from_tag": "1928301774",
  "to_tag": "a6c85cf",
  "section": 1,
  "metadata": { "company": "Example Ltd" },
  "bucket": "call-recordings",
  "files": [
    { "key": "rtpflux/a84b4c76e66710@pc33-1928301774-1.opus",
      "url": "https://call-recordings.s3.eu-west-1.amazonaws.com/rtpflux/…opus",
      "content_type": "audio/ogg", "size": 412733 },
    { "key": "rtpflux/…-1.json", "url": "…", "content_type": "application/json", "size": 911 }
  ],
  "complete": true
}
```

`complete` is false when a file could not be uploaded; `not_uploaded`
then names it (it stays in the local directory). No notification is sent
when nothing was uploaded. The `url`s are not presigned: the receiver
needs its own access to the bucket.

- **Delivery** runs on a thread of its own, from a queue of `queue`
  notifications, so a slow or unreachable receiver never holds up the
  next recording. When the queue is full, a notification is dropped and
  logged.
- **Retries:** timeouts, connection errors, `5xx`, `408` and `429` are
  retried up to `attempts` times in all. The waits double from
  `backoff_ms` up to `backoff_max_ms`, each jittered (half of it plus up
  to half at random), and are at least what a `Retry-After` header asks
  for (in seconds), but never more than `backoff_max_ms`. Any other
  status (`2xx` is success; `3xx` and other `4xx`) is final: redirects
  are not followed.
- **Timeouts:** every attempt ends by `timeout_ms`, everything from
  resolving the host to the response's headers included, and
  `connect_timeout_ms` limits connecting. The response body is not read,
  and response headers over 16 KiB end the attempt.
- **Stopping:** when rtpflux stops, queued notifications get one attempt
  each, for at most twice `timeout_ms` in all. What is left is dropped,
  and how many is logged.
- **Headers:** `Content-Type: application/json`, `X-Rtpflux-Event:
  recording.uploaded`, `X-Rtpflux-Delivery` (the `delivery` id: drop
  repeats of it, since a retry after a lost response arrives twice) and
  `X-Rtpflux-Timestamp` (Unix seconds).
- **Signing:** with `RTPFLUX_WEBHOOK_SECRET` set in the environment (never
  in the configuration file), each request also carries
  `X-Rtpflux-Signature: sha256=<hex>`, the HMAC-SHA256 of
  `<X-Rtpflux-Timestamp>.<raw body>` keyed with the secret. Check it
  in constant time, and refuse old timestamps, so a captured request
  cannot be replayed:

  ```python
  import hashlib, hmac, time
  def valid(secret: bytes, headers, body: bytes) -> bool:
      ts = headers["X-Rtpflux-Timestamp"]
      want = "sha256=" + hmac.new(secret, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
      return hmac.compare_digest(want, headers["X-Rtpflux-Signature"]) and abs(time.time() - int(ts)) < 300
  ```

- Logs name the receiver by scheme, host and path only: a token in the
  URL's query or credentials stays out of them.
- **Watching it:** the web UI's Recordings page lists the last 200
  uploads and webhook deliveries, and `/metrics` counts them
  (`rtpflux_recording_uploads_total`, `…_upload_failures_total`,
  `…_webhooks_delivered_total`, `…_webhooks_failed_total`,
  `…_webhooks_dropped_total`); see [Operations](operations.md#metrics).

 open it in Wireshark and use
*Telephony → RTP → RTP Streams*.

## Announcements

`play media` plays an audio file to one participant, for example "please
hold" or "this call is recorded":

```text
command:      play media
call-id:      call-1@example.com
from-tag:     bob-tag                     # who hears it
file:         /usr/share/rtpflux/hold.wav
repeat-times: 3
```

- **File format:** MP3, FLAC or WAV. WAV at 8 kHz mono (16-bit PCM,
  A-law or μ-law) is played as it is; anything else is decoded, mixed down
  to mono and resampled to 8 kHz (filtered to the telephone band, so
  nothing above it folds back). Converting ahead, for example with
  `sox in.mp3 -r 8000 -c 1 -b 16 out.wav`, saves that work per play.
- **The file** must be a regular file (not a device or a pipe) of at most
  64 MiB, about 35 minutes of 16-bit audio.
- The relay converts the audio to the G.711 law the listener receives and
  sends it in 20 ms packets with its own SSRC. Later announcements to the
  same participant continue that stream (same SSRC, sequence numbers going
  on), as SRTP requires. It encrypts them when the listener uses SRTP.
- While the announcement plays, the other party's audio to the listener
  is held back, so the two do not mix.
- `stop media` ends it early. Without `from-tag`, every announcement in the
  call stops.
- The listener must receive PCMU or PCMA. A participant who receives only
  Opus cannot be played to yet.
- After a [restart](operations.md#restarts), an announcement resumes
  where it would have been. It is not restarted if it would already have
  finished.

## Transcoding

When the two parties have no codec in common, the relay can convert
between them. Any of these converts to any other:

| Codec | Payload type | Audio | Implementation |
|---|---|---|---|
| PCMU, PCMA (G.711) | 0, 8 | 8 kHz | Built in. Between the two laws, a table lookup per sample |
| G.722 | 9 | 16 kHz (RTP clock 8000 Hz) | Built in (the public-domain reference algorithm, 64 kbit/s) |
| G.729, with Annex B | 18 | 8 kHz, 10 ms frames | `g729-sys`, a Rust port of bcg729 (GPL-3.0) |
| Opus | dynamic (111) | 8 or 16 kHz, matching the other side; 24 or 32 kbit/s | `opus-rs` |
| AMR, AMR-WB | dynamic | 8 / 16 kHz, 20 ms frames, 12.2 / 12.65 kbit/s | `amr-nb` / `amr-wb`, ports of opencore-amr; only in a build with the `amr` feature |

Between codecs of different audio rates (G.711 and G.722, for example),
the audio is resampled between 8 and 16 kHz. Opus takes the other side's
rate, so G.722 to Opus stays wideband.

Ask for transcoding in the offer with the `codec` option (or flags):

```text
codec: { transcode: ["PCMU"] }     # or flags: ["codec-transcode-PCMU"]
```

rtpflux adds that codec to the offer it sends to the answerer, keeping the
offerer's codecs too. Then:

- If the answerer picks a codec the offerer also has, nothing is converted.
- If the answerer picks the codec only the relay offered, the relay
  converts both ways. The offerer is answered with its own codec and never
  knows.

To **force** conversion, also withhold the offerer's codec from the
answerer with `mask`:

```text
codec: { transcode: ["PCMA"], mask: ["PCMU"] }
```

**Example: a browser calling an old PBX.** The browser offers only Opus;
the PBX speaks only PCMU. The proxy sends the offer with
`transport-protocol: RTP/AVP` and `codec-transcode-PCMU`:

```text
browser offer:          m=audio 9 UDP/TLS/RTP/SAVPF 111
                        a=rtpmap:111 opus/48000/2
relay's offer to PBX:   m=audio 30002 RTP/AVP 111 0
                        a=rtpmap:111 opus/48000/2
                        a=rtpmap:0 PCMU/8000
PBX answer:             m=audio 50000 RTP/AVP 0
relay's answer to the browser: Opus (payload type 111)
```

The browser sends Opus and the PBX receives PCMU, and the other way
round.

Details:

- When the relay adds Opus or AMR, it uses payload type 111, or the
  first free dynamic number if the offer already uses 111. G.722 and
  G.729 keep their static numbers.
- Every codec is converted packet by packet, with the same packet length
  (a 20 ms packet stays 20 ms): G.729 needs a multiple of 10 ms, AMR of
  20 ms, and other lengths are dropped.
- G.729 is sent without voice activity detection (every frame is voice),
  which suits a peer with or without Annex B; its SID frames are decoded
  into comfort noise.
- AMR is transcoded only in the octet-aligned packing: the relay offers
  `a=fmtp:<pt> octet-align=1`, and an offerer's AMR counts only with
  `octet-align=1` and a `mode-set` that includes 12.2 kbit/s (AMR-WB:
  12.65 kbit/s), the modes the relay sends. AMR packets take one small
  allocation each to pack; the other codecs none. Check AMR's patent
  situation where you use it: that is why it is off by default.
- Opus is converted packet by packet. A G.711 packet of an Opus frame
  length (2.5, 5, 10, 20, 40 or 60 ms; 20 ms is the usual one) becomes
  one Opus frame; other lengths that split into equal frames, such as
  30 ms, become one Opus packet of several frames (three of 10 ms). Up to
  120 ms per packet; anything else is dropped.
- Timestamps are scaled between the RTP clocks (Opus 48 kHz, AMR-WB
  16 kHz, the others 8 kHz, G.722 included). Sequence numbers and SSRCs
  are kept.
- Telephone events (DTMF) and RTCP are passed through unconverted.

## RTCP statistics

Endpoints send RTCP reports about the media they receive. rtpflux reads
the reports it relays (after SRTCP decryption) and shows the latest one
per stream in `query`:

```text
RTCP:
  reports: 14               # reports seen
  SSRC: 3735928559          # who sent them
  sender packets: 1480      # from the last sender report, if any
  sender octets: 236800
  reported SSRC: 1234567    # the stream the report is about
  fraction lost: 3          # out of 256, since the previous report
  packets lost: 21          # in total (can be negative: duplicates)
  highest sequence: 71480
  jitter: 9                 # in RTP timestamp units
  RTT: 38                   # round-trip time, ms
```

**Round-trip time.** When a sender report from one side is answered by a
receiver report from the other, the relay works out how long the round
trip took (RFC 3550, section 6.4.1). It is the time between the relay
forwarding the sender report and receiving the reply, minus the delay the
other side reported. `RTT` is shown once such a pair has been seen.
