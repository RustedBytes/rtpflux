# 07: call-centre features

**The case.** Calls are recorded for compliance, announcements play
while callers wait, IVRs read key presses, and agents must not hear card
numbers.

## Setting it up

```toml
[recording]
dir = "/var/spool/rtpflux"
format = "wav"          # pcap, wav, flac, opus, mp3
channels = "stereo"     # caller left, callee right
```

The proxy sends `start recording`, `play media`, `play DTMF`,
`block DTMF`, `silence media` and so on (Kamailio:
`rtpengine_start_recording()`, `rtpengine_play_media()`, …).

## What `run.py` checks

- **Recording:** a stereo WAV with the caller's 440 Hz tone on the left
  and the callee's 880 Hz on the right, and its JSON. A second recording
  goes to a `-2` file, bad options are refused, and `record-call` in the
  offer works. Hostile Call-IDs and tags (`../../escape`, NUL, 400
  characters) never write outside the directory.
- **Announcements:** a 1 kHz file replaces the other party's audio and
  hands back when it ends; a blob can play twice; `stop media`. Bad
  files (missing, directory, `/dev/zero`, not audio) are refused, and so
  is an Opus-only listener.
- **DTMF:** each key is detected once despite repeated end packets.
  `block DTMF` stops the keys but not the audio, and blocked keys are
  still detected. `play DTMF 12#` arrives as events 1, 2, #, or as the
  in-band tones of '9' without telephone-event.
- **Muting:** `block media` and `silence media`, where silence keeps the
  sequence numbers.

## Caveats

- `play DTMF` clamps out-of-range numbers into range, as rtpengine does
  (a duration of 5 becomes 40 ms, 6000 becomes 5000 ms); a value that is
  not a number is refused.
