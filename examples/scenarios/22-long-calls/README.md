# 22: long calls

**The case.** Calls that last hours: conference bridges, monitoring
lines, call-centre agents logged in all day. What only happens after
hours is compressed here.

## Setting it up

Nothing.

## What `run.py` checks

- **Plain calls:** packets across the sequence-number wrap (65535 → 0)
  and the timestamp wrap (2^32) arrive in order, untouched.
- **SRTP:** 132,000 packets cross two rollovers of the sequence number
  and all decrypt, with none rejected for a wrong rollover counter.
  `--quick`: 3,000 packets, one rollover. The relay's own SRTP towards
  the caller rolls over too.
- **Transcoding:** PCMU to PCMA, and PCMU to Opus. Output timestamps step
  evenly (160, and 960) and sequence numbers by 1 across both wraps.
- **DTMF:** a key press whose timestamp wraps mid-event is detected once.
- **Recording:** a 10-minute recording (`--quick`: 1 minute) whose
  timestamps and sequence numbers wrap converts to exactly 600 s of
  audio, and its JSON counts every packet with none lost.
