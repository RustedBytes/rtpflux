# 05: transcoding

**The case.** The two parties share no codec. Typical pairs are a
browser with Opus and a PBX with PCMU, a trunk with G.729, or HD voice
(G.722) and G.711.

## Setting it up

```text
rtpengine_offer("codec-transcode-PCMA codec-mask-PCMU");   # force PCMA to the callee
rtpengine_offer("codec-transcode-telephone-event");        # DTMF events <-> in-band tones
```

## What `run.py` checks

- **u-law to A-law:** the tone keeps its level and frequency, checked on
  the decoded samples. 10 ms and 30 ms packets are converted too.
- **Pass-through:** when the callee picks the caller's codec, packets
  pass bit-exact.
- **Other codecs:** PCMU to and from G.722, G.729 and Opus, plus garbage
  frames into each decoder.
- **DTMF:** an RFC 4733 key from the callee reaches a caller without
  telephone-event as the two tones of '1', and is detected once.
- **Odd packets:** empty, 1 byte, 1500 bytes, unknown PT.
