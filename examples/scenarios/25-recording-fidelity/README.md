# 25: recording fidelity

**The case.** Recordings made on real networks, where packets arrive
reordered, duplicated, late or never. Parties also pause in silences,
start late or restart their streams.

## What `run.py` checks

Each 20 ms packet carries a different loudness, so the WAV can be
checked window by window. The check first finds where each party's
audio begins, since that need not fall on a 160-sample boundary.

- **A lossy network:** the caller's packets are reordered, duplicated,
  jittered and 10 are lost. Every window holds the right packet, the
  lost ones are silent, and the JSON counts 10 lost and each packet
  once.
- **Silence suppression (DTX):** a 1 s pause is silent in place, and the
  rest follows.
- **A late starter** is placed by its first packet's arrival: about
  600 ms of silence, then its audio.
- **A new SSRC mid-call:** the JSON sees 2 streams, and both are in the
  audio.
- **An SRTP caller** is recorded after decryption.
- **A ZRTP call** keeps its pcap and is not converted.
