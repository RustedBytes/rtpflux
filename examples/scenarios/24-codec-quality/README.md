# 24: codec quality

**The case.** Transcoding between a G.711 network and Opus browsers,
G.722 HD phones or G.729 trunks: how much does the audio lose?

## What `run.py` checks

A PCMU caller sends pure tones at 300 Hz, 1 kHz and 3 kHz. The relay
encodes them into codec X for the callee, which echoes them back, and
the relay decodes them into PCMU for the caller. So each codec is
encoded and decoded once. Per codec and frequency, the scenario measures
the level change and the SINAD: the tone's power against everything
else, with Goertzel filters, so no alignment is needed.

| Codec | Level | SINAD at 300 Hz / 1 kHz / 3 kHz |
|---|---|---|
| PCMA (G.711 → G.711) | ±0.0 dB | 39.9 / 54.6 / 54.6 dB, the G.711 limit itself |
| G.722 | +0.0 to +0.1 dB | 36.9 / 40.9 / 41.8 dB |
| G.729 | −0.7 dB | 24.7 / 29.7 / 27.5 dB |
| Opus | −0.6 to 0.0 dB | 31.4 / 34.5 / 23.6 dB |

The limits in `run.py` sit a few dB under these measurements (reference
run, 2026-11-25), so a regression in a codec or in resampling shows.
