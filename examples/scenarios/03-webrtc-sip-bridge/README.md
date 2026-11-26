# 03: a browser calling a SIP phone

**The case.** A web softphone (WebRTC: ICE, DTLS-SRTP, `rtcp-mux`,
BUNDLE) calls a desk phone or a trunk that only speaks plain RTP. The
relay terminates WebRTC towards the browser and offers the phone
ordinary RTP.

## Setting it up

```toml
[ice]
mode = "full"          # or "lite"; the ICE-lite option overrides it per call
# stun_server = "stun.example.net:3478"   # when the relay is behind NAT without `advertise`
```

```text
rtpengine_offer("trust-address replace-origin RTP/AVP");   # towards the phone
rtpengine_answer("trust-address replace-origin");
```

## What `run.py` checks

- **Towards the phone:** RTP/AVP, one port per stream, no DTLS, BUNDLE or
  SDES keys.
- **Towards the browser:** UDP/TLS/RTP/SAVPF, one bundled port, a
  sha-256 fingerprint, `setup:passive`, ICE credentials and a host
  candidate, `rtcp-mux` and `ice-options:ice2`.
- **ICE:** the relay's own checks (USERNAME and integrity), its answers
  to the browser's checks (XOR-MAPPED-ADDRESS), and refusal of a wrong
  password or ufrag. Media is held back until ICE and DTLS are done.
- **Variants:** ICE-lite, trickle-ICE fragments, and a DTLS offer without
  a fingerprint.
- **Re-offers:** a BUNDLE re-offer from the phone side, and a SIP phone
  with ICE (no DTLS) calling one without ICE.
- **`--browser`:** headless Firefox through the relay
  (`scripts/webrtc-firefox.py`: audio, `--video`, `--lite`). ICE and DTLS
  connect, and media flows both ways.

## Caveats

- A one-section "BUNDLE" re-offer from the phone's side is an ordinary
  re-offer (a group of fewer than two sections is not BUNDLE), so it may
  change the profile.
