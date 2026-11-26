# 16: fax over IP (T.38)

**The case.** A fax machine behind an ATA or a gateway. The call starts as
audio. When the fax tones are heard, the endpoint re-INVITEs to
`m=image <port> udptl t38`, and after the fax it may go back to audio.

## Setting it up

Nothing. Sections the relay does not read as RTP are relayed as they
are. rtpflux is not a fax gateway: both ends must speak T.38.

## What `run.py` checks

- **The re-INVITE to T.38:**
  - The callee is offered `udptl t38`, keeping every `a=T38…` attribute
    and getting no RTP attributes.
  - UDPTL datagrams pass byte for byte both ways, including ones that
    look like RTP or DTLS.
  - `query` counts them.
  - Latching follows a fax machine behind NAT.
- **Back to audio:** RTP flows again after the fax.
- **Mixed and odd offers:**
  - An offer with both audio and T.38 relays both sections.
  - `codec transcode` leaves a T.38 section alone.
  - A T.38 offer answered with G.711 audio is refused: no fax gateway,
    and RFC 3264 keeps the media type.
