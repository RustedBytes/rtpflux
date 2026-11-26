# 13: BUNDLE edge cases

**The case.** A browser bundles audio and video on one port (RFC 8843),
and the phone it calls has a port per stream. Calls change mid-way:
video is added or dropped, the phone re-INVITEs, and the browser uses
`max-bundle`.

## Setting it up

Nothing beyond the WebRTC bridge (scenario 03). On a phone's re-INVITE
towards a bundled browser, the proxy must repeat the browser's profile
(`transport-protocol`).

## What `run.py` checks

Plain `RTP/AVPF` and SDES sections are used. DTLS needs a browser:
`webrtc-firefox.py --video` covers it.

- **Basic bundling:**
  - The phone is offered a port per stream and no group.
  - The browser is answered with one shared port and its group.
  - Bundled media is sorted by payload type to the phone's audio and
    video ports; the phone's two streams leave from the one shared port.
  - Bundled RTCP is sorted by the sender's SSRC.
- **Unknown payload types:** a type no bundled section has is dropped.
- **Re-INVITEs:** the phone's re-INVITE re-offers the browser its group
  on the same shared port, and media goes on. A bundled re-offer from
  the phone is refused, and the call goes on.
- **Changing streams:** video is dropped (port 0) and brought back, and
  a third stream is added.
- **Other forms:** `bundle-only` (max-bundle); a group of one, which is
  no group; SDES, with a key per bundled section in both directions.

## Caveats

- A phone's re-INVITE to a bundled browser must repeat the browser's
  profile (`transport-protocol`). Without it the relay would offer the
  browser the phone's RTP/AVP, which a bundled side may not get, so it
  refuses.
- Dropping a stream from a bundle replaces the whole session, with new
  ports on both sides. That is valid RFC 3264, but a browser must redo
  ICE and DTLS.
