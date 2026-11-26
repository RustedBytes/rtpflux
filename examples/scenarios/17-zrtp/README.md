# 17: ZRTP softphones

**The case.** Linphone, Jitsi, Zoiper or Acrobits users agree SRTP keys
end to end with ZRTP (RFC 6189), inside the media stream, so the relay
never sees them.

## Setting it up

Nothing. Relay the call plainly, with no SDES termination and no
transcoding, if you want ZRTP to work.

## What `run.py` checks

- **A plainly relayed call:**
  - `a=zrtp-hash` passes both ways.
  - ZRTP Hello packets pass byte for byte both ways, and so does the
    phones' end-to-end SRTP.
  - `rtpflux_zrtp_forwarded_total` and the `zrtppackets` statistic count
    the ZRTP packets.
- **When the relay changes the media** (SDES terminated on one side, or
  transcoding): the hash is removed and ZRTP packets are dropped, so the
  phones see that ZRTP is unavailable.
- **One ZRTP phone:** its hash and Hello still reach the other phone,
  which ignores them.
- **First octets (RFC 7983):** 16–19 are relayed as ZRTP on a plain call,
  and 20 (DTLS) on a call without DTLS is not.
