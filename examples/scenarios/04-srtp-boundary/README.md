# 04: encryption at the boundary

**The case.** Customers on the internet use SDES-SRTP. The core network
or a carrier uses plain RTP, or SRTP with other keys. The relay decrypts
on one side and encrypts on the other.

## Setting it up

```text
rtpengine_offer("RTP/AVP");    # SRTP caller -> plain callee
rtpengine_offer("RTP/SAVP");   # plain caller -> SDES-SRTP callee
```

Supported suites: AES_CM_128 and AES_256_CM with HMAC_SHA1_80 or _32, and
AEAD_AES_128/256_GCM.

## What `run.py` checks

The SRTP here is a separate Python implementation of RFC 3711, so a
packet that decrypts shows the two implementations agree.

- **Suites:** all four AES-CM suites in both directions, with the
  answer's tag and suite matching the offer.
- **Attacks:** a tampered packet and a replay are dropped and counted
  (`srtprejected`), and so is plain RTP sent to the SRTP side.
- **Edge cases:** a sequence-number wrap (rollover counter) on both
  sides, and SRTCP decrypted to RTCP.
- **Key handling:** SRTP on both sides with separate keys, and a
  re-INVITE keeps the relay's keys. No `a=crypto` key material appears
  in the log.
- **`a=crypto` lines:** an unsupported suite first, an MKI, invalid
  base64, a short key, no key, and two keys in one line.
