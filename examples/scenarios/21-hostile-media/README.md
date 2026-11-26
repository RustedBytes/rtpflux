# 21: hostile media

**The case.** Media ports are open to the internet: scanners, spoofers
and floods hit them.

## Setting it up

Use `strict-source` (or `[sessions] strict_source = true`) where
injection matters. Everything else here needs no configuration.

## What `run.py` checks

A second call on the same worker is measured throughout.

- **A flood:** 50,000 packets from a stranger at a `strict-source` call
  are not relayed and are all counted as dropped. The relay's CPU per
  packet is reported, and `ng` keeps answering.
- **Oversized datagrams** (2049, 9000 and 65000 bytes) are dropped even
  from the real caller, and normal packets pass right after.
- **Garbage:** every first octet in six lengths. The relay stays up and
  the call goes on.
- **RTCP with lying length fields:** `query` still works.
- **STUN:**
  - STUN at a call without ICE is not answered.
  - Unauthenticated checks at an ICE call never get a success response.
  - The relay never sends back more bytes than it received: no
    amplification.
- **Unused ports:** packets to ports of the range no call uses change
  nothing.
- **The other call** loses nothing.

`run.py` prints the flood's rate and the relay CPU each dropped packet
cost.
