# 02: callers behind NAT

**The case.** Phones on home routers or mobile networks write private
addresses into their SDP. The relay learns where their media really comes
from ("latching") and sends the other side's media back there.

## Setting it up

Nothing in the configuration. The proxy chooses per call:

```text
rtpengine_manage("replace-origin");                    # received-from instead of the SDP address
rtpengine_manage("trust-address strict-source");       # SDP address; drop media from strangers
rtpengine_manage("endpoint-learning=immediate");       # latch onto the first packet
```

| `endpoint-learning` | Behaviour |
|---|---|
| `heuristic` (default) | For 3 s, prefer the source that best matches the SDP, then fixed |
| `immediate` | The first packet's source |
| `off` | Always the SDP address |

## What `run.py` checks

- `received-from` replaces a private SDP address when `trust-address`
  is absent
- Latching with heuristic, immediate and off, and heuristic's preference
  for the SDP's own address over an earlier stranger
- `strict-source` drops a third party; RTCP latches on its own port; both
  sides behind NAT at once

## Caveats

- After the 3 s learning window a NAT rebinding (a new source port) is not
  followed, so the call turns one-way, unless the proxy sends the
  `media-handover` flag. The external reference model's `latch` vectors
  specify this default.
- Without `strict-source`, a third party's packets to a latched port are
  relayed. Turn it on per call, or for every call with
  `[sessions] strict_source = true`.
