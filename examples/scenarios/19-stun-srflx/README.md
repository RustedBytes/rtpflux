# 19: a relay behind NAT (STUN, server-reflexive candidates)

**The case.** The relay runs in a cloud VM or behind a NAT and doesn't
know its public address. It asks a STUN server and offers ICE endpoints
a server-reflexive candidate.

## Setting it up

```toml
[ice]
stun_server = "stun.example.net:3478"   # asked for interfaces without `advertise`
```

## What `run.py` checks

A small Python STUN server answers with a made-up public address.

- **Which interfaces ask:** the interface without `advertise` asks the
  STUN server, and the one with `advertise` does not.
- **The candidates:**
  - ICE endpoints get the host candidate and a `typ srflx` one with the
    public address.
  - The srflx candidate is on the media port, with `raddr`/`rport` set
    to the host candidate, and the host candidate has the higher
    priority.
  - `c=` keeps the interface's address, and the answer carries the
    candidate too.
- **Advertise:** an interface with `advertise` offers that address and
  no srflx candidate.
- **Non-ICE endpoints** get no candidates.
- **A silent STUN server:** only the host candidate is offered, the log
  says why, and the relay works on.
- **Configuration:** `stun_server = ":3478"` is refused by `--check`.
