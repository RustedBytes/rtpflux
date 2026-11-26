# 01: in place of rtpengine

**The case.** A Kamailio or OpenSIPS proxy already uses its `rtpengine`
module. rtpflux speaks the same `ng` protocol, so you can point the
module at it and leave the routing script as it is.

## Setting it up

```toml
# rtpflux.toml
[control]
listen = ["127.0.0.1:2223"]          # UDP, what rtpengine_sock "udp:..." uses
# listen_tcp = ["127.0.0.1:2223"]    # optional: ng over TCP
# listen_http = ["127.0.0.1:2225"]   # optional: POST /ng, /ng-plain, WebSocket

[[interface]]
name = "default"
address = "203.0.113.10"
```

```text
# kamailio.cfg
loadmodule "rtpengine.so"
modparam("rtpengine", "rtpengine_sock", "udp:127.0.0.1:2223")
...
rtpengine_manage("trust-address replace-origin");
```

## What `run.py` checks

- `ping`, then `offer`/`answer`/`delete` with media both ways, `query`,
  `list` and `statistics`
- A retransmitted request (same cookie) gets the same reply and runs
  once
- Error replies for unknown commands, missing keys and unknown calls
- Malformed datagrams, a 60 KB offer, and not-quite-SDP offers
- ng over TCP (pipelined requests, garbage closes the connection) and
  over HTTP with JSON
- `delete-delay`
