# 14: failover through Redis

**The case.** Two relay hosts share a floating IP. Relay A keeps its
dialogs in Redis. When A dies, B takes the IP, reads A's key and carries
on with A's calls on the same ports.

## Setting it up

```toml
[sessions]
redis = "redis://:password@10.0.0.5:6379/2"
redis_key = "rtpflux:state:relay-a"     # B points at A's key to take over
# state_file = "/var/lib/rtpflux/state.json"   # optional too: the newer wins
```

## What `run.py` checks

`redis-server` is used when it is installed; otherwise
`lib/fakeredis.py` stands in, a RESP2 server with AUTH, SELECT, SET and
GET.

- **Writing:** relay A's dialogs reach Redis within seconds, under its
  key, in database 2.
- **Takeover:** A is killed with `kill -9`, and B restores A's calls.
  The SDES-SRTP call goes on with the same ports and keys, and the plain
  call goes on to the address A had learned.
- **Ongoing writes:** B's delete reaches Redis.
- **Redis down:** 20 `ng` offers take milliseconds, media goes on, and
  the outage is logged once, not per write. When Redis returns, the
  newest snapshot is written.
- **Keys and passwords:** a relay with its own key restores nothing of
  A's. With a wrong password the relay runs, says why, and restores
  nothing. The password never appears in the log.
- **File and Redis:** with an older state file, the newer Redis snapshot
  wins.
