# 09: high availability and monitoring

**The case.** Calls must survive a restart or an upgrade of the relay,
and the relay is watched with Prometheus and its web UI.

## Setting it up

```toml
[sessions]
state_file = "/var/lib/rtpflux/state.json"
# redis = "redis://:password@10.0.0.9:6379/0"   # another host can take the calls over
timeout = 60

[metrics]
listen = ["127.0.0.1:9101"]

[webui]
listen = "127.0.0.1:8090"
user = "admin"
password_hash = "sha256:..."     # rtpflux --webui-hash
```

## What `run.py` checks

- **Restarts:** after a SIGTERM restart, a plain and an SDES-SRTP call
  come back on the same ports with the same keys, and media goes on.
- **Crashes:** after `kill -9`, the last call is back and the deleted
  one is not. A corrupt state file lets the relay start, and the log
  says why.
- **Timeouts:** an idle call ends, a one-way call stays up, an
  unanswered offer ends, and timeouts are counted.
- **Monitoring:** `/metrics` works. The web UI needs the login,
  lists the calls, never shows SRTP keys, refuses POST, and handles odd
  query parameters.

## Caveats

- The state file is written at most once a second, so a `kill -9` a few
  hundred milliseconds after a call is answered loses that call.

## Not covered

Redis is skipped when `redis-server` is not installed.
