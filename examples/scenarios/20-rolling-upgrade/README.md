# 20: a rolling restart under traffic

**The case.** You upgrade the relay binary (`systemctl restart rtpflux`)
during the day, with calls up.

## Setting it up

```toml
[sessions]
state_file = "/var/lib/rtpflux/state.json"
```

## What `run.py` checks

40 calls stream 2,000 packets/s in all; 5 of them are SDES-SRTP. The
relay is restarted with SIGTERM three seconds in.

- **Every call is back**, and media resumes on all 40, SRTP included.
- **The silence is measured:** the longest gap per call stays within the
  restart.
- **Loss is bounded:** what was lost fits in the restart window, and
  nothing is delivered twice.

`run.py` prints how long the restart took, the longest silence per
call, and the share of packets lost.
