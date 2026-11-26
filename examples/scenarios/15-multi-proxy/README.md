# 15: several proxies on one relay

**The case.** A pool of Kamailio or OpenSIPS instances, often identical
containers, share one relay. Their cookies collide, their requests for
the same call interleave, and a forked INVITE can produce answers from
two branches.

## Setting it up

Point every proxy's `rtpengine_sock` at the relay. Nothing else is
needed; `sessions.max` is one limit for all of them.

## What `run.py` checks

- **Cookies:** the same cookie from two proxies runs both requests, and
  each gets its own reply. Each proxy's retransmission (the identical
  datagram) gets its own cached reply, and both are counted.
- **Two dialogs under one Call-ID:** `delete` with `from-tag` ends one of
  them, and `delete` without it ends both.
- **Forking:** answers from two branches are both accepted. The branch
  that answered last gets the media and stays in the dialog.
- **Interleaving:** 100 re-offers of one call from two proxies at once
  are all accepted, and leave one dialog.
- **Load:** 8 proxies set up and tear down 480 calls at once with no
  error and nothing left behind (about 12,000 requests/s here).
- **Limit:** `sessions.max = 50` holds across all proxies.
