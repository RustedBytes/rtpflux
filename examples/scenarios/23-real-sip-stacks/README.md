# 23: real SIP stacks

**The case.** Everything else here uses the Python harness as the proxy
and the phones. This scenario runs the repository's integration bench
(`integration/run.sh`) instead: Kamailio's and OpenSIPS's `rtpengine`
modules, SIPp, FreeSWITCH, linphone, and ferrosip when its repository can be fetched,
all in Docker Compose.

## Running

```sh
python3 examples/scenarios/23-real-sip-stacks/run.py --docker
examples/scenarios/run-all.sh --docker
```

Without `--docker` the scenario is skipped. The first run builds the
images, which takes minutes. Logs go to `integration/out/`.

## What `run.py` checks

`integration/run.sh` places six calls and checks each:

- **The calls:**
  - SIPp through Kamailio to a SIPp callee.
  - Through Kamailio to FreeSWITCH.
  - A G.722 call to FreeSWITCH.
  - Through OpenSIPS to a SIPp callee.
  - Through ferrosip.
  - A ZRTP call between two linphones.
- **Each call:** it completes, the callee sees rtpflux's address in the
  SDP, audio goes through rtpflux both ways, every `ng` command is
  answered, and the call is deleted at BYE.
- **The ZRTP call:** both linphones reach the secure state with the same
  short authentication string, and rtpflux relayed their ZRTP packets.
