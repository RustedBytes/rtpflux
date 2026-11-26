# 18: ICE restart and consent freshness

**The case.** A SIP phone or browser that does ICE stays on a call for a
long time. Its network changes and it restarts ICE (new ufrag and
password), or it vanishes without a BYE.

## Setting it up

```toml
[ice]
mode = "full"      # consent freshness needs the full agent
pacing_ms = 50
```

## What `run.py` checks

Python plays the phone's ICE agent: it answers the relay's checks,
nominates, and can go silent.

- **Before any check succeeds:** no media goes to the phone, and the
  relay checks the phone's candidate with the right credentials.
- **Once a check succeeds:** media flows even before a nomination, and
  goes on after the phone nominates.
- **Consent:** checks come every 4–6 s, and media goes on while they are
  answered.
- **ICE restart:** the relay answers with new credentials on the same
  port. Media keeps going to the old pair until the new one works, then
  flows on the new pair.
- **Consent loss** (skipped with `--quick`, since it takes 30 s): media
  still flows after 15 s of silence. After 30 s it stops (RFC 7675), and
  `rtpflux_ice_consent_lost_total` counts it. The call stays, and an ICE
  restart brings media back.
