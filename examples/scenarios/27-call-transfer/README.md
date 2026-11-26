# 27: Call transfer with `connect`

**The case.** An SBC or B2BUA completes a transfer (a SIP `REFER`, or its
own logic) by joining the transferred party with the transfer target.
`connect` does it in the relay: what each sends goes to the other, from
the relay port it already knows, so neither phone needs a re-INVITE. The
transferor's legs are detached, and their media is dropped.

## Setting it up

No configuration is needed (a `state_file` keeps the joins across
restarts). The `ng` sequence:

```text
# attended: Alice–Bob (xfer-1), Bob consults Carol (consult-1), Bob completes
connect  call-id=xfer-1 from-tag=alice to-call-id=consult-1 to-tag=carol

# blind: the SBC calls the target itself (target-2), then joins
connect  call-id=xfer-2 from-tag=erin to-call-id=target-2 to-tag=dave
```

## What `run.py` checks

- **Attended transfer:** after `connect`, Alice and Carol reach each
  other from the relay ports they already know. Same codec: packets pass
  unchanged (payload, SSRC). Bob's two legs get nothing, and what he
  still sends reaches nobody.
- **Blind transfer with conversion:** PCMU to PCMA needs no warning. Each
  side gets the other's 1 kHz tone in its own codec, at the level it was
  sent.
- **Into SRTP:** a plain-RTP party joined with an SDES-SRTP party. Her
  audio arrives encrypted with the relay's key, and the SRTP party's
  arrives decrypted.
- **Transferred again:** a party already transferred is joined with a
  third party. She talks to the new target only, and the previous target
  is detached both ways.
- **Ten transfers at once** with two media workers: some pairs on one
  worker, some across both. All connect, both ways.
- **Restart:** every joined pair still talks after a restart.
- **Refusals:** an unknown call or party on either side, no `to-tag`,
  several sources without `directional`, and a party joined to itself.
- **Endings:** when the target's call ends, nothing reaches the target,
  and the transferred party is left alone.
