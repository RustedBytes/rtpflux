# 11: one-to-many broadcast (publish / subscribe)

**The case.** A WebRTC client publishes its microphone (`publish`), and
any number of listeners subscribe to it, each in its own profile: a
webinar, a monitoring console, a radio-style stream.

## Setting it up

```text
publish            call-id=room from-tag=pub sdp=<sendonly offer>   → the relay's recvonly answer
subscribe request  call-id=room from-tag=pub to-tag=<listener>      → offer for the listener
subscribe answer   call-id=room to-tag=<listener> sdp=<answer>
delete             call-id=room                                     → ends the publication and all subscriptions
```

## What `run.py` checks

- **The publisher:** answered `recvonly` in its own profile, here
  SDES-SRTP, and nothing is sent back to it.
- **Listeners:** plain listeners get decrypted audio, and SRTP listeners
  get audio re-encrypted with the relay's own key.
- **Joining and leaving:** a listener who leaves gets nothing and the
  others are unaffected. A late joiner gets the stream from its answer
  on, and 20 more listeners each get every packet.
- **Bad and changed keys:** a tampered packet from the publisher reaches
  no one. The publisher re-keying (a new `publish` with a new key) keeps
  every listener receiving.
- **Ending:** `delete` ends the publication and every subscription.
- **`--browser`:** a DTLS listener in headless Firefox
  (`scripts/webrtc-firefox.py --subscribe`).
