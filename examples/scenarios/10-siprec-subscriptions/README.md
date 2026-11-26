# 10: SIPREC recording via subscriptions

**The case.** A SIPREC recording server (SRS) records calls. OpenSIPS's
`siprec` module asks the relay for copies of each party's media with
`subscribe request` (`flags: [all, siprec]`), gives the SRS the offer with
the labels in its metadata, and passes the SRS's answer back with
`subscribe answer`.

## Setting it up

No configuration is needed. The `ng` sequence is:

```text
subscribe request  call-id=… flags=[all, siprec] to-tag=srs-1   → offer for the SRS (+ tag-medias, media-labels)
subscribe answer   call-id=… to-tag=srs-1 sdp=<SRS answer>      → copies start
unsubscribe        call-id=… to-tag=srs-1                       → copies stop
```

## What `run.py` checks

- **The offer:** one `sendonly` section per party, labelled 1 and 2. The
  reply has `from-tags`, `tag-medias` and `media-labels`, and `list`
  shows the subscription.
- **Copies:** nothing before the answer. After it, each section gets
  exact copies of one party, with the same payload, SSRC and sequence
  numbers. What the SRS sends is never relayed into the call, and
  `query` links the tags.
- **Restarts:** the subscription is back after a restart (state file)
  and keeps copying.
- **Ending:** `unsubscribe` stops the copies and the call goes on. A
  section the SRS rejects (port 0) gets nothing.
- **Variants:** one party only (`from-tag`), `flags: inactive`, and an
  SDES-SRTP SRS, whose copies decrypt with the relay's key.
- **Refusals:** a plain answer to an SRTP offer, an answer with none of
  the offered formats, and every error case (unknown call, party or
  subscription, or no source).
- **Delete:** `delete` ends the call's subscriptions.
