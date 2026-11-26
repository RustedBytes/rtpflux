# 28: Supervisor monitoring, whisper and barge-in

**The case.** A call-centre supervisor listens in on an agent's call,
coaches the agent without the customer hearing, and joins the call when
needed. The supervisor's phone is in a call of its own with the call
centre's focus. The relay copies media into it:

- **Monitor:** a directional `connect` of the customer and the agent to
  the supervisor. The supervisor gets each as a stream of its own, and
  nobody hears the supervisor.
- **Whisper:** `inject start` of the supervisor into the agent: the agent
  hears the supervisor, the customer does not.
- **Barge-in:** `inject start` into the customer as well.

There is no mixer: each copy is a stream of its own (the speaker's SSRC),
converted to the listener's codec and sent from the relay port the
listener already uses. An endpoint that plays one stream at a time plays
one of them.

## Setting it up

No configuration is needed (a `state_file` keeps the copies across
restarts). The `ng` sequence:

```text
connect        call-id=cust-1 from-tags=[customer, agent] to-call-id=sup-1 to-tag=supervisor
               flags=[directional]                                          → monitor
inject start   call-id=cust-1 to-tag=agent source-call-id=sup-1 source-tag=supervisor      → whisper
inject start   call-id=cust-1 to-tag=customer source-call-id=sup-1 source-tag=supervisor   → barge-in
inject stop    (the same keys)                                              → back
block media    call-id=cust-1 from-tag=customer all=except-offer-answer     → pause the supervisor's copy
unsubscribe    call-id=sup-1 to-tag=supervisor                              → stop monitoring
```

## What `run.py` checks

- **Monitor:** the supervisor (PCMA) hears the customer and the agent
  (PCMU) as two streams, converted to PCMA and at their level, and still
  hears the focus. Neither the customer nor the agent hears the
  supervisor, and their call is unchanged.
- **Whisper:** the agent hears the supervisor (converted to PCMU), the
  customer does not, and monitoring goes on.
- **Barge-in:** both hear the supervisor. `inject stop` steps back to
  whispering, then to listening only. Stopping an injection that does
  not exist is refused.
- **Pausing the supervisor:** blocking the customer's copies (`all:
  except-offer-answer`) stops what the supervisor hears of the customer
  only, while the agent still hears the customer, as when a card number
  is read out. Silencing the copies sends the supervisor silence instead.
- **Restart:** monitoring comes back after a restart.
- **Ending:** `unsubscribe` naming the supervisor ends the copies. When
  the monitored call ends, the supervisor's call goes on. When the
  supervisor hangs up, the monitored call is unaffected. `flags: all`
  monitors every party of a call.
- **Refusals:** `inject start` without a source, into the source itself,
  or from an unknown call, and several sources without `directional`.
