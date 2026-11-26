//! Commands to a running call (play, record, block, BUNDLE) and
//! statistics.

#[allow(clippy::wildcard_imports)]
use super::*;

impl Relay {
    /// Play DTMF (`tones`) to leg `leg` of call `id`; `false`
    /// when the call is unknown.
    ///
    /// # Errors
    ///
    /// [`RelayError::Busy`] when the worker's queue is full,
    /// [`RelayError::WorkerGone`] when the worker has stopped.
    pub fn play_tones(
        &mut self,
        id: CallId,
        leg: CallLeg,
        tones: Tones,
    ) -> Result<bool, RelayError> {
        self.reap();
        let Some(c) = self.calls.get(&id).filter(|c| !c.ending) else {
            return Ok(false);
        };
        let s = &self.shards[c.shard];
        s.commands
            .try_send(Command::PlayTones {
                call: id,
                leg,
                tones: Box::new(tones),
            })
            .map_err(RelayError::from)?;
        s.wake.write(1)?;
        Ok(true)
    }

    /// Start, restart or update the relay's full ICE agent towards side B
    /// (`leg`) or A of call `id`; `false` when the call is unknown.
    ///
    /// # Errors
    ///
    /// [`RelayError::Busy`] when the worker's queue is full,
    /// [`RelayError::WorkerGone`] when the worker has stopped.
    pub fn ice_start(
        &mut self,
        id: CallId,
        leg: CallLeg,
        start: IceStart,
    ) -> Result<bool, RelayError> {
        self.reap();
        let Some(c) = self.calls.get(&id).filter(|c| !c.ending) else {
            return Ok(false);
        };
        let s = &self.shards[c.shard];
        s.commands
            .try_send(Command::IceStart {
                call: id,
                leg,
                start: Box::new(start),
            })
            .map_err(RelayError::from)?;
        s.wake.write(1)?;
        Ok(true)
    }

    /// Candidates trickled by leg `leg` of call `id`, and
    /// whether they are its last; `false` when the call is unknown.
    ///
    /// # Errors
    ///
    /// [`RelayError::Busy`] when the worker's queue is full,
    /// [`RelayError::WorkerGone`] when the worker has stopped.
    pub fn ice_candidates(
        &mut self,
        id: CallId,
        leg: CallLeg,
        candidates: Vec<IceCandidate>,
        end_of_candidates: bool,
    ) -> Result<bool, RelayError> {
        self.reap();
        let Some(c) = self.calls.get(&id).filter(|c| !c.ending) else {
            return Ok(false);
        };
        let s = &self.shards[c.shard];
        s.commands
            .try_send(Command::IceCandidates {
                call: id,
                leg,
                candidates,
                end_of_candidates,
            })
            .map_err(RelayError::from)?;
        s.wake.write(1)?;
        Ok(true)
    }

    /// Play `media` to the relay call's leg `leg`, or stop
    /// (`None`). Returns `false` for an unknown call.
    ///
    /// # Errors
    ///
    /// [`RelayError::Busy`] when the worker's queue is full,
    /// [`RelayError::WorkerGone`] when the worker has stopped.
    pub fn play(
        &mut self,
        id: CallId,
        leg: CallLeg,
        media: Option<Playing>,
    ) -> Result<bool, RelayError> {
        self.reap();
        let Some(c) = self.calls.get(&id).filter(|c| !c.ending) else {
            return Ok(false);
        };
        let s = &self.shards[c.shard];
        s.commands
            .try_send(Command::Play {
                call: id,
                leg,
                media: media.map(Box::new),
            })
            .map_err(RelayError::from)?;
        s.wake.write(1)?;
        Ok(true)
    }

    /// Record the call as `spec` says (into its pcap; an existing recording
    /// goes on; converted when it ends), or stop (`None`). Returns `false`
    /// for an unknown call.
    ///
    /// # Errors
    ///
    /// [`RelayError::Busy`] when the worker's queue is full,
    /// [`RelayError::WorkerGone`] when the worker has stopped.
    pub fn record(
        &mut self,
        id: CallId,
        spec: Option<crate::recording::Spec>,
    ) -> Result<bool, RelayError> {
        self.reap();
        let Some(c) = self.calls.get(&id).filter(|c| !c.ending) else {
            return Ok(false);
        };
        let s = &self.shards[c.shard];
        s.commands
            .try_send(Command::Record {
                call: id,
                spec: spec.map(Box::new),
            })
            .map_err(RelayError::from)?;
        s.wake.write(1)?;
        Ok(true)
    }

    /// Pause (`true`) or resume the relay call's recording. Returns `false`
    /// for an unknown call.
    ///
    /// # Errors
    ///
    /// [`RelayError::Busy`] when the worker's queue is full,
    /// [`RelayError::WorkerGone`] when the worker has stopped.
    pub fn pause_recording(&mut self, id: CallId, paused: bool) -> Result<bool, RelayError> {
        self.reap();
        let Some(c) = self.calls.get(&id).filter(|c| !c.ending) else {
            return Ok(false);
        };
        let s = &self.shards[c.shard];
        s.commands
            .try_send(Command::PauseRecord { call: id, paused })
            .map_err(RelayError::from)?;
        s.wake.write(1)?;
        Ok(true)
    }

    /// Block (`on`) or unblock what the relay call's leg `leg`
    /// sends: all its RTP, or only its telephone events. RTCP passes.
    /// Returns `false` for an unknown call.
    ///
    /// # Errors
    ///
    /// [`RelayError::Busy`] when the worker's queue is full,
    /// [`RelayError::WorkerGone`] when the worker has stopped.
    pub fn block(
        &mut self,
        id: CallId,
        leg: CallLeg,
        what: Blocked,
        on: bool,
    ) -> Result<bool, RelayError> {
        self.reap();
        let Some(c) = self.calls.get(&id).filter(|c| !c.ending) else {
            return Ok(false);
        };
        let s = &self.shards[c.shard];
        s.commands
            .try_send(Command::Block {
                call: id,
                leg,
                what,
                on,
            })
            .map_err(RelayError::from)?;
        s.wake.write(1)?;
        Ok(true)
    }

    /// Whether relay call `id` is on hold: its media timeout is then
    /// `sessions.silent_timeout` instead of `sessions.timeout`. Returns
    /// `false` for an unknown call.
    ///
    /// # Errors
    ///
    /// [`RelayError::Busy`] when the worker's queue is full,
    /// [`RelayError::WorkerGone`] when the worker has stopped.
    pub fn set_held(&mut self, id: CallId, held: bool) -> Result<bool, RelayError> {
        self.reap();
        let Some(c) = self.calls.get(&id).filter(|c| !c.ending) else {
            return Ok(false);
        };
        let timeout_ms = if held {
            self.silent_timeout_ms
        } else {
            self.timeout_ms
        };
        let s = &self.shards[c.shard];
        s.commands
            .try_send(Command::SetTimeout {
                call: id,
                timeout_ms,
            })
            .map_err(RelayError::from)?;
        s.wake.write(1)?;
        Ok(true)
    }

    /// Make relay call `id` a subscription's: what arrives on it is not
    /// relayed. Returns `false` for an unknown call.
    ///
    /// # Errors
    ///
    /// [`RelayError::Busy`] when the worker's queue is full,
    /// [`RelayError::WorkerGone`] when the worker has stopped.
    pub fn sink(&mut self, id: CallId) -> Result<bool, RelayError> {
        self.reap();
        let Some(c) = self.calls.get(&id).filter(|c| !c.ending) else {
            return Ok(false);
        };
        let s = &self.shards[c.shard];
        s.commands
            .try_send(Command::Sink { call: id })
            .map_err(RelayError::from)?;
        s.wake.write(1)?;
        Ok(true)
    }

    /// Copy (`on`) or stop copying what side `source_b` of relay call
    /// `source` sends to side `sub_b` of the subscription call `sub` (made
    /// with [`Relay::create_call_near`] `source`). Returns `false` when
    /// either call is unknown or they are on different workers.
    ///
    /// # Errors
    ///
    /// [`RelayError::Busy`] when the worker's queue is full,
    /// [`RelayError::WorkerGone`] when the worker has stopped.
    pub fn tap(
        &mut self,
        (source, source_leg): (CallId, CallLeg),
        (sub, sub_leg): (CallId, CallLeg),
        on: bool,
    ) -> Result<bool, RelayError> {
        self.reap();
        let shard = |id: CallId| self.calls.get(&id).filter(|c| !c.ending).map(|c| c.shard);
        let (Some(a), Some(b)) = (shard(source), shard(sub)) else {
            return Ok(false);
        };
        if a != b {
            return Ok(false);
        }
        let s = &self.shards[a];
        s.commands
            .try_send(Command::Tap {
                source,
                source_leg,
                sub,
                sub_leg,
                on,
            })
            .map_err(RelayError::from)?;
        s.wake.write(1)?;
        Ok(true)
    }

    /// Whether the relay call waits for an answer: `Some(t)` ends it `t`
    /// from now unless answered (whatever its media); `None` (answered)
    /// applies the media timeout from now on. Returns `false` for an
    /// unknown call.
    ///
    /// # Errors
    ///
    /// [`RelayError::Busy`] when the worker's queue is full,
    /// [`RelayError::WorkerGone`] when the worker has stopped.
    pub fn awaiting_answer(
        &mut self,
        id: CallId,
        deadline: Option<std::time::Duration>,
    ) -> Result<bool, RelayError> {
        self.reap();
        let Some(c) = self.calls.get(&id).filter(|c| !c.ending) else {
            return Ok(false);
        };
        let s = &self.shards[c.shard];
        let within_ms = deadline.map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        s.commands
            .try_send(Command::AwaitAnswer {
                call: id,
                within_ms,
            })
            .map_err(RelayError::from)?;
        s.wake.write(1)?;
        Ok(true)
    }

    /// The relay calls that ended on their own since the last call (their
    /// media or answer timed out); their ports are free again.
    pub fn take_ended(&mut self) -> Vec<CallId> {
        self.reap();
        std::mem::take(&mut self.ended)
    }

    /// Bundle side A of `members` onto side A of `primary` (RFC 8843): A
    /// sends and receives all of them on `primary`'s port, with its ICE,
    /// DTLS and SRTP; arriving RTP goes to the member whose payload types
    /// it uses, RTCP to the member of its sender SSRC. Each member is
    /// `(call, payload types)`; `primary` is one of them. Returns `false`
    /// when a call is unknown or on another worker.
    ///
    /// # Errors
    ///
    /// [`RelayError::Busy`] when the worker's queue is full,
    /// [`RelayError::WorkerGone`] when the worker has stopped.
    pub fn bundle(
        &mut self,
        primary: CallId,
        members: &[(CallId, Vec<Pt>)],
    ) -> Result<bool, RelayError> {
        self.reap();
        let Some(shard) = self.calls.get(&primary).map(|c| c.shard) else {
            return Ok(false);
        };
        if members
            .iter()
            .any(|(id, _)| self.calls.get(id).is_none_or(|c| c.shard != shard))
        {
            return Ok(false);
        }
        let s = &self.shards[shard];
        s.commands
            .try_send(Command::Bundle {
                primary,
                members: members.to_vec(),
            })
            .map_err(RelayError::from)?;
        s.wake.write(1)?;
        Ok(true)
    }

    /// The legs of a call (A RTP, A RTCP, B RTP, B RTCP), from its worker;
    /// `None` for an unknown call or a worker that does not answer within
    /// a second. Packets relayed by the XDP fast path are included as of
    /// the last poll of its counters (every second).
    pub fn query(&mut self, id: CallId) -> Option<[LegStats; 4]> {
        self.reap();
        let c = self.calls.get(&id)?;
        let s = &self.shards[c.shard];
        let (reply, answer) = sync_channel(1);
        s.commands
            .try_send(Command::Query { call: id, reply })
            .ok()?;
        s.wake.write(1).ok()?;
        answer
            .recv_timeout(std::time::Duration::from_secs(1))
            .ok()
            .flatten()
    }

    /// Counters summed over all workers.
    pub fn totals(&mut self) -> Totals {
        self.reap();
        let mut t = Totals {
            active_calls: self.calls.values().filter(|c| !c.ending).count(),
            ..Totals::default()
        };
        for s in &self.shards {
            t.forwarded += s.stats.forwarded.load(Ordering::Relaxed);
            t.forwarded_bytes += s.stats.forwarded_bytes.load(Ordering::Relaxed);
            t.kernel_packets += s.stats.kernel_packets.load(Ordering::Relaxed);
            t.kernel_bytes += s.stats.kernel_bytes.load(Ordering::Relaxed);
            t.dropped += s.stats.dropped.load(Ordering::Relaxed);
            t.send_errors += s.stats.send_errors.load(Ordering::Relaxed);
            t.calls_ended += s.stats.calls_ended.load(Ordering::Relaxed);
            t.srtp_rejected += s.stats.srtp_rejected.load(Ordering::Relaxed);
            t.zrtp += s.stats.zrtp.load(Ordering::Relaxed);
        }
        t
    }
}
