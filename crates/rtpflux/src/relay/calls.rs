//! Creating, restoring, updating and deleting relay calls.

#[allow(clippy::wildcard_imports)]
use super::*;
use rtpflux_core::relay::Slot;

impl Relay {
    pub(super) fn bind_pair(ip: IpAddr, port: u16) -> std::io::Result<(UdpSocket, UdpSocket)> {
        let rtp = UdpSocket::bind((ip, port))?;
        let rtcp = UdpSocket::bind((ip, port + 1))?;
        rtp.set_nonblocking(true)?;
        rtcp.set_nonblocking(true)?;
        Ok((rtp, rtcp))
    }

    /// Allocate and bind a pair in `shard`, skipping ports something else
    /// holds.
    pub(super) fn take_pair(
        &mut self,
        shard: usize,
        ip: IpAddr,
    ) -> Result<(u16, UdpSocket, UdpSocket), RelayError> {
        for _ in 0..16 {
            let port = self.shards[shard]
                .alloc
                .alloc()
                .ok_or(RelayError::PortsExhausted)?;
            match Self::bind_pair(ip, port) {
                Ok((rtp, rtcp)) => return Ok((port, rtp, rtcp)),
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                    log::warn!("port {port} on {ip} is in use outside rtpflux; skipping it");
                    // Keep it marked as allocated so it is not retried.
                }
                Err(e) => {
                    self.shards[shard].alloc.free(port);
                    return Err(e.into());
                }
            }
        }
        Err(RelayError::PortsExhausted)
    }

    /// Create a call between sides `a` and `b`.
    ///
    /// # Errors
    ///
    /// [`RelayError`] when an interface is unknown, ports are exhausted,
    /// sockets cannot be bound or the worker is saturated.
    pub fn create_call(&mut self, a: Side, b: Side) -> Result<CallPorts, RelayError> {
        self.create_call_near(a, b, None)
    }

    /// Create a call on the same worker as call `near` (the members of a
    /// BUNDLE group must share one), or on the next worker.
    ///
    /// # Errors
    ///
    /// As [`Relay::create_call`].
    pub fn create_call_near(
        &mut self,
        a: Side,
        b: Side,
        near: Option<CallId>,
    ) -> Result<CallPorts, RelayError> {
        self.reap();
        let ia = self
            .interfaces
            .get(a.interface.get())
            .ok_or(RelayError::UnknownInterface(a.interface))?
            .clone();
        let ib = self
            .interfaces
            .get(b.interface.get())
            .ok_or(RelayError::UnknownInterface(b.interface))?
            .clone();
        // A BUNDLE member goes on its group's worker; anything else on the
        // next worker in turn, or, when that one is out of ports, the
        // first after it that has some.
        let candidates: Vec<usize> = if let Some(c) = near.and_then(|id| self.calls.get(&id)) {
            vec![c.shard]
        } else {
            let first = self.next_shard;
            self.next_shard = (self.next_shard + 1) % self.shards.len();
            (0..self.shards.len())
                .map(|k| (first + k) % self.shards.len())
                .collect()
        };
        let mut last = RelayError::PortsExhausted;
        for shard in candidates {
            match self.take_pairs(shard, ia.address, ib.address) {
                Ok(((pa, a_rtp, a_rtcp), (pb, b_rtp, b_rtcp))) => {
                    return self.install(shard, (&a, pa, a_rtp, a_rtcp), (&b, pb, b_rtp, b_rtcp));
                }
                Err(RelayError::PortsExhausted) => last = RelayError::PortsExhausted,
                Err(e) => return Err(e),
            }
        }
        Err(last)
    }

    /// Two pairs in `shard` (side A's on `ip_a`, side B's on `ip_b`), or
    /// neither.
    #[allow(clippy::type_complexity)]
    fn take_pairs(
        &mut self,
        shard: usize,
        ip_a: IpAddr,
        ip_b: IpAddr,
    ) -> Result<((u16, UdpSocket, UdpSocket), (u16, UdpSocket, UdpSocket)), RelayError> {
        let a = self.take_pair(shard, ip_a)?;
        match self.take_pair(shard, ip_b) {
            Ok(b) => Ok((a, b)),
            Err(e) => {
                self.shards[shard].alloc.free(a.0);
                Err(e)
            }
        }
    }

    /// Recreate a call on its old ports `port_a` and `port_b` (restoring
    /// state after a restart).
    ///
    /// # Errors
    ///
    /// [`RelayError::PortsExhausted`] when the ports are outside the range,
    /// in different shards or taken; otherwise as [`Relay::create_call`].
    pub fn restore_call(
        &mut self,
        a: Side,
        b: Side,
        port_a: u16,
        port_b: u16,
    ) -> Result<CallPorts, RelayError> {
        self.reap();
        let ia = self
            .interfaces
            .get(a.interface.get())
            .ok_or(RelayError::UnknownInterface(a.interface))?
            .clone();
        let ib = self
            .interfaces
            .get(b.interface.get())
            .ok_or(RelayError::UnknownInterface(b.interface))?
            .clone();
        let shard = self
            .shards
            .iter()
            .position(|s| s.alloc.contains(port_a) && s.alloc.contains(port_b))
            .ok_or(RelayError::PortsExhausted)?;
        if !self.shards[shard].alloc.take(port_a) {
            return Err(RelayError::PortsExhausted);
        }
        if !self.shards[shard].alloc.take(port_b) {
            self.shards[shard].alloc.free(port_a);
            return Err(RelayError::PortsExhausted);
        }
        let bound = Self::bind_pair(ia.address, port_a)
            .and_then(|x| Self::bind_pair(ib.address, port_b).map(|y| (x, y)));
        match bound {
            Ok(((a_rtp, a_rtcp), (b_rtp, b_rtcp))) => self.install(
                shard,
                (&a, port_a, a_rtp, a_rtcp),
                (&b, port_b, b_rtp, b_rtcp),
            ),
            Err(e) => {
                self.shards[shard].alloc.free(port_a);
                self.shards[shard].alloc.free(port_b);
                Err(e.into())
            }
        }
    }

    /// Hand a call with bound sockets to its worker.
    pub(super) fn install(
        &mut self,
        shard: usize,
        (a, pa, a_rtp, a_rtcp): (&Side, u16, UdpSocket, UdpSocket),
        (b, pb, b_rtp, b_rtcp): (&Side, u16, UdpSocket, UdpSocket),
    ) -> Result<CallPorts, RelayError> {
        let (a, b) = (*a, *b);
        let advertised = |s: &Side| self.interfaces[s.interface.get()].advertised();
        let (adv_a, adv_b) = (advertised(&a), advertised(&b));
        let first = self.shards[shard].first_port;
        let slot = |port: u16| Slot::new(u32::from(port - first));
        let rtcp_of = |s: &Side| {
            s.rtcp.or_else(|| {
                s.rtp
                    .map(|r| SocketAddr::new(r.ip(), r.port().wrapping_add(1)))
            })
        };
        let id = self.next_id;
        self.next_id = id.next();
        // Legs: what arrives from A on A's sockets goes to B, and vice versa.
        let legs = [
            LegInit {
                slot: slot(pa),
                socket: a_rtp,
                latch: latch_of(&a, a.rtp),
                partner: slot(pb),
                media: Media::of(&a),
            },
            LegInit {
                slot: slot(pa).rtcp(),
                socket: a_rtcp,
                latch: latch_of(&a, rtcp_of(&a)),
                partner: slot(pb).rtcp(),
                media: Media::of(&a),
            },
            LegInit {
                slot: slot(pb),
                socket: b_rtp,
                latch: latch_of(&b, b.rtp),
                partner: slot(pa),
                media: Media::of(&b),
            },
            LegInit {
                slot: slot(pb).rtcp(),
                socket: b_rtcp,
                latch: latch_of(&b, rtcp_of(&b)),
                partner: slot(pa).rtcp(),
                media: Media::of(&b),
            },
        ];
        let cmd = Command::AddCall {
            call: id,
            legs: Box::new(legs),
            timeout_ms: self.timeout_ms,
        };
        let s = &self.shards[shard];
        if let Err(e) = s.commands.try_send(cmd) {
            let alloc = &mut self.shards[shard].alloc;
            alloc.free(pa);
            alloc.free(pb);
            return Err(e.into());
        }
        self.calls.insert(
            id,
            CallEntry {
                shard,
                port_a: pa,
                port_b: pb,
                ending: false,
            },
        );
        // The worker has the call: a failed wake-up only delays it (the
        // worker looks at its queue every 100 ms anyway).
        if let Err(e) = s.wake.write(1) {
            log::warn!("waking media worker {shard}: {e}");
        }
        Ok(CallPorts {
            id,
            a: SocketAddr::new(adv_a, pa),
            b: SocketAddr::new(adv_b, pb),
        })
    }

    /// Set new peer addresses and SRTP keys for side A or B of a call (an
    /// SDP answer or a re-offer); unchanged keys keep their SRTP state.
    /// Returns `false` for an unknown or ending call.
    ///
    /// # Errors
    ///
    /// [`RelayError::Busy`] when the worker's queue is full,
    /// [`RelayError::WorkerGone`] when the worker has stopped.
    pub fn update_side(
        &mut self,
        id: CallId,
        leg: CallLeg,
        side: &Side,
    ) -> Result<bool, RelayError> {
        self.reap();
        let Some(c) = self.calls.get(&id).filter(|c| !c.ending) else {
            return Ok(false);
        };
        let rtcp = side.rtcp.or_else(|| {
            side.rtp
                .map(|r| SocketAddr::new(r.ip(), r.port().wrapping_add(1)))
        });
        let cmd = Command::UpdatePeer {
            call: id,
            leg,
            latches: Box::new([latch_of(side, side.rtp), latch_of(side, rtcp)]),
            media: Box::new(Media::of(side)),
        };
        let s = &self.shards[c.shard];
        s.commands.try_send(cmd).map_err(RelayError::from)?;
        s.wake.write(1)?;
        Ok(true)
    }

    /// `connect`: join leg `x.1` of call `x.0` with leg `y.1` of call
    /// `y.0` (calls on one worker or on two); each call's other party is
    /// detached. Returns `false` when either call is unknown or ending.
    ///
    /// # Errors
    ///
    /// [`RelayError`] when a worker cannot be told.
    pub fn connect(
        &mut self,
        x: (CallId, CallLeg),
        y: (CallId, CallLeg),
        transcode: [Option<super::Transcode>; 2],
    ) -> Result<bool, RelayError> {
        self.reap();
        let slot_of = |calls: &std::collections::HashMap<CallId, super::CallEntry>,
                       shards: &[super::Shard],
                       (id, leg): (CallId, CallLeg)| {
            let c = calls.get(&id).filter(|c| !c.ending)?;
            let port = if leg == CallLeg::B {
                c.port_b
            } else {
                c.port_a
            };
            Some((
                c.shard,
                Slot::new(u32::from(port - shards[c.shard].first_port)),
            ))
        };
        let (Some((wx, sx)), Some((wy, sy))) = (
            slot_of(&self.calls, &self.shards, x),
            slot_of(&self.calls, &self.shards, y),
        ) else {
            return Ok(false);
        };
        if wx == wy {
            let s = &self.shards[wx];
            s.commands
                .try_send(Command::ConnectLocal {
                    x: sx,
                    y: sy,
                    transcode,
                })
                .map_err(RelayError::from)?;
            s.wake.write(1)?;
            return Ok(true);
        }
        let cells = [(); 2].map(|()| std::sync::Arc::new(std::sync::Mutex::new(None)));
        let (tx_xy, rx_xy) = std::sync::mpsc::sync_channel(super::worker::FORWARD_QUEUE);
        let (tx_yx, rx_yx) = std::sync::mpsc::sync_channel(super::worker::FORWARD_QUEUE);
        let ends = [
            (
                wx,
                super::worker::RemoteEnd {
                    call: x.0,
                    local: sx,
                    peer: sy,
                    tx: tx_xy,
                    rx: rx_yx,
                    peer_wake: std::sync::Arc::clone(&self.shards[wy].wake),
                    mine: std::sync::Arc::clone(&cells[0]),
                    theirs: std::sync::Arc::clone(&cells[1]),
                    transcode: transcode[0],
                },
            ),
            (
                wy,
                super::worker::RemoteEnd {
                    call: y.0,
                    local: sy,
                    peer: sx,
                    tx: tx_yx,
                    rx: rx_xy,
                    peer_wake: std::sync::Arc::clone(&self.shards[wx].wake),
                    mine: std::sync::Arc::clone(&cells[1]),
                    theirs: std::sync::Arc::clone(&cells[0]),
                    transcode: transcode[1],
                },
            ),
        ];
        for (w, end) in ends {
            let s = &self.shards[w];
            s.commands
                .try_send(Command::ConnectRemote(Box::new(end)))
                .map_err(RelayError::from)?;
            s.wake.write(1)?;
        }
        Ok(true)
    }

    /// `connect` with `directional`: copy (`on`) what leg `source` sends
    /// to leg `dest`, which keeps its own media, or stop. On one worker a
    /// tap; across workers a channel like `connect`'s, the listener's end
    /// first (so no copy arrives before it). Returns `false` for an unknown
    /// or ending call. Copies are converted with `transcode` (to the
    /// listener's codec), if given.
    ///
    /// # Errors
    ///
    /// [`RelayError`] when a worker cannot be told.
    pub fn listen(
        &mut self,
        source: (CallId, CallLeg),
        dest: (CallId, CallLeg),
        on: bool,
        transcode: Option<super::Transcode>,
    ) -> Result<bool, RelayError> {
        self.reap();
        let slot_of = |(id, leg): (CallId, CallLeg)| {
            let c = self.calls.get(&id).filter(|c| !c.ending)?;
            let port = if leg == CallLeg::B {
                c.port_b
            } else {
                c.port_a
            };
            Some((
                c.shard,
                Slot::new(u32::from(port - self.shards[c.shard].first_port)),
            ))
        };
        let (Some((ws, ss)), Some((wd, sd))) = (slot_of(source), slot_of(dest)) else {
            return Ok(false);
        };
        let tell = |w: usize, cmd: Command| -> Result<(), RelayError> {
            let s = &self.shards[w];
            s.commands.try_send(cmd).map_err(RelayError::from)?;
            s.wake.write(1)?;
            Ok(())
        };
        if ws == wd {
            tell(
                ws,
                Command::Listen {
                    source: ss,
                    dest: sd,
                    on,
                    transcode,
                },
            )?;
            return Ok(true);
        }
        if !on {
            tell(
                ws,
                Command::Unlisten {
                    source: ss,
                    worker: wd,
                    peer: sd,
                },
            )?;
            return Ok(true);
        }
        let (tx, rx) = std::sync::mpsc::sync_channel(super::worker::FORWARD_QUEUE);
        tell(
            wd,
            Command::ListenIncoming(Box::new(super::worker::ListenEnd { call: dest.0, rx })),
        )?;
        tell(
            ws,
            Command::ListenRemote(Box::new(super::worker::RemoteListen {
                source: ss,
                worker: wd,
                peer: sd,
                tx,
                wake: std::sync::Arc::clone(&self.shards[wd].wake),
                transcode,
            })),
        )?;
        Ok(true)
    }

    /// `media echo`: each side's media (legs A, B) relayed, echoed or
    /// dropped. Returns `false` for an unknown or ending call.
    ///
    /// # Errors
    ///
    /// [`RelayError`] when the worker cannot be told.
    pub fn echo(&mut self, id: CallId, modes: [super::Echo; 2]) -> Result<bool, RelayError> {
        self.reap();
        let Some(c) = self.calls.get(&id).filter(|c| !c.ending) else {
            return Ok(false);
        };
        let first = self.shards[c.shard].first_port;
        let slots = [c.port_a, c.port_b].map(|p| Slot::new(u32::from(p - first)));
        let s = &self.shards[c.shard];
        s.commands
            .try_send(Command::Echo { slots, modes })
            .map_err(RelayError::from)?;
        s.wake.write(1)?;
        Ok(true)
    }

    /// DTMF security (and delay) of the keys leg `leg` of call `id` sends
    /// (`None`: none). Returns `false` for an unknown or ending call.
    ///
    /// # Errors
    ///
    /// [`RelayError`] when the worker cannot be told.
    pub fn secure_dtmf(
        &mut self,
        id: CallId,
        leg: CallLeg,
        security: Option<super::dtmf_security::DtmfSecurity>,
    ) -> Result<bool, RelayError> {
        self.reap();
        let Some(c) = self.calls.get(&id).filter(|c| !c.ending) else {
            return Ok(false);
        };
        let s = &self.shards[c.shard];
        s.commands
            .try_send(Command::SecureDtmf {
                call: id,
                leg,
                security: security.map(Box::new),
            })
            .map_err(RelayError::from)?;
        s.wake.write(1)?;
        Ok(true)
    }

    /// End a call. Returns `false` for an unknown or already ending call.
    /// Its ports are reused once the worker has closed the sockets.
    ///
    /// # Errors
    ///
    /// [`RelayError`] when the worker cannot be told.
    pub fn delete_call(&mut self, id: CallId) -> Result<bool, RelayError> {
        self.reap();
        let Some(c) = self.calls.get_mut(&id).filter(|c| !c.ending) else {
            return Ok(false);
        };
        let shard = c.shard;
        c.ending = true;
        // A full queue does not block the control thread: the delete is
        // kept and sent again until it goes through (never dropped, which
        // would leave the call relaying).
        let s = &self.shards[shard];
        match s.commands.try_send(Command::RemoveCall { call: id }) {
            Ok(()) => {
                let _ = s.wake.write(1);
            }
            Err(TrySendError::Full(_)) => self.unsent_deletes.push(id),
            Err(TrySendError::Disconnected(_)) => return Err(RelayError::WorkerGone),
        }
        Ok(true)
    }

    /// Send again the deletes a full queue refused.
    pub(super) fn retry_deletes(&mut self) {
        let mut left = Vec::new();
        for id in std::mem::take(&mut self.unsent_deletes) {
            let Some(c) = self.calls.get(&id) else {
                continue;
            };
            let s = &self.shards[c.shard];
            match s.commands.try_send(Command::RemoveCall { call: id }) {
                Ok(()) => {
                    let _ = s.wake.write(1);
                }
                Err(TrySendError::Full(_)) => left.push(id),
                // Its worker stopped: nothing relays the call any more.
                Err(TrySendError::Disconnected(_)) => {
                    log::warn!("call {id}: its media worker stopped");
                }
            }
        }
        self.unsent_deletes = left;
    }
}

/// The latch of a leg of `side` whose SDP address is `expected`.
fn latch_of(side: &Side, expected: Option<SocketAddr>) -> Latch {
    let l = Latch::new(expected, side.learning, side.strict_source);
    if side.handover { l.with_handover() } else { l }
}
