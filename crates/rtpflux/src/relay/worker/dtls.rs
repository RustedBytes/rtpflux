//! DTLS-SRTP handshakes on media ports: starting clients, feeding
//! datagrams, and keying a leg once its handshake completes.

#[allow(clippy::wildcard_imports)]
use super::*;

/// How often a DTLS client resends its first flight while unanswered.
pub(super) const DTLS_RETRY_MS: u64 = 1_000;

/// The DTLS association of one leg.
pub(super) struct DtlsLeg {
    pub(super) side: DtlsSide,
    pub(super) assoc: Option<Association>,
    pub(super) started_ms: u64,
}

/// The worker tables a DTLS datagram touches.
pub(super) struct DtlsTables<'a> {
    pub(super) dtls: &'a mut PerSlot<Option<Box<DtlsLeg>>>,
    pub(super) crypto: &'a mut PerSlot<Option<Box<LegCrypto>>>,
    pub(super) legs: &'a mut PerSlot<Option<Leg>>,
    pub(super) sockets: &'a PerSlot<Option<UdpSocket>>,
    pub(super) muxed: &'a PerSlot<bool>,
    pub(super) identity: &'a Identity,
    pub(super) stats: &'a Stats,
    /// An association that keyed (`true`) or failed, to report once the
    /// tables are let go ([`Worker::report_dtls`]).
    pub(super) done: Option<(Slot, bool)>,
}

impl DtlsTables<'_> {
    /// Send what the association on `slot` produced to `dst`.
    pub(super) fn flush(&mut self, slot: Slot, dst: SocketAddr) {
        let Some(Some(leg)) = self.dtls.get_mut(slot) else {
            return;
        };
        let Some(assoc) = leg.assoc.as_mut() else {
            return;
        };
        let Some(sock) = self.sockets.get(slot).and_then(Option::as_ref) else {
            return;
        };
        for d in assoc.take_output() {
            if let Err(e) = sock.send_to(&d, dst) {
                log::debug!("dtls: send to {dst}: {e}");
            }
        }
    }

    /// Keys arrived for `slot`: SRTP on it (and on its RTCP leg when RTCP
    /// is muxed), and the peer's address is the one that completed the
    /// handshake.
    pub(super) fn install(&mut self, slot: Slot, progress: Progress, src: Option<SocketAddr>) {
        match progress {
            Progress::Keyed { inbound, outbound } => {
                let srtp = Srtp {
                    inbound: Inbound::Key(inbound),
                    outbound: Some(outbound),
                };
                let also_rtcp = !slot.is_rtcp() && self.muxed.get(slot).copied().unwrap_or(false);
                for s in [Some(slot), also_rtcp.then_some(slot.rtcp())]
                    .into_iter()
                    .flatten()
                {
                    if let Some(c) = self.crypto.get_mut(s) {
                        *c = LegCrypto::new(srtp, s.is_rtcp(), false);
                    }
                    if let (Some(src), Some(Some(leg))) = (src, self.legs.get_mut(s)) {
                        leg.latch.confirm(src, false);
                    }
                }
                self.stats.dtls_handshakes.fetch_add(1, Ordering::Relaxed);
                log::debug!("dtls: SRTP keyed on slot {slot}");
                self.done = Some((slot, true));
            }
            Progress::Failed => {
                self.stats.dtls_failures.fetch_add(1, Ordering::Relaxed);
                log::info!("dtls: association on slot {slot} failed");
                self.done = Some((slot, false));
            }
            Progress::Pending => {}
        }
    }

    /// A DTLS datagram arrived on `slot` from `src`.
    pub(super) fn datagram(&mut self, slot: Slot, packet: &[u8], src: SocketAddr, now: u64) {
        let identity = self.identity;
        let Some(Some(leg)) = self.dtls.get_mut(slot) else {
            return;
        };
        // A server answers a ClientHello; a failed association starts
        // over on a new one. Anything else (a retransmitted final flight,
        // a stray or spoofed datagram) goes to the association there is:
        // an established one, still waiting for the answer's fingerprint,
        // is not torn down by it.
        let fresh = leg.side.role == Role::Server
            && is_client_hello(packet)
            && leg.assoc.as_ref().is_none_or(Association::failed);
        if fresh {
            match Association::new(identity, Role::Server, leg.side.remote) {
                Ok(a) => {
                    leg.assoc = Some(a);
                    leg.started_ms = now;
                }
                Err(e) => {
                    log::warn!("dtls: {e}");
                    return;
                }
            }
        }
        let Some(assoc) = leg.assoc.as_mut() else {
            return;
        };
        let progress = assoc.receive(packet);
        log::debug!(
            "dtls: {} octets from {src} on slot {slot}: {assoc:?}",
            packet.len()
        );
        self.flush(slot, src);
        self.install(slot, progress, Some(src));
    }
}

impl Worker {
    /// Start (or restart, when unanswered) the handshakes in which the
    /// relay is the DTLS client, towards each leg's current peer address.
    pub(super) fn start_dtls_clients(&mut self, now: u64, slots: &[Slot]) {
        for &slot in slots {
            let Some(Some(leg)) = self.dtls.get_mut(slot) else {
                continue;
            };
            if leg.side.role != Role::Client {
                continue;
            }
            let due = match &leg.assoc {
                None => true,
                Some(a) => a.handshaking() && now.saturating_sub(leg.started_ms) >= DTLS_RETRY_MS,
            };
            let target = self
                .legs
                .get(slot)
                .copied()
                .flatten()
                .and_then(|l| l.latch.target());
            let (true, Some(dst)) = (due, target) else {
                continue;
            };
            // A field apart from `self.dtls`: borrowed, not cloned.
            match Association::new(&self.identity, Role::Client, leg.side.remote) {
                Ok(a) => {
                    leg.assoc = Some(a);
                    leg.started_ms = now;
                }
                Err(e) => {
                    log::warn!("dtls: {e}");
                    continue;
                }
            }
            self.dtls_tables().flush(slot, dst);
        }
    }

    pub(super) fn dtls_tables(&mut self) -> DtlsTables<'_> {
        DtlsTables {
            dtls: &mut self.dtls,
            crypto: &mut self.crypto,
            legs: &mut self.legs,
            sockets: &self.sockets,
            muxed: &self.muxed,
            identity: &self.identity,
            stats: &self.stats,
            done: None,
        }
    }

    /// Report an association that keyed or failed.
    pub(super) fn report_dtls(&self, done: Option<(Slot, bool)>) {
        if let Some((slot, keyed)) = done {
            self.emit_media(
                slot,
                if keyed {
                    crate::relay::media_events::MediaEventKind::DtlsReady
                } else {
                    crate::relay::media_events::MediaEventKind::DtlsFailed
                },
            );
        }
    }
}

/// Whether `packet` starts with a DTLS handshake record (content type 22)
/// carrying a `ClientHello` (handshake type 1, RFC 6347 §4.2.2).
fn is_client_hello(packet: &[u8]) -> bool {
    packet.first() == Some(&22) && packet.get(13) == Some(&1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hellos_are_told_apart() {
        let mut hello = [0u8; 25];
        hello[0] = 22; // handshake record
        hello[13] = 1; // ClientHello
        assert!(is_client_hello(&hello));
        hello[13] = 20; // Finished
        assert!(!is_client_hello(&hello));
        hello[0] = 23; // application data
        hello[13] = 1;
        assert!(!is_client_hello(&hello));
        assert!(!is_client_hello(&[22; 5]));
        assert!(!is_client_hello(&[]));
    }
}
