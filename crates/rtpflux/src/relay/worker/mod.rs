//! One media worker: owns a shard's sockets and legs and relays packets.
//!
//! Hot path, per ready socket: one `recvmmsg` fills up to `batch`
//! preallocated buffers; each datagram goes through
//! `rtpflux_core::relay::on_packet`; accepted ones are sent with one
//! `sendmmsg` per destination socket straight from the receive buffers (no
//! copy). No allocation happens on this path: buffers, message headers and
//! tables are allocated in [`Worker::new`] or at call setup.
//!
//! SRTP is terminated per leg: a packet from an SRTP peer is authenticated
//! and decrypted in its receive buffer before the relay decision (so a
//! forged packet cannot move a latch), and one bound for an SRTP peer is
//! encrypted there before sending. Calls with SRTP stay in userspace.

mod commands;
mod connect;
pub use connect::{FORWARD_QUEUE, Forwarded, RemoteEnd};
mod listen;
pub use listen::{ListenEnd, RemoteListen};

mod bundle;
mod crypto;
mod dtls;
mod dtmf;
mod dtmf_security;
mod dtmf_xcode;
mod features;
mod ice;
mod io;
mod offload;
mod pcm;
mod repack;
mod rtcp;
mod slots;
mod subscribe;
mod tones;
mod uring;
pub use tones::{ToneMode, Tones};

use super::offload::{Dir, OffloadMsg};
use super::{
    DtlsSide, DtmfEvent, IceCreds, Inbound, LegStats, MAX_BATCH, RtcpStats, Side, Srtp, Stats,
};
use crate::dtls::{Association, Identity, Progress};
use crate::relay::{CallId, CallLeg};
use nix::errno::Errno;
use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout};
use nix::sys::eventfd::EventFd;
use nix::sys::socket::{
    ControlMessage, MsgFlags, MultiHeaders, SockaddrStorage, recvmmsg, sendmmsg,
};
use rtpflux_core::dtls::Role;
use rtpflux_core::dtmf::{Detector, Finished};
use rtpflux_core::latch::Latch;
use rtpflux_core::relay::Slot;
use rtpflux_core::relay::{self, Decision, Leg};
use rtpflux_core::stun::{self, Answer, Credentials, Kind};
use rtpflux_srtp::{Protect, Unprotect};
use slots::PerSlot;
use std::collections::HashMap;
use std::io::{IoSlice, IoSliceMut};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, Sender, SyncSender, TryRecvError};
use std::time::Instant;

use bundle::BundleRoute;
use crypto::LegCrypto;
use dtls::{DtlsLeg, DtlsTables};
use dtmf::DtmfLeg;
use features::Playback;
pub use features::{Blocked, Blocks, Playing};
use ice::{IceLegs, answer_stun};
use offload::OFFLOAD_RETRY_MS;
use rtcp::{RtcpLeg, observe_rtcp};
use rtpflux_core::rtp::Pt;

/// Epoll token of the wake-up eventfd (sockets use their slot index).
const WAKE: u64 = u64::MAX;
/// The epoll token of the `io_uring` receiver's completions.
const URING: u64 = u64::MAX - 1;
/// Batches read from one socket before moving to the next ready one.
const MAX_ROUNDS: usize = 8;
/// How often idle calls are looked for.
const SWEEP_MS: u64 = 1_000;

/// A leg to install: its socket, latch and partner slot.
pub(super) struct LegInit {
    pub slot: Slot,
    pub socket: UdpSocket,
    pub latch: Latch,
    pub partner: Slot,
    pub media: Media,
}

/// What a side's legs need besides addresses: SRTP keys, `rtcp-mux`, ICE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Media {
    pub srtp: Srtp,
    pub rtcp_mux: bool,
    pub opaque: bool,
    pub ice: Option<IceCreds>,
    pub dtls: Option<DtlsSide>,
    pub dtmf: Option<(Pt, u32)>,
    pub transcode: Option<super::Transcode>,
    pub dtmf_xcode: Option<super::DtmfXcode>,
    pub repack: Option<super::Repack>,
    pub unidirectional: bool,
}

impl Media {
    pub(super) fn of(side: &Side) -> Self {
        Media {
            srtp: side.srtp,
            rtcp_mux: side.rtcp_mux,
            opaque: side.opaque,
            ice: side.ice,
            dtls: side.dtls,
            dtmf: side.dtmf,
            transcode: side.transcode,
            dtmf_xcode: side.dtmf_xcode,
            repack: side.repack,
            unidirectional: side.unidirectional,
        }
    }
}

pub(super) enum Command {
    /// `connect` of two calls on this worker: the RTP slots of the legs
    /// joined.
    ConnectLocal {
        x: Slot,
        y: Slot,
        /// Converting each one's media for the other (`None`: as it is).
        transcode: [Option<super::Transcode>; 2],
    },
    /// `connect` across workers: this worker's end (boxed: channels).
    ConnectRemote(Box<RemoteEnd>),
    /// A PCM stream of the leg of RTP slot `slot` (of `call`) starts, or
    /// (`None`) stops.
    Pcm {
        call: CallId,
        slot: Slot,
        end: Option<Box<crate::pcm::stream::WorkerEnd>>,
    },
    /// The leg of RTP slot `slot` leaves whatever it is joined to: it
    /// sends nowhere, and nothing is sent to it (a bridge taken down).
    Detach {
        slot: Slot,
    },
    /// `connect` with `directional` on this worker: copy (`on`) what the
    /// leg of RTP slot `source` sends to the leg of `dest`, or stop.
    /// Copies are converted to the listener's codec (`transcode`).
    Listen {
        source: Slot,
        dest: Slot,
        on: bool,
        transcode: Option<crate::relay::Transcode>,
    },
    /// The same across workers: the source's end (boxed: a channel)…
    ListenRemote(Box<RemoteListen>),
    /// …the listener's end…
    ListenIncoming(Box<ListenEnd>),
    /// …and its end, on the source's worker.
    Unlisten {
        source: Slot,
        worker: usize,
        peer: Slot,
    },
    /// DTMF security of one side's keys (`None`: none).
    SecureDtmf {
        call: CallId,
        leg: CallLeg,
        security: Option<Box<crate::relay::dtmf_security::DtmfSecurity>>,
    },
    /// `media echo`: what becomes of each side's media (the RTP slots of
    /// legs A and B).
    Echo {
        slots: [Slot; 2],
        modes: [crate::relay::Echo; 2],
    },
    /// Install the four legs of a call (boxed: sockets make it large).
    AddCall {
        call: CallId,
        legs: Box<[LegInit; 4]>,
        timeout_ms: u64,
    },
    RemoveCall {
        call: CallId,
    },
    /// New peer addresses for one side (an SDP answer or re-offer):
    /// replace the latches of that side's RTP and RTCP legs.
    UpdatePeer {
        call: CallId,
        leg: CallLeg,
        /// The RTP and RTCP latches; boxed, as is `media` (keys make it
        /// large).
        latches: Box<[Latch; 2]>,
        media: Box<Media>,
    },
    /// The kernel relayed packets of this call (it is active).
    Touch {
        call: CallId,
        /// Relayed by the kernel since the last report, from A and from B.
        packets: [u64; 2],
        octets: [u64; 2],
    },
    /// Packets of the call the kernel relayed and recorded: pcap records
    /// (`recording::frame`), to append to its recording.
    Recorded {
        call: CallId,
        frames: Vec<u8>,
    },
    /// Bundle side A of the member calls onto `primary`'s (with each
    /// member's payload types).
    Bundle {
        primary: CallId,
        members: Vec<(CallId, Vec<Pt>)>,
    },
    /// Report the call's legs.
    Query {
        call: CallId,
        reply: SyncSender<QueryReply>,
    },
    /// Answer once every command queued before it is applied.
    Barrier {
        reply: SyncSender<()>,
    },
    /// Play G.711 codes to one side (`None`: stop playing to it).
    Play {
        call: CallId,
        leg: CallLeg,
        media: Option<Box<Playing>>,
    },
    /// Play DTMF to one side.
    PlayTones {
        call: CallId,
        leg: CallLeg,
        tones: Box<Tones>,
    },
    /// Start, restart or update the full ICE agent towards one side.
    IceStart {
        call: CallId,
        leg: CallLeg,
        start: Box<super::IceStart>,
    },
    /// Candidates trickled by one side, and whether they were its last.
    IceCandidates {
        call: CallId,
        leg: CallLeg,
        candidates: Vec<super::IceCandidate>,
        end_of_candidates: bool,
    },
    /// The call waits for an answer, ending this long from now without
    /// one (`Some`); or it is answered (`None`).
    AwaitAnswer {
        call: CallId,
        within_ms: Option<u64>,
    },
    /// The media timeout of the call from now on: `sessions.timeout`, or
    /// `sessions.silent_timeout` while it is on hold.
    SetTimeout {
        call: CallId,
        timeout_ms: u64,
    },
    /// Pause (`true`) or resume the call's recording (the file stays
    /// open).
    PauseRecord {
        call: CallId,
        paused: bool,
    },
    /// Start recording the call into this file (`None`: stop).
    Record {
        call: CallId,
        spec: Option<Box<crate::recording::Spec>>,
    },
    /// Stop or resume relaying what one side sends: all its RTP, or only
    /// its telephone events.
    Block {
        call: CallId,
        leg: CallLeg,
        what: Blocked,
        on: bool,
    },
    /// The call is a subscription's: what arrives on it is not relayed.
    Sink {
        call: CallId,
    },
    /// Copy (`on`) or stop copying what one side of `source` sends to one
    /// side of the subscription call `sub`.
    Tap {
        source: CallId,
        source_leg: CallLeg,
        sub: CallId,
        sub_leg: CallLeg,
        on: bool,
    },
    /// Result of an offload request.
    Offloaded {
        call: CallId,
        ok: bool,
    },
    Shutdown,
}

/// What a worker answers to a query (`Relay::query`).
pub type QueryReply = Option<[LegStats; 4]>;

pub(super) enum Event {
    /// The call's sockets are closed; its ports can be reused.
    Closed { call: CallId, timed_out: bool },
}

/// Where a call stands with the XDP fast path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OffloadState {
    /// In userspace; may be offered once settled.
    No,
    /// Offered at this time (worker ms); waiting for the controller's
    /// answer.
    Pending(u64),
    /// Both RTP directions are relayed by the kernel.
    Active,
    /// Refused; offer again at this time.
    RetryAt(u64),
}

struct CallSlots {
    slots: [Slot; 4],
    timeout_ms: u64,
    offload: OffloadState,
    /// Waiting for an answer: ends at this time (worker ms) without one,
    /// whatever its media.
    answer_by: Option<u64>,
}

pub(super) struct Worker {
    index: usize,
    legs: PerSlot<Option<Leg>>,
    crypto: PerSlot<Option<Box<LegCrypto>>>,
    /// Per leg: the side's ICE-lite credentials.
    ice: PerSlot<Option<IceCreds>>,
    /// Per leg: the side uses `rtcp-mux` (its RTCP leg sends through its
    /// RTP socket).
    muxed: PerSlot<bool>,
    /// Slots whose datagrams are not RTP (T.38's UDPTL…): relayed as
    /// they are.
    opaque: PerSlot<bool>,
    /// STUN responses and checks are written here.
    stun_out: [u8; 1024],
    /// Per RTP slot: the full ICE agent towards the side, if any.
    ice_agents: PerSlot<Option<Box<ice::IceSlot>>>,
    /// The slots that have one.
    ice_slots: Vec<Slot>,
    /// When the next of them has something to do.
    ice_next: Option<u64>,
    /// Per leg: the shared A-RTP slot of its BUNDLE group, if side A of
    /// its call is bundled onto another call's port.
    via: PerSlot<Option<Slot>>,
    /// Per A-RTP slot carrying a BUNDLE group: how to sort its media.
    routes: PerSlot<Option<Box<BundleRoute>>>,
    /// Per RTP leg: telephone-event detection, if the side sends them.
    dtmf: PerSlot<Option<Box<DtmfLeg>>>,
    /// Per RTP leg: DTMF transcoding of what the side sends.
    xcode: PerSlot<Option<Box<dtmf_xcode::XcodeState>>>,
    /// DTMF security of the side of an RTP slot, and the slots that have
    /// it (for their timers).
    secure: PerSlot<Option<Box<dtmf_security::SecureLeg>>>,
    secure_slots: Vec<Slot>,
    /// Which legs each leg's packets are copied to (subscriptions).
    taps: crate::relay::taps::Taps,
    /// Per leg: copies sent (packets, octets).
    copied: PerSlot<[u64; 2]>,
    /// Per slot of a recorded call: the call and the slot's local address.
    record_to: PerSlot<Option<(CallId, SocketAddr)>>,
    /// Announcements being played.
    playbacks: Vec<Playback>,
    /// Per leg: its PCM stream, if it has one; the slots that have one.
    pcm_legs: PerSlot<Option<Box<pcm::PcmLeg>>>,
    pcm_slots: Vec<Slot>,
    /// `play DTMF` in progress.
    tone_plays: Vec<tones::TonePlayback>,
    /// Per slot: the stream announcements to it are sent in.
    play_streams: PerSlot<Option<features::PlayStream>>,
    /// What plays to each slot, holding back the other side's audio.
    hold: crate::relay::hold::Hold,
    /// Open recordings by call.
    recorders: HashMap<CallId, crate::recording::Recorder>,
    /// Per RTP slot: the payload type converted from and to (G.711).
    transcode: PerSlot<Option<super::transcode::Transcoder>>,
    /// Per RTP slot: the repacketiser of what the side sends (`ptime`),
    /// and the slots that have one.
    repack: PerSlot<Option<repack::RepackLeg>>,
    repack_slots: Vec<Slot>,
    /// `connect`: legs whose partner is not their own call's other party,
    /// those whose packets go to another worker, the channels other
    /// workers pass packets into (by this worker's call), and the workers
    /// to wake after a batch.
    connected: PerSlot<bool>,
    /// `unidirectional`: the side's call may be offloaded one way.
    oneway: PerSlot<bool>,
    /// `media echo`: RTP legs whose media goes back to them as it came.
    echoing: PerSlot<bool>,
    remote: PerSlot<Option<connect::RemoteLeg>>,
    /// `connect` with `directional`: where each leg's copies go on other
    /// workers (a list made when connected, never while relaying).
    remote_taps: PerSlot<Vec<listen::RemoteTap>>,
    /// Copies on this worker converted to the listener's codec: per source
    /// RTP slot, (listener's slot, its transcoder).
    copy_xcode: PerSlot<Vec<(Slot, Box<super::transcode::Transcoder>)>>,
    /// Channels from other workers: the call they feed, the RTP slot of a
    /// `connect`ed leg they serve (`None` for copies), and the channel.
    incoming: Vec<(CallId, Option<Slot>, std::sync::mpsc::Receiver<Forwarded>)>,
    wake_peers: Vec<Arc<EventFd>>,
    /// Per slot: what the peer's RTCP reports said, and the SRs it sent.
    rtcp: PerSlot<RtcpLeg>,
    /// Per RTP slot: what of the side's RTP is not relayed, or copied
    /// (the `features::BLOCK_*` bits).
    blocked: PerSlot<u8>,
    /// Per leg: its DTLS association, if the side uses DTLS-SRTP.
    dtls: PerSlot<Option<Box<DtlsLeg>>>,
    identity: Identity,
    sockets: PerSlot<Option<UdpSocket>>,
    calls: HashMap<CallId, CallSlots>,
    epoll: Epoll,
    wake: Arc<EventFd>,
    commands: Receiver<Command>,
    events: Sender<Event>,
    /// Key presses, announcements played out, DTLS and ICE progress, for
    /// the control thread's subscribers.
    media_events: crate::relay::media_events::MediaEvents,
    stats: Arc<Stats>,
    offload: Option<Sender<OffloadMsg>>,
    /// Where finished recordings go to be converted.
    jobs: Sender<crate::recording::Job>,
    /// The thread that writes recordings to disk.
    rec_writer: crate::recording::writer::Writer,
    /// Datagrams received through `AF_XDP` for this worker's ports.
    xsk: Option<Receiver<super::xsk::XskDatagram>>,
    /// `runtime.receive = "io_uring"`: the multishot receiver of this
    /// worker's sockets, each slot's generation (in its tokens) and the
    /// tokens to disarm once it is back from draining.
    uring: Option<rtpflux_uring::Receiver>,
    uring_gen: PerSlot<u32>,
    uring_disarm: Vec<u64>,
    batch: usize,
    packet_buffer: usize,
    bufs: Vec<u8>,
    recv_hdr: MultiHeaders<SockaddrStorage>,
    send_hdr: MultiHeaders<SockaddrStorage>,
    /// The destinations of a `sendmmsg` batch.
    send_addrs: Box<[Option<SockaddrStorage>]>,
    /// The DTLS client slots of a sweep, reused from one to the next.
    dtls_clients: Vec<Slot>,
    start: Instant,
}

fn to_std(a: &SockaddrStorage) -> Option<SocketAddr> {
    if let Some(v4) = a.as_sockaddr_in() {
        Some(SocketAddr::from(*v4))
    } else {
        a.as_sockaddr_in6().map(|v6| SocketAddr::from(*v6))
    }
}

impl Worker {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        index: usize,
        slots: usize,
        batch: usize,
        packet_buffer: usize,
        commands: Receiver<Command>,
        wake: Arc<EventFd>,
        (events, media_events): (Sender<Event>, crate::relay::media_events::MediaEvents),
        stats: Arc<Stats>,
        offload: Option<Sender<OffloadMsg>>,
        identity: Identity,
        (jobs, rec_writer): (
            Sender<crate::recording::Job>,
            crate::recording::writer::Writer,
        ),
        (xsk, uring_buffers): (Option<Receiver<super::xsk::XskDatagram>>, Option<u16>),
    ) -> Result<Self, nix::Error> {
        let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC)?;
        epoll.add(wake.as_fd(), EpollEvent::new(EpollFlags::EPOLLIN, WAKE))?;
        let uring = match uring_buffers.map(|n| uring::receiver(index, n, packet_buffer, &epoll)) {
            Some(Ok(r)) => {
                set_receive(&stats, "io_uring".to_owned());
                Some(r)
            }
            Some(Err(why)) => {
                set_receive(&stats, format!("recvmmsg (io_uring: {why})"));
                None
            }
            None => {
                set_receive(&stats, "recvmmsg".to_owned());
                None
            }
        };
        let batch = batch.clamp(1, MAX_BATCH);
        Ok(Worker {
            index,
            legs: PerSlot::filled(slots, None),
            crypto: PerSlot::with(slots, || None),
            ice: PerSlot::filled(slots, None),
            muxed: PerSlot::filled(slots, false),
            opaque: PerSlot::filled(slots, false),
            stun_out: [0; 1024],
            ice_agents: PerSlot::with(slots, || None),
            ice_slots: Vec::new(),
            ice_next: None,
            dtls: PerSlot::with(slots, || None),
            via: PerSlot::filled(slots, None),
            dtmf: PerSlot::with(slots, || None),
            xcode: PerSlot::with(slots, || None),
            secure: PerSlot::with(slots, || None),
            secure_slots: Vec::new(),
            taps: crate::relay::taps::Taps::new(slots),
            copied: PerSlot::filled(slots, [0; 2]),
            blocked: PerSlot::filled(slots, 0),
            rtcp: PerSlot::filled(slots, RtcpLeg::default()),
            transcode: PerSlot::with(slots, || None),
            repack: PerSlot::with(slots, || None),
            repack_slots: Vec::new(),
            connected: PerSlot::filled(slots, false),
            echoing: PerSlot::filled(slots, false),
            oneway: PerSlot::filled(slots, false),
            remote: PerSlot::with(slots, || None),
            remote_taps: PerSlot::with(slots, Vec::new),
            copy_xcode: PerSlot::with(slots, Vec::new),
            incoming: Vec::new(),
            wake_peers: Vec::new(),
            record_to: PerSlot::filled(slots, None),
            recorders: HashMap::new(),
            playbacks: Vec::new(),
            pcm_legs: PerSlot::with(slots, || None),
            pcm_slots: Vec::new(),
            tone_plays: Vec::new(),
            play_streams: PerSlot::filled(slots, None),
            hold: crate::relay::hold::Hold::new(slots),
            routes: PerSlot::with(slots, || None),
            identity,
            sockets: PerSlot::with(slots, || None),
            calls: HashMap::new(),
            epoll,
            wake,
            commands,
            events,
            media_events,
            stats,
            offload,
            jobs,
            rec_writer,
            xsk,
            uring,
            uring_gen: PerSlot::filled(slots, 0),
            uring_disarm: Vec::new(),
            batch,
            packet_buffer,
            // One more than the batch: copies to subscriptions.
            // The batch, a spare buffer for copies, and one for a copy
            // silenced (`silence media` of copies).
            bufs: vec![0; (batch + 2) * packet_buffer],
            recv_hdr: MultiHeaders::preallocate(batch, None),
            send_hdr: MultiHeaders::preallocate(batch, None),
            send_addrs: vec![None; MAX_BATCH].into_boxed_slice(),
            dtls_clients: Vec::new(),
            start: Instant::now(),
        })
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    pub(super) fn run(mut self) {
        let mut ready = [EpollEvent::empty(); 64];
        let mut last_sweep = 0;
        log::debug!("media worker {} started", self.index);
        loop {
            let due = [
                self.next_playback_ms(),
                self.next_pcm_ms(),
                self.next_tone_ms(),
                self.ice_next,
                self.next_repack_ms(),
                self.next_secure_ms(),
            ]
            .into_iter()
            .flatten()
            .min();
            let wait = due.map_or(100, |due| {
                u16::try_from(due.saturating_sub(self.now_ms()).clamp(1, 100)).unwrap_or(100)
            });
            let n = match self.epoll.wait(&mut ready, EpollTimeout::from(wait)) {
                Ok(n) => n,
                Err(Errno::EINTR) => 0,
                Err(e) => {
                    log::error!("media worker {}: epoll: {e}", self.index);
                    return;
                }
            };
            let now = self.now_ms();
            for ev in &ready[..n] {
                if ev.data() == WAKE {
                    let _ = self.wake.read();
                    if !self.apply_commands() {
                        log::debug!("media worker {} stopping", self.index);
                        // Recordings in progress are converted, and their
                        // pcaps kept for when the relay comes back.
                        for (_, r) in self.recorders.drain() {
                            r.finish(false);
                        }
                        return;
                    }
                } else if ev.data() == URING {
                    self.drain_uring(now);
                } else if let Ok(slot) = u32::try_from(ev.data()) {
                    self.drain(Slot::new(slot), now);
                }
            }
            // AF_XDP datagrams queued while the wake-up was being handled.
            self.drain_xsk(now);
            if !self.playbacks.is_empty() {
                self.play_due(self.now_ms());
            }
            if !self.pcm_slots.is_empty() {
                self.pcm_due(self.now_ms());
            }
            if !self.tone_plays.is_empty() {
                self.tones_due(self.now_ms());
            }
            if !self.repack_slots.is_empty() {
                self.repack_due(self.now_ms());
            }
            if !self.secure_slots.is_empty() {
                self.secure_due(self.now_ms());
            }
            if !self.incoming.is_empty() {
                self.drain_forwarded();
            }
            if self.ice_next.is_some_and(|t| t <= self.now_ms()) {
                self.ice_due(self.now_ms());
            }
            if now.saturating_sub(last_sweep) >= SWEEP_MS {
                self.sweep(now);
                last_sweep = now;
            }
        }
    }

    /// End calls whose RTP legs have both been silent for their timeout.
    fn sweep(&mut self, now: u64) {
        let mut finished = Vec::new();
        for (slot, d) in self.dtmf.slots_mut() {
            if let Some(d) = d {
                d.tick(now, slot);
                if d.unsent_any() {
                    finished.push((slot, d.take_unsent()));
                }
            }
        }
        for (slot, events) in finished {
            self.report_dtmf(slot, events);
        }
        let mut idle: [Option<CallId>; 64] = [None; 64];
        let mut n = 0;
        for (&call, c) in &self.calls {
            let a = self.legs.get(c.slots[0]).copied().flatten();
            let b = self.legs.get(c.slots[2]).copied().flatten();
            let ended = match c.answer_by {
                Some(t) => now >= t,
                None => {
                    matches!((a, b), (Some(a), Some(b)) if relay::idle(&a, &b, now, c.timeout_ms))
                }
            };
            if ended && n < idle.len() {
                idle[n] = Some(call);
                n += 1;
            }
        }
        for call in idle.into_iter().flatten() {
            self.close_call(call, true);
        }
        // Into the buffer kept from the last sweep: no allocation once it
        // has grown to the number of DTLS client legs.
        let mut dtls_clients = std::mem::take(&mut self.dtls_clients);
        dtls_clients.clear();
        dtls_clients.extend(
            self.dtls
                .slots()
                .filter(|(_, d)| d.as_ref().is_some_and(|l| l.side.role == Role::Client))
                .map(|(s, _)| s),
        );
        if !dtls_clients.is_empty() {
            self.start_dtls_clients(now, &dtls_clients);
        }
        self.dtls_clients = dtls_clients;
        if self.offload.is_some() {
            self.offer_settled(now);
        }
    }
}

/// Note how the worker receives (for the web UI).
fn set_receive(stats: &Stats, how: String) {
    *stats
        .receive
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = how;
}
