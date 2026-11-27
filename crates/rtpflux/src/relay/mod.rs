//! The userspace media relay.
//!
//! The port range is split into one contiguous shard per worker thread.
//! A call lives entirely in one shard: its four legs (RTP and RTCP on each
//! side) are sockets of that shard, owned by its worker, so a worker never
//! shares state with another and the hot path takes no locks.
//!
//! The control side ([`Relay`]) allocates port pairs, binds the sockets and
//! hands calls to workers over a bounded queue, waking them through an
//! eventfd. Workers report ended calls (timeouts) back so their ports can be
//! reused.

mod calls;
mod commands;
pub mod media_events;
mod offload;
pub mod repack;
mod transcode;
mod types;
use rtpflux_core::rtp::Pt;
mod worker;
mod xsk;

use crate::config::{Config, Interface, XdpMode};
use nix::sys::eventfd::{EfdFlags, EventFd};
use offload::{Offload, OffloadMsg};
pub use offload::{XdpDir, XdpFlow, XdpFlows};
pub use rtpflux_core::dtls::{Fingerprint, Role as DtlsRole};
use rtpflux_core::latch::{Latch, Learning};
use rtpflux_core::ports::PairAllocator;
pub use rtpflux_core::sdp::Codec;
pub use rtpflux_core::sdp::{MAX_FINGERPRINTS, MasterKey};
use rtpflux_xdp::loader::{AttachMode, FastPath};
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;
pub use types::{
    CallId, CallLeg, CallPorts, DtlsSide, DtmfEvent, DtmfXcode, Echo, ICE_PWD_LEN, ICE_UFRAG_LEN,
    IceCandidate, IceCreds, IceLegState, IcePeer, IceStart, Inbound, InterfaceId, LegStats,
    RelayError, Repack, RtcpStats, Side, Srtp, Stats, Totals, Transcode,
};
pub mod codecs;
pub mod dtmf_security;
pub mod hold;
pub mod play;
pub mod stream;
pub mod taps;
pub mod xcode;
pub use worker::{Blocked, Blocks, Playing, QueryReply, SILENCE, SINE, ToneMode, Tones};
use worker::{Command, Event, LegInit, Media, Worker};

/// `runtime.receive = "io_uring"`: each worker's provided buffers, as many
/// as the packet ring has slots (a power of two, at most 32768).
fn uring_buffers(config: &Config) -> Option<u16> {
    (config.runtime.receive == crate::config::Receive::IoUring)
        .then(|| u16::try_from(config.runtime.ring_capacity.min(32_768)).unwrap_or(u16::MAX))
}

/// Largest receive/send batch (`runtime.batch` is checked against it).
pub const MAX_BATCH: usize = 64;

/// A call as control sees it. Its ports return to the allocator only when
/// the worker reports that it has closed the sockets ([`Event::Closed`]), so
/// a new call never collides with sockets still open.
struct CallEntry {
    shard: usize,
    port_a: u16,
    port_b: u16,
    /// A delete was requested and the worker has not confirmed it yet.
    ending: bool,
}

struct Shard {
    alloc: PairAllocator,
    first_port: u16,
    commands: SyncSender<Command>,
    wake: Arc<EventFd>,
    stats: Arc<Stats>,
    thread: Option<JoinHandle<()>>,
}

/// The relay: its workers and the control-side bookkeeping.
pub struct Relay {
    shards: Vec<Shard>,
    interfaces: Vec<Interface>,
    events: Receiver<Event>,
    /// The queue of media events, until the control side takes it.
    media_events: Option<media_events::MediaEventInbox>,
    /// The sending end of the same queue (for threads the relay starts later).
    media_sender: media_events::MediaEvents,
    calls: HashMap<CallId, CallEntry>,
    next_id: CallId,
    next_shard: usize,
    timeout_ms: u64,
    /// The media timeout of calls on hold (`sessions.silent_timeout`).
    silent_timeout_ms: u64,
    /// Relay calls that ended on their own (timeouts), not yet taken.
    ended: Vec<CallId>,
    /// Deletes a full worker queue refused, to send again.
    unsent_deletes: Vec<CallId>,
    offload: Option<(Sender<OffloadMsg>, JoinHandle<()>)>,
    identity: crate::dtls::Identity,
    /// The recording conversion thread and its queue.
    converter: Option<(Sender<crate::recording::Job>, JoinHandle<()>)>,
    /// What became of finished recordings (counters, recent uploads).
    recording_activity: Arc<crate::recording::activity::Activity>,
    /// The calls the XDP program relays (for the web UI).
    xdp_flows: XdpFlows,
    /// The thread that writes recordings to disk.
    rec_writer: Option<(crate::recording::writer::Writer, JoinHandle<()>)>,
    /// The `AF_XDP` receive threads.
    xsk: Option<xsk::Receivers>,
}

/// Load the XDP program and attach it to every configured device.
fn load_xdp(config: &Config) -> Result<FastPath, RelayError> {
    let object = std::fs::read(&config.xdp.object)?;
    let mut fp = FastPath::load(&object).map_err(RelayError::Xdp)?;
    let mode = match config.xdp.mode {
        XdpMode::Native => AttachMode::Native,
        XdpMode::Generic => AttachMode::Generic,
    };
    for device in &config.xdp.devices {
        fp.attach(device, mode).map_err(RelayError::Xdp)?;
        log::info!("xdp: attached to {device} ({mode:?})");
    }
    Ok(fp)
}

/// Start the thread that converts finished recordings and stores them.
fn start_converter(
    config: &Config,
    activity: &Arc<crate::recording::activity::Activity>,
    events: media_events::MediaEvents,
) -> Result<(Sender<crate::recording::Job>, JoinHandle<()>), RelayError> {
    let store = crate::recording::store::Store::from_config(
        config.recording.storage,
        &config.recording.s3,
        config.recording.dir.as_deref(),
        activity,
    )
    .map_err(RelayError::Recording)?;
    let resumable = config.sessions.persistent();
    Ok(crate::recording::convert::spawn(
        store,
        resumable,
        Arc::clone(activity),
        Some(events),
    )?)
}

/// Start the XDP offload controller's thread.
/// The offload controller's queue and thread, when there is a fast path,
/// and the calls it relays (empty without one).
type OffloadParts = (Option<(Sender<OffloadMsg>, JoinHandle<()>)>, XdpFlows);

fn spawn_offload(
    config: &Config,
    xdp: Option<offload::FastPathParts>,
    (tx, rx): (Sender<OffloadMsg>, Receiver<OffloadMsg>),
    shards: &[Shard],
) -> std::io::Result<OffloadParts> {
    let flows = XdpFlows::default();
    let Some((fp, net)) = xdp else {
        return Ok((None, flows));
    };
    let controller = Offload {
        fp,
        net,
        devices: config.xdp.devices.clone(),
        rx,
        flows: Arc::clone(&flows),
        shards: shards
            .iter()
            .map(|s| (s.commands.clone(), Arc::clone(&s.wake)))
            .collect(),
    };
    let thread = std::thread::Builder::new()
        .name("rtpflux-xdp".to_owned())
        .spawn(move || crate::essential("the XDP controller", || controller.run()))?;
    Ok((Some((tx, thread)), flows))
}

/// Open an `AF_XDP` socket on every receive queue of the first XDP device,
/// register them with the program, and steer the relay's ports on that
/// device's interface addresses to them.
#[cfg(feature = "af-xdp")]
fn open_xsk(
    config: &Config,
    fp: &mut FastPath,
) -> Result<Vec<Box<dyn xsk::FrameSource>>, RelayError> {
    use rtpflux_xdp::neigh;
    use rtpflux_xdp::xsk::XskReceiver;
    let device =
        config
            .xdp
            .devices
            .first()
            .ok_or(RelayError::Xdp(rtpflux_xdp::loader::Error::Missing(
                "an XDP device",
            )))?;
    let ifindex = neigh::ifindex(device).ok_or_else(|| {
        RelayError::Io(std::io::Error::other(format!("af_xdp: no device {device}")))
    })?;
    let queues = neigh::rx_queues(device).min(rtpflux_xdp_common::XSK_QUEUES);
    let mut sources: Vec<Box<dyn xsk::FrameSource>> = Vec::new();
    for q in 0..queues {
        let r = XskReceiver::open(ifindex, q, config.xdp.af_xdp_frames)?;
        fp.set_socket(q, std::os::fd::AsRawFd::as_raw_fd(&r))
            .map_err(RelayError::Xdp)?;
        sources.push(Box::new(r));
    }
    let range = rtpflux_xdp_common::SteerRange {
        min_port: config.ports.min,
        max_port: config.ports.max,
        ifindex,
    };
    let mut steered = 0;
    for i in &config.interfaces {
        if neigh::device_of(i.address).as_deref() == Some(device.as_str()) {
            let addr = match i.address {
                IpAddr::V4(a) => rtpflux_xdp_common::mapped(a.octets()),
                IpAddr::V6(a) => a.octets(),
            };
            fp.steer(addr, range).map_err(RelayError::Xdp)?;
            steered += 1;
        }
    }
    if steered == 0 {
        log::warn!("af_xdp: no interface address is on {device}; nothing is steered");
    }
    log::info!("af_xdp: {queues} receive queue(s) on {device}, {steered} address(es) steered");
    Ok(sources)
}

/// Without the `af-xdp` feature, configuration validation refuses
/// `[xdp] af_xdp`: there is nothing to open.
#[cfg(not(feature = "af-xdp"))]
#[allow(clippy::unnecessary_wraps)]
fn open_xsk(
    _config: &Config,
    _fp: &mut FastPath,
) -> Result<Vec<Box<dyn xsk::FrameSource>>, RelayError> {
    Ok(Vec::new())
}

/// Worker `k`'s first port and its pairs. The configuration was
/// validated; a range that still does not split is an error, not a panic.
fn shard_ports(
    config: &Config,
    per_shard: usize,
    k: usize,
) -> Result<(u16, PairAllocator), RelayError> {
    let first_port = u16::try_from(2 * per_shard * k)
        .ok()
        .and_then(|o| config.ports.min.checked_add(o))
        .ok_or(RelayError::PortRange)?;
    let alloc = PairAllocator::new(first_port, per_shard).map_err(|_| RelayError::PortRange)?;
    Ok((first_port, alloc))
}

impl Relay {
    /// Start one worker per shard. Buffers, tables and queues are allocated
    /// here, once.
    ///
    /// # Errors
    ///
    /// [`RelayError`] when a worker's epoll or eventfd cannot be created, or
    /// (with `[xdp] enabled`) the XDP program cannot be loaded or attached.
    ///
    /// # Panics
    ///
    /// If the configuration was not validated ([`Config::validate`]).
    pub fn start(config: &Config) -> Result<Self, RelayError> {
        let mut sources = Vec::new();
        let xdp: Option<offload::FastPathParts> = if config.xdp.enabled {
            let mut fp = load_xdp(config)?;
            if config.xdp.af_xdp {
                sources = open_xsk(config, &mut fp)?;
            }
            Some((Box::new(fp), Box::new(offload::Host)))
        } else {
            None
        };
        Self::start_with(config, xdp, sources)
    }

    /// [`Relay::start`] with the XDP flow table (and the network it
    /// serves) given: the kernel's, or a test's.
    fn start_with(
        config: &Config,
        xdp: Option<offload::FastPathParts>,
        sources: Vec<Box<dyn xsk::FrameSource>>,
    ) -> Result<Self, RelayError> {
        let workers = match config.runtime.workers {
            0 => std::thread::available_parallelism().map_or(1, std::num::NonZero::get),
            n => n,
        };
        let pairs = config.ports.pairs();
        let workers = workers.clamp(1, pairs / 2);
        let per_shard = pairs / workers;
        let (event_tx, events) = std::sync::mpsc::channel();
        let (media_tx, media_rx) = media_events::channel()?;
        let (offload_tx, offload_rx) = std::sync::mpsc::channel();
        let identity = crate::dtls::Identity::generate().map_err(RelayError::Dtls)?;
        let recording_activity = Arc::new(crate::recording::activity::Activity::default());
        let (jobs, converter) = start_converter(config, &recording_activity, media_tx.clone())?;
        let (rec_writer, writer_thread) = crate::recording::writer::spawn()?;
        // Stopped again if a later step fails (no worker left blocked).
        let mut shards = StartedShards(Vec::with_capacity(workers));
        let mut inboxes = Vec::with_capacity(workers);
        for k in 0..workers {
            let (first_port, alloc) = shard_ports(config, per_shard, k)?;
            let (commands, rx) = sync_channel(config.runtime.ring_capacity);
            let wake = Arc::new(EventFd::from_flags(
                EfdFlags::EFD_NONBLOCK | EfdFlags::EFD_CLOEXEC,
            )?);
            let stats = Arc::new(Stats::default());
            // The worker is built on its own thread: its preallocated
            // message headers hold raw pointers and are not `Send`.
            let (ready_tx, ready_rx) = sync_channel(1);
            let (wake_w, stats_w) = (Arc::clone(&wake), Arc::clone(&stats));
            let events_w = (event_tx.clone(), media_tx.clone());
            let offload_w = xdp.is_some().then(|| offload_tx.clone());
            let (batch, buffer) = (config.runtime.batch, config.runtime.packet_buffer);
            let uring = uring_buffers(config);
            let identity_w = identity.clone();
            let jobs_w = (jobs.clone(), rec_writer.clone());
            let xsk_w = if sources.is_empty() {
                None
            } else {
                let (tx, rx) = sync_channel(xsk::INBOX);
                inboxes.push((tx, Arc::clone(&wake), Arc::clone(&stats)));
                Some(rx)
            };
            let thread = std::thread::Builder::new()
                .name(format!("rtpflux-media-{k}"))
                .spawn(move || {
                    match Worker::new(
                        k,
                        2 * per_shard,
                        batch,
                        buffer,
                        rx,
                        wake_w,
                        events_w,
                        stats_w,
                        offload_w,
                        identity_w,
                        jobs_w,
                        (xsk_w, uring),
                    ) {
                        Ok(worker) => {
                            let _ = ready_tx.send(Ok(()));
                            crate::essential("a media worker", || worker.run());
                        }
                        Err(e) => {
                            let _ = ready_tx.send(Err(e));
                        }
                    }
                })?;
            ready_rx.recv().unwrap_or(Err(nix::Error::EIO))?;
            shards.0.push(Shard {
                alloc,
                first_port,
                commands,
                wake,
                stats,
                thread: Some(thread),
            });
        }
        log::info!("relay: {workers} worker(s), {per_shard} port pairs each");
        let ports_each = u16::try_from(2 * per_shard).map_err(|_| RelayError::PortRange)?;
        let xsk = xsk::Receivers::start(sources, config.ports.min, ports_each, inboxes)?;
        let (offload, xdp_flows) = spawn_offload(config, xdp, (offload_tx, offload_rx), &shards.0)?;
        Ok(Relay {
            shards: std::mem::take(&mut shards.0),
            interfaces: config.interfaces.clone(),
            events,
            media_events: Some(media_rx),
            media_sender: media_tx,
            calls: HashMap::new(),
            next_id: CallId::FIRST,
            next_shard: 0,
            timeout_ms: config.sessions.timeout.saturating_mul(1000),
            silent_timeout_ms: config.sessions.silent_timeout.saturating_mul(1000),
            ended: Vec::new(),
            unsent_deletes: Vec::new(),
            offload,
            identity,
            converter: Some((jobs, converter)),
            recording_activity,
            xdp_flows,
            rec_writer: Some((rec_writer, writer_thread)),
            xsk,
        })
    }

    /// Free the ports of calls whose sockets the workers have closed.
    fn reap(&mut self) {
        if !self.unsent_deletes.is_empty() {
            self.retry_deletes();
        }
        while let Ok(Event::Closed { call, timed_out }) = self.events.try_recv() {
            if let Some(c) = self.calls.remove(&call) {
                let alloc = &mut self.shards[c.shard].alloc;
                alloc.free(c.port_a);
                alloc.free(c.port_b);
                if timed_out {
                    log::info!("call {call} ended: timed out");
                    self.ended.push(call);
                }
            }
        }
    }

    /// The `a=fingerprint` value of the relay's DTLS certificate.
    #[must_use]
    pub fn dtls_fingerprint(&self) -> &str {
        self.identity.fingerprint()
    }

    /// The same under `hash` (`DTLS-fingerprint`).
    #[must_use]
    pub fn dtls_fingerprint_with(&self, hash: rtpflux_core::dtls::HashFn) -> &str {
        self.identity.fingerprint_with(hash)
    }

    /// Each worker's counters (for metrics).
    #[must_use]
    pub fn worker_stats(&self) -> Vec<Arc<Stats>> {
        self.shards.iter().map(|s| Arc::clone(&s.stats)).collect()
    }

    /// The calls the XDP program relays, as of its last poll (for the web
    /// UI).
    #[must_use]
    pub fn xdp_flows(&self) -> XdpFlows {
        Arc::clone(&self.xdp_flows)
    }

    /// What became of finished recordings (for metrics and the web UI).
    #[must_use]
    pub fn recording_activity(&self) -> Arc<crate::recording::activity::Activity> {
        Arc::clone(&self.recording_activity)
    }
}

/// Stop the workers of `shards` and wait for them.
fn stop_shards(shards: &mut [Shard]) {
    for s in shards.iter() {
        let _ = s.commands.send(Command::Shutdown);
        let _ = s.wake.write(1);
    }
    for s in shards {
        if let Some(t) = s.thread.take() {
            let _ = t.join();
        }
    }
}

/// The workers started so far while the relay starts: stopped if it fails.
struct StartedShards(Vec<Shard>);

impl Drop for StartedShards {
    fn drop(&mut self) {
        stop_shards(&mut self.0);
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        // The receive threads first: nothing more is queued for the workers.
        drop(self.xsk.take());
        // Then the XDP controller, while the workers still run: its last
        // read of the recording ring reaches them. Dropping it detaches
        // the program (the workers' sockets get the traffic back).
        if let Some((tx, thread)) = self.offload.take() {
            let _ = tx.send(OffloadMsg::Shutdown);
            let _ = thread.join();
        }
        stop_shards(&mut self.shards);
        // After the workers too: the recordings they ended are written,
        // then converted, before the relay is gone.
        if let Some((writer, thread)) = self.rec_writer.take() {
            drop(writer);
            let _ = thread.join();
        }
        if let Some((jobs, thread)) = self.converter.take() {
            drop(jobs);
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests;
