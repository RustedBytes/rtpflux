//! The XDP offload controller: one thread that owns the loaded program.
//!
//! Workers ask it to move a call's two RTP directions into the kernel once
//! their destinations are settled. It resolves the device and MAC addresses,
//! installs the flows, and every second reads their counters: packets the
//! kernel relayed never reach the worker, so it is told the call is active
//! (`Command::Touch`, with the packets and octets relayed since the last
//! poll) and its idle timeout does not fire. A packet from a
//! source the kernel does not know misses and still reaches the worker.
//!
//! A recorded call stays in the kernel too: its flows copy each datagram
//! into the recording ring, which this thread reads every 10 ms while such
//! a call is installed, sending the owning worker the packets as pcap
//! records (`Command::Recorded`) in one batch per call.
//!
//! Scope: IPv4 or IPv6, one family per call. A direction whose two relay
//! addresses sit on the same device leaves with `XDP_TX`; one that crosses
//! to another device is redirected there (`XDP_REDIRECT`), which needs the
//! program attached to the arrival device and a sending device whose
//! driver accepts redirected frames (native XDP drivers, or both in
//! generic mode). Anything else stays in userspace.

use super::CallId;
use super::worker::Command;
use nix::sys::eventfd::EventFd;
use rtpflux_xdp::loader::FastPath;
use rtpflux_xdp::{Direction, entry, neigh};
use rtpflux_xdp_common::{FlowAction, FlowKey, FlowStats, flags, headers_len, parse_record};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// One relayed direction: packets from `peer` to the relay's `local` port
/// leave from `out_local` towards `target`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Dir {
    pub peer: SocketAddr,
    pub local: SocketAddr,
    pub out_local: SocketAddr,
    pub target: SocketAddr,
    /// What the kernel does besides relaying (`rtpflux_xdp_common::flags`)
    /// and the telephone-event payload type it refers to.
    pub flags: u8,
    pub event_pt: u8,
}

pub(super) enum OffloadMsg {
    Install {
        call: CallId,
        shard: usize,
        dirs: Box<[Dir; 2]>,
    },
    /// New flows for an installed call (its flags changed).
    Update {
        call: CallId,
        dirs: Box<[Dir; 2]>,
    },
    Remove {
        call: CallId,
    },
    Shutdown,
}

/// Where one direction leaves for: the sending device, the target, and
/// the next hop's MAC the flow was installed with.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Hop {
    device: String,
    target: IpAddr,
    mac: [u8; 6],
}

/// A call the XDP program relays, as the web UI shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdpFlow {
    pub call: CallId,
    /// The worker that owns it.
    pub worker: usize,
    /// From side A, from side B.
    pub dirs: [XdpDir; 2],
}

/// One direction of an offloaded call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdpDir {
    /// The peer it comes from, and where it is sent.
    pub from: SocketAddr,
    pub to: SocketAddr,
    /// The device it leaves by.
    pub device: String,
    /// Dropped in the kernel (a blocked side), telephone events sent up to
    /// userspace, copied to the recording ring.
    pub drops: bool,
    pub events_up: bool,
    pub records: bool,
    /// Packets and UDP payload octets relayed, as of the last poll.
    pub packets: u64,
    pub octets: u64,
}

/// The offloaded calls, as of the controller's last poll (once a second).
pub type XdpFlows = Arc<std::sync::Mutex<Vec<XdpFlow>>>;

struct Installed {
    shard: usize,
    keys: [FlowKey; 2],
    /// The directions as installed (to install again when a next hop's
    /// MAC changes) and their next hops.
    dirs: Box<[Dir; 2]>,
    hops: [Hop; 2],
    /// Packets and UDP payload octets per direction (from A, from B), as
    /// last reported.
    packets: [u64; 2],
    octets: [u64; 2],
    /// Its flows copy their datagrams to the recording ring.
    records: bool,
}

/// A flow table operation that failed: which, and why (the map's own
/// error, kept as the source).
#[derive(Debug)]
pub(super) struct FlowError {
    op: &'static str,
    source: Box<dyn std::error::Error + Send + Sync>,
}

impl FlowError {
    fn new(op: &'static str, source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        FlowError {
            op,
            source: source.into(),
        }
    }
}

impl std::fmt::Display for FlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} a flow: {}", self.op, self.source)
    }
}

impl std::error::Error for FlowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.source)
    }
}

/// Why a call's flows cannot go into the kernel (it stays in userspace).
#[derive(Debug)]
pub(super) enum InstallError {
    /// No local device holds the relay's address.
    NoDevice(IpAddr),
    /// The XDP program is not attached to the device.
    NotAttached(String),
    /// The sending device has no interface index.
    NoIfIndex(String),
    /// The sending device has no MAC address.
    NoMac(String),
    /// The next hop's MAC address is not known yet.
    Unresolved(IpAddr),
    /// The two ends are of different address families.
    FamilyChanges,
    /// The kernel's flow table refused it.
    Table(FlowError),
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallError::NoDevice(a) => write!(f, "no device holds {a}"),
            InstallError::NotAttached(d) => write!(f, "XDP is not attached to {d}"),
            InstallError::NoIfIndex(d) => write!(f, "no interface index for {d}"),
            InstallError::NoMac(d) => write!(f, "no MAC for {d}"),
            InstallError::Unresolved(a) => write!(f, "next hop towards {a} not resolved"),
            InstallError::FamilyChanges => f.write_str("the address family changes"),
            InstallError::Table(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for InstallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            InstallError::Table(e) => Some(e),
            _ => None,
        }
    }
}

/// The kernel's flow table as the controller uses it.
pub(super) trait FlowTable {
    fn insert(&mut self, key: FlowKey, action: FlowAction) -> Result<(), FlowError>;
    fn remove(&mut self, key: FlowKey) -> Result<(), FlowError>;
    /// The flow's counters; `None` for an unknown flow.
    fn stats(&mut self, key: FlowKey) -> Result<Option<FlowStats>, FlowError>;
    /// Hand each recorded datagram in the ring to `f` (the bytes of a
    /// `RecordSample`); returns how many.
    fn drain_records(&mut self, f: &mut dyn FnMut(&[u8])) -> usize;
}

impl FlowTable for FastPath {
    fn insert(&mut self, key: FlowKey, action: FlowAction) -> Result<(), FlowError> {
        FastPath::insert(self, key, action).map_err(|e| FlowError::new("inserting", e))
    }

    fn remove(&mut self, key: FlowKey) -> Result<(), FlowError> {
        FastPath::remove(self, key).map_err(|e| FlowError::new("removing", e))
    }

    fn stats(&mut self, key: FlowKey) -> Result<Option<FlowStats>, FlowError> {
        FastPath::stats(self, key).map_err(|e| FlowError::new("reading", e))
    }

    fn drain_records(&mut self, f: &mut dyn FnMut(&[u8])) -> usize {
        FastPath::drain_records(self, f)
    }
}

impl<T: FlowTable + ?Sized> FlowTable for Box<T> {
    fn insert(&mut self, key: FlowKey, action: FlowAction) -> Result<(), FlowError> {
        (**self).insert(key, action)
    }

    fn remove(&mut self, key: FlowKey) -> Result<(), FlowError> {
        (**self).remove(key)
    }

    fn stats(&mut self, key: FlowKey) -> Result<Option<FlowStats>, FlowError> {
        (**self).stats(key)
    }

    fn drain_records(&mut self, f: &mut dyn FnMut(&[u8])) -> usize {
        (**self).drain_records(f)
    }
}

/// Where the relay's addresses live: devices, their MACs, next hops.
pub(super) trait Network {
    fn device_of(&self, ip: IpAddr) -> Option<String>;
    fn ifindex(&self, device: &str) -> Option<u32>;
    fn device_mac(&self, device: &str) -> Option<[u8; 6]>;
    fn next_hop_mac(&self, device: &str, dst: IpAddr) -> Option<[u8; 6]>;
    /// [`Network::next_hop_mac`] of many at once (the tables read once).
    fn next_hop_macs(&self, wants: &[(&str, IpAddr)]) -> Vec<Option<[u8; 6]>> {
        wants
            .iter()
            .map(|(d, ip)| self.next_hop_mac(d, *ip))
            .collect()
    }
}

impl<N: Network + ?Sized> Network for Box<N> {
    fn device_of(&self, ip: IpAddr) -> Option<String> {
        (**self).device_of(ip)
    }

    fn ifindex(&self, device: &str) -> Option<u32> {
        (**self).ifindex(device)
    }

    fn device_mac(&self, device: &str) -> Option<[u8; 6]> {
        (**self).device_mac(device)
    }

    fn next_hop_mac(&self, device: &str, dst: IpAddr) -> Option<[u8; 6]> {
        (**self).next_hop_mac(device, dst)
    }

    fn next_hop_macs(&self, wants: &[(&str, IpAddr)]) -> Vec<Option<[u8; 6]>> {
        (**self).next_hop_macs(wants)
    }
}

/// A flow table and the network it serves, for the offload thread.
pub(super) type FastPathParts = (Box<dyn FlowTable + Send>, Box<dyn Network + Send>);

/// The host's own tables ([`neigh`]).
pub(super) struct Host;

impl Network for Host {
    fn device_of(&self, ip: IpAddr) -> Option<String> {
        neigh::device_of(ip)
    }

    fn ifindex(&self, device: &str) -> Option<u32> {
        neigh::ifindex(device)
    }

    fn device_mac(&self, device: &str) -> Option<[u8; 6]> {
        neigh::device_mac(device)
    }

    fn next_hop_mac(&self, device: &str, dst: IpAddr) -> Option<[u8; 6]> {
        neigh::next_hop_mac(device, dst)
    }

    fn next_hop_macs(&self, wants: &[(&str, IpAddr)]) -> Vec<Option<[u8; 6]>> {
        let tables = neigh::Tables::read();
        wants
            .iter()
            .map(|(d, ip)| tables.next_hop_mac(d, *ip))
            .collect()
    }
}

pub(super) struct Offload<T: FlowTable, N: Network> {
    pub fp: T,
    pub net: N,
    pub devices: Vec<String>,
    pub rx: Receiver<OffloadMsg>,
    pub shards: Vec<(SyncSender<Command>, Arc<EventFd>)>,
    /// What is installed, for the web UI.
    pub flows: XdpFlows,
}

/// Whether a call's flows copy their datagrams to the recording ring.
fn records(dirs: &[Dir; 2]) -> bool {
    dirs.iter().any(|d| d.flags & flags::RECORD != 0)
}

/// How often the counters are read.
const POLL: Duration = Duration::from_secs(1);
/// How often the next hops' MACs are checked: the kernel's flows never
/// pass the stack, so a changed gateway or peer MAC (a failover, a moved
/// address) would otherwise blackhole them until the call ends.
const MAC_REFRESH: Duration = Duration::from_secs(30);
/// How often the recording ring is read while a recorded call is in the
/// kernel. The ring (4 MiB, 1,552-octet records) holds about 2,700
/// datagrams: some 270,000 per second at this pace.
const RECORD_POLL: Duration = Duration::from_millis(10);

/// The address of a flow key's half (an IPv4-mapped address is IPv4).
fn socket_addr(addr: &[u8; 16], port_be: u16) -> SocketAddr {
    let port = u16::from_be(port_be);
    match rtpflux_xdp_common::unmapped(addr) {
        Some(v4) => SocketAddr::new(IpAddr::V4(Ipv4Addr::from(v4)), port),
        None => SocketAddr::new(IpAddr::V6(Ipv6Addr::from(*addr)), port),
    }
}

/// Wall-clock time minus `CLOCK_MONOTONIC` (the kernel's sample clock),
/// in nanoseconds.
fn wall_offset_ns() -> i128 {
    let mono = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC).map_or(0, |t| {
        i128::from(t.tv_sec()) * 1_000_000_000 + i128::from(t.tv_nsec())
    });
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i128::try_from(d.as_nanos()).unwrap_or(0));
    wall - mono
}

/// The wall-clock time of a kernel sample taken at `mono_ns`.
fn wall_time(mono_ns: u64, offset_ns: i128) -> SystemTime {
    let ns = u64::try_from(i128::from(mono_ns) + offset_ns).unwrap_or(0);
    UNIX_EPOCH + Duration::from_nanos(ns)
}

impl<T: FlowTable, N: Network> Offload<T, N> {
    pub(super) fn run(mut self) {
        let mut installed: HashMap<CallId, Installed> = HashMap::new();
        // Which call each installed flow belongs to (for recorded samples).
        let mut owners: HashMap<FlowKey, CallId> = HashMap::new();
        let mut last_poll = Instant::now();
        let mut last_refresh = Instant::now();
        let mut recording = false;
        loop {
            let wait = if recording { RECORD_POLL } else { POLL };
            match self.rx.recv_timeout(wait) {
                Ok(OffloadMsg::Install { call, shard, dirs }) => {
                    let ok = match self.install(&dirs) {
                        Ok((keys, hops)) => {
                            for k in keys {
                                owners.insert(k, call);
                            }
                            installed.insert(
                                call,
                                Installed {
                                    shard,
                                    keys,
                                    packets: [0; 2],
                                    octets: [0; 2],
                                    records: records(&dirs),
                                    dirs,
                                    hops,
                                },
                            );
                            log::debug!("call {call}: both RTP directions moved to XDP");
                            true
                        }
                        Err(why) => {
                            log::debug!("call {call}: not offloaded: {why}");
                            false
                        }
                    };
                    // Lost (a full queue): the worker takes the call back
                    // after a while and offers it again.
                    let _ = self.notify(shard, Command::Offloaded { call, ok });
                }
                Ok(OffloadMsg::Update { call, dirs }) => {
                    self.update(call, dirs, &mut installed, &mut owners);
                }
                Ok(OffloadMsg::Remove { call }) => {
                    // The call's last recorded packets still in the ring
                    // first (they are dropped once it is not an owner).
                    if installed.get(&call).is_some_and(|i| i.records) {
                        self.drain(&installed, &owners);
                    }
                    if let Some(i) = installed.remove(&call) {
                        for k in i.keys {
                            owners.remove(&k);
                            if let Err(e) = self.fp.remove(k) {
                                log::warn!("call {call}: removing an XDP flow: {e}");
                            }
                        }
                    }
                }
                Ok(OffloadMsg::Shutdown) | Err(RecvTimeoutError::Disconnected) => {
                    self.drain(&installed, &owners);
                    return;
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
            recording = installed.values().any(|i| i.records);
            // Read the ring even when no recorded call is left: samples of
            // one that just stopped may still be there.
            self.drain(&installed, &owners);
            if last_poll.elapsed() >= POLL {
                last_poll = Instant::now();
                self.poll(&mut installed);
                self.publish(&installed);
            }
            if last_refresh.elapsed() >= MAC_REFRESH {
                last_refresh = Instant::now();
                self.refresh_macs(&mut installed);
            }
        }
    }

    /// New flows for installed call `call` (its flags changed), or, when
    /// they cannot be installed, the call back to its worker.
    fn update(
        &mut self,
        call: CallId,
        dirs: Box<[Dir; 2]>,
        installed: &mut HashMap<CallId, Installed>,
        owners: &mut HashMap<FlowKey, CallId>,
    ) {
        let Some(shard) = installed.get(&call).map(|i| i.shard) else {
            return;
        };
        match self.install(&dirs) {
            Ok((keys, hops)) => {
                if let Some(i) = installed.get_mut(&call) {
                    for old in i.keys {
                        if !keys.contains(&old) {
                            if let Err(e) = self.fp.remove(old) {
                                log::warn!("call {call}: {e}");
                            }
                            owners.remove(&old);
                        }
                    }
                    for k in keys {
                        owners.insert(k, call);
                    }
                    if i.keys != keys {
                        i.keys = keys;
                        i.packets = [0; 2];
                        i.octets = [0; 2];
                    }
                    i.records = records(&dirs);
                    i.dirs = dirs;
                    i.hops = hops;
                }
                log::debug!("call {call}: XDP flows updated");
            }
            Err(why) => {
                // It cannot stay in the kernel: back to the worker.
                if let Some(i) = installed.remove(&call) {
                    for k in i.keys {
                        if let Err(e) = self.fp.remove(k) {
                            log::warn!("call {call}: {e}");
                        }
                        owners.remove(&k);
                    }
                }
                log::debug!("call {call}: back to userspace: {why}");
                let _ = self.notify(shard, Command::Offloaded { call, ok: false });
            }
        }
    }

    /// Send the recorded samples waiting in the ring to the workers of
    /// their calls, as pcap records, one batch per call. Samples of flows
    /// no longer installed are dropped.
    fn drain(&mut self, installed: &HashMap<CallId, Installed>, owners: &HashMap<FlowKey, CallId>) {
        let offset = wall_offset_ns();
        let mut batches: HashMap<CallId, Vec<u8>> = HashMap::new();
        self.fp.drain_records(&mut |bytes| {
            let Some((key, t, payload)) = parse_record(bytes) else {
                return;
            };
            let Some(&call) = owners.get(&key) else {
                return;
            };
            crate::recording::frame(
                batches.entry(call).or_default(),
                socket_addr(&key.src_addr, key.src_port),
                socket_addr(&key.dst_addr, key.dst_port),
                payload,
                wall_time(t, offset),
            );
        });
        for (call, frames) in batches {
            if let Some(i) = installed.get(&call)
                && !self.notify(i.shard, Command::Recorded { call, frames })
            {
                log::debug!("call {call}: kernel-recorded packets lost (worker busy)");
            }
        }
    }

    /// Queue `cmd` for a worker; `false` when its queue is full.
    fn notify(&self, shard: usize, cmd: Command) -> bool {
        if let Some((tx, wake)) = self.shards.get(shard)
            && tx.try_send(cmd).is_ok()
        {
            let _ = wake.write(1);
            return true;
        }
        false
    }

    /// Tell the owning workers about calls the kernel relayed packets for.
    /// The new packets and octets go with it, so the call's counters
    /// (`query`) include what the kernel relayed.
    /// A report that cannot be queued (the worker's queue is full) is not
    /// lost: the next poll reports from where the last delivered one left.
    fn poll(&mut self, installed: &mut HashMap<CallId, Installed>) {
        let mut touched = Vec::new();
        for (&call, i) in installed.iter() {
            let (mut now_p, mut now_b) = (i.packets, i.octets);
            for (d, k) in i.keys.into_iter().enumerate() {
                // What a counted frame has beyond its UDP payload: Ethernet,
                // IP (no options or extension headers) and UDP headers.
                let overhead = headers_len(&k) as u64;
                if let Ok(Some(s)) = self.fp.stats(k) {
                    now_p[d] = now_p[d].max(s.packets);
                    now_b[d] = now_b[d].max(s.bytes.saturating_sub(s.packets * overhead));
                }
            }
            if now_p != i.packets {
                touched.push((i.shard, call, now_p, now_b));
            }
        }
        for (shard, call, now_p, now_b) in touched {
            let Some(i) = installed.get_mut(&call) else {
                continue;
            };
            let packets = [0, 1].map(|d| now_p[d].saturating_sub(i.packets[d]));
            let octets = [0, 1].map(|d| now_b[d].saturating_sub(i.octets[d]));
            let cmd = Command::Touch {
                call,
                packets,
                octets,
            };
            if self.notify(shard, cmd) {
                i.packets = now_p;
                i.octets = now_b;
            }
        }
    }

    /// Publish what is installed (once a second; for the web UI).
    fn publish(&self, installed: &HashMap<CallId, Installed>) {
        let mut v: Vec<XdpFlow> = installed
            .iter()
            .map(|(&call, i)| XdpFlow {
                call,
                worker: i.shard,
                dirs: [0, 1].map(|d| {
                    let dir = &i.dirs[d];
                    XdpDir {
                        from: dir.peer,
                        to: dir.target,
                        device: i.hops[d].device.clone(),
                        drops: dir.flags & flags::DROP != 0,
                        events_up: dir.flags & flags::EVENTS_UP != 0,
                        records: dir.flags & flags::RECORD != 0,
                        packets: i.packets[d],
                        octets: i.octets[d],
                    }
                }),
            })
            .collect();
        v.sort_by_key(|f| f.call);
        *self
            .flows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = v;
    }

    /// Install both directions, or neither.
    fn install(&mut self, dirs: &[Dir; 2]) -> Result<([FlowKey; 2], [Hop; 2]), InstallError> {
        let mut entries = Vec::with_capacity(2);
        let mut hops = Vec::with_capacity(2);
        for d in dirs {
            let device = self
                .net
                .device_of(d.local.ip())
                .ok_or(InstallError::NoDevice(d.local.ip()))?;
            let out_device = self
                .net
                .device_of(d.out_local.ip())
                .ok_or(InstallError::NoDevice(d.out_local.ip()))?;
            if !self.devices.contains(&device) {
                return Err(InstallError::NotAttached(device));
            }
            // Redirecting needs the sending device's driver to take XDP
            // frames; one with the program attached is known to.
            if out_device != device && !self.devices.contains(&out_device) {
                return Err(InstallError::NotAttached(out_device));
            }
            let ifindex = if out_device == device {
                0
            } else {
                self.net
                    .ifindex(&out_device)
                    .ok_or_else(|| InstallError::NoIfIndex(out_device.clone()))?
            };
            let own_mac = self
                .net
                .device_mac(&out_device)
                .ok_or_else(|| InstallError::NoMac(out_device.clone()))?;
            let next_hop_mac = self
                .net
                .next_hop_mac(&out_device, d.target.ip())
                .ok_or(InstallError::Unresolved(d.target.ip()))?;
            hops.push(Hop {
                device: out_device,
                target: d.target.ip(),
                mac: next_hop_mac,
            });
            entries.push(
                entry(&Direction {
                    peer: d.peer,
                    local: d.local,
                    out_local: d.out_local,
                    target: d.target,
                    own_mac,
                    next_hop_mac,
                    ifindex,
                    flags: d.flags,
                    event_pt: d.event_pt,
                })
                .ok_or(InstallError::FamilyChanges)?,
            );
        }
        let mut done: Vec<FlowKey> = Vec::with_capacity(2);
        for (key, action) in entries {
            if let Err(e) = self.fp.insert(key, action) {
                // Neither direction stays: undo the one put in.
                for k in done {
                    if let Err(e) = self.fp.remove(k) {
                        log::warn!("{e}");
                    }
                }
                return Err(InstallError::Table(e));
            }
            done.push(key);
        }
        // One entry and one hop per direction, both directions given.
        match (done.as_slice(), <[Hop; 2]>::try_from(hops)) {
            (&[k0, k1], Ok(hops)) => Ok(([k0, k1], hops)),
            _ => unreachable!("a flow per direction"),
        }
    }

    /// Check the next hops of the installed calls against the kernel's
    /// tables (read once); install again the calls whose next hop's MAC
    /// changed. A next hop that cannot be resolved now keeps its MAC (its
    /// neighbour entry may just have aged out, as offloaded traffic does
    /// not refresh it).
    fn refresh_macs(&mut self, installed: &mut HashMap<CallId, Installed>) {
        let calls: Vec<CallId> = installed.keys().copied().collect();
        let wants: Vec<(&str, IpAddr)> = calls
            .iter()
            .filter_map(|c| installed.get(c))
            .flat_map(|i| i.hops.iter().map(|h| (h.device.as_str(), h.target)))
            .collect();
        let macs = self.net.next_hop_macs(&wants);
        let changed: Vec<CallId> = calls
            .iter()
            .zip(macs.chunks(2))
            .filter(|(c, m)| {
                installed.get(c).is_some_and(|i| {
                    i.hops
                        .iter()
                        .zip(m.iter())
                        .any(|(h, new)| new.is_some_and(|new| new != h.mac))
                })
            })
            .map(|(&c, _)| c)
            .collect();
        for call in changed {
            let Some(dirs) = installed.get(&call).map(|i| i.dirs.clone()) else {
                continue;
            };
            match self.install(&dirs) {
                Ok((_, hops)) => {
                    if let Some(i) = installed.get_mut(&call) {
                        i.hops = hops;
                    }
                    log::info!("call {call}: next hop changed; XDP flows updated");
                }
                Err(why) => log::debug!("call {call}: next hop changed, not updated: {why}"),
            }
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use nix::sys::eventfd::EfdFlags;
    use std::sync::Mutex;
    use std::sync::mpsc::sync_channel;

    /// The flow table in memory; inserts fail once `fail_at` flows exist.
    #[derive(Default)]
    pub(in crate::relay) struct State {
        pub(in crate::relay) flows: HashMap<FlowKey, FlowAction>,
        pub(in crate::relay) stats: HashMap<FlowKey, FlowStats>,
        /// Samples in the recording ring (`RecordSample` bytes).
        pub(in crate::relay) records: Vec<Vec<u8>>,
        fail_at: Option<usize>,
    }

    #[derive(Clone, Default)]
    pub(in crate::relay) struct Table(pub(in crate::relay) Arc<Mutex<State>>);

    impl FlowTable for Table {
        fn insert(&mut self, key: FlowKey, action: FlowAction) -> Result<(), FlowError> {
            let mut s = self.0.lock().unwrap();
            if s.fail_at.is_some_and(|n| s.flows.len() >= n) {
                return Err(FlowError::new("inserting", "map full"));
            }
            s.flows.insert(key, action);
            Ok(())
        }

        fn remove(&mut self, key: FlowKey) -> Result<(), FlowError> {
            self.0.lock().unwrap().flows.remove(&key);
            Ok(())
        }

        fn stats(&mut self, key: FlowKey) -> Result<Option<FlowStats>, FlowError> {
            Ok(self.0.lock().unwrap().stats.get(&key).copied())
        }

        fn drain_records(&mut self, f: &mut dyn FnMut(&[u8])) -> usize {
            let samples = std::mem::take(&mut self.0.lock().unwrap().records);
            for s in &samples {
                f(s);
            }
            samples.len()
        }
    }

    /// eth0 (index 2) holds 10.0.0.1 and `2001:db8::1`, eth1 (index 3)
    /// 10.1.0.1, lo (index 1) 127.0.0.1; every next
    /// hop resolves but 192.0.2.99's.
    pub(in crate::relay) struct Net;

    impl Network for Net {
        fn device_of(&self, ip: IpAddr) -> Option<String> {
            match ip.to_string().as_str() {
                "10.0.0.1" | "2001:db8::1" => Some("eth0".to_owned()),
                "10.1.0.1" => Some("eth1".to_owned()),
                "127.0.0.1" => Some("lo".to_owned()),
                _ => None,
            }
        }

        fn ifindex(&self, device: &str) -> Option<u32> {
            match device {
                "eth0" => Some(2),
                "eth1" => Some(3),
                "lo" => Some(1),
                _ => None,
            }
        }

        fn device_mac(&self, _: &str) -> Option<[u8; 6]> {
            Some([2, 0, 0, 0, 0, 1])
        }

        fn next_hop_mac(&self, _: &str, dst: IpAddr) -> Option<[u8; 6]> {
            // 192.0.2.77 is a peer whose MAC changes when MOVED is set.
            let last = if dst.to_string() == "192.0.2.77" && MOVED.load(Ordering::Relaxed) {
                7
            } else {
                2
            };
            (dst.to_string() != "192.0.2.99").then_some([2, 0, 0, 0, 0, last])
        }
    }

    use std::sync::atomic::{AtomicBool, Ordering};
    static MOVED: AtomicBool = AtomicBool::new(false);

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// A's and B's directions through `a_local` and `b_local`.
    fn dirs(a_local: &str, b_local: &str, b_peer: &str) -> [Dir; 2] {
        let (a_local, b_local) = (sa(a_local), sa(b_local));
        let (a_peer, b_peer) = (sa("192.0.2.10:4000"), sa(b_peer));
        [
            Dir {
                peer: a_peer,
                local: a_local,
                out_local: b_local,
                target: b_peer,
                flags: 0,
                event_pt: 0,
            },
            Dir {
                peer: b_peer,
                local: b_local,
                out_local: a_local,
                target: a_peer,
                flags: 0,
                event_pt: 0,
            },
        ]
    }

    type Shard = (Receiver<Command>, Arc<EventFd>);

    fn offload(devices: &[&str]) -> (Offload<Table, Net>, Table, SyncSender<OffloadMsg>, Shard) {
        let table = Table::default();
        let (tx, rx) = sync_channel(8);
        let (cmd_tx, cmd_rx) = sync_channel(8);
        let wake = Arc::new(EventFd::from_value_and_flags(0, EfdFlags::EFD_NONBLOCK).unwrap());
        let o = Offload {
            fp: table.clone(),
            net: Net,
            devices: devices.iter().map(|d| (*d).to_owned()).collect(),
            rx,
            shards: vec![(cmd_tx, Arc::clone(&wake))],
            flows: XdpFlows::default(),
        };
        (o, table, tx, (cmd_rx, wake))
    }

    #[test]
    fn both_directions_or_neither() {
        let (mut o, table, _, _) = offload(&["eth0"]);
        // One device: sent back out of it.
        let keys = o
            .install(&dirs("10.0.0.1:30000", "10.0.0.1:30002", "192.0.2.20:5000"))
            .unwrap()
            .0;
        let flows = table.0.lock().unwrap().flows.clone();
        assert_eq!(flows.len(), 2);
        assert!(keys.iter().all(|k| flows[k].ifindex == 0));
        // Across devices: only when the program is on both.
        let cross = dirs("10.0.0.1:30000", "10.1.0.1:30002", "192.0.2.20:5000");
        assert_eq!(
            o.install(&cross).unwrap_err().to_string(),
            "XDP is not attached to eth1"
        );
        o.devices.push("eth1".to_owned());
        let keys = o.install(&cross).unwrap().0;
        let flows = table.0.lock().unwrap().flows.clone();
        assert_eq!(flows[&keys[0]].ifindex, 3, "A's packets leave by eth1");
        assert_eq!(flows[&keys[1]].ifindex, 2, "B's by eth0");
        // What cannot be resolved stays in userspace.
        let e = |d: [Dir; 2]| {
            let (mut o, table, _, _) = offload(&["eth0"]);
            let e = o.install(&d).unwrap_err().to_string();
            assert!(table.0.lock().unwrap().flows.is_empty(), "{e}");
            e
        };
        assert_eq!(
            e(dirs("10.9.9.9:30000", "10.0.0.1:30002", "192.0.2.20:5000")),
            "no device holds 10.9.9.9"
        );
        assert_eq!(
            e(dirs("10.0.0.1:30000", "10.0.0.1:30002", "192.0.2.99:5000")),
            "next hop towards 192.0.2.99 not resolved"
        );
        assert_eq!(
            e(dirs(
                "10.0.0.1:30000",
                "[2001:db8::1]:30002",
                "192.0.2.20:5000"
            )),
            "the address family changes"
        );
        // A failing second insert takes the first one back out.
        let (mut o, table, _, _) = offload(&["eth0"]);
        table.0.lock().unwrap().fail_at = Some(1);
        let e = o
            .install(&dirs("10.0.0.1:30000", "10.0.0.1:30002", "192.0.2.20:5000"))
            .unwrap_err();
        assert!(matches!(e, InstallError::Table(_)));
        assert_eq!(e.to_string(), "inserting a flow: map full");
        assert!(table.0.lock().unwrap().flows.is_empty());
    }

    #[test]
    fn kernel_traffic_is_reported_to_the_worker() {
        let (mut o, table, _, (cmds, _)) = offload(&["eth0"]);
        let d = dirs("10.0.0.1:30000", "10.0.0.1:30002", "192.0.2.20:5000");
        let (keys, hops) = o.install(&d).unwrap();
        let mut installed = HashMap::from([(
            CallId::of(7),
            Installed {
                shard: 0,
                keys,
                packets: [0; 2],
                octets: [0; 2],
                records: false,
                dirs: Box::new(d),
                hops,
            },
        )]);
        o.poll(&mut installed);
        assert!(cmds.try_recv().is_err(), "nothing relayed, nothing to say");
        // 10 frames of 160 octets of payload from A.
        let overhead = headers_len(&keys[0]) as u64;
        table.0.lock().unwrap().stats.insert(
            keys[0],
            FlowStats {
                packets: 10,
                bytes: 10 * (overhead + 160),
                last_ns: 0,
            },
        );
        o.poll(&mut installed);
        let Ok(Command::Touch {
            call,
            packets,
            octets,
        }) = cmds.try_recv()
        else {
            panic!("a touch");
        };
        assert_eq!((call, packets, octets), (CallId::of(7), [10, 0], [1600, 0]));
        // Only what is new is reported.
        o.poll(&mut installed);
        assert!(cmds.try_recv().is_err());
        // The worker's queue full: the report waits, nothing is lost.
        let filler = || Command::Touch {
            call: CallId::of(0),
            packets: [0; 2],
            octets: [0; 2],
        };
        while o.notify(0, filler()) {}
        table
            .0
            .lock()
            .unwrap()
            .stats
            .get_mut(&keys[0])
            .unwrap()
            .packets = 15;
        o.poll(&mut installed);
        while cmds.try_recv().is_ok() {}
        table
            .0
            .lock()
            .unwrap()
            .stats
            .get_mut(&keys[0])
            .unwrap()
            .packets = 20;
        o.poll(&mut installed);
        let Ok(Command::Touch { packets, .. }) = cmds.try_recv() else {
            panic!("a touch");
        };
        assert_eq!(packets, [10, 0], "the 5 not delivered, then 5 more");
    }

    #[test]
    fn the_thread_installs_removes_and_stops() {
        let (o, table, tx, (cmds, _)) = offload(&["eth0"]);
        let t = std::thread::spawn(move || o.run());
        let good = dirs("10.0.0.1:30000", "10.0.0.1:30002", "192.0.2.20:5000");
        let bad = dirs("10.0.0.1:30004", "10.0.0.1:30006", "192.0.2.99:5000");
        let recv = || cmds.recv_timeout(Duration::from_secs(2)).unwrap();
        tx.send(OffloadMsg::Install {
            call: CallId::of(1),
            shard: 0,
            dirs: Box::new(good),
        })
        .unwrap();
        assert!(matches!(recv(), Command::Offloaded { call, ok: true } if call == CallId::of(1)));
        tx.send(OffloadMsg::Install {
            call: CallId::of(2),
            shard: 0,
            dirs: Box::new(bad),
        })
        .unwrap();
        assert!(matches!(recv(), Command::Offloaded { call, ok: false } if call == CallId::of(2)));
        assert_eq!(table.0.lock().unwrap().flows.len(), 2);
        tx.send(OffloadMsg::Remove {
            call: CallId::of(1),
        })
        .unwrap();
        tx.send(OffloadMsg::Remove {
            call: CallId::of(9),
        })
        .unwrap();
        tx.send(OffloadMsg::Shutdown).unwrap();
        t.join().unwrap();
        assert!(table.0.lock().unwrap().flows.is_empty());
    }

    #[test]
    fn the_host_network_on_loopback() {
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(Host.device_of(lo).as_deref(), Some("lo"));
        assert!(Host.ifindex("lo").is_some());
        assert_eq!(Host.device_mac("lo"), Some([0; 6]));
        assert_eq!(Host.next_hop_mac("lo", "192.0.2.1".parse().unwrap()), None);
        let boxed: Box<dyn Network + Send> = Box::new(Net);
        assert_eq!(boxed.device_of(lo).as_deref(), Some("lo"));
        assert_eq!(boxed.ifindex("lo"), Some(1));
        assert!(boxed.device_mac("lo").is_some());
        assert!(boxed.next_hop_mac("lo", lo).is_some());
    }

    /// A sample as the kernel writes it into the ring.
    fn sample(key: &FlowKey, time_ns: u64, payload: &[u8]) -> Vec<u8> {
        use rtpflux_xdp_common::record_layout::{DATA, LEN, SIZE, TIME};
        let mut b = vec![0u8; SIZE];
        b[..16].copy_from_slice(&key.src_addr);
        b[16..32].copy_from_slice(&key.dst_addr);
        b[32..34].copy_from_slice(&key.src_port.to_ne_bytes());
        b[34..36].copy_from_slice(&key.dst_port.to_ne_bytes());
        b[LEN..LEN + 2].copy_from_slice(&u16::try_from(payload.len()).unwrap().to_ne_bytes());
        b[TIME..TIME + 8].copy_from_slice(&time_ns.to_ne_bytes());
        b[DATA..DATA + payload.len()].copy_from_slice(payload);
        b
    }

    #[test]
    fn recorded_samples_reach_their_call_as_pcap_records() {
        let (mut o, table, _, (cmds, _)) = offload(&["eth0"]);
        let d = dirs("10.0.0.1:30000", "10.0.0.1:30002", "192.0.2.20:5000");
        let (keys, hops) = o.install(&d).unwrap();
        let installed = HashMap::from([(
            CallId::of(7),
            Installed {
                shard: 0,
                keys,
                packets: [0; 2],
                octets: [0; 2],
                records: true,
                dirs: Box::new(d),
                hops,
            },
        )]);
        let owners = HashMap::from([(keys[0], CallId::of(7)), (keys[1], CallId::of(7))]);
        let stranger = FlowKey {
            src_port: 1u16.to_be(),
            ..keys[0]
        };
        // Now on the kernel's clock: the record carries the wall time.
        let mono = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC).unwrap();
        let now_ns = u64::try_from(mono.tv_sec()).unwrap() * 1_000_000_000
            + u64::try_from(mono.tv_nsec()).unwrap();
        let rtp = [0x80, 0, 0, 1, 0, 0, 0, 160, 0, 0, 0, 7, 0xff, 0xff];
        table.0.lock().unwrap().records = vec![
            sample(&keys[0], now_ns, &rtp),
            sample(&keys[1], now_ns, &rtp[..12]),
            sample(&stranger, now_ns, &rtp),
            vec![0; 10],
        ];
        o.drain(&installed, &owners);
        let Ok(Command::Recorded { call, frames }) = cmds.try_recv() else {
            panic!("no records sent");
        };
        assert_eq!(call, CallId::of(7));
        assert!(cmds.try_recv().is_err(), "one batch per call");
        // Two pcap records (16-octet header, IPv4 and UDP headers, payload),
        // from each peer to its relay address.
        let first = &frames[..16 + 28 + rtp.len()];
        let second = &frames[first.len()..];
        assert_eq!(second.len(), 16 + 28 + 12);
        let secs = u64::from(u32::from_le_bytes(first[..4].try_into().unwrap()));
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            wall.abs_diff(secs) <= 2,
            "wall-clock time: {secs} vs {wall}"
        );
        let ip = &first[16..];
        let src = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15])),
            u16::from_be_bytes([ip[20], ip[21]]),
        );
        let dst = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19])),
            u16::from_be_bytes([ip[22], ip[23]]),
        );
        assert_eq!(
            (src, dst),
            (
                socket_addr(&keys[0].src_addr, keys[0].src_port),
                socket_addr(&keys[0].dst_addr, keys[0].dst_port)
            )
        );
        assert_eq!(&first[16 + 28..], &rtp);
        // Nothing waiting: nothing sent.
        o.drain(&installed, &owners);
        assert!(cmds.try_recv().is_err());
    }

    #[test]
    fn flow_halves_read_back_as_socket_addresses() {
        let v4 = rtpflux_xdp_common::mapped([192, 0, 2, 1]);
        assert_eq!(
            socket_addr(&v4, 4000u16.to_be()),
            "192.0.2.1:4000".parse().unwrap()
        );
        let v6: Ipv6Addr = "2001:db8::7".parse().unwrap();
        assert_eq!(
            socket_addr(&v6.octets(), 5004u16.to_be()),
            "[2001:db8::7]:5004".parse().unwrap()
        );
        let t = wall_time(1_000_000_000, 5_000_000_000);
        assert_eq!(t, UNIX_EPOCH + Duration::from_secs(6));
        assert_eq!(wall_time(5, -100), UNIX_EPOCH, "before the epoch: clamped");
    }

    #[test]
    fn a_changed_next_hop_mac_updates_the_flows() {
        let (mut o, table, _, _) = offload(&["eth0"]);
        let d = dirs("10.0.0.1:30000", "10.0.0.1:30002", "192.0.2.77:5000");
        let (keys, hops) = o.install(&d).unwrap();
        let mut installed = HashMap::from([(
            CallId::of(7),
            Installed {
                shard: 0,
                keys,
                packets: [0; 2],
                octets: [0; 2],
                records: false,
                dirs: Box::new(d),
                hops,
            },
        )]);
        let mac_towards_b = || table.0.lock().unwrap().flows[&keys[0]].dst_mac;
        assert_eq!(mac_towards_b(), [2, 0, 0, 0, 0, 2]);
        o.refresh_macs(&mut installed);
        assert_eq!(mac_towards_b(), [2, 0, 0, 0, 0, 2], "unchanged");
        MOVED.store(true, Ordering::Relaxed);
        o.refresh_macs(&mut installed);
        assert_eq!(mac_towards_b(), [2, 0, 0, 0, 0, 7], "the new MAC");
        assert_eq!(installed[&CallId::of(7)].hops[0].mac, [2, 0, 0, 0, 0, 7]);
        MOVED.store(false, Ordering::Relaxed);
    }
}
