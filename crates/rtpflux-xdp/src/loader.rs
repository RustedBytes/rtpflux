//! Loading the XDP program and managing its forwarding map.

use crate::pod::{Action, Key, Stats, Steer};
use aya::maps::{HashMap, MapData, MapError, PerCpuHashMap, PerCpuValues, RingBuf, XskMap};
use aya::programs::{ProgramError, Xdp, XdpMode};
use aya::{Ebpf, EbpfError, TestRun, TestRunOptions};
use core::fmt;
use rtpflux_xdp_common::{
    FLOW_MAP, FlowAction, FlowKey, FlowStats, RECORD_MAP, STATS_MAP, STEER_MAP, SteerRange, XSK_MAP,
};
use std::ffi::CString;
use std::os::fd::AsRawFd;

/// Name of the XDP program in the object.
pub const PROGRAM: &str = "rtpflux";

/// Why a fast-path operation failed.
#[derive(Debug)]
pub enum Error {
    /// The object could not be parsed or its maps created.
    Load(EbpfError),
    /// The program was rejected (e.g. by the verifier) or could not run.
    Program(ProgramError),
    /// A map operation failed.
    Map(MapError),
    /// The object lacks the program or map this crate expects.
    Missing(&'static str),
    /// A device name that cannot name an interface.
    BadDevice(String),
    /// The number of CPUs could not be read.
    Cpus(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Load(e) => write!(f, "loading the XDP object: {e}"),
            Error::Program(e) => write!(f, "XDP program: {e}"),
            Error::Map(e) => write!(f, "flow map: {e}"),
            Error::Missing(what) => write!(f, "the XDP object has no {what}"),
            Error::BadDevice(d) => write!(f, "invalid device name {d:?}"),
            Error::Cpus(e) => write!(f, "counting CPUs: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// Outcome of running the program on one frame (`BPF_PROG_TEST_RUN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    /// The XDP action returned (`XDP_PASS` = 2, `XDP_TX` = 3).
    pub action: u32,
    /// Length of the frame the program left in the output buffer.
    pub len: usize,
    /// Kernel-measured duration per repetition, in nanoseconds.
    pub nanos: u128,
}

/// `XDP_PASS`.
pub const XDP_PASS: u32 = 2;
/// `XDP_DROP`: the frame is dropped.
pub const XDP_DROP: u32 = 1;
/// `XDP_TX`.
pub const XDP_TX: u32 = 3;
/// `XDP_REDIRECT`.
pub const XDP_REDIRECT: u32 = 4;

/// How the program is attached to a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachMode {
    /// In the driver (fastest; needs driver support).
    Native,
    /// In the generic kernel path (works with any driver).
    Generic,
}

/// The XDP program loaded into the kernel (verified). Attachments made with
/// [`FastPath::attach`] last as long as the `FastPath`.
pub struct FastPath {
    ebpf: Ebpf,
    cpus: usize,
    /// The recording ring (`RTPFLUX_RECORD`), read from userspace.
    record: RingBuf<MapData>,
}

impl FastPath {
    /// Load the object and its program into the kernel. Needs `CAP_BPF`
    /// (in practice root). Does not attach to any interface.
    ///
    /// # Errors
    ///
    /// [`Error`] when the object is malformed, the verifier rejects the
    /// program, or the expected program or map is missing.
    pub fn load(object: &[u8]) -> Result<Self, Error> {
        let mut ebpf = Ebpf::load(object).map_err(Error::Load)?;
        let prog: &mut Xdp = ebpf
            .program_mut(PROGRAM)
            .ok_or(Error::Missing("rtpflux program"))?
            .try_into()
            .map_err(Error::Program)?;
        prog.load().map_err(Error::Program)?;
        if ebpf.map(FLOW_MAP).is_none() {
            return Err(Error::Missing("RTPFLUX_FLOWS map"));
        }
        if ebpf.map(STATS_MAP).is_none() {
            return Err(Error::Missing("RTPFLUX_STATS map"));
        }
        let record = ebpf
            .take_map(RECORD_MAP)
            .ok_or(Error::Missing("RTPFLUX_RECORD map"))?;
        let record = RingBuf::try_from(record).map_err(Error::Map)?;
        let cpus = aya::util::nr_cpus().map_err(|(_, e)| Error::Cpus(e))?.get() as usize;
        Ok(FastPath { ebpf, cpus, record })
    }

    /// Steer the datagrams no flow relays to `addr` (IPv4-mapped for IPv4)
    /// on ports `range` to the `AF_XDP` sockets ([`FastPath::set_socket`]).
    ///
    /// # Errors
    ///
    /// [`Error::Map`] when the map is full or the update fails.
    pub fn steer(&mut self, addr: [u8; 16], range: SteerRange) -> Result<(), Error> {
        let map = self
            .ebpf
            .map_mut(STEER_MAP)
            .ok_or(Error::Missing("RTPFLUX_STEER map"))?;
        let mut map: HashMap<_, [u8; 16], Steer> = HashMap::try_from(map).map_err(Error::Map)?;
        map.insert(&addr, &Steer(range), 0).map_err(Error::Map)
    }

    /// Stop steering `addr`'s datagrams.
    ///
    /// # Errors
    ///
    /// [`Error::Map`] when the address was not steered.
    pub fn unsteer(&mut self, addr: [u8; 16]) -> Result<(), Error> {
        let map = self
            .ebpf
            .map_mut(STEER_MAP)
            .ok_or(Error::Missing("RTPFLUX_STEER map"))?;
        let mut map: HashMap<_, [u8; 16], Steer> = HashMap::try_from(map).map_err(Error::Map)?;
        map.remove(&addr).map_err(Error::Map)
    }

    /// Receive the steered datagrams arriving on receive queue `queue` of
    /// the device the program is attached to on the `AF_XDP` socket `socket`
    /// (bound to that device and queue).
    ///
    /// # Errors
    ///
    /// [`Error::Map`] for a queue beyond `XSK_QUEUES` or a socket the
    /// kernel refuses.
    pub fn set_socket(&mut self, queue: u32, socket: impl AsRawFd) -> Result<(), Error> {
        let map = self
            .ebpf
            .map_mut(XSK_MAP)
            .ok_or(Error::Missing("RTPFLUX_XSKS map"))?;
        let mut map = XskMap::try_from(map).map_err(Error::Map)?;
        map.set(queue, socket, 0).map_err(Error::Map)
    }

    /// Hand each recorded datagram waiting in the ring to `f`, as the bytes
    /// of a `RecordSample` (`rtpflux_xdp_common::parse_record` reads them).
    /// Returns how many there were.
    pub fn drain_records(&mut self, mut f: impl FnMut(&[u8])) -> usize {
        let mut n = 0;
        while let Some(item) = self.record.next() {
            f(&item);
            n += 1;
        }
        n
    }

    /// Attach the program to network device `device`.
    ///
    /// # Errors
    ///
    /// [`Error::Program`] when the device does not exist or refuses the
    /// mode; [`Error::BadDevice`] for a name with a NUL byte.
    pub fn attach(&mut self, device: &str, mode: AttachMode) -> Result<(), Error> {
        let name = CString::new(device).map_err(|_| Error::BadDevice(device.to_owned()))?;
        let prog: &mut Xdp = self
            .ebpf
            .program_mut(PROGRAM)
            .ok_or(Error::Missing("rtpflux program"))?
            .try_into()
            .map_err(Error::Program)?;
        let mode = match mode {
            AttachMode::Native => XdpMode::Driver,
            AttachMode::Generic => XdpMode::Skb,
        };
        prog.attach(name.as_c_str(), mode).map_err(Error::Program)?;
        Ok(())
    }

    fn stats_map(&mut self) -> Result<PerCpuHashMap<&mut MapData, Key, Stats>, Error> {
        let map = self
            .ebpf
            .map_mut(STATS_MAP)
            .ok_or(Error::Missing("RTPFLUX_STATS map"))?;
        PerCpuHashMap::try_from(map).map_err(Error::Map)
    }

    /// The counters of a flow, summed over all CPUs (`None` if the flow is
    /// not installed).
    ///
    /// # Errors
    ///
    /// [`Error::Map`] when the kernel refuses the lookup.
    pub fn stats(&mut self, key: FlowKey) -> Result<Option<FlowStats>, Error> {
        let per_cpu = match self.stats_map()?.get(&Key(key), 0) {
            Ok(v) => v,
            Err(MapError::KeyNotFound) => return Ok(None),
            Err(e) => return Err(Error::Map(e)),
        };
        let mut total = FlowStats::default();
        for s in per_cpu.iter() {
            total.packets += s.0.packets;
            total.bytes += s.0.bytes;
            total.last_ns = total.last_ns.max(s.0.last_ns);
        }
        Ok(Some(total))
    }

    fn flows(&mut self) -> Result<HashMap<&mut aya::maps::MapData, Key, Action>, Error> {
        let map = self
            .ebpf
            .map_mut(FLOW_MAP)
            .ok_or(Error::Missing("RTPFLUX_FLOWS map"))?;
        HashMap::try_from(map).map_err(Error::Map)
    }

    /// Add a flow, or replace an existing flow's action. A new flow's
    /// counters start at zero (created first, so the program counts from
    /// the first packet); a replaced flow keeps its counters, which the
    /// relay reads as running totals.
    ///
    /// # Errors
    ///
    /// [`Error::Map`] when a map is full or the kernel refuses (the new
    /// flow's counters are removed again).
    pub fn insert(&mut self, key: FlowKey, action: FlowAction) -> Result<(), Error> {
        /// `BPF_NOEXIST`: only create.
        const NO_EXIST: u64 = 1;
        let zero = PerCpuValues::try_from(vec![Stats(FlowStats::default()); self.cpus])
            .map_err(Error::Cpus)?;
        let created = match self.stats_map()?.insert(&Key(key), zero, NO_EXIST) {
            Ok(()) => true,
            Err(MapError::SyscallError(e))
                if e.io_error.raw_os_error() == Some(nix::libc::EEXIST) =>
            {
                false
            }
            Err(e) => return Err(Error::Map(e)),
        };
        let inserted = self
            .flows()?
            .insert(&Key(key), &Action(action), 0)
            .map_err(Error::Map);
        if inserted.is_err() && created {
            let _ = self.stats_map()?.remove(&Key(key));
        }
        inserted
    }

    /// Remove a flow (no error if absent).
    ///
    /// # Errors
    ///
    /// [`Error::Map`] when the kernel refuses for another reason.
    pub fn remove(&mut self, key: FlowKey) -> Result<(), Error> {
        match self.flows()?.remove(&Key(key)) {
            Ok(()) | Err(MapError::KeyNotFound) => {}
            Err(e) => return Err(Error::Map(e)),
        }
        match self.stats_map()?.remove(&Key(key)) {
            Ok(()) | Err(MapError::KeyNotFound) => Ok(()),
            Err(e) => Err(Error::Map(e)),
        }
    }

    /// Run the program on `frame` `repeat` times (`BPF_PROG_TEST_RUN`); the
    /// frame the program produced is written to `out`.
    ///
    /// # Errors
    ///
    /// [`Error::Program`] when the kernel refuses the test run (e.g. `out`
    /// is too small).
    pub fn test_run(&self, frame: &[u8], out: &mut [u8], repeat: u32) -> Result<Run, Error> {
        let prog: &Xdp = self
            .ebpf
            .program(PROGRAM)
            .ok_or(Error::Missing("rtpflux program"))?
            .try_into()
            .map_err(Error::Program)?;
        let r = prog
            .test_run(TestRunOptions {
                data_in: Some(frame),
                data_out: Some(out),
                repeat: repeat.max(1),
                ..TestRunOptions::default()
            })
            .map_err(Error::Program)?;
        Ok(Run {
            action: r.return_value,
            len: r.data_size_out as usize,
            nanos: r.duration.as_nanos(),
        })
    }
}
