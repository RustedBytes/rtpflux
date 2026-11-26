//! The Recordings page's API: the pcaps in `[recording] dir`, each read
//! back into streams and packets (RTP and RTCP header fields, nothing of
//! the payloads), and the file itself for Wireshark.
//!
//! Read-only like the rest of the UI. A file is named by its base name,
//! which must end in `.pcap` and name a regular file directly in the
//! directory (no path, no link). Reading is bounded: at most
//! [`MAX_PACKETS`] packets of a file are decoded per request, and a
//! download at most [`MAX_DOWNLOAD`] octets.

use super::api::{Answer, Query, page};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::io::{BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// Packets decoded per request; a longer recording is reported truncated.
pub const MAX_PACKETS: usize = 300_000;

/// The largest pcap the UI hands out (larger ones: from the host itself).
pub const MAX_DOWNLOAD: u64 = 256 * 1024 * 1024;

/// One recorded datagram: when, between which addresses, and its first
/// octets (enough for an RTP or RTCP header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub time_us: u64,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub len: usize,
    pub head: [u8; 16],
}

/// What a datagram is, from its first octets (RFC 7983 §7, RFC 5761 §4).
#[must_use]
pub fn kind(p: &Packet) -> &'static str {
    match p.head[0] {
        0..=3 => "STUN",
        16..=19 => "ZRTP",
        20..=63 => "DTLS",
        128..=191 if p.len >= 8 && (192..=223).contains(&p.head[1]) => "RTCP",
        128..=191 if p.len >= 12 => "RTP",
        _ => "other",
    }
}

fn rtcp_name(pt: u8) -> &'static str {
    match pt {
        200 => "SR",
        201 => "RR",
        202 => "SDES",
        203 => "BYE",
        204 => "APP",
        205 => "RTPFB",
        206 => "PSFB",
        207 => "XR",
        _ => "RTCP",
    }
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// The addresses and UDP payload of a raw IP frame (`LINKTYPE_RAW`).
fn udp(frame: &[u8]) -> Option<(SocketAddr, SocketAddr, &[u8])> {
    let (src, dst, rest) = match frame.first()? >> 4 {
        4 => {
            let ihl = usize::from(frame[0] & 0x0f) * 4;
            if *frame.get(9)? != 17 || ihl < 20 {
                return None;
            }
            let ip = |o: usize| -> Option<IpAddr> {
                let b = frame.get(o..o + 4)?;
                Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
            };
            (ip(12)?, ip(16)?, frame.get(ihl..)?)
        }
        6 => {
            if *frame.get(6)? != 17 {
                return None;
            }
            let ip = |o: usize| -> Option<IpAddr> {
                let b: [u8; 16] = frame.get(o..o + 16)?.try_into().ok()?;
                Some(IpAddr::V6(Ipv6Addr::from(b)))
            };
            (ip(8)?, ip(24)?, frame.get(40..)?)
        }
        _ => return None,
    };
    let u = rest.get(..8)?;
    Some((
        SocketAddr::new(src, be16(&u[0..2])),
        SocketAddr::new(dst, be16(&u[2..4])),
        rest.get(8..)?,
    ))
}

/// The packets of the recording at `path`, at most `max`; and whether
/// there were more. A damaged or cut-short record ends the reading, as
/// the converter does.
///
/// # Errors
///
/// When the file cannot be read or is not one of the relay's recordings.
pub fn read(path: &Path, max: usize) -> std::io::Result<(Vec<Packet>, bool)> {
    let mut r = BufReader::new(std::fs::File::open(path)?);
    let mut head = [0u8; 24];
    r.read_exact(&mut head)?;
    if head != crate::recording::file_header() {
        return Err(std::io::Error::other("not an rtpflux pcap recording"));
    }
    let mut out = Vec::new();
    let mut rec = [0u8; 16];
    let mut buf = Vec::new();
    while r.read_exact(&mut rec).is_ok() {
        let word = |i: usize| u32::from_le_bytes([rec[i], rec[i + 1], rec[i + 2], rec[i + 3]]);
        if !crate::recording::plausible_record(word(8), word(12)) {
            break;
        }
        buf.resize(word(8) as usize, 0);
        if r.read_exact(&mut buf).is_err() {
            break;
        }
        let Some((src, dst, payload)) = udp(&buf) else {
            continue;
        };
        if out.len() == max {
            return Ok((out, true));
        }
        let mut h = [0u8; 16];
        let n = payload.len().min(16);
        h[..n].copy_from_slice(&payload[..n]);
        out.push(Packet {
            time_us: u64::from(word(0)) * 1_000_000 + u64::from(word(4)),
            src,
            dst,
            len: payload.len(),
            head: h,
        });
    }
    Ok((out, false))
}

/// A packet as the packet list shows it: its number (from 1) and time
/// since the first packet (`start_us`), in microseconds.
fn packet_row(index: usize, packet: &Packet, start_us: u64) -> Value {
    let what = kind(packet);
    let mut row = json!({
        "n": index + 1,
        "t_us": packet.time_us.saturating_sub(start_us),
        "src": packet.src.to_string(),
        "dst": packet.dst.to_string(),
        "len": packet.len,
        "kind": what,
    });
    let h = &packet.head;
    if let Value::Object(o) = &mut row {
        match what {
            "RTP" => {
                o.insert("pt".into(), json!(h[1] & 0x7f));
                o.insert("marker".into(), json!(h[1] & 0x80 != 0));
                o.insert("seq".into(), json!(be16(&h[2..4])));
                o.insert("ts".into(), json!(be32(&h[4..8])));
                o.insert("ssrc".into(), json!(format!("{:08x}", be32(&h[8..12]))));
            }
            "RTCP" => {
                o.insert("rtcp".into(), json!(rtcp_name(h[1])));
                o.insert("ssrc".into(), json!(format!("{:08x}", be32(&h[4..8]))));
            }
            _ => {}
        }
    }
    row
}

/// Per stream (sender, receiver, SSRC; RTCP and other kinds by sender
/// and receiver): packets, octets, payload types, duration, and the RTP
/// packets lost (sequence numbers never seen, across wraps).
fn streams(packets: &[Packet]) -> Vec<Value> {
    #[derive(Default)]
    struct S {
        packets: u64,
        octets: u64,
        first_us: u64,
        last_us: u64,
        pts: BTreeMap<u8, u64>,
        // Extended sequence numbers: the highest seen, the first, the
        // count of distinct ones (for loss).
        ext_first: Option<i64>,
        ext_max: i64,
        last_seq: Option<u16>,
        cycles: i64,
    }
    let mut map: BTreeMap<(String, String, String, &'static str), S> = BTreeMap::new();
    for p in packets {
        let k = kind(p);
        let ssrc = match k {
            "RTP" => format!("{:08x}", be32(&p.head[8..12])),
            "RTCP" => format!("{:08x}", be32(&p.head[4..8])),
            _ => String::new(),
        };
        let s = map
            .entry((p.src.to_string(), p.dst.to_string(), ssrc, k))
            .or_default();
        if s.packets == 0 {
            s.first_us = p.time_us;
        }
        s.packets += 1;
        s.octets += p.len as u64;
        s.first_us = s.first_us.min(p.time_us);
        s.last_us = s.last_us.max(p.time_us);
        if k == "RTP" {
            *s.pts.entry(p.head[1] & 0x7f).or_default() += 1;
            let seq = be16(&p.head[2..4]);
            if let Some(last) = s.last_seq
                && seq < last
                && last - seq > 0x8000
            {
                s.cycles += 1;
            }
            let ext = s.cycles * 65_536 + i64::from(seq);
            s.ext_first = Some(s.ext_first.map_or(ext, |f| f.min(ext)));
            s.ext_max = s.ext_max.max(ext);
            if s.last_seq.is_none_or(|l| seq.wrapping_sub(l) < 0x8000) {
                s.last_seq = Some(seq);
            }
        }
    }
    map.into_iter()
        .map(|((src, dst, ssrc, k), s)| {
            let lost = s
                .ext_first
                .map(|f| (s.ext_max - f + 1 - i64::try_from(s.packets).unwrap_or(i64::MAX)).max(0));
            json!({
                "src": src,
                "dst": dst,
                "kind": k,
                "ssrc": (!ssrc.is_empty()).then_some(ssrc),
                "packets": s.packets,
                "octets": s.octets,
                "pts": s.pts.iter().map(|(pt, n)| json!({"pt": pt, "packets": n})).collect::<Vec<_>>(),
                "lost": lost,
                "duration_ms": (s.last_us - s.first_us) / 1000,
            })
        })
        .collect()
}

/// What `[recording] dir` holds, and reading it for the UI.
pub struct Recordings {
    dir: Option<PathBuf>,
}

impl Recordings {
    #[must_use]
    pub fn new(dir: Option<PathBuf>) -> Self {
        Recordings { dir }
    }

    #[must_use]
    pub fn enabled(&self) -> bool {
        self.dir.is_some()
    }

    /// The pcap `name` names in the directory: a path relative to it of
    /// plain names (none starting with `.`, at most
    /// [`naming::MAX_DEPTH`](crate::recording::naming::MAX_DEPTH)
    /// subdirectories, a `recording-path`), ending in `.pcap`, of a
    /// regular file reached through real directories (no links).
    fn file(&self, name: Option<&String>) -> Result<PathBuf, Answer> {
        let Some(dir) = &self.dir else {
            return Err((
                404,
                json!({ "error": "recording is off (no [recording] dir)" }),
            ));
        };
        let Some(name) = name else {
            return Err((400, json!({ "error": "file is required" })));
        };
        let parts: Vec<&str> = name.split('/').collect();
        let plain = |p: &&str| {
            !p.is_empty()
                && !p.starts_with('.')
                && Path::new(p).file_name().and_then(|n| n.to_str()) == Some(*p)
        };
        if parts.len() > crate::recording::naming::MAX_DEPTH + 1
            || !parts.iter().all(plain)
            || !is_pcap(name)
            || name
                .chars()
                .any(|c| c.is_control() || c == '"' || c == '\\')
        {
            return Err((400, json!({ "error": "not a recording's file name" })));
        }
        let mut path = dir.clone();
        for (k, p) in parts.iter().enumerate() {
            path.push(p);
            let last = k + 1 == parts.len();
            match std::fs::symlink_metadata(&path) {
                Ok(m) if (last && m.is_file()) || (!last && m.is_dir()) => {}
                _ => return Err((404, json!({ "error": "no such recording" }))),
            }
        }
        Ok(path)
    }

    /// `path` under `recordings`.
    #[must_use]
    pub fn handle(&self, path: &str, q: &Query) -> Answer {
        match path {
            "" => self.list(q),
            "streams" => self.read_with(q, |packets, truncated, meta| {
                json!({ "streams": streams(packets), "truncated": truncated, "meta": meta })
            }),
            "packets" => self.read_with(q, |packets, truncated, _| {
                let t0 = packets.first().map_or(0, |p| p.time_us);
                let filter = q.get("kind").map(String::as_str).filter(|k| !k.is_empty());
                let rows: Vec<Value> = packets
                    .iter()
                    .enumerate()
                    .filter(|(_, p)| filter.is_none_or(|f| kind(p) == f))
                    .map(|(i, p)| packet_row(i, p, t0))
                    .collect();
                let mut v = page(Value::Array(rows), q);
                if let Value::Object(o) = &mut v {
                    o.insert("truncated".into(), json!(truncated));
                }
                v
            }),
            _ => (404, json!({ "error": "no such API path" })),
        }
    }

    fn read_with(&self, q: &Query, f: impl FnOnce(&[Packet], bool, Value) -> Value) -> Answer {
        let path = match self.file(q.get("file")) {
            Ok(p) => p,
            Err(a) => return a,
        };
        match read(&path, MAX_PACKETS) {
            Ok((packets, truncated)) => (200, f(&packets, truncated, sidecar(&path))),
            Err(e) => (
                422,
                json!({ "error": format!("cannot read the recording: {e}") }),
            ),
        }
    }

    /// Every pcap in the directory, newest first unless sorted otherwise,
    /// with what the converter wrote next to it.
    fn list(&self, q: &Query) -> Answer {
        let Some(dir) = &self.dir else {
            return (
                404,
                json!({ "error": "recording is off (no [recording] dir)" }),
            );
        };
        let mut rows: Vec<Value> = crate::recording::naming::walk(dir)
            .into_iter()
            .filter_map(|(name, path, meta)| {
                if !is_pcap(&name) {
                    return None;
                }
                let audio = ["wav", "flac", "opus", "mp3"]
                    .into_iter()
                    .find(|x| path.with_extension(x).is_file());
                let modified = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map_or(0, |d| d.as_secs());
                let mut row = Map::new();
                row.insert("file".into(), json!(name));
                row.insert("size".into(), json!(meta.len()));
                row.insert("modified".into(), json!(modified));
                row.insert("audio".into(), json!(audio));
                if let Value::Object(m) = sidecar(&path) {
                    for k in ["call_id", "from_tag", "to_tag", "section", "duration_ms"] {
                        if let Some(v) = m.get(k) {
                            row.insert(k.into(), v.clone());
                        }
                    }
                }
                Some(Value::Object(row))
            })
            .collect();
        if !q.contains_key("sort") {
            rows.sort_by_key(|r| std::cmp::Reverse(r["modified"].as_u64().unwrap_or(0)));
        }
        (200, page(Value::Array(rows), q))
    }

    /// The pcap named by `file` for download: (base name, contents).
    ///
    /// # Errors
    ///
    /// The answer to give instead: no such file, a bad name, or too large.
    pub fn download(&self, q: &Query) -> Result<(String, Vec<u8>), Answer> {
        let path = self.file(q.get("file"))?;
        let len = std::fs::metadata(&path).map_or(0, |m| m.len());
        if len > MAX_DOWNLOAD {
            return Err((
                413,
                json!({ "error": "too large to download here; copy it from the host" }),
            ));
        }
        let bytes = std::fs::read(&path).map_err(|e| {
            (
                500,
                json!({ "error": format!("cannot read the recording: {e}") }),
            )
        })?;
        let name = path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        Ok((name, bytes))
    }
}

/// A recording's file name: `*.pcap`, as the recorder writes it.
fn is_pcap(name: &str) -> bool {
    Path::new(name).extension().is_some_and(|x| x == "pcap")
}

/// The converter's JSON next to a pcap (call, tags, section, which port
/// is the caller's), or `null` when there is none (yet).
fn sidecar(pcap: &Path) -> Value {
    std::fs::read(pcap.with_extension("json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rtp(seq: u16, ssrc: u32, pt: u8) -> Vec<u8> {
        let mut p = vec![0x80, pt, 0, 0, 0, 0, 0, 160];
        p[2..4].copy_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(&[0xd5; 160]);
        p
    }

    fn write(dir: &Path, name: &str, payloads: &[(&str, &str, Vec<u8>)]) -> PathBuf {
        let path = dir.join(name);
        let mut r = crate::recording::Recorder::open(&path).unwrap();
        for (src, dst, p) in payloads {
            r.packet(src.parse().unwrap(), dst.parse().unwrap(), p);
        }
        r.flush();
        path
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One directory, read every way.
    fn a_recording_reads_back_into_streams_and_packets() {
        let dir = std::env::temp_dir().join(format!("rtpflux-webui-rec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (a, relay) = ("192.0.2.1:4000", "192.0.2.9:30000");
        let mut ps: Vec<(&str, &str, Vec<u8>)> = Vec::new();
        // seq 65534..=65535, then 0..=4 without 2: one lost across a wrap
        for seq in [65_534u16, 65_535, 0, 1, 3, 4] {
            ps.push((a, relay, rtp(seq, 7, 0)));
        }
        ps.push((
            a,
            "192.0.2.9:30001",
            vec![0x80, 200, 0, 6, 0, 0, 0, 7, 0, 0, 0, 0],
        ));
        ps.push((
            "[2001:db8::1]:5000",
            "[2001:db8::9]:30002",
            vec![0x10, 0, 0, 1, b'Z', b'R', b'T', b'P'],
        ));
        let path = write(&dir, "c-a-1.pcap", &ps);
        let (packets, truncated) = read(&path, 100).unwrap();
        assert_eq!((packets.len(), truncated), (8, false));
        let kinds: Vec<&str> = packets.iter().map(kind).collect();
        assert_eq!(
            kinds,
            ["RTP", "RTP", "RTP", "RTP", "RTP", "RTP", "RTCP", "ZRTP"]
        );
        assert_eq!(packets[7].src, "[2001:db8::1]:5000".parse().unwrap());
        let s = streams(&packets);
        let rtp_stream = s.iter().find(|x| x["kind"] == "RTP").unwrap();
        assert_eq!(rtp_stream["packets"], 6);
        assert_eq!(rtp_stream["lost"], 1, "one lost across the wrap");
        assert_eq!(rtp_stream["ssrc"], "00000007");
        let row = packet_row(6, &packets[6], packets[0].time_us);
        assert_eq!(
            (row["rtcp"].as_str(), row["n"].as_u64()),
            (Some("SR"), Some(7))
        );
        assert!(read(&path, 3).unwrap().1, "a cap reports truncation");

        let rec = Recordings::new(Some(dir.clone()));
        let (code, list) = rec.handle("", &Query::new());
        assert_eq!((code, list["total"].as_u64()), (200, Some(1)));
        assert_eq!(list["rows"][0]["file"], "c-a-1.pcap");
        let q = |f: &str| Query::from([("file".to_owned(), f.to_owned())]);
        let (code, v) = rec.handle("packets", &q("c-a-1.pcap"));
        assert_eq!((code, v["total"].as_u64()), (200, Some(8)));
        let mut kq = q("c-a-1.pcap");
        kq.insert("kind".into(), "RTCP".into());
        assert_eq!(rec.handle("packets", &kq).1["total"], 1);
        assert_eq!(
            rec.download(&q("c-a-1.pcap")).unwrap().1,
            std::fs::read(&path).unwrap()
        );
        // Names that are not a recording's own: refused, never read.
        std::fs::write(dir.join("notes.txt"), "x").unwrap();
        std::os::unix::fs::symlink(&path, dir.join("link.pcap")).unwrap();
        for bad in [
            "../c-a-1.pcap",
            "/etc/passwd",
            "notes.txt",
            "",
            ".pcap",
            "sub/../c-a-1.pcap",
            ".hidden/x.pcap",
            "a//b.pcap",
            "a/b/c/d/e/f.pcap",
            "a\"b.pcap",
        ] {
            assert_eq!(rec.handle("packets", &q(bad)).0, 400, "{bad}");
        }
        assert_eq!(
            rec.handle("packets", &q("link.pcap")).0,
            404,
            "a link is not followed"
        );
        assert_eq!(rec.handle("packets", &q("gone.pcap")).0, 404);
        assert_eq!(rec.handle("packets", &q("sub/x.pcap")).0, 404);
        assert_eq!(
            rec.handle("", &Query::new()).1["total"],
            1,
            "links are not listed"
        );
        std::fs::write(dir.join("bad.pcap"), "not a pcap at all, really").unwrap();
        assert_eq!(rec.handle("streams", &q("bad.pcap")).0, 422);
        assert_eq!(Recordings::new(None).handle("", &Query::new()).0, 404);
        // A `recording-path` subdirectory: listed and read by its path;
        // a linked directory is neither.
        std::fs::create_dir_all(dir.join("acme/agents")).unwrap();
        write(&dir, "acme/agents/x.pcap", &ps);
        std::os::unix::fs::symlink(dir.join("acme"), dir.join("via-link")).unwrap();
        let list = rec.handle("", &Query::new()).1;
        assert_eq!(list["total"], 3, "{list}");
        assert!(
            list["rows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["file"] == "acme/agents/x.pcap"),
            "{list}"
        );
        assert_eq!(
            rec.handle("packets", &q("acme/agents/x.pcap")).1["total"],
            8
        );
        assert_eq!(rec.handle("packets", &q("via-link/agents/x.pcap")).0, 404);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
