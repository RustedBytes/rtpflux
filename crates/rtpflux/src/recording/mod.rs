//! Call recording as pcap (`LINKTYPE_RAW`): every RTP and RTCP packet a
//! peer sends, as the relay received it (after SRTP decryption, before
//! transcoding or blocking), in an IPv4 or IPv6 / UDP frame from the peer
//! to the relay's port, stamped with the wall clock. Frames are collected
//! in memory and written to the file in chunks.
//!
//! When a recording ends it can be converted to an audio file (WAV, FLAC,
//! Ogg Opus, MP3), stereo or mono: [`settings`], [`convert`].

pub mod activity;
pub mod convert;
mod encode;
mod mix;
pub mod mixrec;
pub mod naming;
mod read;
mod resample;
pub mod settings;
pub mod store;
pub mod webhook;
pub mod writer;

pub use convert::{Conversion, Job, Meta};
pub use settings::{Channels, Format, Settings};

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// `LINKTYPE_RAW`: each frame starts with an IPv4 or IPv6 header.
const LINKTYPE_RAW: u32 = 101;
/// Bytes collected before a write.
const CHUNK: usize = 64 * 1024;

/// What to record into, and how to convert it when it ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    pub path: std::path::PathBuf,
    /// `None`: keep the pcap only.
    pub conversion: Option<Conversion>,
}

/// Whether a record header's captured and original lengths can be one of
/// ours: equal, and within the snap length.
pub(crate) fn plausible_record(captured: u32, original: u32) -> bool {
    captured == original && captured <= 65_535
}

/// The length of the complete records of the recording in `file` (from
/// the file header on): a record cut short, or a damaged one, ends it.
fn complete_len(file: &mut File) -> std::io::Result<u64> {
    use std::io::{BufReader, Seek, SeekFrom};
    let total = file.metadata()?.len();
    let mut r = BufReader::new(&mut *file);
    r.seek(SeekFrom::Start(24))?;
    let mut at: u64 = 24;
    let mut rec = [0u8; 16];
    while at + 16 <= total {
        r.read_exact(&mut rec)?;
        let word = |i: usize| u32::from_le_bytes([rec[i], rec[i + 1], rec[i + 2], rec[i + 3]]);
        if !plausible_record(word(8), word(12)) || at + 16 + u64::from(word(8)) > total {
            break;
        }
        at += 16 + u64::from(word(8));
        r.seek(SeekFrom::Start(at))?;
    }
    Ok(at)
}

/// One open recording.
#[derive(Debug)]
pub struct Recorder {
    file: std::sync::Arc<writer::RecFile>,
    buf: Vec<u8>,
    /// The conversion when it ends, and where to send it.
    convert: Option<(Conversion, std::sync::mpsc::Sender<Job>)>,
    /// The writer thread (none: written here).
    writer: Option<writer::Writer>,
}

/// The pcap file header (microsecond timestamps).
#[must_use]
pub fn file_header() -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0..4].copy_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    h[4..6].copy_from_slice(&2u16.to_le_bytes());
    h[6..8].copy_from_slice(&4u16.to_le_bytes());
    h[16..20].copy_from_slice(&65_535u32.to_le_bytes());
    h[20..24].copy_from_slice(&LINKTYPE_RAW.to_le_bytes());
    h
}

/// Internet checksum (RFC 1071) of `parts`, concatenated.
fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    let mut odd: Option<u8> = None;
    for p in parts {
        for &b in *p {
            match odd.take() {
                Some(hi) => sum += u32::from(u16::from_be_bytes([hi, b])),
                None => odd = Some(b),
            }
        }
    }
    if let Some(hi) = odd {
        sum += u32::from(u16::from_be_bytes([hi, 0]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    #[allow(clippy::cast_possible_truncation)]
    !(sum as u16)
}

/// Append one packet record: IP and UDP headers from `src` to `dst`
/// (one family) around `payload`, at `when`.
pub fn frame(
    out: &mut Vec<u8>,
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
    when: SystemTime,
) {
    let since = when.duration_since(UNIX_EPOCH).unwrap_or_default();
    let udp_len = 8 + payload.len();
    let mut udp = [0u8; 8];
    udp[0..2].copy_from_slice(&src.port().to_be_bytes());
    udp[2..4].copy_from_slice(&dst.port().to_be_bytes());
    #[allow(clippy::cast_possible_truncation)]
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    let mut ip = [0u8; 40];
    let ip = match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => {
            ip[0] = 0x45;
            #[allow(clippy::cast_possible_truncation)]
            ip[2..4].copy_from_slice(&((20 + udp_len) as u16).to_be_bytes());
            ip[6] = 0x40; // DF
            ip[8] = 64;
            ip[9] = 17;
            ip[12..16].copy_from_slice(&s.ip().octets());
            ip[16..20].copy_from_slice(&d.ip().octets());
            let c = checksum(&[&ip[..20]]);
            ip[10..12].copy_from_slice(&c.to_be_bytes());
            // The UDP checksum is optional over IPv4: left zero.
            &ip[..20]
        }
        (s, d) => {
            let v6 = |a: SocketAddr| match a {
                SocketAddr::V6(a) => a.ip().octets(),
                SocketAddr::V4(a) => a.ip().to_ipv6_mapped().octets(),
            };
            ip[0] = 0x60;
            #[allow(clippy::cast_possible_truncation)]
            ip[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            ip[6] = 17;
            ip[7] = 64;
            ip[8..24].copy_from_slice(&v6(s));
            ip[24..40].copy_from_slice(&v6(d));
            #[allow(clippy::cast_possible_truncation)]
            let pseudo_len = (udp_len as u32).to_be_bytes();
            let c = checksum(&[&ip[8..40], &pseudo_len, &[0, 0, 0, 17], &udp, payload]);
            udp[6..8].copy_from_slice(&(if c == 0 { 0xffff } else { c }).to_be_bytes());
            &ip[..40]
        }
    };
    #[allow(clippy::cast_possible_truncation)]
    let len = (ip.len() + udp_len) as u32;
    #[allow(clippy::cast_possible_truncation)]
    out.extend_from_slice(&(since.as_secs() as u32).to_le_bytes());
    out.extend_from_slice(&since.subsec_micros().to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(ip);
    out.extend_from_slice(&udp);
    out.extend_from_slice(payload);
}

impl Recorder {
    /// Open `path` to record into: a new file gets the file header, an
    /// existing recording is continued (a call recorded again, or after a
    /// restart).
    ///
    /// # Errors
    ///
    /// I/O errors, or an existing file that is not a recording of this
    /// format.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)?;
        let written = if file.metadata()?.len() == 0 {
            file.write_all(&file_header())?;
            24
        } else {
            let mut head = [0u8; 24];
            file.read_exact(&mut head)?;
            if head != file_header() {
                return Err(std::io::Error::other("not an rtpflux pcap recording"));
            }
            // Continued after a stop: a last record cut short goes, so the
            // new ones line up.
            let complete = complete_len(&mut file)?;
            if complete < file.metadata()?.len() {
                log::warn!(
                    "recording: {}: an incomplete last record removed",
                    path.display()
                );
                file.set_len(complete)?;
            }
            complete
        };
        Ok(Recorder {
            file: std::sync::Arc::new(writer::RecFile {
                file,
                path: path.to_path_buf(),
                written: std::sync::atomic::AtomicU64::new(written),
            }),
            buf: Vec::with_capacity(CHUNK + 2048),
            convert: None,
            writer: None,
        })
    }

    /// Write on the writer thread behind `writer` (the caller never waits
    /// for the disk).
    #[must_use]
    pub fn writing_on(mut self, writer: writer::Writer) -> Self {
        self.writer = Some(writer);
        self
    }

    /// The recording's file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.file.path
    }

    /// Convert the recording as `conversion` says when it ends, on the
    /// thread behind `jobs`.
    #[must_use]
    pub fn converting(
        mut self,
        conversion: Conversion,
        jobs: std::sync::mpsc::Sender<Job>,
    ) -> Self {
        self.convert = Some((conversion, jobs));
        self
    }

    /// End the recording: write what is left and hand it to the converter.
    /// `last`: the recording is over for good (not just the relay
    /// stopping), so the pcap may go once converted.
    pub fn finish(mut self, last: bool) {
        self.flush();
        if let Some((conversion, jobs)) = self.convert.take() {
            let job = Job {
                pcap: self.file.path.clone(),
                conversion,
                last,
                mix: None,
            };
            match &self.writer {
                // After the writes still queued.
                Some(w) => w.done(job, jobs),
                None => {
                    if let Err(e) = jobs.send(job) {
                        log::warn!(
                            "recording: {}: no converter left, not converted",
                            e.0.pcap.display()
                        );
                    }
                }
            }
        }
    }

    /// Record one packet; writes out a full chunk.
    pub fn packet(&mut self, src: SocketAddr, dst: SocketAddr, payload: &[u8]) {
        frame(&mut self.buf, src, dst, payload, SystemTime::now());
        if self.buf.len() >= CHUNK {
            self.flush();
        }
    }

    /// Append records made elsewhere (by [`frame`]: the kernel's copies of
    /// the packets it relayed); writes out a full chunk.
    pub fn append(&mut self, frames: &[u8]) {
        self.buf.extend_from_slice(frames);
        if self.buf.len() >= CHUNK {
            self.flush();
        }
    }

    /// Write what is collected (or hand it to the writer). A failed write
    /// (a full disk) loses these packets but not the file: what it left
    /// half-written is cut off.
    pub fn flush(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        if let Some(w) = &self.writer {
            let chunk = std::mem::replace(&mut self.buf, Vec::with_capacity(CHUNK + 2048));
            w.append(&self.file, chunk);
        } else {
            self.file.append(&self.buf);
            self.buf.clear();
        }
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.flush();
    }
}

/// A file name part from arbitrary octets (call-ids, tags): letters,
/// digits and `.-_@` kept, anything else `_`.
///
/// At most 128 characters: a longer value is cut to 111 and followed by
/// `-` and 16 hex digits of its SHA-256, so that two values sharing a long
/// prefix still name different files.
#[must_use]
pub fn name_part(raw: &[u8]) -> String {
    use sha2::Digest as _;
    use std::fmt::Write as _;
    let clean = |b: &[u8]| -> String {
        b.iter()
            .map(|&c| {
                if c.is_ascii_alphanumeric() || b".-_@".contains(&c) {
                    char::from(c)
                } else {
                    '_'
                }
            })
            .collect()
    };
    if raw.len() <= 128 {
        return clean(raw);
    }
    let mut s = clean(&raw[..111]);
    s.push('-');
    for b in &sha2::Sha256::digest(raw)[..8] {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sum_ok(parts: &[&[u8]]) -> bool {
        checksum(parts) == 0
    }

    #[test]
    fn frames_carry_valid_headers() {
        let when = UNIX_EPOCH + std::time::Duration::from_micros(1_700_000_000_123_456);
        let mut out = Vec::new();
        let payload = [0x80u8, 0, 0, 1, 2, 3, 4];
        frame(
            &mut out,
            "192.0.2.1:4000".parse().unwrap(),
            "198.51.100.7:30000".parse().unwrap(),
            &payload,
            when,
        );
        assert_eq!(
            u32::from_le_bytes(out[0..4].try_into().unwrap()),
            1_700_000_000
        );
        assert_eq!(u32::from_le_bytes(out[4..8].try_into().unwrap()), 123_456);
        let f = &out[16..];
        assert_eq!(f.len(), 20 + 8 + payload.len());
        assert!(sum_ok(&[&f[..20]]), "IPv4 header checksum");
        assert_eq!(&f[20..22], &4000u16.to_be_bytes());
        assert_eq!(&f[28..], &payload);

        out.clear();
        frame(
            &mut out,
            "[2001:db8::1]:4000".parse().unwrap(),
            "[2001:db8::7]:30000".parse().unwrap(),
            &payload,
            when,
        );
        let f = &out[16..];
        assert_eq!(f[0] >> 4, 6);
        let len = u32::try_from(8 + payload.len()).unwrap().to_be_bytes();
        assert!(
            sum_ok(&[&f[8..40], &len, &[0, 0, 0, 17], &f[40..]]),
            "UDP checksum over IPv6"
        );
        assert_eq!(name_part(b"a b/c@x.y"), "a_b_c@x.y");
        assert_eq!(file_header()[20], 101);
    }

    #[test]
    fn long_names_stay_apart() {
        let a = [b'a'; 200];
        let mut b = a;
        b[199] = b'b';
        let (na, nb) = (name_part(&a), name_part(&b));
        assert_eq!((na.len(), nb.len()), (128, 128));
        assert_ne!(na, nb, "a shared prefix, different files");
        assert_eq!(name_part(b"call 1@x"), "call_1@x");
    }
}
