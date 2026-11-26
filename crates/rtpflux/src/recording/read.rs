//! Reading a recording's pcap back: for each frame, its arrival time, the
//! relay port it was sent to and where its UDP payload lies in the file.
//! Only what [`super::frame`] writes is understood (`LINKTYPE_RAW`, IPv4 or
//! IPv6 and UDP); anything else is skipped.

use super::file_header;
use std::io::{BufReader, Read};
use std::path::Path;

/// One recorded datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Frame {
    /// Arrival time, in microseconds since the Unix epoch.
    pub time_us: u64,
    /// The relay port it was sent to.
    pub dst_port: u16,
    /// The UDP payload's offset and length in the file.
    pub offset: u64,
    pub len: usize,
    /// The payload's first 12 octets (an RTP header), zero-padded.
    pub head: [u8; 12],
}

impl Frame {
    /// A ZRTP packet (RFC 6189 §5: first octet 0x10-0x13 and the magic
    /// cookie "ZRTP"): its stream is encrypted end to end, with keys the
    /// relay never has.
    pub fn is_zrtp(&self) -> bool {
        (0x10..=0x13).contains(&self.head[0]) && &self.head[4..8] == b"ZRTP"
    }
}

/// The IP header length and UDP destination port of a raw IP frame, and
/// where its UDP payload starts.
fn udp_payload(frame: &[u8]) -> Option<(u16, usize)> {
    let ip_len = match frame.first()? >> 4 {
        4 => usize::from(frame[0] & 0x0f) * 4,
        6 => 40,
        _ => return None,
    };
    let protocol = if frame[0] >> 4 == 4 {
        *frame.get(9)?
    } else {
        *frame.get(6)?
    };
    if protocol != 17 {
        return None;
    }
    let udp = frame.get(ip_len..ip_len + 8)?;
    Some((u16::from_be_bytes([udp[2], udp[3]]), ip_len + 8))
}

/// Every UDP frame of the recording at `path`.
///
/// # Errors
///
/// When the file cannot be read or is not one of the relay's recordings.
pub(super) fn frames(path: &Path) -> std::io::Result<Vec<Frame>> {
    let mut r = BufReader::new(std::fs::File::open(path)?);
    let mut head = [0u8; 24];
    r.read_exact(&mut head)?;
    if head != file_header() {
        return Err(std::io::Error::other("not an rtpflux pcap recording"));
    }
    let mut at: u64 = 24;
    let mut out = Vec::new();
    let mut rec = [0u8; 16];
    let mut buf = Vec::new();
    loop {
        match r.read_exact(&mut rec) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let word = |i: usize| u32::from_le_bytes([rec[i], rec[i + 1], rec[i + 2], rec[i + 3]]);
        let (secs, micros, len) = (word(0), word(4), word(8) as usize);
        if !super::plausible_record(word(8), word(12)) {
            // Damaged from here (a write cut short): keep what came before.
            log::warn!(
                "recording: {}: a damaged record at offset {at}; the rest is skipped",
                path.display()
            );
            break;
        }
        buf.resize(len, 0);
        if r.read_exact(&mut buf).is_err() {
            // A frame cut short (a recording still being written): stop.
            break;
        }
        at += 16;
        if let Some((dst_port, start)) = udp_payload(&buf) {
            let payload = &buf[start..];
            let mut head = [0u8; 12];
            let n = payload.len().min(12);
            head[..n].copy_from_slice(&payload[..n]);
            out.push(Frame {
                time_us: u64::from(secs) * 1_000_000 + u64::from(micros),
                dst_port,
                offset: at + start as u64,
                len: payload.len(),
                head,
            });
        }
        at += len as u64;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::super::frame;
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn reads_back_what_is_recorded() {
        let dir = std::env::temp_dir().join(format!("rtpflux-read-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("r.pcap");
        let mut bytes = file_header().to_vec();
        let when = UNIX_EPOCH + Duration::from_micros(1_000_000_123);
        frame(
            &mut bytes,
            "192.0.2.1:4000".parse().unwrap(),
            "192.0.2.9:30000".parse().unwrap(),
            &[0x80, 0, 0, 1, 0, 0, 0, 160, 0, 0, 0, 7, 0xff],
            when,
        );
        frame(
            &mut bytes,
            "[2001:db8::1]:4000".parse().unwrap(),
            "[2001:db8::9]:30002".parse().unwrap(),
            &[1, 2, 3],
            when,
        );
        // A non-UDP frame and a truncated one are skipped.
        bytes.extend_from_slice(&[0; 8]);
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&[0x45, 0, 0, 4]);
        bytes.extend_from_slice(&[0; 8]);
        bytes.extend_from_slice(&99u32.to_le_bytes());
        bytes.extend_from_slice(&99u32.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        let f = frames(&path).unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(
            (f[0].time_us, f[0].dst_port, f[0].len),
            (1_000_000_123, 30000, 13)
        );
        assert_eq!(f[0].head[11], 7);
        assert_eq!(bytes[usize::try_from(f[0].offset).unwrap() + 12], 0xff);
        assert_eq!((f[1].dst_port, f[1].len, f[1].head[2]), (30002, 3, 3));
        assert!(!f[0].is_zrtp() && !f[1].is_zrtp());
        std::fs::write(&path, b"not a pcap at all, really").unwrap();
        assert!(frames(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn zrtp_is_recognised() {
        let mut f = Frame {
            time_us: 0,
            dst_port: 0,
            offset: 0,
            len: 12,
            head: [0x10, 0, 0, 1, b'Z', b'R', b'T', b'P', 0, 0, 0, 7],
        };
        assert!(f.is_zrtp());
        f.head[0] = 0x80; // RTP with the same octets after it
        assert!(!f.is_zrtp());
        f.head[0] = 0x10;
        f.head[4] = b'X'; // no magic cookie
        assert!(!f.is_zrtp());
    }

    #[test]
    fn a_damaged_recording_is_read_up_to_the_damage_and_continued_cleanly() {
        let dir = std::env::temp_dir().join(format!("rtpflux-damaged-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("d.pcap");
        let one = |bytes: &mut Vec<u8>, seq: u8| {
            frame(
                bytes,
                "192.0.2.1:4000".parse().unwrap(),
                "192.0.2.9:30000".parse().unwrap(),
                &[0x80, 0, 0, seq, 0, 0, 0, 160, 0, 0, 0, 7, 0xff],
                UNIX_EPOCH + Duration::from_secs(1),
            );
        };
        // Two records, then half of a third (a write cut short).
        let mut bytes = file_header().to_vec();
        one(&mut bytes, 1);
        one(&mut bytes, 2);
        let mut third = Vec::new();
        one(&mut third, 3);
        bytes.extend_from_slice(&third[..20]);
        std::fs::write(&path, &bytes).unwrap();
        // Continued (a restart): the half record goes, new ones line up.
        let mut r = super::super::Recorder::open(&path).unwrap();
        r.packet(
            "192.0.2.1:4000".parse().unwrap(),
            "192.0.2.9:30000".parse().unwrap(),
            &[0x80, 0, 0, 4, 0, 0, 0, 160, 0, 0, 0, 7, 0xff],
        );
        r.flush();
        drop(r);
        let seqs: Vec<u8> = frames(&path).unwrap().iter().map(|f| f.head[3]).collect();
        assert_eq!(seqs, [1, 2, 4]);
        // A record claiming 4 GiB is damage, not an allocation.
        let mut bytes = file_header().to_vec();
        one(&mut bytes, 1);
        bytes.extend_from_slice(&[0; 8]);
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.extend_from_slice(&[0; 64]);
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(frames(&path).unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
