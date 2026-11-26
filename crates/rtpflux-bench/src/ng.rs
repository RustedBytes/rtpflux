//! A minimal blocking `ng` client: bencoded requests, matched replies.

#[allow(clippy::wildcard_imports)]
use super::*;

/// An ng dictionary entry being built: a byte-string or a list value.
pub(super) type Entry<'a> = (&'a [u8], Option<&'a [u8]>, Option<&'a [&'a [u8]]>);

// ---------------------------------------------------------------- ng

pub(super) struct Ng {
    pub(super) sock: UdpSocket,
    pub(super) server: SocketAddr,
    pub(super) seq: u64,
    pub(super) buf: Vec<u8>,
}

impl Ng {
    pub(super) fn new(server: SocketAddr) -> Self {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("ng client socket");
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        Ng {
            sock,
            server,
            seq: 0,
            buf: vec![0; 65_535],
        }
    }

    /// Send `pairs` (keys sorted by the caller) and return the reply's
    /// `sdp`, or panic with the error reason.
    pub(super) fn request(
        &mut self,
        pairs: &[(&[u8], &[u8])],
        lists: &[(&[u8], &[&[u8]])],
    ) -> Vec<u8> {
        self.seq += 1;
        // Unique per process: the relay answers a repeated cookie from its
        // reply cache (a retransmission) without executing it again.
        let cookie = format!("b{}-{}", std::process::id(), self.seq);
        let mut entries: Vec<Entry<'_>> = pairs
            .iter()
            .map(|(k, v)| (*k, Some(*v), None))
            .chain(lists.iter().map(|(k, v)| (*k, None, Some(*v))))
            .collect();
        entries.sort_by_key(|e| e.0);
        let mut req = vec![0u8; 16_384];
        let mut e = Encoder::new(&mut req);
        e.raw(cookie.as_bytes()).unwrap();
        e.raw(b" ").unwrap();
        e.dict().unwrap();
        for (k, v, l) in entries {
            e.bytes(k).unwrap();
            if let Some(v) = v {
                e.bytes(v).unwrap();
            } else if let Some(l) = l {
                e.list().unwrap();
                for item in l {
                    e.bytes(item).unwrap();
                }
                e.end().unwrap();
            }
        }
        e.end().unwrap();
        let n = e.len();
        self.sock.send_to(&req[..n], self.server).expect("ng send");
        loop {
            let (len, _) = self
                .sock
                .recv_from(&mut self.buf)
                .expect("ng reply (is the relay running?)");
            let reply = &self.buf[..len];
            let Some(space) = reply.iter().position(|&b| b == b' ') else {
                continue;
            };
            if &reply[..space] != cookie.as_bytes() {
                continue; // a late reply to an earlier request
            }
            let Ok(Value::Dict(d)) = decode(&reply[space + 1..]) else {
                panic!("malformed ng reply")
            };
            let result = d.get_bytes(b"result").unwrap_or_default();
            assert!(
                result == b"ok" || result == b"pong",
                "ng {}: {}",
                String::from_utf8_lossy(result),
                String::from_utf8_lossy(d.get_bytes(b"error-reason").unwrap_or_default())
            );
            return d.get_bytes(b"sdp").unwrap_or_default().to_vec();
        }
    }
}
