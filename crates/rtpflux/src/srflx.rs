//! The relay's server-reflexive address on each interface (RFC 8445
//! §5.1.1.2), learned from a STUN server (`[ice] stun_server`), for relays
//! behind a NAT whose public address is not configured (`advertise`).
//!
//! A Binding request from the interface's address reports the address the
//! server saw it come from. The relay offers it as a `typ srflx` candidate
//! on each media port, which assumes the NAT keeps the port (a 1:1 NAT or
//! an endpoint-independent, port-preserving one); where it does not, the
//! endpoint's checks still reach the relay through the host candidate's
//! NAT mapping, and the relay learns the endpoint peer-reflexively.

use crate::config::Interface;
use rtpflux_core::stun;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Per interface: the server-reflexive address, once known.
pub type Shared = Arc<RwLock<Vec<Option<IpAddr>>>>;

/// How often the addresses are asked for again.
pub const REFRESH: Duration = Duration::from_secs(300);

/// The address `server` (`host:port`) sees a datagram from `local` come
/// from; `None` without an answer in about `timeout`.
#[must_use]
pub fn discover(server: &str, local: IpAddr, timeout: Duration) -> Option<IpAddr> {
    let to: SocketAddr = server
        .to_socket_addrs()
        .ok()?
        .find(|a| a.is_ipv4() == local.is_ipv4())?;
    let sock = UdpSocket::bind(SocketAddr::new(local, 0)).ok()?;
    sock.set_read_timeout(Some(timeout / 3)).ok()?;
    let mut tid = [0u8; 12];
    rand::fill(&mut tid);
    let mut out = [0u8; 64];
    let len = stun::write_binding(&mut out, &tid)?;
    let mut buf = [0u8; 512];
    for _ in 0..3 {
        sock.send_to(&out[..len], to).ok()?;
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            if from == to
                && let Some(mapped) = stun::read_binding(&buf[..n], &tid)
            {
                return Some(mapped.ip());
            }
        }
    }
    None
}

/// Ask `server` for each interface's address now and every [`REFRESH`],
/// into `shared`; interfaces with an `advertise` address are left out.
///
/// # Errors
///
/// When the thread cannot be started.
pub fn spawn(server: String, interfaces: Vec<Interface>, shared: Shared) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("rtpflux-stun".to_owned())
        .spawn(move || {
            loop {
                let found: Vec<Option<IpAddr>> = interfaces
                    .iter()
                    .map(|i| {
                        if i.advertise.is_some() {
                            return None;
                        }
                        let a = discover(&server, i.address, Duration::from_secs(3));
                        match a {
                            Some(a) => {
                                log::debug!("ice: interface {}: server-reflexive {a}", i.name);
                            }
                            None => {
                                log::warn!("ice: interface {}: no answer from {server}", i.name);
                            }
                        }
                        a
                    })
                    .collect();
                if let Ok(mut s) = shared.write() {
                    *s = found;
                }
                std::thread::sleep(REFRESH);
            }
        })
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A STUN server answering with a fixed address.
    fn fake_server(mapped: SocketAddr) -> SocketAddr {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let at = s.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, from) = s.recv_from(&mut buf).unwrap();
            assert!(n >= 20 && buf[..2] == [0, 1]);
            let mut r = vec![0x01, 0x01, 0, 12, 0x21, 0x12, 0xa4, 0x42];
            r.extend_from_slice(&buf[8..20]);
            r.extend_from_slice(&[0, 0x20, 0, 8, 0, 1]);
            r.extend_from_slice(&(mapped.port() ^ 0x2112).to_be_bytes());
            let IpAddr::V4(v4) = mapped.ip() else {
                panic!()
            };
            for (o, c) in v4.octets().iter().zip([0x21, 0x12, 0xa4, 0x42]) {
                r.push(o ^ c);
            }
            s.send_to(&r, from).unwrap();
        });
        at
    }

    #[test]
    fn learns_the_reflexive_address() {
        let server = fake_server("203.0.113.5:40000".parse().unwrap());
        let got = discover(
            &server.to_string(),
            "127.0.0.1".parse().unwrap(),
            Duration::from_secs(2),
        );
        assert_eq!(got, Some("203.0.113.5".parse().unwrap()));
    }

    #[test]
    fn no_answer() {
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let got = discover(
            &silent.local_addr().unwrap().to_string(),
            "127.0.0.1".parse().unwrap(),
            Duration::from_millis(300),
        );
        assert_eq!(got, None);
    }
}
