//! The endpoints' SDP, and the SDES keys of the SRTP modes.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn sdp_for(addr: SocketAddr, key: Option<&MasterKey>) -> Vec<u8> {
    let (ip, port) = (addr.ip(), addr.port());
    let fam = if ip.is_ipv4() { "IP4" } else { "IP6" };
    let (proto, crypto) = match key {
        Some(k) => (
            "RTP/SAVP",
            format!(
                "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{}\r\n",
                base64(k.bytes())
            ),
        ),
        None => ("RTP/AVP", String::new()),
    };
    format!(
        "v=0\r\no=- 1 1 IN {fam} {ip}\r\ns=-\r\nc=IN {fam} {ip}\r\nt=0 0\r\nm=audio {port} {proto} 0\r\n{crypto}a=sendrecv\r\n"
    )
    .into_bytes()
}

pub(super) fn base64(bytes: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let v = chunk
            .iter()
            .enumerate()
            .fold(0u32, |v, (i, &b)| v | u32::from(b) << (16 - 8 * i));
        for k in 0..=chunk.len() {
            out.push(char::from(B64[(v >> (18 - 6 * k) & 63) as usize]));
        }
        out.extend(std::iter::repeat_n('=', 3 - chunk.len()));
    }
    out
}

/// A deterministic master key per call and side (load generation only).
pub(super) fn bench_key(call: usize, side: u8) -> MasterKey {
    let mut key = [0u8; 30];
    for (i, b) in key.iter_mut().enumerate() {
        #[allow(clippy::cast_possible_truncation)]
        let x = (call.wrapping_mul(2_654_435_761) ^ (i * 40_503) ^ usize::from(side) << 20) as u8;
        *b = x.wrapping_add(side);
    }
    MasterKey::new(Suite::AesCm128HmacSha1_80, &key).unwrap_or_else(|| unreachable!("30 octets"))
}

/// The relay's SDES key in an SDP it wrote.
pub(super) fn relay_key(sdp: &[u8]) -> MasterKey {
    let mut m = [Media::EMPTY; MAX_MEDIA];
    read_media(sdp, &mut m).expect("relay SDP");
    m[0].crypto.expect("the relay's a=crypto").key
}

pub(super) fn relay_port(sdp: &[u8]) -> SocketAddr {
    let mut m = [Media::EMPTY; MAX_MEDIA];
    let n = read_media(sdp, &mut m).expect("relay SDP");
    assert!(n >= 1, "relay SDP has no media");
    SocketAddr::new(m[0].address.expect("relay SDP address"), m[0].port)
}
