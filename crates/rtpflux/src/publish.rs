//! `publish`: the answer the relay gives, on the publisher's unused side,
//! to its own offer.

/// The directions of a media section (RFC 3264 §6.1 attributes).
const DIRECTIONS: [&str; 4] = ["sendrecv", "sendonly", "recvonly", "inactive"];

/// The answer the relay gives its own offer `sdp` on a publication's
/// unused side: the same media, received by no one (`0.0.0.0`, port 9,
/// receive-only), with no BUNDLE group nor ICE.
#[must_use]
pub fn sink_answer(sdp: &[u8]) -> Vec<u8> {
    use std::fmt::Write as _;
    let text = String::from_utf8_lossy(sdp);
    let mut out = String::new();
    for line in text.lines().map(str::trim_end) {
        if let Some(c) = line.strip_prefix("c=IN ") {
            let v6 = c.starts_with("IP6");
            out.push_str(if v6 {
                "c=IN IP6 ::"
            } else {
                "c=IN IP4 0.0.0.0"
            });
        } else if let Some(m) = line.strip_prefix("m=") {
            let mut f = m.splitn(3, ' ');
            let (kind, port, rest) = (
                f.next().unwrap_or(""),
                f.next().unwrap_or("0"),
                f.next().unwrap_or(""),
            );
            let port = if port.starts_with('0') { "0" } else { "9" };
            let _ = write!(out, "m={kind} {port} {rest}\r\na=recvonly");
        } else if DIRECTIONS.iter().any(|d| line == format!("a={d}"))
            || line.starts_with("a=group:")
            || line.starts_with("a=ice-")
            || line.starts_with("a=candidate:")
            || line == "a=end-of-candidates"
        {
            continue;
        } else {
            out.push_str(line);
        }
        out.push_str("\r\n");
    }
    out.into_bytes()
}
