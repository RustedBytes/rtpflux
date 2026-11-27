//! The answers the relay gives its own offer on a side no one is on: a
//! publication's (`publish`, receive-only) and that of a party made from
//! its own offer (`create from offer`, the offer's directions mirrored).

/// The directions of a media section (RFC 3264 §6.1 attributes).
const DIRECTIONS: [&str; 4] = ["sendrecv", "sendonly", "recvonly", "inactive"];

/// The answer the relay gives its own offer `sdp` on a publication's
/// unused side: the same media, received by no one (`0.0.0.0`, port 9,
/// receive-only), with no BUNDLE group nor ICE.
#[must_use]
pub fn sink_answer(sdp: &[u8]) -> Vec<u8> {
    hidden_answer(sdp, |_| "recvonly")
}

/// The answer the relay gives its own offer `sdp` on the hidden side of
/// a party made by `create from offer`: as [`sink_answer`], but each
/// section takes the direction that mirrors the offer's (RFC 3264 §6.1:
/// `sendonly` is answered `recvonly`, and the other way round), so the
/// party is answered the media it offered.
#[must_use]
pub fn mirror_answer(sdp: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(sdp);
    // The session's direction, then each section's (its own, else the
    // session's).
    let mut session = "sendrecv";
    let mut sections: Vec<&str> = Vec::new();
    for line in text.lines().map(str::trim_end) {
        if line.starts_with("m=") {
            sections.push(session);
        } else if let Some(d) = line
            .strip_prefix("a=")
            .and_then(|a| DIRECTIONS.iter().find(|d| **d == a))
        {
            match sections.last_mut() {
                Some(s) => *s = d,
                None => session = d,
            }
        }
    }
    hidden_answer(sdp, |i| match sections.get(i).copied() {
        Some("sendonly") => "recvonly",
        Some("recvonly") => "sendonly",
        Some("inactive") => "inactive",
        _ => "sendrecv",
    })
}

/// The answer of a side no one is on to the relay's offer `sdp`: at no
/// address (`0.0.0.0`, port 9), with no BUNDLE group nor ICE, each section
/// (by index) with the direction `direction` gives it.
fn hidden_answer(sdp: &[u8], direction: impl Fn(usize) -> &'static str) -> Vec<u8> {
    use std::fmt::Write as _;
    let mut index = 0;
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
            let _ = write!(out, "m={kind} {port} {rest}\r\na={}", direction(index));
            index += 1;
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

#[cfg(test)]
mod tests {
    use super::*;

    const OFFER: &str = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n\
        t=0 0\r\na=sendonly\r\nm=audio 30000 RTP/AVP 0\r\na=ice-ufrag:x\r\n\
        m=audio 30002 RTP/AVP 8\r\na=recvonly\r\nm=audio 30004 RTP/AVP 8\r\n\
        a=inactive\r\nm=video 0 RTP/AVP 96\r\n";

    #[test]
    fn a_mirrored_answer_reverses_each_sections_direction() {
        let a = String::from_utf8(mirror_answer(OFFER.as_bytes())).unwrap();
        let dirs: Vec<&str> = a
            .lines()
            .filter(|l| DIRECTIONS.iter().any(|d| l.strip_prefix("a=") == Some(*d)))
            .collect();
        // The session's `sendonly` applies to the first and the last.
        assert_eq!(
            dirs,
            ["a=recvonly", "a=sendonly", "a=inactive", "a=recvonly"],
            "{a}"
        );
        assert!(a.contains("m=audio 9 RTP/AVP 0\r\n"), "{a}");
        assert!(a.contains("m=video 0 RTP/AVP 96\r\n"), "{a}");
        assert!(
            a.contains("c=IN IP4 0.0.0.0\r\n") && !a.contains("ice-"),
            "{a}"
        );
    }

    #[test]
    fn a_sink_answer_only_receives() {
        let a = String::from_utf8(sink_answer(OFFER.as_bytes())).unwrap();
        assert_eq!(a.matches("a=recvonly").count(), 4, "{a}");
        assert!(
            !a.contains("a=sendonly") && !a.contains("a=inactive"),
            "{a}"
        );
    }
}
