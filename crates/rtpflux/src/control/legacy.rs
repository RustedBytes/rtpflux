//! Legacy ("best effort") opportunistic SRTP: before RFC 8643, an endpoint
//! offered each stream twice, in `RTP/SAVP` with its keys and then in
//! `RTP/AVP`, and the answerer took one (the other at port 0). `OSRTP:
//! offer-legacy` writes the offer to the answerer so, and folds its answer
//! back; `OSRTP: accept-legacy` folds such an offer from the offerer into
//! one opportunistic (RFC 8643) section per stream, and unfolds the answer
//! to it. The rest is the RFC 8643 handling (`keys::Osrtp`).

/// An SDP split into its session part and its media sections (each from
/// its `m=` line to the next).
fn split(sdp: &[u8]) -> (Vec<&[u8]>, Vec<Vec<&[u8]>>) {
    let mut head = Vec::new();
    let mut sections: Vec<Vec<&[u8]>> = Vec::new();
    for line in sdp
        .split(|&c| c == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .filter(|l| !l.is_empty())
    {
        if line.starts_with(b"m=") {
            sections.push(vec![line]);
        } else if let Some(s) = sections.last_mut() {
            s.push(line);
        } else {
            head.push(line);
        }
    }
    (head, sections)
}

fn join(head: &[&[u8]], sections: &[Vec<Vec<u8>>]) -> Vec<u8> {
    let mut out = Vec::new();
    for l in head {
        out.extend_from_slice(l);
        out.extend_from_slice(b"\r\n");
    }
    for s in sections {
        for l in s {
            out.extend_from_slice(l);
            out.extend_from_slice(b"\r\n");
        }
    }
    out
}

/// The `m=` line's (port, profile).
fn port_and_proto(m: &[u8]) -> (&[u8], &[u8]) {
    let mut f = m.get(2..).unwrap_or_default().split(|&c| c == b' ');
    let _kind = f.next();
    let port = f.next().unwrap_or_default();
    (port, f.next().unwrap_or_default())
}

/// The `m=` line with another port and/or profile.
fn with(m: &[u8], port: Option<&[u8]>, proto: Option<&[u8]>) -> Vec<u8> {
    let mut f: Vec<&[u8]> = m.split(|&c| c == b' ').collect();
    if let (Some(p), Some(slot)) = (port, f.get_mut(1)) {
        *slot = p;
    }
    if let (Some(p), Some(slot)) = (proto, f.get_mut(2)) {
        *slot = p;
    }
    f.join(&b" "[..])
}

fn is_plain(proto: &[u8]) -> bool {
    proto == b"RTP/AVP" || proto == b"RTP/AVPF"
}

/// The SRTP profile of a plain one.
fn secure(proto: &[u8]) -> &'static [u8] {
    if proto == b"RTP/AVPF" {
        b"RTP/SAVPF"
    } else {
        b"RTP/SAVP"
    }
}

fn has_crypto(s: &[&[u8]]) -> bool {
    s.iter().any(|l| l.starts_with(b"a=crypto:"))
}

fn without_crypto(s: &[&[u8]]) -> Vec<Vec<u8>> {
    s.iter()
        .filter(|l| !l.starts_with(b"a=crypto:"))
        .map(|l| l.to_vec())
        .collect()
}

/// A section rejected: its `m=` line at port 0 only.
fn rejected(m: &[u8], proto: Option<&[u8]>) -> Vec<Vec<u8>> {
    vec![with(m, Some(b"0"), proto)]
}

/// `offer-legacy`: each opportunistic section (a plain profile with
/// `a=crypto`) written twice, in the SRTP profile with the keys, then
/// plain without; which were (for [`fold_answer`]).
pub(super) fn duplicate(sdp: &[u8]) -> (Vec<u8>, Vec<bool>) {
    let (head, sections) = split(sdp);
    let mut out = Vec::new();
    let mut pattern = Vec::new();
    for s in &sections {
        let (_, proto) = port_and_proto(s[0]);
        if is_plain(proto) && has_crypto(s) {
            let mut srtp: Vec<Vec<u8>> = s.iter().map(|l| l.to_vec()).collect();
            srtp[0] = with(s[0], None, Some(secure(proto)));
            out.push(srtp);
            out.push(without_crypto(s));
            pattern.push(true);
        } else {
            out.push(s.iter().map(|l| l.to_vec()).collect());
            pattern.push(false);
        }
    }
    (join(&head, &out), pattern)
}

/// The answer to a [`duplicate`]d offer, one section per stream again: of
/// each pair, the one taken; the SRTP one as an opportunistic section (a
/// plain profile with its `a=crypto`), so the RFC 8643 handling reads it.
pub(super) fn fold_answer(sdp: &[u8], pattern: &[bool]) -> Option<Vec<u8>> {
    let (head, sections) = split(sdp);
    let mut out = Vec::new();
    let mut i = 0;
    for &pair in pattern {
        let s = sections.get(i)?;
        if !pair {
            out.push(s.iter().map(|l| l.to_vec()).collect());
            i += 1;
            continue;
        }
        let plain = sections.get(i + 1)?;
        let (port, proto) = port_and_proto(s[0]);
        if port == b"0" {
            out.push(without_crypto(plain));
        } else {
            let mut taken: Vec<Vec<u8>> = s.iter().map(|l| l.to_vec()).collect();
            let plain_proto: &[u8] = if proto == b"RTP/SAVPF" {
                b"RTP/AVPF"
            } else {
                b"RTP/AVP"
            };
            taken[0] = with(s[0], None, Some(plain_proto));
            out.push(taken);
        }
        i += 2;
    }
    (i == sections.len()).then(|| join(&head, &out))
}

/// `accept-legacy`: an offer's legacy pairs (an SRTP section with
/// `a=crypto`, then a plain one at the same port) as one opportunistic
/// section each; which were (for [`unfold_answer`]).
pub(super) fn fold_offer(sdp: &[u8]) -> (Vec<u8>, Vec<bool>) {
    let (head, sections) = split(sdp);
    let mut out = Vec::new();
    let mut pattern = Vec::new();
    let mut i = 0;
    while i < sections.len() {
        let s = &sections[i];
        let (port, proto) = port_and_proto(s[0]);
        let pair = sections.get(i + 1).filter(|next| {
            let (p, pr) = port_and_proto(next[0]);
            (proto == b"RTP/SAVP" || proto == b"RTP/SAVPF")
                && has_crypto(s)
                && p == port
                && is_plain(pr)
        });
        if let Some(plain) = pair {
            let (_, plain_proto) = port_and_proto(plain[0]);
            let mut one: Vec<Vec<u8>> = s.iter().map(|l| l.to_vec()).collect();
            one[0] = with(s[0], None, Some(plain_proto));
            out.push(one);
            pattern.push(true);
            i += 2;
        } else {
            out.push(s.iter().map(|l| l.to_vec()).collect());
            pattern.push(false);
            i += 1;
        }
    }
    (join(&head, &out), pattern)
}

/// The answer to a [`fold_offer`]ed offer, as the legacy offerer expects
/// it: each folded section twice, the SRTP one taken (and the plain one at
/// port 0) when the answer has keys, else the other way round.
pub(super) fn unfold_answer(sdp: &[u8], pattern: &[bool]) -> Vec<u8> {
    let (head, sections) = split(sdp);
    let mut out = Vec::new();
    for (s, &pair) in sections
        .iter()
        .zip(pattern.iter().chain(std::iter::repeat(&false)))
    {
        if !pair {
            out.push(s.iter().map(|l| l.to_vec()).collect());
            continue;
        }
        let (_, proto) = port_and_proto(s[0]);
        if has_crypto(s) {
            let mut srtp: Vec<Vec<u8>> = s.iter().map(|l| l.to_vec()).collect();
            srtp[0] = with(s[0], None, Some(secure(proto)));
            out.push(srtp);
            out.push(rejected(s[0], None));
        } else {
            out.push(rejected(s[0], Some(secure(proto))));
            out.push(s.iter().map(|l| l.to_vec()).collect());
        }
    }
    join(&head, &out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &str = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n";

    fn text(b: &[u8]) -> String {
        String::from_utf8(b.to_vec()).unwrap()
    }

    #[test]
    fn an_offer_is_duplicated_and_its_answer_folded() {
        let offer = format!(
            "{HEAD}m=audio 30000 RTP/AVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:K\r\n\
             a=sendrecv\r\nm=video 30002 RTP/AVP 96\r\n"
        );
        let (out, pattern) = duplicate(offer.as_bytes());
        assert_eq!(pattern, [true, false]);
        assert_eq!(
            text(&out),
            format!(
                "{HEAD}m=audio 30000 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:K\r\n\
                 a=sendrecv\r\nm=audio 30000 RTP/AVP 0\r\na=sendrecv\r\nm=video 30002 RTP/AVP 96\r\n"
            )
        );
        let took_srtp = format!(
            "{HEAD}m=audio 4000 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:B\r\n\
             m=audio 0 RTP/AVP 0\r\nm=video 4002 RTP/AVP 96\r\n"
        );
        assert_eq!(
            text(&fold_answer(took_srtp.as_bytes(), &pattern).unwrap()),
            format!(
                "{HEAD}m=audio 4000 RTP/AVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:B\r\n\
                 m=video 4002 RTP/AVP 96\r\n"
            )
        );
        let took_plain = format!(
            "{HEAD}m=audio 0 RTP/SAVP 0\r\nm=audio 4000 RTP/AVP 0\r\nm=video 4002 RTP/AVP 96\r\n"
        );
        assert_eq!(
            text(&fold_answer(took_plain.as_bytes(), &pattern).unwrap()),
            format!("{HEAD}m=audio 4000 RTP/AVP 0\r\nm=video 4002 RTP/AVP 96\r\n")
        );
        assert!(
            fold_answer(HEAD.as_bytes(), &pattern).is_none(),
            "sections missing"
        );
    }

    #[test]
    fn a_legacy_offer_is_folded_and_its_answer_unfolded() {
        let offer = format!(
            "{HEAD}m=audio 5000 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:A\r\n\
             m=audio 5000 RTP/AVP 0\r\n"
        );
        let (folded, pattern) = fold_offer(offer.as_bytes());
        assert_eq!(pattern, [true]);
        assert_eq!(
            text(&folded),
            format!(
                "{HEAD}m=audio 5000 RTP/AVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:A\r\n"
            )
        );
        let srtp = format!(
            "{HEAD}m=audio 30000 RTP/AVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:R\r\n"
        );
        assert_eq!(
            text(&unfold_answer(srtp.as_bytes(), &pattern)),
            format!(
                "{HEAD}m=audio 30000 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:R\r\n\
                 m=audio 0 RTP/AVP 0\r\n"
            )
        );
        let plain = format!("{HEAD}m=audio 30000 RTP/AVP 0\r\n");
        assert_eq!(
            text(&unfold_answer(plain.as_bytes(), &pattern)),
            format!("{HEAD}m=audio 0 RTP/SAVP 0\r\nm=audio 30000 RTP/AVP 0\r\n")
        );
    }
}
