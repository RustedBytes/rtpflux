//! Tests of SDP reading and rewriting.

#![allow(clippy::wildcard_imports)]

use super::read::*;
use super::rewrite::*;
use super::*;
use rtpflux_srtp::MASTER_LEN;

fn pt(n: u8) -> Pt {
    Pt::new(n).unwrap()
}

const OFFER: &[u8] = b"v=0\r\n\
o=alice 2890844526 2890844526 IN IP4 192.0.2.10\r\n\
s=-\r\n\
c=IN IP4 192.0.2.10\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0 8 101\r\n\
a=rtpmap:101 telephone-event/8000\r\n\
a=rtcp:49181 IN IP4 192.0.2.10\r\n\
a=ice-ufrag:abcd\r\n\
a=candidate:1 1 UDP 2130706431 192.0.2.10 49170 typ host\r\n\
a=sendrecv\r\n\
m=video 0 RTP/AVP 96\r\n\
c=IN IP4 192.0.2.11\r\n";

fn media(sdp: &[u8]) -> ([Media; MAX_MEDIA], usize) {
    let mut out = [Media::EMPTY; MAX_MEDIA];
    let n = read_media(sdp, &mut out).unwrap();
    (out, n)
}

#[test]
fn bodies_are_checked_before_reading() {
    assert_eq!(check_body(OFFER), Ok(()));
    for (body, want) in [
        (&b"hello"[..], SdpError::NotSdp),
        (b"", SdpError::NotSdp),
        (b"o=- 1 1 IN IP4 192.0.2.1\r\nv=0\r\n", SdpError::NotSdp),
        // A section with a port and no c= anywhere.
        (b"v=0\r\nm=audio 5000 RTP/AVP 0\r\n", SdpError::NoConnection),
        (
            b"v=0\r\nm=audio 5000 RTP/AVP 0\r\nc=IN IP4 192.0.2.1\r\nm=video 5002 RTP/AVP 96\r\n",
            SdpError::NoConnection,
        ),
    ] {
        assert_eq!(check_body(body), Err(want), "{body:?}");
    }
    for ok in [
        // No media at all (RFC 3264 allows it), a session-level c=, a
        // rejected section without one, media-level c= lines, LF endings.
        &b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\n"[..],
        b"v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 5000 RTP/AVP 0\r\nm=video 5002 RTP/AVP 96\r\n",
        b"v=0\r\nm=audio 5000 RTP/AVP 0\r\nc=IN IP4 192.0.2.1\r\nm=video 0 RTP/AVP 96\r\n",
        b"v=0\nm=audio 5000/2 RTP/AVP 0\nc=IN IP6 ::1\n",
    ] {
        assert_eq!(check_body(ok), Ok(()), "{ok:?}");
    }
}

#[test]
fn hold_is_read_from_the_direction_attributes() {
    let held = |sdp: &[u8]| {
        let (m, n) = media(sdp);
        let mut out = [false; 3];
        for (o, m) in out.iter_mut().zip(&m[..n]) {
            *o = m.direction.held();
        }
        (out, n)
    };
    let c = "v=0\r\nc=IN IP4 192.0.2.1\r\n";
    let sdp = std::format!(
        "{c}m=audio 1 RTP/AVP 0\r\na=sendonly\r\nm=audio 2 RTP/AVP 0\r\na=recvonly\r\nm=audio 3 RTP/AVP 0\r\na=sendrecv\r\n"
    );
    assert_eq!(held(sdp.as_bytes()), ([true, true, false], 3));
    // A session-level direction is every section's default.
    let sdp = std::format!(
        "{c}a=inactive\r\nm=audio 1 RTP/AVP 0\r\nm=audio 2 RTP/AVP 0\r\na=sendrecv\r\n"
    );
    assert_eq!(held(sdp.as_bytes()), ([true, false, false], 2));
    assert_eq!(held(OFFER), ([false, false, false], 2));
}

#[test]
fn reads_media_sections() {
    let (m, n) = media(OFFER);
    assert_eq!(n, 2);
    assert_eq!(m[0].port, 49170);
    assert_eq!(m[0].address, Some("192.0.2.10".parse().unwrap()));
    assert_eq!(m[0].rtcp_port, 49181);
    assert_eq!(m[1].port, 0);
    assert_eq!(
        m[1].address,
        Some("192.0.2.11".parse().unwrap()),
        "media c= wins"
    );
    assert_eq!(m[1].rtcp_port, 1);
}

#[test]
fn rtcp_defaults_and_mux_and_lf_endings() {
    let sdp = b"v=0\nc=IN IP6 2001:db8::1\nm=audio 4000 RTP/AVP 0\na=rtcp-mux\n";
    let (m, n) = media(sdp);
    assert_eq!(n, 1);
    assert_eq!((m[0].rtcp_port, m[0].rtcp_mux), (4001, true));
    assert_eq!(m[0].address, Some("2001:db8::1".parse().unwrap()));
}

#[test]
fn rewrites_addresses_ports_rtcp_and_strips_ice() {
    // The video section is rejected (port 0): the plan says so with port 0.
    let relayed = [Relayed::ports(30000, 30001), Relayed::ports(0, 0)];
    let plan = Plan {
        address: "203.0.113.1".parse().unwrap(),
        media: &relayed,
        replace_origin: true,
        bundle: &[],
        keep_connection: false,
        session: SessionEdits::NONE,
    };
    let mut buf = [0u8; 1024];
    let n = rewrite(OFFER, &plan, &mut buf).unwrap();
    let out = core::str::from_utf8(&buf[..n]).unwrap();
    let expected = "v=0\r\n\
o=alice 2890844526 2890844526 IN IP4 203.0.113.1\r\n\
s=-\r\n\
c=IN IP4 203.0.113.1\r\n\
t=0 0\r\n\
m=audio 30000 RTP/AVP 0 8 101\r\n\
a=rtpmap:101 telephone-event/8000\r\n\
a=rtcp:30001 IN IP4 203.0.113.1\r\n\
a=sendrecv\r\n\
m=video 0 RTP/AVP 96\r\n\
c=IN IP4 203.0.113.1\r\n";
    assert_eq!(out, expected);
    // the rewritten SDP reads back as the relay's
    let (m, k) = media(&buf[..n]);
    assert_eq!(k, 2);
    assert_eq!((m[0].port, m[0].rtcp_port), (30000, 30001));
}

#[test]
fn keeps_origin_unless_asked_and_ipv6() {
    let relayed = [Relayed::ports(30000, 30001)];
    let sdp =
        b"v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\nc=IN IP4 192.0.2.10\r\nm=audio 4000/2 RTP/AVP 0\r\n";
    let plan = Plan {
        address: "2001:db8::7".parse().unwrap(),
        media: &relayed,
        replace_origin: false,
        bundle: &[],
        keep_connection: false,
        session: SessionEdits::NONE,
    };
    let mut buf = [0u8; 256];
    let n = rewrite(sdp, &plan, &mut buf).unwrap();
    let out = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(out.contains("o=- 1 1 IN IP4 192.0.2.10\r\n"));
    assert!(out.contains("c=IN IP6 2001:db8::7\r\n"));
    assert!(out.contains("m=audio 30000/2 RTP/AVP 0\r\n"));
}

/// `a=zrtp-hash` stays where the relay passes media through, and goes
/// (session- and media-level) where it transforms it.
#[test]
fn zrtp_hash_kept_or_removed() {
    let sdp = b"v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\nc=IN IP4 192.0.2.10\r\na=zrtp-hash:1.10 aa\r\n\
        m=audio 4000 RTP/AVP 0\r\na=zrtp-hash:1.10 bb\r\nm=audio 4002 RTP/AVP 0\r\na=zrtp-hash:1.10 cc\r\n";
    let out = |strip: [bool; 2]| {
        let relayed = [
            Relayed {
                strip_zrtp: strip[0],
                ..Relayed::ports(30000, 30001)
            },
            Relayed {
                strip_zrtp: strip[1],
                ..Relayed::ports(30002, 30003)
            },
        ];
        let plan = Plan {
            address: "192.0.2.1".parse().unwrap(),
            media: &relayed,
            replace_origin: false,
            bundle: &[],
            keep_connection: false,
            session: SessionEdits::NONE,
        };
        let mut buf = [0u8; 512];
        let n = rewrite(sdp, &plan, &mut buf).unwrap();
        std::string::String::from_utf8(buf[..n].to_vec()).unwrap()
    };
    let plain = out([false, false]);
    assert!(
        ["aa", "bb", "cc"]
            .iter()
            .all(|h| plain.contains(&std::format!("a=zrtp-hash:1.10 {h}\r\n"))),
        "{plain}"
    );
    // The second section is transformed: its hash and the session's go.
    let one = out([false, true]);
    assert!(
        one.contains("zrtp-hash:1.10 bb") && !one.contains(" cc") && !one.contains(" aa"),
        "{one}"
    );
    assert!(!out([true, true]).contains("zrtp-hash"));
}

#[test]
fn errors() {
    let relayed = [Relayed::ports(30000, 30001)];
    let plan = Plan {
        address: "203.0.113.1".parse().unwrap(),
        media: &relayed,
        replace_origin: false,
        bundle: &[],
        keep_connection: false,
        session: SessionEdits::NONE,
    };
    let mut small = [0u8; 16];
    assert_eq!(rewrite(OFFER, &plan, &mut small), Err(SdpError::Overflow));
    let mut buf = [0u8; 1024];
    assert_eq!(
        rewrite(OFFER, &plan, &mut buf),
        Err(SdpError::Malformed),
        "plan misses a media section"
    );
    let mut m = [Media::EMPTY; MAX_MEDIA];
    assert_eq!(
        read_media(b"m=audio x RTP/AVP 0\r\n", &mut m),
        Err(SdpError::Malformed)
    );
    // A host name is legal (no address); another family is not.
    assert_eq!(
        read_media(b"c=IN IP4 2001:db8::1\r\n", &mut m),
        Err(SdpError::Malformed)
    );
    let line = b"m=audio 1 RTP/AVP 0\r\n";
    let mut many = [0u8; 21 * (MAX_MEDIA + 1)];
    for chunk in many.chunks_mut(line.len()) {
        chunk.copy_from_slice(line);
    }
    assert_eq!(read_media(&many, &mut m), Err(SdpError::TooManyMedia));
}

const KEY: [u8; MASTER_LEN] = [
    0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0, 0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39,
    0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb, 0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6,
];
const KEY_B64: &str = "4fl6DT4Bi+DWT6MsBt5BOQ7Gda1Jiv7rtpYLOqvm";

fn secure_offer() -> std::string::String {
    std::format!(
        "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
m=audio 4000 RTP/SAVP 0 8\r\n\
a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejEy\r\n\
a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:{KEY_B64}|2^20|1:4\r\n\
a=crypto:3 AES_CM_128_HMAC_SHA1_32 inline:{KEY_B64}|2^31\r\n\
a=crypto:4 AES_CM_128_HMAC_SHA1_80 inline:{KEY_B64}\r\n\
a=sendrecv\r\n"
    )
}

extern crate std;

#[test]
fn reads_transport_and_the_first_usable_crypto_line() {
    let offer = secure_offer();
    let (m, n) = media(offer.as_bytes());
    assert_eq!(n, 1);
    assert_eq!(m[0].transport, Transport::Savp);
    assert!(m[0].transport.is_secure());
    // tag 1: unsupported suite; tag 2: MKI; tag 3 is the first usable.
    let c = m[0].crypto.unwrap();
    assert_eq!(c.tag, 3);
    assert_eq!(c.key.suite, Suite::AesCm128HmacSha1_32);
    assert_eq!(c.key.bytes(), &KEY[..]);
    let (plain, _) = media(OFFER);
    assert_eq!(
        (plain[0].transport, plain[0].crypto),
        (Transport::Avp, None)
    );
    assert_eq!(
        Transport::parse(b"UDP/TLS/RTP/SAVPF"),
        Transport::UdpTlsSavpf
    );
    assert_eq!(Transport::parse(b"DCCP/TLS/RTP/SAVPF"), Transport::Other);
}

#[test]
fn unusable_keys_are_ignored() {
    for bad in [
        "inline:4fl6DT4Bi+DWT6MsBt5BOQ7Gda1Jiv7rtpYL", // short
        "inline:4fl6DT4Bi+DWT6MsBt5BOQ7Gda1Jiv7rtpYLOqvmAA==", // long
        "inline:4fl6DT4Bi+DWT6MsBt5BOQ7Gda1Jiv7rtpYLOqv!", // alphabet
        "inline:4fl6DT4Bi+DWT6MsBt5BOQ7Gda1Jiv7rtpYLOqvm;inline:4fl6DT4Bi+DWT6MsBt5BOQ7Gda1Jiv7rtpYLOqvm",
        "inline:4fl6DT4Bi+DWT6MsBt5BOQ7Gda1Jiv7rtpYLOqvm UNENCRYPTED_SRTP",
        "4fl6DT4Bi+DWT6MsBt5BOQ7Gda1Jiv7rtpYLOqvm",
    ] {
        let sdp =
            std::format!("m=audio 4000 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 {bad}\r\n");
        let (m, _) = media(sdp.as_bytes());
        assert_eq!(m[0].crypto, None, "{bad}");
    }
}

#[test]
fn rewrites_transport_and_keys() {
    let offer = secure_offer();
    let mine = Crypto {
        tag: 1,
        key: MasterKey {
            suite: Suite::AesCm128HmacSha1_80,
            key: MasterKey::new(Suite::AesCm128HmacSha1_80, &[7; MASTER_LEN])
                .unwrap()
                .key,
            policy: rtpflux_srtp::Policy::NONE,
        },
    };
    let address = "203.0.113.1".parse().unwrap();
    let mut buf = [0u8; 1024];
    // SRTP towards a plain-RTP side: profile RTP/AVP, no keys.
    let relayed = [Relayed {
        transport: Some(Transport::Avp),
        ..Relayed::ports(30000, 30001)
    }];
    let plan = Plan {
        address,
        media: &relayed,
        replace_origin: false,
        bundle: &[],
        keep_connection: false,
        session: SessionEdits::NONE,
    };
    let n = rewrite(offer.as_bytes(), &plan, &mut buf).unwrap();
    let out = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(out.contains("m=audio 30000 RTP/AVP 0 8\r\n"), "{out}");
    assert!(!out.contains("a=crypto"), "{out}");
    // Towards an SRTP side: the relay's key is the only crypto line.
    let relayed = [Relayed {
        transport: Some(Transport::Savp),
        crypto: Some(mine),
        ..Relayed::ports(30000, 30001)
    }];
    let plan = Plan {
        address,
        media: &relayed,
        replace_origin: false,
        bundle: &[],
        keep_connection: false,
        session: SessionEdits::NONE,
    };
    let n = rewrite(OFFER, &plan, &mut buf).unwrap_err();
    assert_eq!(n, SdpError::Malformed, "OFFER has two media sections");
    let n = rewrite(offer.as_bytes(), &plan, &mut buf).unwrap();
    let out = core::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(out.matches("a=crypto:").count(), 1, "{out}");
    assert!(out.contains("m=audio 30000 RTP/SAVP 0 8\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH\r\n"), "{out}");
    let (m, _) = media(&buf[..n]);
    assert_eq!(m[0].crypto, Some(mine), "the written key reads back");
}

#[test]
fn dtls_attributes_are_read_and_replaced() {
    use crate::dtls::{HashFn, Setup};
    let octets = |n: usize, v: &str| std::vec![v; n].join(":");
    let sdp = std::format!(
        "v=0\r\nc=IN IP4 192.0.2.1\r\na=fingerprint:sha-256 {}\r\na=setup:actpass\r\n\
m=audio 4000 UDP/TLS/RTP/SAVPF 111\r\na=fingerprint:md5 00:11\r\na=setup:active\r\na=tls-id:abc\r\n\
m=video 4002 UDP/TLS/RTP/SAVPF 96\r\na=fingerprint:sha-1 {}\r\n",
        octets(32, "AA"),
        octets(20, "01")
    );
    let mut m = [Media::EMPTY; MAX_MEDIA];
    assert_eq!(read_media(sdp.as_bytes(), &mut m).unwrap(), 2);
    assert!(m[0].transport.is_dtls() && !m[0].transport.is_sdes());
    assert_eq!(m[0].setup, Some(Setup::Active), "media level wins");
    assert_eq!(m[1].setup, Some(Setup::Actpass), "session level otherwise");
    // md5 is not checked: the session-level sha-256 applies to audio.
    assert_eq!(m[0].fingerprints[0].unwrap().hash, HashFn::Sha256);
    assert_eq!(m[1].fingerprints[0].unwrap().hash, HashFn::Sha1);
    let fp = "sha-256 01:23";
    let relayed = [
        Relayed {
            dtls: Some(DtlsAttrs {
                setup: Setup::Passive,
                fingerprint: fp,
            }),
            ..Relayed::ports(30000, 30001)
        },
        Relayed::ports(30002, 30003),
    ];
    let plan = Plan {
        address: "203.0.113.1".parse().unwrap(),
        media: &relayed,
        replace_origin: false,
        bundle: &[],
        keep_connection: false,
        session: SessionEdits::NONE,
    };
    let mut buf = [0u8; 1024];
    let n = rewrite(sdp.as_bytes(), &plan, &mut buf).unwrap();
    let out = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(
        !out.contains("AA:BB")
            && !out.contains("md5")
            && !out.contains("tls-id")
            && !out.contains("01:02"),
        "{out}"
    );
    assert!(out.contains("m=audio 30000 UDP/TLS/RTP/SAVPF 111\r\na=setup:passive\r\na=fingerprint:sha-256 01:23\r\n"), "{out}");
    assert_eq!(out.matches("a=setup").count(), 1, "{out}");
}

#[test]
fn bundle_group_is_read_and_answered() {
    let offer = b"v=0\r\na=group:BUNDLE 0 1\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\na=rtcp-mux\r\n\
m=video 0 UDP/TLS/RTP/SAVPF 96 97\r\na=mid:1\r\na=bundle-only\r\na=rtcp-mux\r\n";
    let mut group = [None; MAX_MEDIA];
    let n = bundle_group(offer, &mut group);
    assert_eq!(n, 2);
    assert_eq!(group[1].unwrap().as_bytes(), b"1");
    let mut m = [Media::EMPTY; MAX_MEDIA];
    read_media(offer, &mut m).unwrap();
    assert!(m[1].bundle_only && m[1].port == 0);
    assert_eq!(m[1].payload_types.as_slice(), &[pt(96), pt(97)]);
    // The answer: one port for both, the group, mid and rtcp-mux.
    let relayed = [
        Relayed {
            mid: Some(b"0"),
            rtcp_mux: true,
            ..Relayed::ports(40000, 40001)
        },
        Relayed {
            mid: Some(b"1"),
            rtcp_mux: true,
            ..Relayed::ports(40000, 40001)
        },
    ];
    let ids: [&[u8]; 2] = [b"0", b"1"];
    let plan = Plan {
        address: "203.0.113.1".parse().unwrap(),
        media: &relayed,
        replace_origin: false,
        bundle: &ids,
        keep_connection: false,
        session: SessionEdits::NONE,
    };
    let mut buf = [0u8; 1024];
    let n = rewrite(offer, &plan, &mut buf).unwrap();
    let out = core::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(out.matches("a=group:BUNDLE 0 1\r\n").count(), 1, "{out}");
    assert!(
        out.contains("m=video 40000 UDP/TLS/RTP/SAVPF 96 97\r\na=mid:1\r\na=rtcp-mux\r\n"),
        "{out}"
    );
    assert!(!out.contains("bundle-only"), "{out}");
    assert_eq!(out.matches("a=mid:1").count(), 1, "{out}");
    assert_eq!(out.matches("a=rtcp-mux").count(), 2, "{out}");
}

#[test]
fn opus_is_read_and_added() {
    let sdp = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
m=audio 4000 RTP/AVP 0 109\r\na=rtpmap:109 OPUS/48000/2\r\na=fmtp:109 useinbandfec=1\r\n";
    let mut m = [Media::EMPTY; MAX_MEDIA];
    read_media(sdp, &mut m).unwrap();
    assert_eq!(m[0].opus, Some(pt(109)));
    assert_eq!(
        (
            m[0].codec_of(pt(0)),
            m[0].codec_of(pt(109)),
            m[0].codec_of(pt(96))
        ),
        (Some(Codec::Pcmu), Some(Codec::Opus), None)
    );
    assert_eq!(
        parse_opus(b"111 opus/8000"),
        None,
        "Opus is always 48000 Hz"
    );
    assert_eq!(Codec::from_name(b"Opus"), Some(Codec::Opus));
    // Opus replaces PCMU: its rtpmap is written, PCMU's lines go.
    let media = [Relayed {
        formats: [Some(FormatEdit::Replace(pt(0), pt(111))), None],
        dynamic: Some((pt(111), Codec::Opus)),
        ..Relayed::ports(30000, 30001)
    }];
    let plan = Plan {
        address: "203.0.113.1".parse().unwrap(),
        media: &media,
        replace_origin: false,
        bundle: &[],
        keep_connection: false,
        session: SessionEdits::NONE,
    };
    let mut buf = [0u8; 1024];
    let n = rewrite(sdp, &plan, &mut buf).unwrap();
    let out = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(
        out.contains("m=audio 30000 RTP/AVP 111 109\r\na=rtpmap:111 opus/48000/2\r\n"),
        "{out}"
    );
}

#[test]
fn format_edits_for_transcoding() {
    let sdp = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
m=audio 4000 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n\
a=fmtp:101 0-15\r\na=sendrecv\r\n";
    let run = |formats: [Option<FormatEdit>; 2], check: &dyn Fn(&str)| {
        let media = [Relayed {
            formats,
            ..Relayed::ports(30000, 30001)
        }];
        let plan = Plan {
            address: "203.0.113.1".parse().unwrap(),
            media: &media,
            replace_origin: false,
            bundle: &[],
            keep_connection: false,
            session: SessionEdits::NONE,
        };
        let mut out = [0u8; 1024];
        let n = rewrite(sdp, &plan, &mut out).unwrap();
        check(core::str::from_utf8(&out[..n]).unwrap());
    };
    run([Some(FormatEdit::Replace(pt(0), pt(8))), None], &|t| {
        assert!(
            t.contains("m=audio 30000 RTP/AVP 8 101\r\na=rtpmap:8 PCMA/8000\r\n"),
            "{t}"
        );
        assert!(!t.contains("rtpmap:0 "), "{t}");
        assert!(t.contains("a=fmtp:101 0-15\r\n"), "{t}");
    });
    run([Some(FormatEdit::Append(pt(8))), None], &|t| {
        assert!(
            t.contains("m=audio 30000 RTP/AVP 0 101 8\r\na=rtpmap:8 PCMA/8000\r\n"),
            "{t}"
        );
        assert!(t.contains("a=rtpmap:0 PCMU/8000\r\n"), "{t}");
    });
    run(
        [
            Some(FormatEdit::Remove(pt(101))),
            Some(FormatEdit::Append(pt(0))),
        ],
        &|t| {
            assert!(t.contains("m=audio 30000 RTP/AVP 0\r\n"), "{t}");
            assert!(!t.contains("101"), "{t}");
        },
    );
}

#[test]
fn transports_mids_formats_and_codecs() {
    for t in [
        Transport::Avp,
        Transport::Avpf,
        Transport::Savp,
        Transport::Savpf,
        Transport::UdpTlsSavp,
        Transport::UdpTlsSavpf,
    ] {
        assert_eq!(Transport::parse(t.name().unwrap().as_bytes()), t);
    }
    assert_eq!(Transport::parse(b"TCP/MRCPv2"), Transport::Other);
    assert_eq!(Transport::Other.name(), None);
    assert!(Mid::new(b"").is_none());
    assert!(Mid::new(b"a b").is_none());
    assert!(Mid::new(&[b'm'; MAX_MID + 1]).is_none());
    assert_eq!(
        std::format!("{:?}", Mid::new(b"audio").unwrap()),
        "Mid(\"audio\")"
    );
    let mut types = PayloadTypes::EMPTY;
    for n in 0..=u8::try_from(MAX_FORMATS).unwrap() {
        types.push(pt(n));
    }
    assert_eq!(types.as_slice().len(), MAX_FORMATS, "the rest is dropped");
    assert_eq!((Codec::Pcmu.clock(), Codec::Opus.clock()), (8000, 48_000));
}

/// Rewrite `sdp` for one relayed section on port 30000 of 203.0.113.1.
fn rewrite_one(sdp: &[u8]) -> Result<std::string::String, SdpError> {
    let relayed = [Relayed::ports(30000, 30001)];
    let plan = Plan {
        address: "203.0.113.1".parse().unwrap(),
        media: &relayed,
        replace_origin: true,
        bundle: &[],
        keep_connection: false,
        session: SessionEdits::NONE,
    };
    let mut buf = [0u8; 1024];
    let n = rewrite(sdp, &plan, &mut buf)?;
    Ok(std::string::String::from(
        core::str::from_utf8(&buf[..n]).unwrap(),
    ))
}

#[test]
fn media_lines_are_read_and_rewritten_alike() {
    // Two spaces: read and rewritten with the same fields, single-spaced.
    let sdp = b"v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio  4000 RTP/AVP  0 8\r\n";
    let (m, n) = media(sdp);
    assert_eq!((n, m[0].port), (1, 4000));
    let out = rewrite_one(sdp).unwrap();
    assert!(out.contains("m=audio 30000 RTP/AVP 0 8\r\n"), "{out}");
    // Formats of 128 and above are not RTP payload types: kept as they
    // are, and they hide no other format.
    let out =
        rewrite_one(b"v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 4000 RTP/AVP 0 200 72\r\n").unwrap();
    assert!(out.contains("m=audio 30000 RTP/AVP 0 200 72\r\n"), "{out}");
    // A signed port is not a port; nor is one whose RTCP port would wrap.
    let mut out = [Media::EMPTY; MAX_MEDIA];
    for bad in [
        &b"v=0\r\nm=audio +4000 RTP/AVP 0\r\n"[..],
        b"v=0\r\nm=audio 65535 RTP/AVP 0\r\n",
    ] {
        assert_eq!(
            read_media(bad, &mut out),
            Err(SdpError::Malformed),
            "{bad:?}"
        );
    }
}

#[test]
fn connection_lines_accept_host_names_and_check_the_family() {
    let (m, n) = media(b"v=0\r\nc=IN IP4 pbx.example.com\r\nm=audio 4000 RTP/AVP 0\r\n");
    assert_eq!((n, m[0].address), (1, None), "a host name: no address");
    let out =
        rewrite_one(b"v=0\r\nc=IN IP4 pbx.example.com\r\nm=audio 4000 RTP/AVP 0\r\n").unwrap();
    assert!(out.contains("c=IN IP4 203.0.113.1\r\n"), "{out}");
    let mut out = [Media::EMPTY; MAX_MEDIA];
    for bad in [
        &b"v=0\r\nc=IN IP4 ::1\r\nm=audio 4000 RTP/AVP 0\r\n"[..],
        b"v=0\r\nc=IN IP6 192.0.2.1\r\nm=audio 4000 RTP/AVP 0\r\n",
        b"v=0\r\nc=XX IP4 192.0.2.1\r\nm=audio 4000 RTP/AVP 0\r\n",
    ] {
        assert_eq!(
            read_media(bad, &mut out),
            Err(SdpError::Malformed),
            "{bad:?}"
        );
    }
}

#[test]
fn a_session_level_rtcp_attribute_is_dropped() {
    let sdp = b"v=0\r\nc=IN IP4 192.0.2.1\r\na=rtcp:5001\r\nm=audio 4000 RTP/AVP 0\r\n";
    assert_eq!(media(sdp).1, 1);
    let out = rewrite_one(sdp).unwrap();
    assert!(!out.contains("a=rtcp:5001"), "{out}");
}

#[test]
fn only_the_bundle_semantics_is_bundle() {
    let mut out = [None; MAX_MEDIA];
    assert_eq!(
        bundle_group(
            b"v=0\r\na=group:BUNDLEX a b\r\nm=audio 0 RTP/AVP 0\r\n",
            &mut out
        ),
        0
    );
    assert_eq!(
        bundle_group(
            b"v=0\r\na=group:BUNDLE a b\r\nm=audio 0 RTP/AVP 0\r\n",
            &mut out
        ),
        2
    );
}

/// AMR is transcodable only octet-aligned with the relay's mode allowed;
/// G.722 and G.729 by their static payload types.
#[test]
fn codecs_of_payload_types() {
    let sdp = b"v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 4000 RTP/AVP 9 18 96 97 98 99\r\n\
        a=rtpmap:96 AMR/8000\r\na=fmtp:96 octet-align=1; mode-set=0,2,7\r\n\
        a=rtpmap:97 AMR-WB/16000\r\na=fmtp:97 octet-align=1;mode-set=0,1\r\n\
        a=rtpmap:98 opus/48000/2\r\n";
    let (m, n) = media(sdp);
    assert_eq!(n, 1);
    let m = &m[0];
    assert_eq!(m.codec_of(pt(9)), Some(Codec::G722));
    assert_eq!(m.codec_of(pt(18)), Some(Codec::G729));
    assert_eq!(m.codec_of(pt(96)), Some(Codec::Amr));
    assert_eq!(m.codec_of(pt(97)), None, "AMR-WB without mode 2");
    assert_eq!(m.codec_of(pt(98)), Some(Codec::Opus));
    assert_eq!(m.codec_of(pt(99)), None);
    assert_eq!(
        (m.dynamic_pt(Codec::Amr), m.dynamic_pt(Codec::AmrWb)),
        (Some(pt(96)), Some(pt(97)))
    );
    // The default (bandwidth-efficient) packing is not transcoded.
    let (m, _) =
        media(b"v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 4000 RTP/AVP 96\r\na=rtpmap:96 AMR/8000\r\n");
    assert_eq!(m[0].codec_of(pt(96)), None);
    for c in Codec::ALL {
        assert_eq!(Codec::from_name(c.name().as_bytes()), Some(c));
        assert_eq!(
            c.static_pt().and_then(Codec::of_static),
            c.static_pt().map(|_| c)
        );
    }
    assert_eq!(Codec::from_name(b"g722"), Some(Codec::G722));
}

#[test]
fn full_and_lite_ice_attributes() {
    let ice = |lite: bool, trickle: bool, srflx: Option<IpAddr>| IceAttrs {
        ufrag: b"rfxUfrag",
        pwd: b"0123456789abcdefghijklmn",
        rtcp_candidate: true,
        candidates: true,
        lite,
        trickle,
        srflx,
    };
    let sdp = b"v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\nc=IN IP4 10.0.0.1\r\nm=audio 4000 RTP/AVP 0\r\n";
    let write = |i: IceAttrs<'static>| {
        let relayed = [Relayed {
            ice: Some(i),
            ..Relayed::ports(30000, 30001)
        }];
        let plan = Plan {
            address: "10.0.0.2".parse().unwrap(),
            media: &relayed,
            replace_origin: false,
            bundle: &[],
            keep_connection: false,
            session: SessionEdits::NONE,
        };
        let mut buf = [0u8; 2048];
        let n = rewrite(sdp, &plan, &mut buf).unwrap();
        let mut out = [0u8; 2048];
        out[..n].copy_from_slice(&buf[..n]);
        (out, n)
    };
    // Full, behind a NAT: ice2, host and server-reflexive candidates.
    let (out, n) = write(ice(false, true, Some("203.0.113.7".parse().unwrap())));
    let out = core::str::from_utf8(&out[..n]).unwrap();
    assert!(!out.contains("a=ice-lite"), "{out}");
    assert!(out.contains("a=ice-options:trickle ice2\r\n"), "{out}");
    assert!(
        out.contains("a=candidate:1 1 UDP 2130706431 10.0.0.2 30000 typ host\r\n"),
        "{out}"
    );
    assert!(
        out.contains("a=candidate:1 2 UDP 2130706430 10.0.0.2 30001 typ host\r\n"),
        "{out}"
    );
    assert!(
        out.contains("a=candidate:2 1 UDP 1694498815 203.0.113.7 30000 typ srflx raddr 10.0.0.2 rport 30000\r\n"),
        "{out}"
    );
    assert!(
        out.contains("a=candidate:2 2 UDP 1694498814 203.0.113.7 30001 typ srflx raddr 10.0.0.2 rport 30001\r\n"),
        "{out}"
    );
    assert!(out.find("typ srflx") < out.find("a=end-of-candidates"));
    // Lite: a=ice-lite, no options; a srflx equal to the host is left out.
    let (out, n) = write(ice(true, true, Some("10.0.0.2".parse().unwrap())));
    let out = core::str::from_utf8(&out[..n]).unwrap();
    assert!(
        out.contains("a=ice-lite\r\n") && !out.contains("ice-options"),
        "{out}"
    );
    assert!(!out.contains("srflx"), "{out}");
}

/// An `a=rtpmap` counts only for a format the m-line lists: telephone
/// events, Opus and AMR of a payload type not offered are none.
#[test]
fn rtpmap_of_an_unlisted_format_offers_nothing() {
    let sdp = b"v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 4000 RTP/AVP 0 96\r\n\
                a=rtpmap:101 telephone-event/8000\r\na=rtpmap:111 opus/48000/2\r\n\
                a=rtpmap:97 AMR/8000\r\na=rtpmap:96 telephone-event/16000\r\n";
    let (m, n) = media(sdp);
    assert_eq!(n, 1);
    assert_eq!(
        m[0].telephone_event,
        Some((pt(96), 16_000)),
        "the listed one"
    );
    assert_eq!(m[0].opus, None);
    assert_eq!(m[0].amr, None);
    let (m, _) = media(
        b"v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 4000 RTP/AVP 0 101 111\r\n\
                         a=rtpmap:101 telephone-event/8000\r\na=rtpmap:111 opus/48000/2\r\n",
    );
    assert_eq!(m[0].telephone_event, Some((pt(101), 8000)));
    assert_eq!(m[0].opus, Some(pt(111)));
}

/// The relay's own attributes of a section (here its SDES key) come after
/// the section's `c=` and `b=` lines, before its first `a=` line (RFC 8866
/// §5: a media description's lines in the order m, i, c, b, k, a).
#[test]
fn relay_attributes_follow_the_connection_line() {
    let sdp = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\nm=audio 4000 RTP/SAVP 0\r\n\
                c=IN IP4 192.0.2.1\r\nb=AS:64\r\na=sendrecv\r\nm=audio 4002 RTP/SAVP 8\r\nc=IN IP4 192.0.2.1\r\n";
    let key = MasterKey::new(Suite::AesCm128HmacSha1_80, &[7; 30]).unwrap();
    let r = Relayed {
        crypto: Some(Crypto { tag: 1, key }),
        ..Relayed::ports(30000, 30001)
    };
    let plan = Plan {
        address: "203.0.113.1".parse().unwrap(),
        media: &[r, r],
        replace_origin: false,
        bundle: &[],
        keep_connection: false,
        session: SessionEdits::NONE,
    };
    let mut out = [0u8; 2048];
    let n = rewrite(sdp, &plan, &mut out).unwrap();
    let text = core::str::from_utf8(&out[..n]).unwrap();
    let crypto =
        "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH\r\n";
    assert_eq!(
        text,
        std::format!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\nm=audio 30000 RTP/SAVP 0\r\n\
             c=IN IP4 203.0.113.1\r\nb=AS:64\r\n{crypto}a=sendrecv\r\nm=audio 30000 RTP/SAVP 8\r\n\
             c=IN IP4 203.0.113.1\r\n{crypto}"
        )
    );
}

#[test]
fn a_selection_orders_and_drops_formats() {
    let sdp = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
m=audio 4000 RTP/AVP 0 8 96 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n\
a=rtpmap:96 opus/48000/2\r\na=fmtp:96 useinbandfec=1\r\na=rtpmap:101 telephone-event/8000\r\n\
a=fmtp:101 0-15\r\na=sendrecv\r\n";
    let run = |select: &[Pt], formats: [Option<FormatEdit>; 2]| {
        let media = [Relayed {
            select: Some(select),
            formats,
            ..Relayed::ports(30000, 30001)
        }];
        let plan = Plan {
            address: "203.0.113.1".parse().unwrap(),
            media: &media,
            replace_origin: false,
            bundle: &[],
            keep_connection: false,
            session: SessionEdits::NONE,
        };
        let mut buf = [0u8; 1024];
        let n = rewrite(sdp, &plan, &mut buf).unwrap();
        let mut out = [0u8; 1024];
        out[..n].copy_from_slice(&buf[..n]);
        (out, n)
    };
    // Opus first, PCMU and its lines gone (an `offer` and a `strip`).
    let (out, n) = run(&[pt(96), pt(8), pt(101)], [None, None]);
    let out = core::str::from_utf8(&out[..n]).unwrap();
    assert!(
        out.contains(
            "m=audio 30000 RTP/AVP 96 8 101\r\na=rtpmap:8 PCMA/8000\r\n\
a=rtpmap:96 opus/48000/2\r\na=fmtp:96 useinbandfec=1\r\na=rtpmap:101"
        ),
        "{out}"
    );
    assert!(!out.contains("PCMU"), "{out}");
    // Everything stripped but a transcoded codec, which replaced a format
    // that is no longer there: it is still offered.
    let (out, n) = run(&[], [Some(FormatEdit::Replace(pt(0), pt(9))), None]);
    let out = core::str::from_utf8(&out[..n]).unwrap();
    assert!(
        out.contains("m=audio 30000 RTP/AVP 9\r\na=rtpmap:9 G722/8000\r\na=sendrecv"),
        "{out}"
    );
}

#[test]
fn ptime_is_read_and_replaced() {
    let sdp = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
a=ptime:20\r\nm=audio 4000 RTP/AVP 0\r\na=ptime:20.0\r\na=sendrecv\r\nm=audio 4002 RTP/AVP 8\r\n";
    let mut m = [Media::EMPTY; MAX_MEDIA];
    assert_eq!(read_media(sdp, &mut m).unwrap(), 2);
    assert_eq!((m[0].ptime, m[1].ptime), (Some(20), None));
    let media = [
        Relayed {
            ptime: Some(30),
            ..Relayed::ports(30000, 30001)
        },
        Relayed::ports(30002, 30003),
    ];
    let plan = Plan {
        address: "203.0.113.1".parse().unwrap(),
        media: &media,
        replace_origin: false,
        bundle: &[],
        keep_connection: false,
        session: SessionEdits::NONE,
    };
    let mut buf = [0u8; 1024];
    let n = rewrite(sdp, &plan, &mut buf).unwrap();
    let out = core::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(out.matches("a=ptime").count(), 1, "{out}");
    assert!(
        out.contains("m=audio 30000 RTP/AVP 0\r\na=ptime:30\r\na=sendrecv\r\nm=audio 30002"),
        "{out}"
    );
}

#[test]
fn proxy_edits_of_the_session_and_its_attributes() {
    let sdp = b"v=0\r\no=pbx 42 7 IN IP4 10.9.8.7\r\ns=internal call\r\nc=IN IP4 10.9.8.7\r\nt=0 0\r\n\
a=tool:internal-pbx 10.9.8.7\r\na=extmap-allow-mixed\r\n\
m=audio 4000 RTP/AVP 0\r\na=x-internal:10.9.8.7\r\na=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n\
a=label:1\r\na=sendrecv\r\nm=audio 4002 RTP/AVP 0\r\na=rtcp:4003\r\n";
    let remove: [&[u8]; 2] = [b"x-internal", b"extmap"];
    let add: [&[u8]; 1] = [b"x-relayed:yes"];
    let substitute: [(&[u8], &[u8]); 1] = [(b"label:1", b"label:caller")];
    let media = [
        Relayed {
            attrs: AttrEdits {
                add: &add,
                remove: &remove,
                substitute: &substitute,
            },
            rtcp_attr: RtcpAttr::Full,
            ..Relayed::ports(30000, 30001)
        },
        Relayed {
            rtcp_attr: RtcpAttr::Omit,
            ..Relayed::ports(30002, 30003)
        },
    ];
    let session_remove: [&[u8]; 1] = [b"tool"];
    let session_add: [&[u8]; 1] = [b"x-session:1"];
    let plan = Plan {
        address: "203.0.113.1".parse().unwrap(),
        media: &media,
        replace_origin: false,
        bundle: &[],
        keep_connection: false,
        session: SessionEdits {
            username: true,
            session_name: true,
            version: Some(9),
            origin: None,
            attrs: AttrEdits {
                add: &session_add,
                remove: &session_remove,
                substitute: &[],
            },
        },
    };
    let mut buf = [0u8; 2048];
    let n = rewrite(sdp, &plan, &mut buf).unwrap();
    let out = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(
        out.starts_with(
            "v=0\r\no=- 42 9 IN IP4 10.9.8.7\r\ns=-\r\nc=IN IP4 203.0.113.1\r\nt=0 0\r\n\
a=extmap-allow-mixed\r\na=x-session:1\r\nm=audio 30000 RTP/AVP 0\r\n\
a=rtcp:30001 IN IP4 203.0.113.1\r\na=x-relayed:yes\r\na=label:caller\r\na=sendrecv\r\n\
m=audio 30002 RTP/AVP 0\r\n"
        ),
        "{out}"
    );
    assert!(
        !out.contains("a=rtcp:4003") && !out.contains("a=rtcp:30003"),
        "{out}"
    );
    assert_eq!(origin_version(sdp), Some(7));
    assert_eq!(origin_version(b"v=0\r\no=- 1\r\n"), None);
}

#[test]
fn session_parameters_are_read_only_into_declared() {
    let sdp = "v=0\r\nm=audio 4000 RTP/SAVP 0\r\n\
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:MjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5P UNENCRYPTED_SRTP UNAUTHENTICATED_SRTP\r\n\
a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:MjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5P\r\n\
a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:MjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5P FEC_ORDER=FEC_SRTP\r\n";
    let mut m = [Media::EMPTY; MAX_MEDIA];
    read_media(sdp.as_bytes(), &mut m).unwrap();
    // The usable line is still the first without parameters.
    assert_eq!(m[0].crypto.map(|c| c.tag), Some(2));
    let declared: [Option<(u32, bool, bool)>; 3] = [0, 1, 2].map(|i| {
        m[0].declared[i].map(|c| {
            (
                c.tag,
                c.key.policy.unencrypted_srtp,
                c.key.policy.unauthenticated_srtp,
            )
        })
    });
    assert_eq!(
        declared,
        [Some((1, true, true)), Some((2, false, false)), None]
    );
    let gcm = "a=crypto:1 AEAD_AES_128_GCM inline:AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHA== UNENCRYPTED_SRTP";
    assert!(parse_crypto_declared(gcm.strip_prefix("a=crypto:").unwrap().as_bytes()).is_none());
}
