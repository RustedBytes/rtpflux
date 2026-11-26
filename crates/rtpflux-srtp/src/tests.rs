extern crate std;

use super::cipher::{Aes, Gcm, prf};
use super::replay::{MAX_SOURCES, Source};
use super::*;
use std::vec;
use std::vec::Vec;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    hex(s).try_into().unwrap()
}

/// libsrtp's test key (RFC 3711 B.3 master key and salt).
fn master() -> [u8; MASTER_LEN] {
    arr("e1f97a0d3e018be0d64fa32c06de41390ec675ad498afeebb6960b3aabe6")
}

const RTP: &str = "800f1234decafbadcafebabeabababababababababababababababab";
const RTCP: &str = "81c8000bcafebabeabababababababababababababababab";

// ------------------------------------------------------------ RFC vectors

#[test]
fn rfc3711_b2_aes_cm_keystream() {
    let key: [u8; 16] = arr("2B7E151628AED2A6ABF7158809CF4F3C");
    let iv = u128::from_be_bytes(arr("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000"));
    let block = |n: u128| {
        let mut out = [0u8; 16];
        Aes::new(&key).ctr((iv + n).to_be_bytes(), &mut out);
        out.to_vec()
    };
    assert_eq!(block(0), hex("E03EAD0935C95E80E166B16DD92B4EB4"));
    assert_eq!(block(1), hex("D23513162B02D0F72A43A2FE4A5F97AB"));
    assert_eq!(block(2), hex("41E95B3BB0A2E8DD477901E4FCA894C0"));
    assert_eq!(block(0xFEFF), hex("EC8CDF7398607CB0F2D21675EA9EA1E4"));
    assert_eq!(block(0xFF00), hex("362B7C3C6773516318A077D7FC5073AE"));
    assert_eq!(block(0xFF01), hex("6A2CC3787889374FBEB4C81B17BA6C44"));
}

#[test]
fn rfc3711_b3_key_derivation() {
    let mk: [u8; 16] = arr("E1F97A0D3E018BE0D64FA32C06DE4139");
    let ms: [u8; 14] = arr("0EC675AD498AFEEBB6960B3AABE6");
    let master = Aes::new(&mk);
    let mut enc = [0u8; 16];
    prf(&master, &ms, 0, &mut enc);
    assert_eq!(enc.to_vec(), hex("C61E7A93744F39EE10734AFE3FF7A087"));
    let mut salt = [0u8; 14];
    prf(&master, &ms, 2, &mut salt);
    assert_eq!(salt.to_vec(), hex("30CBBC08863D8C85D49DB34A9AE1"));
    let mut auth = [0u8; 94];
    prf(&master, &ms, 1, &mut auth);
    let expected = hex(
        "CEBE321F6FF7716B6FD4AB49AF256A156D38BAA48F0A0ACF3C34E2359E6CDBCEE049646C43D9327AD175578EF7227098\
         6371C10C9A369AC2F94A8C5FBCDDDC256D6E919A48B610EF17C2041E474035766B68642C59BBFC2F34DB60DBDFB2",
    );
    assert_eq!(auth.to_vec(), expected);
}

#[test]
fn rfc6188_7_2_aes_256_key_derivation() {
    let mk: [u8; 32] = arr("f0f04914b513f2763a1b1fa130f10e2998f6f6e43e4309d1e622a0e332b9f1b6");
    let ms: [u8; 14] = arr("3b04803de51ee7c96423ab5b78d2");
    let master = Aes::new(&mk);
    let mut enc = [0u8; 32];
    prf(&master, &ms, 0, &mut enc);
    assert_eq!(
        enc.to_vec(),
        hex("5ba1064e30ec51613cad926c5a28ef731ec7fb397f70a960653caf06554cd8c4")
    );
    let mut salt = [0u8; 14];
    prf(&master, &ms, 2, &mut salt);
    assert_eq!(salt.to_vec(), hex("fa31791685ca444a9e07c6c64e93"));
    let mut auth = [0u8; 20];
    prf(&master, &ms, 1, &mut auth);
    assert_eq!(
        auth.to_vec(),
        hex("fd9c32d39ed5fbb5a9dc96b30818454d1313dc05")
    );
}

// ------------------------------------------------ RFC 7714 (AES-GCM)

/// RFC 7714 §16/§17 give session keys: contexts built from them directly.
fn gcm(suite: Suite, key: &[u8]) -> (Protect, Unprotect) {
    let keys = || SessionKeys::Gcm {
        aead: Gcm::new(key),
        salt: arr("517569642070726f2071756f"),
    };
    (
        Protect {
            suite,
            policy: Policy::NONE,
            rtp: keys(),
            rtcp: keys(),
            sources: Sources::default(),
        },
        Unprotect {
            suite,
            policy: Policy::NONE,
            rtp: keys(),
            rtcp: keys(),
            sources: Sources::default(),
        },
    )
}

const GALLIA: &str = "8040f17b8041f8d35501a0b247616c6c696120657374206f6d6e697320646976697361\
                      20696e20706172746573207472 6573";
const RTCP7714: &str = "81c8000d4d6172734e5450314e54503252545020 0000042a0000e9304c756e61\
                        deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

fn h(s: &str) -> Vec<u8> {
    hex(&s.replace([' ', '\n'], ""))
}

#[test]
fn rfc7714_16_rtp_aes_gcm_both_ways() {
    let k128: Vec<u8> = (0u8..16).collect();
    let k256: Vec<u8> = (0u8..32).collect();
    for (suite, key, wire) in [
        (
            Suite::AeadAes128Gcm,
            &k128,
            "8040f17b8041f8d35501a0b2f24de3a3fb34de6cacba861c9d7e4bcabe633bd50d294e6f42a5f47a51c7d19b36de3adf\
             8833899d7f27beb16a9152cf765ee4390cce",
        ),
        (
            Suite::AeadAes256Gcm,
            &k256,
            "8040f17b8041f8d35501a0b232b1de78a822fe12ef9f78fa332e33aab18012389a58e2f3b50b2a0276ffae0f1ba63799\
             b87b7aa3db36dfffd6b0f9bb7878d7a76c13",
        ),
    ] {
        let (mut tx, mut rx) = gcm(suite, key);
        let plain = h(GALLIA);
        let mut buf = plain.clone();
        buf.resize(plain.len() + 16, 0);
        let n = tx.rtp(&mut buf, plain.len()).unwrap();
        assert_eq!(
            buf[..n].to_vec(),
            h(wire),
            "{suite:?} encrypt and tag (§16.x.1)"
        );
        let n = rx.rtp(&mut buf, n).unwrap();
        assert_eq!(
            buf[..n].to_vec(),
            plain,
            "{suite:?} verify and decrypt (§16.x.2)"
        );
        let mut bad = h(wire);
        bad[20] ^= 1;
        let (_, mut rx) = gcm(suite, key);
        let len = bad.len();
        assert_eq!(rx.rtp(&mut bad, len), Err(Error::Auth));
    }
}

#[test]
fn rfc7714_17_srtcp_aes_gcm() {
    let k128: Vec<u8> = (0u8..16).collect();
    let k256: Vec<u8> = (0u8..32).collect();
    let plain = h(RTCP7714);
    let ssrc = Ssrc::new(0x4d61_7273);
    // §17.1: AES-128, encrypted and tagged, SRTCP index 0x5d4.
    let (mut tx, _) = gcm(Suite::AeadAes128Gcm, &k128);
    tx.sources.commit(
        None,
        ssrc,
        Source {
            rtcp_index: 0x5d4,
            ..Source::default()
        },
    );
    let mut buf = plain.clone();
    buf.resize(plain.len() + 20, 0);
    let n = tx.rtcp(&mut buf, plain.len()).unwrap();
    let wire_17_1 = "81c8000d4d61727363e94885dcdab67ca727d7662f6b7e997ff5c0f76c06f32dc676a5f1730d6fda\
                     4ce09b4686303ded0bb9275bc84aa45896cf4d2fc5abf87245d9eade800005d4";
    assert_eq!(buf[..n].to_vec(), h(wire_17_1));
    let (_, mut rx) = gcm(Suite::AeadAes128Gcm, &k128);
    let n = rx.rtcp(&mut buf, n).unwrap();
    assert_eq!(buf[..n].to_vec(), plain);
    // §17.2: AES-256, verify and decrypt.
    let mut wire = h(
        "81c8000d4d617273d50ae4d1f5ce5d304ba297e47d470c282c3ece5dbffe0a50a2eaa5c1110555be\
                      8415f658c61de0476f1b6fad1d1eb30c4446839f57ff6f6cb26ac3be800005d4",
    );
    let (_, mut rx) = gcm(Suite::AeadAes256Gcm, &k256);
    let len = wire.len();
    let n = rx.rtcp(&mut wire, len).unwrap();
    assert_eq!(wire[..n].to_vec(), plain);
    // §17.3 / §17.4: tagged, not encrypted (E = 0).
    for (suite, key, tag) in [
        (
            Suite::AeadAes128Gcm,
            &k128,
            "841dd9683dd78ec92ae58790125f62b3",
        ),
        (
            Suite::AeadAes256Gcm,
            &k256,
            "91db4afbfeee5a978fab4393ed2615fe",
        ),
    ] {
        let mut wire = plain.clone();
        wire.extend(h(tag));
        wire.extend(h("000005d4"));
        let (_, mut rx) = gcm(suite, key);
        let len = wire.len();
        let mut bad = wire.clone();
        bad[10] ^= 1;
        assert_eq!(rx.rtcp(&mut bad, len), Err(Error::Auth), "{suite:?}");
        let mut before = wire.clone();
        before[10] ^= 1;
        assert_eq!(bad, before, "a rejected packet is left as it was");
        let n = rx.rtcp(&mut wire, len).unwrap();
        assert_eq!(wire[..n].to_vec(), plain, "{suite:?} E=0");
    }
}

#[test]
fn every_suite_round_trips_from_a_master_key() {
    for suite in [
        Suite::AesCm128HmacSha1_80,
        Suite::AesCm128HmacSha1_32,
        Suite::AesCm256HmacSha1_80,
        Suite::AesCm256HmacSha1_32,
        Suite::AeadAes128Gcm,
        Suite::AeadAes256Gcm,
    ] {
        let master: Vec<u8> = (0..suite.master_len())
            .map(|i| u8::try_from(i * 7 % 251).unwrap())
            .collect();
        let key = MasterKey::new(suite, &master).unwrap();
        assert!(MasterKey::new(suite, &master[1..]).is_none());
        let (mut tx, mut rx) = (Protect::from_key(&key), Unprotect::from_key(&key));
        for seq in 0..20u16 {
            let plain = rtp_packet(seq, 5, 9);
            let mut w = protect(&mut tx, &plain);
            assert_eq!(w.len(), plain.len() + suite.rtp_tag_len());
            let len = w.len();
            let n = rx.rtp(&mut w, len).unwrap();
            assert_eq!(&w[..n], &plain[..], "{suite:?}");
        }
        let rtcp = hex(RTCP);
        let mut w = rtcp.clone();
        w.resize(rtcp.len() + suite.srtcp_trailer(), 0);
        let n = tx.rtcp(&mut w, rtcp.len()).unwrap();
        assert_eq!(n, rtcp.len() + suite.srtcp_trailer());
        let n = rx.rtcp(&mut w, n).unwrap();
        assert_eq!(&w[..n], &rtcp[..], "{suite:?} SRTCP");
    }
}

// ------------------------------------------------------- known packets

#[test]
fn libsrtp_known_answer_sha1_80() {
    let mut p = Protect::new(Suite::AesCm128HmacSha1_80, &master());
    let mut buf = hex(RTP);
    let len = buf.len();
    buf.resize(len + 16, 0);
    let n = p.rtp(&mut buf, len).unwrap();
    assert_eq!(
        buf[..n].to_vec(),
        hex("800f1234decafbadcafebabe4e55dc4ce79978d88ca4d215949d2402b78d6acc99ea179b8dbb")
    );
}

#[test]
fn known_answer_sha1_32() {
    let mut p = Protect::new(Suite::AesCm128HmacSha1_32, &master());
    let mut buf = hex(RTP);
    let len = buf.len();
    buf.resize(len + 16, 0);
    let n = p.rtp(&mut buf, len).unwrap();
    assert_eq!(
        buf[..n].to_vec(),
        hex("800f1234decafbadcafebabe4e55dc4ce79978d88ca4d215949d2402b78d6acc")
    );
}

#[test]
fn known_answer_srtcp() {
    let mut p = Protect::new(Suite::AesCm128HmacSha1_80, &master());
    let mut expected = [
        hex("81c8000bcafebabeb19c219a086b6c7ae61d8e0bfeb4be3f800000005631d6cfc906cdb30f41"),
        hex("81c8000bcafebabe7128035be487b9bdbef89041f977a5a880000001993e08cd54d6c1230798"),
    ]
    .into_iter();
    for _ in 0..2 {
        let mut buf = hex(RTCP);
        let len = buf.len();
        buf.resize(len + SRTCP_TRAILER, 0);
        let n = p.rtcp(&mut buf, len).unwrap();
        assert_eq!(buf[..n].to_vec(), expected.next().unwrap());
    }
}

// ------------------------------------------------------- behaviour

fn rtp_packet(seq: u16, ssrc: u32, payload: u8) -> Vec<u8> {
    let mut p = vec![0x80, 0x00];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0x10, 0]);
    p.extend_from_slice(&ssrc.to_be_bytes());
    p.extend(std::iter::repeat_n(payload, 160));
    p
}

fn protect(p: &mut Protect, plain: &[u8]) -> Vec<u8> {
    let mut buf = plain.to_vec();
    buf.resize(plain.len() + 16, 0);
    let n = p.rtp(&mut buf, plain.len()).unwrap();
    buf.truncate(n);
    buf
}

#[test]
fn round_trip_both_suites() {
    for suite in [Suite::AesCm128HmacSha1_80, Suite::AesCm128HmacSha1_32] {
        let (mut tx, mut rx) = (
            Protect::new(suite, &master()),
            Unprotect::new(suite, &master()),
        );
        for seq in 0..100u16 {
            let plain = rtp_packet(seq, 0x1234_5678, u8::try_from(seq % 251).unwrap());
            let mut wire = protect(&mut tx, &plain);
            assert_ne!(wire[12..plain.len()], plain[12..], "payload is encrypted");
            assert_eq!(wire[..12], plain[..12], "header stays clear");
            let len = wire.len();
            let n = rx.rtp(&mut wire, len).unwrap();
            assert_eq!(&wire[..n], &plain[..]);
        }
    }
}

#[test]
fn any_flipped_bit_is_rejected_and_nothing_changes() {
    let mut tx = Protect::new(Suite::AesCm128HmacSha1_80, &master());
    let wire = protect(&mut tx, &rtp_packet(7, 1, 0x55));
    for i in 0..wire.len() {
        for bit in [0x01u8, 0x80] {
            let mut rx = Unprotect::new(Suite::AesCm128HmacSha1_80, &master());
            let mut bad = wire.clone();
            bad[i] ^= bit;
            let before = bad.clone();
            let r = rx.rtp(&mut bad, wire.len());
            // Flipping the version bits makes it malformed; anything else
            // fails authentication.
            assert!(
                matches!(r, Err(Error::Auth | Error::Malformed)),
                "byte {i} bit {bit:#x}: {r:?}"
            );
            assert_eq!(bad, before, "a rejected packet is not modified");
        }
    }
}

#[test]
fn replays_are_rejected_reordering_is_not() {
    let mut tx = Protect::new(Suite::AesCm128HmacSha1_80, &master());
    let mut rx = Unprotect::new(Suite::AesCm128HmacSha1_80, &master());
    let wires: Vec<Vec<u8>> = (0..10u16)
        .map(|s| protect(&mut tx, &rtp_packet(s, 9, 1)))
        .collect();
    // 0, 2, 1 (reordered), then a replay of 1, then 3..9
    for i in [0usize, 2, 1] {
        let mut w = wires[i].clone();
        let len = w.len();
        rx.rtp(&mut w, len).unwrap();
    }
    let mut w = wires[1].clone();
    let len = w.len();
    assert_eq!(rx.rtp(&mut w, len), Err(Error::Replay));
    for wire in &wires[3..] {
        let mut w = wire.clone();
        let len = w.len();
        rx.rtp(&mut w, len).unwrap();
    }
    // Far behind the window: rejected as a replay without authenticating.
    let late: Vec<Vec<u8>> = (10..110u16)
        .map(|s| protect(&mut tx, &rtp_packet(s, 9, 1)))
        .collect();
    for wire in &late {
        let mut w = wire.clone();
        let len = w.len();
        rx.rtp(&mut w, len).unwrap();
    }
    let mut w = wires[5].clone();
    let len = w.len();
    assert_eq!(rx.rtp(&mut w, len), Err(Error::Replay));
}

#[test]
fn sequence_wraps_into_the_next_rollover_counter() {
    let mut tx = Protect::new(Suite::AesCm128HmacSha1_80, &master());
    let mut rx = Unprotect::new(Suite::AesCm128HmacSha1_80, &master());
    let seqs: Vec<u16> = (65_530..=65_535).chain(0..6).collect();
    let wires: Vec<Vec<u8>> = seqs
        .iter()
        .map(|&s| protect(&mut tx, &rtp_packet(s, 3, 2)))
        .collect();
    // deliver with one reordering across the wrap: 65535 after 0
    let order = [0usize, 1, 2, 3, 4, 6, 5, 7, 8, 9, 10, 11];
    for i in order {
        let mut w = wires[i].clone();
        let len = w.len();
        let n = rx
            .rtp(&mut w, len)
            .unwrap_or_else(|e| panic!("seq {}: {e:?}", seqs[i]));
        assert_eq!(&w[..n], &rtp_packet(seqs[i], 3, 2)[..]);
    }
    // The packet after the wrap used ROC 1: it equals the reference with ROC 1.
    let mut tx2 = Protect::new(Suite::AesCm128HmacSha1_80, &master());
    for s in 65_530..=65_535u16 {
        protect(&mut tx2, &rtp_packet(s, 0xcafe_babe, 0xab));
    }
    let wire = protect(&mut tx2, &hex(RTP));
    assert_eq!(
        wire,
        hex("800f1234decafbadcafebabe179265c8bf303e4c24e7279f739bb5a6f8b3916fd670057bf1dc"),
        "seq 0x1234 after the wrap uses ROC 1"
    );
}

#[test]
fn a_new_ssrc_starts_over() {
    let mut rx = Unprotect::new(Suite::AesCm128HmacSha1_80, &master());
    let mut a = Protect::new(Suite::AesCm128HmacSha1_80, &master());
    let mut b = Protect::new(Suite::AesCm128HmacSha1_80, &master());
    let mut deliver = |p: &mut Protect, ssrc: u32, seq: u16| {
        let mut w = protect(p, &rtp_packet(seq, ssrc, 0));
        let len = w.len();
        rx.rtp(&mut w, len).unwrap();
    };
    deliver(&mut a, 1, 40_000);
    deliver(&mut b, 2, 5);
    deliver(&mut a, 1, 40_001);
}

#[test]
fn srtcp_round_trip_tamper_replay() {
    let mut tx = Protect::new(Suite::AesCm128HmacSha1_32, &master());
    let mut rx = Unprotect::new(Suite::AesCm128HmacSha1_32, &master());
    let plain = hex(RTCP);
    let mut wires = Vec::new();
    for _ in 0..3 {
        let mut buf = plain.clone();
        buf.resize(plain.len() + SRTCP_TRAILER, 0);
        let n = tx.rtcp(&mut buf, plain.len()).unwrap();
        assert_eq!(n, plain.len() + 14, "SRTCP always carries an 80-bit tag");
        wires.push(buf);
    }
    let mut bad = wires[0].clone();
    bad[10] ^= 1;
    assert_eq!(rx.rtcp(&mut bad, wires[0].len()), Err(Error::Auth));
    let mut w = wires[0].clone();
    let len = w.len();
    let n = rx.rtcp(&mut w, len).unwrap();
    assert_eq!(&w[..n], &plain[..]);
    let mut again = wires[0].clone();
    assert_eq!(rx.rtcp(&mut again, len), Err(Error::Replay));
}

#[test]
fn malformed_and_small_buffers() {
    let mut tx = Protect::new(Suite::AesCm128HmacSha1_80, &master());
    let mut rx = Unprotect::new(Suite::AesCm128HmacSha1_80, &master());
    let plain = rtp_packet(1, 1, 0);
    let mut exact = plain.clone();
    assert_eq!(tx.rtp(&mut exact, plain.len()), Err(Error::BufferTooSmall));
    let mut short = [0x80u8; 8];
    assert_eq!(tx.rtp(&mut short, 8), Err(Error::Malformed));
    assert_eq!(rx.rtp(&mut short, 8), Err(Error::Malformed));
    let mut v1 = plain.clone();
    v1[0] = 0x40;
    v1.resize(plain.len() + 16, 0);
    assert_eq!(tx.rtp(&mut v1, plain.len()), Err(Error::Malformed));
    assert_eq!(
        Suite::from_name(b"AES_CM_128_HMAC_SHA1_80"),
        Some(Suite::AesCm128HmacSha1_80)
    );
    assert_eq!(Suite::from_name(b"F8_128_HMAC_SHA1_80"), None);
}

#[test]
fn sources_keep_their_own_state_and_a_full_context_refuses_new_ones() {
    let mut tx = Protect::new(Suite::AesCm128HmacSha1_80, &master());
    let mut rx = Unprotect::new(Suite::AesCm128HmacSha1_80, &master());
    let deliver = |rx: &mut Unprotect, w: &[u8]| {
        let mut w = w.to_vec();
        let len = w.len();
        rx.rtp(&mut w, len)
    };
    // MAX_SOURCES sources fill both contexts.
    let first = protect(&mut tx, &rtp_packet(10, 100, 0));
    deliver(&mut rx, &first).unwrap();
    for s in 1..MAX_SOURCES {
        deliver(
            &mut rx,
            &protect(&mut tx, &rtp_packet(10, 100 + u32::try_from(s).unwrap(), 0)),
        )
        .unwrap();
    }
    // One more is refused by the sender, and by the receiver (a packet
    // from a sender with room for it).
    let mut pkt = rtp_packet(10, 999, 0);
    let len = pkt.len();
    pkt.resize(len + 16, 0);
    assert_eq!(tx.rtp(&mut pkt, len), Err(Error::TooManySources));
    let mut other = Protect::new(Suite::AesCm128HmacSha1_80, &master());
    let extra = protect(&mut other, &rtp_packet(10, 999, 0));
    assert_eq!(deliver(&mut rx, &extra), Err(Error::TooManySources));
    // Nobody was forgotten: a replay of the first source is still caught,
    // and its sender goes on from where it was.
    assert_eq!(deliver(&mut rx, &first), Err(Error::Replay), "remembered");
    deliver(&mut rx, &protect(&mut tx, &rtp_packet(11, 100, 0))).unwrap();
}

#[test]
fn a_length_beyond_the_buffer_is_malformed() {
    let mut rx = Unprotect::new(Suite::AesCm128HmacSha1_80, &master());
    let mut w = protect(
        &mut Protect::new(Suite::AesCm128HmacSha1_80, &master()),
        &rtp_packet(1, 7, 0),
    );
    let len = w.len();
    assert_eq!(rx.rtp(&mut w, len + 1), Err(Error::Malformed));
    assert_eq!(rx.rtcp(&mut w, len + 1), Err(Error::Malformed));
}

#[test]
fn the_sender_never_encrypts_twice_at_one_index() {
    let mut tx = Protect::new(Suite::AesCm128HmacSha1_80, &master());
    let mut send = |p: &[u8]| {
        let mut w = p.to_vec();
        let len = w.len();
        w.resize(len + 16, 0);
        tx.rtp(&mut w, len)
    };
    send(&rtp_packet(10, 7, 0)).unwrap();
    send(&rtp_packet(11, 7, 0)).unwrap();
    // The same sequence number again (another payload would reuse the
    // keystream): refused.
    assert_eq!(send(&rtp_packet(10, 7, 0)), Err(Error::Replay));
    // Reordered but unused: fine.
    send(&rtp_packet(13, 7, 0)).unwrap();
    send(&rtp_packet(12, 7, 0)).unwrap();
}

#[test]
fn sdes_session_parameters_switch_protection_off() {
    let base = MasterKey::new(Suite::AesCm128HmacSha1_80, &[9; 30]).unwrap();
    assert!(
        MasterKey::new(Suite::AeadAes128Gcm, &[9; 28])
            .unwrap()
            .with_policy(Policy {
                unencrypted_srtp: true,
                ..Policy::NONE
            })
            .is_none(),
        "AEAD suites have no such parameters"
    );
    let rtp_pkt = {
        let mut p = vec![0x80, 0, 0, 7, 0, 0, 0, 160, 0, 0, 0, 1];
        p.extend_from_slice(&[0x55; 160]);
        p
    };
    for (policy, clear, tag) in [
        (Policy::NONE, false, 10),
        (
            Policy {
                unencrypted_srtp: true,
                ..Policy::NONE
            },
            true,
            10,
        ),
        (
            Policy {
                unauthenticated_srtp: true,
                ..Policy::NONE
            },
            false,
            0,
        ),
        (
            Policy {
                unencrypted_srtp: true,
                unauthenticated_srtp: true,
                ..Policy::NONE
            },
            true,
            0,
        ),
    ] {
        let key = base.with_policy(policy).unwrap();
        let (mut tx, mut rx) = (Protect::from_key(&key), Unprotect::from_key(&key));
        let mut buf = [0u8; 256];
        buf[..rtp_pkt.len()].copy_from_slice(&rtp_pkt);
        let n = tx.rtp(&mut buf, rtp_pkt.len()).unwrap();
        assert_eq!(n, rtp_pkt.len() + tag, "{policy:?}");
        assert_eq!(
            buf[..rtp_pkt.len()] == rtp_pkt[..],
            clear,
            "{policy:?}: payload in clear"
        );
        let back = rx.rtp(&mut buf, n).unwrap();
        assert_eq!(&buf[..back], &rtp_pkt[..], "{policy:?}");
        if tag > 0 {
            // Authenticated: a changed payload is refused.
            buf[..rtp_pkt.len()].copy_from_slice(&rtp_pkt);
            let mut tx2 = Protect::from_key(&key);
            let n = tx2.rtp(&mut buf, rtp_pkt.len()).unwrap();
            buf[20] ^= 1;
            assert!(
                Unprotect::from_key(&key).rtp(&mut buf, n).is_err(),
                "{policy:?}"
            );
        }
    }
    // Unencrypted SRTCP: E = 0 and the packet in clear, still authenticated.
    let key = base
        .with_policy(Policy {
            unencrypted_srtcp: true,
            ..Policy::NONE
        })
        .unwrap();
    let rr = [
        0x81u8, 201, 0, 7, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];
    let mut buf = [0u8; 128];
    buf[..rr.len()].copy_from_slice(&rr);
    let n = Protect::from_key(&key).rtcp(&mut buf, rr.len()).unwrap();
    assert_eq!(&buf[..rr.len()], &rr[..], "in clear");
    assert_eq!(buf[rr.len()] & 0x80, 0, "E = 0");
    let back = Unprotect::from_key(&key).rtcp(&mut buf, n).unwrap();
    assert_eq!(&buf[..back], &rr[..]);
}
