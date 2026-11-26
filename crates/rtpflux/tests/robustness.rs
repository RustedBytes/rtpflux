//! No untrusted input makes the relay panic (AGENTS.md §5): every parser
//! of what arrives from the network — RTP, RTCP, STUN, telephone events,
//! SDP, bencode, the ng control messages, SRTP, the XDP program's frame
//! checks — gets random bytes and mutations of valid inputs (bits flipped,
//! octets changed, cut short, spliced together, lengths stretched).
//!
//! The generator is a seeded xorshift, so a failure is reproducible: the
//! panic message says which target and input. `RTPFLUX_FUZZ_SCALE=<n>`
//! runs `n` times as many cases (for a longer soak).

#[path = "support/logging.rs"]
mod logging;

use rtpflux::config::Config;
use rtpflux::control::Control;
use rtpflux::relay::Relay;
use rtpflux_core::sdp::{MAX_MEDIA, Media};
use rtpflux_ng::bencode::{Encoder, Value};
use std::panic::{AssertUnwindSafe, catch_unwind};

/// A xorshift generator: deterministic, no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n.max(1)).unwrap()).unwrap()
    }

    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }

    /// Random octets, up to `max`.
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = self.below(max + 1);
        (0..n).map(|_| self.byte()).collect()
    }

    /// `seed` mutated: bits flipped, octets set to edge values, cut short,
    /// octets inserted, a piece repeated, or spliced with `other`.
    fn mutate(&mut self, seed: &[u8], other: &[u8]) -> Vec<u8> {
        let mut v = seed.to_vec();
        for _ in 0..=self.below(4) {
            match self.below(7) {
                0 if !v.is_empty() => {
                    let i = self.below(v.len());
                    v[i] ^= 1 << self.below(8);
                }
                1 if !v.is_empty() => {
                    let i = self.below(v.len());
                    v[i] = [0, 0x7f, 0x80, 0xff, b'0', b':', b'e'][self.below(7)];
                }
                2 => v.truncate(self.below(v.len() + 1)),
                3 => {
                    let i = self.below(v.len() + 1);
                    let b = self.byte();
                    v.insert(i, b);
                }
                4 if !v.is_empty() => {
                    let (a, b) = (self.below(v.len()), self.below(v.len()));
                    let piece = v[a.min(b)..a.max(b)].to_vec();
                    let at = self.below(v.len() + 1);
                    v.splice(at..at, piece);
                }
                5 => {
                    let cut = self.below(v.len() + 1);
                    v.truncate(cut);
                    v.extend_from_slice(&other[self.below(other.len() + 1)..]);
                }
                _ => {
                    // A length or count field stretched: digits grow.
                    if let Some(i) = v.iter().position(u8::is_ascii_digit) {
                        v.insert(i, b'9');
                    }
                }
            }
        }
        v
    }
}

/// How many times the usual number of cases to run.
fn scale() -> usize {
    std::env::var("RTPFLUX_FUZZ_SCALE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
}

/// Run `f` on `cases` inputs from `generate`; a panic names the target and the
/// input (as hex).
fn fuzz(
    name: &str,
    cases: usize,
    mut generate: impl FnMut(&mut Rng) -> Vec<u8>,
    f: impl Fn(&[u8]),
) {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ name.len() as u64);
    for i in 0..cases * scale() {
        let input = generate(&mut rng);
        if catch_unwind(AssertUnwindSafe(|| f(&input))).is_err() {
            let hex = input.iter().fold(String::new(), |mut s, b| {
                use std::fmt::Write as _;
                let _ = write!(s, "{b:02x}");
                s
            });
            panic!("{name}: case {i} panics on {hex}");
        }
    }
}

/// Random bytes or a mutation of one of `seeds`.
fn inputs<'a>(seeds: &'a [&'a [u8]], max: usize) -> impl FnMut(&mut Rng) -> Vec<u8> + 'a {
    move |rng| {
        if seeds.is_empty() || rng.below(4) == 0 {
            rng.bytes(max)
        } else {
            let (a, b) = (rng.below(seeds.len()), rng.below(seeds.len()));
            rng.mutate(seeds[a], seeds[b])
        }
    }
}

const RTP: &[u8] = &[
    0x80, 0, 0, 1, 0, 0, 0, 160, 1, 2, 3, 4, 0xff, 0xff, 0xff, 0xff,
];
const RTP_EXT: &[u8] = &[
    0x90, 0x60, 0, 1, 0, 0, 0, 160, 1, 2, 3, 4, 0xbe, 0xde, 0, 1, 0x10, 0xaa, 0, 0, 9, 9,
];
const RTCP_SR: &[u8] = &[
    0x81, 200, 0, 12, 1, 2, 3, 4, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 5, 6,
    7, 8, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0x81, 202, 0, 1, 1, 2, 3, 4,
];
const EVENT: &[u8] = &[5, 0x8a, 0x03, 0x20];

const SDP: &[u8] = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
a=group:BUNDLE 0 1\r\nm=audio 4000 RTP/SAVPF 0 8 101 96\r\na=mid:0\r\na=rtpmap:101 telephone-event/8000\r\n\
a=rtpmap:96 opus/48000/2\r\na=fmtp:96 minptime=10\r\na=ptime:20\r\na=rtcp:4001 IN IP4 192.0.2.1\r\n\
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:4fl6DT4Bi+DWT6MsBt5BOQ7Gda1Jiv7rtpYLOqvm|2^31|1:1\r\n\
a=ice-ufrag:abcd\r\na=ice-pwd:passwordpasswordpassword\r\n\
a=candidate:1 1 UDP 2130706431 192.0.2.1 4000 typ host\r\n\
a=candidate:2 1 UDP 1694498815 198.51.100.1 5000 typ srflx raddr 192.0.2.1 rport 4000\r\n\
a=setup:actpass\r\na=fingerprint:sha-256 AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89\r\n\
a=rtcp-mux\r\na=sendrecv\r\nm=video 4002 RTP/AVP 97\r\na=mid:1\r\na=rtpmap:97 H264/90000\r\n\
m=image 4004 udptl t38\r\na=T38FaxVersion:0\r\n";

const PLAIN_SDP: &[u8] =
    b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
m=audio 4000 RTP/AVP 0 8 101\r\na=rtpmap:101 telephone-event/8000\r\na=sendrecv\r\n";

#[test]
fn rtp_rtcp_events_and_stun_never_panic() {
    let seeds: &[&[u8]] = &[RTP, RTP_EXT, RTCP_SR, EVENT];
    fuzz("rtp", 20_000, inputs(seeds, 64), |b| {
        if let Ok(p) = rtpflux_core::rtp::Packet::parse(b) {
            let _ = (p.payload(), p.padding(), p.timestamp(), p.payload_type());
        }
    });
    fuzz("rtcp", 20_000, inputs(seeds, 128), |b| {
        if let Some(c) = rtpflux_core::rtcp::compound(b) {
            for p in c {
                if let Some(r) = rtpflux_core::rtcp::Report::of(&p) {
                    let _ = r.blocks().count();
                }
            }
        }
    });
    fuzz("telephone event", 5_000, inputs(seeds, 16), |b| {
        let _ = rtpflux_core::dtmf::decode(b);
    });
    let creds = rtpflux_core::stun::Credentials {
        ufrag: b"abcd:efgh",
        pwd: b"passwordpasswordpassword",
    };
    let src = "192.0.2.1:4000".parse().unwrap();
    let mut binding = [0u8; 64];
    let n = rtpflux_core::stun::write_binding(&mut binding, &[7; 12]).unwrap();
    let binding = binding[..n].to_vec();
    let stun_seeds: &[&[u8]] = &[&binding, RTP];
    fuzz("stun", 20_000, inputs(stun_seeds, 200), |b| {
        let mut out = [0u8; 512];
        let _ = rtpflux_core::stun::ice_lite(b, creds, src, &mut out);
        let _ = rtpflux_core::stun::check_request(b, creds, &mut out);
        let _ = rtpflux_core::stun::read_response(b, creds.pwd);
        let _ = rtpflux_core::stun::read_binding(b, &[7; 12]);
        let _ = rtpflux_core::stun::response_tid(b);
        let _ = rtpflux_core::stun::is_muxed_rtcp(b);
    });
}

#[test]
fn sdp_never_panics() {
    let seeds: &[&[u8]] = &[SDP];
    fuzz("sdp", 20_000, inputs(seeds, 400), |b| {
        let _ = rtpflux_core::sdp::check_body(b);
        let mut media = [Media::EMPTY; MAX_MEDIA];
        if let Ok(n) = rtpflux_core::sdp::read_media(b, &mut media) {
            for i in 0..n {
                if let Some(ice) = rtpflux_core::sdp::ice::section_ice(b, i) {
                    let _ = ice.candidates().count();
                }
            }
        }
        let mut group = [None; MAX_MEDIA];
        let _ = rtpflux_core::sdp::bundle_group(b, &mut group);
        for l in rtpflux_core::sdp::ice::frag_lines(b) {
            let _ = l;
        }
    });
}

#[test]
fn bencode_and_ng_messages_never_panic() {
    let seeds: &[&[u8]] = &[
        b"c1 d7:command5:offer7:call-id1:c8:from-tag1:f3:sdp3:v=05:flagsl13:trust-addressee",
        b"d1:ad1:bl1:ci-5eeee",
        b"li0e4:spami9999999999999999ee",
    ];
    fuzz("bencode", 30_000, inputs(seeds, 120), |b| {
        let _ = rtpflux_ng::bencode::decode(b);
        let _ = rtpflux_ng::bencode::item_len(b);
        let _ = rtpflux_ng::parse_message(b);
    });
}

/// Every suite, with room for the tag, with none, and with a `len`
/// beyond the buffer.
#[test]
fn srtp_never_panics() {
    use rtpflux_srtp::{MasterKey, Protect, Suite, Unprotect};
    let suites = [
        Suite::AesCm128HmacSha1_80,
        Suite::AesCm128HmacSha1_32,
        Suite::AesCm256HmacSha1_80,
        Suite::AesCm256HmacSha1_32,
        Suite::AeadAes128Gcm,
        Suite::AeadAes256Gcm,
    ];
    let keys: Vec<MasterKey> = suites
        .iter()
        .map(|&s| MasterKey::new(s, &vec![7u8; s.master_len()]).unwrap())
        .collect();
    let seeds: &[&[u8]] = &[RTP, RTP_EXT, RTCP_SR];
    let n = std::cell::Cell::new(0usize);
    fuzz("srtp", 12_000, inputs(seeds, 200), |b| {
        let n = n.replace(n.get() + 1);
        let key = &keys[n % keys.len()];
        let len = match n % 3 {
            0 => b.len(),
            1 => b.len() + 64,
            _ => b.len().saturating_sub(1),
        };
        for room in [0, 64] {
            let mut buf = b.to_vec();
            buf.resize(b.len() + room, 0);
            let mut rx = Unprotect::from_key(key);
            let _ = rx.rtp(&mut buf, len);
            let _ = rx.rtcp(&mut buf, len);
            let mut tx = Protect::from_key(key);
            let _ = tx.rtp(&mut buf, len);
            let _ = tx.rtcp(&mut buf, len);
        }
    });
}

/// The codecs decode payloads from the network (when a call transcodes):
/// any octets, in a decoder whose state carries on from packet to packet,
/// and back through the encoder. Tests build with overflow checks, so an
/// overflow in the arithmetic would panic here.
#[test]
fn codecs_never_panic() {
    // State carried across inputs (the fuzz closure is `Fn`).
    let codecs = std::cell::RefCell::new((
        rtpflux_core::g722::Decoder::new(),
        rtpflux_core::g722::Encoder::new(),
        rtpflux_core::g722::Encoder::new(),
    ));
    let ulaw_to_alaw =
        rtpflux_core::g711::converter(rtpflux_core::rtp::Pt::PCMU, rtpflux_core::rtp::Pt::PCMA)
            .unwrap();
    let seeds: &[&[u8]] = &[&[0u8; 160], &[0xffu8; 160], &[0x55u8; 160]];
    fuzz("codecs", 5_000, inputs(seeds, 400), |b| {
        let (dec, enc, extreme) = &mut *codecs.borrow_mut();
        let mut pcm = [0i16; 1024];
        let n = dec.decode(b, &mut pcm);
        let mut out = [0u8; 512];
        let _ = enc.encode(&pcm[..n], &mut out);
        // Full-scale square waves, the hardest input for the predictor.
        let square: Vec<i16> = b
            .iter()
            .map(|&x| if x & 1 == 0 { i16::MAX } else { i16::MIN })
            .collect();
        let _ = extreme.encode(&square, &mut out);
        let mut g711 = b.to_vec();
        rtpflux_core::g711::transcode(ulaw_to_alaw, &mut g711);
    });
}

#[test]
fn xdp_frame_checks_never_panic() {
    // An Ethernet + IPv4 + UDP + RTP frame, and its IPv6 form's start.
    let mut v4 = vec![0u8; 12];
    v4.extend_from_slice(&[0x08, 0x00, 0x45, 0, 0, 40, 0, 0, 0, 0, 64, 17, 0, 0]);
    v4.extend_from_slice(&[
        192, 0, 2, 1, 192, 0, 2, 2, 0x0f, 0xa0, 0x0f, 0xa2, 0, 20, 0, 0,
    ]);
    v4.extend_from_slice(RTP);
    let mut v6 = vec![0u8; 12];
    v6.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0, 0, 20, 17, 64]);
    v6.extend_from_slice(&[0x20; 32]);
    v6.extend_from_slice(&[0x0f, 0xa0, 0x0f, 0xa2, 0, 20, 0x12, 0x34]);
    v6.extend_from_slice(RTP);
    let seeds: &[&[u8]] = &[&v4, &v6];
    fuzz("xdp frames", 20_000, inputs(seeds, 120), |b| {
        let _ = rtpflux_xdp_common::classify(b);
        let _ = rtpflux_xdp_common::steer_key(b);
        let _ = rtpflux_xdp_common::datagram(b);
        let _ = rtpflux_xdp_common::parse_record(b);
    });
}

/// An ng request: `pairs` (values as given: strings or raw bencode).
fn request(cookie: &str, pairs: &[(&[u8], &[u8], bool)]) -> Vec<u8> {
    let mut sorted = pairs.to_vec();
    sorted.sort_by_key(|(k, _, _)| *k);
    sorted.dedup_by_key(|(k, _, _)| *k);
    let mut buf = vec![0u8; 16_384];
    let mut e = Encoder::new(&mut buf);
    e.raw(cookie.as_bytes()).unwrap();
    e.raw(b" ").unwrap();
    e.dict().unwrap();
    for (k, v, raw) in sorted {
        e.bytes(k).unwrap();
        if raw && rtpflux_ng::bencode::decode(v).is_ok() {
            e.raw(v).unwrap();
        } else {
            e.bytes(v).unwrap();
        }
    }
    e.end().unwrap();
    let n = e.len();
    buf.truncate(n);
    buf
}

/// Every command, with options whose values are mutated (the SDP too), and
/// whole datagrams mutated: the control layer answers each (an error is an
/// answer) and never panics.
#[test]
#[allow(clippy::too_many_lines)] // The commands and options, then the run.
fn ng_control_never_panics() {
    logging::init();
    let config = Config::from_toml(
        "[[interface]]\nname = \"pub\"\naddress = \"127.0.0.1\"\n\
         [ports]\nmin = 41000\nmax = 41199\n[sessions]\nmax = 32\n[runtime]\nworkers = 2\n",
    )
    .unwrap();
    let mut c = Control::new(Relay::start(&config).unwrap(), config.interfaces.clone());
    let commands: &[&[u8]] = &[
        b"offer",
        b"answer",
        b"delete",
        b"query",
        b"list",
        b"ping",
        b"block media",
        b"unblock media",
        b"silence media",
        b"block DTMF",
        b"play DTMF",
        b"play media",
        b"stop media",
        b"start recording",
        b"statistics",
        b"subscribe request",
        b"subscribe answer",
        b"unsubscribe",
        b"connect",
        b"publish",
        b"rollback",
        b"create",
        b"create answer",
        b"inject start",
        b"inject stop",
        b"mesh",
    ];
    // Options, and values: strings, numbers, lists and dictionaries.
    let keys: &[&[u8]] = &[
        b"flags",
        b"replace",
        b"direction",
        b"ICE",
        b"DTLS",
        b"SDES",
        b"OSRTP",
        b"codec",
        b"transport-protocol",
        b"rtcp-mux",
        b"ptime",
        b"label",
        b"to-label",
        b"from-tags",
        b"all",
        b"DTMF-security",
        b"trigger",
        b"DTMF-delay",
        b"code",
        b"media echo",
        b"sdp-attr",
        b"address-family",
        b"media-address",
        b"medias",
        b"calls",
        b"tags",
        b"via-branch",
        b"delete-delay",
        b"duration",
        b"volume",
        b"endpoint-learning",
        b"record-call",
        b"metadata",
        b"set-label",
        b"to-call-id",
        b"source-tag",
    ];
    let values: &[&[u8]] = &[
        b"l13:trust-address11:directional12:track-statee",
        b"d9:transcodel4:PCMAe4:maskl4:PCMUe5:offerl4:opusee",
        b"ld4:from1:f2:tol1:teee",
        b"i-1e",
        b"i99999999999e",
        b"force-relay",
        b"zero",
        b"*1#",
        b"RTP/SAVPF",
        b"UDP/TLS/RTP/SAVPF",
        b"l3:pub3:pube",
        b"d4:nonel1:xe3:addl13:a=foo:bar baree",
        b"",
    ];
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let calls: [&[u8]; 3] = [b"fz-1", b"fz-2", b"fz-3"];
    let tags: [&[u8]; 4] = [b"f", b"t", b"x", b"srv"];
    let mut last: Vec<u8> = Vec::new();
    for i in 0..10_000 * scale() {
        let command = commands[rng.below(commands.len())];
        // Valid SDP often enough for dialogs to come about (and answers,
        // re-offers, blocking and the rest to have something to act on).
        let sdp = match rng.below(10) {
            0 | 1 => rng.bytes(300),
            2..=5 => rng.mutate(SDP, PLAIN_SDP),
            6 | 7 => PLAIN_SDP.to_vec(),
            _ => SDP.to_vec(),
        };
        let mut pairs: Vec<(&[u8], &[u8], bool)> = vec![
            (b"command", command, false),
            (b"call-id", calls[rng.below(3)], false),
            (b"from-tag", tags[rng.below(4)], false),
            (b"to-tag", tags[rng.below(4)], false),
            (b"sdp", &sdp, false),
        ];
        let picked: Vec<(&[u8], Vec<u8>)> = (0..rng.below(5))
            .map(|_| {
                let v = values[rng.below(values.len())];
                let v = if rng.below(3) == 0 {
                    rng.mutate(v, v)
                } else {
                    v.to_vec()
                };
                (keys[rng.below(keys.len())], v)
            })
            .collect();
        for (k, v) in &picked {
            pairs.push((k, v, true));
        }
        let mut datagram = request(&format!("fz{i}"), &pairs);
        // Now and then the whole datagram mangled.
        if rng.below(5) == 0 {
            datagram = rng.mutate(&datagram, &last);
        }
        if catch_unwind(AssertUnwindSafe(|| {
            let _ = c.handle(&datagram);
        }))
        .is_err()
        {
            panic!(
                "control: case {i} panics on {}",
                String::from_utf8_lossy(&datagram)
            );
        }
        last = datagram;
    }
    // Still answering.
    let ping = request("p", &[(b"command", b"ping", false)]);
    assert!(String::from_utf8_lossy(c.handle(&ping).unwrap()).contains("pong"));
    let _ = Value::Int(0);
}

/// What arrives on a call's ports — garbage, mutated RTP, RTCP, telephone
/// events, STUN, DTLS-looking records, from the parties and from a stranger
/// — never stops the media workers: afterwards media still flows and the
/// call still answers `query`. The call transcodes (PCMU to PCMA), has DTMF
/// security and repacketisation, so most of the packet path is on. The
/// worker receives with `io_uring` (the default), so its buffers take the
/// garbage first.
#[test]
#[allow(clippy::too_many_lines)] // The call, the run, the checks.
fn media_workers_never_panic() {
    use std::net::{SocketAddr, UdpSocket};
    use std::time::Duration;
    logging::init();
    let config = Config::from_toml(
        "[[interface]]\nname = \"pub\"\naddress = \"127.0.0.1\"\n\
         [ports]\nmin = 41200\nmax = 41263\n[sessions]\nmax = 8\n[runtime]\nworkers = 1\n",
    )
    .unwrap();
    let mut ctl = Control::new(Relay::start(&config).unwrap(), config.interfaces.clone());
    let rings = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
        .filter(|l| l.to_string_lossy().contains("io_uring"))
        .count();
    assert!(rings >= 1, "the worker receives with io_uring");
    let (alice, bob, stranger) = (
        UdpSocket::bind("127.0.0.1:0").unwrap(),
        UdpSocket::bind("127.0.0.1:0").unwrap(),
        UdpSocket::bind("127.0.0.1:0").unwrap(),
    );
    let sdp = |s: &UdpSocket, pts: &str| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP {pts}\r\na=rtpmap:101 telephone-event/8000\r\na=sendrecv\r\n",
            s.local_addr().unwrap().port()
        )
    };
    let sdp_of = |reply: &[u8]| -> u16 {
        let text = String::from_utf8_lossy(reply).into_owned();
        let m = text.find("m=audio ").expect("an SDP");
        text[m + 8..].split(' ').next().unwrap().parse().unwrap()
    };
    let (sa, sb) = (sdp(&alice, "0 101"), sdp(&bob, "8 101"));
    let offer = request(
        "o",
        &[
            (b"command", b"offer", false),
            (b"call-id", b"media-fuzz", false),
            (b"from-tag", b"f", false),
            (b"sdp", sa.as_bytes(), false),
            (b"endpoint-learning", b"off", false),
            (b"codec", b"d9:transcodel4:PCMAee", true),
            (b"ptime-reverse", b"40", false),
        ],
    );
    let for_b = sdp_of(ctl.handle(&offer).unwrap());
    let answer = request(
        "a",
        &[
            (b"command", b"answer", false),
            (b"call-id", b"media-fuzz", false),
            (b"from-tag", b"f", false),
            (b"to-tag", b"t", false),
            (b"sdp", sb.as_bytes(), false),
            (b"endpoint-learning", b"off", false),
        ],
    );
    let for_a = sdp_of(ctl.handle(&answer).unwrap());
    let secure = request(
        "s",
        &[
            (b"command", b"block DTMF", false),
            (b"call-id", b"media-fuzz", false),
            (b"from-tag", b"f", false),
            (b"DTMF-security", b"random", false),
            (b"trigger", b"*1", false),
            (b"DTMF-security-trigger", b"tone", false),
        ],
    );
    assert!(String::from_utf8_lossy(ctl.handle(&secure).unwrap()).contains("2:ok"));
    let at = |p: u16| -> SocketAddr { SocketAddr::new("127.0.0.1".parse().unwrap(), p) };
    let mut stun = [0u8; 64];
    let n = rtpflux_core::stun::write_binding(&mut stun, &[3; 12]).unwrap();
    let dtls: &[u8] = &[22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 1, 0, 0];
    let seeds: Vec<Vec<u8>> = vec![
        RTP.to_vec(),
        RTP_EXT.to_vec(),
        RTCP_SR.to_vec(),
        [&[0x80, 101, 0, 9, 0, 0, 1, 0, 1, 2, 3, 4][..], EVENT].concat(),
        stun[..n].to_vec(),
        dtls.to_vec(),
    ];
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for i in 0..20_000 * scale() {
        let s = &seeds[rng.below(seeds.len())];
        let o = &seeds[rng.below(seeds.len())];
        let pkt = if rng.below(5) == 0 {
            rng.bytes(300)
        } else {
            rng.mutate(s, o)
        };
        let from = [&alice, &bob, &stranger][rng.below(3)];
        // To either leg, RTP or RTCP port.
        let port = [for_a, for_b][rng.below(2)] + u16::from(rng.below(2) == 1);
        let _ = from.send_to(&pkt, at(port));
        if i % 500 == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    // The workers are alive: media flows (PCMU to PCMA) and `query` works.
    std::thread::sleep(Duration::from_millis(300));
    bob.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let mut buf = [0u8; 2048];
    while bob.recv_from(&mut buf).is_ok() {}
    bob.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut pkt = vec![0x80, 0, 0x7f, 0, 0, 1, 0, 0, 9, 9, 9, 9];
    pkt.extend_from_slice(&[0xff; 160]);
    let mut got = false;
    for k in 0..10u8 {
        pkt[3] = k;
        alice.send_to(&pkt, at(for_a)).unwrap();
        if bob
            .recv_from(&mut buf)
            .is_ok_and(|(_, _)| buf[1] & 0x7f == 8)
        {
            got = true;
            break;
        }
    }
    assert!(got, "media still relayed (as PCMA)");
    let query = request(
        "q",
        &[
            (b"command", b"query", false),
            (b"call-id", b"media-fuzz", false),
        ],
    );
    assert!(String::from_utf8_lossy(ctl.handle(&query).unwrap()).contains("2:ok"));
}
