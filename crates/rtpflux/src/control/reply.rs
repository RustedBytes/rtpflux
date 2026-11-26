//! Reply values built in memory (`list`, `query`) and their bencoding.

#[allow(clippy::wildcard_imports)]
use super::*;

/// A reply value built in memory (for `list` and `query`).
#[derive(Debug, Clone)]
pub(super) enum B {
    Int(i64),
    Bytes(Vec<u8>),
    List(Vec<B>),
    /// Encoded with its keys sorted, as bencode requires.
    Dict(Vec<(Vec<u8>, B)>),
}

impl B {
    pub(super) fn encode(&self, e: &mut Encoder<'_>) -> Result<(), rtpflux_ng::bencode::Overflow> {
        match self {
            B::Int(n) => e.int(*n),
            B::Bytes(b) => e.bytes(b),
            B::List(l) => {
                e.list()?;
                for v in l {
                    v.encode(e)?;
                }
                e.end()
            }
            B::Dict(d) => {
                let mut d: Vec<&(Vec<u8>, B)> = d.iter().collect();
                d.sort_by(|a, b| a.0.cmp(&b.0));
                e.dict()?;
                for (k, v) in d {
                    e.bytes(k)?;
                    v.encode(e)?;
                }
                e.end()
            }
        }
    }

    pub(super) fn dict(entries: &[(&str, B)]) -> B {
        B::Dict(
            entries
                .iter()
                .map(|(k, v)| (k.as_bytes().to_vec(), v.clone()))
                .collect(),
        )
    }

    pub(super) fn int(n: u64) -> B {
        B::Int(i64::try_from(n).unwrap_or(i64::MAX))
    }
}

/// What a successful command returns besides `result`.
pub(super) enum Reply {
    Pong,
    Ok,
    /// The rewritten SDP, in `sdp_buf`.
    Sdp(usize),
    Fields(Vec<(Vec<u8>, B)>),
}

/// Counters in rtpengine's `query` form.
pub(super) fn stats(packets: u64, bytes: u64, errors: u64) -> B {
    B::dict(&[
        ("packets", B::int(packets)),
        ("bytes", B::int(bytes)),
        ("errors", B::int(errors)),
    ])
}

/// One stream of `query`: local port, peer endpoint, counters and the
/// telephone events received.
pub(super) fn stream_dict(leg: &crate::relay::LegStats) -> B {
    let endpoint = leg.peer.map_or_else(
        || B::dict(&[]),
        |p| {
            B::dict(&[
                (
                    "family",
                    B::Bytes(if p.is_ipv4() {
                        b"IPv4".to_vec()
                    } else {
                        b"IPv6".to_vec()
                    }),
                ),
                ("address", B::Bytes(p.ip().to_string().into_bytes())),
                ("port", B::int(u64::from(p.port()))),
            ])
        },
    );
    let dtmf = leg
        .dtmf
        .iter()
        .map(|e| {
            let event =
                rtpflux_core::dtmf::digit(e.code).map_or_else(|| e.code.to_string(), String::from);
            B::dict(&[
                ("event", B::Bytes(event.into_bytes())),
                ("timestamp", B::int(u64::from(e.ts))),
                ("duration", B::int(u64::from(e.duration_ms))),
            ])
        })
        .collect();
    let mut fields = vec![
        ("local port", B::int(u64::from(leg.local_port))),
        ("endpoint", endpoint),
        ("stats", stats(leg.packets, leg.octets, leg.dropped)),
        ("DTMF", B::List(dtmf)),
    ];
    if leg.rtcp.reports > 0 {
        fields.push(("RTCP", rtcp_dict(&leg.rtcp)));
    }
    B::dict(&fields)
}

/// The latest RTCP reports of a leg's peer: its SSRC, what it sent (SR)
/// and what it receives (first report block; fraction lost in 1/256), and
/// its round trip to the relay.
pub(super) fn rtcp_dict(r: &crate::relay::RtcpStats) -> B {
    let mut fields = vec![
        ("reports", B::int(r.reports)),
        ("SSRC", B::int(u64::from(r.ssrc.get()))),
    ];
    if let Some(s) = r.sender {
        fields.push(("sender packets", B::int(u64::from(s.packets))));
        fields.push(("sender octets", B::int(u64::from(s.octets))));
    }
    if let Some(b) = r.block {
        fields.push(("reported SSRC", B::int(u64::from(b.ssrc.get()))));
        fields.push(("fraction lost", B::int(u64::from(b.fraction))));
        // Cumulative loss is signed (duplicates make it negative).
        fields.push(("packets lost", B::Int(i64::from(b.lost))));
        fields.push(("highest sequence", B::int(u64::from(b.highest))));
        fields.push(("jitter", B::int(u64::from(b.jitter))));
    }
    if let Some(ms) = r.rtt_ms {
        fields.push(("RTT", B::int(u64::from(ms))));
    }
    B::dict(&fields)
}
