//! Protocol kernels of rtpflux: pure functions over packets and session
//! state, with no I/O and no allocation (`no_std`, no `alloc`), so they run
//! on the hot path and can be tested and checked in isolation.

// No `unsafe` here, and no way to allow it (AGENTS.md §5).
#![forbid(unsafe_code)]
// Packets, SDP and STUN from the network go through here: no unchecked
// indexing or arithmetic that could panic on them (AGENTS.md §5). Tests
// may, and so may the tables built at compile time.
#![cfg_attr(
    not(test),
    deny(clippy::indexing_slicing, clippy::arithmetic_side_effects)
)]
#![no_std]

pub mod dsp;
pub mod dtls;
pub mod dtmf;
pub mod dtmf_inband;
pub mod g711;
pub mod g722;
pub mod ice;
pub mod latch;
pub mod ports;
pub mod relay;
pub mod ring;
pub mod rtcp;
pub mod rtp;
pub mod sdp;
pub mod stun;
