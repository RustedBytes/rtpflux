//! SRTP and SRTCP (RFC 3711) with the AES counter-mode suites
//! (`AES_CM_128_HMAC_SHA1_80/32`, RFC 4568 §6.2; `AES_256_CM_HMAC_SHA1_80/32`,
//! RFC 6188) and the AES-GCM suites (`AEAD_AES_128_GCM`,
//! `AEAD_AES_256_GCM`, RFC 7714).
//!
//! * Key derivation (RFC 3711 §4.3) with AES-CM as the PRF under the master
//!   key (AES-128 or AES-256, RFC 6188 §3), key derivation rate 0. The
//!   96-bit master salt of the GCM suites is zero-padded on the right to
//!   112 bits, as libsrtp and the WebRTC stacks do.
//! * Counter mode (RFC 3711 §4.1.1): IV = salt·2^16 ⊕ SSRC·2^64 ⊕
//!   index·2^16; HMAC-SHA1 over the packet and the rollover counter,
//!   truncated to 80 or 32 bits (SRTCP always 80).
//! * GCM (RFC 7714): IV = salt ⊕ (0 ‖ SSRC ‖ ROC ‖ SEQ) for SRTP and
//!   salt ⊕ (0 ‖ SSRC ‖ 0 ‖ SRTCP index) for SRTCP; the RTP header (SRTCP:
//!   the first 8 octets and the E ‖ index word) is the associated data; a
//!   16-octet tag; SRTCP carries the E ‖ index word after the tag.
//! * Index estimation (Appendix A) and a 64-packet replay window (§3.3.2).
//!
//! Everything works in place on the caller's buffer: protecting encrypts
//! and appends the tag, unprotecting verifies (constant time), decrypts and
//! returns the shorter length. Keys are expanded once per context; nothing
//! is allocated.
//!
//! A context keeps the state of up to [`MAX_SOURCES`] SSRCs (RFC 3711
//! §3.2.3), each created by the first authenticated packet of a new SSRC
//! under the same master key (RFC 4568 §6.4 late binding).

// No `unsafe` here, and no way to allow it (AGENTS.md §5).
#![forbid(unsafe_code)]
// Packets from the network go through here: no unchecked indexing or
// arithmetic that could panic on them (AGENTS.md §5). Tests may.
#![cfg_attr(
    not(test),
    deny(clippy::indexing_slicing, clippy::arithmetic_side_effects)
)]
#![no_std]

mod cipher;
mod protect;
mod replay;
mod ssrc;
mod suite;
mod unprotect;

use aes::cipher::{InnerIvInit, KeyInit, StreamCipher};
use aes::{Aes128, Aes256};
use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use hmac::{Hmac, Mac};
use sha1::Sha1;

use cipher::{SessionKeys, rtcp_iv, rtp_iv};
pub use protect::Protect;
pub use replay::MAX_SOURCES;
use replay::{SeqState, Sources, at_chunk, at_chunk_mut, be16, index, rtp_header_len, ssrc_at};
pub use ssrc::Ssrc;
use suite::master_key;
pub use suite::{MasterKey, Policy, Suite};
pub use unprotect::Unprotect;

type HmacSha1 = Hmac<Sha1>;

/// Master key and salt of the `AES_CM_128` suites, as carried in SDES.
pub const MASTER_LEN: usize = 30;
/// The longest master key and salt (`AES_256_CM`: 32 + 14).
pub const MAX_MASTER_LEN: usize = 46;
/// The longest SRTCP trailer (GCM: 16-octet tag, E ‖ index).
pub const MAX_SRTCP_TRAILER: usize = 20;
/// SRTCP trailer of the counter-mode suites: E ‖ index, then an 80-bit tag.
pub const SRTCP_TRAILER: usize = 4 + 10;
/// The longest SRTP tag (GCM).
pub const MAX_RTP_TAG: usize = 16;

/// Why a packet was not protected or unprotected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Shorter than its header (and tag), or not version 2.
    Malformed,
    /// The buffer has no room for the trailer.
    BufferTooSmall,
    /// The authentication tag does not match.
    Auth,
    /// Already received, or older than the replay window.
    Replay,
    /// A new SSRC, but the context already tracks [`MAX_SOURCES`].
    TooManySources,
}

#[cfg(test)]
mod tests;
