//! The `ng` control protocol: a cookie followed by a bencoded dictionary,
//! one message per UDP datagram, as spoken by the `rtpengine` modules of
//! Kamailio and `OpenSIPS`.
//!
//! Zero-copy and allocation-free: a parsed [`Message`] borrows from the
//! datagram, and replies are written into a caller-provided buffer.

// No `unsafe` here, and no way to allow it (AGENTS.md §5).
#![forbid(unsafe_code)]
// Every request is parsed here, from whoever sends one: no indexing or
// arithmetic that could panic (offsets are taken with `get` and checked
// operations), outside the tests.
#![cfg_attr(
    not(test),
    deny(clippy::indexing_slicing, clippy::arithmetic_side_effects)
)]
#![no_std]

pub mod bencode;

use bencode::{Dict, Encoder, Overflow, Value, decode};

/// A request: the cookie that pairs it with its reply, and the dictionary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message<'a> {
    pub cookie: &'a [u8],
    pub body: Dict<'a>,
}

/// Why a datagram is not an `ng` message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageError {
    /// No space separates the cookie from the body, or the cookie is empty.
    NoCookie,
    /// The body is not valid bencode.
    Bencode(bencode::DecodeError),
    /// The body is valid bencode but not a dictionary.
    NotDict,
}

/// Parse a datagram `<cookie> <bencoded dictionary>`.
///
/// # Errors
///
/// Returns a [`MessageError`] when the cookie is missing or the body is not a
/// bencoded dictionary.
pub fn parse_message(datagram: &[u8]) -> Result<Message<'_>, MessageError> {
    let space = datagram
        .iter()
        .position(|&b| b == b' ')
        .ok_or(MessageError::NoCookie)?;
    if space == 0 {
        return Err(MessageError::NoCookie);
    }
    // The cookie, and what follows the space after it.
    let (cookie, rest) = datagram.split_at(space);
    let body = rest.get(1..).unwrap_or_default();
    match decode(body).map_err(MessageError::Bencode)? {
        Value::Dict(body) => Ok(Message { cookie, body }),
        _ => Err(MessageError::NotDict),
    }
}

/// Write a reply `<cookie> <dictionary>` into `out`: the cookie and a space,
/// then whatever `body` encodes (it must write one dictionary). Returns the
/// datagram length.
///
/// # Errors
///
/// [`Overflow`] when `out` is too small.
pub fn write_reply(
    cookie: &[u8],
    out: &mut [u8],
    body: impl FnOnce(&mut Encoder<'_>) -> Result<(), Overflow>,
) -> Result<usize, Overflow> {
    let mut e = Encoder::new(out);
    e.raw(cookie)?;
    e.raw(b" ")?;
    body(&mut e)?;
    Ok(e.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_pong() {
        let m = parse_message(b"5323_1 d7:command4:pinge").unwrap();
        assert_eq!(m.cookie, b"5323_1");
        assert_eq!(m.body.get_bytes(b"command"), Some(&b"ping"[..]));
        let mut out = [0u8; 64];
        let n = write_reply(m.cookie, &mut out, |e| {
            e.dict()?;
            e.bytes(b"result")?;
            e.bytes(b"pong")?;
            e.end()
        })
        .unwrap();
        assert_eq!(&out[..n], b"5323_1 d6:result4:ponge");
    }

    #[test]
    fn rejects_malformed_datagrams() {
        assert_eq!(
            parse_message(b"d7:command4:pinge"),
            Err(MessageError::NoCookie)
        );
        assert_eq!(
            parse_message(b" d7:command4:pinge"),
            Err(MessageError::NoCookie)
        );
        assert_eq!(parse_message(b"c li1ee"), Err(MessageError::NotDict));
        assert!(matches!(
            parse_message(b"c d7:command"),
            Err(MessageError::Bencode(_))
        ));
    }

    #[test]
    fn reply_overflow() {
        let mut out = [0u8; 8];
        assert_eq!(
            write_reply(b"cookie", &mut out, |e| {
                e.dict()?;
                e.end()
            }),
            Err(Overflow)
        );
    }
}
