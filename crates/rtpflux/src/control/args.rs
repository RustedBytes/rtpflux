//! Reading request values the way proxies send them: a number is an
//! integer or its decimal text (the `rtpengine` modules send both), and a
//! list of names is a list of strings (or, where one will do, a string).

use super::{Error, RequestError};
use rtpflux_ng::bencode::{Dict, Value};

/// An integer or its decimal text (spaces around it allowed).
fn as_number(v: Value<'_>) -> Option<i64> {
    match v {
        Value::Int(n) => Some(n),
        Value::Bytes(b) => core::str::from_utf8(b).ok()?.trim().parse().ok(),
        _ => None,
    }
}

/// The number under `key`: `None` when absent; a value that is not a
/// number is refused (named in the error).
pub(super) fn number(d: &Dict<'_>, key: &[u8]) -> Result<Option<i64>, Error> {
    d.get(key)
        .map(|v| {
            as_number(v).ok_or_else(|| {
                Error::Request(RequestError::NotANumber(
                    String::from_utf8_lossy(key).into_owned(),
                ))
            })
        })
        .transpose()
}

/// The number under `key`, if there is one that is a number (for options
/// that fall back to a default).
pub(super) fn number_or_none(d: &Dict<'_>, key: &[u8]) -> Option<i64> {
    d.get(key).and_then(as_number)
}

/// The strings of list `v` (other items skipped).
pub(super) fn strings(v: Option<Value<'_>>) -> Vec<&[u8]> {
    match v {
        Some(Value::List(l)) => l
            .iter()
            .filter_map(|v| match v {
                Value::Bytes(b) => Some(b),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// The strings of list `v`, or `v` itself when it is one string.
pub(super) fn strings_or_one(v: Option<Value<'_>>) -> Vec<&[u8]> {
    match v {
        Some(Value::Bytes(b)) => vec![b],
        v => strings(v),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtpflux_ng::bencode::decode;

    fn dict(bencode: &[u8]) -> Dict<'_> {
        match decode(bencode) {
            Ok(Value::Dict(d)) => d,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn numbers_are_integers_or_their_text() {
        let d = dict(b"d1:ai-5e1:b4: 42 1:c3:x121:dlee");
        assert_eq!(number(&d, b"a").unwrap(), Some(-5));
        assert_eq!(number(&d, b"b").unwrap(), Some(42));
        assert_eq!(number(&d, b"z").unwrap(), None);
        assert!(number(&d, b"c").unwrap_err().to_string().contains('c'));
        assert!(number(&d, b"d").is_err(), "a list is no number");
        assert_eq!(number_or_none(&d, b"c"), None);
        assert_eq!(number_or_none(&d, b"b"), Some(42));
    }

    #[test]
    fn lists_of_strings() {
        let d = dict(b"d1:al1:xi1e1:ye1:b1:ze");
        assert_eq!(strings(d.get(b"a")), [&b"x"[..], b"y"]);
        assert_eq!(strings(d.get(b"b")), Vec::<&[u8]>::new());
        assert_eq!(strings_or_one(d.get(b"b")), [&b"z"[..]]);
        assert_eq!(strings_or_one(d.get(b"none")), Vec::<&[u8]>::new());
    }
}
