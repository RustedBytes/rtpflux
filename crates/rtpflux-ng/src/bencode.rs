//! Bencode: integers `i<n>e`, byte strings `<len>:<bytes>`, lists `l…e`
//! and dictionaries `d…e` with byte-string keys.
//!
//! Zero-copy and allocation-free. [`decode`] validates the whole input once
//! (strict integers: no leading zeros, no `-0`; no duplicate dictionary
//! keys; nesting bounded by [`MAX_DEPTH`], dictionaries by [`MAX_KEYS`])
//! and returns a [`Value`] that borrows from it: byte strings are slices,
//! lists and dictionaries are validated slices decoded lazily by their
//! iterators. Walking validated input is linear (`skip`), so decoding
//! and reading cost O(input) apart from the bounded duplicate-key check.
//! [`Encoder`] writes into a caller-provided buffer.

/// Maximum nesting of lists and dictionaries accepted by [`decode`].
pub const MAX_DEPTH: usize = 32;

/// Maximum keys in one dictionary (the duplicate check compares each key
/// with the earlier ones). `ng` messages carry a few dozen.
pub const MAX_KEYS: usize = 256;

/// A decoded value borrowing from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value<'a> {
    Int(i64),
    Bytes(&'a [u8]),
    List(List<'a>),
    Dict(Dict<'a>),
}

/// A validated list: the encoded items between `l` and `e`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct List<'a> {
    raw: &'a [u8],
}

/// A validated dictionary: the encoded entries between `d` and `e`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dict<'a> {
    raw: &'a [u8],
}

/// Why input is not bencode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Input ended inside a value.
    UnexpectedEnd,
    /// A byte that cannot start or continue the current value, at this offset.
    Unexpected(usize),
    /// A malformed or out-of-range integer or length, at this offset.
    BadNumber(usize),
    /// A dictionary repeats a key, at this offset.
    DuplicateKey(usize),
    /// Nesting deeper than [`MAX_DEPTH`].
    TooDeep,
    /// A dictionary with more than [`MAX_KEYS`] keys, at this offset.
    TooManyKeys(usize),
    /// Bytes remain after the top-level value, at this offset.
    TrailingData(usize),
}

/// Validate `input` as exactly one bencoded value and return a view of it.
///
/// # Errors
///
/// Returns a [`DecodeError`] describing the first problem found.
pub fn decode(input: &[u8]) -> Result<Value<'_>, DecodeError> {
    let end = validate(input, 0, 0)?;
    if end != input.len() {
        return Err(DecodeError::TrailingData(end));
    }
    Ok(read(input, 0).map_or(Value::Int(0), |(v, _)| v))
}

/// The length of the bencoded value that starts `input`, for reading values
/// from a stream: `None` when `input` ends inside it.
///
/// # Errors
///
/// A [`DecodeError`] other than [`DecodeError::UnexpectedEnd`] when the
/// bytes cannot start a valid value.
pub fn item_len(input: &[u8]) -> Result<Option<usize>, DecodeError> {
    match validate(input, 0, 0) {
        Ok(end) => Ok(Some(end)),
        Err(DecodeError::UnexpectedEnd) => Ok(None),
        Err(e) => Err(e),
    }
}

impl<'a> List<'a> {
    /// The items, decoded on demand.
    #[must_use]
    pub fn iter(&self) -> ListIter<'a> {
        ListIter {
            raw: self.raw,
            pos: 0,
        }
    }
}

impl<'a> Dict<'a> {
    /// The entries in input order, decoded on demand.
    #[must_use]
    pub fn iter(&self) -> DictIter<'a> {
        DictIter {
            raw: self.raw,
            pos: 0,
        }
    }

    /// The value of `key` (keys are unique after validation).
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<Value<'a>> {
        self.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    /// The byte-string value of `key`.
    #[must_use]
    pub fn get_bytes(&self, key: &[u8]) -> Option<&'a [u8]> {
        match self.get(key)? {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }
}

impl<'a> IntoIterator for List<'a> {
    type Item = Value<'a>;
    type IntoIter = ListIter<'a>;
    fn into_iter(self) -> ListIter<'a> {
        self.iter()
    }
}

impl<'a> IntoIterator for Dict<'a> {
    type Item = (&'a [u8], Value<'a>);
    type IntoIter = DictIter<'a>;
    fn into_iter(self) -> DictIter<'a> {
        self.iter()
    }
}

impl<'a> IntoIterator for &List<'a> {
    type Item = Value<'a>;
    type IntoIter = ListIter<'a>;
    fn into_iter(self) -> ListIter<'a> {
        self.iter()
    }
}

impl<'a> IntoIterator for &Dict<'a> {
    type Item = (&'a [u8], Value<'a>);
    type IntoIter = DictIter<'a>;
    fn into_iter(self) -> DictIter<'a> {
        self.iter()
    }
}

/// Iterator over a [`List`].
#[derive(Debug, Clone)]
pub struct ListIter<'a> {
    raw: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for ListIter<'a> {
    type Item = Value<'a>;
    fn next(&mut self) -> Option<Value<'a>> {
        let (v, next) = read(self.raw, self.pos)?;
        self.pos = next;
        Some(v)
    }
}

/// Iterator over a [`Dict`].
#[derive(Debug, Clone)]
pub struct DictIter<'a> {
    raw: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for DictIter<'a> {
    type Item = (&'a [u8], Value<'a>);
    fn next(&mut self) -> Option<Self::Item> {
        let (key, after_key) = read_bytes(self.raw, self.pos)?;
        let (v, next) = read(self.raw, after_key)?;
        self.pos = next;
        Some((key, v))
    }
}

// ---- validation (one pass, bounded recursion, no allocation) ----
//
// Offsets are checked as they are used (`get`, `checked_add`): an offset
// past the input is an error (`UnexpectedEnd`), never a panic, whatever the
// input (the crate denies unchecked indexing and arithmetic).

/// The offset after `p`.
fn next(p: usize) -> Result<usize, DecodeError> {
    p.checked_add(1).ok_or(DecodeError::UnexpectedEnd)
}

/// `input[from..to]`, or the end of input.
fn span(input: &[u8], from: usize, to: usize) -> Result<&[u8], DecodeError> {
    input.get(from..to).ok_or(DecodeError::UnexpectedEnd)
}

fn find(input: &[u8], from: usize, byte: u8) -> Result<usize, DecodeError> {
    input
        .get(from..)
        .and_then(|s| s.iter().position(|&b| b == byte))
        .and_then(|i| from.checked_add(i))
        .ok_or(DecodeError::UnexpectedEnd)
}

/// The value of ASCII digit `d`.
fn digit(d: u8) -> Option<u8> {
    d.is_ascii_digit().then(|| d.wrapping_sub(b'0'))
}

fn parse_len(digits: &[u8], at: usize) -> Result<usize, DecodeError> {
    if digits.is_empty()
        || !digits.iter().all(u8::is_ascii_digit)
        || (digits.len() > 1 && digits.first() == Some(&b'0'))
    {
        return Err(DecodeError::BadNumber(at));
    }
    digits.iter().try_fold(0usize, |acc, &d| {
        acc.checked_mul(10)
            .and_then(|a| a.checked_add(usize::from(digit(d)?)))
            .ok_or(DecodeError::BadNumber(at))
    })
}

fn parse_int(text: &[u8], at: usize) -> Result<i64, DecodeError> {
    let (negative, digits) = match text.split_first() {
        Some((b'-', rest)) => (true, rest),
        _ => (false, text),
    };
    if digits.is_empty()
        || !digits.iter().all(u8::is_ascii_digit)
        || (digits.len() > 1 && digits.first() == Some(&b'0'))
        || (negative && digits == b"0")
    {
        return Err(DecodeError::BadNumber(at));
    }
    // Accumulate negatively so that i64::MIN is representable.
    let magnitude = digits.iter().try_fold(0i64, |acc, &d| {
        acc.checked_mul(10)
            .and_then(|a| a.checked_sub(i64::from(digit(d)?)))
            .ok_or(DecodeError::BadNumber(at))
    })?;
    if negative {
        Ok(magnitude)
    } else {
        magnitude.checked_neg().ok_or(DecodeError::BadNumber(at))
    }
}

/// Validate a byte string at `pos`; returns (content start, end).
fn validate_bytes(input: &[u8], pos: usize) -> Result<(usize, usize), DecodeError> {
    let colon = find(input, pos, b':')?;
    let len = parse_len(span(input, pos, colon)?, pos)?;
    let start = next(colon)?;
    let end = start.checked_add(len).ok_or(DecodeError::BadNumber(pos))?;
    if end > input.len() {
        return Err(DecodeError::UnexpectedEnd);
    }
    Ok((start, end))
}

/// Validate the value at `pos`; returns the offset just past it.
fn validate(input: &[u8], pos: usize, depth: usize) -> Result<usize, DecodeError> {
    match input.get(pos) {
        None => Err(DecodeError::UnexpectedEnd),
        Some(b'i') => {
            let first = next(pos)?;
            let end = find(input, first, b'e')?;
            parse_int(span(input, first, end)?, first)?;
            next(end)
        }
        Some(b'0'..=b'9') => validate_bytes(input, pos).map(|(_, end)| end),
        Some(b'l') => {
            if depth >= MAX_DEPTH {
                return Err(DecodeError::TooDeep);
            }
            let mut p = next(pos)?;
            loop {
                match input.get(p) {
                    None => return Err(DecodeError::UnexpectedEnd),
                    Some(b'e') => return next(p),
                    Some(_) => p = validate(input, p, next(depth)?)?,
                }
            }
        }
        Some(b'd') => {
            if depth >= MAX_DEPTH {
                return Err(DecodeError::TooDeep);
            }
            let first = next(pos)?;
            let mut p = first;
            let mut keys = 0usize;
            loop {
                match input.get(p) {
                    None => return Err(DecodeError::UnexpectedEnd),
                    Some(b'e') => return next(p),
                    Some(b'0'..=b'9') => {
                        keys = next(keys)?;
                        if keys > MAX_KEYS {
                            return Err(DecodeError::TooManyKeys(p));
                        }
                        let (ks, ke) = validate_bytes(input, p)?;
                        if key_seen(input, first, p, span(input, ks, ke)?) {
                            return Err(DecodeError::DuplicateKey(p));
                        }
                        p = validate(input, ke, next(depth)?)?;
                    }
                    Some(_) => return Err(DecodeError::Unexpected(p)),
                }
            }
        }
        Some(_) => Err(DecodeError::Unexpected(pos)),
    }
}

/// Whether `key` occurs among the already-validated entries of the
/// dictionary body `input[from..until]`.
fn key_seen(input: &[u8], from: usize, until: usize, key: &[u8]) -> bool {
    let Some(raw) = input.get(..until) else {
        return false;
    };
    let mut it = DictIter { raw, pos: from };
    it.any(|(k, _)| k == key)
}

// ---- reading validated input (no errors possible; `None` ends iteration) ----
//
// The same checks as validation (`get`, `checked_add`), so that reading
// cannot panic even on input it was not given validated.

fn read_bytes(raw: &[u8], pos: usize) -> Option<(&[u8], usize)> {
    let colon = pos.checked_add(raw.get(pos..)?.iter().position(|&b| b == b':')?)?;
    let len = parse_len(raw.get(pos..colon)?, pos).ok()?;
    let start = colon.checked_add(1)?;
    let end = start.checked_add(len)?;
    Some((raw.get(start..end)?, end))
}

/// The offset just past an integer `i<n>e` at `pos`.
fn int_end(raw: &[u8], pos: usize) -> Option<usize> {
    let first = pos.checked_add(1)?;
    first.checked_add(raw.get(first..)?.iter().position(|&b| b == b'e')?)
}

/// The offset just past the validated value at `pos`: one linear walk,
/// counting list and dictionary nesting (no re-validation).
fn skip(raw: &[u8], pos: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut p = pos;
    loop {
        match raw.get(p)? {
            b'i' => p = int_end(raw, p)?.checked_add(1)?,
            b'0'..=b'9' => p = read_bytes(raw, p)?.1,
            b'l' | b'd' => {
                depth = depth.checked_add(1)?;
                p = p.checked_add(1)?;
                continue;
            }
            b'e' => {
                depth = depth.checked_sub(1)?;
                p = p.checked_add(1)?;
            }
            _ => return None,
        }
        if depth == 0 {
            return Some(p);
        }
    }
}

fn read(raw: &[u8], pos: usize) -> Option<(Value<'_>, usize)> {
    let kind = *raw.get(pos)?;
    match kind {
        b'i' => {
            let end = int_end(raw, pos)?;
            let text = raw.get(pos.checked_add(1)?..end)?;
            Some((Value::Int(parse_int(text, pos).ok()?), end.checked_add(1)?))
        }
        b'0'..=b'9' => read_bytes(raw, pos).map(|(b, end)| (Value::Bytes(b), end)),
        b'l' | b'd' => {
            let end = skip(raw, pos)?;
            let body = raw.get(pos.checked_add(1)?..end.checked_sub(1)?)?;
            let v = if kind == b'l' {
                Value::List(List { raw: body })
            } else {
                Value::Dict(Dict { raw: body })
            };
            Some((v, end))
        }
        _ => None,
    }
}

// ---- encoding into a caller buffer ----

/// The output buffer is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overflow;

/// Writes bencode into a borrowed buffer. Dictionary keys must be written
/// in ascending byte order (canonical bencode); the encoder does not sort.
#[derive(Debug)]
pub struct Encoder<'b> {
    out: &'b mut [u8],
    pos: usize,
}

impl<'b> Encoder<'b> {
    #[must_use]
    pub fn new(out: &'b mut [u8]) -> Self {
        Encoder { out, pos: 0 }
    }

    /// Bytes written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pos
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }

    /// Append raw bytes.
    ///
    /// # Errors
    ///
    /// [`Overflow`] when the buffer is full.
    pub fn raw(&mut self, b: &[u8]) -> Result<(), Overflow> {
        let end = self.pos.checked_add(b.len()).ok_or(Overflow)?;
        self.out
            .get_mut(self.pos..end)
            .ok_or(Overflow)?
            .copy_from_slice(b);
        self.pos = end;
        Ok(())
    }

    fn decimal(&mut self, n: u64) -> Result<(), Overflow> {
        // u64::MAX has 20 digits: they fill `digits` from the end.
        let mut digits = [0u8; 20];
        let mut i = digits.len();
        let mut m = n;
        loop {
            i = i.checked_sub(1).ok_or(Overflow)?;
            // `m % 10 < 10` fits in a u8.
            #[allow(clippy::cast_possible_truncation)]
            let d = m.checked_rem(10).ok_or(Overflow)? as u8;
            *digits.get_mut(i).ok_or(Overflow)? = b'0'.wrapping_add(d);
            m = m.checked_div(10).ok_or(Overflow)?;
            if m == 0 {
                break;
            }
        }
        self.raw(digits.get(i..).ok_or(Overflow)?)
    }

    /// `i<n>e`.
    ///
    /// # Errors
    ///
    /// [`Overflow`] when the buffer is full.
    pub fn int(&mut self, n: i64) -> Result<(), Overflow> {
        self.raw(b"i")?;
        if n < 0 {
            self.raw(b"-")?;
        }
        self.decimal(n.unsigned_abs())?;
        self.raw(b"e")
    }

    /// `<len>:<bytes>`.
    ///
    /// # Errors
    ///
    /// [`Overflow`] when the buffer is full.
    pub fn bytes(&mut self, b: &[u8]) -> Result<(), Overflow> {
        self.decimal(b.len() as u64)?;
        self.raw(b":")?;
        self.raw(b)
    }

    /// Open a list; close it with [`Encoder::end`].
    ///
    /// # Errors
    ///
    /// [`Overflow`] when the buffer is full.
    pub fn list(&mut self) -> Result<(), Overflow> {
        self.raw(b"l")
    }

    /// Open a dictionary; write key/value pairs, then [`Encoder::end`].
    ///
    /// # Errors
    ///
    /// [`Overflow`] when the buffer is full.
    pub fn dict(&mut self) -> Result<(), Overflow> {
        self.raw(b"d")
    }

    /// Close the innermost list or dictionary.
    ///
    /// # Errors
    ///
    /// [`Overflow`] when the buffer is full.
    pub fn end(&mut self) -> Result<(), Overflow> {
        self.raw(b"e")
    }

    /// Copy an already-encoded value (e.g. one taken from a request).
    ///
    /// # Errors
    ///
    /// [`Overflow`] when the buffer is full.
    pub fn value(&mut self, v: Value<'_>) -> Result<(), Overflow> {
        match v {
            Value::Int(n) => self.int(n),
            Value::Bytes(b) => self.bytes(b),
            Value::List(l) => {
                self.list()?;
                self.raw(l.raw)?;
                self.end()
            }
            Value::Dict(d) => {
                self.dict()?;
                self.raw(d.raw)?;
                self.end()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_each_kind() {
        assert_eq!(decode(b"i42e"), Ok(Value::Int(42)));
        assert_eq!(decode(b"i-7e"), Ok(Value::Int(-7)));
        assert_eq!(decode(b"i0e"), Ok(Value::Int(0)));
        assert_eq!(decode(b"4:spam"), Ok(Value::Bytes(b"spam")));
        assert_eq!(decode(b"0:"), Ok(Value::Bytes(b"")));
        let Ok(Value::List(l)) = decode(b"l4:spami1ee") else {
            panic!("not a list")
        };
        assert!(l.iter().eq([Value::Bytes(b"spam"), Value::Int(1)]));
        let Ok(Value::Dict(d)) = decode(b"d3:bar4:spam3:fooi42ee") else {
            panic!("not a dict")
        };
        assert_eq!(d.get(b"foo"), Some(Value::Int(42)));
        assert_eq!(d.get_bytes(b"bar"), Some(&b"spam"[..]));
        assert_eq!(d.get(b"baz"), None);
    }

    #[test]
    fn values_borrow_from_input() {
        let input = *b"d3:sdp5:v=0\r\ne";
        let Ok(Value::Dict(d)) = decode(&input) else {
            panic!("not a dict")
        };
        let sdp = d.get_bytes(b"sdp").unwrap();
        assert_eq!(sdp, b"v=0\r\n");
        // the slice points into `input`
        assert!(input.as_ptr_range().contains(&sdp.as_ptr()));
    }

    #[test]
    fn integer_bounds() {
        assert_eq!(decode(b"i9223372036854775807e"), Ok(Value::Int(i64::MAX)));
        assert_eq!(decode(b"i-9223372036854775808e"), Ok(Value::Int(i64::MIN)));
        assert!(matches!(
            decode(b"i9223372036854775808e"),
            Err(DecodeError::BadNumber(_))
        ));
    }

    #[test]
    fn rejects_non_canonical_and_malformed() {
        for bad in [&b"i-0e"[..], b"i03e", b"ie", b"i-e", b"01:a", b"i1x2e"] {
            assert!(
                matches!(decode(bad), Err(DecodeError::BadNumber(_))),
                "{bad:?}"
            );
        }
        assert_eq!(decode(b"5:spam"), Err(DecodeError::UnexpectedEnd));
        assert_eq!(decode(b"l"), Err(DecodeError::UnexpectedEnd));
        assert_eq!(decode(b"i1ei2e"), Err(DecodeError::TrailingData(3)));
        assert_eq!(decode(b"di1ei2ee"), Err(DecodeError::Unexpected(1)));
        assert_eq!(decode(b"d1:ai1e1:ai2ee"), Err(DecodeError::DuplicateKey(7)));
        assert_eq!(decode(b"x"), Err(DecodeError::Unexpected(0)));
    }

    #[test]
    fn depth_is_bounded() {
        let mut deep = [0u8; 2 * (MAX_DEPTH + 1)];
        deep[..=MAX_DEPTH].fill(b'l');
        deep[MAX_DEPTH + 1..].fill(b'e');
        assert_eq!(decode(&deep), Err(DecodeError::TooDeep));
        let mut ok = [0u8; 2 * MAX_DEPTH];
        ok[..MAX_DEPTH].fill(b'l');
        ok[MAX_DEPTH..].fill(b'e');
        assert!(decode(&ok).is_ok());
    }

    #[test]
    fn nested_iteration() {
        let Ok(Value::Dict(d)) = decode(b"d5:flagsl13:trust-address13:strict-sourcee1:ni-12ee")
        else {
            panic!()
        };
        let Some(Value::List(flags)) = d.get(b"flags") else {
            panic!()
        };
        assert!(flags.iter().eq([
            Value::Bytes(b"trust-address"),
            Value::Bytes(b"strict-source")
        ]));
        assert_eq!(d.get(b"n"), Some(Value::Int(-12)));
        assert_eq!(d.iter().count(), 2);
    }

    #[test]
    fn encoder_round_trip() {
        let mut buf = [0u8; 128];
        let mut e = Encoder::new(&mut buf);
        e.dict().unwrap();
        e.bytes(b"command").unwrap();
        e.bytes(b"offer").unwrap();
        e.bytes(b"flags").unwrap();
        e.list().unwrap();
        e.bytes(b"trust-address").unwrap();
        e.end().unwrap();
        e.bytes(b"n").unwrap();
        e.int(i64::MIN).unwrap();
        e.end().unwrap();
        let n = e.len();
        let Ok(Value::Dict(d)) = decode(&buf[..n]) else {
            panic!()
        };
        assert_eq!(d.get_bytes(b"command"), Some(&b"offer"[..]));
        assert_eq!(d.get(b"n"), Some(Value::Int(i64::MIN)));
        // copying a decoded value reproduces its encoding
        let mut out = [0u8; 128];
        let mut e2 = Encoder::new(&mut out);
        e2.value(Value::Dict(d)).unwrap();
        let m = e2.len();
        assert_eq!(&out[..m], &buf[..n]);
    }

    #[test]
    fn encoder_reports_overflow() {
        let mut buf = [0u8; 4];
        let mut e = Encoder::new(&mut buf);
        assert_eq!(e.bytes(b"spam"), Err(Overflow));
    }

    #[test]
    fn nesting_truncation_iteration_and_reencoding() {
        extern crate std;
        use std::vec::Vec;
        // Nesting: lists and dictionaries are bounded alike.
        let deep_list: Vec<u8> = [&[b'l'; MAX_DEPTH + 1][..], &[b'e'; MAX_DEPTH + 1][..]].concat();
        assert_eq!(decode(&deep_list), Err(DecodeError::TooDeep));
        let mut deep_dict = Vec::new();
        for _ in 0..=MAX_DEPTH {
            deep_dict.extend_from_slice(b"d1:k");
        }
        deep_dict.extend_from_slice(b"i0e");
        deep_dict.extend(core::iter::repeat_n(b'e', MAX_DEPTH + 1));
        assert_eq!(decode(&deep_dict), Err(DecodeError::TooDeep));
        assert_eq!(decode(b"li1e"), Err(DecodeError::UnexpectedEnd));
        assert_eq!(decode(b"d1:ki1e"), Err(DecodeError::UnexpectedEnd));
        // Iteration by value and by reference.
        let Ok(Value::Dict(d)) = decode(b"d1:ali1ei2ee1:bi3ee") else {
            unreachable!()
        };
        assert_eq!((&d).into_iter().count(), 2);
        let Some(Value::List(l)) = d.get(b"a") else {
            unreachable!()
        };
        assert_eq!((&l).into_iter().count(), 2);
        assert_eq!(l.into_iter().count(), 2);
        assert_eq!(d.into_iter().count(), 2);
        assert_eq!(d.get_bytes(b"b"), None, "an integer, not bytes");
        // Re-encoding decoded values copies them.
        let mut buf = [0u8; 64];
        let mut e = Encoder::new(&mut buf);
        assert!(e.is_empty());
        e.list().unwrap();
        for v in [
            Value::Int(-4),
            Value::Bytes(b"x"),
            Value::List(l),
            Value::Dict(d),
        ] {
            e.value(v).unwrap();
        }
        e.end().unwrap();
        assert!(!e.is_empty());
        let n = e.len();
        assert_eq!(&buf[..n], b"li-4e1:xli1ei2eed1:ali1ei2ee1:bi3eee");
    }

    /// Nested and wide dictionaries decode in time linear in their size
    /// (re-validating each nested value on every read was exponential in
    /// the depth: 280 octets took seconds).
    #[test]
    fn nesting_costs_linear_time() {
        extern crate std;
        use std::string::String;
        fn nest(k: usize) -> String {
            if k == 0 {
                return String::from("i0e");
            }
            std::format!("d1:a{}1:bi0e1:ci0ee", nest(k - 1))
        }
        let deep = nest(MAX_DEPTH);
        let t = std::time::Instant::now();
        let Ok(Value::Dict(mut d)) = decode(deep.as_bytes()) else {
            panic!("not decoded")
        };
        // Walk down to the innermost value, reading every level.
        for _ in 1..MAX_DEPTH {
            assert_eq!(d.iter().count(), 3);
            let Some(Value::Dict(inner)) = d.get(b"a") else {
                panic!("no nested dict")
            };
            d = inner;
        }
        assert_eq!(d.get(b"a"), Some(Value::Int(0)));
        assert!(
            t.elapsed() < std::time::Duration::from_millis(200),
            "{:?}",
            t.elapsed()
        );
    }

    #[test]
    fn dictionaries_have_a_key_limit() {
        extern crate std;
        use std::string::String;
        let dict = |n: usize| {
            let mut s = String::from("d");
            for i in 0..n {
                use core::fmt::Write as _;
                let _ = write!(s, "5:{i:05}i0e");
            }
            s.push('e');
            s
        };
        assert!(decode(dict(MAX_KEYS).as_bytes()).is_ok());
        assert!(matches!(
            decode(dict(MAX_KEYS + 1).as_bytes()),
            Err(DecodeError::TooManyKeys(_))
        ));
    }
}
