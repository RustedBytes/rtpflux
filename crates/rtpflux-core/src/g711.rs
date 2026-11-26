//! G.711 (ITU-T G.711, RFC 3551 §4.5.14): μ-law (PCMU, payload type 0)
//! and A-law (PCMA, 8), and transcoding between them through the 16-bit
//! linear sample. The conversion tables are computed at compile time from
//! the reference algorithms (the Sun `g711.c` formulation); transcoding a
//! payload is one table lookup per octet, in place.

/// Static payload types (RFC 3551 Table 4).
pub const PT_PCMU: crate::rtp::Pt = crate::rtp::Pt::PCMU;
pub const PT_PCMA: crate::rtp::Pt = crate::rtp::Pt::PCMA;

/// A-law segment ends (13-bit magnitude after the shift).
const SEG_A_END: [i32; 8] = [0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF];
/// μ-law segment ends (14-bit magnitude, biased).
const SEG_U_END: [i32; 8] = [0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF, 0x1FFF];
const ULAW_BIAS: i32 = 0x84;
const ULAW_CLIP: i32 = 8159;

/// The segment of `v`: the first end at or above it (8: none).
const fn search(v: i32, ends: &[i32; 8]) -> usize {
    let mut rest: &[i32] = ends;
    let mut i = 0usize;
    while let [end, tail @ ..] = rest {
        if v <= *end {
            return i;
        }
        // At most 8.
        i = i.wrapping_add(1);
        rest = tail;
    }
    8
}

/// A-law code of a 16-bit linear sample.
#[must_use]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub const fn linear_to_alaw(pcm: i16) -> u8 {
    let p = (pcm as i32) >> 3;
    let (mask, p) = if p >= 0 {
        (0xD5u8, p)
    } else {
        // −p − 1: `p` >= −4096 (a 16-bit sample shifted by 3).
        (0x55u8, !p)
    };
    let seg = search(p, &SEG_A_END);
    if seg >= 8 {
        return 0x7F ^ mask;
    }
    let q = if seg < 2 { p >> 1 } else { p >> seg };
    ((seg as u8) << 4 | (q & 0xF) as u8) ^ mask
}

/// The linear sample of an A-law code.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub const fn alaw_to_linear(a: u8) -> i16 {
    let a = a ^ 0x55;
    let mut t = ((a & 0x0F) as i32) << 4;
    let seg = ((a & 0x70) >> 4) as i32;
    // Below 2^13 << 6: no overflow.
    t = match seg {
        0 => t.wrapping_add(8),
        1 => t.wrapping_add(0x108),
        _ => t
            .wrapping_add(0x108)
            .wrapping_shl(seg.wrapping_sub(1).cast_unsigned()),
    };
    (if a & 0x80 != 0 { t } else { t.wrapping_neg() }) as i16
}

/// μ-law code of a 16-bit linear sample.
#[must_use]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub const fn linear_to_ulaw(pcm: i16) -> u8 {
    let p = (pcm as i32) >> 2;
    // `p` >= −8192 (a 16-bit sample shifted by 2): negating it fits.
    let (mask, p) = if p < 0 {
        (0x7Fu8, p.wrapping_neg())
    } else {
        (0xFFu8, p)
    };
    let p = (if p > ULAW_CLIP { ULAW_CLIP } else { p }).wrapping_add(ULAW_BIAS >> 2);
    let seg = search(p, &SEG_U_END);
    if seg >= 8 {
        return 0x7F ^ mask;
    }
    ((seg as u8) << 4 | (p.wrapping_shr(seg.wrapping_add(1) as u32) & 0xF) as u8) ^ mask
}

/// The linear sample of a μ-law code.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub const fn ulaw_to_linear(u: u8) -> i16 {
    let u = !u;
    // At most (0x7F + 0x84) << 7: no overflow.
    let t =
        ((((u & 0x0F) as i32) << 3).wrapping_add(ULAW_BIAS)).wrapping_shl(((u & 0x70) >> 4) as u32);
    (if u & 0x80 != 0 {
        ULAW_BIAS.wrapping_sub(t)
    } else {
        t.wrapping_sub(ULAW_BIAS)
    }) as i16
}

// Evaluated at compile time (for the statics below): an out-of-range index
// or an overflow would be a build error, never a panic at run time.
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const fn table(ulaw_to_alaw: bool) -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut c = 0;
    while c < 256 {
        #[allow(clippy::cast_possible_truncation)]
        let code = c as u8;
        t[c] = if ulaw_to_alaw {
            linear_to_alaw(ulaw_to_linear(code))
        } else {
            linear_to_ulaw(alaw_to_linear(code))
        };
        c += 1;
    }
    t
}

/// μ-law code → A-law code.
pub static ULAW_TO_ALAW: [u8; 256] = table(true);
/// A-law code → μ-law code.
pub static ALAW_TO_ULAW: [u8; 256] = table(false);

/// The table converting payload type `from` to `to`, if both are G.711
/// and differ.
#[must_use]
pub fn converter(from: crate::rtp::Pt, to: crate::rtp::Pt) -> Option<&'static [u8; 256]> {
    match (from, to) {
        (PT_PCMU, PT_PCMA) => Some(&ULAW_TO_ALAW),
        (PT_PCMA, PT_PCMU) => Some(&ALAW_TO_ULAW),
        _ => None,
    }
}

/// Convert `payload` in place.
pub fn transcode(table: &[u8; 256], payload: &mut [u8]) {
    for b in payload {
        // A `u8` indexes all 256 entries.
        *b = table.get(usize::from(*b)).copied().unwrap_or(*b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every 16-bit sample and every code, through every function, with
    /// overflow checks (tests build with them): nothing overflows or
    /// panics, whatever the input.
    #[test]
    fn every_input_converts() {
        for pcm in i16::MIN..=i16::MAX {
            let (a, u) = (linear_to_alaw(pcm), linear_to_ulaw(pcm));
            let _ = (alaw_to_linear(a), ulaw_to_linear(u));
        }
        for code in 0..=u8::MAX {
            let _ = (alaw_to_linear(code), ulaw_to_linear(code));
            let mut payload = [code];
            transcode(&ULAW_TO_ALAW, &mut payload);
            transcode(&ALAW_TO_ULAW, &mut payload);
        }
    }

    #[test]
    fn round_trips_and_zero() {
        for c in 0..=255u8 {
            assert_eq!(linear_to_alaw(alaw_to_linear(c)), c);
            if c != 0x7F {
                assert_eq!(linear_to_ulaw(ulaw_to_linear(c)), c);
            }
        }
        assert_eq!(
            (
                ulaw_to_linear(0x7F),
                ulaw_to_linear(0xFF),
                linear_to_ulaw(0)
            ),
            (0, 0, 0xFF)
        );
        // Silence: μ-law 0xFF is A-law 0xD5.
        assert_eq!(ULAW_TO_ALAW[0xFF], 0xD5);
        assert_eq!(converter(PT_PCMU, PT_PCMA).map(|t| t[0xFF]), Some(0xD5));
        assert!(converter(PT_PCMU, PT_PCMU).is_none());
    }

    #[test]
    fn the_tables_match_their_definition_and_extremes_saturate() {
        // The tables are built at compile time; build them again here.
        assert_eq!(table(true), ULAW_TO_ALAW);
        assert_eq!(table(false), ALAW_TO_ULAW);
        assert_eq!(linear_to_alaw(i16::MAX), 0xAA);
        assert_eq!(linear_to_alaw(i16::MIN), 0x2A);
        assert_eq!(converter(PT_PCMU, PT_PCMU), None);
    }
}
