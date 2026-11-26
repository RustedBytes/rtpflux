//! In-band DTMF: the dual tones of ITU-T Q.23 found in 8 kHz audio (as
//! G.711 carries), for converting them to telephone events (RFC 4733).
//!
//! Each frame (20 ms, 160 samples) goes through eight Goertzel filters, one
//! per row and column frequency. A frame holds a key when the strongest row
//! and column tones carry most of its energy (at least 70 %), neither is
//! far weaker than the other (twist within 4:1 in power), each stands well
//! above the other tones of its group (8:1), and the audio is not near
//! silence. A key starts after two frames in a row hold it, and ends after
//! two frames in a row do not (40 ms each way, against speech and dropouts).
//!
//! Arithmetic only (no trigonometry at run time); no allocation.

/// Row frequencies (Hz) and column frequencies.
pub const ROWS: [u32; 4] = [697, 770, 852, 941];
pub const COLS: [u32; 4] = [1209, 1336, 1477, 1633];

/// 2·cos(2πf/8000) for each row and column frequency.
const COEF: [f32; 8] = [
    1.707_737_8,
    1.645_281,
    1.568_687,
    1.478_204_6,
    1.164_104,
    0.996_370_2,
    0.798_618_4,
    0.568_532_7,
];

/// Samples per frame (20 ms at 8 kHz).
pub const FRAME: usize = 160;

/// The event code (RFC 4733 §3.2) of a row and column.
const KEYS: [[u8; 4]; 4] = [[1, 2, 3, 12], [4, 5, 6, 13], [7, 8, 9, 14], [10, 0, 11, 15]];

/// What a frame changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// A key was pressed (its event code).
    Start(u8),
    /// The key was released.
    End,
}

/// Goertzel power of `x` at the frequency of coefficient `k`.
fn power(x: &[i16], k: f32) -> f32 {
    let (mut s1, mut s2) = (0f32, 0f32);
    for &v in x {
        let s = f32::from(v) + k * s1 - s2;
        s2 = s1;
        s1 = s;
    }
    s1 * s1 + s2 * s2 - k * s1 * s2
}

/// The key one frame holds, if any.
#[must_use]
pub fn key_of(x: &[i16]) -> Option<u8> {
    if x.is_empty() {
        return None;
    }
    let energy: f32 = x.iter().map(|&v| f32::from(v) * f32::from(v)).sum();
    #[allow(clippy::cast_precision_loss)]
    let len = x.len() as f32;
    // Near silence (an RMS below 100) holds no key.
    if energy < len * 100.0 * 100.0 {
        return None;
    }
    let mut powers = [0f32; 8];
    for (o, &k) in powers.iter_mut().zip(COEF.iter()) {
        *o = power(x, k);
    }
    let best = |g: &[f32]| {
        // The first of the strongest.
        let first = g.first().copied().unwrap_or(0.0);
        let (i, top) =
            g.iter()
                .copied()
                .enumerate()
                .skip(1)
                .fold(
                    (0, first),
                    |(bi, bv), (j, v)| if v > bv { (j, v) } else { (bi, bv) },
                );
        let second = g
            .iter()
            .enumerate()
            .filter(|&(j, _)| j != i)
            .map(|(_, &v)| v)
            .fold(0f32, f32::max);
        (i, top, second)
    };
    let (row, pr, r2) = best(&powers[..4]);
    let (col, pc, c2) = best(&powers[4..]);
    // A pure tone of amplitude A gives a power near (A·n/2)², its energy is
    // n·A²/2: power / (energy·n/2) is the share of the energy at that
    // frequency.
    let scale = energy * len / 2.0;
    let share = (pr + pc) / scale;
    let twist = pr.min(pc) * 4.0 >= pr.max(pc);
    let clear = pr >= 8.0 * r2 && pc >= 8.0 * c2;
    let key = KEYS.get(row).and_then(|r| r.get(col)).copied();
    key.filter(|_| share >= 0.7 && twist && clear)
}

/// Key presses in a stream of frames.
#[derive(Debug, Clone, Copy, Default)]
pub struct Detector {
    /// The key being held (reported).
    held: Option<u8>,
    /// The key the last frame held, and how many frames in a row.
    last: Option<u8>,
    run: u8,
}

impl Detector {
    #[must_use]
    pub const fn new() -> Self {
        Detector {
            held: None,
            last: None,
            run: 0,
        }
    }

    /// The key being held, if any.
    #[must_use]
    pub const fn held(&self) -> Option<u8> {
        self.held
    }

    /// Feed one frame.
    pub fn frame(&mut self, x: &[i16]) -> Option<Change> {
        self.step(key_of(x))
    }

    /// Feed one frame's classification: the key it holds, or none.
    pub fn step(&mut self, k: Option<u8>) -> Option<Change> {
        if k == self.last {
            self.run = self.run.saturating_add(1);
        } else {
            self.last = k;
            self.run = 1;
        }
        if self.run < 2 {
            return None;
        }
        match (self.held, k) {
            (None, Some(code)) => {
                self.held = Some(code);
                Some(Change::Start(code))
            }
            (Some(_), None) => {
                self.held = None;
                Some(Change::End)
            }
            (Some(h), Some(code)) if h != code => {
                // Another key straight after: end this one (the next frame
                // pair starts the new one).
                self.held = None;
                self.last = None;
                self.run = 0;
                Some(Change::End)
            }
            _ => None,
        }
    }
}
