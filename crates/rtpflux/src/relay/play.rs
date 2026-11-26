//! What an announcement (`play media`) plays, frame by frame.
//!
//! [`plan`] turns the request into the part of the media played and how
//! often: from `start-pos`, `duration` long, `repeat-times` over, or
//! repeated for `repeat-duration` and cut there. [`Cursor`] then gives
//! each 20 ms frame (160 codes at 8 kHz): where in the media it starts and
//! how many of its codes are media (the last frame of a repetition is
//! padded with silence). Resuming after a restart skips whole frames,
//! counting the padded ones.

/// Codes in a frame (20 ms at 8 kHz).
pub const FRAME: usize = 160;

/// The part of the media played and how often.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    /// Where the played part starts in the media, and its length (codes).
    pub start: usize,
    pub len: usize,
    pub repeat: u32,
    /// Codes to play in all, if cut (`repeat-duration`).
    pub limit: Option<usize>,
}

/// The plan for media of `media_len` codes: from `start_ms`, `length_ms`
/// long (to the end without; 0 is none), repeated `repeat_times` (at least
/// once) or for `repeat_ms` (0 is none). `None` when `start_ms` is past the
/// end.
#[must_use]
pub fn plan(
    media_len: usize,
    start_ms: u64,
    length_ms: Option<u64>,
    repeat_times: u32,
    repeat_ms: Option<u64>,
) -> Option<Plan> {
    let codes = |ms: u64| usize::try_from(ms.saturating_mul(8)).unwrap_or(usize::MAX);
    let start = codes(start_ms);
    if start >= media_len {
        return None;
    }
    let len = match length_ms.filter(|&l| l > 0) {
        Some(l) => (media_len - start).min(codes(l)),
        None => media_len - start,
    };
    Some(match repeat_ms.filter(|&r| r > 0) {
        Some(r) => Plan {
            start,
            len,
            repeat: u32::try_from(codes(r).div_ceil(len)).unwrap_or(u32::MAX),
            limit: Some(codes(r)),
        },
        None => Plan {
            start,
            len,
            repeat: repeat_times.max(1),
            limit: None,
        },
    })
}

/// Where a playback is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    len: usize,
    repeat: u32,
    pos: usize,
    left: Option<usize>,
}

impl Cursor {
    /// Start playing `len` codes `repeat` times, cut after `limit` codes,
    /// with `skip` codes (whole frames, padding counted) already played.
    /// `None` when nothing is left.
    #[must_use]
    pub fn start(len: usize, repeat: u32, limit: Option<usize>, skip: usize) -> Option<Self> {
        if len == 0 {
            return None;
        }
        let per_round = len.div_ceil(FRAME);
        let frames = skip / FRAME;
        let rounds = u32::try_from(frames / per_round).unwrap_or(u32::MAX);
        if rounds >= repeat {
            return None;
        }
        Some(Cursor {
            len,
            repeat: repeat - rounds,
            pos: (frames % per_round) * FRAME,
            left: limit.map(|l| l.saturating_sub(frames * FRAME)),
        })
    }

    /// The next frame: where it starts in the played part and how many of
    /// its codes are media (the rest is silence); `None` once over.
    pub fn next_frame(&mut self) -> Option<(usize, usize)> {
        let cut = self.left == Some(0);
        if cut || self.pos >= self.len {
            if !cut && self.repeat > 1 {
                self.repeat -= 1;
                self.pos = 0;
            } else {
                return None;
            }
        }
        let at = self.pos;
        self.pos += FRAME;
        self.left = self.left.map(|l| l.saturating_sub(FRAME));
        Some((at, FRAME.min(self.len - at)))
    }
}
