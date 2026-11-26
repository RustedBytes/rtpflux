//! DTMF security (rtpengine's `DTMF-security`): what becomes of the keys a
//! party presses, so that digits such as a card number do not reach the
//! other party (an agent, a recording). The pure part: the blocking mode,
//! the triggers that switch it, and the digits that replace keys. The
//! worker applies it to telephone events and in-band tones
//! (`worker::dtmf_security`).
//!
//! Modes:
//! - `off`: keys pass;
//! - `drop`: telephone events are dropped (in-band tones pass);
//! - `silence`, `tone`: each key, event or in-band tone, is replaced by
//!   silence or a sine tone in the listener's audio;
//! - `random`, `zero`, `DTMF` (a digit of the proxy's choice): each key is
//!   replaced by another key (a random one, never the key itself; `0`; the
//!   digit): an event's code is rewritten, an in-band tone replaced by the
//!   other key's tones.
//!
//! Triggers: a key sequence (`trigger`) switches to a mode (default `drop`);
//! then `trigger-end` (another sequence), `trigger-end-time` (ms) or
//! `trigger-end-digits` (keys) switch to the end mode (default `off`), and
//! the trigger is watched for again. Sequences are matched on the latest
//! keys, a gap of [`KEY_GAP_MS`] starting afresh.

use serde::{Deserialize, Serialize};

/// What a key becomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Mode {
    #[default]
    Off,
    Drop,
    Silence,
    Tone,
    Random,
    /// Another key: `zero` is `Digit(0)`.
    Digit(u8),
}

impl Mode {
    /// The mode named `name` (`DTMF` takes `digit`, an event code).
    #[must_use]
    pub fn parse(name: &[u8], digit: Option<u8>) -> Option<Self> {
        Some(match name {
            b"off" => Mode::Off,
            b"drop" => Mode::Drop,
            b"silence" => Mode::Silence,
            b"tone" => Mode::Tone,
            b"random" => Mode::Random,
            b"zero" => Mode::Digit(0),
            b"DTMF" | b"dtmf" => Mode::Digit(digit?),
            _ => return None,
        })
    }
}

/// The event code of a key (`0-9 * # A-D`).
#[must_use]
pub fn code_of(key: u8) -> Option<u8> {
    Some(match key {
        b'0'..=b'9' => key - b'0',
        b'*' => 10,
        b'#' => 11,
        b'A'..=b'D' => key - b'A' + 12,
        b'a'..=b'd' => key - b'a' + 12,
        _ => return None,
    })
}

/// Longest trigger sequence.
pub const MAX_KEYS: usize = 16;

/// Keys apart by more than this start a sequence afresh (rtpengine's
/// default `dtmf-digit-delay`).
pub const KEY_GAP_MS: u64 = 2_500;

/// A key sequence (event codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Keys {
    codes: [u8; MAX_KEYS],
    len: u8,
}

impl Keys {
    /// The keys of `text` (`0-9 * # A-D`); `None` if empty, too long or
    /// not keys.
    #[must_use]
    pub fn parse(text: &[u8]) -> Option<Self> {
        if text.is_empty() || text.len() > MAX_KEYS {
            return None;
        }
        let mut k = Keys::default();
        for &c in text {
            k.codes[usize::from(k.len)] = code_of(c)?;
            k.len += 1;
        }
        Some(k)
    }

    fn as_slice(&self) -> &[u8] {
        &self.codes[..usize::from(self.len)]
    }

    /// Add `code` as the latest key, the oldest going when full.
    fn push(&mut self, code: u8) {
        if usize::from(self.len) == MAX_KEYS {
            self.codes.copy_within(1.., 0);
            self.len -= 1;
        }
        self.codes[usize::from(self.len)] = code;
        self.len += 1;
    }

    /// Whether the latest keys are `seq`.
    fn ends_with(&self, seq: &Keys) -> bool {
        self.as_slice().ends_with(seq.as_slice())
    }
}

/// What the proxy asked for one party's keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Plan {
    /// The mode until a trigger (`DTMF-security`).
    pub mode: Mode,
    /// `trigger` and the mode it switches to (`DTMF-security-trigger`).
    pub trigger: Option<Keys>,
    pub trigger_mode: Mode,
    /// `trigger-end` and the mode it switches to
    /// (`DTMF-security-trigger-end`); after `end_ms` (`trigger-end-time`)
    /// or `end_keys` keys (`trigger-end-digits`) too.
    pub end: Option<Keys>,
    pub end_mode: Mode,
    pub end_ms: Option<u64>,
    pub end_keys: Option<u32>,
    /// `DTMF-delay`: keys reach the listener this much later (ms).
    pub delay_ms: u32,
    /// `tone`'s frequency (Hz) and the level of what replaces keys (below
    /// 0 dBm0).
    pub tone_hz: u16,
    pub volume: u8,
}

/// The sine of `tone` when the proxy names none.
pub const TONE_HZ: u16 = 400;

/// What becomes of one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Pass,
    Drop,
    Silence,
    Tone,
    /// Another key (event code).
    Replace(u8),
}

/// A party's keys over time: the mode in force and the triggers' progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    plan: Plan,
    mode: Mode,
    recent: Keys,
    last_ms: Option<u64>,
    /// Since when (ms) a trigger's mode has been on, and the keys since.
    triggered: Option<(u64, u32)>,
    rng: u64,
}

impl State {
    /// `seed`: anything that differs between parties (no key depends on
    /// it: a replacing key tells nothing of the key replaced).
    #[must_use]
    pub fn new(plan: Plan, seed: u64) -> Self {
        State {
            plan,
            mode: plan.mode,
            recent: Keys::default(),
            last_ms: None,
            triggered: None,
            rng: seed | 1,
        }
    }

    #[must_use]
    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    #[must_use]
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// A key `code` starts at `now` (ms): what becomes of it, in the mode
    /// in force when it was pressed; then the triggers move on.
    pub fn key(&mut self, code: u8, now: u64) -> Action {
        self.tick(now);
        let action = self.action(code);
        if self
            .last_ms
            .is_some_and(|t| now.saturating_sub(t) > KEY_GAP_MS)
        {
            self.recent = Keys::default();
        }
        self.last_ms = Some(now);
        self.recent.push(code);
        match self.triggered {
            None => {
                if self.plan.trigger.is_some_and(|t| self.recent.ends_with(&t)) {
                    self.mode = self.plan.trigger_mode;
                    self.triggered = Some((now, 0));
                    self.recent = Keys::default();
                }
            }
            Some((since, keys)) => {
                let keys = keys + 1;
                self.triggered = Some((since, keys));
                if self.plan.end.is_some_and(|e| self.recent.ends_with(&e))
                    || self.plan.end_keys.is_some_and(|n| keys >= n)
                {
                    self.end();
                }
            }
        }
        action
    }

    /// Time passes: a trigger's mode whose time is up ends.
    pub fn tick(&mut self, now: u64) {
        if let (Some((since, _)), Some(ms)) = (self.triggered, self.plan.end_ms)
            && now.saturating_sub(since) >= ms
        {
            self.end();
        }
    }

    /// When [`State::tick`] has something to do next.
    #[must_use]
    pub fn next_ms(&self) -> Option<u64> {
        Some(self.triggered?.0 + self.plan.end_ms?)
    }

    fn end(&mut self) {
        self.mode = self.plan.end_mode;
        self.triggered = None;
        self.recent = Keys::default();
    }

    fn action(&mut self, code: u8) -> Action {
        match self.mode {
            Mode::Off => Action::Pass,
            Mode::Drop => Action::Drop,
            Mode::Silence => Action::Silence,
            Mode::Tone => Action::Tone,
            Mode::Digit(d) => Action::Replace(d),
            Mode::Random => Action::Replace(self.random_key(code)),
        }
    }

    /// A key other than `code`, from a xorshift generator.
    fn random_key(&mut self, code: u8) -> u8 {
        loop {
            self.rng ^= self.rng << 13;
            self.rng ^= self.rng >> 7;
            self.rng ^= self.rng << 17;
            #[allow(clippy::cast_possible_truncation)] // Below 16.
            let k = (self.rng % 16) as u8;
            if k != code {
                return k;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(s: &str) -> Keys {
        Keys::parse(s.as_bytes()).unwrap()
    }

    #[test]
    fn modes_and_keys_parse() {
        assert_eq!(Mode::parse(b"zero", None), Some(Mode::Digit(0)));
        assert_eq!(Mode::parse(b"DTMF", Some(5)), Some(Mode::Digit(5)));
        assert_eq!(Mode::parse(b"DTMF", None), None, "needs its digit");
        assert_eq!(Mode::parse(b"frob", None), None);
        assert_eq!(code_of(b'#'), Some(11));
        assert_eq!(code_of(b'D'), Some(15));
        assert_eq!(code_of(b'x'), None);
        assert!(Keys::parse(b"").is_none());
        assert!(Keys::parse(&[b'1'; MAX_KEYS + 1]).is_none());
        assert!(Keys::parse(b"12x").is_none());
    }

    #[test]
    fn each_mode_does_its_thing() {
        for (mode, action) in [
            (Mode::Off, Action::Pass),
            (Mode::Drop, Action::Drop),
            (Mode::Silence, Action::Silence),
            (Mode::Tone, Action::Tone),
            (Mode::Digit(0), Action::Replace(0)),
        ] {
            let mut s = State::new(
                Plan {
                    mode,
                    ..Plan::default()
                },
                1,
            );
            assert_eq!(s.key(7, 0), action, "{mode:?}");
        }
        let mut s = State::new(
            Plan {
                mode: Mode::Random,
                ..Plan::default()
            },
            42,
        );
        let mut seen = [false; 16];
        for i in 0..500 {
            let code = (i % 16) as u8;
            let Action::Replace(k) = s.key(code, i * 100) else {
                panic!()
            };
            assert!(k < 16 && k != code, "never the key itself");
            seen[usize::from(k)] = true;
        }
        assert!(seen.iter().all(|&s| s), "every key comes up");
    }

    #[test]
    fn a_trigger_switches_and_its_end_switches_back() {
        let plan = Plan {
            trigger: Some(keys("*1")),
            trigger_mode: Mode::Digit(0),
            end: Some(keys("#")),
            ..Plan::default()
        };
        let mut s = State::new(plan, 1);
        // The trigger's own keys pass.
        assert_eq!(s.key(10, 0), Action::Pass);
        assert_eq!(s.key(1, 100), Action::Pass);
        assert_eq!(s.mode(), Mode::Digit(0));
        assert_eq!(s.key(4, 200), Action::Replace(0));
        assert_eq!(s.key(2, 300), Action::Replace(0));
        // The end key is the last one replaced.
        assert_eq!(s.key(11, 400), Action::Replace(0));
        assert_eq!(s.mode(), Mode::Off);
        assert_eq!(s.key(4, 500), Action::Pass);
        // And the trigger is watched for again.
        s.key(10, 600);
        s.key(1, 700);
        assert_eq!(s.key(9, 800), Action::Replace(0));
    }

    #[test]
    fn a_trigger_ends_after_its_time_or_keys() {
        let plan = Plan {
            trigger: Some(keys("1")),
            trigger_mode: Mode::Drop,
            end_ms: Some(1_000),
            ..Plan::default()
        };
        let mut s = State::new(plan, 1);
        s.key(1, 0);
        assert_eq!(s.next_ms(), Some(1_000));
        assert_eq!(s.key(5, 900), Action::Drop);
        s.tick(1_000);
        assert_eq!(s.mode(), Mode::Off);
        assert_eq!(s.next_ms(), None);
        let plan = Plan {
            trigger: Some(keys("1")),
            trigger_mode: Mode::Drop,
            end_keys: Some(3),
            ..Plan::default()
        };
        let mut s = State::new(plan, 1);
        s.key(1, 0);
        for t in 1..=3 {
            assert_eq!(s.key(5, t * 100), Action::Drop);
        }
        assert_eq!(s.key(5, 400), Action::Pass, "three keys, then off");
    }

    #[test]
    fn a_slow_sequence_does_not_trigger() {
        let plan = Plan {
            trigger: Some(keys("12")),
            trigger_mode: Mode::Drop,
            ..Plan::default()
        };
        let mut s = State::new(plan, 1);
        s.key(1, 0);
        s.key(2, KEY_GAP_MS + 1);
        assert_eq!(s.mode(), Mode::Off);
        // Interrupted sequences match on the latest keys.
        s.key(1, 10_000);
        s.key(1, 10_100);
        s.key(2, 10_200);
        assert_eq!(s.mode(), Mode::Drop);
    }
}

/// One party's DTMF security as its relay leg applies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtmfSecurity {
    pub plan: Plan,
    /// The party's audio (payload type, codec): its in-band keys are
    /// found in it.
    pub own_audio: Option<(rtpflux_core::rtp::Pt, super::Codec)>,
    /// The listener's audio: what replaces keys (silence, a tone, other
    /// keys) is made in it.
    pub listener_audio: Option<(rtpflux_core::rtp::Pt, super::Codec)>,
    /// The listener's telephone events (payload type, clock rate): delayed
    /// keys reach it as events when it takes them.
    pub listener_events: Option<(rtpflux_core::rtp::Pt, u32)>,
}
