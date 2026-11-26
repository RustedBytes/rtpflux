//! Two small state machines of a call's life: its recording
//! ([`Rec`]: `start recording`, `pause recording`, `stop recording`) and
//! deletes put off by `delete-delay` ([`Delays`]).

/// A relay call's recording: the file being written (numbered from 0 per
/// call) and whether it is paused, and how many files were opened.
///
/// A file is opened only when none is: starting a recording already going
/// on resumes it (if paused) in the same file, and a recording started
/// again after a stop gets a new file, so a finished one (its audio already
/// made) is never written again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rec {
    current: Option<(u32, bool)>,
    opened: u32,
}

/// What an operation did to the recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecStep {
    /// A new file was opened.
    Open(u32),
    /// The file goes on (was paused, or already running).
    Resume(u32),
    Pause(u32),
    /// The file was finished.
    Close(u32),
    /// Nothing to do.
    Nothing,
}

impl Rec {
    /// The state as saved: the file being written and whether paused, and
    /// how many files were opened.
    #[must_use]
    pub fn of(current: Option<(u32, bool)>, opened: u32) -> Self {
        Rec { current, opened }
    }

    #[must_use]
    pub fn current(&self) -> Option<(u32, bool)> {
        self.current
    }

    #[must_use]
    pub fn opened(&self) -> u32 {
        self.opened
    }

    pub fn start(&mut self) -> RecStep {
        if let Some((f, _)) = self.current {
            self.current = Some((f, false));
            RecStep::Resume(f)
        } else {
            let f = self.opened;
            self.current = Some((f, false));
            self.opened += 1;
            RecStep::Open(f)
        }
    }

    pub fn pause(&mut self) -> RecStep {
        match self.current {
            Some((f, _)) => {
                self.current = Some((f, true));
                RecStep::Pause(f)
            }
            None => RecStep::Nothing,
        }
    }

    pub fn stop(&mut self) -> RecStep {
        match self.current.take() {
            Some((f, _)) => RecStep::Close(f),
            None => RecStep::Nothing,
        }
    }

    /// The file a packet arriving now is written to, if any.
    #[must_use]
    pub fn writes(&self) -> Option<u32> {
        match self.current {
            Some((f, false)) => Some(f),
            _ => None,
        }
    }
}

/// Deletes put off until a time: each runs at the first tick at or after
/// it, in the order they were asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delays<T, K> {
    pending: Vec<(T, K)>,
}

impl<T, K> Default for Delays<T, K> {
    fn default() -> Self {
        Delays {
            pending: Vec::new(),
        }
    }
}

impl<T: Ord + Copy, K> Delays<T, K> {
    pub fn schedule(&mut self, at: T, key: K) {
        self.pending.push((at, key));
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Deletes waiting.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// The deletes waiting: when each is due, and what it deletes.
    pub fn pending(&self) -> impl Iterator<Item = &(T, K)> {
        self.pending.iter()
    }

    /// The deletes due at `now`, taken off the list.
    pub fn due(&mut self, now: T) -> Vec<K> {
        if self.pending.iter().all(|(t, _)| *t > now) {
            return Vec::new();
        }
        let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending)
            .into_iter()
            .partition(|(t, _)| *t <= now);
        self.pending = later;
        due.into_iter().map(|(_, k)| k).collect()
    }
}
