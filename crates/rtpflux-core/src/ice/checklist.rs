//! Candidate pairs and their checklist (RFC 8445 §5.1.2, §6.1.2, §6.1.4,
//! §14.3), with candidates trickled in after checks started (RFC 8838 §8,
//! §11, §12).
//!
//! Pure functions over the pairs; insertion works on a fixed-capacity
//! [`List`].

use super::list::List;
use crate::stun::Role;

/// The state of a pair (RFC 8445 §6.1.2.6, Figure 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairState {
    Frozen,
    Waiting,
    InProgress,
    Succeeded,
    Failed,
}

impl PairState {
    /// Waiting or Frozen: the pairs checked for redundancy and evictable for
    /// priority (RFC 8838 §11).
    #[must_use]
    pub const fn pending(self) -> bool {
        matches!(self, PairState::Waiting | PairState::Frozen)
    }
}

/// A candidate pair. The local candidate is named by its base, the remote
/// one by an index; `list` is the checklist (one per data stream).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pair {
    pub id: u16,
    pub list: u8,
    pub base: u16,
    pub remote: u16,
    pub foundation: u32,
    pub component: u8,
    pub priority: u64,
    pub state: PairState,
    pub nominated: bool,
    /// When a check on the pair last succeeded (ms).
    pub ok_ms: u64,
    /// Controlled agent: the peer nominated the pair before its check
    /// succeeded (RFC 8445 §7.3.1.5).
    pub nominate_on_success: bool,
    /// Controlling agent: the next check on the pair carries USE-CANDIDATE.
    pub nominating: bool,
}

impl Pair {
    /// Unused storage.
    pub const EMPTY: Pair = Pair::new(0, 0, 0, 0, 0, 0, 0);

    #[must_use]
    pub const fn new(
        id: u16,
        list: u8,
        base: u16,
        remote: u16,
        foundation: u32,
        component: u8,
        priority: u64,
    ) -> Self {
        Pair {
            id,
            list,
            base,
            remote,
            foundation,
            component,
            priority,
            state: PairState::Frozen,
            nominated: false,
            ok_ms: 0,
            nominate_on_success: false,
            nominating: false,
        }
    }

    const fn key(&self) -> (u8, u16, u16) {
        (self.list, self.base, self.remote)
    }
}

/// The type preference recommended for each candidate type (RFC 8445
/// §5.1.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandType {
    Host,
    Srflx,
    Prflx,
    Relay,
}

impl CandType {
    #[must_use]
    pub const fn type_pref(self) -> u32 {
        match self {
            CandType::Host => 126,
            CandType::Prflx => 110,
            CandType::Srflx => 100,
            CandType::Relay => 0,
        }
    }
}

/// A candidate's priority (RFC 8445 §5.1.2.1): `type_pref` 0–126,
/// `local_pref` 0–65535, `component` 1–256.
#[must_use]
pub const fn candidate_priority(type_pref: u32, local_pref: u32, component: u32) -> u32 {
    // Within the documented ranges no step overflows; outside them the
    // result saturates.
    (type_pref << 24)
        .saturating_add(local_pref << 8)
        .saturating_add(256u32.saturating_sub(component))
}

/// A pair's priority (RFC 8445 §6.1.2.3) for an agent in `role` whose
/// candidate has priority `local` and the peer's `remote`.
#[must_use]
pub fn pair_priority(role: Role, local: u32, remote: u32) -> u64 {
    let (g, d) = match role {
        Role::Controlling => (u64::from(local), u64::from(remote)),
        Role::Controlled => (u64::from(remote), u64::from(local)),
    };
    // 2^32·MIN + 2·MAX + (G > D ? 1 : 0). Priorities below 2^31 (RFC 8445
    // §5.1.2.1) never overflow; a peer's PRIORITY attribute can carry more,
    // and then the result saturates (still ordered) instead of wrapping.
    (g.min(d) << 32)
        .saturating_add(g.max(d).saturating_mul(2))
        .saturating_add(u64::from(g > d))
}

/// Initial states (RFC 8445 §6.1.2.6): in the checklist-set order of
/// `pairs`, the first pair of each foundation Waiting, the others Frozen.
pub fn initial_states(pairs: &mut [Pair]) {
    for k in 0..pairs.len() {
        let Some((before, rest)) = pairs.split_at_mut_checked(k) else {
            break;
        };
        let Some(p) = rest.first_mut() else {
            break;
        };
        let seen = before.iter().any(|q| q.foundation == p.foundation);
        p.state = if seen {
            PairState::Frozen
        } else {
            PairState::Waiting
        };
    }
}

/// The pair to check when Ta fires (RFC 8445 §6.1.4.2): the head of the
/// triggered-check queue, otherwise the Waiting pair with the highest
/// priority (then the lowest component; the first of equals).
#[must_use]
pub fn next_check(queue: &[u16], pairs: &[Pair]) -> Option<u16> {
    if let Some(&id) = queue.first() {
        return Some(id);
    }
    let mut best: Option<&Pair> = None;
    for p in pairs.iter().filter(|p| p.state == PairState::Waiting) {
        if best.is_none_or(|b| {
            p.priority > b.priority || (p.priority == b.priority && p.component < b.component)
        }) {
            best = Some(p);
        }
    }
    best.map(|p| p.id)
}

/// Step 2 of RFC 8445 §6.1.4.2 when no pair is Waiting: for each
/// foundation with no Waiting or In-Progress pair, the Frozen pair with the
/// lowest component, then the highest priority, becomes Waiting.
pub fn unfreeze_idle(pairs: &mut [Pair]) {
    for k in 0..pairs.len() {
        let Some(&p) = pairs.get(k) else {
            break;
        };
        if p.state != PairState::Frozen {
            continue;
        }
        let busy = pairs.iter().any(|q| {
            q.foundation == p.foundation
                && matches!(q.state, PairState::Waiting | PairState::InProgress)
        });
        let first = pairs.iter().all(|q| {
            q.foundation != p.foundation
                || q.state != PairState::Frozen
                || q.component > p.component
                || (q.component == p.component && q.priority <= p.priority)
        });
        if !busy
            && first
            && let Some(p) = pairs.get_mut(k)
        {
            p.state = PairState::Waiting;
        }
    }
}

/// A success unfreezes the pairs of its foundation (RFC 8445 §7.2.5.3.3).
pub fn unfreeze_foundation(pairs: &mut [Pair], foundation: u32) {
    for p in pairs.iter_mut() {
        if p.foundation == foundation && p.state == PairState::Frozen {
            p.state = PairState::Waiting;
        }
    }
}

/// The retransmission timeout of a check (RFC 8445 §14.3): at least 500 ms.
#[must_use]
pub fn check_rto(ta: u64, n: u64, waiting: u64, in_progress: u64) -> u64 {
    500u64.max(
        ta.saturating_mul(n)
            .saturating_mul(waiting.saturating_add(in_progress)),
    )
}

/// The state of a pair formed after checks started (RFC 8838 §12): Waiting
/// when it is the topmost pair of its foundation (lowest component, then
/// highest priority) or a pair of its foundation succeeded, else Frozen.
#[must_use]
pub fn new_state(pairs: &[Pair], p: &Pair) -> PairState {
    let topmost = pairs.iter().all(|q| {
        q.foundation != p.foundation
            || p.component < q.component
            || (p.component == q.component && q.priority <= p.priority)
    });
    let succeeded = pairs
        .iter()
        .any(|q| q.foundation == p.foundation && q.state == PairState::Succeeded);
    if topmost || succeeded {
        PairState::Waiting
    } else {
        PairState::Frozen
    }
}

/// Insert pair `p` into a checklist of at most `limit` pairs (RFC 8838 §11
/// steps 4–5, §12): dropped when a redundant pair (same checklist, base and
/// remote) exists that is not a lower-priority Waiting/Frozen pair; such
/// lower pairs are replaced. At the limit a Failed pair makes room, then
/// the lowest-priority Waiting/Frozen pair below `p`; with none, `p` is
/// dropped. In-Progress and Succeeded pairs are never removed. Returns
/// whether `p` was added (with its §12 state).
pub fn insert_pair<const N: usize>(limit: usize, pairs: &mut List<Pair, N>, mut p: Pair) -> bool {
    let drop_new = pairs
        .as_slice()
        .iter()
        .any(|q| q.key() == p.key() && !(q.state.pending() && q.priority < p.priority));
    if drop_new {
        return false;
    }
    let state = new_state(pairs.as_slice(), &p);
    let others = pairs
        .as_slice()
        .iter()
        .filter(|q| q.key() != p.key())
        .count();
    let victim = if others < limit {
        None
    } else {
        // The evictable pair of lowest rank: Failed first, then priority;
        // the first of equals.
        let mut best: Option<(usize, (u8, u64))> = None;
        for (k, q) in pairs.as_slice().iter().enumerate() {
            if q.key() == p.key() {
                continue;
            }
            let evictable =
                q.state == PairState::Failed || (q.state.pending() && q.priority < p.priority);
            if !evictable {
                continue;
            }
            let rank = (u8::from(q.state != PairState::Failed), q.priority);
            if best.is_none_or(|(_, r)| rank < r) {
                best = Some((k, rank));
            }
        }
        match best {
            Some((k, _)) => pairs.as_slice().get(k).map(|p| p.id),
            None => return false,
        }
    };
    pairs.retain(|q| q.key() != p.key() && Some(q.id) != victim);
    p.state = state;
    p.nominated = false;
    pairs.push(p)
}

/// The state of a checklist (RFC 8445 §6.1.3, §8.1.2; RFC 8838 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListState {
    Running,
    Completed,
    Failed,
}

/// Completed once each of `components` has a nominated pair; Failed when
/// every pair is Failed or Succeeded, some component has no valid pair,
/// local gathering is complete (`gathered`) and the peer sent
/// end-of-candidates (`eoc`); Running otherwise.
#[must_use]
pub fn list_state(gathered: bool, eoc: bool, components: &[u8], pairs: &[Pair]) -> ListState {
    let has = |k: u8, f: &dyn Fn(&Pair) -> bool| pairs.iter().any(|q| q.component == k && f(q));
    if components.iter().all(|&k| has(k, &|q| q.nominated)) {
        ListState::Completed
    } else if gathered
        && eoc
        && pairs
            .iter()
            .all(|q| matches!(q.state, PairState::Failed | PairState::Succeeded))
        && !components
            .iter()
            .all(|&k| has(k, &|q| q.state == PairState::Succeeded))
    {
        ListState::Failed
    } else {
        ListState::Running
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A peer's PRIORITY attribute is any 32-bit value (RFC 8445 wants
    /// 1 to 2^31 − 1, but a check carrying more is still read): the pair
    /// priority saturates instead of overflowing, and keeps the order.
    #[test]
    fn pair_priority_of_out_of_range_priorities() {
        for role in [Role::Controlling, Role::Controlled] {
            let top = pair_priority(role, u32::MAX, u32::MAX);
            assert_eq!(top, u64::MAX);
            assert!(pair_priority(role, u32::MAX, 0x7fff_ffff) <= top);
            assert!(pair_priority(role, 0x7fff_ffff, 0x7fff_ffff) < top);
        }
    }

    #[test]
    fn priorities() {
        assert_eq!(candidate_priority(126, 65_535, 1), 2_130_706_431);
        assert_eq!(candidate_priority(100, 65_535, 1), 1_694_498_815);
        assert_eq!(candidate_priority(0, 0, 256), 0);
        assert_eq!(pair_priority(Role::Controlling, 10, 20), (10 << 32) + 40);
        assert_eq!(pair_priority(Role::Controlling, 20, 10), (10 << 32) + 41);
        assert_eq!(
            pair_priority(Role::Controlling, 20, 10),
            pair_priority(Role::Controlled, 10, 20)
        );
    }
}
