//! A re-offer's decision for one media section: keep the section's relay
//! call (the same ports and relay keys, side A updated), leave a bundled
//! member as its group's, give it a new call, or none (disabled now).

/// What a re-offer does with a media section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Keep the call; side A becomes the new offer's.
    Keep,
    /// Keep the call as it is: its side A is its BUNDLE group's.
    KeepBundled,
    /// A new call.
    Create,
    /// No call (port 0).
    Disabled,
}

/// The action for a section whose previous call is `prev` (side A
/// bundled, a bundled member other than the group's first, the profile
/// offered to B), offered now on `port` and to be offered to B as
/// `profile`; and whether the previous call ends. A call is kept while
/// the section stays enabled (or bundled) and B is offered the same
/// profile (RFC 3264 §8).
#[must_use]
pub fn action<T: PartialEq>(
    prev: Option<(bool, bool, T)>,
    port: u16,
    profile: &T,
) -> (Action, bool) {
    let fresh = if port == 0 {
        Action::Disabled
    } else {
        Action::Create
    };
    match prev {
        Some((a_bundled, member, b_transport)) => {
            if (port != 0 || a_bundled) && b_transport == *profile {
                let keep = if a_bundled && member {
                    Action::KeepBundled
                } else {
                    Action::Keep
                };
                (keep, false)
            } else {
                (fresh, true)
            }
        }
        None => (fresh, false),
    }
}
