//! `aya::Pod` wrappers for the forwarding map's key and value.
//!
//! The only `unsafe` code in the workspace outside the XDP program (see
//! AGENTS.md §5). `aya::Pod` is an unsafe trait: implementing it promises
//! that every byte of the type is initialised plain data, so aya may copy
//! the value to and from the kernel as raw bytes. The wrappers keep
//! `rtpflux-xdp-common` free of aya and of `unsafe`.
#![allow(unsafe_code)]

use rtpflux_xdp_common::{FlowAction, FlowKey, FlowStats, SteerRange};

/// Map key as aya sees it.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Key(pub(crate) FlowKey);

/// Map value as aya sees it.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Action(pub(crate) FlowAction);

/// A steered port range as aya sees it.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Steer(pub(crate) SteerRange);

/// Per-flow counters as aya sees them.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stats(pub(crate) FlowStats);

// No padding: the sum of the field sizes equals the struct size, so every
// byte is a field byte and therefore initialised.
const _: () = assert!(size_of::<FlowKey>() == 16 + 16 + 2 + 2);
const _: () = assert!(size_of::<FlowAction>() == 16 + 16 + 2 + 2 + 6 + 6 + 4 + 1 + 1 + 2);
const _: () = assert!(size_of::<FlowStats>() == 8 + 8 + 8);
const _: () = assert!(size_of::<SteerRange>() == 2 + 2 + 4);

// SAFETY: `Key` is `repr(transparent)` over `FlowKey`, which is `repr(C)`,
// `Copy`, `'static`, made only of integers, and has no padding (asserted
// above). Any bit pattern is a valid value.
unsafe impl aya::Pod for Key {}

// SAFETY: as for `Key`: `repr(transparent)` over the `repr(C)`, padding-free,
// integer-only `FlowAction`.
unsafe impl aya::Pod for Action {}

// SAFETY: as for `Key`: `repr(transparent)` over the `repr(C)`, padding-free
// `FlowStats` of three `u64`s.
unsafe impl aya::Pod for Stats {}

// SAFETY: as for `Key`: `repr(transparent)` over the `repr(C)`, padding-free
// `SteerRange` of two `u16`s and a `u32`.
unsafe impl aya::Pod for Steer {}
