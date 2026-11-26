//! The `ng` server end to end over UDP: what Kamailio's rtpengine module
//! would send, then media through the ports the rewritten SDP announces.

#[path = "../support/logging.rs"]
mod logging;

mod bundle;
mod calls;
mod codecs;
mod commands;
mod common;
mod create;
mod dtmf_security;
mod dtmf_xcode;
mod features;
mod ice;
mod inject;
mod negotiation;
mod options;
mod parties;
mod reinvite;
mod rollback;
mod secure;
mod subscribe;
mod t38;
mod uring;
mod zrtp;
