//! Echo (RTP loopback) of the native API: `endpoint.echo`.
//!
//! An echoing endpoint gets its own media back as it sent it: each RTP
//! packet it sends is returned to it by the media worker, unchanged, in
//! its own codec and packet time (`media echo` of `ng`, on the endpoint's
//! leg). Its RTCP is dropped, and nothing reaches the hidden side. It is
//! the media half of an echo test, and a loopback for checking a path.
//!
//! The state is the call's `media echo`, so it is kept with the state
//! file (restored after a restart) and survives a renegotiation. An
//! endpoint echoes or is bridged, never both: `endpoint.echo` refuses a
//! bridged endpoint or a mixer participant, and `bridge.attach` and
//! `mixer.add` refuse an echoing one.

use super::native::{Code, Endpoint, NativeError, Request};
use super::{Control, Error};
use crate::relay::{CallLeg, Echo};
use serde_json::{Value as Json, json};

impl Control {
    /// Whether the party tagged `tag` of call `call` has its media echoed.
    pub(super) fn party_echoing(&self, call: &[u8], tag: &[u8]) -> bool {
        self.party_legs(call, tag)
            .into_iter()
            .flatten()
            .flatten()
            .any(|((id, leg), _)| {
                self.extras
                    .get(&id)
                    .is_some_and(|x| x.echo[usize::from(leg == CallLeg::B)] == Echo::Echo.code())
            })
    }

    /// The party's media echoed (`on`), or parked (dropped, both ways).
    pub(super) fn set_party_echo(
        &mut self,
        call: &[u8],
        tag: &[u8],
        on: bool,
    ) -> Result<(), Error> {
        let legs = self.party_legs(call, tag).ok_or(Error::UnknownCallOrTag)?;
        for ((id, leg), _) in legs.into_iter().flatten() {
            let mut modes = [Echo::Discard; 2];
            if on {
                modes[usize::from(leg == CallLeg::B)] = Echo::Echo;
            }
            if !self.relay.echo(id, modes)? {
                return Err(Error::UnknownCallOrTag);
            }
            // Kept with the call's extras, for a restart.
            self.extras.entry(id).or_default().echo = modes.map(Echo::code);
        }
        self.mark_dirty();
        Ok(())
    }

    /// Whether endpoint `ep` echoes.
    pub(super) fn echoing(&self, ep: &Endpoint) -> bool {
        self.party_echoing(ep.session.as_bytes(), ep.id.as_bytes())
    }

    /// Refused when `ep` echoes (before it is bridged or mixed).
    pub(super) fn not_echoing(&self, ep: &Endpoint) -> Result<(), NativeError> {
        if self.echoing(ep) {
            return Err(NativeError::new(
                Code::Conflict,
                format!("endpoint {} echoes (endpoint.echo off first)", ep.id),
            ));
        }
        Ok(())
    }

    /// `endpoint.echo`: `echo: true` sends the endpoint its own media
    /// back; `false` stops it (its media dropped again, as before).
    pub(super) fn native_echo(&mut self, req: &Request<'_>) -> Result<Json, NativeError> {
        let ep = self
            .native
            .get(req.need("endpoint_id")?, req.tenant)?
            .clone();
        let on = req
            .body
            .get("echo")
            .and_then(Json::as_bool)
            .ok_or_else(|| NativeError::invalid("echo: true or false"))?;
        if self.echoing(&ep) == on {
            return Ok(json!({"echo": on, "changed": false}));
        }
        if on {
            if ep.bridged_to.is_some() {
                return Err(NativeError::new(
                    Code::Conflict,
                    "the endpoint is bridged (bridge.detach first)",
                ));
            }
            if self.in_mixer(&ep.id) {
                return Err(NativeError::new(
                    Code::Conflict,
                    "the endpoint is in a mixer (mixer.remove first)",
                ));
            }
            if !ep.ready {
                return Err(NativeError::new(
                    Code::Conflict,
                    "the endpoint is not answered yet",
                ));
            }
        }
        self.set_party_echo(ep.session.as_bytes(), ep.id.as_bytes(), on)?;
        self.confirm(&[&ep])?;
        Ok(json!({"echo": on, "changed": true}))
    }
}
