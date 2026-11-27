//! The native API's audit log and per-tenant rate limits.
//!
//! Every request that changes something (and every ownership claim) is
//! written to the `rtpflux::audit` log target, at `info`, once its outcome
//! is known: who (tenant, peer, connection), what (operation, operation
//! id and key, the resources named and made), and how it ended. Never a
//! body: no SDP (it can hold SRTP keys), no token, no digit.

use super::native::{Origin, Request};
use serde_json::Value as Json;
use std::collections::HashMap;
use std::time::Instant;

/// The audit line of request `req` from `origin`, answered `reply`.
#[must_use]
pub(super) fn line(req: &Request<'_>, origin: &Origin, reply: &Json) -> String {
    let named: Vec<&str> = [
        "endpoint_id",
        "peer_endpoint_id",
        "external_id",
        "recording_id",
        "group",
    ]
    .iter()
    .filter_map(|k| req.str(k))
    .collect();
    let made = reply
        .get("result")
        .map_or_else(Vec::new, super::native::resource_refs);
    let outcome = if reply.get("ok").and_then(Json::as_bool) == Some(true) {
        "ok"
    } else {
        reply
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(Json::as_str)
            .unwrap_or("error")
    };
    format!(
        "tenant={} peer=\"{}\" connection={} op={} operation_id={} key={} named={:?} resources={:?} outcome={outcome}",
        req.tenant,
        origin.peer,
        origin.connection,
        req.op,
        req.operation_id.unwrap_or("-"),
        req.str("idempotency_key").unwrap_or("-"),
        named,
        made,
    )
}

/// Requests per second per tenant, a token bucket each (as large as the
/// rate).
#[derive(Debug, Default)]
pub(super) struct Limiter {
    pub(super) rate: u32,
    buckets: HashMap<String, (f64, Instant)>,
}

impl Limiter {
    /// Whether `tenant` may make one more request now.
    pub(super) fn allow(&mut self, tenant: &str, now: Instant) -> bool {
        if self.rate == 0 {
            return true;
        }
        let rate = f64::from(self.rate);
        let (tokens, at) = self.buckets.entry(tenant.to_owned()).or_insert((rate, now));
        *tokens = (*tokens + now.saturating_duration_since(*at).as_secs_f64() * rate).min(rate);
        *at = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    #[test]
    fn a_line_names_who_and_what_never_a_body() {
        let body = json!({"op": "endpoint.create", "remote_sdp": "v=0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:SECRETKEY", "idempotency_key": "k1", "external_id": "call-1/a"});
        let req = Request {
            op: "endpoint.create",
            operation_id: Some("op-1"),
            tenant: "t",
            body: body.as_object().unwrap(),
        };
        let origin = Origin {
            connection: 3,
            events: None,
            tenant: None,
            peer: "uid 1000 pid 9".into(),
        };
        let ok = json!({"ok": true, "result": {"endpoint_id": "ep-1", "sdp": "a=crypto:… inline:OTHERKEY"}});
        let l = line(&req, &origin, &ok);
        assert!(l.contains("tenant=t") && l.contains("op=endpoint.create") && l.contains("key=k1"));
        assert!(l.contains("\"ep-1\"") && l.contains("call-1/a") && l.contains("outcome=ok"));
        assert!(!l.contains("SECRETKEY") && !l.contains("OTHERKEY") && !l.contains("crypto"));
        let failed = json!({"ok": false, "error": {"code": "fenced"}});
        assert!(line(&req, &origin, &failed).ends_with("outcome=fenced"));
    }

    #[test]
    fn tenants_are_limited_apart() {
        let mut l = Limiter {
            rate: 5,
            ..Limiter::default()
        };
        let t0 = Instant::now();
        assert_eq!(
            (0..10).filter(|_| l.allow("a", t0)).count(),
            5,
            "a burst of the rate"
        );
        assert!(l.allow("b", t0), "another tenant's own bucket");
        assert!(!l.allow("a", t0));
        assert!(
            l.allow("a", t0 + Duration::from_millis(250)),
            "refilled over time"
        );
        let mut off = Limiter::default();
        assert!((0..1000).all(|_| off.allow("a", t0)));
    }
}
