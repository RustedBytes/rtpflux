# rtpflux-client

A client of rtpflux's [native control API](../../docs/native-api.md): what
a B2BUA or softswitch links to manage media endpoints, without any of the
relay's internals. It depends only on `serde_json`.

```rust
use rtpflux_client::Client;
use serde_json::json;
use std::time::Duration;

let mut c = Client::connect("/run/rtpflux/native.sock")?;
c.call("events.subscribe", json!({"types": ["dtmf.detected"]}))?;
let inbound = c.call("endpoint.create", json!({"remote_sdp": offer}))?;
let outbound = c.call("endpoint.create", json!({"codecs": ["PCMU"]}))?;
// … send outbound["sdp"] in an INVITE, then:
c.call("endpoint.apply_answer", json!({"endpoint_id": outbound["endpoint_id"], "sdp": answer}))?;
c.call("bridge.attach", json!({"endpoint_id": inbound["endpoint_id"],
                                "peer_endpoint_id": outbound["endpoint_id"]}))?;
if let Some(ev) = c.wait_event("dtmf.detected", Duration::from_secs(10))? {
    println!("pressed {}", ev["data"]["digit"]);
}
```

Over TCP, `Client::connect_tcp(addr, token)` connects and authenticates
with a tenant's token.

`call` returns the operation's `result`, or `ClientError::Refused` with the
relay's error code (`not_found`, `conflict`, …). Events that arrive while
waiting for a reply are kept for `next_event` and `wait_event`.

`fixtures/` holds protocol examples, request by request, which this crate's
tests check are well formed. A softswitch's own tests can use them as
golden messages.
