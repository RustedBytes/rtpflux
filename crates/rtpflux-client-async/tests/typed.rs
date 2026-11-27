//! The async client's typed reconciliation calls against a running relay
//! with an operation ledger: capabilities, the whole inventory with its
//! watermark (a cursor that misses nothing after it), operations by key,
//! external ids, leases and the recovery report.

use rtpflux::config::Config as RelayConfig;
use rtpflux::daemon::Daemon;
use rtpflux_client_async::{
    Config, CreateEndpointRequest, EventFilter, EventKind, MediaClient, OperationState,
};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn capabilities_inventory_operations_and_recovery() {
    let dir = std::env::temp_dir().join(format!("rtpflux-async-typed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("api.sock");
    let config = RelayConfig::from_toml(&format!(
        r#"
        [control]
        listen = ["127.0.0.1:0"]
        native_socket = "{}"
        [[interface]]
        name = "lo"
        address = "127.0.0.1"
        [ports]
        min = 61700
        max = 61763
        [sessions]
        max = 12
        state_file = "{}"
        ledger = "{}"
        [runtime]
        workers = 1
        "#,
        sock.display(),
        dir.join("state.json").display(),
        dir.join("ledger.jsonl").display(),
    ))
    .unwrap();
    let daemon = Daemon::start(&config).unwrap();
    let media = MediaClient::connect(Config::unix(&sock)).await.unwrap();

    let caps = media.hello().await.unwrap();
    assert!(caps.versions.contains(&1));
    assert!(caps.supports("inventory.list") && caps.supports("operation.query"));
    assert_eq!(caps.guarantees.idempotency.as_deref(), Some("durable"));
    let boot = caps.boot_id.clone().unwrap();

    // Created with a key and an external id; the key's operation applied.
    let mut req = CreateEndpointRequest::offering(["PCMU"]);
    req.idempotency_key = Some("op-a".into());
    req.lease_ms = Some(60_000);
    let mut fields = serde_json::Map::new();
    fields.insert("external_id".into(), "call-9/a".into());
    let a = media.create_endpoint(req.clone()).await.unwrap();
    let op = media.operation("op-a", None).await.unwrap();
    assert_eq!(op.state, OperationState::Applied);
    assert_eq!(op.resources, vec![a.endpoint_id.clone()]);
    assert!(op.durable);
    assert_eq!(
        media.operation("op-none", None).await.unwrap().state,
        OperationState::NotFound
    );
    media
        .call(
            "endpoint.create",
            {
                let mut f = fields.clone();
                f.insert("codecs".into(), serde_json::json!(["PCMA"]));
                f
            },
            None,
        )
        .await
        .unwrap();
    let found = media.lookup("call-9/a").await.unwrap();
    assert_eq!(found["state_of_id"], "live");
    media
        .renew(&a.endpoint_id, Some(Duration::from_secs(30)))
        .await
        .unwrap();

    // The whole inventory, and a subscription from its watermark: only
    // what follows.
    let (items, watermark) = media.inventory_all("endpoints", 3).await.unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(watermark.boot_id, boot);
    let mut events = media
        .subscribe_events(EventFilter {
            cursor: Some(watermark.cursor()),
            ..EventFilter::default()
        })
        .await
        .unwrap();
    media
        .destroy_endpoint(rtpflux_client_async::DestroyEndpointRequest::new(
            &a.endpoint_id,
        ))
        .await
        .unwrap();
    let e = tokio::time::timeout(Duration::from_secs(3), events.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(e.kind, EventKind::EndpointDestroyed);
    assert_eq!(e.endpoint_id.as_deref(), Some(a.endpoint_id.as_str()));
    assert!(e.event_id.as_deref().unwrap().starts_with(&boot));

    let report = media.recovery_report().await.unwrap();
    assert_eq!(report.boot_id, boot);
    assert!(report.lost.is_empty() && report.unknown_operations.is_empty());
    drop((media, events));
    tokio::task::spawn_blocking(move || daemon.stop())
        .await
        .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}
