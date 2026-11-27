//! The async client against a running relay: two legs negotiated, bridged
//! and destroyed through typed requests, with events on their own
//! connection; deadlines, cancellation and bounded queues; reconnecting
//! (requests and events) across a restart of the relay; TCP tokens; a
//! slow event consumer.

use rtpflux::config::Config as RelayConfig;
use rtpflux::daemon::Daemon;
use rtpflux_client_async::{
    ApplyAnswerRequest, AttachBridgeRequest, Config, CreateEndpointRequest, DestroyEndpointRequest,
    ErrorCode, EventFilter, EventKind, MediaClient, MediaError,
};
use serde_json::json;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(3);

fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rtpflux-async-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A relay with the native API on `dir/api.sock` (and TCP), ports from
/// `min`, a state file in `dir`.
fn relay(dir: &Path, min: u16) -> (Daemon, PathBuf) {
    let sock = dir.join("api.sock");
    let config = RelayConfig::from_toml(&format!(
        r#"
        [control]
        listen = ["127.0.0.1:0"]
        native_socket = "{}"
        native_listen = ["127.0.0.1:0"]
        native_tokens = {{ default = "token-of-default-0" }}
        [[interface]]
        name = "lo"
        address = "127.0.0.1"
        [ports]
        min = {min}
        max = {}
        [sessions]
        max = 12
        state_file = "{}"
        [runtime]
        workers = 2
        "#,
        sock.display(),
        min + 63,
        dir.join("state.json").display(),
    ))
    .unwrap();
    (Daemon::start(&config).unwrap(), sock)
}

fn endpoint() -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    s
}

fn sdp(s: &UdpSocket) -> String {
    format!(
        "v=0\r\no=- 7 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n",
        s.local_addr().unwrap().port()
    )
}

fn relay_addr(sdp: &str) -> SocketAddr {
    let port = sdp
        .lines()
        .find_map(|l| l.strip_prefix("m=audio "))
        .and_then(|l| l.split(' ').next())
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap();
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn rtp(seq: u16) -> Vec<u8> {
    let mut p = vec![0x80, 0];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
    p.extend_from_slice(&7u32.to_be_bytes());
    p.extend_from_slice(&[0xff; 160]);
    p
}

fn opts() -> serde_json::Map<String, serde_json::Value> {
    json!({"flags": ["trust-address"], "endpoint-learning": "off"})
        .as_object()
        .unwrap()
        .clone()
}

/// Many requests at once (spread over the connections, bounded), a
/// deadline already gone, and cancelled requests; `endpoint_id` exists.
async fn limits(media: &MediaClient, endpoint_id: &str) {
    // Many requests at once, spread over the connections.
    let calls = (0..200).map(|_| {
        let m = media.clone();
        tokio::spawn(async move { m.query_endpoint("ep-none", None).await })
    });
    for c in calls {
        let e = c.await.unwrap().unwrap_err();
        assert!(
            e.code() == Some(&ErrorCode::NotFound) || e == MediaError::Overloaded,
            "{e}"
        );
    }

    // A deadline already gone: refused here, never sent.
    let mut late = DestroyEndpointRequest::new(endpoint_id);
    late.deadline = Some(Duration::ZERO);
    assert_eq!(
        media.destroy_endpoint(late).await.unwrap_err(),
        MediaError::Timeout { sent: false }
    );
    // Cancelled requests leave the connections usable.
    for _ in 0..20 {
        let m = media.clone();
        let t = tokio::spawn(async move { m.list_endpoints(None).await });
        t.abort();
    }
    assert_eq!(
        media.list_endpoints(None).await.unwrap()["endpoints"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_legs_with_typed_requests_and_events() {
    let dir = temp_dir("legs");
    let (daemon, sock) = relay(&dir, 53_300);
    let media = MediaClient::connect(Config::unix(&sock)).await.unwrap();
    let mut events = media
        .subscribe_events(EventFilter::default())
        .await
        .unwrap();
    let (caller, callee) = (endpoint(), endpoint());

    let mut inbound = CreateEndpointRequest::answering(sdp(&caller));
    inbound.options = Some(opts());
    inbound.idempotency_key = Some("call-1/a".into());
    let leg_a = media.create_endpoint(inbound.clone()).await.unwrap();
    assert_eq!(
        (leg_a.sdp_type.as_str(), leg_a.state.as_str()),
        ("answer", "ready")
    );
    // A retry: the same endpoint.
    assert_eq!(media.create_endpoint(inbound).await.unwrap(), leg_a);
    let leg_b = media
        .create_endpoint(CreateEndpointRequest::offering(["PCMU"]))
        .await
        .unwrap();
    media
        .apply_answer(ApplyAnswerRequest {
            endpoint_id: leg_b.endpoint_id.clone(),
            sdp: sdp(&callee),
            expected_generation: Some(leg_b.generation),
            options: Some(opts()),
            deadline: None,
        })
        .await
        .unwrap();
    let bridged = media
        .attach_bridge(AttachBridgeRequest::new(
            &leg_a.endpoint_id,
            &leg_b.endpoint_id,
        ))
        .await
        .unwrap();
    assert_eq!(bridged.bridged_to, leg_b.endpoint_id);
    // In effect when it returns.
    caller.send_to(&rtp(1), relay_addr(&leg_a.sdp)).unwrap();
    let mut buf = [0u8; 512];
    assert!(callee.recv_from(&mut buf).is_ok(), "media flows");

    // Events, on their own connection: ready, then the bridge.
    let mut kinds = Vec::new();
    while kinds.len() < 4 {
        let e = tokio::time::timeout(WAIT, events.next())
            .await
            .unwrap()
            .unwrap();
        kinds.push(e.kind);
    }
    assert!(kinds.contains(&EventKind::EndpointReady), "{kinds:?}");
    assert!(kinds.contains(&EventKind::BridgeChanged), "{kinds:?}");

    // Typed errors; a stale generation is a conflict.
    let mut stale = AttachBridgeRequest::new(&leg_a.endpoint_id, &leg_b.endpoint_id);
    stale.expected_generation = Some(999);
    let e = media.attach_bridge(stale).await.unwrap_err();
    assert_eq!(e.code(), Some(&ErrorCode::Conflict));
    assert!(!e.outcome_unknown());

    limits(&media, &leg_a.endpoint_id).await;

    for ep in [&leg_a, &leg_b] {
        media
            .destroy_endpoint(DestroyEndpointRequest::new(&ep.endpoint_id))
            .await
            .unwrap();
    }
    // Twice: still a success.
    media
        .destroy_endpoint(DestroyEndpointRequest::new(&leg_a.endpoint_id))
        .await
        .unwrap();
    let destroyed = loop {
        let e = tokio::time::timeout(WAIT, events.next())
            .await
            .unwrap()
            .unwrap();
        if e.kind == EventKind::EndpointDestroyed {
            break e;
        }
    };
    assert!(destroyed.endpoint_id.is_some());
    drop((media, events));
    tokio::task::spawn_blocking(move || daemon.stop())
        .await
        .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The relay restarts: requests meanwhile fail with a typed error, the
/// client reconnects (its requests and its events), the endpoint is back
/// (state file), and the event stream says it missed events.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_client_reconnects_across_a_restart() {
    let dir = temp_dir("restart");
    let (daemon, sock) = relay(&dir, 55_900);
    let mut config = Config::unix(&sock);
    config.backoff_max = Duration::from_millis(200);
    let media = MediaClient::connect(config).await.unwrap();
    let mut events = media
        .subscribe_events(EventFilter::default())
        .await
        .unwrap();
    let ep = media
        .create_endpoint(CreateEndpointRequest::offering(["PCMA"]))
        .await
        .unwrap();
    tokio::task::spawn_blocking(move || daemon.stop())
        .await
        .unwrap();

    // While it is down: a typed failure within the deadline.
    let e = media
        .query_endpoint(&ep.endpoint_id, Some(Duration::from_millis(300)))
        .await
        .unwrap_err();
    assert!(
        matches!(
            e,
            MediaError::Timeout { .. } | MediaError::Disconnected { .. }
        ),
        "{e}"
    );

    let (dir2, daemon) = tokio::task::spawn_blocking(move || {
        let (d, _) = relay(&dir, 55_900);
        (dir, d)
    })
    .await
    .unwrap();
    // Back: the same endpoint, through the reconnected connections.
    let snap = loop {
        match media
            .query_endpoint(&ep.endpoint_id, Some(Duration::from_millis(500)))
            .await
        {
            Ok(s) => break s,
            Err(e) if !matches!(e, MediaError::Refused { .. }) => {}
            Err(e) => panic!("{e}"),
        }
    };
    assert_eq!(snap["generation"], ep.generation);
    // The events say what was lost.
    let gap = loop {
        let e = tokio::time::timeout(WAIT, events.next())
            .await
            .unwrap()
            .unwrap();
        if e.kind == EventKind::Gap {
            break e;
        }
    };
    // The stream came back from its cursor, which was of the run before:
    // the relay says so (reconcile with the inventory).
    assert_eq!(gap.data["reason"], "boot_changed");
    drop((media, events));
    tokio::task::spawn_blocking(move || daemon.stop())
        .await
        .unwrap();
    std::fs::remove_dir_all(&dir2).unwrap();
}

/// TCP with a tenant's token (a wrong one is refused at connect), and a
/// consumer too slow for its events: the stream pauses and resumes from
/// its cursor, so it gets every event once, in order, with bounded
/// memory.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_tokens_and_a_slow_event_consumer() {
    let dir = temp_dir("tcp");
    let (daemon, _) = relay(&dir, 59_300);
    let addr = daemon.native_addrs()[0].to_string();
    let bad = MediaClient::connect(Config::tcp(&addr, "not-the-token-0000"))
        .await
        .unwrap_err();
    assert_eq!(bad.code(), Some(&ErrorCode::Unauthorized));
    let mut config = Config::tcp(&addr, "token-of-default-0");
    config.event_queue = 2;
    let media = MediaClient::connect(config).await.unwrap();
    let mut events = media
        .subscribe_events(EventFilter {
            types: vec!["endpoint.destroyed".into()],
            ..EventFilter::default()
        })
        .await
        .unwrap();
    // Many events, none read meanwhile: the stream stops reading and
    // comes back from its cursor once there is room. Nothing is lost,
    // nothing is queued without bound, nothing comes twice.
    let mut made = Vec::new();
    for _ in 0..30 {
        let ep = media
            .create_endpoint(CreateEndpointRequest::offering(["PCMU"]))
            .await
            .unwrap();
        media
            .destroy_endpoint(DestroyEndpointRequest::new(&ep.endpoint_id))
            .await
            .unwrap();
        made.push(ep.endpoint_id);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Each comes, however slowly the stream resumes on a busy machine;
    // nothing comes after.
    let mut got = Vec::new();
    while got.len() < made.len() {
        let e = tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .expect("the next event")
            .unwrap();
        assert_ne!(e.kind, EventKind::Gap, "{e:?}");
        got.push(e.endpoint_id.unwrap());
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(300), events.next())
            .await
            .is_err(),
        "nothing twice"
    );
    assert_eq!(got, made, "every destroy, once, in order");
    drop((media, events));
    tokio::task::spawn_blocking(move || daemon.stop())
        .await
        .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}
