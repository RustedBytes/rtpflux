//! The async client against a fake relay that answers only when the test
//! says: what cancellation means at each stage of a request (queued,
//! written, answered late), a connection lost with requests in flight,
//! fragmented frames, and correlation ids that stay unique across
//! reconnects.

use rtpflux_client_async::{Config, MediaClient, MediaError};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

fn socket(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("rtpflux-async-fake-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("fake.sock")
}

async fn read(s: &mut UnixStream) -> Option<Value> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await.ok()?;
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut body).await.ok()?;
    serde_json::from_slice(&body).ok()
}

/// `v`, framed, written in pieces of `chunk` octets.
async fn write(s: &mut UnixStream, v: &Value, chunk: usize) {
    let body = v.to_string().into_bytes();
    let mut f = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    f.extend_from_slice(&body);
    for piece in f.chunks(chunk) {
        s.write_all(piece).await.unwrap();
        s.flush().await.unwrap();
        if chunk < f.len() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
}

fn ok(op_id: &Value, result: Value) -> Value {
    let mut reply = json!({"v": 1, "operation_id": op_id, "ok": true});
    reply["result"] = result;
    reply
}

/// A fake relay: answers `hello` at once; every other request is handed to
/// the test (`requests`), which answers through `replies` (request,
/// reply), or never.
fn fake(
    path: &std::path::Path,
) -> (
    mpsc::UnboundedReceiver<Value>,
    mpsc::UnboundedSender<Option<(Value, usize)>>,
) {
    type Writer = std::sync::Arc<tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>>;
    let listener = UnixListener::bind(path).unwrap();
    let (req_tx, req_rx) = mpsc::unbounded_channel();
    let (rep_tx, mut rep_rx) = mpsc::unbounded_channel::<Option<(Value, usize)>>();
    let current: std::sync::Arc<tokio::sync::Mutex<Option<Writer>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(None));
    let latest = std::sync::Arc::clone(&current);
    // Accept every connection; the latest one gets the test's replies.
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            let (mut r, w) = s.into_split();
            let own: Writer = std::sync::Arc::new(tokio::sync::Mutex::new(w));
            *latest.lock().await = Some(std::sync::Arc::clone(&own));
            let req_tx = req_tx.clone();
            tokio::spawn(async move {
                loop {
                    let mut len = [0u8; 4];
                    if r.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
                    if r.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    let v: Value = serde_json::from_slice(&body).unwrap();
                    if v["op"] == "hello" {
                        let reply = ok(&v["operation_id"], json!({"versions": [1]}));
                        let body = reply.to_string().into_bytes();
                        let mut f = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
                        f.extend_from_slice(&body);
                        let _ = own.lock().await.write_all(&f).await;
                    } else {
                        let _ = req_tx.send(v);
                    }
                }
            });
        }
    });
    tokio::spawn(async move {
        while let Some(m) = rep_rx.recv().await {
            let mut g = current.lock().await;
            let Some(conn) = g.clone() else {
                continue;
            };
            let mut w = conn.lock().await;
            if let Some((reply, chunk)) = m {
                {
                    let body = reply.to_string().into_bytes();
                    let mut f = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
                    f.extend_from_slice(&body);
                    for piece in f.chunks(chunk) {
                        if w.write_all(piece).await.is_err() {
                            break;
                        }
                        let _ = w.flush().await;
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                }
            } else {
                let _ = w.shutdown().await;
                *g = None;
            }
        }
    });
    (req_rx, rep_tx)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancellation_at_each_stage() {
    let path = socket("cancel");
    let (mut requests, replies) = fake(&path);
    let mut config = Config::unix(&path);
    config.connections = 1;
    config.in_flight_per_connection = 1;
    config.backoff_min = Duration::from_millis(20);
    config.backoff_max = Duration::from_millis(50);
    let media = MediaClient::connect(config).await.unwrap();

    // 1. Written, then cancelled: the relay got it (it may run it); its
    //    late reply is not taken for anyone else's.
    let m = media.clone();
    let first = tokio::spawn(async move { m.list_endpoints(None).await });
    let written = tokio::time::timeout(Duration::from_secs(2), requests.recv())
        .await
        .unwrap()
        .unwrap();
    // 2. Queued behind it (one in flight at most), then cancelled: never
    //    written.
    let m = media.clone();
    let queued = tokio::spawn(async move { m.query_endpoint("ep-queued", None).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    queued.abort();
    first.abort();
    // The late reply to the first; then the next request is answered as
    // its own.
    replies
        .send(Some((
            ok(&written["operation_id"], json!({"endpoints": ["late"]})),
            4096,
        )))
        .unwrap();
    let m = media.clone();
    let third = tokio::spawn(async move { m.query_endpoint("ep-third", None).await });
    let req = tokio::time::timeout(Duration::from_secs(2), requests.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        req["endpoint_id"], "ep-third",
        "the cancelled one was never written"
    );
    // Its reply, fragmented into 3-octet pieces.
    replies
        .send(Some((
            ok(&req["operation_id"], json!({"endpoint_id": "ep-third"})),
            3,
        )))
        .unwrap();
    let r = third.await.unwrap().unwrap();
    assert_eq!(r["endpoint_id"], "ep-third");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), requests.recv())
            .await
            .is_err(),
        "nothing else was sent"
    );

    // 3. In flight when the connection is lost: Disconnected, sent; and
    //    the client reconnects with new operation ids.
    let m = media.clone();
    let lost = tokio::spawn(async move { m.list_endpoints(Some(Duration::from_secs(2))).await });
    let before = tokio::time::timeout(Duration::from_secs(2), requests.recv())
        .await
        .unwrap()
        .unwrap();
    replies.send(None).unwrap();
    let e = lost.await.unwrap().unwrap_err();
    assert_eq!(e, MediaError::Disconnected { sent: true });
    assert!(e.outcome_unknown());
    let m = media.clone();
    let after = tokio::spawn(async move { m.list_endpoints(Some(Duration::from_secs(3))).await });
    let again = tokio::time::timeout(Duration::from_secs(3), requests.recv())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(
        again["operation_id"], before["operation_id"],
        "ids are not reused"
    );
    assert_ne!(again["operation_id"], written["operation_id"]);
    replies
        .send(Some((
            ok(&again["operation_id"], json!({"endpoints": []})),
            4096,
        )))
        .unwrap();
    assert!(after.await.unwrap().is_ok());
    let _ = read;
    let _ = write;
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

/// A relay that never answers: the request times out within its deadline,
/// and says it was sent (its outcome is unknown).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_never_answered_times_out_as_sent() {
    let path = socket("mute");
    let (mut requests, _replies) = fake(&path);
    let media = MediaClient::connect(Config::unix(&path)).await.unwrap();
    let started = std::time::Instant::now();
    let e = media
        .list_endpoints(Some(Duration::from_millis(200)))
        .await
        .unwrap_err();
    assert_eq!(e, MediaError::Timeout { sent: true });
    assert!(started.elapsed() < Duration::from_secs(1));
    let req = requests.recv().await.unwrap();
    assert!(
        req["deadline_unix_ms"].as_u64().unwrap() > 0,
        "the deadline went with it"
    );
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
