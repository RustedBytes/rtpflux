//! One connection to the relay, owned by a task (an actor): it writes the
//! requests queued for it, matches the replies to them by `operation_id`
//! (requests are pipelined), and reconnects with backoff when the
//! connection breaks.
//!
//! Reading a frame is not cancellation-safe, so a reader task of its own
//! reads them and hands them over through a bounded channel; the actor's
//! `select!` only ever waits on channels and timers.

use crate::config::{Config, Transport};
use crate::error::{ErrorCode, MediaError};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

/// The largest message, either way.
pub const MAX_MESSAGE: usize = 1 << 20;

pub(crate) type Reader = Box<dyn AsyncRead + Unpin + Send>;
pub(crate) type Writer = Box<dyn AsyncWrite + Unpin + Send>;

/// One framed message from `r`.
pub(crate) async fn read_frame(r: &mut Reader) -> std::io::Result<Value> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_MESSAGE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).await?;
    serde_json::from_slice(&body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// `body` (JSON text), framed, to `w`.
pub(crate) async fn write_frame(w: &mut Writer, body: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(body.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "too large"))?;
    let mut f = Vec::with_capacity(body.len() + 4);
    f.extend_from_slice(&len.to_be_bytes());
    f.extend_from_slice(body);
    w.write_all(&f).await?;
    w.flush().await
}

/// The result, or the relay's refusal, in reply `v`.
pub(crate) fn outcome(v: &Value) -> Result<Value, MediaError> {
    if v.get("ok").and_then(Value::as_bool) == Some(true) {
        return Ok(v.get("result").cloned().unwrap_or(Value::Null));
    }
    let e = v
        .get("error")
        .ok_or_else(|| MediaError::Protocol(format!("{v}")))?;
    Err(MediaError::Refused {
        code: ErrorCode::parse(e.get("code").and_then(Value::as_str).unwrap_or("internal")),
        message: e
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
    })
}

/// Connect (and, over TCP, authenticate) within the connect timeout.
pub(crate) async fn open(config: &Config) -> Result<(Reader, Writer), MediaError> {
    let connect = async {
        let (mut r, mut w): (Reader, Writer) = match &config.transport {
            Transport::Unix(path) => {
                let s = tokio::net::UnixStream::connect(path).await?;
                let (r, w) = s.into_split();
                (Box::new(r), Box::new(w))
            }
            Transport::Tcp { addr, .. } => {
                let s = tokio::net::TcpStream::connect(addr.as_str()).await?;
                s.set_nodelay(true)?;
                let (r, w) = s.into_split();
                (Box::new(r), Box::new(w))
            }
        };
        if let Transport::Tcp { token, .. } = &config.transport {
            let auth = json!({"v": 1, "op": "auth", "operation_id": "auth", "token": token});
            write_frame(&mut w, auth.to_string().as_bytes()).await?;
            let reply = read_frame(&mut r).await?;
            return Ok::<_, std::io::Error>((r, w, Some(reply)));
        }
        Ok((r, w, None))
    };
    match tokio::time::timeout(config.connect_timeout, connect).await {
        Err(_) => Err(MediaError::Timeout { sent: false }),
        Ok(Err(_)) => Err(MediaError::Disconnected { sent: false }),
        Ok(Ok((r, w, auth))) => {
            if let Some(reply) = auth {
                outcome(&reply)?;
            }
            Ok((r, w))
        }
    }
}

/// A request for a connection's actor.
pub(crate) struct Job {
    pub(crate) operation_id: String,
    /// The message (JSON text).
    pub(crate) body: Vec<u8>,
    pub(crate) deadline: Instant,
    /// Set once the request is written (its outcome is then unknown if no
    /// reply comes).
    pub(crate) sent: Arc<AtomicBool>,
    pub(crate) reply: oneshot::Sender<Result<Value, MediaError>>,
}

/// Start a connection's actor, taking requests from `jobs`. It ends when
/// every sender of `jobs` is gone.
pub(crate) fn spawn(config: Arc<Config>, jobs: mpsc::Receiver<Job>) {
    tokio::spawn(run(config, jobs));
}

/// The next backoff after `b`.
pub(crate) fn next_backoff(b: Duration, config: &Config) -> Duration {
    (b * 2).min(config.backoff_max).max(config.backoff_min)
}

async fn run(config: Arc<Config>, mut jobs: mpsc::Receiver<Job>) {
    let mut backoff = config.backoff_min;
    loop {
        let (reader, mut writer) = match open(&config).await {
            Ok(rw) => {
                backoff = config.backoff_min;
                rw
            }
            Err(e) => {
                log::debug!("rtpflux-client: connect: {e}; again in {backoff:?}");
                // Waiting requests whose deadline passed (or that were
                // cancelled) are answered meanwhile; the others wait.
                tokio::select! {
                    () = tokio::time::sleep(backoff) => {}
                    () = jobs.closed_or_none() => return,
                }
                backoff = next_backoff(backoff, &config);
                continue;
            }
        };
        let (frames_tx, mut frames) = mpsc::channel::<Value>(64);
        let reader_task = tokio::spawn(read_loop(reader, frames_tx));
        let mut pending: HashMap<String, oneshot::Sender<Result<Value, MediaError>>> =
            HashMap::new();
        let mut sweep = tokio::time::interval(Duration::from_millis(250));
        let closed = loop {
            tokio::select! {
                job = jobs.recv(), if pending.len() < config.in_flight_per_connection => {
                    let Some(job) = job else { break true };
                    // Cancelled, or too late, before it was written: never sent.
                    if job.reply.is_closed() {
                        continue;
                    }
                    if job.deadline <= Instant::now() {
                        let _ = job.reply.send(Err(MediaError::Timeout { sent: false }));
                        continue;
                    }
                    job.sent.store(true, Ordering::Release);
                    if write_frame(&mut writer, &job.body).await.is_err() {
                        let _ = job.reply.send(Err(MediaError::Disconnected { sent: true }));
                        break false;
                    }
                    pending.insert(job.operation_id, job.reply);
                }
                frame = frames.recv() => {
                    let Some(v) = frame else { break false };
                    if let Some(id) = v.get("operation_id").and_then(Value::as_str)
                        && let Some(tx) = pending.remove(id)
                    {
                        let _ = tx.send(outcome(&v));
                    }
                }
                _ = sweep.tick() => {
                    // Callers gone (cancelled, timed out): their replies are
                    // not waited for.
                    pending.retain(|_, tx| !tx.is_closed());
                }
            }
        };
        reader_task.abort();
        for (_, tx) in pending.drain() {
            let _ = tx.send(Err(MediaError::Disconnected { sent: true }));
        }
        if closed {
            return;
        }
        log::debug!("rtpflux-client: connection lost; reconnecting");
    }
}

/// Read frames from `r` into `tx` until the connection ends.
pub(crate) async fn read_loop(mut r: Reader, tx: mpsc::Sender<Value>) {
    while let Ok(v) = read_frame(&mut r).await {
        if tx.send(v).await.is_err() {
            return;
        }
    }
}

/// Waiting for a receiver's senders to be gone, without taking its items.
trait ClosedOrNone {
    async fn closed_or_none(&mut self);
}

impl<T> ClosedOrNone for mpsc::Receiver<T> {
    async fn closed_or_none(&mut self) {
        // A closed channel with nothing left: the client is gone.
        while !(self.is_closed() && self.is_empty()) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
