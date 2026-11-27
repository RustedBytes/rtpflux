//! Event subscriptions, each on a connection of its own (never sharing the
//! request connections, so a burst of events never delays a reply).
//!
//! The stream keeps its position: the `event_id` of the last event handed
//! to the consumer (or, before any, the cursor the subscription began at).
//! Whenever the connection must be made again, it subscribes again from
//! that position, and the relay replays from its journal what came after:
//! - the connection broke (reconnected with backoff);
//! - the relay said this subscriber overflowed (`gap`, `overflow`);
//! - the consumer fell behind: its bounded queue ([`Config::event_queue`])
//!   is full. The stream stops reading, lets the connection go, and comes
//!   back from its position once there is room, so nothing queues without
//!   bound and nothing is lost meanwhile.
//!
//! Events at or before the position are dropped (a replay may repeat
//! some): the consumer gets each event once, in order. Only what the relay
//! cannot replay reaches the consumer as a [`EventKind::Gap`]: a cursor of
//! another run of the relay (`boot_changed`), one older than its journal
//! (`retention_expired`), or events lost before the journal
//! (`media_overflow`). Then reconcile with [`MediaClient::inventory`] and
//! [`MediaClient::recovery_report`].
//!
//! [`MediaClient::inventory`]: crate::MediaClient::inventory
//! [`MediaClient::recovery_report`]: crate::MediaClient::recovery_report

use crate::config::{Config, Transport};
use crate::conn::{next_backoff, open, outcome, read_frame, write_frame};
use crate::error::MediaError;
use crate::types::{EventFilter, EventKind, MediaEvent};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// A subscription's events, in order, each once. Dropping it ends the
/// subscription (and its connection).
#[derive(Debug)]
pub struct MediaEventStream {
    rx: mpsc::Receiver<MediaEvent>,
    task: JoinHandle<()>,
}

impl MediaEventStream {
    /// The next event; `None` once the client is shut down.
    pub async fn next(&mut self) -> Option<MediaEvent> {
        self.rx.recv().await
    }

    /// The next event if one is waiting.
    pub fn try_next(&mut self) -> Option<MediaEvent> {
        self.rx.try_recv().ok()
    }
}

impl Drop for MediaEventStream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A subscribed connection: its reader, its writer (kept open), the
/// subscription's reply, and the events that came before the reply (a
/// replay is written as the subscription is made, and may overtake it).
type Subscribed = (crate::conn::Reader, crate::conn::Writer, Value, Vec<Value>);

/// A connection subscribed to `filter` from `cursor` (if any).
async fn subscribe(
    config: &Config,
    filter: &EventFilter,
    cursor: Option<&str>,
) -> Result<Subscribed, MediaError> {
    let (mut r, mut w) = open(config).await?;
    let mut req = serde_json::to_value(filter).map_err(|e| MediaError::Protocol(e.to_string()))?;
    if let Some(o) = req.as_object_mut() {
        o.insert("v".into(), json!(1));
        o.insert("op".into(), json!("events.subscribe"));
        o.insert("operation_id".into(), json!("subscribe"));
        o.remove("cursor");
        if let Some(c) = cursor {
            o.insert("cursor".into(), json!(c));
        }
        if let (Some(t), Transport::Unix(_)) = (&config.tenant, &config.transport) {
            o.insert("tenant".into(), json!(t));
        }
    }
    let mut early = Vec::new();
    let wait = async {
        write_frame(&mut w, req.to_string().as_bytes())
            .await
            .map_err(|_| MediaError::Disconnected { sent: true })?;
        loop {
            let v = read_frame(&mut r)
                .await
                .map_err(|_| MediaError::Disconnected { sent: true })?;
            if v.get("operation_id").and_then(Value::as_str) == Some("subscribe") {
                return outcome(&v);
            }
            if v.get("event").is_some() {
                early.push(v);
            }
        }
    };
    let reply = tokio::time::timeout(config.connect_timeout, wait)
        .await
        .map_err(|_| MediaError::Timeout { sent: true })??;
    Ok((r, w, reply, early))
}

/// Where a stream is: the cursor to resume from, and the last event's
/// number in its run (to drop repeats).
#[derive(Debug, Clone, Default)]
struct Position {
    cursor: Option<String>,
    boot: Option<String>,
    last_seq: u64,
}

/// A cursor's run and number.
fn split_cursor(c: &str) -> Option<(&str, u64)> {
    let (boot, seq) = c.rsplit_once(':')?;
    Some((boot, seq.parse().ok()?))
}

impl Position {
    fn at(cursor: Option<&str>) -> Self {
        let mut p = Position::default();
        if let Some((b, s)) = cursor.and_then(split_cursor) {
            p.cursor = cursor.map(str::to_owned);
            p.boot = Some(b.to_owned());
            p.last_seq = s;
        }
        p
    }

    /// Whether `e` was handed over already (a replay's repeat).
    fn seen(&self, e: &MediaEvent) -> bool {
        let Some((boot, seq)) = e.event_id.as_deref().and_then(split_cursor) else {
            return false;
        };
        Some(boot) == self.boot.as_deref() && seq <= self.last_seq
    }

    /// `e` handed over.
    fn advance(&mut self, e: &MediaEvent) {
        if let Some(id) = &e.event_id
            && let Some((b, s)) = split_cursor(id)
        {
            self.boot = Some(b.to_owned());
            self.last_seq = s;
            self.cursor = Some(id.clone());
        }
    }

    /// Where a subscription's reply says it began, when nothing was handed
    /// over yet (or the relay could not resume: it starts again there).
    fn start_at(&mut self, reply: &Value) {
        let resumed = reply.get("resumed").and_then(Value::as_bool);
        if (self.cursor.is_none() || resumed == Some(false))
            && let Some(c) = reply.get("cursor").and_then(Value::as_str)
        {
            *self = Position::at(Some(c));
        }
    }
}

/// Subscribe to `filter` on a connection of its own (from `filter`'s
/// `cursor`, if it has one).
pub(crate) async fn start(
    config: Arc<Config>,
    filter: EventFilter,
) -> Result<MediaEventStream, MediaError> {
    let mut position = Position::at(filter.cursor.as_deref());
    // The first subscription is made before returning: the stream is live.
    let (reader, writer, reply, early) =
        subscribe(&config, &filter, position.cursor.as_deref()).await?;
    position.start_at(&reply);
    let (tx, rx) = mpsc::channel(config.event_queue.max(1));
    let task = tokio::spawn(run(config, filter, tx, position, (reader, writer, early)));
    Ok(MediaEventStream { rx, task })
}

/// Why a connection was let go.
enum Ended {
    /// The consumer is gone: the stream ends.
    Consumer,
    /// Subscribe again from the position (`wait`: with backoff first).
    Again { wait: bool },
}

/// Read one connection's events (after `early`, those that came before
/// its subscription's reply) into `tx` until it must be let go.
async fn pump(
    reader: crate::conn::Reader,
    early: Vec<Value>,
    tx: &mpsc::Sender<MediaEvent>,
    position: &mut Position,
) -> Ended {
    use mpsc::error::TrySendError;
    let (frames_tx, mut frames) = mpsc::channel::<Value>(64);
    let reading = tokio::spawn(crate::conn::read_loop(reader, frames_tx));
    let mut early = early.into_iter();
    let ended = loop {
        let next = match early.next() {
            Some(v) => Some(v),
            None => frames.recv().await,
        };
        let Some(v) = next else {
            break Ended::Again { wait: true };
        };
        let Some(e) = MediaEvent::from_wire(&v) else {
            continue;
        };
        if e.kind == EventKind::Gap {
            // The relay still has them: back from the position.
            if e.data.get("reason").and_then(Value::as_str) == Some("overflow") {
                break Ended::Again { wait: false };
            }
            // It does not: the consumer reconciles.
            if tx.send(e).await.is_err() {
                break Ended::Consumer;
            }
            continue;
        }
        if position.seen(&e) {
            continue;
        }
        match tx.try_send(e.clone()) {
            Ok(()) => position.advance(&e),
            // Behind: stop reading; back from the position once the
            // consumer has room.
            Err(TrySendError::Full(_)) => {
                reading.abort();
                while tx.capacity() == 0 {
                    if tx.is_closed() {
                        return Ended::Consumer;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                return Ended::Again { wait: false };
            }
            Err(TrySendError::Closed(_)) => break Ended::Consumer,
        }
    };
    reading.abort();
    ended
}

async fn run(
    config: Arc<Config>,
    filter: EventFilter,
    tx: mpsc::Sender<MediaEvent>,
    mut position: Position,
    (mut reader, mut writer, mut early): (crate::conn::Reader, crate::conn::Writer, Vec<Value>),
) {
    let mut backoff = config.backoff_min;
    loop {
        let wait = match pump(reader, std::mem::take(&mut early), &tx, &mut position).await {
            Ended::Consumer => return,
            Ended::Again { wait } => wait,
        };
        drop(writer);
        // Again from the position, with backoff when the connection broke.
        if wait {
            tokio::time::sleep(backoff).await;
        }
        loop {
            if tx.is_closed() {
                return;
            }
            match subscribe(&config, &filter, position.cursor.as_deref()).await {
                Ok((r, w, reply, e)) => {
                    reader = r;
                    writer = w;
                    early = e;
                    backoff = config.backoff_min;
                    // Not resumed: the relay's gap says why, and the
                    // stream goes on from where it now is.
                    position.start_at(&reply);
                    break;
                }
                Err(e) => {
                    log::debug!("rtpflux-client: events: {e}; again in {backoff:?}");
                    tokio::time::sleep(backoff).await;
                    backoff = next_backoff(backoff, &config);
                }
            }
        }
    }
}
