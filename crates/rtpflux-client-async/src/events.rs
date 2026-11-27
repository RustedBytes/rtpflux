//! Event subscriptions, each on a connection of its own (never sharing the
//! request connections, so a burst of events never delays a reply).
//!
//! The connection's task reads the events and hands them to the consumer
//! through a bounded queue ([`Config::event_queue`]): when the consumer is
//! behind, events are dropped and counted, and the next one it gets is a
//! gap (`missed`). When the connection breaks, the task reconnects with
//! backoff and subscribes again, then reports a gap with `reason:
//! "reconnected"`: events of the meantime are lost, and the consumer
//! reconciles (`endpoint.list`).

use crate::config::{Config, Transport};
use crate::conn::{next_backoff, open, outcome, read_frame, write_frame};
use crate::error::MediaError;
use crate::types::{EventFilter, MediaEvent};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// A subscription's events, in order. Dropping it ends the subscription
/// (and its connection).
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

/// A connection subscribed to `filter`: its reader, writer kept open.
async fn subscribe(
    config: &Config,
    filter: &EventFilter,
) -> Result<(crate::conn::Reader, crate::conn::Writer), MediaError> {
    let (mut r, mut w) = open(config).await?;
    let mut req = serde_json::to_value(filter).map_err(|e| MediaError::Protocol(e.to_string()))?;
    if let Some(o) = req.as_object_mut() {
        o.insert("v".into(), json!(1));
        o.insert("op".into(), json!("events.subscribe"));
        o.insert("operation_id".into(), json!("subscribe"));
        if let (Some(t), Transport::Unix(_)) = (&config.tenant, &config.transport) {
            o.insert("tenant".into(), json!(t));
        }
    }
    let wait = async {
        write_frame(&mut w, req.to_string().as_bytes())
            .await
            .map_err(|_| MediaError::Disconnected { sent: true })?;
        loop {
            let v = read_frame(&mut r)
                .await
                .map_err(|_| MediaError::Disconnected { sent: true })?;
            if v.get("operation_id").and_then(Value::as_str) == Some("subscribe") {
                return outcome(&v).map(|_| ());
            }
        }
    };
    tokio::time::timeout(config.connect_timeout, wait)
        .await
        .map_err(|_| MediaError::Timeout { sent: true })??;
    Ok((r, w))
}

/// Hands events to the consumer, counting what it could not take.
struct Delivery {
    tx: mpsc::Sender<MediaEvent>,
    missed: u64,
}

impl Delivery {
    /// Report what was missed, if the consumer has room now: `false` once
    /// it is gone.
    fn flush_gap(&mut self) -> bool {
        use mpsc::error::TrySendError;
        if self.missed == 0 {
            return !self.tx.is_closed();
        }
        match self.tx.try_send(MediaEvent::gap("overflow", self.missed)) {
            Ok(()) => {
                self.missed = 0;
                true
            }
            Err(TrySendError::Full(_)) => true,
            Err(TrySendError::Closed(_)) => false,
        }
    }

    /// Deliver `e` (after a gap for what was missed): `false` once the
    /// consumer is gone.
    fn deliver(&mut self, e: MediaEvent) -> bool {
        use mpsc::error::TrySendError;
        if self.missed > 0 {
            match self.tx.try_send(MediaEvent::gap("overflow", self.missed)) {
                Ok(()) => self.missed = 0,
                Err(TrySendError::Full(_)) => {
                    self.missed += 1;
                    return true;
                }
                Err(TrySendError::Closed(_)) => return false,
            }
        }
        match self.tx.try_send(e) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                self.missed += 1;
                true
            }
            Err(TrySendError::Closed(_)) => false,
        }
    }
}

/// Subscribe to `filter` on a connection of its own.
pub(crate) async fn start(
    config: Arc<Config>,
    filter: EventFilter,
) -> Result<MediaEventStream, MediaError> {
    // The first subscription is made before returning: the stream is live.
    let (reader, writer) = subscribe(&config, &filter).await?;
    let (tx, rx) = mpsc::channel(config.event_queue.max(1));
    let task = tokio::spawn(run(
        config,
        filter,
        Delivery { tx, missed: 0 },
        reader,
        writer,
    ));
    Ok(MediaEventStream { rx, task })
}

async fn run(
    config: Arc<Config>,
    filter: EventFilter,
    mut out: Delivery,
    mut reader: crate::conn::Reader,
    mut writer: crate::conn::Writer,
) {
    let mut backoff = config.backoff_min;
    loop {
        // Events until the connection breaks (the writer is kept: dropping
        // it would close the connection). Frames are read by a task of
        // their own (reading is not cancellation-safe), so that a gap is
        // reported as soon as the consumer has room, even when no event
        // follows.
        let (frames_tx, mut frames) = mpsc::channel(64);
        let reading = tokio::spawn(crate::conn::read_loop(reader, frames_tx));
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(50));
        loop {
            tokio::select! {
                v = frames.recv() => {
                    let Some(v) = v else { break };
                    if let Some(e) = MediaEvent::from_wire(&v)
                        && !out.deliver(e)
                    {
                        reading.abort();
                        return;
                    }
                }
                _ = tick.tick() => {
                    if !out.flush_gap() {
                        reading.abort();
                        return;
                    }
                }
            }
        }
        reading.abort();
        drop(writer);
        // Again, with backoff, until it works or the consumer is gone.
        loop {
            if out.tx.is_closed() {
                return;
            }
            tokio::time::sleep(backoff).await;
            match subscribe(&config, &filter).await {
                Ok((r, w)) => {
                    reader = r;
                    writer = w;
                    backoff = config.backoff_min;
                    break;
                }
                Err(e) => {
                    log::debug!("rtpflux-client: events: {e}; again in {backoff:?}");
                    backoff = next_backoff(backoff, &config);
                }
            }
        }
        let missed = std::mem::take(&mut out.missed);
        if !out.deliver(MediaEvent::gap("reconnected", missed)) {
            return;
        }
    }
}
