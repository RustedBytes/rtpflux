//! `ng` messages that arrive on streams (TCP, HTTP, WebSocket): the
//! connection threads ([`crate::ngstream`]) hand each message to the
//! control thread and wait for its reply, which is made as for a datagram
//! (the same reply cache, by sender and cookie).

#[allow(clippy::wildcard_imports)]
use super::*;
use nix::sys::eventfd::{EfdFlags, EventFd};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};

/// Messages waiting for the control thread, at most.
const QUEUE: usize = 256;
/// How long a connection waits for its reply.
const WAIT: Duration = Duration::from_secs(5);

/// One message from a stream, and where its reply goes (`None`: no reply,
/// the message was not `ng`).
#[derive(Debug)]
pub struct NgRequest {
    message: Vec<u8>,
    from: Option<SocketAddr>,
    reply: SyncSender<Option<Vec<u8>>>,
}

/// A connection thread's link to the control thread.
#[derive(Debug, Clone)]
pub struct NgLink {
    tx: SyncSender<NgRequest>,
    wake: Arc<EventFd>,
}

impl NgLink {
    /// The reply to `message` (`cookie SP bencode`) from `from`; `None`
    /// when it is not an `ng` message, or the control thread is busy or
    /// gone.
    #[must_use]
    pub fn ask(&self, message: Vec<u8>, from: Option<SocketAddr>) -> Option<Vec<u8>> {
        let (reply, answer) = sync_channel(1);
        match self.tx.try_send(NgRequest {
            message,
            from,
            reply,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => return None,
        }
        let _ = self.wake.write(1);
        answer.recv_timeout(WAIT).ok().flatten()
    }
}

/// The control thread's end.
#[derive(Debug)]
pub(super) struct NgInbox {
    rx: Receiver<NgRequest>,
    pub(super) wake: Arc<EventFd>,
}

impl Control {
    /// The link of the stream listeners to this control thread (made once;
    /// later calls replace it).
    ///
    /// # Errors
    ///
    /// When the eventfd cannot be created.
    pub fn ng_link(&mut self) -> Result<NgLink, nix::Error> {
        let (tx, rx) = sync_channel(QUEUE);
        let wake = Arc::new(EventFd::from_flags(
            EfdFlags::EFD_NONBLOCK | EfdFlags::EFD_CLOEXEC,
        )?);
        self.streams = Some(NgInbox {
            rx,
            wake: Arc::clone(&wake),
        });
        Ok(NgLink { tx, wake })
    }

    /// Answer the messages waiting.
    pub(super) fn answer_streams(&mut self) {
        let Some(inbox) = &self.streams else {
            return;
        };
        let _ = inbox.wake.read();
        let waiting: Vec<NgRequest> = inbox.rx.try_iter().collect();
        for r in waiting {
            let reply = if r.message.len() > self.max_message {
                None
            } else {
                self.handle_from(&r.message, r.from).map(<[u8]>::to_vec)
            };
            let _ = r.reply.send(reply);
        }
    }
}
