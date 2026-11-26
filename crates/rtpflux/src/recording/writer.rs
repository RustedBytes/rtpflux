//! Writing recordings to disk off the media path: workers hand each full
//! chunk of complete pcap records to one writer thread and go on; a slow
//! or full disk delays the writer, never a worker. Chunks are written in
//! the order they came; a recording's conversion job goes through the
//! writer too, so it starts after the recording's last write.

use super::convert::Job;
use std::fs::File;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;

/// Chunks waiting for the writer, at most (64 KiB each).
const QUEUE: usize = 256;

/// A recording's file, as its writer sees it.
#[derive(Debug)]
pub struct RecFile {
    pub(super) file: File,
    pub(super) path: PathBuf,
    /// The file's length after the last complete write: a failed write is
    /// cut back to it, so later records stay readable.
    pub(super) written: AtomicU64,
}

impl RecFile {
    /// Append `data` (complete records); on failure, cut the file back.
    pub(super) fn append(&self, data: &[u8]) {
        let mut f = &self.file;
        match f.write_all(data) {
            Ok(()) => {
                self.written.fetch_add(data.len() as u64, Ordering::Relaxed);
            }
            Err(e) => {
                log::warn!("recording: {}: {e}", self.path.display());
                if let Err(e) = self.file.set_len(self.written.load(Ordering::Relaxed)) {
                    log::warn!("recording: {}: {e}", self.path.display());
                }
            }
        }
    }
}

/// What the writer does.
#[derive(Debug)]
pub enum WriteOp {
    /// Append these records to this file.
    Append(Arc<RecFile>, Vec<u8>),
    /// A recording ended: after its writes, hand it to the converter.
    Done(Box<Job>, Sender<Job>),
}

/// The writer's queue.
#[derive(Debug, Clone)]
pub struct Writer(SyncSender<WriteOp>);

impl Writer {
    /// Queue a chunk; dropped (and logged) when the writer is that far
    /// behind: the recording loses these packets, the call does not wait.
    pub(super) fn append(&self, file: &Arc<RecFile>, data: Vec<u8>) {
        if let Err(TrySendError::Full(_)) = self.0.try_send(WriteOp::Append(Arc::clone(file), data))
        {
            log::warn!(
                "recording: {}: the disk is behind; packets dropped",
                file.path.display()
            );
        }
    }

    /// Queue a finished recording's conversion (waits for room: once per
    /// recording, and it must not be lost).
    pub(super) fn done(&self, job: Job, jobs: Sender<Job>) {
        let _ = self.0.send(WriteOp::Done(Box::new(job), jobs));
    }
}

fn run(ops: &Receiver<WriteOp>) {
    for op in ops {
        match op {
            WriteOp::Append(file, data) => file.append(&data),
            WriteOp::Done(job, jobs) => {
                let _ = jobs.send(*job);
            }
        }
    }
}

/// Start the writer thread; it ends when every [`Writer`] is gone.
///
/// # Errors
///
/// When the thread cannot be started.
pub fn spawn() -> std::io::Result<(Writer, JoinHandle<()>)> {
    let (tx, rx) = sync_channel(QUEUE);
    let thread = std::thread::Builder::new()
        .name("rtpflux-rec-writer".to_owned())
        .spawn(move || run(&rx))?;
    Ok((Writer(tx), thread))
}
