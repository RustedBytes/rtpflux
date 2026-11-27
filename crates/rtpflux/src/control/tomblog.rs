//! Tombstones of destroyed endpoints, kept in an append-only file next to
//! the state file (`<state>.tombs.jsonl`), one JSON line each.
//!
//! They used to be part of the state file, which is rewritten whole: with
//! a durable ledger every keyed operation rewrote and synced it, so its
//! cost grew with every endpoint ever destroyed (up to 65 536 tombstones).
//! Now a destruction appends one line, synced with the operation in
//! durable mode. The file is rewritten compact at start-up and whenever it
//! holds more than twice the tombstones kept. A torn last line (a crash in
//! the middle of a write) is skipped.

use crate::state::SavedTomb;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// Lines below which the file is never compacted.
const MIN_COMPACT: usize = 1024;

/// The tombstones' file.
#[derive(Debug)]
pub(super) struct TombLog {
    path: PathBuf,
    file: File,
    lines: usize,
    unsynced: bool,
}

/// The tombstones' file next to state file `state`.
pub(super) fn path_for(state: &Path) -> PathBuf {
    state.with_extension("tombs.jsonl")
}

impl TombLog {
    /// Open (or create) the file at `path`, and the tombstones it holds,
    /// oldest first (a later line for an id replaces an earlier one).
    pub(super) fn open(path: &Path) -> std::io::Result<(Self, Vec<SavedTomb>)> {
        let mut tombs: Vec<SavedTomb> = Vec::new();
        let mut lines = 0;
        match File::open(path) {
            Ok(f) => {
                for line in BufReader::new(f).lines() {
                    let line = line?;
                    lines += 1;
                    // A torn last line, or anything not a tombstone: left out.
                    if let Ok(t) = serde_json::from_str::<SavedTomb>(&line) {
                        tombs.retain(|o| o.id != t.id);
                        tombs.push(t);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok((
            TombLog {
                path: path.to_owned(),
                file,
                lines,
                unsynced: false,
            },
            tombs,
        ))
    }

    /// One more tombstone.
    pub(super) fn append(&mut self, t: &SavedTomb) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(t).map_err(std::io::Error::other)?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.lines += 1;
        self.unsynced = true;
        Ok(())
    }

    /// What was appended, on the disk.
    pub(super) fn sync(&mut self) -> std::io::Result<()> {
        if self.unsynced {
            self.file.sync_data()?;
            self.unsynced = false;
        }
        Ok(())
    }

    /// Whether the file holds more than twice the `kept` tombstones.
    pub(super) fn wants_compacting(&self, kept: usize) -> bool {
        self.lines > MIN_COMPACT.max(2 * kept)
    }

    /// The file rewritten with `all` only (written aside, synced, renamed).
    pub(super) fn rewrite(&mut self, all: &[SavedTomb]) -> std::io::Result<()> {
        let tmp = self.path.with_extension("tombs.tmp");
        {
            let mut f = File::create(&tmp)?;
            for t in all {
                let mut line = serde_json::to_vec(t).map_err(std::io::Error::other)?;
                line.push(b'\n');
                f.write_all(&line)?;
            }
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            File::open(dir)?.sync_all()?;
        }
        self.file = OpenOptions::new().append(true).open(&self.path)?;
        self.lines = all.len();
        self.unsynced = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tomb(id: &str, generation: u64) -> SavedTomb {
        SavedTomb {
            id: id.into(),
            tenant: "t".into(),
            generation,
            reason: "request".into(),
            at_unix_ms: 1,
            external_id: None,
        }
    }

    #[test]
    fn appended_compacted_and_torn() {
        let dir = std::env::temp_dir().join(format!("rtpflux-tombs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = path_for(&dir.join("state.json"));
        let (mut log, none) = TombLog::open(&path).unwrap();
        assert_eq!(none.len(), 0);
        log.append(&tomb("a", 1)).unwrap();
        log.append(&tomb("b", 2)).unwrap();
        log.append(&tomb("a", 3)).unwrap();
        log.sync().unwrap();
        // A crash in the middle of a line.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"id\":\"c\",\"ten")
            .unwrap();
        let (mut log, back) = TombLog::open(&path).unwrap();
        let ids: Vec<(&str, u64)> = back.iter().map(|t| (t.id.as_str(), t.generation)).collect();
        assert_eq!(
            ids,
            [("b", 2), ("a", 3)],
            "the later line wins; the torn one is left out"
        );
        log.rewrite(&back).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
        log.append(&tomb("d", 4)).unwrap();
        assert_eq!(TombLog::open(&path).unwrap().1.len(), 3);
        assert!(!log.wants_compacting(3));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
