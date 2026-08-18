//! The file device: JSON Lines, one record per line.
//!
//! One line is one record, and the line **is** the hashed payload — so a chain can
//! be verified from the file alone, with `sha256sum` on a single line if it comes to
//! that. Nothing wraps the record and nothing is appended to it, because anything
//! wrapped around the payload would have to be stripped again byte-exactly before
//! hashing, and that is a step that can be got wrong.
//!
//! Each write is flushed and synced before returning. Fail-closed means the caller
//! is entitled to treat a success as "this is on disk"; without the sync it would
//! mean "this is in a buffer that a power failure will discard", and the request
//! would have been allowed on a promise.
//!
//! Rotation is by size. When the current file reaches the limit it is renamed with a
//! timestamp suffix and a new one is started. Compression, retention, and shipping
//! are left to whatever already does that on the host — this device's job is to not
//! lose a line.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::chain::EncodedRecord;
use crate::device::AuditDevice;
use crate::time::rfc3339_millis;

/// An audit device that appends JSON Lines to a file.
pub struct FileDevice {
    name: String,
    path: PathBuf,
    file: File,
    written: u64,
    rotate_at: Option<u64>,
}

impl FileDevice {
    /// Open or create an audit file.
    ///
    /// `rotate_at` is the size in bytes at which the file is rotated, or `None` to
    /// let it grow. Rotation happens *before* a write that would exceed the limit, so
    /// a record is never split across two files.
    ///
    /// # Errors
    ///
    /// Returns any I/O error from opening the file or reading its current size.
    pub fn open(path: impl AsRef<Path>, rotate_at: Option<u64>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let written = file.metadata()?.len();

        Ok(Self {
            name: format!("file:{}", path.display()),
            path,
            file,
            written,
            rotate_at,
        })
    }

    /// The path being written to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Current size of the open file, in bytes.
    pub fn size(&self) -> u64 {
        self.written
    }

    fn rotate(&mut self, now_millis: i64) -> std::io::Result<()> {
        // A timestamp rather than a rolling `.1`, `.2`: renaming a chain of files
        // is more moving parts, and a name that says when the file was closed is
        // more useful when someone is looking for a particular day.
        let stamp = rfc3339_millis(now_millis).replace(':', "-");
        let mut rotated = self.path.clone().into_os_string();
        rotated.push(format!(".{stamp}"));

        std::fs::rename(&self.path, &rotated)?;
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.written = 0;
        Ok(())
    }
}

impl AuditDevice for FileDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn write(&mut self, record: &EncodedRecord) -> Result<(), String> {
        let line_len = record.payload.len() as u64 + 1;

        if let Some(limit) = self.rotate_at
            && self.written > 0
            && self.written + line_len > limit
        {
            self.rotate(record.ts_millis)
                .map_err(|error| format!("could not rotate {}: {error}", self.path.display()))?;
        }

        self.file
            .write_all(record.payload.as_bytes())
            .and_then(|()| self.file.write_all(b"\n"))
            .and_then(|()| self.file.flush())
            // Durability, not tidiness: a success here is what allows the request to
            // proceed, so it has to mean the bytes are on the disk.
            .and_then(|()| self.file.sync_data())
            .map_err(|error| format!("could not write to {}: {error}", self.path.display()))?;

        self.written += line_len;
        Ok(())
    }

    fn reopen(&mut self) -> Result<(), String> {
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| format!("could not reopen {}: {error}", self.path.display()))?;
        self.written = self
            .file
            .metadata()
            .map(|metadata| metadata.len())
            .map_err(|error| format!("could not stat {}: {error}", self.path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::FileDevice;
    use crate::chain::{Chain, hash_payload};
    use crate::device::{AuditDevice, AuditSink};
    use crate::entry::{Action, Entry};
    use std::io::Read;

    fn read_lines(path: &std::path::Path) -> Vec<String> {
        let mut text = String::new();
        std::fs::File::open(path)
            .expect("open")
            .read_to_string(&mut text)
            .expect("read");
        text.lines().map(str::to_owned).collect()
    }

    #[test]
    fn a_line_is_exactly_the_hashed_payload() {
        // The property that lets a chain be checked from the file alone.
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("audit.jsonl");

        let mut sink = AuditSink::new(
            vec![Box::new(FileDevice::open(&path, None).expect("open"))],
            Chain::new(),
        )
        .expect("sink");

        let written = sink
            .record(&Entry::allowed(Action::Read), 1)
            .expect("write");

        let lines = read_lines(&path);
        assert_eq!(lines.len(), 1);
        assert_eq!(hash_payload(lines[0].as_bytes()), written.hash);
    }

    #[test]
    fn appends_to_an_existing_file_without_losing_what_was_there() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("audit.jsonl");

        {
            let mut device = FileDevice::open(&path, None).expect("open");
            let chain = Chain::new();
            let record = chain
                .encode(&Entry::allowed(Action::Init), 1)
                .expect("encode");
            device.write(&record).expect("write");
        }

        {
            let mut device = FileDevice::open(&path, None).expect("reopen");
            assert!(device.size() > 0, "size must reflect the existing file");
            let chain = Chain::resume(1, [7_u8; 32]);
            let record = chain
                .encode(&Entry::allowed(Action::Read), 2)
                .expect("encode");
            device.write(&record).expect("write");
        }

        assert_eq!(read_lines(&path).len(), 2);
    }

    #[test]
    fn rotates_when_the_limit_is_reached_and_keeps_every_line() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("audit.jsonl");

        // Small enough that the second record triggers a rotation.
        let mut sink = AuditSink::new(
            vec![Box::new(FileDevice::open(&path, Some(200)).expect("open"))],
            Chain::new(),
        )
        .expect("sink");

        let mut hashes = Vec::new();
        for tick in 1..=6_i64 {
            hashes.push(
                sink.record(&Entry::allowed(Action::Read), tick)
                    .expect("write")
                    .hash,
            );
        }

        let rotated: Vec<_> = std::fs::read_dir(directory.path())
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name() != "audit.jsonl")
            .collect();
        assert!(!rotated.is_empty(), "the file must have been rotated");

        // Every record is still on disk exactly once, across all the files.
        let mut lines = read_lines(&path);
        for entry in rotated {
            lines.extend(read_lines(&entry.path()));
        }
        assert_eq!(lines.len(), 6, "no line may be lost to rotation");

        for hash in hashes {
            assert!(
                lines
                    .iter()
                    .any(|line| hash_payload(line.as_bytes()) == hash),
                "a record went missing"
            );
        }
    }

    #[test]
    fn reopening_starts_writing_to_a_new_file_after_it_is_moved_away() {
        // What SIGHUP is for: an external rotation moved the file, and the next write
        // must land in a fresh one rather than into the moved inode.
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("audit.jsonl");
        let moved = directory.path().join("audit.jsonl.moved");

        let mut device = FileDevice::open(&path, None).expect("open");
        let chain = Chain::new();
        let first = chain
            .encode(&Entry::allowed(Action::Init), 1)
            .expect("encode");
        device.write(&first).expect("write");

        std::fs::rename(&path, &moved).expect("rename");
        device.reopen().expect("reopen");

        let second = chain
            .encode(&Entry::allowed(Action::Read), 2)
            .expect("encode");
        device.write(&second).expect("write");

        assert_eq!(read_lines(&moved).len(), 1);
        assert_eq!(read_lines(&path).len(), 1);
    }

    #[test]
    fn a_write_to_an_impossible_path_is_an_error_not_a_panic() {
        // The failure the sink has to be able to survive, so it must be an error
        // rather than an unwrap somewhere in this device.
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory
            .path()
            .join("no-such-directory")
            .join("audit.jsonl");
        assert!(FileDevice::open(&path, None).is_err());
    }
}
