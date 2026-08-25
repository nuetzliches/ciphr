//! The file device: JSON Lines, one record per line.
//!
//! One line is one record, and the line **is** the hashed payload — so a chain can
//! be verified from the file alone, with `sha256sum` on a single line if it comes to
//! that. Nothing wraps the record and nothing is appended to it, because anything
//! wrapped around the payload would have to be stripped again byte-exactly before
//! hashing, and that is a step that can be got wrong.
//!
//! A write that fails part-way truncates back to where the file ended before it. A
//! partial line would otherwise be concatenated with the next record and break the
//! chain at that point for good -- indistinguishable, afterwards, from an edit.
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
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::chain::EncodedRecord;
use crate::device::AuditDevice;
use crate::time::rfc3339_millis;

/// How many archives may share one timestamp-and-sequence suffix before rotation
/// refuses.
///
/// Reachable only if something outside this process is creating files with these
/// names, because the sequence is unique per record. A bound rather than an unbounded
/// loop, so that case ends in an error naming the path instead of spinning.
const ATTEMPTS_PER_STAMP: u32 = 100;

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

    /// Move the current file aside and start a new one.
    ///
    /// The name carries the timestamp **and** the sequence of the last record in the file
    /// being closed, and it never replaces a file that is already there. Finding F6 of
    /// `docs/assurance/reviews/review-2026-08-21-current-tree.md`: the name was the timestamp alone, so two
    /// rotations in the same millisecond targeted one path — which `fs::rename` answers by
    /// replacing the earlier archive on Unix and by failing on Windows. One loses a
    /// segment of the trail; the other takes the device down. A small rotation threshold,
    /// a burst of records, or a clock that steps backwards is all it takes to get there.
    ///
    /// That matters more here than a name collision usually would. `ciphr audit verify`
    /// walks a chain and `--anchor` compares it against a head recorded outside the store,
    /// so a replaced archive is a gap that verification finds *later* — and auditing is
    /// fail-closed per device, so requests keep succeeding while one device has quietly
    /// stopped being complete.
    fn rotate(&mut self, now_millis: i64, next_seq: u64) -> std::io::Result<()> {
        // A timestamp rather than a rolling `.1`, `.2`: renaming a chain of files
        // is more moving parts, and a name that says when the file was closed is
        // more useful when someone is looking for a particular day.
        let stamp = rfc3339_millis(now_millis).replace(':', "-");

        // The sequence of the last record that is *in* the file being closed. Rotation
        // happens before the record that would overflow the limit, so that is one below
        // the record about to be written. `saturating_sub` for a case that cannot occur --
        // rotation requires a non-empty file, so `next_seq` is at least two -- rather than
        // an underflow that would name an archive after `u64::MAX`.
        let closing = next_seq.saturating_sub(1);
        let suffix = format!(".{stamp}-{closing}");

        // Never replace an archive. `fs::rename` overwrites silently on Unix and refuses
        // on Windows, so "that name is taken" is a case this has to answer itself instead
        // of inheriting one of two bad answers from the platform.
        //
        // Not the racy shape a check-then-act on a shared file would be: one process
        // writes this file at a time, and the store lock is what guarantees it. Anything
        // that could take the name between these two lines is outside the deployment, and
        // for that the loop is what protects the archive rather than the check.
        let mut rotated = self.archive_path(&suffix);
        for attempt in 1..=ATTEMPTS_PER_STAMP {
            if !rotated.exists() {
                break;
            }
            rotated = self.archive_path(&format!("{suffix}.{attempt}"));
        }
        if rotated.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "{ATTEMPTS_PER_STAMP} archives already exist for {}{suffix}",
                    self.path.display()
                ),
            ));
        }

        std::fs::rename(&self.path, &rotated)?;
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.written = 0;
        Ok(())
    }

    /// The live path with one suffix appended.
    ///
    /// Built through `OsString` rather than `with_extension`, which would replace
    /// `.jsonl` instead of adding to it.
    fn archive_path(&self, suffix: &str) -> PathBuf {
        let mut name = self.path.clone().into_os_string();
        name.push(suffix);
        PathBuf::from(name)
    }
}

impl AuditDevice for FileDevice {
    fn name(&self) -> &str {
        &self.name
    }

    /// The sequence number on the last line, read from the end of the file.
    ///
    /// Backwards in blocks rather than forwards through the file: an audit file is the
    /// one file in this deployment that is expected to be large, and reading all of it
    /// to learn one number at startup would make a slow start out of a big trail.
    ///
    /// A trailing newline is normal and skipped. A file whose last line is *not* valid
    /// JSON, or carries no `seq`, is an error rather than `None` — "the last line is
    /// unreadable" and "there are no lines" are different facts, and the sink treats
    /// them differently.
    fn head_seq(&self) -> Result<Option<u64>, String> {
        // 8 KiB is comfortably more than one record and small enough that the ordinary
        // case is one read. The loop below exists for the record that does not fit.
        const BLOCK: u64 = 8 * 1024;

        let mut file = File::open(&self.path).map_err(|error| {
            format!(
                "cannot open {} to read its head: {error}",
                self.path.display()
            )
        })?;
        let size = file
            .metadata()
            .map_err(|error| format!("cannot measure {}: {error}", self.path.display()))?
            .len();
        if size == 0 {
            return Ok(None);
        }

        let mut tail: Vec<u8> = Vec::new();
        let mut read_from = size;

        let line = loop {
            let take = BLOCK.min(read_from);
            read_from -= take;
            file.seek(SeekFrom::Start(read_from))
                .map_err(|error| format!("cannot seek in {}: {error}", self.path.display()))?;
            let mut block = vec![0u8; usize::try_from(take).unwrap_or(usize::MAX)];
            file.read_exact(&mut block)
                .map_err(|error| format!("cannot read {}: {error}", self.path.display()))?;
            block.extend_from_slice(&tail);
            tail = block;

            // Ignore the newline the last record ended with, then look for the one
            // before it: what lies between them is the last line.
            let end = tail
                .iter()
                .rposition(|byte| *byte != b'\n')
                .map_or(0, |at| at + 1);
            if let Some(start) = tail[..end].iter().rposition(|byte| *byte == b'\n') {
                break tail[start + 1..end].to_vec();
            }
            if read_from == 0 {
                break tail[..end].to_vec();
            }
        };

        if line.is_empty() {
            return Ok(None);
        }

        let text = String::from_utf8(line)
            .map_err(|_| format!("the last line of {} is not UTF-8", self.path.display()))?;
        let parsed: serde_json::Value = serde_json::from_str(&text).map_err(|error| {
            format!(
                "the last line of {} is not a record: {error}",
                self.path.display()
            )
        })?;
        parsed
            .get("seq")
            .and_then(serde_json::Value::as_u64)
            .map(Some)
            .ok_or_else(|| {
                format!(
                    "the last line of {} carries no sequence number",
                    self.path.display()
                )
            })
    }

    fn write(&mut self, record: &EncodedRecord) -> Result<(), String> {
        // One buffer, written once. `write_all` loops internally, so building the
        // line in two calls doubles the number of places a partial write can happen.
        let mut line = String::with_capacity(record.payload.len() + 1);
        line.push_str(&record.payload);
        line.push('\n');
        let line_len = line.len() as u64;

        if let Some(limit) = self.rotate_at
            && self.written > 0
            && self.written + line_len > limit
        {
            self.rotate(record.ts_millis, record.seq)
                .map_err(|error| format!("could not rotate {}: {error}", self.path.display()))?;
        }

        // Where the file ends now. `write_all` is not atomic: it loops over `write`,
        // so a failure part-way through -- `ENOSPC` being the one this device is
        // designed around -- leaves bytes on disk and reports the error afterwards.
        // Without the truncation below, the next successful write appends to that
        // fragment and produces one line that is half of one record followed by all of
        // another. The chain then fails to verify there, permanently, and looks exactly
        // like tampering. A full disk has to stay an outage, not a corrupted trail.
        let resume_at = self.written;

        let outcome = self
            .file
            .write_all(line.as_bytes())
            .and_then(|()| self.file.flush())
            // Durability, not tidiness: a success here is what allows the request to
            // proceed, so it has to mean the bytes are on the disk.
            .and_then(|()| self.file.sync_data());

        if let Err(error) = outcome {
            // Best effort. If this fails too there is nothing further to try, and the
            // caller is told the write failed either way -- which is what fail-closed
            // needs. Reporting the truncation failure instead would replace the useful
            // error with a less useful one.
            let _ = self.file.set_len(resume_at);
            let _ = self.file.sync_data();
            return Err(format!(
                "could not write to {}: {error}",
                self.path.display()
            ));
        }

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

    /// The head is read from the end of the file, and it is the *last* record.
    ///
    /// What the sink compares against the chain at startup (finding F6). A wrong answer
    /// here either stops a healthy device or lets a device with a gap keep writing, so
    /// this is asserted at three sizes rather than one.
    #[test]
    fn the_head_is_the_sequence_on_the_last_line() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("audit.jsonl");

        let device = FileDevice::open(&path, None).expect("open");
        assert_eq!(
            device.head_seq().expect("head"),
            None,
            "a file with nothing in it holds nothing -- which is not the same as an error"
        );
        drop(device);

        let mut sink = AuditSink::new(
            vec![Box::new(FileDevice::open(&path, None).expect("open"))],
            Chain::new(),
        )
        .expect("sink");
        for at in 1..=3 {
            sink.record(&Entry::allowed(Action::Read), at)
                .expect("record");
        }
        drop(sink);

        let device = FileDevice::open(&path, None).expect("reopen");
        assert_eq!(device.head_seq().expect("head"), Some(3));
    }

    /// A record larger than one read block is still found.
    ///
    /// The loop that reads backwards exists for this case and for no other, so it is the
    /// case worth writing down: without it, a single large record would make the device
    /// report no head at all and the sink would treat a device holding records as empty.
    #[test]
    fn the_head_is_found_when_the_last_record_spans_several_blocks() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("audit.jsonl");

        let mut sink = AuditSink::new(
            vec![Box::new(FileDevice::open(&path, None).expect("open"))],
            Chain::new(),
        )
        .expect("sink");
        sink.record(&Entry::allowed(Action::Read), 1)
            .expect("small");

        // Comfortably past the 8 KiB block the reader uses.
        let long = "p/".repeat(12_000);
        let entry = Entry::allowed(Action::Read).with_detail(&long);
        sink.record(&entry, 2).expect("large");
        drop(sink);

        let device = FileDevice::open(&path, None).expect("reopen");
        assert_eq!(device.head_seq().expect("head"), Some(2));
    }

    /// A last line that is not a record is an error, not an absence.
    ///
    /// The two answers mean opposite things to the sink: "holds nothing" lets a device
    /// start a new segment, "cannot say" leaves it alone. A file whose end is unreadable
    /// must not be mistaken for a file that was rotated away.
    #[test]
    fn an_unreadable_last_line_is_an_error_rather_than_an_empty_device() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("audit.jsonl");
        std::fs::write(
            &path,
            b"{\"seq\":1}
not a record at all
",
        )
        .expect("write");

        let device = FileDevice::open(&path, None).expect("open");
        assert!(device.head_seq().is_err());
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

    /// Finding F6: two rotations in one millisecond used to be one file name.
    ///
    /// Every record here carries the *same* timestamp, so the name that used to be the
    /// whole suffix is the same for all of them. What that produced depended on the
    /// platform, and both answers were wrong: `fs::rename` replaces silently on Unix — the
    /// earlier archive, and the records in it, gone — and refuses on Windows, which takes
    /// the device down. The trail is a protected asset in its own right, and a segment that
    /// disappears is a gap `audit verify` finds later, during whatever made somebody look.
    #[test]
    fn rotations_in_the_same_millisecond_do_not_overwrite_each_other() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("audit.jsonl");

        let mut sink = AuditSink::new(
            vec![Box::new(FileDevice::open(&path, Some(200)).expect("open"))],
            Chain::new(),
        )
        .expect("sink");

        // One clock reading for all of them: a burst inside a millisecond, or a clock that
        // stepped back onto one.
        let mut hashes = Vec::new();
        for _ in 0..6 {
            hashes.push(
                sink.record(&Entry::allowed(Action::Read), 1_700_000_000_000)
                    .expect("write")
                    .hash,
            );
        }

        let archives: Vec<_> = std::fs::read_dir(directory.path())
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name() != "audit.jsonl")
            .map(|entry| entry.path())
            .collect();
        assert!(
            archives.len() > 1,
            "the point of this test is more than one rotation at one timestamp, got {archives:?}"
        );

        // The closing sequence is what separates them, so no two share a name.
        let mut names: Vec<_> = archives
            .iter()
            .map(|path| path.file_name().expect("a name").to_owned())
            .collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), archives.len(), "archive names must be unique");

        // And nothing was lost, which is the property the names exist to protect.
        let mut lines = read_lines(&path);
        for archive in &archives {
            lines.extend(read_lines(archive));
        }
        assert_eq!(lines.len(), 6, "no line may be lost to a rotation");
        for hash in hashes {
            assert!(
                lines
                    .iter()
                    .any(|line| hash_payload(line.as_bytes()) == hash),
                "a record went missing"
            );
        }
    }

    /// The archive is named after the last record in it, not the first of the next file.
    #[test]
    fn the_archive_name_carries_the_sequence_it_closes_at() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("audit.jsonl");

        let mut sink = AuditSink::new(
            vec![Box::new(FileDevice::open(&path, Some(200)).expect("open"))],
            Chain::new(),
        )
        .expect("sink");

        // Two records, one rotation: the archive holds sequence 1 and the live file gets 2.
        for tick in 1..=2_i64 {
            sink.record(&Entry::allowed(Action::Read), tick)
                .expect("write");
        }

        let archive = std::fs::read_dir(directory.path())
            .expect("read dir")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .find(|name| name != "audit.jsonl")
            .expect("one rotation");

        assert!(
            archive.ends_with("-1"),
            "the name says which record the archive ends at, got {archive:?}"
        );
        assert_eq!(read_lines(&path).len(), 1, "the live file holds the second");
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
    #[test]
    fn the_tracked_size_never_drifts_from_the_file_on_disk() {
        // The accounting half of the torn-line problem. `written` decides when rotation
        // happens; if a write can advance the file without advancing the counter, every
        // later rotation triggers late by the accumulated difference. Checked after each
        // record rather than once at the end, so a drift is attributed to the write that
        // caused it.
        //
        // The other half — a write that fails part-way and is truncated back — is not
        // exercised here. Provoking it needs a filesystem that runs out of space mid
        // `write`, and a test that fakes the error would only be testing the fake.
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("audit.jsonl");
        let mut device = FileDevice::open(&path, None).expect("open");
        let mut chain = Chain::new();

        for tick in 1..=5 {
            let record = chain
                .encode(&Entry::allowed(Action::Read), tick)
                .expect("encode");
            device.write(&record).expect("write");
            chain.commit(&record);

            let on_disk = std::fs::metadata(&path).expect("stat").len();
            assert_eq!(
                device.size(),
                on_disk,
                "after record {tick} the tracked size must equal the file"
            );
        }
    }

    #[test]
    fn reopening_resynchronises_the_tracked_size() {
        // `reopen` is the SIGHUP path. It re-stats deliberately: an external rotation
        // moved the file, so whatever the counter held is no longer about this file.
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("audit.jsonl");
        let mut device = FileDevice::open(&path, None).expect("open");
        let chain = Chain::new();

        let record = chain
            .encode(&Entry::allowed(Action::Read), 1)
            .expect("encode");
        device.write(&record).expect("write");
        let before = device.size();
        assert!(before > 0);

        device.reopen().expect("reopen");
        assert_eq!(
            device.size(),
            std::fs::metadata(&path).expect("stat").len(),
            "a reopened device must agree with the file it reopened"
        );
    }
}
