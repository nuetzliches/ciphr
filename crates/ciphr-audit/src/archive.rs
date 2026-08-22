//! The archive: the file device's lines, read back to prove a record still exists.
//!
//! Cutting the queryable device removes evidence from it. That is only defensible if
//! the evidence is somewhere else, and "somewhere else" for this crate means the file
//! device ([`crate::file`]) — one record per line, unbounded, rotated by size, shipped
//! to a backup by whatever already does that on the host.
//!
//! This module answers one question: **are these records in that file?** It answers it
//! by hash rather than by parsing, because the hash of a record *is* the hash of the
//! line. A line whose hash matches is byte-identical to the stored record, so a match
//! needs no JSON reading and cannot be fooled by a re-serialization that means the same
//! thing.
//!
//! Two properties worth stating, because both bound what a positive answer is worth:
//!
//! - **It proves presence, not durability.** A file on the same disk as the database is
//!   a copy that one disk failure takes with it, and a file the store's writer can
//!   rewrite is a copy that adds nothing against a writer. Where the archive lives
//!   decides what this check buys, and that is an operational decision this code cannot
//!   make.
//! - **It reads what it can read.** Rotated files that host tooling has compressed are
//!   not JSON Lines any more, so they are not counted — the report says how many files
//!   it read, so a coverage gap caused by compression is visible as one rather than
//!   mistaken for a missing record.
//!
//! # Example
//!
//! ```
//! use ciphr_audit::archive::{coverage_of, rotation_set};
//! use ciphr_audit::{Action, AuditSink, Chain, Entry, StoredRecord};
//!
//! # let directory = tempfile::tempdir()?;
//! # let path = directory.path().join("audit.jsonl");
//! let device = ciphr_audit::FileDevice::open(&path, None)?;
//! let mut sink = AuditSink::new(vec![Box::new(device)], Chain::new())?;
//! let written = sink.record(&Entry::allowed(Action::Read), 1_767_225_599_999)?;
//!
//! // The record as the queryable device holds it, and the same record in the archive.
//! let payload = std::fs::read_to_string(&path)?;
//! let stored = StoredRecord { seq: written.seq, payload: payload.trim_end(), hash: None };
//!
//! let coverage = coverage_of(&rotation_set(&path)?, [stored])?;
//! assert!(coverage.is_complete());
//! assert_eq!(coverage.found(), 1);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use crate::chain::{HASH_LEN, hash_payload};
use crate::verify::StoredRecord;

/// Length of the timestamp part of the suffix [`crate::FileDevice`] gives a rotated
/// file: an RFC 3339 timestamp with its colons replaced, as in
/// `2026-08-19T21-04-07.912Z`. The closing sequence follows it after a dash.
const STAMP_LEN: usize = 24;

/// Which records an archive holds, and which it does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    missing: Vec<u64>,
    found: u64,
    lines: u64,
    files: usize,
}

impl Coverage {
    /// Whether every record asked about was found.
    pub fn is_complete(&self) -> bool {
        self.missing.is_empty()
    }

    /// The sequence numbers that were not found, lowest first.
    pub fn missing(&self) -> &[u64] {
        &self.missing
    }

    /// How many of the records asked about were found.
    pub const fn found(&self) -> u64 {
        self.found
    }

    /// How many lines were read, across every file.
    pub const fn lines_read(&self) -> u64 {
        self.lines
    }

    /// How many files were read.
    pub const fn files_read(&self) -> usize {
        self.files
    }
}

/// The files belonging to one file device: the live file and its rotated siblings.
///
/// A rotated file is the live path plus `.`, the timestamp and the sequence
/// [`crate::FileDevice`] renames with, so the set is recognized by that shape rather
/// than by "everything beside it". The narrower rule is deliberate: a compressed or
/// archived copy is not JSON Lines, and reading one as text would count garbage lines
/// as records.
///
/// The live file is first; the rotated ones follow in name order, which the timestamp
/// makes time order down to the millisecond. Two archives *inside* one millisecond sort
/// by their sequence as text rather than as a number, so `-9` follows `-10`; nothing
/// here depends on their relative order, and saying so is cheaper than padding every
/// name in every archive to fix a tie that only a burst produces.
///
/// A path that does not exist yields an empty set rather than an error —
/// a device that has never written is not a broken one.
///
/// # Errors
///
/// Any I/O error from reading the containing directory.
pub fn rotation_set(path: impl AsRef<Path>) -> std::io::Result<Vec<PathBuf>> {
    let path = path.as_ref();
    let mut set = Vec::new();

    if path.is_file() {
        set.push(path.to_path_buf());
    }

    let (Some(directory), Some(name)) = (path.parent(), path.file_name()) else {
        return Ok(set);
    };
    // An empty parent means the path is a bare file name in the working directory.
    let directory = if directory.as_os_str().is_empty() {
        Path::new(".")
    } else {
        directory
    };
    if !directory.is_dir() {
        return Ok(set);
    }

    let prefix = {
        let mut prefix = name.to_os_string();
        prefix.push(".");
        prefix
    };

    let mut rotated = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(candidate) = file_name.to_str() else {
            continue;
        };
        let Some(prefix) = prefix.to_str() else {
            continue;
        };
        if let Some(stamp) = candidate.strip_prefix(prefix)
            && is_rotation_stamp(stamp)
            && entry.path().is_file()
        {
            rotated.push(entry.path());
        }
    }
    rotated.sort();
    set.extend(rotated);

    Ok(set)
}

/// Whether a suffix is one a rotation appends.
///
/// Two shapes, because the name gained a part: the timestamp alone, which is what
/// rotation wrote up to `0.6.1`, and the timestamp followed by `-` and the sequence the
/// archive closes at, which is what it writes since finding F6. Both are recognized, and
/// that is not politeness — an archive written by an older build is evidence, and a reader
/// that skipped it would report records as unarchived and tell an operator to keep
/// something they already have.
///
/// Shape only, not a date: `2026-13-45T99-99-99.999Z` passes. This decides which files to
/// read, and a reader that rejected a file because a clock had once been wrong would be
/// refusing to look at evidence over a formatting opinion.
fn is_rotation_stamp(suffix: &str) -> bool {
    // `get` rather than slicing: a suffix shorter than the stamp, or one whose bytes do
    // not divide there, is simply not a rotation.
    let (Some(stamp), Some(tail)) = (suffix.get(..STAMP_LEN), suffix.get(STAMP_LEN..)) else {
        return false;
    };

    if !stamp.ends_with('Z') {
        return false;
    }

    let shaped = stamp.chars().enumerate().all(|(index, character)| {
        match index {
            4 | 7 | 13 | 16 => character == '-',
            10 => character == 'T',
            19 => character == '.',
            23 => character == 'Z',
            // Everything else is a digit, including the two that would be colons in
            // RFC 3339 and are dashes in a file name.
            _ => character.is_ascii_digit(),
        }
    });

    shaped && is_archive_tail(tail)
}

/// What may follow the timestamp in an archive name.
///
/// Nothing, for a file written before the sequence was part of the name. Or `-` and the
/// closing sequence. Or that, plus `.` and a counter — which rotation only ever reaches if
/// something outside this process took the name first, and which is recognized here so
/// that such a file is still read rather than silently left out of the set.
fn is_archive_tail(tail: &str) -> bool {
    if tail.is_empty() {
        return true;
    }

    let Some(rest) = tail.strip_prefix('-') else {
        return false;
    };
    let (sequence, counter) = match rest.split_once('.') {
        Some((sequence, counter)) => (sequence, Some(counter)),
        None => (rest, None),
    };

    let digits = |text: &str| !text.is_empty() && text.chars().all(|c| c.is_ascii_digit());
    digits(sequence) && counter.is_none_or(digits)
}

/// Which of `wanted` appear in `files`, byte for byte.
///
/// Records are matched by the hash of their stored bytes, so a match is an identical
/// line and nothing weaker. A stored hash on the record is not trusted for this: the
/// payload is hashed here, because a row whose stored hash disagrees with its payload
/// would otherwise be able to claim coverage from a line it does not equal.
///
/// # Errors
///
/// Any I/O error from opening or reading one of the files. A file that cannot be read
/// is an error rather than an absence: treating it as empty would report records as
/// unarchived because of a permission problem, and the caller would then be told to keep
/// evidence it already has.
pub fn coverage_of<'a>(
    files: &[PathBuf],
    wanted: impl IntoIterator<Item = StoredRecord<'a>>,
) -> std::io::Result<Coverage> {
    let mut outstanding: HashMap<[u8; HASH_LEN], u64> = wanted
        .into_iter()
        .map(|record| (hash_payload(record.payload.as_bytes()), record.seq))
        .collect();
    let asked = outstanding.len() as u64;

    let mut lines = 0_u64;
    for file in files {
        let reader = BufReader::new(std::fs::File::open(file)?);
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            lines += 1;
            outstanding.remove(&hash_payload(line.as_bytes()));
            if outstanding.is_empty() {
                // Every record is accounted for. The rest of the archive is history
                // this call was not asked about.
                break;
            }
        }
    }

    let mut missing: Vec<u64> = outstanding.into_values().collect();
    missing.sort_unstable();

    Ok(Coverage {
        found: asked - missing.len() as u64,
        missing,
        lines,
        files: files.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::{coverage_of, is_rotation_stamp, rotation_set};
    use crate::Chain;
    use crate::device::AuditSink;
    use crate::entry::{Action, Entry};
    use crate::file::FileDevice;
    use crate::verify::StoredRecord;

    /// Write `count` records to a file device with the given rotation limit, and return
    /// the payloads in order.
    fn written(path: &std::path::Path, count: i64, rotate_at: Option<u64>) -> Vec<String> {
        let device = FileDevice::open(path, rotate_at).expect("open");
        let mut chain = Chain::new();
        let mut payloads = Vec::new();
        let mut sink = AuditSink::new(vec![Box::new(device)], Chain::new()).expect("sink");
        for tick in 1..=count {
            let at = 1_767_225_600_000 + tick;
            // The same record the sink is about to write, encoded here so the test holds
            // the exact bytes that reached the file.
            let record = chain
                .encode(&Entry::allowed(Action::Read), at)
                .expect("encode");
            chain.commit(&record);
            let seq = sink
                .record(&Entry::allowed(Action::Read), at)
                .expect("record")
                .seq;
            assert_eq!(seq, record.seq, "the sink and the local chain must agree");
            payloads.push(record.payload);
        }
        payloads
    }

    fn as_records(payloads: &[String]) -> Vec<StoredRecord<'_>> {
        payloads
            .iter()
            .enumerate()
            .map(|(index, payload)| StoredRecord {
                seq: index as u64 + 1,
                payload,
                hash: None,
            })
            .collect()
    }

    #[test]
    fn a_record_in_the_archive_is_found_and_one_that_is_not_is_named() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("audit.jsonl");
        let payloads = written(&path, 3, None);

        let files = rotation_set(&path).expect("set");
        assert_eq!(files, vec![path.clone()]);

        let coverage = coverage_of(&files, as_records(&payloads)).expect("read");
        assert!(coverage.is_complete());
        assert_eq!(coverage.found(), 3);
        assert_eq!(coverage.lines_read(), 3);

        // A record that was never written to this device: a store whose file device was
        // configured later than its SQLite one, which is the realistic way to arrive here.
        let absent =
            "{\"seq\":9,\"ts\":\"1970-01-01T00:00:00.000Z\",\"prev_hash\":\"00\"}".to_owned();
        let mut mixed = payloads.clone();
        mixed.push(absent);
        let coverage = coverage_of(&files, as_records(&mixed)).expect("read");
        assert!(!coverage.is_complete());
        assert_eq!(coverage.missing(), [4], "the position it was offered at");
        assert_eq!(coverage.found(), 3);
    }

    #[test]
    fn a_line_that_differs_by_one_byte_does_not_cover_the_record() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("audit.jsonl");
        let payloads = written(&path, 2, None);

        // The archive holds the record; the row offered claims the same position with an
        // altered payload. Matching by hash is what makes that a miss instead of a hit.
        let altered = payloads[1].replace("\"read\"", "\"list\"");
        assert_ne!(
            altered, payloads[1],
            "the test needs the substitution to apply"
        );
        let rows = vec![StoredRecord {
            seq: 2,
            payload: &altered,
            hash: None,
        }];

        let coverage = coverage_of(&rotation_set(&path).expect("set"), rows).expect("read");
        assert_eq!(coverage.missing(), [2]);
    }

    #[test]
    fn a_stored_hash_cannot_stand_in_for_the_payload() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("audit.jsonl");
        let payloads = written(&path, 1, None);

        // A row whose stored hash is the archived line's but whose payload is not: what
        // an in-place edit that forgot the hash column looks like. Coverage hashes the
        // payload, so the row does not get to borrow the line's identity.
        let hash = crate::hash_payload(payloads[0].as_bytes());
        let altered = payloads[0].replace("\"read\"", "\"list\"");
        let rows = vec![StoredRecord {
            seq: 1,
            payload: &altered,
            hash: Some(hash),
        }];

        let coverage = coverage_of(&rotation_set(&path).expect("set"), rows).expect("read");
        assert_eq!(coverage.missing(), [1]);
    }

    #[test]
    fn rotated_files_are_part_of_the_set_and_cover_the_records_in_them() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("audit.jsonl");
        // A limit small enough that every record rotates the file.
        let payloads = written(&path, 4, Some(1));

        let files = rotation_set(&path).expect("set");
        assert!(
            files.len() > 1,
            "the device must have rotated for this test to mean anything, got {files:?}"
        );
        assert_eq!(files[0], path, "the live file comes first");

        // The whole point: the oldest records are no longer in the live file, and the
        // coverage check finds them anyway.
        let coverage = coverage_of(&files, as_records(&payloads)).expect("read");
        assert!(coverage.is_complete(), "missing {:?}", coverage.missing());
        assert_eq!(coverage.found(), 4);
        assert_eq!(coverage.files_read(), files.len());
    }

    #[test]
    fn a_neighbour_that_is_not_a_rotation_is_not_read() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("audit.jsonl");
        written(&path, 1, None);

        // Compressed rotations, editor backups, and unrelated files all live beside an
        // audit file. None of them is JSON Lines.
        for neighbour in [
            "audit.jsonl.2026-08-19T21-04-07.912Z.gz",
            "audit.jsonl.gz",
            "audit.jsonl.bak",
            "audit.jsonl.1",
            "audit.jsonl.2026-08-19T21-04-07.912",
            "other.jsonl",
        ] {
            std::fs::write(directory.path().join(neighbour), "not json\n").expect("write");
        }

        assert_eq!(
            rotation_set(&path).expect("set"),
            vec![path.clone()],
            "only the live file and files with a rotation stamp belong to the set"
        );
    }

    #[test]
    fn a_device_that_has_never_written_has_an_empty_set() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("audit.jsonl");

        assert!(rotation_set(&path).expect("set").is_empty());

        // And an empty set covers nothing, rather than vacuously covering everything.
        let payload = "{\"seq\":1}".to_owned();
        let coverage = coverage_of(
            &[],
            [StoredRecord {
                seq: 1,
                payload: &payload,
                hash: None,
            }],
        )
        .expect("read");
        assert!(!coverage.is_complete());
        assert_eq!(coverage.missing(), [1]);
        assert_eq!(coverage.files_read(), 0);
    }

    #[test]
    fn nothing_asked_about_is_covered_by_anything() {
        // The degenerate case, pinned because the cut relies on it: an empty request is
        // complete, and that must not be reachable from "the archive was unreadable".
        let coverage = coverage_of(&[], []).expect("read");
        assert!(coverage.is_complete());
        assert_eq!(coverage.found(), 0);
    }

    #[test]
    fn an_unreadable_file_is_an_error_rather_than_an_absence() {
        let directory = tempfile::tempdir().expect("temp dir");
        let missing = directory.path().join("gone.jsonl");
        let payload = "{\"seq\":1}".to_owned();

        let outcome = coverage_of(
            &[missing],
            [StoredRecord {
                seq: 1,
                payload: &payload,
                hash: None,
            }],
        );
        assert!(
            outcome.is_err(),
            "a file that cannot be read must not be reported as one holding nothing"
        );
    }

    #[test]
    fn the_stamp_shape_matches_what_a_rotation_writes() {
        // The one place this module and the rotation in `file.rs` have to agree. The
        // rotated-set test above is the real guard; this pins the boundaries.
        assert!(is_rotation_stamp("2026-08-19T21-04-07.912Z"));
        assert!(is_rotation_stamp("0000-01-01T00-00-00.000Z"));
        assert!(!is_rotation_stamp("2026-08-19T21:04:07.912Z"), "colons");
        assert!(!is_rotation_stamp("2026-08-19T21-04-07.912"), "no Z");
        assert!(!is_rotation_stamp(""));
        assert_eq!(
            crate::time::rfc3339_millis(1_767_225_600_000)
                .replace(':', "-")
                .len(),
            super::STAMP_LEN,
            "the expected length has to be what a rotation actually writes"
        );
    }

    /// The sequence half of the name, which is what finding F6 added.
    ///
    /// A reader that took the timestamp alone would stop seeing archives the moment
    /// rotation started naming them after the record they close at — every one of them,
    /// which is a worse failure than the collision it was fixing.
    #[test]
    fn an_archive_named_after_its_closing_sequence_is_still_a_rotation() {
        assert!(is_rotation_stamp("2026-08-19T21-04-07.912Z-273"));
        assert!(is_rotation_stamp("2026-08-19T21-04-07.912Z-1"));
        // The counter, for a name something outside this process had already taken.
        assert!(is_rotation_stamp("2026-08-19T21-04-07.912Z-273.1"));

        // And the older shape stays a rotation, because an archive an earlier build wrote
        // is evidence: skipping it would report its records as unarchived and tell an
        // operator to keep what they already have.
        assert!(is_rotation_stamp("2026-08-19T21-04-07.912Z"));

        // Not everything after the stamp is a sequence.
        assert!(!is_rotation_stamp("2026-08-19T21-04-07.912Z0"), "no dash");
        assert!(!is_rotation_stamp("2026-08-19T21-04-07.912Z-"), "no digits");
        assert!(
            !is_rotation_stamp("2026-08-19T21-04-07.912Z-273.gz"),
            "a compressed archive is not JSON Lines and must not be read as text"
        );
        assert!(
            !is_rotation_stamp("2026-08-19T21-04-07.912Z-abc"),
            "a sequence is digits"
        );
    }
}
