//! Bounding the queryable trail, exercised through the binary.
//!
//! The properties here are the ones that only exist outside the library: that a cut
//! removes from the database and not from the archive, that it refuses when the archive
//! cannot account for what it would remove, that what it leaves behind still verifies,
//! and that it runs while another process holds the store lock — the case that decides
//! whether a retention job is schedulable at all, because the other process is normally
//! the running server.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// Sixty-four hexadecimal characters, so the test needs nothing from its environment.
const MASTER_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// A trail with the store's own creation plus `extra` further entries.
///
/// One `put` per entry. It used to be `list`, which audited its own read; the
/// listings are read-only now and record nothing (ADR-22), so a write is the
/// cheapest command that still grows the trail.
fn trail_of(store: &Path, archive: &Path, extra: usize) {
    assert!(audited(store, archive, &["init"]).status.success(), "init");
    for n in 0..extra {
        audited_put(store, archive, &format!("grow/entry-{n}"));
    }
}

/// Write a secret with the audit file attached, appending one `write` entry.
fn audited_put(store: &Path, archive: &Path, path: &str) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ciphr"))
        .arg("-d")
        .arg(store)
        .arg("--audit-file")
        .arg(archive)
        .args(["put", path])
        .env("CIPHR_MASTER_KEY", MASTER_KEY)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("run ciphr put");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"value")
        .expect("write the value");
    assert!(child.wait().expect("wait").success(), "put");
}

fn audited(store: &Path, archive: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ciphr"))
        .arg("-d")
        .arg(store)
        .arg("--audit-file")
        .arg(archive)
        .args(args)
        .env("CIPHR_MASTER_KEY", MASTER_KEY)
        .output()
        .expect("run ciphr")
}

fn ciphr(store: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ciphr"))
        .arg("-d")
        .arg(store)
        .args(args)
        .env("CIPHR_MASTER_KEY", MASTER_KEY)
        .output()
        .expect("run ciphr")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr is UTF-8")
}

fn lines(path: &Path) -> usize {
    std::fs::read_to_string(path)
        .expect("read")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
}

fn cut(store: &Path, anchors: &Path, archive: &Path, keep: &str, extra: &[&str]) -> Output {
    let mut args = vec![
        "audit",
        "cut",
        "--keep",
        keep,
        "--anchor",
        anchors.to_str().expect("path"),
        "--archive",
        archive.to_str().expect("path"),
    ];
    args.extend_from_slice(extra);
    ciphr(store, &args)
}

#[test]
fn a_cut_bounds_the_queryable_trail_and_leaves_the_archive_alone() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = directory.path().join("store.db");
    let archive = directory.path().join("audit.jsonl");
    let anchors = directory.path().join("anchors.jsonl");

    trail_of(&store, &archive, 5);
    assert_eq!(lines(&archive), 6, "the archive holds every entry");

    let done = cut(&store, &anchors, &archive, "2", &[]);
    assert!(done.status.success(), "cut: {}", stderr(&done));
    assert!(
        stderr(&done).contains("removed 4 entries through sequence 4"),
        "got: {}",
        stderr(&done)
    );

    // The queryable copy is bounded; the evidence is not touched.
    assert_eq!(
        lines(&archive),
        6,
        "the archive is not what a cut removes from"
    );
    let tail = ciphr(&store, &["audit", "tail", "-n", "20"]);
    let shown = stdout(&tail);
    let sequences: Vec<&str> = shown
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    assert_eq!(
        sequences,
        ["5", "6"],
        "only the newest two entries remain, got: {shown}"
    );

    // Two anchors: the one at the cut, which is what the remainder is verified from, and
    // one over what survived. The second is the newest line, so it is the one a later
    // check reaches first and it covers the most.
    assert_eq!(lines(&anchors), 2, "the cut appended both anchors");
    let written = std::fs::read_to_string(&anchors).expect("anchors");
    let mut written = written.lines();
    assert!(
        written.next().expect("first").contains("\"seq\":4"),
        "the anchor at the cut comes first"
    );
    assert!(
        written.next().expect("second").contains("\"seq\":6"),
        "the anchor over the remainder comes second"
    );
    assert_eq!(stdout(&done).lines().count(), 2, "both lines on stdout");
}

#[test]
fn what_a_cut_leaves_behind_verifies_and_anchors_again() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = directory.path().join("store.db");
    let archive = directory.path().join("audit.jsonl");
    let anchors = directory.path().join("anchors.jsonl");
    let out = anchors.to_str().expect("path");

    trail_of(&store, &archive, 5);
    assert!(cut(&store, &anchors, &archive, "3", &[]).status.success());

    // Without the anchor file the check still passes. A cut store that reported tampering
    // on the routine check would be a store whose checks get switched off.
    let plain = ciphr(&store, &["audit", "verify"]);
    assert!(plain.status.success(), "verify: {}", stderr(&plain));
    assert!(
        stdout(&plain).contains("the trail begins at sequence 4"),
        "it says where the trail now starts, got: {}",
        stdout(&plain)
    );
    assert!(
        stdout(&plain).contains("Nothing here checks the recorded cut itself"),
        "and it says what that check is worth, got: {}",
        stdout(&plain)
    );

    let against = ciphr(&store, &["audit", "verify", "--anchor", out]);
    assert!(against.status.success(), "verify: {}", stderr(&against));
    assert!(
        stdout(&against).contains("The recorded cut agrees with the anchor"),
        "the cut is checked against the copy outside the store, got: {}",
        stdout(&against)
    );

    // Anchoring a cut trail used to be the thing a cut would have broken: the records no
    // longer start at sequence one, and an anchor over them has to know that.
    let again = ciphr(&store, &["audit", "anchor", "--out", out]);
    assert!(again.status.success(), "anchor: {}", stderr(&again));
    assert_eq!(lines(&anchors), 3, "appended, not rewritten");
}

#[test]
fn a_cut_the_archive_cannot_account_for_is_refused_and_removes_nothing() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = directory.path().join("store.db");
    let archive = directory.path().join("audit.jsonl");
    let anchors = directory.path().join("anchors.jsonl");

    trail_of(&store, &archive, 4);

    // An archive that is not this store's trail: what pointing --archive at the wrong file
    // looks like, and what a deployment that never configured the file device looks like.
    let elsewhere = directory.path().join("someone-elses.jsonl");
    std::fs::write(&elsewhere, "{\"seq\":1}\n").expect("write");

    let refused = cut(&store, &anchors, &elsewhere, "1", &[]);
    assert!(!refused.status.success(), "the cut must be refused");
    assert!(
        stderr(&refused).contains("the audit log was not cut"),
        "it says the log is untouched, got: {}",
        stderr(&refused)
    );

    let tail = ciphr(&store, &["audit", "tail", "-n", "20"]);
    assert_eq!(
        stdout(&tail).lines().count(),
        5,
        "every entry is still there: {}",
        stdout(&tail)
    );
    assert!(
        !anchors.exists(),
        "and no anchor was appended for a cut that did not happen"
    );
}

#[test]
fn a_dry_run_reports_the_cut_and_performs_none_of_it() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = directory.path().join("store.db");
    let archive = directory.path().join("audit.jsonl");
    let anchors = directory.path().join("anchors.jsonl");

    trail_of(&store, &archive, 4);

    let planned = cut(&store, &anchors, &archive, "2", &["--dry-run"]);
    assert!(planned.status.success(), "dry run: {}", stderr(&planned));
    assert!(
        stderr(&planned).contains("would remove 3 entries up to sequence 3"),
        "got: {}",
        stderr(&planned)
    );
    assert_eq!(
        stdout(&planned).lines().count(),
        1,
        "the anchor it would write is shown"
    );

    assert!(!anchors.exists(), "nothing was appended");
    let tail = ciphr(&store, &["audit", "tail", "-n", "20"]);
    assert_eq!(stdout(&tail).lines().count(), 5, "nothing was removed");
}

#[test]
fn a_trail_shorter_than_the_bound_is_left_alone_and_reported_as_success() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = directory.path().join("store.db");
    let archive = directory.path().join("audit.jsonl");
    let anchors = directory.path().join("anchors.jsonl");

    trail_of(&store, &archive, 2);

    // A scheduled cut that failed on a young trail is a scheduled cut somebody switches
    // off, and then the bound this command exists for stops existing.
    let nothing = cut(&store, &anchors, &archive, "100", &[]);
    assert!(
        nothing.status.success(),
        "a bound larger than the trail is not an error: {}",
        stderr(&nothing)
    );
    assert!(
        stderr(&nothing).contains("nothing to remove"),
        "got: {}",
        stderr(&nothing)
    );
    assert!(!anchors.exists(), "and nothing was written");
}

#[test]
fn cutting_works_while_another_process_holds_the_store_lock() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = directory.path().join("store.db");
    let archive = directory.path().join("audit.jsonl");
    let anchors = directory.path().join("anchors.jsonl");

    trail_of(&store, &archive, 4);

    // Stand in for the running server. If a cut needed this lock, retention would need
    // downtime, and a retention policy that needs downtime does not get scheduled.
    let lock = ciphr_store::StoreLock::acquire(&store).expect("take the lock");

    // `get` and not `list`: the listings take the read-only path and run fine under
    // the lock (ADR-22), so only a command that opens a session shows the contrast.
    let refused = ciphr(&store, &["get", "grow/entry-0", "--force"]);
    assert!(
        !refused.status.success(),
        "a command that opens a session must still be refused while the lock is held"
    );
    assert!(
        stderr(&refused).contains("in use by process"),
        "and refused because of the lock, not for another reason: {}",
        stderr(&refused)
    );

    let done = cut(&store, &anchors, &archive, "2", &[]);
    assert!(
        done.status.success(),
        "cutting must not need the lock: {}",
        stderr(&done)
    );

    let verified = ciphr(
        &store,
        &[
            "audit",
            "verify",
            "--anchor",
            anchors.to_str().expect("path"),
        ],
    );
    assert!(
        verified.status.success(),
        "and the result must verify while the lock is still held: {}",
        stderr(&verified)
    );

    drop(lock);
}

#[test]
fn a_second_cut_moves_the_start_forward_and_keeps_both_anchors() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = directory.path().join("store.db");
    let archive = directory.path().join("audit.jsonl");
    let anchors = directory.path().join("anchors.jsonl");
    let out = anchors.to_str().expect("path");

    trail_of(&store, &archive, 7);

    assert!(cut(&store, &anchors, &archive, "5", &[]).status.success());
    let second = cut(&store, &anchors, &archive, "2", &[]);
    assert!(second.status.success(), "second cut: {}", stderr(&second));

    // Four anchors, and the sequence numbers never go backwards -- which is what keeps
    // "the newest line" the strongest statement in the file.
    let contents = std::fs::read_to_string(&anchors).expect("anchors");
    assert_eq!(contents.lines().count(), 4);
    let sequences: Vec<u64> = contents
        .lines()
        .map(|line| {
            ciphr_audit::Anchor::parse(line)
                .expect("every line is an anchor")
                .seq
        })
        .collect();
    assert_eq!(sequences, [3, 8, 6, 8], "cut, head, cut, head");
    assert!(
        sequences.last() >= sequences.iter().max(),
        "the newest line is not behind any earlier one, got {sequences:?}"
    );

    let verified = ciphr(&store, &["audit", "verify", "--anchor", out]);
    assert!(verified.status.success(), "verify: {}", stderr(&verified));
    assert!(
        stdout(&verified).contains("the trail begins at sequence 7"),
        "got: {}",
        stdout(&verified)
    );
}
