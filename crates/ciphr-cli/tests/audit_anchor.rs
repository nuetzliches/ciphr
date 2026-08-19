//! What an anchor is for, exercised through the binary.
//!
//! Three properties are only observable from outside, which is why this is an integration
//! test: that the anchor lands in a file as one line, that a chain contradicting it stops
//! verification, and that both commands work while another process holds the store lock —
//! the case that matters, because the other process is normally the running server.

use std::path::Path;
use std::process::{Command, Output};

/// Sixty-four hexadecimal characters, so the test needs nothing from its environment.
const MASTER_KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";

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

#[test]
fn an_anchor_is_written_as_one_line_and_verified_against() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = directory.path().join("store.db");
    let anchors = directory.path().join("anchors.jsonl");

    assert!(ciphr(&store, &["init"]).status.success(), "init");

    let taken = ciphr(
        &store,
        &["audit", "anchor", "--out", anchors.to_str().expect("path")],
    );
    assert!(taken.status.success(), "anchor: {}", stderr(&taken));

    // Standard output is the record and nothing else, so that a scheduled job can pipe
    // it somewhere without filtering prose out of it.
    let line = stdout(&taken);
    assert_eq!(line.lines().count(), 1, "one line on stdout, got: {line}");
    assert!(
        line.contains("\"anchor\":1") && line.contains("\"seq\":1"),
        "the line anchors the store's own creation, got: {line}"
    );
    assert_eq!(
        std::fs::read_to_string(&anchors).expect("anchor file"),
        line,
        "the file holds exactly what stdout showed"
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
    assert!(verified.status.success(), "verify: {}", stderr(&verified));
    assert!(
        stdout(&verified).contains("agrees with the anchor"),
        "verification says the anchor held, got: {}",
        stdout(&verified)
    );
}

#[test]
fn an_anchor_the_chain_disagrees_with_stops_verification() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = directory.path().join("store.db");
    let anchors = directory.path().join("anchors.jsonl");

    assert!(ciphr(&store, &["init"]).status.success(), "init");

    // An anchor for sequence 1 with a hash that is not this store's: what a forward
    // rewrite looks like from the outside, and also what an anchor file from a different
    // store looks like. Neither can be told from the other, and both must stop here.
    std::fs::write(
        &anchors,
        format!(
            "{{\"anchor\":1,\"taken_at\":\"2026-08-19T00:00:00.000Z\",\"seq\":1,\"hash\":\"{}\"}}\n",
            "ab".repeat(32)
        ),
    )
    .expect("write anchor");

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
        !verified.status.success(),
        "verification must fail, got: {}",
        stdout(&verified)
    );
    let message = stderr(&verified);
    assert!(
        message.contains("rewritten") && message.contains("different store"),
        "the message names both possible causes, got: {message}"
    );

    // And a new anchor must not be appended over the contradiction: that would hand a
    // rewrite a fresh alibi and leave the file looking healthy.
    let taken = ciphr(
        &store,
        &["audit", "anchor", "--out", anchors.to_str().expect("path")],
    );
    assert!(!taken.status.success(), "anchoring must refuse");
    assert_eq!(
        std::fs::read_to_string(&anchors)
            .expect("anchor file")
            .lines()
            .count(),
        1,
        "nothing was appended"
    );
}

#[test]
fn anchoring_and_verifying_work_while_another_process_holds_the_lock() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = directory.path().join("store.db");
    let anchors = directory.path().join("anchors.jsonl");

    assert!(ciphr(&store, &["init"]).status.success(), "init");

    // Stand in for the running server. Only one writer may hold the chain, and this is
    // the lock that enforces it.
    let lock = ciphr_store::StoreLock::acquire(&store).expect("take the lock");

    let listed = ciphr(&store, &["list"]);
    assert!(
        !listed.status.success(),
        "a command that opens a session must still be refused while the lock is held"
    );

    let taken = ciphr(
        &store,
        &["audit", "anchor", "--out", anchors.to_str().expect("path")],
    );
    assert!(
        taken.status.success(),
        "anchoring must not need the lock: {}",
        stderr(&taken)
    );

    let verified = ciphr(&store, &["audit", "verify"]);
    assert!(
        verified.status.success(),
        "verifying must not need the lock: {}",
        stderr(&verified)
    );

    drop(lock);
}

#[test]
fn a_second_anchor_records_growth_and_confirms_the_first() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = directory.path().join("store.db");
    let anchors = directory.path().join("anchors.jsonl");
    let out = anchors.to_str().expect("path");

    assert!(ciphr(&store, &["init"]).status.success(), "init");
    assert!(
        ciphr(&store, &["audit", "anchor", "--out", out])
            .status
            .success(),
        "first anchor"
    );

    // Anything that writes to the trail moves the head. `list` audits its own read.
    assert!(ciphr(&store, &["list"]).status.success(), "list");

    let second = ciphr(&store, &["audit", "anchor", "--out", out]);
    assert!(
        second.status.success(),
        "second anchor: {}",
        stderr(&second)
    );
    assert!(
        stderr(&second).contains("the previous anchor, sequence 1"),
        "the earlier anchor was checked and said so, got: {}",
        stderr(&second)
    );

    let contents = std::fs::read_to_string(&anchors).expect("anchor file");
    assert_eq!(contents.lines().count(), 2, "the file is appended to");
    assert!(
        contents
            .lines()
            .next()
            .expect("first")
            .contains("\"seq\":1")
            && !contents
                .lines()
                .nth(1)
                .expect("second")
                .contains("\"seq\":1"),
        "the second anchor is past the first, got: {contents}"
    );
}
