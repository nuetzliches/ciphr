//! `ciphr backup`, exercised through the binary.
//!
//! Three of these are only observable from outside the process, which is why this is an
//! integration test: that the command works while another process holds the store lock —
//! normally the running server, and the whole reason the command exists rather than a
//! documented `cp` — that it needs no master key, and that what it writes is a store the
//! binary can serve secrets out of afterwards.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// Sixty-four hexadecimal characters, so the test needs nothing from its environment.
const MASTER_KEY: &str = "3333333333333333333333333333333333333333333333333333333333333333";

fn ciphr(store: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ciphr"))
        .arg("-d")
        .arg(store)
        .args(args)
        .env("CIPHR_MASTER_KEY", MASTER_KEY)
        .output()
        .expect("run ciphr")
}

/// The same, with the master key deliberately absent from the environment.
fn ciphr_without_key(store: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ciphr"))
        .arg("-d")
        .arg(store)
        .args(args)
        .env_remove("CIPHR_MASTER_KEY")
        .output()
        .expect("run ciphr")
}

fn put(store: &Path, path: &str, value: &str) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ciphr"))
        .arg("-d")
        .arg(store)
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
        .write_all(value.as_bytes())
        .expect("write the value");
    assert!(child.wait().expect("wait").success(), "put");
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr is UTF-8")
}

#[test]
fn a_backup_is_a_store_the_binary_can_read_secrets_out_of() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = directory.path().join("store.db");
    let copy = directory.path().join("backup.db");

    assert!(ciphr(&store, &["init"]).status.success(), "init");
    put(&store, "infra/service-a/DB_PASSWORD", "s3cret");

    let taken = ciphr(&store, &["backup", copy.to_str().expect("path")]);
    assert!(taken.status.success(), "backup: {}", stderr(&taken));
    assert!(
        stdout(&taken).contains("schema"),
        "the report names the schema version of the copy, got: {}",
        stdout(&taken)
    );
    // The one sentence that has to be on this command's output, because the mistake it
    // warns about cannot be undone once the archive exists.
    assert!(
        stdout(&taken).contains("master key"),
        "the output says the key belongs somewhere else, got: {}",
        stdout(&taken)
    );

    // The claim: the copy is not merely a file that opens, it is a store. Read the
    // secret back *out of the backup*, with the same key, through the same binary.
    let read = ciphr(&copy, &["get", "infra/service-a/DB_PASSWORD", "--force"]);
    assert!(
        read.status.success(),
        "get from the copy: {}",
        stderr(&read)
    );
    assert_eq!(stdout(&read).trim_end(), "s3cret");
}

#[test]
fn a_backup_runs_while_another_process_holds_the_lock() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = directory.path().join("store.db");
    let copy = directory.path().join("backup.db");

    assert!(ciphr(&store, &["init"]).status.success(), "init");

    // Stand in for the running server, which is the situation a backup is normally
    // taken in. If this command needed the lock it would need a maintenance window,
    // and a backup that needs one is a backup that gets skipped.
    let lock = ciphr_store::StoreLock::acquire(&store).expect("take the lock");

    // `get` and not `list`: the listings take the read-only path and run fine under
    // the lock (ADR-22), so only a command that opens a session shows the contrast.
    let refused = ciphr(&store, &["get", "infra/service-a/DB_PASSWORD", "--force"]);
    assert!(
        !refused.status.success(),
        "a command that opens a session must still be refused while the lock is held"
    );
    assert!(
        stderr(&refused).contains("in use by process"),
        "and refused because of the lock, not for another reason: {}",
        stderr(&refused)
    );

    let taken = ciphr(&store, &["backup", copy.to_str().expect("path")]);
    assert!(
        taken.status.success(),
        "backing up must not need the lock: {}",
        stderr(&taken)
    );
    assert!(copy.exists(), "the copy was written");

    drop(lock);
}

#[test]
fn a_backup_needs_no_master_key() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = directory.path().join("store.db");
    let copy = directory.path().join("backup.db");

    assert!(ciphr(&store, &["init"]).status.success(), "init");

    // Nothing in a backup is decrypted, so nothing about it should require the key to
    // be present. That is what allows a backup job to run without the highest-value
    // secret in the deployment being in its environment.
    let taken = ciphr_without_key(&store, &["backup", copy.to_str().expect("path")]);
    assert!(
        taken.status.success(),
        "backing up must not read the master key: {}",
        stderr(&taken)
    );
    assert!(copy.exists(), "the copy was written");

    // The contrast, so this is a property of the command and not of the environment:
    // a command that does need the key fails in the same environment. `get` and not
    // `list`, because the listings need no key either (ADR-22).
    let refused = ciphr_without_key(&store, &["get", "some/secret", "--force"]);
    assert!(
        !refused.status.success(),
        "a command that needs the key must still fail without it"
    );
    assert!(
        stderr(&refused).contains("is not set"),
        "and failed for the missing key, not for another reason: {}",
        stderr(&refused)
    );
}

#[test]
fn an_existing_destination_is_refused_and_left_alone() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = directory.path().join("store.db");
    let copy = directory.path().join("backup.db");

    assert!(ciphr(&store, &["init"]).status.success(), "init");

    let path = copy.to_str().expect("path");
    assert!(
        ciphr(&store, &["backup", path]).status.success(),
        "the first backup"
    );
    let first = std::fs::read(&copy).expect("read the first backup");

    let second = ciphr(&store, &["backup", path]);
    assert!(
        !second.status.success(),
        "a second backup to the same path must be refused"
    );
    assert!(
        stderr(&second).contains("already exists"),
        "the refusal says why, got: {}",
        stderr(&second)
    );
    assert_eq!(
        first,
        std::fs::read(&copy).expect("read it again"),
        "a refused backup leaves the existing one untouched — that is the point of refusing"
    );
}
