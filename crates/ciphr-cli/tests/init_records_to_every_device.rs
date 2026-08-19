//! `init` must write its record to the file device, not only to the store.
//!
//! An integration test rather than a unit test because `init` is a private function in a
//! binary crate, and because the thing under test is the effect of a command-line flag on
//! a file. Both are only observable from outside.

use std::process::Command;

/// The regression: `--audit-file` was ignored by `init` alone.
///
/// Every other command honoured it, so the omission was invisible in normal use and showed
/// up as an archive whose first record referenced a hash it did not contain.
#[test]
fn init_honours_the_audit_file_flag() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = directory.path().join("store.db");
    let audit = directory.path().join("audit.jsonl");

    let status = Command::new(env!("CARGO_BIN_EXE_ciphr"))
        .arg("-d")
        .arg(&store)
        .arg("--audit-file")
        .arg(&audit)
        .arg("init")
        // A master key the test controls, so this needs nothing from the environment it
        // runs in. Sixty-four hexadecimal characters is the accepted form.
        .env("CIPHR_MASTER_KEY", "11".repeat(32))
        .status()
        .expect("run ciphr init");
    assert!(status.success(), "init must succeed");

    let recorded = std::fs::read_to_string(&audit).expect("the audit file must exist");
    assert!(
        recorded.contains("\"seq\":1"),
        "the file device must hold the first record of the chain, got: {recorded}"
    );
    assert!(
        recorded.contains("\"action\":\"init\""),
        "and that record must be the store's own creation, got: {recorded}"
    );
}
