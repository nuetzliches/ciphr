//! `ciphr state`, exercised through the binary.
//!
//! The command exists so that "what has to be kept" is derived from the configuration
//! rather than copied into a document, and the first test is the one that makes that
//! claim checkable: a configuration that moved its store has to produce an inventory
//! naming *that* store and not the default. A command that printed a fixed list would
//! pass everything else here.
//!
//! The last test is a leak guard rather than a feature test. This command reads a
//! configuration that names where the master key lives, so its output is one edit away
//! from carrying the key itself.

use std::path::Path;
use std::process::{Command, Output};

fn ciphr(args: &[&str], working_directory: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ciphr"))
        .args(args)
        .current_dir(working_directory)
        .output()
        .expect("run ciphr")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr is UTF-8")
}

/// A configuration with every path pointing inside `directory`, so the test owns them.
fn write_config(directory: &Path, seal: &str, store: &str) {
    std::fs::write(
        directory.join("ciphr.toml"),
        format!(
            r#"policies = "policies.toml"

[server]
listen = "0.0.0.0:4400"

[server.tls]
cert = "cert.pem"
key  = "key.pem"

[storage]
backend = "sqlite"
path    = "{store}"

{seal}

[[audit]]
type = "sqlite"

[[audit]]
type = "file"
path = "audit.jsonl"
"#
        ),
    )
    .expect("write the configuration");
}

/// Everything a configuration requires, so a test can then remove one thing.
fn create_required(directory: &Path, store: &str) {
    for name in ["policies.toml", "cert.pem", "key.pem", store] {
        std::fs::write(directory.join(name), b"placeholder").expect("create a required file");
    }
}

#[test]
fn the_inventory_follows_the_configuration_rather_than_a_fixed_list() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path();

    // Not the default path. A command printing a remembered list would name
    // `/var/lib/ciphr/store.db` here, which is exactly the drift this replaces.
    write_config(path, "[seal]\ntype = \"static_env\"", "somewhere-else.db");
    create_required(path, "somewhere-else.db");

    let listed = ciphr(&["state", "ciphr.toml"], path);
    assert!(listed.status.success(), "state: {}", stderr(&listed));

    let report = stdout(&listed);
    assert!(
        report.contains("somewhere-else.db"),
        "the configured store has to appear, got:\n{report}"
    );
    assert!(
        !report.contains("/var/lib/ciphr/store.db"),
        "a default path must not appear when the configuration named another, got:\n{report}"
    );
    // The sidecars are derived from that same path rather than from the default.
    assert!(
        report.contains("somewhere-else.db-wal") && report.contains("somewhere-else.db.lock"),
        "the sidecars follow the store, got:\n{report}"
    );
}

#[test]
fn a_required_file_that_is_not_there_is_an_error() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path();

    write_config(path, "[seal]\ntype = \"static_env\"", "store.db");
    create_required(path, "store.db");
    std::fs::remove_file(path.join("policies.toml")).expect("remove the policy file");

    let listed = ciphr(&["state", "ciphr.toml"], path);
    assert!(
        !listed.status.success(),
        "a missing policy file has to fail: the service would deny every request"
    );
    assert!(
        stdout(&listed).contains("MISSING"),
        "the row says which one, got:\n{}",
        stdout(&listed)
    );
}

#[test]
fn an_absent_audit_archive_is_reported_and_is_not_an_error() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path();

    write_config(path, "[seal]\ntype = \"static_env\"", "store.db");
    create_required(path, "store.db");

    // `audit.jsonl` was deliberately never created. The file device makes it on the
    // first record, so its absence on a service that has not started is correct — and a
    // check that failed here would cry wolf on every fresh deployment.
    let listed = ciphr(&["state", "ciphr.toml"], path);
    assert!(
        listed.status.success(),
        "an absent archive must not fail the check: {}",
        stderr(&listed)
    );
    assert!(
        stdout(&listed).contains("audit.jsonl"),
        "it still has to be listed, got:\n{}",
        stdout(&listed)
    );
}

#[test]
fn a_variable_seal_is_a_variable_and_not_a_missing_file() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path();

    write_config(
        path,
        "[seal]\ntype = \"static_env\"\nenv = \"CIPHR_KEY_FOR_THIS_HOST\"",
        "store.db",
    );
    create_required(path, "store.db");

    let listed = ciphr(&["state", "ciphr.toml"], path);
    assert!(listed.status.success(), "state: {}", stderr(&listed));

    let report = stdout(&listed);
    assert!(
        report.contains("$CIPHR_KEY_FOR_THIS_HOST"),
        "the variable is named, so an operator can see which source is live, got:\n{report}"
    );
    assert!(
        report.contains("NEVER in the same backup"),
        "the one rule about the key belongs on its row whichever source it is, got:\n{report}"
    );
}

#[test]
fn the_key_is_named_by_location_and_never_by_value() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path();

    write_config(
        path,
        "[seal]\ntype = \"static_file\"\npath = \"master.key\"",
        "store.db",
    );
    create_required(path, "store.db");

    // A real-looking key, in the file the configuration points at. This command opens a
    // configuration that says where the key is; reading it would be one line, and this
    // is what would notice.
    let key = "9".repeat(64);
    std::fs::write(path.join("master.key"), &key).expect("write a key file");

    let listed = ciphr(&["state", "ciphr.toml"], path);
    assert!(listed.status.success(), "state: {}", stderr(&listed));

    let everything = stdout(&listed) + &stderr(&listed);
    assert!(
        everything.contains("master.key"),
        "the path is reported, got:\n{everything}"
    );
    assert!(
        !everything.contains(&key),
        "the key's value must never reach the output"
    );
}
