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

/// The two machine-readable forms exist because a job cannot read the table, and the
/// point of a test here is the *contract*: a consumer branches on `verdict`, so the
/// spellings are what must not move. The sentences in `note` may be reworded, and
/// nothing below asserts one.
#[test]
fn the_json_form_carries_the_verdict_as_a_value() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path();

    write_config(path, "[seal]\ntype = \"static_env\"", "store.db");
    create_required(path, "store.db");

    let listed = ciphr(&["state", "--json", "ciphr.toml"], path);
    assert!(listed.status.success(), "state --json: {}", stderr(&listed));

    let document: serde_json::Value =
        serde_json::from_str(&stdout(&listed)).expect("the output is one JSON document");
    assert_eq!(
        document["format"], "ciphr.state.v1",
        "the document names its own format, so a consumer can refuse an unknown one"
    );

    let verdict = |role: &str| -> String {
        document["pieces"]
            .as_array()
            .expect("pieces is an array")
            .iter()
            .find(|piece| piece["role"] == role)
            .unwrap_or_else(|| panic!("a row for {role}, got:\n{document:#}"))["verdict"]
            .as_str()
            .expect("a verdict string")
            .to_owned()
    };

    // The three the field report asked for by name, and the two that separate this from
    // a list of paths: the key is `separately` rather than `never`, and TLS is neither.
    assert_eq!(verdict("store"), "include");
    assert_eq!(verdict("write-ahead log"), "include-with-store");
    assert_eq!(verdict("store lock"), "never");
    assert_eq!(verdict("master key"), "separately");
    assert_eq!(verdict("tls key"), "reissue");

    // The role is the role, without the table's indent. A consumer keying on it must not
    // have to strip layout.
    assert!(
        document["pieces"]
            .as_array()
            .expect("pieces is an array")
            .iter()
            .all(|piece| !piece["role"].as_str().expect("a role").starts_with(' ')),
        "no role carries the table's indent, got:\n{document:#}"
    );

    // The two rows no configuration names are in the document rather than only in the
    // note beside the table, because the job that builds a file list is what needs them.
    let not_derivable = document["not_derivable"]
        .as_array()
        .expect("not_derivable is an array");
    assert!(
        not_derivable
            .iter()
            .any(|row| row["role"] == "anchor file" && row["verdict"] == "include"),
        "the anchor file is named as something to include, got:\n{document:#}"
    );
}

#[test]
fn the_exclude_form_names_the_lock_and_never_the_key() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path();

    write_config(
        path,
        "[seal]\ntype = \"static_file\"\npath = \"master.key\"",
        "store.db",
    );
    create_required(path, "store.db");
    std::fs::write(path.join("master.key"), b"placeholder").expect("write a key file");

    let listed = ciphr(&["state", "--exclude", "ciphr.toml"], path);
    assert!(
        listed.status.success(),
        "state --exclude: {}",
        stderr(&listed)
    );

    let printed = stdout(&listed);
    let lines: Vec<&str> = printed.lines().map(str::trim_end).collect();
    assert!(
        lines.contains(&"store.db.lock"),
        "the lock is the file this form exists for, got:\n{lines:?}"
    );
    // Printed although it does not exist here: the lock appears when the service comes
    // up, which is after whoever wrote the exclude list read this output.
    assert!(
        lines.contains(&"store.db-shm"),
        "the shared-memory index is the other one a `store.db*` glob picks up, got:\n{lines:?}"
    );

    // The whole point of the distinction between `never` and `separately`. A job handed
    // the key here would exclude it from every backup it takes, which is how a key is
    // lost rather than how it is kept out of this archive.
    assert!(
        !lines.contains(&"master.key"),
        "the master key must not be in an exclude list, got:\n{lines:?}"
    );
    assert!(
        !lines.contains(&"store.db") && !lines.contains(&"store.db-wal"),
        "nothing that belongs in the backup may appear here, got:\n{lines:?}"
    );
}

#[test]
fn the_machine_readable_forms_keep_the_exit_code() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path();

    write_config(path, "[seal]\ntype = \"static_env\"", "store.db");
    create_required(path, "store.db");
    std::fs::remove_file(path.join("policies.toml")).expect("remove the policy file");

    // The pre-flight half of this command does not depend on who reads it: a job that
    // runs `--json` before an upgrade has to fail for the same reason a person does.
    let listed = ciphr(&["state", "--json", "ciphr.toml"], path);
    assert_eq!(
        listed.status.code(),
        Some(3),
        "a missing required file fails in JSON too, with the same code all three forms use"
    );

    // And the document is still a document, so the consumer can say *which* file.
    let document: serde_json::Value =
        serde_json::from_str(&stdout(&listed)).expect("valid JSON even on the failure path");
    assert!(
        document["pieces"]
            .as_array()
            .expect("pieces is an array")
            .iter()
            .any(|piece| piece["role"] == "policies" && piece["state"] == "missing"),
        "the row says which one, got:\n{document:#}"
    );
}

/// The finding: a backup job cannot tell "the listing is complete" from "the command
/// failed", and the exit code is where that distinction has to live.
///
/// The `never` rows are derived from `[storage] path` alone, so nothing a missing TLS leaf
/// or key file does can change them. A deployment that follows `backup.md` most strictly
/// keeps the key and the certificate out of the container that takes the backup — so its
/// job could never see a zero here, and had to either ignore the status or re-implement
/// the check the tool had just performed (`docs/assurance/field-reports/field-report-2026-08-23.md`, finding 2).
#[test]
fn a_complete_listing_with_a_missing_required_file_has_its_own_exit_code() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path();

    write_config(path, "[seal]\ntype = \"static_env\"", "store.db");
    create_required(path, "store.db");
    // What the backup container sees: no TLS material, on purpose.
    for name in ["cert.pem", "key.pem"] {
        std::fs::remove_file(path.join(name)).expect("remove the TLS material");
    }

    let listed = ciphr(&["state", "--exclude", "ciphr.toml"], path);
    assert_eq!(
        listed.status.code(),
        Some(3),
        "the pre-flight failure has its own code: {}",
        stderr(&listed)
    );

    // And the listing it exited non-zero on is complete.
    let printed = stdout(&listed);
    let lines: Vec<&str> = printed.lines().collect();
    assert!(
        lines.iter().any(|line| line.ends_with("store.db.lock")),
        "the lock is the exclusion whose absence breaks a restore, got:\n{lines:?}"
    );
    assert!(
        lines.iter().any(|line| line.ends_with("store.db-shm")),
        "and the -shm beside it, got:\n{lines:?}"
    );

    // The reason it is `3` and not `2`: clap already uses `2` for a usage error, and a
    // job that branched on `2` would confuse a misspelled flag with a pre-flight result.
    let misused = ciphr(&["state", "--json", "--exclude", "ciphr.toml"], path);
    assert_eq!(
        misused.status.code(),
        Some(2),
        "a usage error stays clap's own code"
    );
}

#[test]
fn the_two_forms_are_not_combinable() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path();

    write_config(path, "[seal]\ntype = \"static_env\"", "store.db");
    create_required(path, "store.db");

    // One output or the other. A JSON document with paths appended after it would be
    // neither, and a consumer that got one would fail on a day nobody chose.
    let listed = ciphr(&["state", "--json", "--exclude", "ciphr.toml"], path);
    assert!(
        !listed.status.success(),
        "the two forms conflict rather than both printing"
    );
}
