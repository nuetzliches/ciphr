//! `--check-config` answers about the file without a store, and about the host beside it.
//!
//! **Every test here is a property the previous version did not have**, and the reason
//! they are worth pinning is in `docs/assurance/field-reports/field-report-2026-08-23.md`: the check that catches
//! a *forgotten* surface stanza — the mistake ADR-20 makes possible, and the one a legal
//! file can hold — used to print only after the store had been opened, locked and written
//! to. So the one report worth reading in review, where there is no store and no key, was
//! the one report that could not be produced there.
//!
//! The store half is still checked, still refuses, and still exits non-zero. What changed
//! is that it can no longer suppress the half above it, and that it no longer changes
//! anything on the way past.

use ciphr_crypto::{MasterKey, RootKey, RootKeyId, Seal, StaticSeal};
use ciphr_server::{Config, Server};
use ciphr_store::{SealState, SqliteStore, Store};

const POLICIES: &str = r#"
[[identity]]
name     = "deploy"
kind     = "machine"
policies = ["infra"]

[[policy]]
name = "infra"

  [[policy.rule]]
  path         = "infra/**"
  capabilities = ["read", "list"]

  [[policy.rule]]
  path         = "infra/ciphr/**"
  capabilities = []
"#;

/// Every *build* entry this binary contains, as stanzas.
///
/// **A configuration that omits one is refused**, deliberately: `surface::resolve` will
/// not let a binary and a file disagree about compiled-in surface (ADR-20, property 3).
/// So an `--all-features` build — which is what CI runs — needs `honeypot_alert` named in
/// every configuration a test writes here, and a default build needs it named nowhere.
/// Derived from `SURFACE_ENTRIES` rather than hardcoded, so a second build entry does not
/// break this file in a way whose message is about surface rather than about the test.
fn build_entries() -> String {
    let mut stanzas = String::new();
    for entry in ciphr_server::SURFACE_ENTRIES {
        if entry.compiled_in && matches!(entry.kind, ciphr_server::surface::Kind::Build) {
            stanzas.push_str("[[surface]]\nentry = \"");
            stanzas.push_str(entry.name);
            stanzas.push_str(
                "\"\naccepted = \"2026-08-23\"\nreason = \"this binary contains it, so the file \
                 has to say so\"\n\n",
            );
        }
    }
    stanzas
}

/// A configuration whose every path is inside `directory`, so a test owns them all.
fn config_text(directory: &std::path::Path, key_env: &str, surface: &str) -> String {
    let at = |name: &str| {
        directory
            .join(name)
            .display()
            .to_string()
            .replace('\\', "/")
    };
    format!(
        r#"policies = "{}"

[server]
listen = "0.0.0.0:4400"

[server.tls]
cert = "{}"
key  = "{}"

[storage]
backend = "sqlite"
path    = "{}"

[seal]
type = "static_env"
env  = "{key_env}"

[[audit]]
type = "sqlite"

[[audit]]
type = "file"
path = "{}"

{}{surface}
"#,
        at("policies.toml"),
        at("cert.pem"),
        at("key.pem"),
        at("store.db"),
        at("audit.jsonl"),
        build_entries(),
    )
}

fn write_policies(directory: &std::path::Path) {
    std::fs::write(directory.join("policies.toml"), POLICIES).expect("write the policy file");
}

/// A store this configuration can serve from, sealed under `key`.
fn initialize(directory: &std::path::Path, key: &str) {
    let seal = StaticSeal::from_master_key(
        "the label is cosmetic",
        MasterKey::from_hex(key).expect("a valid key"),
    );
    let root = RootKey::generate().expect("entropy");
    let root_id = RootKeyId::generate().expect("entropy");

    let mut store = SqliteStore::open(directory.join("store.db")).expect("open");
    store
        .initialize(&SealState {
            seal_id: seal.id().to_owned(),
            wrapped_root_key: seal.rewrap(&root, root_id).expect("wrap"),
        })
        .expect("initialize");
}

/// A policy file with the shape `0.9.0` refuses: a control-plane path granting a
/// capability about a secret (ADR-23).
const POLICIES_BEFORE_ADR_23: &str = r#"
[[identity]]
name     = "viewer"
kind     = "human"
policies = ["viewer"]

[[policy]]
name = "viewer"

  [[policy.rule]]
  path         = "sys/**"
  capabilities = ["read"]
"#;

/// Run the real binary, because the exit code is the thing under test.
fn check_config(config: &std::path::Path, key: Option<(&str, &str)>) -> std::process::Output {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_ciphr-server"));
    command.arg("--check-config").arg(config);
    if let Some((name, value)) = key {
        command.env(name, value);
    }
    command.output().expect("run the server binary")
}

/// The finding: a refused file and an absent store were the same status, and the
/// difference is the entire point of the check on a review host.
///
/// **`0.9.0` is what makes this worth a status rather than a paragraph.** Its policy edit
/// is mandatory, `upgrade.md` names `--check-config` as the way to catch a file that still
/// has the old form, and it names review as the place to run it — where there is no store
/// by design. A pipeline that runs the documented command on the documented host got `1`
/// for the finding and `1` for the host, so the only way to tell them apart was to parse a
/// dozen lines of prose (`docs/assurance/field-reports/field-report-2026-08-23-b.md`, finding 1).
///
/// All three cases in one test on purpose: the claim is not what any one of them exits
/// with, it is that the three are distinguishable.
#[test]
fn a_refused_file_an_unready_host_and_a_ready_one_are_three_statuses() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path();
    let config = path.join("ciphr.toml");
    let key_env = "CIPHR_CHECK_EXIT_CODE_KEY";
    std::fs::write(&config, config_text(path, key_env, "")).expect("write the configuration");

    // A: the file is unusable. Nothing about the host can change that, and nothing about
    // the host is what the operator has to fix.
    std::fs::write(path.join("policies.toml"), POLICIES_BEFORE_ADR_23).expect("the old form");
    let refused = check_config(&config, None);
    assert_eq!(
        refused.status.code(),
        Some(1),
        "a refused policy file is a failure, as it always was: {}",
        String::from_utf8_lossy(&refused.stderr)
    );
    let said = String::from_utf8_lossy(&refused.stderr);
    assert!(
        said.contains("'sys/**'") && said.contains("inspect"),
        "and it still names the rule and the capability meant, got: {said}"
    );

    // B: the file is usable and this host has no store. The report above the store line
    // is complete, and that is what the code has to say.
    write_policies(path);
    let unready = check_config(&config, None);
    assert_eq!(
        unready.status.code(),
        Some(3),
        "the file half is usable and the host half is not: {}",
        String::from_utf8_lossy(&unready.stdout)
    );
    let report = String::from_utf8_lossy(&unready.stdout);
    assert!(
        report.starts_with("configuration and policies are usable"),
        "the report a review host reads is unchanged, got: {report}"
    );
    assert!(
        report.contains("the store is not initialized"),
        "and it still says which half is missing, got: {report}"
    );

    // C: both halves. The status every existing caller already branches on.
    let key = "11".repeat(32);
    initialize(path, &key);
    let ready = check_config(&config, Some((key_env, &key)));
    assert_eq!(
        ready.status.code(),
        Some(0),
        "a usable file and a ready host is success: {}",
        String::from_utf8_lossy(&ready.stdout)
    );
}

/// `2` stays the usage error, so a job branching on a status never has to tell a
/// misspelled flag from a pre-flight result.
///
/// The same reservation `ciphr` makes for clap, made by hand here because this binary
/// takes two arguments and parses them itself.
#[test]
fn a_usage_error_is_not_a_pre_flight_result() {
    let refused = std::process::Command::new(env!("CARGO_BIN_EXE_ciphr-server"))
        .arg("--check-config")
        .output()
        .expect("run the server binary");

    assert_eq!(
        refused.status.code(),
        Some(2),
        "no path was given, which is a usage error and nothing about a host"
    );
}

/// The finding, as a test: the surface report is produced with no store on this host.
///
/// A configuration edit is exactly the change that wants review before it reaches a host,
/// and a forgotten stanza is legal — so if this report needs a store, the discipline the
/// report exists to support is only enforceable on the host, at the last moment before
/// the file is used.
#[test]
fn the_surface_report_is_answered_without_a_store() {
    let directory = tempfile::tempdir().expect("temp dir");
    write_policies(directory.path());

    let config = Config::parse(&config_text(
        directory.path(),
        "CIPHR_CHECK_NO_STORE_KEY",
        "",
    ))
    .expect("a usable configuration");
    let check = Server::check(&config).expect("the files are usable");

    // The half that travels with the file: every entry this binary knows is answerable
    // from here, which is what makes a forgotten stanza visible.
    assert!(
        check.store.is_err(),
        "there is no store in this directory, so the host half has to say so"
    );
    // Named by what it turns *off* rather than by a count: an `--all-features` build has
    // to name its build entry, so the count is a property of the build and the runtime
    // entries being off is the property of the file.
    for entry in ciphr_server::SURFACE_ENTRIES {
        if matches!(entry.kind, ciphr_server::surface::Kind::Runtime) {
            assert!(
                !check.surface.has(entry.name),
                "{} is not named by this configuration",
                entry.name
            );
        }
    }
    assert_eq!(check.identities, 1, "the policy file was read");
    assert_eq!(check.rules, 2, "including its rules");
}

/// The old check created what it was asked to inspect.
///
/// `SqliteStore::open` creates and migrates, so checking a configuration on a host with
/// no store left an empty `store.db` behind at the configured path — and the next reader
/// of that directory finds a store that no `init` ever wrote.
#[test]
fn a_check_creates_no_store() {
    let directory = tempfile::tempdir().expect("temp dir");
    write_policies(directory.path());

    let config = Config::parse(&config_text(
        directory.path(),
        "CIPHR_CHECK_NO_CREATE_KEY",
        "",
    ))
    .expect("a usable configuration");
    let _ = Server::check(&config).expect("the files are usable");

    assert!(
        !directory.path().join("store.db").exists(),
        "a check must not create the thing it is checking"
    );
}

/// A stanza this binary cannot honour is still refused before anything is opened.
///
/// The deserialization refusals are the half that was never the problem, and they have to
/// stay: this is what makes the store-free report an *answer* rather than only a listing.
#[test]
fn an_unknown_surface_entry_is_refused_with_no_store_present() {
    let directory = tempfile::tempdir().expect("temp dir");
    write_policies(directory.path());

    let text = config_text(
        directory.path(),
        "CIPHR_CHECK_UNKNOWN_ENTRY_KEY",
        "[[surface]]\nentry = \"nonexistent_entry\"\naccepted = \"2026-08-23\"\nreason = \"test\"",
    );
    let config = Config::parse(&text).expect("the file parses; the entry is checked later");

    // Matched rather than `expect_err`: `Check` has no `Debug`, and it must not acquire
    // one to satisfy a test — the workspace deliberately leaves `Debug` off types that
    // travel beside secret-bearing ones (ADR-1).
    let Err(refused) = Server::check(&config) else {
        panic!("an entry this binary has never heard of has to be refused")
    };
    assert!(
        refused.to_string().contains("nonexistent_entry"),
        "the refusal names it, got: {refused}"
    );
}

/// With a store, the host half answers — and the master key has to be the store's own.
///
/// The second half of this test is what the gate was worth: nothing about the *file* is
/// confirmed by a store, and nothing about a store is confirmed by the file. Both are
/// reported, separately.
#[test]
fn the_host_half_reports_a_store_it_can_open() {
    let directory = tempfile::tempdir().expect("temp dir");
    write_policies(directory.path());
    let key = "11".repeat(32);
    initialize(directory.path(), &key);

    let config = Config::parse(&config_text(
        directory.path(),
        "CIPHR_CHECK_HOST_HALF_KEY",
        "",
    ))
    .expect("a usable configuration");

    // The seal is read from the environment this configuration names. Set here rather
    // than in a fixture because the *check* is what reads it, which is the claim.
    // SAFETY-free: this is a test binary and the variable is its own.
    unsafe { std::env::set_var("CIPHR_CHECK_HOST_HALF_KEY", &key) };

    let check = Server::check(&config).expect("the files are usable");
    let store = check.store.expect("a store sealed under this key opens");
    assert_eq!(
        store.schema_version,
        ciphr_store::SCHEMA_VERSION,
        "the schema is reported as found"
    );
    assert!(!store.seal_id.is_empty(), "the seal record is named");
    assert_eq!(
        store.devices.len(),
        2,
        "both configured audit devices opened, got: {:?}",
        store.devices
    );

    // The wrong key is a host-half failure and nothing else: the file above it is
    // unchanged and still reported.
    unsafe { std::env::set_var("CIPHR_CHECK_HOST_HALF_KEY", "22".repeat(32)) };
    let check = Server::check(&config).expect("the files are still usable");
    assert!(
        check.store.is_err(),
        "a key that does not open this store is not readiness"
    );
    assert_eq!(check.identities, 1, "and the file half still answered");

    unsafe { std::env::remove_var("CIPHR_CHECK_HOST_HALF_KEY") };
}

/// A policy file with the grant `token_revoke` needs, on the path it is authorized
/// against.
const POLICIES_WITH_REVOKE: &str = r#"
[[identity]]
name     = "break-glass"
kind     = "human"
policies = ["break-glass"]

[[policy]]
name = "break-glass"

  [[policy.rule]]
  path         = "sys/tokens"
  capabilities = ["revoke"]
"#;

/// An entry that is on and that nobody can call is said out loud.
///
/// **The case this is for is a deployment mid-incident.** `token_revoke` exists so that
/// revoking a leaked credential does not stop the service, and the token that calls it can
/// only be issued on the host, under the store lock — so turning the entry on and issuing
/// nothing leaves the job half done, and the operator who finds out is the one who reached
/// for it (`docs/assurance/field-reports/field-report-2026-08-23-b.md`, finding 3).
///
/// Through the real binary, because the claim is about the report an operator reads. Not
/// through the exit code: naming the entry before the identity exists is a legitimate order
/// of work, and this is a note.
#[test]
fn an_entry_that_is_on_and_unreachable_is_named_in_the_report() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path();
    let config = path.join("ciphr.toml");
    let entry = "[[surface]]
entry = \"token_revoke\"
accepted = \"2026-08-23\"
reason = \"the revoke step must not take the service down\"";
    std::fs::write(
        &config,
        config_text(path, "CIPHR_CHECK_UNREACHABLE_KEY", entry),
    )
    .expect("write the configuration");

    // The policy file this deployment already had: no identity is authorized to revoke.
    write_policies(path);
    let reported = check_config(&config, None);
    let report = String::from_utf8_lossy(&reported.stdout);
    // Under the entry's own line, so that the note is read with the thing it is about.
    let noted = report
        .lines()
        .position(|line| line.contains("note:"))
        .expect("the note is printed");
    let entry_line = report
        .lines()
        .position(|line| line.contains("on   token_revoke"))
        .expect("the entry is on");
    assert_eq!(
        noted,
        entry_line + 1,
        "the note belongs under its own entry, got: {report}"
    );

    // The grant, because the reader has to write a rule afterwards.
    // Wrapped for a terminal, so the claim is about the words and not their line breaks.
    let flowed = report.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flowed.contains("authorized for 'revoke' on 'sys/tokens'"),
        "the note names the edit that is missing, got: {report}"
    );
    assert!(
        report.contains("planned stop"),
        "and says why finishing the job is not an edit, got: {report}"
    );
    assert_eq!(
        reported.status.code(),
        Some(3),
        "and it is a note: the status is still only about this host"
    );

    // The same configuration once an identity holds the grant.
    std::fs::write(path.join("policies.toml"), POLICIES_WITH_REVOKE).expect("the grant");
    let reported = check_config(&config, None);
    let report = String::from_utf8_lossy(&reported.stdout);
    assert!(
        !report.contains("note:"),
        "an entry that can be called is not worth a line, got: {report}"
    );
}

/// An audit device that cannot be opened says what the device needs.
///
/// **The message was the finding, not the behaviour.** `cannot open <path>: Read-only file
/// system (os error 30)` reads as a broken device, when what happened is that the
/// directory was mounted read-only — the safe instinct for a command whose name says
/// *check*, and one that costs whoever is pre-flighting a host they gave as little access
/// as possible (`docs/assurance/field-reports/field-report-2026-08-23-b.md`, finding 2).
///
/// An absent directory rather than a read-only one, because that fails the same way on
/// every platform this runs on and the claim here is about the sentence.
#[test]
fn an_audit_device_that_cannot_be_opened_names_the_requirement() {
    let directory = tempfile::tempdir().expect("temp dir");
    write_policies(directory.path());
    let key = "11".repeat(32);
    initialize(directory.path(), &key);

    let text = config_text(directory.path(), "CIPHR_CHECK_AUDIT_DEVICE_KEY", "")
        .replace("audit.jsonl", "no-such-directory/audit.jsonl");
    let config = Config::parse(&text).expect("a usable configuration");
    unsafe { std::env::set_var("CIPHR_CHECK_AUDIT_DEVICE_KEY", &key) };

    let check = Server::check(&config).expect("the files are usable");
    let Err(error) = check.store else {
        panic!("a device that cannot be opened is not readiness")
    };
    let said = error.to_string();
    unsafe { std::env::remove_var("CIPHR_CHECK_AUDIT_DEVICE_KEY") };

    assert!(
        said.contains("for append"),
        "the message says how the device is opened, got: {said}"
    );
    assert!(
        said.contains("writable"),
        "and what that requires of the directory, got: {said}"
    );
}

/// The check runs while something else holds the store's writer lock.
///
/// **This is the half of the finding that has nothing to do with review hosts.** The old
/// check was `prepare` with the listener left off, so it took the exclusive lock — which
/// the running service holds. The only host with a store was therefore the only host where
/// the check could not be run, unless the service was stopped first. A check that requires
/// an outage is a check that happens once.
#[test]
fn the_check_runs_while_the_lock_is_held() {
    let directory = tempfile::tempdir().expect("temp dir");
    write_policies(directory.path());
    let key = "11".repeat(32);
    initialize(directory.path(), &key);

    let config = Config::parse(&config_text(directory.path(), "CIPHR_CHECK_LOCKED_KEY", ""))
        .expect("a usable configuration");
    unsafe { std::env::set_var("CIPHR_CHECK_LOCKED_KEY", &key) };

    // What the running service holds for the life of its process.
    let held =
        ciphr_store::StoreLock::acquire(&directory.path().join("store.db")).expect("acquire");

    let check = Server::check(&config).expect("the files are usable");
    assert!(
        check.store.is_ok(),
        "a check is a reader, not a second writer: {:?}",
        check.store.err().map(|error| error.to_string())
    );

    drop(held);
    unsafe { std::env::remove_var("CIPHR_CHECK_LOCKED_KEY") };
}

/// A check does not migrate the store it is checking.
///
/// This is the one that would have cost a rollback. `upgrade.md` says: pre-flight with the
/// new binary, *then* back up, then move the pin. The old check opened the store
/// read-write, and `SqliteStore::open` migrates on open — so on a store one schema behind,
/// the pre-flight step performed the schema move that the backup taken after it exists to
/// make reversible.
#[test]
fn a_check_does_not_migrate_the_store() {
    let directory = tempfile::tempdir().expect("temp dir");
    write_policies(directory.path());
    let key = "11".repeat(32);
    initialize(directory.path(), &key);

    // One schema behind, as an upgrade would find it.
    let database = directory.path().join("store.db");
    let behind = ciphr_store::SCHEMA_VERSION - 1;
    {
        let connection = rusqlite::Connection::open(&database).expect("open");
        connection
            .pragma_update(None, "user_version", behind)
            .expect("wind the schema back");
    }

    let config = Config::parse(&config_text(
        directory.path(),
        "CIPHR_CHECK_MIGRATION_KEY",
        "",
    ))
    .expect("a usable configuration");
    unsafe { std::env::set_var("CIPHR_CHECK_MIGRATION_KEY", &key) };
    let _ = Server::check(&config);
    unsafe { std::env::remove_var("CIPHR_CHECK_MIGRATION_KEY") };

    let connection = rusqlite::Connection::open(&database).expect("open");
    let found: u32 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("read the schema version");
    assert_eq!(
        found, behind,
        "a check must not be the step that spends the rollback"
    );
}
