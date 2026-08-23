//! `--check-config` answers about the file without a store, and about the host beside it.
//!
//! **Every test here is a property the previous version did not have**, and the reason
//! they are worth pinning is in `docs/field-report-2026-08-23.md`: the check that catches
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
