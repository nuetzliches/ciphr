//! A write that carries a rotation class either happens whole or not at all.
//!
//! Finding F13 of the review of 2026-08-24. `PUT` with a class used to be two store
//! operations: commit the version, then set the class. A failure in the second left the
//! value stored, the class unset, and an error on the wire — and automation reads an HTTP
//! failure as *the requested state was not established*. Here it was established by half,
//! and the missing half is the one that **says a secret is unclassified**. Retrying wrote
//! a second version of the same value.
//!
//! # How the failure is produced
//!
//! With a SQLite trigger, installed through a second connection, which aborts the
//! statement that publishes the version and the class. That is real fault injection into
//! a real transaction: no hook in the production code, no mock store, nothing that exists
//! only for this test to succeed.
//!
//! It matters that there is no other way to write this. The store has no fault-injection
//! point — the audit side has `AuditKind::Broken` and this side has no equivalent — so
//! without the trigger, "the transaction rolls back" would be an assertion about code
//! nobody had run.

use ciphr_core::{Plaintext, Rotation, SecretPath, SecretVersion};
use ciphr_crypto::{MasterKey, RootKey, RootKeyId, Seal, StaticSeal, encrypt};
use ciphr_store::{SealState, SqliteStore, Store};

/// An initialized store on disk, so a second connection can reach the same database.
fn initialized(at: &std::path::Path) -> RootKey {
    let seal =
        StaticSeal::from_master_key("CIPHR_MASTER_KEY", MasterKey::generate().expect("entropy"));
    let root = RootKey::generate().expect("entropy");
    let id = RootKeyId::generate().expect("entropy");

    let mut store = SqliteStore::open(at).expect("open");
    store
        .initialize(&SealState {
            seal_id: seal.id().to_owned(),
            wrapped_root_key: seal.rewrap(&root, id).expect("wrap"),
        })
        .expect("initialize");
    root
}

fn write(store: &mut SqliteStore, root: &RootKey, at: &SecretPath, value: &[u8]) {
    let plaintext = Plaintext::from(value);
    store
        .put(at, "operator", &mut |version| {
            encrypt(root, at, version, &plaintext)
        })
        .expect("put");
}

/// Abort any statement that actually changes a rotation class.
///
/// `WHEN NEW.rotation IS NOT OLD.rotation` matters: the class now rides on the statement
/// that publishes every version, so a trigger without the guard would abort an ordinary
/// write as well and the test would prove nothing about the classified path.
fn break_classification(at: &std::path::Path) {
    let connection = rusqlite::Connection::open(at).expect("open a second connection");
    connection
        .execute_batch(
            "CREATE TRIGGER injected_failure
             BEFORE UPDATE OF rotation ON secrets
             WHEN NEW.rotation IS NOT OLD.rotation
             BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        )
        .expect("install the trigger");
}

#[test]
fn a_classified_write_that_fails_leaves_no_version_behind() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let database = dir.path().join("store.db");
    let root = initialized(&database);
    let path = SecretPath::parse("infra/service-a/DB_PASSWORD").expect("a valid path");

    let mut store = SqliteStore::open(&database).expect("reopen");
    write(&mut store, &root, &path, b"first");

    let before = store.metadata(&path).expect("metadata");
    assert_eq!(before.current_version.map(SecretVersion::get), Some(1));
    assert_eq!(before.rotation, Rotation::Unclassified);

    break_classification(&database);

    let plaintext = Plaintext::from(&b"second"[..]);
    let outcome = store.put_with_rotation(
        &path,
        "operator",
        Some(Rotation::BreaksData),
        &mut |version| encrypt(&root, &path, version, &plaintext),
    );
    assert!(outcome.is_err(), "the injected failure must surface");

    // The whole finding, in three assertions: no new version, no advanced pointer, no
    // class. Before this change the first two would have held and the third would not,
    // which is a stored value the caller was told did not happen.
    let after = store.metadata(&path).expect("metadata");
    assert_eq!(
        after.current_version.map(SecretVersion::get),
        Some(1),
        "the version pointer did not move"
    );
    assert_eq!(
        after.rotation,
        Rotation::Unclassified,
        "and no class was recorded"
    );
    assert_eq!(
        store.versions(&path).expect("versions").len(),
        1,
        "no second version row survived the rollback"
    );
}

/// The rollback is not achieved by refusing to write at all.
///
/// A test that only asserts "nothing happened" passes just as well against a function
/// that does nothing. This is the other half: with no trigger installed, the same call
/// writes both the version and the class.
#[test]
fn a_classified_write_that_succeeds_stores_both() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let database = dir.path().join("store.db");
    let root = initialized(&database);
    let path = SecretPath::parse("infra/service-a/DB_PASSWORD").expect("a valid path");

    let mut store = SqliteStore::open(&database).expect("reopen");
    let plaintext = Plaintext::from(&b"only"[..]);
    let version = store
        .put_with_rotation(
            &path,
            "operator",
            Some(Rotation::BreaksData),
            &mut |version| encrypt(&root, &path, version, &plaintext),
        )
        .expect("put with a class");

    assert_eq!(version.get(), 1);
    let metadata = store.metadata(&path).expect("metadata");
    assert_eq!(metadata.current_version.map(SecretVersion::get), Some(1));
    assert_eq!(metadata.rotation, Rotation::BreaksData);
}

/// A write with no class leaves the class alone rather than resetting it.
///
/// The `COALESCE` in the statement, asserted rather than assumed: the class is now in the
/// `SET` list of every write, so "no class named" has to mean *keep the one there is*. If
/// it meant "write the default", every ordinary `PUT` would quietly unclassify a secret
/// somebody had classified — a worse defect than the one F13 named.
#[test]
fn an_unclassified_write_keeps_the_class_a_path_already_had() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let database = dir.path().join("store.db");
    let root = initialized(&database);
    let path = SecretPath::parse("infra/service-a/DB_PASSWORD").expect("a valid path");

    let mut store = SqliteStore::open(&database).expect("reopen");
    let plaintext = Plaintext::from(&b"first"[..]);
    store
        .put_with_rotation(
            &path,
            "operator",
            Some(Rotation::VolumeBound),
            &mut |version| encrypt(&root, &path, version, &plaintext),
        )
        .expect("put with a class");

    write(&mut store, &root, &path, b"second");

    let metadata = store.metadata(&path).expect("metadata");
    assert_eq!(
        metadata.current_version.map(SecretVersion::get),
        Some(2),
        "the value did move"
    );
    assert_eq!(
        metadata.rotation,
        Rotation::VolumeBound,
        "and the class it was given survived a write that named none"
    );
}
