//! `VACUUM INTO` as a backup, exercised through the public API only.
//!
//! Every test here is a claim a restore depends on. The first two are the ones that
//! decide whether this is a backup at all: the copy is a database holding the same
//! secrets, and taking it changes nothing about the original.

use ciphr_core::{Plaintext, SecretPath};
use ciphr_crypto::{MasterKey, RootKey, RootKeyId, Seal, StaticSeal, decrypt, encrypt};
use ciphr_store::{SealState, SqliteStore, Store};

/// A file-backed store holding one secret, as a deployment would have it.
///
/// On disk rather than in memory, because half of what is claimed below is about
/// files: that the source is not written to, and that the copy stands alone.
fn store_with_a_secret(at: &std::path::Path) -> (RootKey, SecretPath, Vec<u8>) {
    let seal =
        StaticSeal::from_master_key("CIPHR_MASTER_KEY", MasterKey::generate().expect("entropy"));
    let root = RootKey::generate().expect("entropy");
    let id = RootKeyId::generate().expect("entropy");
    let path = SecretPath::parse("infra/service-a/DB_PASSWORD").expect("a valid path");
    let value = b"s3cret".to_vec();

    let mut store = SqliteStore::open(at).expect("open");
    store
        .initialize(&SealState {
            seal_id: seal.id().to_owned(),
            wrapped_root_key: seal.rewrap(&root, id).expect("wrap"),
        })
        .expect("initialize");

    let plaintext = Plaintext::from(&value[..]);
    store
        .put(&path, "operator", &mut |version| {
            encrypt(&root, &path, version, &plaintext)
        })
        .expect("put");

    (root, path, value)
}

#[test]
fn a_backup_is_a_database_holding_the_same_secrets() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let source = dir.path().join("store.db");
    let (root, path, value) = store_with_a_secret(&source);

    let copy = dir.path().join("backup.db");
    let report = SqliteStore::open_read_only(&source)
        .expect("open the source")
        .backup_into(&copy)
        .expect("back up");

    assert!(
        report.bytes > 0,
        "a backup of a store with a secret in it is not empty"
    );
    assert_eq!(
        report.schema_version,
        ciphr_store::SCHEMA_VERSION,
        "the copy carries the schema the source was migrated to"
    );

    // The point of the whole exercise: the value comes back out of the copy, under
    // the same master key. A backup that opens but cannot be decrypted is not a
    // backup, and nothing about the file's size would have said so.
    let restored = SqliteStore::open_read_only(&copy).expect("open the copy");
    let stored = restored
        .get(&path, None)
        .expect("the secret is in the copy");
    let plaintext = decrypt(&root, &stored.path, stored.version, &stored.value).expect("decrypt");
    assert_eq!(plaintext.expose(), &value[..]);
}

#[test]
fn a_backup_writes_nothing_to_the_database_it_copies() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let source = dir.path().join("store.db");
    store_with_a_secret(&source);

    let before = std::fs::read(&source).expect("read the source");

    let copy = dir.path().join("backup.db");
    SqliteStore::open_read_only(&source)
        .expect("open the source")
        .backup_into(&copy)
        .expect("back up");

    let after = std::fs::read(&source).expect("read the source again");
    assert_eq!(
        before, after,
        "taking a backup must not change one byte of the database it copies"
    );
}

#[test]
fn a_backup_does_not_migrate_the_database_it_copies() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let source = dir.path().join("store.db");
    store_with_a_secret(&source);

    // The claim is about the constructor, and it is the reason `ciphr backup` opens
    // read-only: a backup taken with a newer binary must not be the thing that
    // migrates the database. `open_read_only` checks the schema and does not apply
    // it, and `backup_into` is reachable from there — which is what this asserts by
    // compiling and by leaving the source's version where it was.
    let store = SqliteStore::open_read_only(&source).expect("open the source");
    let before = store.schema_version().expect("read the schema version");

    store
        .backup_into(dir.path().join("backup.db"))
        .expect("back up");

    let after = SqliteStore::open_read_only(&source)
        .expect("reopen the source")
        .schema_version()
        .expect("read the schema version again");
    assert_eq!(before, after);
}

#[test]
fn an_existing_destination_is_refused_rather_than_overwritten() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let source = dir.path().join("store.db");
    store_with_a_secret(&source);

    let copy = dir.path().join("backup.db");
    let store = SqliteStore::open_read_only(&source).expect("open the source");
    store.backup_into(&copy).expect("the first backup");

    let first = std::fs::read(&copy).expect("read the first backup");
    let refused = store.backup_into(&copy);
    assert!(
        refused.is_err(),
        "a second backup to the same path must be refused, not silently overwrite the first"
    );
    assert_eq!(
        first,
        std::fs::read(&copy).expect("read it again"),
        "the refusal leaves the existing backup exactly as it was"
    );
}

/// A destination that cannot be written names the *directory*, and says which end failed.
///
/// The message this replaces was `unable to open database: <destination>`, one word away
/// from what an unreadable source says — and the row above it in `backup.md` is exactly
/// that source failure. The deployment in `docs/field-report-2026-08-23.md` hit this while
/// taking the pre-upgrade copy as the service uid into a directory owned by its operator's
/// login, and read it as a store it could not open.
#[test]
fn an_unwritable_destination_names_the_directory_and_not_only_the_file() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let source = dir.path().join("store.db");
    store_with_a_secret(&source);

    // A directory that is not there stands in for one the uid cannot write: the same
    // SQLite refusal, and portable, which a permission bit is not.
    let unreachable = dir.path().join("not-a-directory").join("backup.db");
    let refused = SqliteStore::open_read_only(&source)
        .expect("open the source")
        .backup_into(&unreachable)
        .expect_err("the destination cannot be written");

    let message = refused.to_string();
    assert!(
        message.contains("not-a-directory"),
        "the directory is the thing to check, got: {message}"
    );
    assert!(
        message.contains("uid"),
        "and what about it has to change, got: {message}"
    );
    assert!(
        message.contains("not the store"),
        "the source is what the reader guesses first, so it is ruled out: {message}"
    );
}

#[test]
fn the_copy_stands_alone_without_a_write_ahead_log() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let source = dir.path().join("store.db");
    store_with_a_secret(&source);

    let copy = dir.path().join("backup.db");
    SqliteStore::open_read_only(&source)
        .expect("open the source")
        .backup_into(&copy)
        .expect("back up");

    // This is what makes the command safer than `cp`, and it is worth pinning rather
    // than trusting: a `VACUUM INTO` product is not write-ahead-logged, so there is
    // no sidecar file that a backup job could leave behind and no restore that can be
    // silently short of the newest writes.
    for suffix in ["-wal", "-shm"] {
        let sidecar = dir.path().join(format!("backup.db{suffix}"));
        assert!(
            !sidecar.exists(),
            "the copy must be one file, but {} exists",
            sidecar.display()
        );
    }
}
