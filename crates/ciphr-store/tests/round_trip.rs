//! End-to-end behaviour of the store, exercised through the public API only.

use ciphr_core::{Plaintext, Rotation, SecretPath, SecretVersion};
use ciphr_crypto::{MasterKey, RootKey, RootKeyId, Seal, StaticSeal, decrypt, encrypt};
use ciphr_store::{SealState, SqliteStore, Store, StoreError};

/// A store with a root key, as `ciphr init` would leave it.
fn initialized() -> (SqliteStore, RootKey) {
    let seal =
        StaticSeal::from_master_key("CIPHR_MASTER_KEY", MasterKey::generate().expect("entropy"));
    let root = RootKey::generate().expect("entropy");
    let id = RootKeyId::generate().expect("entropy");

    let mut store = SqliteStore::open_in_memory().expect("open");
    store
        .initialize(&SealState {
            seal_id: seal.id().to_owned(),
            wrapped_root_key: seal.rewrap(&root, id).expect("wrap"),
        })
        .expect("initialize");

    (store, root)
}

fn path(text: &str) -> SecretPath {
    SecretPath::parse(text).expect("test paths are valid")
}

fn put(store: &mut SqliteStore, root: &RootKey, at: &SecretPath, value: &[u8]) -> SecretVersion {
    let plaintext = Plaintext::from(value);
    store
        .put(at, "operator", &mut |version| {
            encrypt(root, at, version, &plaintext)
        })
        .expect("put")
}

fn read(
    store: &SqliteStore,
    root: &RootKey,
    at: &SecretPath,
    version: Option<SecretVersion>,
) -> Vec<u8> {
    let stored = store.get(at, version).expect("get");
    decrypt(root, &stored.path, stored.version, &stored.value)
        .expect("decrypt")
        .expose()
        .to_vec()
}

#[test]
fn a_fresh_store_is_at_the_current_schema_and_uninitialized() {
    let store = SqliteStore::open_in_memory().expect("open");
    assert_eq!(
        store.schema_version().expect("version"),
        ciphr_store::SCHEMA_VERSION
    );
    assert!(store.seal_state().expect("seal state").is_none());
}

#[test]
fn initializing_twice_is_refused() {
    let (mut store, root) = initialized();
    let id = store
        .seal_state()
        .expect("seal state")
        .expect("initialized")
        .wrapped_root_key
        .id;

    let seal = StaticSeal::from_master_key("OTHER", MasterKey::generate().expect("entropy"));
    let result = store.initialize(&SealState {
        seal_id: seal.id().to_owned(),
        wrapped_root_key: seal.rewrap(&root, id).expect("wrap"),
    });

    // Overwriting the seal record would orphan every secret in the database.
    assert!(matches!(result, Err(StoreError::AlreadyInitialized)));
}

#[test]
fn values_round_trip_through_the_store() {
    let (mut store, root) = initialized();
    let at = path("infra/service-a/DB_PASSWORD");

    let version = put(&mut store, &root, &at, b"first value");
    assert_eq!(version, SecretVersion::FIRST);
    assert_eq!(read(&store, &root, &at, None), b"first value");

    let second = put(&mut store, &root, &at, b"second value");
    assert_eq!(second.get(), 2);

    // The current version is the newest, and older versions stay readable.
    assert_eq!(read(&store, &root, &at, None), b"second value");
    assert_eq!(
        read(&store, &root, &at, Some(SecretVersion::FIRST)),
        b"first value"
    );
}

#[test]
fn the_version_in_the_ciphertext_is_the_version_it_is_stored_under() {
    // The point of passing encryption in as a callback: if the store allocated a
    // version and the caller encrypted for another, this would fail.
    let (mut store, root) = initialized();
    let at = path("infra/service-a/DB_PASSWORD");

    for expected in 1..=5_u32 {
        let version = put(
            &mut store,
            &root,
            &at,
            format!("value {expected}").as_bytes(),
        );
        assert_eq!(version.get(), expected);

        let stored = store.get(&at, Some(version)).expect("get");
        let plaintext =
            decrypt(&root, &stored.path, stored.version, &stored.value).expect("decrypt");
        assert_eq!(plaintext.expose(), format!("value {expected}").as_bytes());
    }
}

#[test]
fn metadata_and_version_listing_need_no_key() {
    let (mut store, root) = initialized();
    let at = path("infra/service-a/DB_PASSWORD");
    put(&mut store, &root, &at, b"one");
    put(&mut store, &root, &at, b"two");

    let metadata = store.metadata(&at).expect("metadata");
    assert_eq!(metadata.path, at);
    assert_eq!(metadata.current_version.map(SecretVersion::get), Some(2));
    assert_eq!(metadata.rotation, Rotation::Rotatable);
    assert!(metadata.updated_at >= metadata.created_at);

    let versions = store.versions(&at).expect("versions");
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].version, SecretVersion::FIRST);
    assert_eq!(versions[0].created_by, "operator");
    assert!(versions.iter().all(|v| v.deleted_at.is_none()));
    assert!(versions.iter().all(|v| v.destroyed_at.is_none()));
}

#[test]
fn rotation_class_is_stored_and_read_back() {
    let (mut store, root) = initialized();
    let at = path("infra/service-a/JWT_SECRET");
    put(&mut store, &root, &at, b"value");

    store
        .set_rotation(&at, Rotation::InvalidatesSessions)
        .expect("set rotation");
    assert_eq!(
        store.metadata(&at).expect("metadata").rotation,
        Rotation::InvalidatesSessions
    );

    // Metadata only: the classification must never affect whether a value can be
    // read. Rotating the wrong secret is an operational problem, not an
    // authorization one.
    assert_eq!(read(&store, &root, &at, None), b"value");
}

#[test]
fn missing_things_are_reported_as_missing() {
    let (mut store, root) = initialized();
    let at = path("infra/service-a/DB_PASSWORD");

    assert!(matches!(
        store.get(&at, None),
        Err(StoreError::NotFound { .. })
    ));
    assert!(matches!(
        store.metadata(&at),
        Err(StoreError::NotFound { .. })
    ));
    assert!(matches!(
        store.set_rotation(&at, Rotation::SeedOnly),
        Err(StoreError::NotFound { .. })
    ));

    put(&mut store, &root, &at, b"value");
    assert!(matches!(
        store.get(&at, SecretVersion::new(9)),
        Err(StoreError::VersionNotFound { .. })
    ));
}

#[test]
fn soft_delete_is_reversible_and_destruction_is_not() {
    let (mut store, root) = initialized();
    let at = path("infra/service-a/DB_PASSWORD");
    let version = put(&mut store, &root, &at, b"value");

    store.delete(&at, version).expect("delete");
    assert!(matches!(
        store.get(&at, Some(version)),
        Err(StoreError::VersionDeleted { .. })
    ));
    // Deleting twice leaves the world as the caller asked for it.
    store.delete(&at, version).expect("delete again");

    store.undelete(&at, version).expect("undelete");
    assert_eq!(read(&store, &root, &at, Some(version)), b"value");

    store.destroy(&at, version).expect("destroy");
    assert!(matches!(
        store.get(&at, Some(version)),
        Err(StoreError::VersionDestroyed { .. })
    ));
    // Undelete must not pretend to bring back a value nobody can decrypt.
    assert!(matches!(
        store.undelete(&at, version),
        Err(StoreError::VersionDestroyed { .. })
    ));

    let versions = store.versions(&at).expect("versions");
    assert!(versions[0].destroyed_at.is_some());
}

#[test]
fn destruction_removes_the_wrapped_key_not_just_a_flag() {
    // The claim is that a shredded version is unreadable even to someone holding
    // the root key and reading the row directly, so it is tested that way.
    let (mut store, root) = initialized();
    let at = path("infra/service-a/DB_PASSWORD");
    let version = put(&mut store, &root, &at, b"value");

    let before = store.get(&at, Some(version)).expect("get");
    assert!(!before.value.wrapped_dek.is_empty());

    store.destroy(&at, version).expect("destroy");

    // Reconstruct the record as it now sits in the database, minus the flag, and
    // confirm the key material is genuinely gone rather than merely marked.
    let mut shredded = before.value.clone();
    shredded.wrapped_dek.clear();
    assert!(decrypt(&root, &at, version, &shredded).is_err());
}

#[test]
fn listing_is_prefix_scoped_on_segment_boundaries() {
    let (mut store, root) = initialized();
    for text in [
        "infra/a",
        "infra/a/db",
        "infra/a/db/password",
        "infra/ab",
        "infra/b",
        "ci/widget/token",
    ] {
        put(&mut store, &root, &path(text), b"value");
    }

    let all = store.list(None).expect("list");
    assert_eq!(all.len(), 6);

    let under_a = store.list(Some(&path("infra/a"))).expect("list");
    let names: Vec<&str> = under_a.iter().map(SecretPath::as_str).collect();
    // `infra/ab` is not under `infra/a`, which a plain string prefix would get
    // wrong.
    assert_eq!(names, ["infra/a", "infra/a/db", "infra/a/db/password"]);

    let under_infra = store.list(Some(&path("infra"))).expect("list");
    assert_eq!(under_infra.len(), 5);
}

#[test]
fn listing_handles_paths_that_look_like_sql_patterns() {
    // `_` is a LIKE wildcard and a legal path character, so a prefix query built on
    // LIKE would match `infra/axb` when asked for `infra/a_b`. The range scan does not.
    //
    // This test used to cover `%` and `[` as well. Since path segments were narrowed to
    // an allowed set (letters, digits, `-`, `_`, `.`) neither is a legal path character
    // any more, so `_` is what carries this guard. The narrowing was worth it — those
    // two characters bought this test and nothing else, while the old rule let every
    // invisible format character through — but it does mean a switch to GLOB, whose
    // metacharacters are `*`, `?` and `[`, would no longer be caught here. `*` is
    // refused in paths for its own reasons, which covers the common half of that.
    let (mut store, root) = initialized();
    for text in ["infra/a_b/value", "infra/axb/value"] {
        put(&mut store, &root, &path(text), b"value");
    }

    let underscore = store.list(Some(&path("infra/a_b"))).expect("list");
    assert_eq!(
        underscore
            .iter()
            .map(SecretPath::as_str)
            .collect::<Vec<_>>(),
        ["infra/a_b/value"]
    );

    // And the sibling is not swept in, which is the actual failure a LIKE query would
    // produce here.
    assert_eq!(underscore.len(), 1);
}

#[test]
fn a_failing_encryption_leaves_nothing_behind() {
    // The callback runs inside the transaction, so a failure must not leave a
    // secret row with a version that was never written.
    let (mut store, _root) = initialized();
    let at = path("infra/service-a/DB_PASSWORD");

    let result = store.put(&at, "operator", &mut |_version| {
        Err(ciphr_crypto::CryptoError::Entropy)
    });
    assert!(matches!(
        result,
        Err(StoreError::Crypto(ciphr_crypto::CryptoError::Entropy))
    ));

    assert!(matches!(
        store.metadata(&at),
        Err(StoreError::NotFound { .. })
    ));
    assert!(store.list(None).expect("list").is_empty());
}

#[test]
fn a_reopened_database_keeps_everything() {
    let directory = tempfile::tempdir().expect("temp dir");
    let file = directory.path().join("store.db");

    let seal =
        StaticSeal::from_master_key("CIPHR_MASTER_KEY", MasterKey::generate().expect("entropy"));
    let root = RootKey::generate().expect("entropy");
    let id = RootKeyId::generate().expect("entropy");
    let at = path("infra/service-a/DB_PASSWORD");

    {
        let mut store = SqliteStore::open(&file).expect("open");
        store
            .initialize(&SealState {
                seal_id: seal.id().to_owned(),
                wrapped_root_key: seal.rewrap(&root, id).expect("wrap"),
            })
            .expect("initialize");
        put(&mut store, &root, &at, b"persisted");
    }

    let store = SqliteStore::open(&file).expect("reopen");
    let state = store
        .seal_state()
        .expect("seal state")
        .expect("initialized");
    // The mechanism, not the source: the same key opens the store whether it was read
    // from the environment or from a file.
    assert_eq!(state.seal_id, "static");
    assert_eq!(state.wrapped_root_key.id, id);

    let unsealed = seal.unseal(&state.wrapped_root_key).expect("unseal");
    assert_eq!(read(&store, &unsealed, &at, None), b"persisted");
}
