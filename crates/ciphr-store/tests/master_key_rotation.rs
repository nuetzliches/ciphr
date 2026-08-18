//! Master key rotation, demonstrated end to end.
//!
//! This is the test that justifies the root key existing at all (ADR-5). Rotating
//! the master key must:
//!
//! 1. leave every stored secret readable,
//! 2. rewrite exactly one record rather than re-encrypting anything,
//! 3. make the old master key useless.
//!
//! If rotation were expensive or risky, nobody would ever do it, and a key that is
//! never rotated is the same as a key that cannot be.

use ciphr_core::{Plaintext, SecretPath, SecretVersion};
use ciphr_crypto::{MasterKey, RootKey, RootKeyId, Seal, StaticEnvSeal, decrypt, encrypt};
use ciphr_store::{SealState, SqliteStore, Store, StoreError};

const SECRETS: [(&str, &[u8]); 3] = [
    ("infra/service-a/DB_PASSWORD", b"first"),
    ("infra/service-b/API_TOKEN", b"second"),
    ("ci/widget/REGISTRY_TOKEN", b"third"),
];

fn path(text: &str) -> SecretPath {
    SecretPath::parse(text).expect("test paths are valid")
}

#[test]
fn rotating_the_master_key_rewraps_one_record_and_keeps_every_secret_readable() {
    let directory = tempfile::tempdir().expect("temp dir");
    let file = directory.path().join("store.db");

    let old_master = MasterKey::from_hex(&"11".repeat(32)).expect("valid hex");
    let new_master = MasterKey::from_hex(&"22".repeat(32)).expect("valid hex");
    let old_seal = StaticEnvSeal::from_master_key("CIPHR_MASTER_KEY", old_master);
    let new_seal = StaticEnvSeal::from_master_key("CIPHR_MASTER_KEY", new_master);

    let root_id = RootKeyId::generate().expect("entropy");

    // --- Day one: initialize and write some secrets. ------------------------
    let stored_ciphertexts = {
        let root = RootKey::generate().expect("entropy");
        let mut store = SqliteStore::open(&file).expect("open");
        store
            .initialize(&SealState {
                seal_id: old_seal.id().to_owned(),
                wrapped_root_key: old_seal.rewrap(&root, root_id).expect("wrap"),
            })
            .expect("initialize");

        for (text, value) in SECRETS {
            let at = path(text);
            let plaintext = Plaintext::from(value);
            store
                .put(&at, "operator", &mut |version| {
                    encrypt(&root, &at, version, &plaintext)
                })
                .expect("put");
        }

        // Remember the stored ciphertexts, so that "nothing was re-encrypted" can
        // be checked rather than assumed.
        SECRETS.map(|(text, _)| store.get(&path(text), None).expect("get").value.ciphertext)
    };

    // --- Rotation: unseal with the old key, rewrap with the new one. --------
    {
        let mut store = SqliteStore::open(&file).expect("reopen");
        let state = store
            .seal_state()
            .expect("seal state")
            .expect("initialized");

        let root = old_seal.unseal(&state.wrapped_root_key).expect("unseal");
        store
            .replace_seal(&SealState {
                seal_id: new_seal.id().to_owned(),
                wrapped_root_key: new_seal
                    .rewrap(&root, state.wrapped_root_key.id)
                    .expect("rewrap"),
            })
            .expect("replace seal");
    }

    // --- After rotation ----------------------------------------------------
    let store = SqliteStore::open(&file).expect("reopen");
    let state = store
        .seal_state()
        .expect("seal state")
        .expect("initialized");

    // The root key is the same key, so its identifier is unchanged.
    assert_eq!(state.wrapped_root_key.id, root_id);

    // The old master key no longer opens the store.
    assert!(matches!(
        old_seal.unseal(&state.wrapped_root_key),
        Err(ciphr_crypto::CryptoError::Aead)
    ));

    // The new one does, and every secret is still readable.
    let root = new_seal.unseal(&state.wrapped_root_key).expect("unseal");
    for (index, (text, expected)) in SECRETS.into_iter().enumerate() {
        let at = path(text);
        let stored = store.get(&at, None).expect("get");
        let plaintext =
            decrypt(&root, &stored.path, stored.version, &stored.value).expect("decrypt");
        assert_eq!(plaintext.expose(), expected, "{text} must survive rotation");

        // And the ciphertext is byte-for-byte what it was: rotation touched the
        // seal record only. If this ever fails, rotation has become a full
        // re-encryption, which is the thing the key hierarchy exists to avoid.
        assert_eq!(
            stored.value.ciphertext, stored_ciphertexts[index],
            "{text} must not have been re-encrypted"
        );
    }
}

#[test]
fn a_replacement_for_a_different_root_key_is_refused() {
    // The failure mode this guards against is silent and total: storing a wrapped
    // record for a *different* root key would make every secret in the database
    // undecryptable, with no error until the first read.
    let seal =
        StaticEnvSeal::from_master_key("CIPHR_MASTER_KEY", MasterKey::generate().expect("entropy"));
    let root = RootKey::generate().expect("entropy");

    let mut store = SqliteStore::open_in_memory().expect("open");
    store
        .initialize(&SealState {
            seal_id: seal.id().to_owned(),
            wrapped_root_key: seal
                .rewrap(&root, RootKeyId::generate().expect("entropy"))
                .expect("wrap"),
        })
        .expect("initialize");

    let unrelated = RootKey::generate().expect("entropy");
    let result = store.replace_seal(&SealState {
        seal_id: seal.id().to_owned(),
        wrapped_root_key: seal
            .rewrap(&unrelated, RootKeyId::generate().expect("entropy"))
            .expect("wrap"),
    });

    assert!(matches!(result, Err(StoreError::Corrupt { .. })));
}

#[test]
fn replacing_the_seal_of_an_uninitialized_store_is_refused() {
    let seal =
        StaticEnvSeal::from_master_key("CIPHR_MASTER_KEY", MasterKey::generate().expect("entropy"));
    let mut store = SqliteStore::open_in_memory().expect("open");

    let result = store.replace_seal(&SealState {
        seal_id: seal.id().to_owned(),
        wrapped_root_key: seal
            .rewrap(
                &RootKey::generate().expect("entropy"),
                RootKeyId::generate().expect("entropy"),
            )
            .expect("wrap"),
    });

    assert!(matches!(result, Err(StoreError::NotInitialized)));
}

#[test]
fn a_secret_written_after_rotation_reads_alongside_older_ones() {
    // Rotation must not split the database into "before" and "after".
    let old_seal = StaticEnvSeal::from_master_key(
        "CIPHR_MASTER_KEY",
        MasterKey::from_hex(&"33".repeat(32)).expect("valid hex"),
    );
    let new_seal = StaticEnvSeal::from_master_key(
        "CIPHR_MASTER_KEY",
        MasterKey::from_hex(&"44".repeat(32)).expect("valid hex"),
    );

    let root = RootKey::generate().expect("entropy");
    let root_id = RootKeyId::generate().expect("entropy");
    let before = path("infra/before/VALUE");
    let after = path("infra/after/VALUE");

    let mut store = SqliteStore::open_in_memory().expect("open");
    store
        .initialize(&SealState {
            seal_id: old_seal.id().to_owned(),
            wrapped_root_key: old_seal.rewrap(&root, root_id).expect("wrap"),
        })
        .expect("initialize");

    let plaintext = Plaintext::from(&b"written before"[..]);
    store
        .put(&before, "operator", &mut |version| {
            encrypt(&root, &before, version, &plaintext)
        })
        .expect("put");

    let state = store
        .seal_state()
        .expect("seal state")
        .expect("initialized");
    let unsealed = old_seal.unseal(&state.wrapped_root_key).expect("unseal");
    store
        .replace_seal(&SealState {
            seal_id: new_seal.id().to_owned(),
            wrapped_root_key: new_seal.rewrap(&unsealed, root_id).expect("rewrap"),
        })
        .expect("replace seal");

    let root = new_seal
        .unseal(
            &store
                .seal_state()
                .expect("seal state")
                .expect("initialized")
                .wrapped_root_key,
        )
        .expect("unseal");

    let plaintext = Plaintext::from(&b"written after"[..]);
    store
        .put(&after, "operator", &mut |version| {
            encrypt(&root, &after, version, &plaintext)
        })
        .expect("put");

    for (at, expected, version) in [
        (&before, &b"written before"[..], SecretVersion::FIRST),
        (&after, &b"written after"[..], SecretVersion::FIRST),
    ] {
        let stored = store.get(at, Some(version)).expect("get");
        let value = decrypt(&root, &stored.path, stored.version, &stored.value).expect("decrypt");
        assert_eq!(value.expose(), expected);
    }
}
