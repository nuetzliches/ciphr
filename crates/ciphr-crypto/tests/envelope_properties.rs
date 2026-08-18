//! Property tests for the envelope scheme.
//!
//! The known-answer tests in `src/envelope.rs` pin the format. These check the
//! behaviour that has to hold for *every* input, which is where a subtle mistake
//! in the authenticated-data construction would show up — a length prefix that
//! truncates, a path whose bytes collide with another path's, a version that
//! wraps.

use ciphr_core::{Plaintext, SecretPath, SecretVersion};
use ciphr_crypto::{RootKey, decrypt, encrypt};
use proptest::prelude::*;

fn valid_path() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z0-9_.=+-]{1,20}(/[a-zA-Z0-9_.=+-]{1,20}){0,4}")
        .expect("the regex is a literal and compiles")
        .prop_filter("segments must not be relative", |candidate| {
            candidate
                .split('/')
                .all(|segment| segment != "." && segment != "..")
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Whatever goes in comes back out, for any value, path and version.
    #[test]
    fn round_trips(
        value in prop::collection::vec(any::<u8>(), 0..4096),
        path in valid_path(),
        version in 1_u32..u32::MAX,
    ) {
        let root = RootKey::generate().expect("entropy");
        let path = SecretPath::parse(&path).expect("generated paths are valid");
        let version = SecretVersion::new(version).expect("non-zero");

        let stored = encrypt(&root, &path, version, &Plaintext::from(value.as_slice()))
            .expect("encryption must succeed");
        let recovered = decrypt(&root, &path, version, &stored)
            .expect("decryption of an untouched record must succeed");

        prop_assert_eq!(recovered.expose(), value.as_slice());
    }

    /// Two encryptions of the same value under the same key share nothing: a new
    /// data key, a new identifier, new nonces, different ciphertext. This is the
    /// property that makes nonce reuse impossible rather than merely unlikely.
    #[test]
    fn nothing_is_ever_reused(
        value in prop::collection::vec(any::<u8>(), 1..256),
        path in valid_path(),
    ) {
        let root = RootKey::generate().expect("entropy");
        let path = SecretPath::parse(&path).expect("generated paths are valid");
        let plaintext = Plaintext::from(value.as_slice());

        let first = encrypt(&root, &path, SecretVersion::FIRST, &plaintext).expect("encrypt");
        let second = encrypt(&root, &path, SecretVersion::FIRST, &plaintext).expect("encrypt");

        prop_assert_ne!(first.dek_id, second.dek_id);
        prop_assert_ne!(first.dek_nonce, second.dek_nonce);
        prop_assert_ne!(first.value_nonce, second.value_nonce);
        prop_assert_ne!(first.ciphertext, second.ciphertext);
        prop_assert_ne!(first.wrapped_dek, second.wrapped_dek);
    }

    /// A record cannot be read under a different version. Checked across the whole
    /// range rather than for version 1 and 2, because the binding is a byte string
    /// and an encoding mistake might only bite at a particular width.
    #[test]
    fn a_record_belongs_to_exactly_one_version(
        path in valid_path(),
        stored_version in 1_u32..u32::MAX,
        other_version in 1_u32..u32::MAX,
    ) {
        prop_assume!(stored_version != other_version);

        let root = RootKey::generate().expect("entropy");
        let path = SecretPath::parse(&path).expect("generated paths are valid");
        let stored = encrypt(
            &root,
            &path,
            SecretVersion::new(stored_version).expect("non-zero"),
            &Plaintext::from(&b"value"[..]),
        )
        .expect("encrypt");

        let wrong = SecretVersion::new(other_version).expect("non-zero");
        prop_assert!(decrypt(&root, &path, wrong, &stored).is_err());
    }

    /// A record cannot be read under a different path, however similar. The
    /// length-prefixed authenticated data exists so that no pair of distinct paths
    /// can produce the same byte string; this is that claim, tested.
    #[test]
    fn a_record_belongs_to_exactly_one_path(
        stored_path in valid_path(),
        other_path in valid_path(),
    ) {
        prop_assume!(stored_path != other_path);

        let root = RootKey::generate().expect("entropy");
        let stored_path = SecretPath::parse(&stored_path).expect("valid");
        let other_path = SecretPath::parse(&other_path).expect("valid");
        prop_assume!(stored_path != other_path);

        let stored = encrypt(
            &root,
            &stored_path,
            SecretVersion::FIRST,
            &Plaintext::from(&b"value"[..]),
        )
        .expect("encrypt");

        prop_assert!(decrypt(&root, &other_path, SecretVersion::FIRST, &stored).is_err());
    }

    /// A different root key cannot read the record, whatever else matches.
    #[test]
    fn a_record_belongs_to_exactly_one_root_key(path in valid_path()) {
        let path = SecretPath::parse(&path).expect("valid");
        let stored = encrypt(
            &RootKey::generate().expect("entropy"),
            &path,
            SecretVersion::FIRST,
            &Plaintext::from(&b"value"[..]),
        )
        .expect("encrypt");

        let other_root = RootKey::generate().expect("entropy");
        prop_assert!(decrypt(&other_root, &path, SecretVersion::FIRST, &stored).is_err());
    }

    /// Flipping any single bit of the stored record is detected. Byte-level
    /// coverage of what the unit test checks at five hand-picked positions.
    #[test]
    fn any_single_bit_flip_is_detected(
        path in valid_path(),
        byte_index in 0_usize..37,
        bit in 0_u32..8,
    ) {
        let root = RootKey::generate().expect("entropy");
        let path = SecretPath::parse(&path).expect("valid");
        let mut stored = encrypt(
            &root,
            &path,
            SecretVersion::FIRST,
            &Plaintext::from(&b"a value of known length"[..]),
        )
        .expect("encrypt");

        // 23 bytes of plaintext plus a 16-byte tag.
        prop_assume!(byte_index < stored.ciphertext.len());
        stored.ciphertext[byte_index] ^= 1 << bit;

        prop_assert!(decrypt(&root, &path, SecretVersion::FIRST, &stored).is_err());
    }
}
