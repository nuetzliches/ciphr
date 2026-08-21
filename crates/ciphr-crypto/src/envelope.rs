//! Envelope encryption: the wire format and the two operations on it.
//!
//! ```text
//! master key (32 B, from the environment, never persisted)
//!     |  AES-256-GCM, AAD = "ciphr/root-key/v1" || root_key_id
//!     v
//! root key (32 B, generated at init, stored only wrapped)
//!     |  AES-256-GCM, AAD = "ciphr/dek/v1" || dek_id
//!     v
//! data encryption key (32 B, exactly one per secret version)
//!     |  AES-256-GCM, AAD = "ciphr/value/v1" || len(path) || path || version || dek_id
//!     v
//! secret plaintext
//! ```
//!
//! # Why it is built this way
//!
//! **The root key exists so that changing the master key re-wraps one record.**
//! Without that indirection, rotating the master key would mean re-encrypting
//! every secret in the database — which is to say, something nobody ever dares to
//! do. It is also what makes a change of seal mechanism (ADR-5) a single-row
//! migration rather than a data format change.
//!
//! **One data key per secret version makes nonce reuse structurally impossible
//! for a value.** Each data key encrypts exactly one payload, so exactly one nonce
//! ever exists under it. The best-known way to destroy AES-GCM — encrypting two
//! messages with the same key and nonce — cannot occur there, rather than being
//! avoided by careful counter management. It also bounds the blast radius of a
//! leaked data key to one version, and makes crypto-shredding a version a matter
//! of deleting its wrapped key.
//!
//! **One level up the guarantee is a bound, not a structure**, and saying otherwise
//! was finding F3 of the review of 2026-08-21. `dek_nonce` is a *random* 96-bit
//! nonce, and the root key performs one such wrap per version write, unbounded over
//! its life — there is no counter and no uniqueness argument, only the birthday
//! bound. NIST SP 800-38D §8.3 puts the limit for random IVs at 2^32 invocations of
//! one key: 4.3 billion version writes, at which point a collision stands at about
//! 2^-33. The master key does one wrap per rotation.
//!
//! Two consequences a reader should not have to derive. The count **does not
//! reset** in v1: `rotate-master-key` re-wraps the same root key under the same
//! identifier, by design, and there is no command that issues a new one. And a
//! collision would expose the XOR of two wrapped data keys plus the GCM
//! authentication key — to somebody holding the database already. At the scale this
//! is built for, that is a sentence to state and not a design to change.
//!
//! **Path and version are authenticated, not just stored.** An adversary with
//! write access to the database cannot move the ciphertext of
//! `infra/service-a/db-password` into the row for `infra/service-b/db-password`:
//! the additional authenticated data no longer matches and decryption fails.
//! Without that binding it would be a silent privilege transfer.
//!
//! # Wire format of the authenticated data
//!
//! The value AAD is length-prefixed rather than a bare concatenation:
//!
//! ```text
//! "ciphr/value/v1" || u32be(path.len()) || path || u32be(version) || dek_id
//! ```
//!
//! With fixed-width trailing fields a bare concatenation would already be
//! unambiguous, but that argument has to be re-derived by every reader. An
//! explicit length prefix does not, and it survives a future field being added.
//! The domain string is versioned so that a format change is a visible decision
//! and not a silent incompatibility.
//!
//! The known-answer tests at the bottom of this file pin all of it. They exist so
//! that a refactor cannot quietly change the format and make every stored secret
//! undecryptable; they do not validate AES-GCM itself, which is the job of the
//! `aes-gcm` crate and its own NIST vectors.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use ciphr_core::{Plaintext, SecretPath, SecretVersion};

use crate::error::CryptoError;
use crate::key::{Dek, DekId, KEY_LEN, MasterKey, RootKey, RootKeyId};

/// Length of an AES-GCM nonce, in bytes.
pub const NONCE_LEN: usize = 12;

/// Domain separator for wrapping the root key with the master key.
const AAD_ROOT_KEY: &[u8] = b"ciphr/root-key/v1";
/// Domain separator for wrapping a data key with the root key.
const AAD_DEK: &[u8] = b"ciphr/dek/v1";
/// Domain separator for encrypting a secret value with a data key.
const AAD_VALUE: &[u8] = b"ciphr/value/v1";

/// A root key wrapped by a master key, as stored.
///
/// Every field is ciphertext or a label, so none of it is secret. `Debug` is
/// still not derived: printing wrapped key material has no legitimate use, and
/// leaving the option out keeps it out of log lines.
#[derive(Clone, PartialEq, Eq)]
pub struct WrappedRootKey {
    /// Which root key this is.
    pub id: RootKeyId,
    /// Nonce used to wrap it.
    pub nonce: [u8; NONCE_LEN],
    /// The wrapped key, including the authentication tag.
    pub ciphertext: Vec<u8>,
}

/// One encrypted secret version, as stored.
///
/// Holds the wrapped data key next to the value it encrypts. Deleting
/// `wrapped_dek` alone renders the version permanently unreadable, which is what
/// crypto-shredding a version means — and it takes effect in every backup that
/// contains the shredded row.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedValue {
    /// Which data key encrypted this version.
    pub dek_id: DekId,
    /// Nonce used to wrap the data key.
    pub dek_nonce: [u8; NONCE_LEN],
    /// The data key, wrapped by the root key.
    pub wrapped_dek: Vec<u8>,
    /// Nonce used to encrypt the value.
    pub value_nonce: [u8; NONCE_LEN],
    /// The encrypted value, including the authentication tag.
    pub ciphertext: Vec<u8>,
}

/// Wrap a root key with a master key.
///
/// # Errors
///
/// Returns [`CryptoError::Entropy`] if no randomness is available, or
/// [`CryptoError::Aead`] if the AEAD refuses the input.
pub fn wrap_root_key(
    master: &MasterKey,
    root: &RootKey,
    id: RootKeyId,
) -> Result<WrappedRootKey, CryptoError> {
    wrap_root_key_with(master, root, id, random_nonce()?)
}

/// Unwrap a root key with a master key.
///
/// # Errors
///
/// Returns [`CryptoError::Aead`] if the master key is wrong, the record was
/// modified, or the record belongs to a different root key identifier. The three
/// are indistinguishable on purpose.
pub fn unwrap_root_key(
    master: &MasterKey,
    wrapped: &WrappedRootKey,
) -> Result<RootKey, CryptoError> {
    let aad = root_key_aad(wrapped.id);
    let mut bytes = open(master.expose(), &wrapped.nonce, &aad, &wrapped.ciphertext)?;
    if bytes.len() != KEY_LEN {
        zeroize::Zeroize::zeroize(&mut bytes);
        return Err(CryptoError::Aead);
    }
    let mut key = [0_u8; KEY_LEN];
    key.copy_from_slice(&bytes);
    zeroize::Zeroize::zeroize(&mut bytes);
    let root = RootKey::from_bytes(key);
    zeroize::Zeroize::zeroize(&mut key);
    Ok(root)
}

/// Encrypt a secret value for a given path and version.
///
/// A fresh data key is generated for this version and wrapped by the root key.
///
/// # Errors
///
/// Returns [`CryptoError::Entropy`] if no randomness is available, or
/// [`CryptoError::Aead`] if the AEAD refuses the input.
pub fn encrypt(
    root: &RootKey,
    path: &SecretPath,
    version: SecretVersion,
    plaintext: &Plaintext,
) -> Result<EncryptedValue, CryptoError> {
    encrypt_with(
        root,
        path,
        version,
        plaintext,
        &ValueMaterial {
            dek: &Dek::generate()?,
            dek_id: DekId::generate()?,
            dek_nonce: random_nonce()?,
            value_nonce: random_nonce()?,
        },
    )
}

/// Decrypt a secret value, which must be presented with the path and version it
/// was encrypted for.
///
/// Passing a different path or version fails: that binding is the defence against
/// a ciphertext being relocated inside the database.
///
/// # Errors
///
/// Returns [`CryptoError::Aead`] if the root key is wrong, the record was
/// modified, the data key was shredded, or the path or version do not match.
pub fn decrypt(
    root: &RootKey,
    path: &SecretPath,
    version: SecretVersion,
    value: &EncryptedValue,
) -> Result<Plaintext, CryptoError> {
    let dek = unwrap_dek(root, value)?;
    let aad = value_aad(path, version, value.dek_id);
    let plaintext = open(dek.expose(), &value.value_nonce, &aad, &value.ciphertext)?;
    Ok(Plaintext::new(plaintext))
}

/// Deterministic core of [`wrap_root_key`], for known-answer tests.
fn wrap_root_key_with(
    master: &MasterKey,
    root: &RootKey,
    id: RootKeyId,
    nonce: [u8; NONCE_LEN],
) -> Result<WrappedRootKey, CryptoError> {
    let aad = root_key_aad(id);
    let ciphertext = seal(master.expose(), &nonce, &aad, root.expose())?;
    Ok(WrappedRootKey {
        id,
        nonce,
        ciphertext,
    })
}

/// Deterministic core of [`encrypt`], for known-answer tests.
///
/// Kept private: there is no feature flag and no hidden public seam that would
/// let a caller supply its own nonces in production. "No test mode" is a rule
/// about the shipped API, not only about authentication.
fn encrypt_with(
    root: &RootKey,
    path: &SecretPath,
    version: SecretVersion,
    plaintext: &Plaintext,
    material: &ValueMaterial<'_>,
) -> Result<EncryptedValue, CryptoError> {
    let ValueMaterial {
        dek,
        dek_id,
        dek_nonce,
        value_nonce,
    } = *material;

    let wrapped_dek = seal(root.expose(), &dek_nonce, &dek_aad(dek_id), dek.expose())?;
    let aad = value_aad(path, version, dek_id);
    let ciphertext = seal(dek.expose(), &value_nonce, &aad, plaintext.expose())?;
    Ok(EncryptedValue {
        dek_id,
        dek_nonce,
        wrapped_dek,
        value_nonce,
        ciphertext,
    })
}

/// The per-version material that [`encrypt`] generates and `encrypt_with`
/// accepts, grouped so that the deterministic seam takes one argument rather than
/// four loose values that could be passed in the wrong order.
#[derive(Clone, Copy)]
struct ValueMaterial<'a> {
    dek: &'a Dek,
    dek_id: DekId,
    dek_nonce: [u8; NONCE_LEN],
    value_nonce: [u8; NONCE_LEN],
}

fn unwrap_dek(root: &RootKey, value: &EncryptedValue) -> Result<Dek, CryptoError> {
    let aad = dek_aad(value.dek_id);
    let mut bytes = open(root.expose(), &value.dek_nonce, &aad, &value.wrapped_dek)?;
    if bytes.len() != KEY_LEN {
        zeroize::Zeroize::zeroize(&mut bytes);
        return Err(CryptoError::Aead);
    }
    let mut key = [0_u8; KEY_LEN];
    key.copy_from_slice(&bytes);
    zeroize::Zeroize::zeroize(&mut bytes);
    let dek = Dek::from_bytes(key);
    zeroize::Zeroize::zeroize(&mut key);
    Ok(dek)
}

fn root_key_aad(id: RootKeyId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_ROOT_KEY.len() + id.as_bytes().len());
    aad.extend_from_slice(AAD_ROOT_KEY);
    aad.extend_from_slice(id.as_bytes());
    aad
}

fn dek_aad(id: DekId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DEK.len() + id.as_bytes().len());
    aad.extend_from_slice(AAD_DEK);
    aad.extend_from_slice(id.as_bytes());
    aad
}

fn value_aad(path: &SecretPath, version: SecretVersion, dek_id: DekId) -> Vec<u8> {
    let path = path.as_str().as_bytes();
    let path_len = u32::try_from(path.len()).unwrap_or(u32::MAX);
    let mut aad =
        Vec::with_capacity(AAD_VALUE.len() + 4 + path.len() + 4 + dek_id.as_bytes().len());
    aad.extend_from_slice(AAD_VALUE);
    aad.extend_from_slice(&path_len.to_be_bytes());
    aad.extend_from_slice(path);
    aad.extend_from_slice(&version.to_be_bytes());
    aad.extend_from_slice(dek_id.as_bytes());
    aad
}

fn random_nonce() -> Result<[u8; NONCE_LEN], CryptoError> {
    let mut nonce = [0_u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::Entropy)?;
    Ok(nonce)
}

fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::KeyLength {
        expected: KEY_LEN,
        found: key.len(),
    })?;
    cipher
        .encrypt(
            &(*nonce).into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)
}

fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::KeyLength {
        expected: KEY_LEN,
        found: key.len(),
    })?;
    cipher
        .decrypt(
            &(*nonce).into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)
}

#[cfg(test)]
mod tests {
    use super::{
        AAD_VALUE, EncryptedValue, NONCE_LEN, ValueMaterial, decrypt, encrypt, encrypt_with,
        unwrap_root_key, value_aad, wrap_root_key, wrap_root_key_with,
    };
    use crate::error::CryptoError;
    use crate::key::{Dek, DekId, KEY_LEN, MasterKey, RootKey, RootKeyId};
    use ciphr_core::hex;
    use ciphr_core::{Plaintext, SecretPath, SecretVersion};

    // Fixed inputs for the known-answer tests. Not real key material and not
    // shaped like any: a test fixture that looks like a credential only trains
    // people to ignore secret scanners.
    const MASTER: [u8; KEY_LEN] = [0x11; KEY_LEN];
    const ROOT: [u8; KEY_LEN] = [0x22; KEY_LEN];
    const DEK_BYTES: [u8; KEY_LEN] = [0x33; KEY_LEN];
    const ROOT_ID: [u8; 16] = [0xa0; 16];
    const DEK_ID: [u8; 16] = [0xb0; 16];
    const NONCE_A: [u8; NONCE_LEN] = [0x01; NONCE_LEN];
    const NONCE_B: [u8; NONCE_LEN] = [0x02; NONCE_LEN];
    const NONCE_C: [u8; NONCE_LEN] = [0x03; NONCE_LEN];
    const PLAINTEXT: &[u8] = b"the value of a secret";
    const PATH: &str = "infra/service-a/DB_PASSWORD";

    // Pinned outputs. Regenerating these is never the fix for a failing test
    // here: if they change, the stored format changed, and every secret already
    // written under the old format has become undecryptable.
    const AAD_HEX: &str = "63697068722f76616c75652f76310000001b696e6672612f736572766963652d612f44425f50415353574f524400000001b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0";
    const WRAPPED_ROOT_KEY_HEX: &str = "6491a2feac21eeee232a8bfc8d93549fbd6401a194cdd8817a238fadd6fab4b7a5595ea84461395fb8166a7ca1c29d95";
    const VALUE_CIPHERTEXT_HEX: &str =
        "6c4545a5f73056dfd8a3d5b80ffec4ffa9df0223bb565d75c5dd879ffd480a9036a7bb683c";
    const WRAPPED_DEK_HEX: &str = "45edce2259aedc859a7e787a4293a3217aee29c916613b59c83f4d56bfd6dbfaa5330f7f1605ba75afdbf6a5b196a60a";

    /// A modification an adversary with database write access could make.
    type Mutation = fn(&mut EncryptedValue);

    fn path() -> SecretPath {
        SecretPath::parse(PATH).unwrap()
    }

    #[test]
    fn kat_value_aad_format() {
        // Pins the byte string that binds a ciphertext to its location. A change
        // here makes every stored secret undecryptable, so it must be a decision
        // and never a side effect.
        let aad = value_aad(&path(), SecretVersion::FIRST, DekId::from_bytes(DEK_ID));

        let mut expected = Vec::new();
        expected.extend_from_slice(AAD_VALUE);
        expected.extend_from_slice(&27_u32.to_be_bytes());
        expected.extend_from_slice(PATH.as_bytes());
        expected.extend_from_slice(&1_u32.to_be_bytes());
        expected.extend_from_slice(&DEK_ID);
        assert_eq!(aad, expected);

        assert_eq!(hex::encode(&aad), AAD_HEX);
    }

    #[test]
    fn kat_wrapped_root_key() {
        let wrapped = wrap_root_key_with(
            &MasterKey::from_bytes(MASTER),
            &RootKey::from_bytes(ROOT),
            RootKeyId::from_bytes(ROOT_ID),
            NONCE_A,
        )
        .unwrap();
        assert_eq!(hex::encode(&wrapped.ciphertext), WRAPPED_ROOT_KEY_HEX);
    }

    #[test]
    fn kat_encrypted_value() {
        let value = encrypt_with(
            &RootKey::from_bytes(ROOT),
            &path(),
            SecretVersion::FIRST,
            &Plaintext::from(PLAINTEXT),
            &ValueMaterial {
                dek: &Dek::from_bytes(DEK_BYTES),
                dek_id: DekId::from_bytes(DEK_ID),
                dek_nonce: NONCE_B,
                value_nonce: NONCE_C,
            },
        )
        .unwrap();
        assert_eq!(hex::encode(&value.wrapped_dek), WRAPPED_DEK_HEX);
        assert_eq!(hex::encode(&value.ciphertext), VALUE_CIPHERTEXT_HEX);
    }

    #[test]
    fn root_key_round_trips() {
        let master = MasterKey::generate().unwrap();
        let root = RootKey::generate().unwrap();
        let id = RootKeyId::generate().unwrap();

        let wrapped = wrap_root_key(&master, &root, id).unwrap();
        let recovered = unwrap_root_key(&master, &wrapped).unwrap();
        assert_eq!(recovered.expose(), root.expose());
        assert_eq!(wrapped.id, id);
    }

    #[test]
    fn a_different_master_key_cannot_unwrap() {
        let wrapped = wrap_root_key(
            &MasterKey::generate().unwrap(),
            &RootKey::generate().unwrap(),
            RootKeyId::generate().unwrap(),
        )
        .unwrap();
        // `assert_eq!` is not available here: `RootKey` implements neither
        // `Debug` nor `PartialEq`, which is the guarantee this crate is built on.
        assert!(matches!(
            unwrap_root_key(&MasterKey::generate().unwrap(), &wrapped),
            Err(CryptoError::Aead)
        ));
    }

    #[test]
    fn a_swapped_root_key_id_is_detected() {
        let master = MasterKey::generate().unwrap();
        let mut wrapped = wrap_root_key(
            &master,
            &RootKey::generate().unwrap(),
            RootKeyId::generate().unwrap(),
        )
        .unwrap();
        wrapped.id = RootKeyId::generate().unwrap();
        assert!(matches!(
            unwrap_root_key(&master, &wrapped),
            Err(CryptoError::Aead)
        ));
    }

    #[test]
    fn value_round_trips() {
        let root = RootKey::generate().unwrap();
        let value = encrypt(
            &root,
            &path(),
            SecretVersion::FIRST,
            &Plaintext::from(PLAINTEXT),
        )
        .unwrap();
        let recovered = decrypt(&root, &path(), SecretVersion::FIRST, &value).unwrap();
        assert_eq!(recovered.expose(), PLAINTEXT);
    }

    #[test]
    fn every_version_gets_its_own_data_key_and_nonce() {
        let root = RootKey::generate().unwrap();
        let plaintext = Plaintext::from(PLAINTEXT);
        let first = encrypt(&root, &path(), SecretVersion::FIRST, &plaintext).unwrap();
        let second = encrypt(
            &root,
            &path(),
            SecretVersion::FIRST.next().unwrap(),
            &plaintext,
        )
        .unwrap();

        // The property that makes nonce reuse impossible rather than merely
        // avoided: no *data* key is ever used twice, so no value nonce is ever
        // reused. The root key is used twice here, under two random nonces -- that
        // is the level where the guarantee is the birthday bound in the module
        // documentation, and no test can pin it.
        assert_ne!(first.dek_id, second.dek_id);
        assert_ne!(first.wrapped_dek, second.wrapped_dek);
        assert_ne!(first.value_nonce, second.value_nonce);
        assert_ne!(first.dek_nonce, second.dek_nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn a_ciphertext_cannot_be_moved_to_another_path() {
        let root = RootKey::generate().unwrap();
        let value = encrypt(
            &root,
            &path(),
            SecretVersion::FIRST,
            &Plaintext::from(PLAINTEXT),
        )
        .unwrap();

        let elsewhere = SecretPath::parse("infra/service-b/DB_PASSWORD").unwrap();
        assert!(matches!(
            decrypt(&root, &elsewhere, SecretVersion::FIRST, &value),
            Err(CryptoError::Aead)
        ));
    }

    #[test]
    fn a_ciphertext_cannot_be_moved_to_another_version() {
        let root = RootKey::generate().unwrap();
        let value = encrypt(
            &root,
            &path(),
            SecretVersion::FIRST,
            &Plaintext::from(PLAINTEXT),
        )
        .unwrap();
        assert!(matches!(
            decrypt(&root, &path(), SecretVersion::FIRST.next().unwrap(), &value),
            Err(CryptoError::Aead)
        ));
    }

    #[test]
    fn tampering_is_detected_everywhere_it_can_happen() {
        let root = RootKey::generate().unwrap();
        let original = encrypt(
            &root,
            &path(),
            SecretVersion::FIRST,
            &Plaintext::from(PLAINTEXT),
        )
        .unwrap();

        let mutate: [(&str, Mutation); 5] = [
            ("ciphertext", |v| v.ciphertext[0] ^= 1),
            ("tag", |v| {
                let last = v.ciphertext.len() - 1;
                v.ciphertext[last] ^= 1;
            }),
            ("value nonce", |v| v.value_nonce[0] ^= 1),
            ("wrapped data key", |v| v.wrapped_dek[0] ^= 1),
            ("data key id", |v| {
                v.dek_id = DekId::from_bytes([0xcc; 16]);
            }),
        ];

        for (what, mutation) in mutate {
            let mut value = original.clone();
            mutation(&mut value);
            assert!(
                matches!(
                    decrypt(&root, &path(), SecretVersion::FIRST, &value),
                    Err(CryptoError::Aead)
                ),
                "modifying the {what} must be detected"
            );
        }
    }

    #[test]
    fn shredding_the_wrapped_data_key_makes_the_version_unreadable() {
        let root = RootKey::generate().unwrap();
        let mut value = encrypt(
            &root,
            &path(),
            SecretVersion::FIRST,
            &Plaintext::from(PLAINTEXT),
        )
        .unwrap();

        value.wrapped_dek.clear();
        assert!(matches!(
            decrypt(&root, &path(), SecretVersion::FIRST, &value),
            Err(CryptoError::Aead)
        ));
    }

    #[test]
    fn an_empty_value_round_trips() {
        let root = RootKey::generate().unwrap();
        let value = encrypt(
            &root,
            &path(),
            SecretVersion::FIRST,
            &Plaintext::new(Vec::new()),
        )
        .unwrap();
        let recovered = decrypt(&root, &path(), SecretVersion::FIRST, &value).unwrap();
        assert!(recovered.is_empty());
    }
}
