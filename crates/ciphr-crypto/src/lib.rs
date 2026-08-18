#![forbid(unsafe_code)]
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

//! Envelope encryption and the seal abstraction.
//!
//! Master key wraps root key, root key wraps one data encryption key per secret
//! *version*, and that key encrypts exactly one payload — so nonce reuse cannot
//! occur by construction. Path and version are bound as additional authenticated
//! data, so a ciphertext cannot be moved from one path to another. The details,
//! including the exact wire format of the authenticated data, are in
//! [`envelope`].
//!
//! Together with `ciphr-policy` this crate *is* the project; everything else is
//! packaging. It therefore carries a hard dependency budget, stays small enough
//! for one person to review in full, and must pass external review before the
//! first production use.
//!
//! No custom constructions: established AEAD primitives, composed in the
//! documented standard pattern, with known-answer tests so a later refactor
//! cannot silently break compatibility.
//!
//! # Example
//!
//! ```
//! use ciphr_core::{Plaintext, SecretPath, SecretVersion};
//! use ciphr_crypto::{MasterKey, RootKey, RootKeyId, Seal, StaticEnvSeal, decrypt, encrypt};
//!
//! // At `init`: a root key is generated and stored only in wrapped form.
//! let seal = StaticEnvSeal::from_master_key("CIPHR_MASTER_KEY", MasterKey::generate()?);
//! let root = RootKey::generate()?;
//! let root_id = RootKeyId::generate()?;
//! let wrapped = seal.rewrap(&root, root_id)?;
//!
//! // At startup: the root key comes back from the wrapped record.
//! let root = seal.unseal(&wrapped)?;
//!
//! // Writing and reading a secret.
//! let path = SecretPath::parse("infra/service-a/DB_PASSWORD")?;
//! let stored = encrypt(&root, &path, SecretVersion::FIRST, &Plaintext::from(&b"s3cret"[..]))?;
//! let read_back = decrypt(&root, &path, SecretVersion::FIRST, &stored)?;
//! assert_eq!(read_back.expose(), b"s3cret");
//!
//! // The same ciphertext under a different path does not decrypt.
//! let elsewhere = SecretPath::parse("infra/service-b/DB_PASSWORD")?;
//! assert!(decrypt(&root, &elsewhere, SecretVersion::FIRST, &stored).is_err());
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

pub mod envelope;
pub mod error;
pub mod key;
pub mod seal;

pub use envelope::{
    EncryptedValue, NONCE_LEN, WrappedRootKey, decrypt, encrypt, unwrap_root_key, wrap_root_key,
};
pub use error::CryptoError;
pub use key::{Dek, DekId, ID_LEN, KEY_LEN, MasterKey, RootKey, RootKeyId};
pub use seal::{Seal, StaticEnvSeal};
