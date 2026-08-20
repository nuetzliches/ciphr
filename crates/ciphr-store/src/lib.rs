#![forbid(unsafe_code)]
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

//! Persistence: the [`Store`] trait, its SQLite backend, and the migrations.
//!
//! The database holds ciphertext only and is not a trust anchor. The trait exists
//! so a different backend stays possible without touching the layers above it;
//! SQLite is the v1 choice because it adds no network dependency that could take
//! the secret store down with it (ADR-7).
//!
//! Migrations are numbered, additive SQL files applied in numeric order.
//!
//! # What this crate does not do
//!
//! It never sees a plaintext value and never holds a key. Encryption is passed in
//! as a callback so that the version number a value is encrypted for is, by
//! construction, the version it is stored under — see [`store::EncryptForVersion`].
//!
//! # Example
//!
//! ```
//! use ciphr_core::{Plaintext, SecretPath, SecretVersion};
//! use ciphr_crypto::{MasterKey, RootKey, RootKeyId, Seal, StaticSeal};
//! use ciphr_store::{SealState, SqliteStore, Store};
//!
//! // `ciphr init`: generate a root key and store it wrapped.
//! let seal = StaticSeal::from_master_key("CIPHR_MASTER_KEY", MasterKey::generate()?);
//! let root_id = RootKeyId::generate()?;
//! let root = RootKey::generate()?;
//!
//! let mut store = SqliteStore::open_in_memory()?;
//! store.initialize(&SealState {
//!     seal_id: seal.id().to_owned(),
//!     wrapped_root_key: seal.rewrap(&root, root_id)?,
//! })?;
//!
//! // Writing a secret. The store allocates the version and hands it to the
//! // closure, which binds it into the ciphertext.
//! let path = SecretPath::parse("infra/service-a/DB_PASSWORD")?;
//! let value = Plaintext::from(&b"s3cret"[..]);
//! let version = store.put(&path, "operator", &mut |version| {
//!     ciphr_crypto::encrypt(&root, &path, version, &value)
//! })?;
//! assert_eq!(version, SecretVersion::FIRST);
//!
//! // Reading it back.
//! let stored = store.get(&path, None)?;
//! let plaintext = ciphr_crypto::decrypt(&root, &stored.path, stored.version, &stored.value)?;
//! assert_eq!(plaintext.expose(), b"s3cret");
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

pub mod audit;
pub mod error;
pub mod lock;
pub mod migrations;
pub mod sqlite;
pub mod store;
pub mod tokens;

pub use audit::{AuditCut, AuditFilter, AuditRow, SqliteAuditDevice};
pub use error::StoreError;
pub use lock::StoreLock;
pub use migrations::SCHEMA_VERSION;
pub use sqlite::SqliteStore;
pub use store::{
    EncryptForVersion, SealState, SecretMetadata, Store, StoredVersion, VersionSummary,
    reject_reserved,
};
pub use tokens::{Authenticated, TokenRecord};
