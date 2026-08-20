//! The storage trait and the records that cross it.

use ciphr_core::{Rotation, SecretPath, SecretVersion};
use ciphr_crypto::{CryptoError, EncryptedValue, WrappedRootKey};

use crate::error::StoreError;

/// The sealed root key and the mechanism that sealed it.
///
/// Recorded together because the mechanism is part of what the record means: a
/// database says how it was sealed rather than leaving that to configuration that
/// may since have changed (ADR-5).
pub struct SealState {
    /// Identifier of the seal mechanism, from `Seal::id`.
    pub seal_id: String,
    /// The wrapped root key.
    pub wrapped_root_key: WrappedRootKey,
}

/// What is known about a secret without decrypting anything.
///
/// The metadata view exists so that the UI's secret browser and, later, the MCP
/// server can explore the inventory completely without a single value being
/// decrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMetadata {
    /// The path.
    pub path: SecretPath,
    /// The newest version, or `None` if nothing has been written yet.
    pub current_version: Option<SecretVersion>,
    /// How safe this secret is to rotate.
    pub rotation: Rotation,
    /// When the secret was created, in milliseconds since the Unix epoch, UTC.
    pub created_at: i64,
    /// When it was last written, in milliseconds since the Unix epoch, UTC.
    pub updated_at: i64,
}

/// What is known about one version without decrypting it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionSummary {
    /// The version.
    pub version: SecretVersion,
    /// When it was written, in milliseconds since the Unix epoch, UTC.
    pub created_at: i64,
    /// Which identity wrote it.
    pub created_by: String,
    /// When it was soft-deleted, if it was.
    pub deleted_at: Option<i64>,
    /// When it was crypto-shredded, if it was.
    pub destroyed_at: Option<i64>,
}

/// One stored version, ciphertext included.
///
/// The caller decrypts, which is why the path and version are part of the record:
/// they are the additional authenticated data, and passing the wrong ones fails
/// rather than returning the wrong secret.
pub struct StoredVersion {
    /// The path this version belongs to.
    pub path: SecretPath,
    /// The version.
    pub version: SecretVersion,
    /// The encrypted value.
    pub value: EncryptedValue,
    /// When it was written, in milliseconds since the Unix epoch, UTC.
    pub created_at: i64,
    /// Which identity wrote it.
    pub created_by: String,
}

/// A function that encrypts a value once its version is known.
///
/// The version is part of the authenticated data, so it has to be decided before
/// the value is encrypted — and it can only be decided inside the transaction that
/// allocates it. Passing encryption in as a callback is what keeps those two facts
/// from drifting apart: there is no window in which a value is encrypted for a
/// version other than the one it is stored under.
///
/// `FnMut` rather than `FnOnce` so that the trait stays usable behind `dyn`.
pub type EncryptForVersion<'a> =
    &'a mut dyn FnMut(SecretVersion) -> Result<EncryptedValue, CryptoError>;

/// Persistence for secrets and the seal record.
///
/// SQLite is the v1 implementation (ADR-7). The trait exists so that a different
/// backend stays possible without touching the layers above; it is deliberately
/// small, and it holds no cryptographic keys — the store sees ciphertext only.
///
/// Writers take `&mut self`. SQLite serializes writes anyway, so pretending
/// otherwise would only move the locking somewhere less visible.
pub trait Store {
    /// The schema version of the open database.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] if the database cannot be queried.
    fn schema_version(&self) -> Result<u32, StoreError>;

    /// The sealed root key, if the store has been initialized.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Corrupt`] if the record exists but is malformed, or
    /// [`StoreError::Sqlite`] on a database error.
    fn seal_state(&self) -> Result<Option<SealState>, StoreError>;

    /// Write the seal record for a fresh store.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::AlreadyInitialized`] if a record is already present.
    /// Overwriting it would orphan every secret in the database.
    fn initialize(&mut self, state: &SealState) -> Result<(), StoreError>;

    /// Replace the seal record, keeping the same root key.
    ///
    /// This is what a master key change or a seal change is: one row, rewritten.
    /// No secret is re-encrypted.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotInitialized`] if there is nothing to replace, or
    /// [`StoreError::Corrupt`] if the new record is for a different root key —
    /// which would make every stored secret unreadable.
    fn replace_seal(&mut self, state: &SealState) -> Result<(), StoreError>;

    /// Write a new version of a secret.
    ///
    /// The next version number is allocated and handed to `encrypt` inside the
    /// same transaction that stores the result.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Reserved`] for a path under `sys/`, which no caller may
    /// create; whatever `encrypt` returns, wrapped in [`StoreError::Crypto`];
    /// [`StoreError::VersionOverflow`] if the path has exhausted its version
    /// numbers; or [`StoreError::Sqlite`] on a database error. On any error the
    /// transaction is rolled back and no version is created.
    fn put(
        &mut self,
        path: &SecretPath,
        created_by: &str,
        encrypt: EncryptForVersion<'_>,
    ) -> Result<SecretVersion, StoreError>;

    /// Read a version, or the current one if `version` is `None`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`], [`StoreError::VersionNotFound`],
    /// [`StoreError::VersionDeleted`], or [`StoreError::VersionDestroyed`] as
    /// appropriate — the four are distinguished so that a caller can tell a
    /// mistake from a deliberate removal.
    fn get(
        &self,
        path: &SecretPath,
        version: Option<SecretVersion>,
    ) -> Result<StoredVersion, StoreError>;

    /// Metadata for a secret, without decrypting anything.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] if the path does not exist.
    fn metadata(&self, path: &SecretPath) -> Result<SecretMetadata, StoreError>;

    /// Summaries of every version of a secret, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] if the path does not exist.
    fn versions(&self, path: &SecretPath) -> Result<Vec<VersionSummary>, StoreError>;

    /// Every path at or below `prefix`, or every path if `prefix` is `None`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] on a database error, or
    /// [`StoreError::Path`] if the database contains a path this build rejects.
    fn list(&self, prefix: Option<&SecretPath>) -> Result<Vec<SecretPath>, StoreError>;

    /// Set how safe a secret is to rotate.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] if the path does not exist.
    fn set_rotation(&mut self, path: &SecretPath, rotation: Rotation) -> Result<(), StoreError>;

    /// Soft-delete a version. Reversible with [`Store::undelete`].
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Reserved`] for a path under `sys/`, or
    /// [`StoreError::NotFound`] / [`StoreError::VersionNotFound`] if there is
    /// nothing to delete.
    fn delete(&mut self, path: &SecretPath, version: SecretVersion) -> Result<(), StoreError>;

    /// Restore a soft-deleted version.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::VersionDestroyed`] if the version was shredded —
    /// destruction is not reversible, and pretending otherwise would restore a row
    /// whose value can never be read again.
    fn undelete(&mut self, path: &SecretPath, version: SecretVersion) -> Result<(), StoreError>;

    /// Crypto-shred a version: delete its wrapped data key.
    ///
    /// Irreversible. The ciphertext stays, and stays unreadable — including in
    /// every backup taken after this point, which is what makes shredding
    /// meaningful where deleting a row is not.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] or [`StoreError::VersionNotFound`] if
    /// there is nothing to destroy.
    fn destroy(&mut self, path: &SecretPath, version: SecretVersion) -> Result<(), StoreError>;
}

/// Refuse a path under the reserved prefix. Part of the [`Store`] contract, not of
/// one implementation.
///
/// Every implementation of [`Store::put`] and [`Store::delete`] calls this. It lives
/// here rather than in `sqlite.rs` so that a second backend inherits the rule instead
/// of having to remember it, and it lives in the storage layer rather than in a
/// caller because that is where the claim speaks: no secret may exist under `sys/`,
/// for any way in, not merely for requests that arrive over HTTP.
///
/// [`Store::put`] is the gate that matters — it is the only way a secret comes into
/// existence, so nothing reserved can be there for the other operations to find.
/// [`Store::delete`] checks anyway, because the claim names deletes too and a
/// refusal is cheaper than an argument about why it is unnecessary.
///
/// # Errors
///
/// Returns [`StoreError::Reserved`] if `path` lies under
/// [`ciphr_core::path::RESERVED_PREFIX`].
pub fn reject_reserved(path: &SecretPath) -> Result<(), StoreError> {
    if path.is_reserved() {
        return Err(StoreError::Reserved {
            path: path.as_str().to_owned(),
        });
    }
    Ok(())
}
