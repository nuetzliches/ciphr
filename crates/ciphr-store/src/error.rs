//! Storage errors.
//!
//! Paths, versions, and identity names may appear here. Values and key material
//! may not — the store never sees plaintext, and a wrapped key is ciphertext, so
//! there is nothing to leak as long as no variant grows a blob field.

use core::fmt;

use ciphr_core::path::RESERVED_PREFIX;
use ciphr_core::{PathError, RotationError, SecretVersion};
use ciphr_crypto::CryptoError;

/// Something went wrong in the storage layer.
#[derive(Debug)]
pub enum StoreError {
    /// Another process holds the store's lock.
    ///
    /// The audit chain is held in memory, so two writers against one store make the
    /// second one's records collide on a sequence number -- and because the chain
    /// only advances on a committed record, that repeats until the process
    /// restarts. Refusing here is what turns that into an error before the fact
    /// rather than a permanent `503` after it.
    Locked {
        /// The process id in the lock file, when it could be read.
        holder: Option<u32>,
    },
    /// The lock file could not be created.
    Io {
        /// What went wrong, including the path.
        detail: String,
    },
    /// No secret exists at this path.
    NotFound {
        /// The path that was requested.
        path: String,
    },
    /// The secret exists, but not at this version.
    VersionNotFound {
        /// The path that was requested.
        path: String,
        /// The version that was requested.
        version: SecretVersion,
    },
    /// The version exists but is soft-deleted.
    ///
    /// Distinct from [`Self::VersionNotFound`] so that a caller — and the audit
    /// trail — can tell "never existed" from "deliberately removed, and can be
    /// restored".
    VersionDeleted {
        /// The path that was requested.
        path: String,
        /// The version that was requested.
        version: SecretVersion,
    },
    /// The version was crypto-shredded and is permanently unreadable.
    ///
    /// Distinct from a decryption failure: this is the recorded, deliberate
    /// destruction of a value, not a sign that something is broken.
    VersionDestroyed {
        /// The path that was requested.
        path: String,
        /// The version that was requested.
        version: SecretVersion,
    },
    /// No token with this identifier exists.
    ///
    /// Only reported for administrative operations such as revoking. Authentication
    /// never says whether an identifier exists.
    TokenNotFound {
        /// The identifier that was requested.
        token_id: String,
    },
    /// The path lies under the reserved prefix, which cannot hold secrets.
    ///
    /// `sys/**` names the virtual paths the administrative operations authorize
    /// against. A secret stored there would shadow one of them, and a rule granting
    /// `read` on `sys/audit` would then authorize both the audit trail and whatever
    /// was planted under that name. Refused here rather than at a caller, so that
    /// every way in is covered — the review of 2026-08-21 found the check living in
    /// the HTTP layer alone, where the CLI walked past it (finding F2).
    Reserved {
        /// The path that was refused.
        path: String,
    },
    /// The store already holds a sealed root key.
    ///
    /// Initializing twice would overwrite the record that every secret in the
    /// database depends on, so it is refused rather than merged.
    AlreadyInitialized,
    /// The store holds no sealed root key yet.
    NotInitialized,
    /// The database was written by a newer version of ciphr.
    ///
    /// Refused rather than opened: a newer schema may store things this build
    /// does not understand, and guessing would risk writing a database that
    /// neither version can read.
    SchemaTooNew {
        /// Schema version found in the database.
        found: u32,
        /// Highest schema version this build understands.
        supported: u32,
    },
    /// A secret has had 2^32 - 1 versions. Not a realistic scenario; still not
    /// something to wrap around silently, since the version is authenticated data.
    VersionOverflow {
        /// The path that ran out of versions.
        path: String,
    },
    /// A stored row does not have the shape it must have.
    ///
    /// Carries a description of the defect, never the data.
    Corrupt {
        /// What was wrong.
        detail: String,
    },
    /// A cut of the queryable audit log was refused, and nothing was removed.
    ///
    /// Separate from [`Self::Corrupt`] because it is the opposite finding: the store is
    /// intact and the *cut* was wrong. Every refusal here happens before the delete, so
    /// the trail is exactly as it was.
    CutRefused {
        /// Why, in terms an operator can act on.
        detail: String,
    },
    /// A migration failed. Nothing from it has been applied.
    Migration {
        /// Which migration.
        version: u32,
        /// Its name, as in the file name.
        name: &'static str,
        /// What the database said.
        source: rusqlite::Error,
    },
    /// The database rejected an operation.
    Sqlite(rusqlite::Error),
    /// A cryptographic operation failed.
    Crypto(CryptoError),
    /// A stored path does not parse.
    ///
    /// Only reachable if something wrote to the database without going through
    /// this crate, which is itself worth knowing about.
    Path(PathError),
    /// A stored rotation class is not one this build knows.
    Rotation(RotationError),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locked { holder } => match holder {
                Some(pid) => write!(
                    f,
                    "the store is in use by process {pid}; stop it, run this, start it again. Two writers collide on the audit sequence and leave the first one refusing every request."
                ),
                None => f.write_str(
                    "a lock file exists whose holder cannot be verified. If no ciphr process is using this store, remove the '.lock' file beside it.",
                ),
            },
            Self::Io { detail } => f.write_str(detail),
            Self::NotFound { path } => write!(f, "no secret at '{path}'"),
            Self::VersionNotFound { path, version } => {
                write!(f, "'{path}' has no version {version}")
            }
            Self::VersionDeleted { path, version } => {
                write!(f, "version {version} of '{path}' is deleted")
            }
            Self::VersionDestroyed { path, version } => {
                write!(f, "version {version} of '{path}' was destroyed")
            }
            Self::TokenNotFound { token_id } => write!(f, "no token with id '{token_id}'"),
            Self::Reserved { path } => write!(
                f,
                "'{RESERVED_PREFIX}/' is reserved and cannot hold secrets, so '{path}' was refused"
            ),
            Self::AlreadyInitialized => f.write_str("the store is already initialized"),
            Self::NotInitialized => f.write_str("the store is not initialized"),
            Self::SchemaTooNew { found, supported } => write!(
                f,
                "database schema version {found} is newer than the supported {supported}"
            ),
            Self::VersionOverflow { path } => {
                write!(f, "'{path}' has exhausted its version numbers")
            }
            Self::Corrupt { detail } => write!(f, "stored data is malformed: {detail}"),
            Self::CutRefused { detail } => {
                write!(f, "the audit log was not cut: {detail}")
            }
            Self::Migration {
                version,
                name,
                source,
            } => write!(f, "migration {version} ({name}) failed: {source}"),
            Self::Sqlite(error) => write!(f, "database error: {error}"),
            Self::Crypto(error) => write!(f, "{error}"),
            Self::Path(error) => write!(f, "stored path is invalid: {error}"),
            Self::Rotation(error) => write!(f, "stored rotation class is invalid: {error}"),
        }
    }
}

impl core::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Migration { source, .. } => Some(source),
            Self::Sqlite(error) => Some(error),
            Self::Crypto(error) => Some(error),
            Self::Path(error) => Some(error),
            Self::Rotation(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<CryptoError> for StoreError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<PathError> for StoreError {
    fn from(error: PathError) -> Self {
        Self::Path(error)
    }
}

impl From<RotationError> for StoreError {
    fn from(error: RotationError) -> Self {
        Self::Rotation(error)
    }
}
