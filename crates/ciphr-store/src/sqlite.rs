//! The SQLite implementation of [`Store`].
//!
//! The database holds ciphertext, wrapped keys, and labels. It is not a trust
//! anchor: a stolen copy is worthless without the master key, which is what makes
//! a single embedded file an acceptable place to keep it (adversary A4).
//!
//! Pragmas are set on every connection rather than assumed:
//!
//! - `journal_mode = WAL` — readers do not block the writer.
//! - `foreign_keys = ON` — off by default in SQLite, so a version could otherwise
//!   outlive the secret it belongs to.
//! - `synchronous = FULL` — writes are rare and each one is a secret; losing the
//!   last write to a power failure is not a trade worth making here.
//! - `busy_timeout` — a concurrent writer waits instead of failing immediately.

use std::path::Path;

use ciphr_core::{Rotation, SecretPath, SecretVersion, hex};
use ciphr_crypto::{DekId, EncryptedValue, NONCE_LEN, WrappedRootKey};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::error::StoreError;
use crate::migrations::{self, SCHEMA_VERSION};
use crate::store::{
    EncryptForVersion, SealState, SecretMetadata, Store, StoredVersion, VersionSummary,
};

/// Meta keys holding the seal record. All four are written together or not at all.
const META_SEAL_ID: &str = "seal_id";
const META_ROOT_KEY_ID: &str = "root_key_id";
const META_ROOT_KEY_NONCE: &str = "root_key_nonce";
const META_ROOT_KEY_WRAPPED: &str = "root_key_wrapped";

/// A store backed by a SQLite database.
pub struct SqliteStore {
    connection: Connection,
}

impl SqliteStore {
    /// Open or create a database at `path` and migrate it to the current schema.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SchemaTooNew`] if the file was written by a newer
    /// build, or [`StoreError::Sqlite`] if it cannot be opened or migrated.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::prepare(Connection::open(path)?)
    }

    /// Open an existing database without writing to it and without migrating it.
    ///
    /// For reading the audit trail while the service is running. Verifying a chain or
    /// taking an anchor over it needs neither the master key nor the write lock — the
    /// records are not encrypted and hashing them changes nothing — and requiring
    /// either would mean the trail can only be checked with the service stopped, which
    /// is the opposite of when a check is wanted.
    ///
    /// Two consequences of read-only that are worth knowing before an incident:
    ///
    /// - **The schema is checked, not applied.** A database older than this build is
    ///   opened as it is, so a query against a table a later migration adds fails on
    ///   the query rather than being fixed silently by the reader.
    /// - **WAL needs the sidecar files.** SQLite reads a write-ahead-logged database
    ///   through its `-shm` file, which it may have to create; a directory the reader
    ///   cannot write to therefore fails to open even though nothing would be written
    ///   to the database itself. That is SQLite's behaviour rather than a choice here,
    ///   and it is the reason this returns an error instead of falling back to a
    ///   read-write connection.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SchemaTooNew`] if the file was written by a newer build,
    /// or [`StoreError::Sqlite`] if it does not exist or cannot be opened.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;

        let found: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if found > SCHEMA_VERSION {
            return Err(StoreError::SchemaTooNew {
                found,
                supported: SCHEMA_VERSION,
            });
        }

        Ok(Self { connection })
    }

    /// Open a database that exists only for the lifetime of this value.
    ///
    /// Used by tests. It is not a "test mode": the schema, the queries, and the
    /// code paths are the same ones production uses, which is the only reason it is
    /// acceptable to test against.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] if the database cannot be created.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::prepare(Connection::open_in_memory()?)
    }

    fn prepare(mut connection: Connection) -> Result<Self, StoreError> {
        // An in-memory database reports `memory` here rather than `wal`; both are
        // acceptable, so the returned value is not checked against an expectation.
        connection.pragma_update_and_check(None, "journal_mode", "WAL", |_| Ok(()))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;

        migrations::apply(&mut connection)?;
        Ok(Self { connection })
    }

    /// The open connection, for the sibling modules in this crate.
    ///
    /// Crate-private: the point of this crate is that SQL lives in one place, and a
    /// caller that could reach the connection could write its own.
    pub(crate) fn connection(&self) -> &Connection {
        &self.connection
    }

    fn secret_id(&self, path: &SecretPath) -> Result<Option<(i64, u32, Rotation)>, StoreError> {
        let row = self
            .connection
            .query_row(
                "SELECT id, current_version, rotation FROM secrets WHERE path = ?1",
                params![path.as_str()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;

        match row {
            None => Ok(None),
            Some((id, current, rotation)) => {
                let current = u32::try_from(current).map_err(|_| StoreError::Corrupt {
                    detail: format!("current_version of '{path}' is out of range"),
                })?;
                Ok(Some((id, current, Rotation::parse(&rotation)?)))
            }
        }
    }

    fn require_secret(&self, path: &SecretPath) -> Result<(i64, u32, Rotation), StoreError> {
        self.secret_id(path)?.ok_or_else(|| StoreError::NotFound {
            path: path.as_str().to_owned(),
        })
    }
}

impl Store for SqliteStore {
    fn schema_version(&self) -> Result<u32, StoreError> {
        Ok(self
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))?)
    }

    fn seal_state(&self) -> Result<Option<SealState>, StoreError> {
        let seal_id = read_meta(&self.connection, META_SEAL_ID)?;
        let root_key_id = read_meta(&self.connection, META_ROOT_KEY_ID)?;
        let nonce = read_meta(&self.connection, META_ROOT_KEY_NONCE)?;
        let wrapped = read_meta(&self.connection, META_ROOT_KEY_WRAPPED)?;

        match (seal_id, root_key_id, nonce, wrapped) {
            (None, None, None, None) => Ok(None),
            (Some(seal_id), Some(root_key_id), Some(nonce), Some(wrapped)) => {
                let id = ciphr_crypto::RootKeyId::from_hex(&root_key_id).map_err(|_| {
                    StoreError::Corrupt {
                        detail: "the stored root key identifier is not valid hexadecimal"
                            .to_owned(),
                    }
                })?;
                Ok(Some(SealState {
                    seal_id,
                    wrapped_root_key: WrappedRootKey {
                        id,
                        nonce: decode_nonce(&nonce, "root key nonce")?,
                        ciphertext: hex::decode(&wrapped).map_err(|_| StoreError::Corrupt {
                            detail: "the wrapped root key is not valid hexadecimal".to_owned(),
                        })?,
                    },
                }))
            }
            // A partial record means an interrupted write or a hand edit. Refusing
            // is the only safe answer: guessing which half is authoritative could
            // mean unsealing with the wrong record.
            _ => Err(StoreError::Corrupt {
                detail: "the seal record is incomplete".to_owned(),
            }),
        }
    }

    fn initialize(&mut self, state: &SealState) -> Result<(), StoreError> {
        if self.seal_state()?.is_some() {
            return Err(StoreError::AlreadyInitialized);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        write_seal(&transaction, state)?;
        transaction.commit()?;
        Ok(())
    }

    fn replace_seal(&mut self, state: &SealState) -> Result<(), StoreError> {
        let current = self.seal_state()?.ok_or(StoreError::NotInitialized)?;

        // The root key identifier must not change: a re-wrap protects the *same*
        // key. A different identifier means a different key, and storing it would
        // make every secret in the database unreadable.
        if current.wrapped_root_key.id != state.wrapped_root_key.id {
            return Err(StoreError::Corrupt {
                detail: "the replacement seal record is for a different root key".to_owned(),
            });
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        write_seal(&transaction, state)?;
        transaction.commit()?;
        Ok(())
    }

    fn put(
        &mut self,
        path: &SecretPath,
        created_by: &str,
        encrypt: EncryptForVersion<'_>,
    ) -> Result<SecretVersion, StoreError> {
        let now = now_millis();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let existing = transaction
            .query_row(
                "SELECT id, current_version FROM secrets WHERE path = ?1",
                params![path.as_str()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;

        let (secret_id, current) = if let Some((id, current)) = existing {
            (id, current)
        } else {
            transaction.execute(
                "INSERT INTO secrets (path, current_version, rotation, created_at, updated_at)
                 VALUES (?1, 0, ?2, ?3, ?3)",
                params![path.as_str(), Rotation::default().as_str(), now],
            )?;
            (transaction.last_insert_rowid(), 0)
        };

        let current = u32::try_from(current).map_err(|_| StoreError::Corrupt {
            detail: format!("current_version of '{path}' is out of range"),
        })?;
        let next = match SecretVersion::new(current) {
            None => SecretVersion::FIRST,
            Some(version) => version.next().ok_or_else(|| StoreError::VersionOverflow {
                path: path.as_str().to_owned(),
            })?,
        };

        // Encryption happens here, inside the transaction, because the version is
        // authenticated data: it must be the number this value is actually stored
        // under. See `EncryptForVersion`.
        let value = encrypt(next)?;

        transaction.execute(
            "INSERT INTO secret_versions (
                 secret_id, version, dek_id, dek_nonce, wrapped_dek,
                 value_nonce, ciphertext, created_at, created_by
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                secret_id,
                i64::from(next.get()),
                value.dek_id.to_hex(),
                value.dek_nonce.as_slice(),
                value.wrapped_dek,
                value.value_nonce.as_slice(),
                value.ciphertext,
                now,
                created_by,
            ],
        )?;
        transaction.execute(
            "UPDATE secrets SET current_version = ?2, updated_at = ?3 WHERE id = ?1",
            params![secret_id, i64::from(next.get()), now],
        )?;

        transaction.commit()?;
        Ok(next)
    }

    fn get(
        &self,
        path: &SecretPath,
        version: Option<SecretVersion>,
    ) -> Result<StoredVersion, StoreError> {
        let (secret_id, current, _) = self.require_secret(path)?;

        let wanted = match version {
            Some(version) => version,
            None => SecretVersion::new(current).ok_or_else(|| StoreError::NotFound {
                path: path.as_str().to_owned(),
            })?,
        };

        let row = self
            .connection
            .query_row(
                "SELECT dek_id, dek_nonce, wrapped_dek, value_nonce, ciphertext,
                        created_at, created_by, deleted_at, destroyed_at
                 FROM secret_versions WHERE secret_id = ?1 AND version = ?2",
                params![secret_id, i64::from(wanted.get())],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Option<i64>>(7)?,
                        row.get::<_, Option<i64>>(8)?,
                    ))
                },
            )
            .optional()?;

        let (
            dek_id,
            dek_nonce,
            wrapped_dek,
            value_nonce,
            ciphertext,
            created_at,
            created_by,
            deleted_at,
            destroyed_at,
        ) = row.ok_or_else(|| StoreError::VersionNotFound {
            path: path.as_str().to_owned(),
            version: wanted,
        })?;

        if destroyed_at.is_some() {
            return Err(StoreError::VersionDestroyed {
                path: path.as_str().to_owned(),
                version: wanted,
            });
        }
        if deleted_at.is_some() {
            return Err(StoreError::VersionDeleted {
                path: path.as_str().to_owned(),
                version: wanted,
            });
        }

        Ok(StoredVersion {
            path: path.clone(),
            version: wanted,
            value: EncryptedValue {
                dek_id: DekId::from_hex(&dek_id).map_err(|_| StoreError::Corrupt {
                    detail: "a stored data key identifier is not valid hexadecimal".to_owned(),
                })?,
                dek_nonce: to_nonce(&dek_nonce, "data key nonce")?,
                wrapped_dek,
                value_nonce: to_nonce(&value_nonce, "value nonce")?,
                ciphertext,
            },
            created_at,
            created_by,
        })
    }

    fn metadata(&self, path: &SecretPath) -> Result<SecretMetadata, StoreError> {
        let (_, current, rotation) = self.require_secret(path)?;
        let (created_at, updated_at) = self.connection.query_row(
            "SELECT created_at, updated_at FROM secrets WHERE path = ?1",
            params![path.as_str()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )?;

        Ok(SecretMetadata {
            path: path.clone(),
            current_version: SecretVersion::new(current),
            rotation,
            created_at,
            updated_at,
        })
    }

    fn versions(&self, path: &SecretPath) -> Result<Vec<VersionSummary>, StoreError> {
        let (secret_id, _, _) = self.require_secret(path)?;

        let mut statement = self.connection.prepare(
            "SELECT version, created_at, created_by, deleted_at, destroyed_at
             FROM secret_versions WHERE secret_id = ?1 ORDER BY version",
        )?;
        let rows = statement.query_map(params![secret_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })?;

        let mut summaries = Vec::new();
        for row in rows {
            let (version, created_at, created_by, deleted_at, destroyed_at) = row?;
            let version = u32::try_from(version)
                .ok()
                .and_then(SecretVersion::new)
                .ok_or_else(|| StoreError::Corrupt {
                    detail: format!("'{path}' has a version number out of range"),
                })?;
            summaries.push(VersionSummary {
                version,
                created_at,
                created_by,
                deleted_at,
                destroyed_at,
            });
        }
        Ok(summaries)
    }

    fn list(&self, prefix: Option<&SecretPath>) -> Result<Vec<SecretPath>, StoreError> {
        let mut paths = Vec::new();

        match prefix {
            None => {
                let mut statement = self
                    .connection
                    .prepare("SELECT path FROM secrets ORDER BY path")?;
                let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
                for row in rows {
                    paths.push(SecretPath::parse(&row?)?);
                }
            }
            Some(prefix) => {
                // A range scan rather than LIKE or GLOB. Both of those have
                // metacharacters that would need escaping, and a path may legally
                // contain `%`, `_`, or `[`. The bounds below need no escaping at
                // all: every descendant starts with `prefix/`, and `0` is the byte
                // after `/`, so the half-open range is exactly the subtree.
                let lower = format!("{}/", prefix.as_str());
                let upper = format!("{}0", prefix.as_str());
                let mut statement = self.connection.prepare(
                    "SELECT path FROM secrets
                     WHERE path = ?1 OR (path >= ?2 AND path < ?3)
                     ORDER BY path",
                )?;
                let rows = statement.query_map(params![prefix.as_str(), lower, upper], |row| {
                    row.get::<_, String>(0)
                })?;
                for row in rows {
                    paths.push(SecretPath::parse(&row?)?);
                }
            }
        }

        Ok(paths)
    }

    fn set_rotation(&mut self, path: &SecretPath, rotation: Rotation) -> Result<(), StoreError> {
        let changed = self.connection.execute(
            "UPDATE secrets SET rotation = ?2, updated_at = ?3 WHERE path = ?1",
            params![path.as_str(), rotation.as_str(), now_millis()],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound {
                path: path.as_str().to_owned(),
            });
        }
        Ok(())
    }

    fn delete(&mut self, path: &SecretPath, version: SecretVersion) -> Result<(), StoreError> {
        let (secret_id, _, _) = self.require_secret(path)?;
        let changed = self.connection.execute(
            "UPDATE secret_versions SET deleted_at = ?3
             WHERE secret_id = ?1 AND version = ?2 AND deleted_at IS NULL",
            params![secret_id, i64::from(version.get()), now_millis()],
        )?;
        if changed == 0 {
            // Either there is no such version, or it was already deleted. The
            // latter is not an error: deleting a deleted version leaves the world
            // in the state the caller asked for.
            self.version_exists(path, secret_id, version).map(|_| ())?;
        }
        Ok(())
    }

    fn undelete(&mut self, path: &SecretPath, version: SecretVersion) -> Result<(), StoreError> {
        let (secret_id, _, _) = self.require_secret(path)?;
        let destroyed = self.version_exists(path, secret_id, version)?;
        if destroyed {
            return Err(StoreError::VersionDestroyed {
                path: path.as_str().to_owned(),
                version,
            });
        }
        self.connection.execute(
            "UPDATE secret_versions SET deleted_at = NULL
             WHERE secret_id = ?1 AND version = ?2",
            params![secret_id, i64::from(version.get())],
        )?;
        Ok(())
    }

    fn destroy(&mut self, path: &SecretPath, version: SecretVersion) -> Result<(), StoreError> {
        let (secret_id, _, _) = self.require_secret(path)?;
        self.version_exists(path, secret_id, version)?;

        // Emptying `wrapped_dek` is the destruction: without the wrapped data key
        // the ciphertext cannot be decrypted by anyone, ever, including from a
        // backup taken after this write.
        self.connection.execute(
            "UPDATE secret_versions
             SET wrapped_dek = X'', destroyed_at = COALESCE(destroyed_at, ?3)
             WHERE secret_id = ?1 AND version = ?2",
            params![secret_id, i64::from(version.get()), now_millis()],
        )?;
        Ok(())
    }
}

impl SqliteStore {
    /// Whether the version exists, and whether it is destroyed.
    ///
    /// Takes the path as well as the row id, so that an error message names the
    /// path a caller asked about rather than an internal identifier.
    fn version_exists(
        &self,
        path: &SecretPath,
        secret_id: i64,
        version: SecretVersion,
    ) -> Result<bool, StoreError> {
        let destroyed: Option<Option<i64>> = self
            .connection
            .query_row(
                "SELECT destroyed_at FROM secret_versions WHERE secret_id = ?1 AND version = ?2",
                params![secret_id, i64::from(version.get())],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?;

        match destroyed {
            None => Err(StoreError::VersionNotFound {
                path: path.as_str().to_owned(),
                version,
            }),
            Some(destroyed_at) => Ok(destroyed_at.is_some()),
        }
    }
}

fn read_meta(connection: &Connection, key: &str) -> Result<Option<String>, StoreError> {
    Ok(connection
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .optional()?)
}

fn write_seal(connection: &Connection, state: &SealState) -> Result<(), StoreError> {
    let entries = [
        (META_SEAL_ID, state.seal_id.clone()),
        (META_ROOT_KEY_ID, state.wrapped_root_key.id.to_hex()),
        (
            META_ROOT_KEY_NONCE,
            hex::encode(&state.wrapped_root_key.nonce),
        ),
        (
            META_ROOT_KEY_WRAPPED,
            hex::encode(&state.wrapped_root_key.ciphertext),
        ),
    ];
    for (key, value) in entries {
        connection.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
    }
    Ok(())
}

fn decode_nonce(input: &str, what: &str) -> Result<[u8; NONCE_LEN], StoreError> {
    let bytes = hex::decode(input).map_err(|_| StoreError::Corrupt {
        detail: format!("the stored {what} is not valid hexadecimal"),
    })?;
    to_nonce(&bytes, what)
}

fn to_nonce(bytes: &[u8], what: &str) -> Result<[u8; NONCE_LEN], StoreError> {
    <[u8; NONCE_LEN]>::try_from(bytes).map_err(|_| StoreError::Corrupt {
        detail: format!("the stored {what} is not {NONCE_LEN} bytes"),
    })
}

/// Milliseconds since the Unix epoch, UTC.
///
/// A clock that reports a time before the epoch would produce a negative value;
/// that is stored as-is rather than clamped, because silently rewriting a
/// timestamp is worse than an obviously wrong one.
pub(crate) fn now_millis() -> i64 {
    let now = std::time::SystemTime::now();
    match now.duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX),
        Err(before) => -i64::try_from(before.duration().as_millis()).unwrap_or(i64::MAX),
    }
}

/// The schema version this build produces.
pub const fn schema_version() -> u32 {
    SCHEMA_VERSION
}
