//! The SQLite audit device, and reading the chain back out.
//!
//! The device lives here rather than in `ciphr-audit` because this crate owns the
//! connection and the migrations. Two crates opening the same database file would be
//! two crates that can disagree about its schema.
//!
//! It holds its own connection to the same file. The alternative — sharing one
//! connection with the store — would mean the audit write and the secret write
//! contend for a single `&mut`, and the audit write has to be able to happen while a
//! request is in flight. SQLite in WAL mode is built for exactly this: one writer,
//! many readers, and a short transaction each time.

use std::path::Path;

use ciphr_audit::{AuditDevice, Chain, EncodedRecord, HASH_LEN, StoredRecord, hash_payload};
use ciphr_core::hex;
use rusqlite::{Connection, OptionalExtension, params};

use crate::error::StoreError;

/// An audit device that appends to the `audit_log` table.
pub struct SqliteAuditDevice {
    name: String,
    connection: Connection,
}

impl SqliteAuditDevice {
    /// Open an audit device on an existing ciphr database.
    ///
    /// The database must already be migrated — open it with
    /// [`crate::SqliteStore::open`] first. This does not migrate, because a device
    /// that could create its own schema could also create it in the wrong place.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] if the file cannot be opened, or
    /// [`StoreError::NotInitialized`] if it has no `audit_log` table — which means it
    /// is not a migrated ciphr database.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        let connection = Connection::open(path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "synchronous", "FULL")?;

        let exists: Option<String> = connection
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'audit_log'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if exists.is_none() {
            return Err(StoreError::NotInitialized);
        }

        Ok(Self {
            name: format!("sqlite:{}", path.display()),
            connection,
        })
    }

    /// Open an audit device on an in-memory database that is already migrated.
    ///
    /// Only useful together with a store on the same connection, which is why this
    /// takes the connection rather than a path.
    pub fn from_connection(name: impl Into<String>, connection: Connection) -> Self {
        Self {
            name: name.into(),
            connection,
        }
    }

    /// The head of the stored chain: the last sequence number and hash.
    ///
    /// Returns `None` for an empty log. Used at startup to resume the chain, so that
    /// a restart does not begin a second history in the same table.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Corrupt`] if the stored head hash is not a chain hash,
    /// or [`StoreError::Sqlite`] on a database error.
    pub fn head(&self) -> Result<Option<(u64, [u8; HASH_LEN])>, StoreError> {
        let row: Option<(i64, String)> = self
            .connection
            .query_row(
                "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let Some((seq, hash)) = row else {
            return Ok(None);
        };

        let seq = u64::try_from(seq).map_err(|_| StoreError::Corrupt {
            detail: "an audit sequence number is negative".to_owned(),
        })?;
        let mut bytes = [0_u8; HASH_LEN];
        hex::decode_into(&hash, &mut bytes).map_err(|_| StoreError::Corrupt {
            detail: "a stored audit hash is not a chain hash".to_owned(),
        })?;

        Ok(Some((seq, bytes)))
    }

    /// A chain positioned to continue the stored log.
    ///
    /// # Errors
    ///
    /// As [`Self::head`].
    pub fn resume_chain(&self) -> Result<Chain, StoreError> {
        Ok(match self.head()? {
            None => Chain::new(),
            Some((seq, hash)) => Chain::resume(seq, hash),
        })
    }

    /// Read stored records, oldest first, for verification.
    ///
    /// Returns owned rows rather than borrowing, because verification needs the whole
    /// range and a streaming borrow would hold a statement open across it.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] on a database error, or [`StoreError::Corrupt`]
    /// if a row's sequence number or hash is not readable.
    pub fn records(&self) -> Result<Vec<AuditRow>, StoreError> {
        let mut statement = self
            .connection
            .prepare("SELECT seq, hash, payload FROM audit_log ORDER BY seq")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;

        let mut records = Vec::new();
        for row in rows {
            let (seq, hash, payload) = row?;
            let seq = u64::try_from(seq).map_err(|_| StoreError::Corrupt {
                detail: "an audit sequence number is negative".to_owned(),
            })?;
            let mut hash_bytes = [0_u8; HASH_LEN];
            hex::decode_into(&hash, &mut hash_bytes).map_err(|_| StoreError::Corrupt {
                detail: "a stored audit hash is not a chain hash".to_owned(),
            })?;
            records.push(AuditRow {
                seq,
                hash: hash_bytes,
                payload,
            });
        }
        Ok(records)
    }

    /// How many records the log holds.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] on a database error.
    pub fn len(&self) -> Result<u64, StoreError> {
        let count: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Whether the log is empty.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] on a database error.
    pub fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.len()? == 0)
    }
}

/// One stored audit row.
#[derive(Debug, Clone)]
pub struct AuditRow {
    /// The sequence number.
    pub seq: u64,
    /// The stored hash.
    pub hash: [u8; HASH_LEN],
    /// The stored payload bytes.
    pub payload: String,
}

impl AuditRow {
    /// Borrow this row for verification.
    pub fn as_stored(&self) -> StoredRecord<'_> {
        StoredRecord {
            seq: self.seq,
            payload: &self.payload,
            hash: Some(self.hash),
        }
    }

    /// Whether the stored hash matches the stored payload.
    ///
    /// A cheap check that does not need the rest of the chain — useful for spotting an
    /// in-place edit in a single row.
    pub fn hash_matches(&self) -> bool {
        hash_payload(self.payload.as_bytes()) == self.hash
    }
}

impl AuditDevice for SqliteAuditDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn write(&mut self, record: &EncodedRecord) -> Result<(), String> {
        // `INSERT`, never `INSERT OR REPLACE`: a sequence number that already exists
        // means two records claim the same position in the chain, and overwriting one
        // would destroy evidence rather than record it.
        self.connection
            .execute(
                "INSERT INTO audit_log (seq, ts, prev_hash, hash, payload)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    i64::try_from(record.seq).unwrap_or(i64::MAX),
                    record.ts_millis,
                    record.prev_hash_hex(),
                    record.hash_hex(),
                    record.payload,
                ],
            )
            .map(|_| ())
            .map_err(|error| format!("could not append to audit_log: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::SqliteAuditDevice;
    use crate::sqlite::SqliteStore;
    use ciphr_audit::{Action, AuditSink, Chain, Entry, verify_from_genesis};

    fn store_with_audit(path: &std::path::Path) -> SqliteAuditDevice {
        // The store runs the migrations; the device then attaches to the same file.
        let _store = SqliteStore::open(path).expect("open store");
        SqliteAuditDevice::open(path).expect("open audit device")
    }

    #[test]
    fn refuses_a_database_that_has_no_audit_table() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("not-ciphr.db");
        rusqlite::Connection::open(&path).expect("create");

        assert!(SqliteAuditDevice::open(&path).is_err());
    }

    #[test]
    fn records_survive_a_reopen_and_the_chain_resumes() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("store.db");

        {
            let device = store_with_audit(&path);
            assert!(device.is_empty().expect("count"));
            let mut sink = AuditSink::new(vec![Box::new(device)], Chain::new()).expect("sink");
            for tick in 1..=3 {
                sink.record(&Entry::allowed(Action::Read), tick)
                    .expect("record");
            }
        }

        let device = SqliteAuditDevice::open(&path).expect("reopen");
        assert_eq!(device.len().expect("count"), 3);

        let (seq, _) = device.head().expect("head").expect("not empty");
        assert_eq!(seq, 3);

        // A restart continues the same chain rather than starting a second one.
        let mut sink = AuditSink::new(
            vec![Box::new(SqliteAuditDevice::open(&path).expect("reopen"))],
            device.resume_chain().expect("resume"),
        )
        .expect("sink");
        let written = sink
            .record(&Entry::allowed(Action::Write), 4)
            .expect("record");
        assert_eq!(written.seq, 4);

        let rows = device.records().expect("records");
        assert_eq!(rows.len(), 4);
        let verified = verify_from_genesis(rows.iter().map(super::AuditRow::as_stored))
            .expect("the chain must verify");
        assert_eq!(verified.records, 4);
        assert_eq!(verified.head_hash, written.hash);
    }

    #[test]
    fn a_row_edited_in_place_is_detected() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("store.db");

        {
            let device = store_with_audit(&path);
            let mut sink = AuditSink::new(vec![Box::new(device)], Chain::new()).expect("sink");
            for tick in 1..=3 {
                sink.record(&Entry::allowed(Action::Read), tick)
                    .expect("record");
            }
        }

        // Someone with write access edits the payload of the middle record and leaves
        // the hash column alone — the shape of a hurried cover-up.
        let connection = rusqlite::Connection::open(&path).expect("open");
        connection
            .execute(
                "UPDATE audit_log SET payload = replace(payload, '\"read\"', '\"list\"')
                 WHERE seq = 2",
                [],
            )
            .expect("tamper");

        let device = SqliteAuditDevice::open(&path).expect("reopen");
        let rows = device.records().expect("records");

        assert!(!rows[1].hash_matches(), "the edited row must not match");
        let break_at = verify_from_genesis(rows.iter().map(super::AuditRow::as_stored))
            .expect_err("the chain must not verify");
        assert_eq!(break_at.seq, 2);
    }

    #[test]
    fn a_deleted_row_is_detected() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("store.db");

        {
            let device = store_with_audit(&path);
            let mut sink = AuditSink::new(vec![Box::new(device)], Chain::new()).expect("sink");
            for tick in 1..=4 {
                sink.record(&Entry::allowed(Action::Read), tick)
                    .expect("record");
            }
        }

        rusqlite::Connection::open(&path)
            .expect("open")
            .execute("DELETE FROM audit_log WHERE seq = 3", [])
            .expect("tamper");

        let device = SqliteAuditDevice::open(&path).expect("reopen");
        let rows = device.records().expect("records");
        assert_eq!(rows.len(), 3);

        let break_at = verify_from_genesis(rows.iter().map(super::AuditRow::as_stored))
            .expect_err("a hole must be detected");
        assert_eq!(break_at.seq, 4);
    }

    #[test]
    fn the_same_sequence_number_cannot_be_written_twice() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("store.db");
        let mut device = store_with_audit(&path);

        let chain = Chain::new();
        let record = chain
            .encode(&Entry::allowed(Action::Read), 1)
            .expect("encode");

        ciphr_audit::AuditDevice::write(&mut device, &record).expect("first write");
        // Two records claiming one position is evidence, not something to overwrite.
        assert!(ciphr_audit::AuditDevice::write(&mut device, &record).is_err());
    }
}
