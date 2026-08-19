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
//!
//! The same connection is what lets the table be **cut** while the service runs. A cut
//! removes the oldest records and records where it cut, and it needs neither the master
//! key nor the store lock — it touches no secret and no row a request reads. What it
//! does need is the anchor that makes the remainder verifiable, and writing that is the
//! caller's job: see [`SqliteAuditDevice::cut`].

use std::path::Path;

use ciphr_audit::{AuditDevice, Chain, EncodedRecord, HASH_LEN, Start, StoredRecord, hash_payload};
use ciphr_core::hex;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::error::StoreError;
use crate::sqlite::SqliteStore;

/// A hash column, as a chain hash.
fn decode_hash(stored: &str) -> Result<[u8; HASH_LEN], StoreError> {
    let mut bytes = [0_u8; HASH_LEN];
    hex::decode_into(stored, &mut bytes).map_err(|_| StoreError::Corrupt {
        detail: "a stored audit hash is not a chain hash".to_owned(),
    })?;
    Ok(bytes)
}

/// A count or sequence column, as the unsigned number it must be.
fn decode_count(stored: i64) -> Result<u64, StoreError> {
    u64::try_from(stored).map_err(|_| StoreError::Corrupt {
        detail: "an audit sequence number or count is negative".to_owned(),
    })
}

/// The last sequence number and hash in `audit_log`, or `None` for an empty table.
fn head_of(connection: &Connection) -> Result<Option<(u64, [u8; HASH_LEN])>, StoreError> {
    let row: Option<(i64, String)> = connection
        .query_row(
            "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    let Some((seq, hash)) = row else {
        return Ok(None);
    };
    Ok(Some((decode_count(seq)?, decode_hash(&hash)?)))
}

/// Whether this database has the table that records cuts.
///
/// A database migrated by a build older than the one that introduced cutting does not,
/// and cannot have been cut by it either: the table and the operation arrived in the
/// same migration.
fn has_cut_table(connection: &Connection) -> Result<bool, StoreError> {
    let found: Option<String> = connection
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'audit_cut'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

/// The refusal a database that cannot record a cut has earned, or `Ok(())`.
///
/// Checked twice on the way to a cut, and the message lives here so the two cannot come
/// to disagree. The first check belongs to the caller, *before* it writes the anchor: a
/// refusal discovered afterwards would leave an anchor in the file for a cut that never
/// happened. The second is inside the transaction, so this crate's own API stays safe for
/// a caller that skipped the first.
fn require_cut_table(connection: &Connection) -> Result<(), StoreError> {
    if has_cut_table(connection)? {
        return Ok(());
    }
    Err(StoreError::CutRefused {
        detail: "this database has no table to record a cut in: it was migrated by a build from \
                 before cutting existed, and removing records without recording where would leave \
                 the remainder unverifiable"
            .to_owned(),
    })
}

/// The most recently recorded cut, or `None` if the log has never been cut.
///
/// `None` also for a database whose schema predates the table, per [`has_cut_table`].
/// That absence is not papered over anywhere else: a store that *was* cut and then had
/// the table dropped verifies as a chain that does not begin at sequence 1, which is the
/// break it should be.
fn latest_cut_of(connection: &Connection) -> Result<Option<AuditCut>, StoreError> {
    if !has_cut_table(connection)? {
        return Ok(None);
    }

    let row: Option<(i64, i64, String, i64, Option<String>)> = connection
        .query_row(
            "SELECT cut_at, seq, hash, removed, anchor FROM audit_cut ORDER BY id DESC LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;

    let Some((cut_at, seq, hash, removed, anchor)) = row else {
        return Ok(None);
    };

    Ok(Some(AuditCut {
        cut_at,
        seq: decode_count(seq)?,
        hash: decode_hash(&hash)?,
        removed: decode_count(removed)?,
        anchor,
    }))
}

/// Where verification of this store's queryable trail begins.
fn start_of(connection: &Connection) -> Result<Start, StoreError> {
    Ok(match latest_cut_of(connection)? {
        None => Start::Genesis,
        Some(cut) => cut.as_start(),
    })
}

/// The chain a restart has to continue, from the stored head and the recorded cut.
///
/// Two states are refused rather than continued, both for the same fail-closed reason:
/// continuing would produce a trail that reads as consistent while hiding a removal.
///
/// - **The log ends at or before a recorded cut.** Records that survived the cut were
///   removed afterwards without one.
/// - **The log is empty and a cut is recorded.** A cut never empties the table, so this
///   cannot be a state that cutting produced.
fn chain_to_continue(connection: &Connection) -> Result<Chain, StoreError> {
    let head = head_of(connection)?;
    let cut = latest_cut_of(connection)?;

    match (head, cut) {
        (Some((seq, _)), Some(cut)) if cut.seq >= seq => Err(StoreError::Corrupt {
            detail: format!(
                "a cut through sequence {} is recorded, but the audit log ends at {seq}: records \
                 that survived the cut were removed without recording one",
                cut.seq
            ),
        }),
        (Some((seq, hash)), _) => Ok(Chain::resume(seq, hash)),
        (None, Some(cut)) => Err(StoreError::Corrupt {
            detail: format!(
                "the audit log is empty, but a cut through sequence {} is recorded, and a cut \
                 never empties it",
                cut.seq
            ),
        }),
        (None, None) => Ok(Chain::new()),
    }
}

/// One recorded cut of the queryable audit log.
///
/// A claim by whoever wrote the database, not evidence — see `004_audit_cut.sql`. The
/// anchor taken at the same sequence number is the copy that lives outside the store,
/// and [`ciphr_audit::verify_with_anchor`] is where the two are compared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditCut {
    /// When the cut ran, in milliseconds since the Unix epoch.
    pub cut_at: i64,
    /// The last sequence number the cut removed.
    pub seq: u64,
    /// That record's hash: the predecessor the first surviving record chains to.
    pub hash: [u8; HASH_LEN],
    /// How many records the cut removed.
    pub removed: u64,
    /// Where the anchor for this cut was appended, if it was given a file.
    pub anchor: Option<String>,
}

impl AuditCut {
    /// This cut as a starting point for verification.
    pub const fn as_start(&self) -> Start {
        Start::AfterCut {
            seq: self.seq,
            hash: self.hash,
        }
    }
}

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
        head_of(&self.connection)
    }

    /// The most recently recorded cut of this log, or `None` if it has never been cut.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Corrupt`] if the stored row is not readable, or
    /// [`StoreError::Sqlite`] on a database error.
    pub fn latest_cut(&self) -> Result<Option<AuditCut>, StoreError> {
        latest_cut_of(&self.connection)
    }

    /// A chain positioned to continue the stored log.
    ///
    /// # Errors
    ///
    /// As [`Self::head`], plus [`StoreError::Corrupt`] where the log and the recorded
    /// cut contradict each other.
    pub fn resume_chain(&self) -> Result<Chain, StoreError> {
        chain_to_continue(&self.connection)
    }

    /// Remove every record up to and including `through_seq`, and record the cut.
    ///
    /// The delete and the record of it are one transaction. A cut that removed records
    /// without leaving behind the sequence number and hash they ended at would make
    /// everything that survived it unverifiable, which is the one outcome retention must
    /// not produce.
    ///
    /// **This does not write the anchor, and it cannot check that one exists.** What is
    /// kept in this database is a claim by whoever can write this database; the evidence
    /// is the copy outside it. The caller writes that copy *before* calling this, so
    /// that a crash in between leaves an anchor over a record still present — which
    /// verifies — rather than a cut nothing outside the store can attest to.
    ///
    /// `through_hash` is what the caller verified the record at `through_seq` to hash
    /// to. It is checked against the stored row again here, so a cut cannot be committed
    /// on a verification that no longer describes the table.
    ///
    /// # Errors
    ///
    /// [`StoreError::CutRefused`] if the record at `through_seq` is absent or is not the
    /// one that was verified, if the cut would leave the queryable log empty, if a cut
    /// through a sequence number at least as high is already recorded, or if this
    /// database's schema predates the table that records cuts.
    pub fn cut(
        &mut self,
        through_seq: u64,
        through_hash: [u8; HASH_LEN],
        now_millis: i64,
        anchor: Option<&str>,
    ) -> Result<AuditCut, StoreError> {
        let refused = |detail: String| StoreError::CutRefused { detail };

        let through = i64::try_from(through_seq)
            .map_err(|_| refused(format!("sequence {through_seq} is out of range")))?;

        require_cut_table(&self.connection)?;

        // `Immediate`, so the write lock is taken at the start rather than upgraded
        // half-way through. Upgrading is what deadlocks against the process appending to
        // this table, which is normally the running server.
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        // The record the cut ends at has to be the one the caller verified. A different
        // hash means the table is not what that verification described, and cutting on a
        // stale verification would remove records nothing checked.
        let stored: Option<String> = transaction
            .query_row(
                "SELECT hash FROM audit_log WHERE seq = ?1",
                params![through],
                |row| row.get(0),
            )
            .optional()?;
        let Some(stored) = stored else {
            return Err(refused(format!(
                "the audit log has no record at sequence {through_seq}"
            )));
        };
        if decode_hash(&stored)? != through_hash {
            return Err(refused(format!(
                "the record at sequence {through_seq} is not the one that was verified"
            )));
        }

        // Never leave the table empty. An empty queryable log has no head, and a service
        // resuming from no head would begin a second chain at sequence one in a table
        // that had a million records — two histories, one table, no way to compare them.
        let remaining: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM audit_log WHERE seq > ?1",
            params![through],
            |row| row.get(0),
        )?;
        if remaining == 0 {
            return Err(refused(format!(
                "cutting through sequence {through_seq} would leave the queryable log empty"
            )));
        }

        if let Some(previous) = latest_cut_of(&transaction)?
            && previous.seq >= through_seq
        {
            return Err(refused(format!(
                "a cut through sequence {} is already recorded, so cutting through \
                 {through_seq} would move it backwards",
                previous.seq
            )));
        }

        let removed =
            transaction.execute("DELETE FROM audit_log WHERE seq <= ?1", params![through])?;
        let removed = u64::try_from(removed).unwrap_or(0);

        transaction.execute(
            "INSERT INTO audit_cut (cut_at, seq, hash, removed, anchor)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                now_millis,
                through,
                hex::encode(&through_hash),
                i64::try_from(removed).unwrap_or(i64::MAX),
                anchor,
            ],
        )?;

        transaction.commit()?;

        Ok(AuditCut {
            cut_at: now_millis,
            seq: through_seq,
            hash: through_hash,
            removed,
            anchor: anchor.map(str::to_owned),
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
    use crate::error::StoreError;
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

    /// A store with `count` audit records, closed again so the file can be reopened.
    fn store_with_records(path: &std::path::Path, count: i64) {
        let device = store_with_audit(path);
        let mut sink = AuditSink::new(vec![Box::new(device)], Chain::new()).expect("sink");
        for tick in 1..=count {
            sink.record(&Entry::allowed(Action::Read), tick)
                .expect("record");
        }
    }

    /// The hash of the record at `seq`, as the cut's caller would have verified it.
    fn hash_at(device: &SqliteAuditDevice, seq: u64) -> [u8; ciphr_audit::HASH_LEN] {
        device
            .records()
            .expect("records")
            .into_iter()
            .find(|row| row.seq == seq)
            .expect("the record must exist")
            .hash
    }

    #[test]
    fn what_a_cut_leaves_behind_verifies_from_the_recorded_cut() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("store.db");
        store_with_records(&path, 6);

        let mut device = SqliteAuditDevice::open(&path).expect("reopen");
        let through = hash_at(&device, 3);
        let cut = device
            .cut(3, through, 1_767_225_600_000, Some("anchors.jsonl"))
            .expect("cut");

        assert_eq!(cut.seq, 3);
        assert_eq!(cut.removed, 3);
        assert_eq!(cut.hash, through);
        assert_eq!(device.len().expect("count"), 3);

        // From genesis the remainder is a chain that begins in the wrong place, which is
        // what a removal looks like -- and a cut is a removal. What tells them apart is
        // the recorded start.
        let rows = device.records().expect("records");
        assert!(
            verify_from_genesis(rows.iter().map(super::AuditRow::as_stored)).is_err(),
            "a cut trail cannot verify from genesis, and pretending otherwise would mean \
             verifying nothing"
        );

        let recorded = device.latest_cut().expect("cut record").expect("recorded");
        assert_eq!(recorded, cut);
        let verified = ciphr_audit::verify_from(
            recorded.as_start(),
            rows.iter().map(super::AuditRow::as_stored),
        )
        .expect("the remainder must verify from the cut");
        assert_eq!(verified.records, 3);
        assert_eq!(verified.head_seq, 6);
    }

    #[test]
    fn an_anchor_taken_at_the_cut_agrees_with_what_the_store_recorded() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("store.db");
        store_with_records(&path, 5);

        let mut device = SqliteAuditDevice::open(&path).expect("reopen");

        // The anchor is taken over the prefix the cut is about to remove -- which is what
        // makes it the anchor *at* the cut -- and then the cut happens.
        let rows = device.records().expect("records");
        let prefix: Vec<_> = rows[..2].iter().map(super::AuditRow::as_stored).collect();
        let anchor = ciphr_audit::Anchor::over(
            &verify_from_genesis(prefix.iter().copied()).expect("verify prefix"),
            1_767_225_600_000,
        );

        let cut = device
            .cut(anchor.seq, anchor.hash, 1_767_225_600_000, None)
            .expect("cut");
        assert_eq!(cut.seq, 2);
        assert_eq!(cut.anchor, None);

        let rows = device.records().expect("records");
        let survivors: Vec<_> = rows.iter().map(super::AuditRow::as_stored).collect();
        let verified = ciphr_audit::verify_with_anchor(&anchor, cut.as_start(), &survivors)
            .expect("the anchor at the cut must agree with the recorded cut");
        assert_eq!(verified.head_seq, 5);
    }

    #[test]
    fn a_cut_that_would_empty_the_queryable_log_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("store.db");
        store_with_records(&path, 3);

        let mut device = SqliteAuditDevice::open(&path).expect("reopen");
        let through = hash_at(&device, 3);

        // An empty table has no head, and a service resuming from no head would start a
        // second chain at sequence one in the same table.
        let refused = device
            .cut(3, through, 1, None)
            .expect_err("cutting the whole log must be refused");
        assert!(
            matches!(refused, StoreError::CutRefused { .. }),
            "got {refused:?}"
        );
        assert_eq!(device.len().expect("count"), 3, "nothing was removed");
        assert!(device.latest_cut().expect("cut record").is_none());
    }

    #[test]
    fn a_cut_on_a_hash_that_is_not_the_stored_record_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("store.db");
        store_with_records(&path, 4);

        let mut device = SqliteAuditDevice::open(&path).expect("reopen");
        // Record 1's hash offered as record 2's: what cutting on a verification that no
        // longer describes the table looks like.
        let wrong = hash_at(&device, 1);

        let refused = device
            .cut(2, wrong, 1, None)
            .expect_err("the hash must be checked against the row");
        assert!(
            matches!(refused, StoreError::CutRefused { .. }),
            "got {refused:?}"
        );
        assert_eq!(device.len().expect("count"), 4, "nothing was removed");

        // And a sequence number that is not in the table at all.
        let absent = device
            .cut(9, wrong, 1, None)
            .expect_err("a record that is not there cannot be cut through");
        assert!(
            matches!(absent, StoreError::CutRefused { .. }),
            "got {absent:?}"
        );
    }

    #[test]
    fn a_second_cut_cannot_move_the_first_one_backwards() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("store.db");
        store_with_records(&path, 8);

        let mut device = SqliteAuditDevice::open(&path).expect("reopen");
        let first = hash_at(&device, 4);
        device.cut(4, first, 1, None).expect("first cut");

        // Cutting through 4 again: the records are gone, so this can only be a cut record
        // being rewritten to describe less than was removed.
        let refused = device
            .cut(4, first, 2, None)
            .expect_err("a cut may not be recorded twice");
        assert!(
            matches!(refused, StoreError::CutRefused { .. }),
            "got {refused:?}"
        );

        let second = hash_at(&device, 6);
        let cut = device.cut(6, second, 2, None).expect("second cut");
        assert_eq!(cut.removed, 2);
        assert_eq!(
            device
                .latest_cut()
                .expect("cut record")
                .expect("recorded")
                .seq,
            6,
            "the newest cut is the one verification starts from"
        );
    }

    #[test]
    fn a_restart_after_a_cut_continues_the_sequence_rather_than_restarting_it() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("store.db");
        store_with_records(&path, 5);

        {
            let mut device = SqliteAuditDevice::open(&path).expect("reopen");
            let through = hash_at(&device, 3);
            device.cut(3, through, 1, None).expect("cut");
        }

        let device = SqliteAuditDevice::open(&path).expect("reopen");
        let mut sink = AuditSink::new(
            vec![Box::new(SqliteAuditDevice::open(&path).expect("reopen"))],
            device.resume_chain().expect("resume"),
        )
        .expect("sink");
        let written = sink
            .record(&Entry::allowed(Action::Write), 6)
            .expect("record");
        assert_eq!(written.seq, 6);

        let rows = device.records().expect("records");
        let start = device
            .latest_cut()
            .expect("cut")
            .expect("recorded")
            .as_start();
        let verified = ciphr_audit::verify_from(start, rows.iter().map(super::AuditRow::as_stored))
            .expect("the chain must still verify across the restart");
        assert_eq!(verified.head_hash, written.hash);
    }

    #[test]
    fn a_database_that_cannot_record_a_cut_refuses_before_it_removes_anything() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("store.db");
        store_with_records(&path, 4);

        // A database migrated by a build from before cutting existed. Dropping the table
        // is how a test reaches that state; an upgrade that has not restarted the service
        // yet is how an operator does.
        rusqlite::Connection::open(&path)
            .expect("open")
            .execute("DROP TABLE audit_cut", [])
            .expect("drop");

        // The store answers before the caller writes an anchor, which is the point: the
        // same refusal arriving after one would leave a line in the anchor file for a cut
        // that never happened.
        let store = SqliteStore::open_read_only(&path).expect("open read-only");
        let early = store
            .require_audit_cut_support()
            .expect_err("a database with no cut table cannot be cut");
        assert!(
            matches!(early, StoreError::CutRefused { .. }),
            "got {early:?}"
        );

        let mut device = SqliteAuditDevice::open(&path).expect("reopen");
        let hash = hash_at(&device, 2);
        let refused = device
            .cut(2, hash, 1, None)
            .expect_err("and cutting refuses again inside the transaction");
        assert!(
            matches!(refused, StoreError::CutRefused { .. }),
            "got {refused:?}"
        );
        assert_eq!(device.len().expect("count"), 4, "nothing was removed");
    }

    #[test]
    fn a_log_emptied_behind_a_recorded_cut_refuses_to_resume() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("store.db");
        store_with_records(&path, 5);

        {
            let mut device = SqliteAuditDevice::open(&path).expect("reopen");
            let through = hash_at(&device, 3);
            device.cut(3, through, 1, None).expect("cut");
        }

        // What is left after a cut, removed by hand. Resuming from no head would begin a
        // second chain at sequence one; resuming from the cut would make records 4 and 5
        // disappear without a trace. Neither is acceptable, so it refuses.
        rusqlite::Connection::open(&path)
            .expect("open")
            .execute("DELETE FROM audit_log", [])
            .expect("tamper");

        let device = SqliteAuditDevice::open(&path).expect("reopen");
        let refused = device
            .resume_chain()
            .expect_err("an empty log behind a recorded cut is not a state a cut produces");
        assert!(
            matches!(refused, StoreError::Corrupt { .. }),
            "got {refused:?}"
        );
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

/// Filters for reading the audit log.
///
/// Server-side filtering exists because the alternative is a client pulling the
/// whole log and filtering it locally — which for the MCP server would mean pulling
/// the audit trail into a model context to answer "who read this last week"
/// (ADR-13), and for the UI would mean shipping megabytes to render a page.
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    /// Return at most this many entries. The caller is expected to clamp it.
    pub limit: u32,
    /// Only entries with a sequence number greater than this.
    pub after_seq: Option<u64>,
    /// Only entries at or after this time, in milliseconds since the Unix epoch.
    pub since: Option<i64>,
    /// Only entries for this identity.
    pub identity: Option<String>,
    /// Only entries for this exact path.
    pub path: Option<String>,
    /// Only allowed entries, or only denied ones.
    pub allowed: Option<bool>,
}

impl SqliteStore {
    /// Read audit entries, oldest first, matching a filter.
    ///
    /// Filtering on identity, path, and decision reads inside the stored payload with
    /// SQLite's JSON functions. That keeps one representation of a record — the bytes
    /// that were hashed — rather than duplicating fields into columns that could
    /// disagree with it.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] on a database error, or [`StoreError::Corrupt`]
    /// if a stored row is not readable.
    pub fn audit_query(&self, filter: &AuditFilter) -> Result<Vec<AuditRow>, StoreError> {
        let mut statement = self.connection().prepare(
            "SELECT seq, hash, payload FROM audit_log
             WHERE (?1 IS NULL OR seq > ?1)
               AND (?2 IS NULL OR ts >= ?2)
               AND (?3 IS NULL OR json_extract(payload, '$.entry.principal.name') = ?3)
               AND (?4 IS NULL OR json_extract(payload, '$.entry.path') = ?4)
               AND (?5 IS NULL OR json_extract(payload, '$.entry.allowed') = ?5)
             ORDER BY seq
             LIMIT ?6",
        )?;

        let rows = statement.query_map(
            params![
                filter
                    .after_seq
                    .map(|seq| i64::try_from(seq).unwrap_or(i64::MAX)),
                filter.since,
                filter.identity,
                filter.path,
                filter.allowed,
                i64::from(filter.limit),
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?;

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

    /// Every audit row, oldest first, for `ciphr audit verify`.
    ///
    /// # Errors
    ///
    /// As [`Self::audit_query`].
    pub fn audit_all(&self) -> Result<Vec<AuditRow>, StoreError> {
        self.audit_query(&AuditFilter {
            limit: u32::MAX,
            ..AuditFilter::default()
        })
    }

    /// The head of the stored chain.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Corrupt`] if the stored head hash is not a chain hash.
    pub fn audit_head(&self) -> Result<Option<(u64, [u8; HASH_LEN])>, StoreError> {
        head_of(self.connection())
    }

    /// The most recently recorded cut, or `None` if the log has never been cut.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Corrupt`] if the stored row is not readable.
    pub fn audit_cut_latest(&self) -> Result<Option<AuditCut>, StoreError> {
        latest_cut_of(self.connection())
    }

    /// Refuse now if this database cannot record a cut.
    ///
    /// For calling **before** the anchor is written. Cutting checks this again inside its
    /// transaction, but by then an anchor for the cut is already in a file, and an anchor
    /// for a cut that never happened is a line somebody has to explain later.
    ///
    /// # Errors
    ///
    /// [`StoreError::CutRefused`] if the schema predates the table that records cuts.
    pub fn require_audit_cut_support(&self) -> Result<(), StoreError> {
        require_cut_table(self.connection())
    }

    /// Where verification of this store's queryable trail begins.
    ///
    /// [`Start::Genesis`] for a trail nobody has cut, and the recorded cut otherwise.
    /// What that record is worth is the subject of `004_audit_cut.sql`: it keeps the
    /// routine check from reporting tampering on a store that was cut legitimately, and
    /// the anchor outside the store is what makes it more than a claim.
    ///
    /// # Errors
    ///
    /// As [`Self::audit_cut_latest`].
    pub fn audit_start(&self) -> Result<Start, StoreError> {
        start_of(self.connection())
    }

    /// The chain a restart has to continue.
    ///
    /// # Errors
    ///
    /// As [`Self::audit_head`], plus [`StoreError::Corrupt`] where the log and the
    /// recorded cut contradict each other.
    pub fn audit_chain(&self) -> Result<Chain, StoreError> {
        chain_to_continue(self.connection())
    }
}
