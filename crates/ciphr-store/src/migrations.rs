//! Schema migrations.
//!
//! Numbered SQL files, applied in numeric order, each in one transaction together
//! with the `user_version` bump that records it. Either a migration and its
//! version marker both land or neither does; a database cannot end up in a state
//! where the schema and the marker disagree.
//!
//! Migrations are **additive**. Rewriting stored rows is not a migration pattern
//! here: the key hierarchy exists precisely so that rotating a key touches one
//! record rather than every secret, and a migration that re-encrypts data would
//! throw that away.
//!
//! A database from a *newer* build is refused rather than opened. Opening it would
//! mean writing rows a newer schema may interpret differently, which is the one
//! way to produce a database that neither version can read.

use rusqlite::Connection;

use crate::error::StoreError;

/// The schema version this build produces and understands.
pub const SCHEMA_VERSION: u32 = 5;

struct Migration {
    version: u32,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "init",
        sql: include_str!("../migrations/001_init.sql"),
    },
    Migration {
        version: 2,
        name: "audit",
        sql: include_str!("../migrations/002_audit.sql"),
    },
    Migration {
        version: 3,
        name: "tokens",
        sql: include_str!("../migrations/003_tokens.sql"),
    },
    Migration {
        version: 4,
        name: "audit_cut",
        sql: include_str!("../migrations/004_audit_cut.sql"),
    },
    Migration {
        version: 5,
        name: "rotation_unclassified",
        sql: include_str!("../migrations/005_rotation_unclassified.sql"),
    },
];

/// Bring a database up to [`SCHEMA_VERSION`].
///
/// # Errors
///
/// Returns [`StoreError::SchemaTooNew`] if the database is newer than this build,
/// or [`StoreError::Sqlite`] if a migration fails — in which case nothing from
/// that migration has been applied.
pub(crate) fn apply(connection: &mut Connection) -> Result<(), StoreError> {
    let current: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;

    if current > SCHEMA_VERSION {
        return Err(StoreError::SchemaTooNew {
            found: current,
            supported: SCHEMA_VERSION,
        });
    }

    for migration in MIGRATIONS.iter().filter(|m| m.version > current) {
        let transaction = connection.transaction()?;
        // Named in the error: "migration 003 (identities) failed" is actionable,
        // a bare SQL error at an unknown point in the sequence is not.
        transaction
            .execute_batch(migration.sql)
            .map_err(|source| StoreError::Migration {
                version: migration.version,
                name: migration.name,
                source,
            })?;
        // `PRAGMA user_version` takes no parameters, so the value is formatted in.
        // It comes from a constant in this file, never from input.
        transaction.pragma_update(None, "user_version", migration.version)?;
        transaction.commit()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{MIGRATIONS, SCHEMA_VERSION, apply};
    use crate::error::StoreError;
    use rusqlite::Connection;

    #[test]
    fn versions_are_consecutive_and_end_at_the_declared_version() {
        // A gap or a duplicate would mean a migration silently never runs.
        for (index, migration) in MIGRATIONS.iter().enumerate() {
            let expected = u32::try_from(index + 1).unwrap();
            assert_eq!(
                migration.version, expected,
                "migration {} is numbered {}",
                migration.name, migration.version
            );
        }
        assert_eq!(MIGRATIONS.len(), SCHEMA_VERSION as usize);
    }

    #[test]
    fn applying_twice_is_a_no_op() {
        let mut connection = Connection::open_in_memory().unwrap();
        apply(&mut connection).unwrap();
        apply(&mut connection).unwrap();

        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn refuses_a_database_from_a_newer_build() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();

        assert!(matches!(
            apply(&mut connection),
            Err(StoreError::SchemaTooNew { found, supported })
                if found == SCHEMA_VERSION + 1 && supported == SCHEMA_VERSION
        ));
    }

    #[test]
    fn tables_are_strict_so_types_are_enforced() {
        let mut connection = Connection::open_in_memory().unwrap();
        apply(&mut connection).unwrap();

        // A text value in an integer column must be rejected rather than stored.
        let result = connection.execute(
            "INSERT INTO secrets (path, current_version, rotation, created_at, updated_at)
             VALUES ('a', 'not a number', 'rotatable', 0, 0)",
            [],
        );
        assert!(result.is_err(), "STRICT tables must reject a type mismatch");
    }

    /// Bring a connection up to schema 4 only, so migration 005 can be tested
    /// against the data an existing store actually holds.
    fn at_schema_four(connection: &mut Connection) {
        for migration in MIGRATIONS.iter().take_while(|m| m.version <= 4) {
            let transaction = connection.transaction().unwrap();
            transaction.execute_batch(migration.sql).unwrap();
            transaction
                .pragma_update(None, "user_version", migration.version)
                .unwrap();
            transaction.commit().unwrap();
        }
    }

    #[test]
    fn migration_005_resets_only_the_ambiguous_class() {
        // The asymmetry is the design: 'rotatable' may be a decision or the old
        // default and nothing tells them apart, while every other class was
        // necessarily typed by somebody and must survive untouched.
        let mut connection = Connection::open_in_memory().unwrap();
        at_schema_four(&mut connection);

        connection
            .execute_batch(
                "INSERT INTO secrets (id, path, current_version, rotation, created_at, updated_at)
                 VALUES (1, 'a/default', 0, 'rotatable', 10, 10),
                        (2, 'a/careful', 0, 'breaks-data', 20, 20),
                        (3, 'a/bound',   0, 'volume-bound', 30, 30);",
            )
            .unwrap();

        apply(&mut connection).unwrap();

        let mut statement = connection
            .prepare("SELECT path, rotation, created_at, updated_at FROM secrets ORDER BY id")
            .unwrap();
        let rows: Vec<(String, String, i64, i64)> = statement
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();

        assert_eq!(
            rows,
            vec![
                ("a/default".to_owned(), "unclassified".to_owned(), 10, 10),
                ("a/careful".to_owned(), "breaks-data".to_owned(), 20, 20),
                ("a/bound".to_owned(), "volume-bound".to_owned(), 30, 30),
            ]
        );
    }

    #[test]
    fn migration_005_keeps_versions_attached_to_their_secret() {
        // The rebuild drops and recreates `secrets`, and `secret_versions`
        // references it by id. If SQLite were allowed to reassign those ids,
        // every version would silently repoint at a different secret -- which is
        // worse than any failure this migration could produce.
        let mut connection = Connection::open_in_memory().unwrap();
        at_schema_four(&mut connection);

        connection
            .execute_batch(
                "INSERT INTO secrets (id, path, current_version, rotation, created_at, updated_at)
                 VALUES (7, 'a/one', 1, 'rotatable', 10, 10),
                        (9, 'a/two', 1, 'seed-only', 20, 20);
                 INSERT INTO secret_versions
                     (secret_id, version, dek_id, dek_nonce, wrapped_dek, value_nonce,
                      ciphertext, created_at, created_by)
                 VALUES (7, 1, 'k', x'00', x'00', x'00', x'00', 10, 'operator'),
                        (9, 1, 'k', x'00', x'00', x'00', x'00', 20, 'operator');",
            )
            .unwrap();

        apply(&mut connection).unwrap();

        let pairs: Vec<(String, i64)> = connection
            .prepare(
                "SELECT s.path, v.version FROM secret_versions v
                 JOIN secrets s ON s.id = v.secret_id ORDER BY s.path",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();

        assert_eq!(
            pairs,
            vec![("a/one".to_owned(), 1), ("a/two".to_owned(), 1)]
        );
    }

    #[test]
    fn a_secret_written_without_a_class_is_not_called_rotatable() {
        // The column default is what this migration exists to change. Written as
        // a SQL-level assertion because the Rust default and the schema default
        // are two separate claims, and only one of them is exercised by the
        // store's own insert path.
        let mut connection = Connection::open_in_memory().unwrap();
        apply(&mut connection).unwrap();

        connection
            .execute_batch(
                "INSERT INTO secrets (path, current_version, created_at, updated_at)
                 VALUES ('a/omitted', 0, 1, 1);",
            )
            .unwrap();

        let class: String = connection
            .query_row(
                "SELECT rotation FROM secrets WHERE path = 'a/omitted'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(class, "unclassified");
    }
}
