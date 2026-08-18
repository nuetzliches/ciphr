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
pub const SCHEMA_VERSION: u32 = 3;

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
}
