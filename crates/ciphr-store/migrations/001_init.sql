-- Migration 001: the key/value core.
--
-- Covers what phase 1 needs: the seal record, secrets, and their versions.
-- Identities, tokens, and the audit log arrive in later phases as their own
-- migrations. Migrations are additive and applied in numeric order, so a table
-- that nothing uses yet is dead schema and is not created early.
--
-- Every table is STRICT: SQLite otherwise accepts a string in an integer column,
-- and a store whose types are advisory is a store that can be corrupted by a
-- careless write.

-- Singleton-ish key/value for state that has exactly one row.
--
-- The schema version is *not* kept here; it lives in `PRAGMA user_version`, which
-- is set inside the same transaction as the migration itself. Two places holding
-- the same number is two places that can disagree.
CREATE TABLE meta (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
) STRICT;

-- One row per secret path.
--
-- `current_version` is 0 until the first write, which is why SecretVersion starts
-- at 1: "no version yet" and "version zero" cannot be confused.
CREATE TABLE secrets (
    id              INTEGER PRIMARY KEY,
    path            TEXT    NOT NULL UNIQUE,
    current_version INTEGER NOT NULL DEFAULT 0,
    rotation        TEXT    NOT NULL DEFAULT 'rotatable',
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
) STRICT;

-- One row per version of a secret. Nothing here is plaintext.
--
-- `wrapped_dek` is what crypto-shredding deletes: emptying that one column makes
-- the version permanently unreadable, and it stays unreadable in every backup
-- taken after the shred. `deleted_at` is the reversible soft delete;
-- `destroyed_at` records the irreversible one.
CREATE TABLE secret_versions (
    secret_id    INTEGER NOT NULL REFERENCES secrets(id),
    version      INTEGER NOT NULL,
    dek_id       TEXT    NOT NULL,
    dek_nonce    BLOB    NOT NULL,
    wrapped_dek  BLOB    NOT NULL,
    value_nonce  BLOB    NOT NULL,
    ciphertext   BLOB    NOT NULL,
    created_at   INTEGER NOT NULL,
    -- The identity that wrote this version. A plain name in phase 1, because
    -- identities do not exist yet; phase 3 adds the table and the reference.
    created_by   TEXT    NOT NULL,
    deleted_at   INTEGER,
    destroyed_at INTEGER,
    PRIMARY KEY (secret_id, version)
) STRICT;
