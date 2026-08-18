-- Migration 002: the audit log.
--
-- One row per audited access, in the same database as the secrets. That is
-- deliberate: the audit write and the secret write can then share a transaction
-- boundary, and a database file that is copied carries its own history with it.
-- The file device exists as the second copy that is *not* in this file, which is
-- what makes a break in one of them localizable (see ciphr-audit).
--
-- `payload` holds the exact bytes that were hashed. Verification recomputes the
-- hash from this column and never re-serializes anything, so a future change in
-- how records are encoded cannot invalidate a chain written today.
--
-- `hash` is stored as well as derivable. It is redundant on purpose: a stored hash
-- that disagrees with its payload is itself evidence — it is what an in-place edit
-- by someone who forgot the hash column looks like.
CREATE TABLE audit_log (
    seq       INTEGER PRIMARY KEY,
    ts        INTEGER NOT NULL,
    prev_hash TEXT    NOT NULL,
    hash      TEXT    NOT NULL,
    payload   TEXT    NOT NULL
) STRICT;

-- The audit browser filters by time, and `audit tail` reads the end of the table.
-- The primary key already orders by sequence; this covers the other axis.
CREATE INDEX audit_log_ts ON audit_log (ts);
