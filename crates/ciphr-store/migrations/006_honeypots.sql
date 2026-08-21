-- Migration 006: bait, and where a trip is remembered.
--
-- ADR-15's `alert` tier (phase 8). Two flags and one table, all additive: no row
-- is rewritten, nothing is dropped, and a database that has never seen a honeypot
-- is indistinguishable from one that never will.
--
-- ## Why the schema is unconditional while the behaviour is not
--
-- `honeypot_alert` is a *build* entry (ADR-20): the code that recognizes bait is
-- absent from the default binary. The columns are not. Two schemas for one
-- version number is a distribution problem -- two artefacts with the same version
-- and different databases, and a checksum that tells you nothing about which one
-- you hold. Plan section 24 already settled this shape for ADR-21's value index:
-- what is optional is the route, not the column.
--
-- The cost is three unused objects in a deployment that plants no bait. The cost
-- of the alternative is a migration that runs or does not depending on how the
-- binary was compiled, which is the state where a rollback stops being a
-- question anyone can answer.
--
-- ## secrets.honeypot_tier
--
-- NULL means "not bait", which is what every existing row means and what the
-- overwhelming majority of rows will always mean. So NULL rather than a string
-- like 'none': a default that is a value invites `WHERE honeypot_tier != 'alert'`,
-- and the one thing this column must never do is make bait easier to filter out
-- than to notice.
--
-- The CHECK admits only 'alert'. The severe tiers of ADR-15 are designed and
-- deliberately not built, and a column that accepts 'freeze' in a build that
-- honours nothing by that name is the dormant-flag failure ADR-20 rejects: the
-- value would sit there looking like protection. Widening it is a migration, which
-- is the right price for turning on an availability lever.
--
-- ## tokens.honeypot
--
-- A boolean, not a tier. A honeypot token authenticates nothing whatever the tier
-- would say, and ADR-15's severe tiers act on *the identity that tripped them* --
-- which a bait credential does not have, because it never authenticates. So the
-- column records only that the credential is bait.
--
-- ## The tripwire table, and the latch as an index
--
-- ADR-15 (2026-08-21) decided that the authoritative record of a trip is the
-- request's own audit entry, not a row here: an audit device and the store hold
-- separate connections to the same file, so a row and a record cannot be made to
-- fail together, and with a `file` device configured the record survives a
-- database the row would fail on. This table is therefore **derived state** -- the
-- latch, and what `/v1/health` reads `tripped` from -- written after the response
-- is flushed.
--
-- It earns its place for the one thing the trail cannot do: survive
-- `ciphr audit cut`. Retention bounds the trail, and a latch derived from the
-- trail would silently un-latch when the entry that held it aged out.
--
-- **The latch is two partial unique indexes rather than application logic.** One
-- trip per piece of bait until it is cleared, and stating that as an invariant
-- means two concurrent reads of the same bait cannot produce two open trips --
-- which application-side checking would have to get right under a lock it does not
-- hold. `cleared_at IS NULL` in the index predicate is what makes clearing work:
-- a cleared trip stops occupying the slot, so the same bait can trip again, and
-- the history of both trips is still there.

ALTER TABLE secrets ADD COLUMN honeypot_tier TEXT
    CHECK (honeypot_tier IS NULL OR honeypot_tier = 'alert');

ALTER TABLE tokens ADD COLUMN honeypot INTEGER NOT NULL DEFAULT 0
    CHECK (honeypot IN (0, 1));

CREATE TABLE tripwire (
    id         INTEGER PRIMARY KEY,
    -- Milliseconds since the Unix epoch, as everywhere else in this schema.
    tripped_at INTEGER NOT NULL,
    -- 'secret' or 'token'. The two catch different things and neither replaces
    -- the other, so the kind is recorded rather than inferred from which of the
    -- two reference columns is set.
    kind       TEXT    NOT NULL CHECK (kind IN ('secret', 'token')),
    -- Set when kind = 'secret'. The normalized path.
    path       TEXT,
    -- Set when kind = 'token'. The non-secret token identifier, never the token.
    token_id   TEXT,
    -- Who took it, when there was an authenticated identity. NULL for a honeypot
    -- token: presenting bait authenticates nothing, so there is nobody to name --
    -- which is the same reason an unauthenticated audit entry has no principal.
    identity   TEXT,
    tier       TEXT    NOT NULL CHECK (tier = 'alert'),
    cleared_at INTEGER,
    -- Exactly one of the two reference columns, matching the kind. A row that
    -- names neither could not be traced back to any bait; one that names both
    -- would leave which piece tripped a matter of interpretation.
    CHECK (
        (kind = 'secret' AND path IS NOT NULL AND token_id IS NULL)
        OR
        (kind = 'token' AND token_id IS NOT NULL AND path IS NULL)
    )
) STRICT;

-- The latch. See the header: an invariant rather than a check somebody remembers.
CREATE UNIQUE INDEX tripwire_open_secret
    ON tripwire (path) WHERE kind = 'secret' AND cleared_at IS NULL;

CREATE UNIQUE INDEX tripwire_open_token
    ON tripwire (token_id) WHERE kind = 'token' AND cleared_at IS NULL;

-- `/v1/health` asks one question on every poll: is anything tripped and untouched.
CREATE INDEX tripwire_open ON tripwire (tripped_at) WHERE cleared_at IS NULL;
