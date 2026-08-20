-- Migration 005: "nobody has said" becomes a state a secret can be in.
--
-- `secrets.rotation` defaulted to 'rotatable' from migration 001. That default
-- was a claim -- "safe to rotate" -- attached to every secret whose writer never
-- passed `--rotation`, which is the shortest path through both `put` and
-- `import`. Two things followed from it, and neither was intended:
--
--   * The most convenient way to write a secret asserted the one property whose
--     being wrong destroys data. `ciphr-core`'s own `Rotation::parse` already
--     refuses an unknown class rather than defaulting, on the grounds that
--     defaulting to `rotatable` "would turn a typo into safe to rotate". The
--     same argument had simply never been applied to the absence of an answer.
--   * "Is every value classified?" -- the completion criterion for phase 6 --
--     could not be answered. A deliberate `rotatable` and an untouched default
--     were the same nine bytes in the same column.
--
-- ## What happens to rows that already exist
--
-- Only 'rotatable' is rewritten. Every other class is left exactly as it is.
--
-- That asymmetry is the whole design. No secret acquires 'breaks-data',
-- 'volume-bound', 'seed-only' or 'invalidates-sessions' by accident -- somebody
-- typed it -- so those rows carry a real decision and this migration must not
-- discard it. A row saying 'rotatable' carries either a real decision or the old
-- default, and **nothing in the database distinguishes them**. Keeping such a row
-- would preserve a possibly-unmade claim that a rotation is safe; resetting it
-- costs a re-classification of the values somebody did look at.
--
-- Resetting is the fail-safe direction: `unclassified` warns, `rotatable` does
-- not, and this field never influences an authorization decision. The cost is
-- human work on a corpus that has to be classified for phase 6 anyway. The other
-- direction's cost is a rotation somebody performs because a column told them it
-- was fine.
--
-- `updated_at` is deliberately not touched. This migration changes what a row
-- means, not when its secret was last written, and moving the timestamp would
-- make every secret look freshly modified in the one view an operator uses to
-- find recent changes.
--
-- ## Why the column is swapped rather than the table rebuilt
--
-- SQLite cannot change a column default in place, so the obvious route is its
-- documented table rebuild: create a replacement, copy, `DROP TABLE`, rename.
-- **That route was written, tested, and abandoned, and the reason is worth
-- keeping** -- it fails at COMMIT with a foreign key violation, and it fails
-- there even with `PRAGMA defer_foreign_keys = ON`.
--
-- `secret_versions.secret_id` references this table. With foreign keys enabled,
-- `DROP TABLE` performs an implicit `DELETE FROM`, which increments SQLite's
-- deferred-violation counter for every version row. Re-populating a table under
-- a *different* name and renaming it afterwards never decrements that counter,
-- so the commit fails although the data is correct -- the join returns exactly
-- the right rows immediately before the failure. The documented rebuild wants
-- `PRAGMA foreign_keys = OFF`, which cannot be set inside a transaction, and
-- every migration here runs inside one on purpose.
--
-- The swap below stays away from all of that: the table is never dropped, no row
-- is deleted, and no `id` moves, so nothing in `secret_versions` is ever
-- momentarily orphaned. The one visible cost is that `rotation` is now the last
-- column rather than the fourth. Nothing reads this table with `SELECT *` -- the
-- queries name their columns -- but a reader comparing the live schema against
-- `001_init.sql` will notice, which is what this paragraph is for.

ALTER TABLE secrets RENAME COLUMN rotation TO rotation_before_005;

ALTER TABLE secrets ADD COLUMN rotation TEXT NOT NULL DEFAULT 'unclassified';

UPDATE secrets
SET rotation = CASE
    WHEN rotation_before_005 = 'rotatable' THEN 'unclassified'
    ELSE rotation_before_005
END;

ALTER TABLE secrets DROP COLUMN rotation_before_005;
