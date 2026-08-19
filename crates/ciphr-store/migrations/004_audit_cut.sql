-- Migration 004: where the queryable audit log was cut.
--
-- `audit_log` is the queryable copy of the trail, and bounding it means removing
-- its oldest records. Removing records from a hash chain makes everything after
-- them unverifiable from genesis: the first survivor chains to a record that is
-- no longer there. Verification has to start from the cut instead, which needs
-- the sequence number and the hash of the last record the cut removed.
--
-- This table holds those, and holds them as a **claim, not as evidence**.
-- Whoever can write this database can write this row, so a forged cut record is
-- precisely what a deletion dressed up as retention would produce. What makes a
-- cut evidence is the anchor written *outside* the store at the same sequence
-- number (see ciphr-audit::anchor), which is why the cut refuses to run without
-- one and why verification against an anchor compares the two.
--
-- The row exists for the other half of the problem: without it, the routine
-- verification of a legitimately cut store reports a chain break, and an audit
-- trail that cries wolf is one nobody reads. It also answers "when was the trail
-- last shortened, and by how much" without anyone reconstructing it from
-- sequence numbers.
--
-- Append-only, newest by `id`. A single overwritten row would lose the history
-- of when the trail was shortened, which is the part an incident asks about.
CREATE TABLE audit_cut (
    id      INTEGER PRIMARY KEY,
    -- Milliseconds since the Unix epoch, as in `audit_log.ts`.
    cut_at  INTEGER NOT NULL,
    -- The last sequence number this cut removed. The first surviving record is
    -- `seq` + 1, and it chains to `hash`.
    seq     INTEGER NOT NULL,
    hash    TEXT    NOT NULL,
    removed INTEGER NOT NULL,
    -- Where the anchor for this cut was appended, as it was given. A path on a
    -- host rather than a fact about the data, and here anyway: during an incident
    -- the first question is where the anchor is, and the answer should not depend
    -- on someone remembering a schedule entry. NULL for a cut whose anchor went
    -- to standard output alone.
    anchor  TEXT
) STRICT;
