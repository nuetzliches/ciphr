# ADR-7 — Storage: SQLite behind a store trait

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-08-18 |
| **Affects** | `ciphr-store`, operations |

## Context

The store holds wrapped keys, ciphertext, identities, tokens, and the audit log. The data volume is
tiny — thousands of rows, not millions — and the access patterns are point lookups by path plus
prefix listings.

## Decision

`rusqlite` with WAL mode, migrations as numbered SQL files, behind a `Store` trait so that
PostgreSQL remains possible later.

Deliberately **not** `sqlx`: compile-time query checking adds little at this scale and pulls a large
async layer into the dependency surface.

## Rationale

SQLite is one of the most thoroughly tested codebases in existence, backup is `VACUUM INTO` plus an
existing file-backup job, and — the decisive point — it introduces **no network dependency**. A
database outage would otherwise take the secret store down with it, and the secret store is the
component whose unavailability blocks deploys.

The database is not a trust anchor in any case: it contains nothing but ciphertext, wrapped keys, and
token HMACs. That is what makes a single embedded file an acceptable place to keep it (adversary A4
in the threat model).

## Consequences

- One process owns the database file. That is consistent with the single-instance decision and with
  "exactly one process holds plaintext" (ADR-11).
- No horizontal scaling of the server. Not a goal; high availability is an explicit non-goal.
- Migrations are additive and applied in numeric order. A migration that rewrites ciphertext is a
  design smell — the key hierarchy exists so that rotation touches one row.
- Backups are file-level, which means they inherit the master-key rule from ADR-5: never in the same
  backup as the database.

**Amended by implementation (2026-08-21).** The rationale above says "backup is `VACUUM INTO` plus an
existing file-backup job", and for three releases that sentence described a SQLite capability rather
than anything this project shipped: there was no `ciphr backup`, and the runtime image contains no
`sqlite3`, so the statement could only be run against the volume from outside the container. A
deployment following this record would have reached for `cp` — which on a live WAL database is the one
backup mistake with no error attached to it.

`ciphr backup` closes that, and the decision is unchanged rather than revisited: still an embedded
file, still backed up at file level, still `VACUUM INTO`. What the command adds over the raw statement
is what a record like this one cannot: it opens the source **read-only**, so taking a pre-upgrade
backup with the new binary cannot migrate the database it was taken to protect, and it verifies the
copy it wrote instead of trusting the return code. It needs neither the store lock nor the master key,
which is what makes "plus an existing file-backup job" true for a *running* service.

The procedure, and the rest of what a backup has to contain, is in
[operations/backup.md](../operations/backup.md).

## Rejected alternatives

**PostgreSQL in v1** — a network dependency and more attack surface, for a data volume that does not
need it. The trait keeps it available if multi-instance operation ever becomes a requirement.

**Raft or an embedded key-value store** — consensus code is its own class of bug, worth taking on
only with a genuine high-availability requirement.
