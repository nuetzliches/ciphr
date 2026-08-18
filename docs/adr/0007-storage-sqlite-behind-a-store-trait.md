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

## Rejected alternatives

**PostgreSQL in v1** — a network dependency and more attack surface, for a data volume that does not
need it. The trait keeps it available if multi-instance operation ever becomes a requirement.

**Raft or an embedded key-value store** — consensus code is its own class of bug, worth taking on
only with a genuine high-availability requirement.
