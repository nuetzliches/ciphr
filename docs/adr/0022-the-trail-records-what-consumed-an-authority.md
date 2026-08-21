# ADR-22 — The trail records what consumed an authority

| | |
|---|---|
| **Status** | **Accepted 2026-08-22, built the same day.** The four listings — `list`, `versions`, `rotation <path>` without a class, `token list` — run read-only: no lock, no master key, no audit entry |
| **Date** | 2026-08-22 |
| **Affects** | `ciphr-cli`, ADR-3's framing in `session.rs`, `docs/operations/cli.md`, `docs/operations/honeypots.md`, issues #3 and #14 |

## Context

The CLI's stated principle was *"the CLI audits what it does, reads included"*, and it was enforced
structurally: every command went through `Session::open`, which takes the exclusive store lock
before anything else, because a recorded entry advances the audit chain and the chain tolerates one
writer. The consequence was documented with unusual honesty in `operations/cli.md`: **asking whether
a credential is still valid required stopping the secrets service.** Issue #14 filed that as the
operational cost it is — the question "which token do I revoke" is asked mid-incident, which is
exactly when the service must stay up — and the field report of 2026-08-21 had already asked for the
read-only path by name, after answering the question in production with a second `sqlite3`
connection opened beside the running server.

`token list` was also the principle's own outlier: it recorded nothing, and still paid the lock and
the master key for having opened a session. The worst of both worlds — downtime **and** no entry.

The two goals exclude each other, and that is the fact this record exists to state. Recording an
entry advances the chain; advancing the chain needs the lock; the lock is what the outage is. A
listing cannot be both lock-free and audited.

## Decision

The trail records what **consumed an authority**, not what politely passed through the CLI.

- `get` spends the master key: nothing else can produce the plaintext, so its entry measures
  something nobody affected can route around. It stays audited, fail-closed, session-bound.
- Every mutation — `put`, `delete`, `undelete`, `destroy`, `classify`, `token issue`,
  `token revoke` — changes the store and stays audited, session-bound.
- The **plaintext-metadata listings** — `list`, `versions`, `rotation <path>` read, `token list` —
  consume nothing. Path, rotation class, version history and token records are plaintext columns in
  the database file; whoever can invoke the CLI against that file can run
  `sqlite3 store.db "SELECT path FROM secrets"` and leave no entry at all. An audit record that
  everyone affected can trivially bypass measures politeness, not access. These four take
  `SqliteStore::open_read_only`: no lock, no master key, no entry — and therefore they answer while
  the service runs, which is when the questions get asked.

`backup`, `audit anchor`, `audit verify` and `audit cut` were already in this class, on the same
grounds; this record generalizes their reasoning instead of leaving it per-command.

## Rationale

**The counterargument was our own sentence, so it gets answered first.** The `list` implementation
said: *"a channel that records less is a channel someone will use for that reason."* That is true of
channels that reveal what another channel would have recorded. It is not true here, because the
lesser channel — direct file access — exists regardless and reveals exactly the same rows. The CLI
entry never guarded anything; deleting it removes a comfort, not a control. The API's `list` entry
is untouched and still means something, because an API caller cannot read the file: there the entry
measures an authorization that cannot be routed around.

**The lock exists for writers, and a reader that writes nothing was paying for a property it does
not have.** The measured failure the lock prevents — two processes advancing the chain — cannot be
caused by a `SELECT` on a read-only connection; WAL exists for precisely this concurrency.

**The incident case decides the priority.** `State::authenticate` checks revocation live, so the
server-side mechanism for instant invalidation exists; what was missing first was the ability to
*see* credential state without an outage. That is now host-side and live. Revoking still needs the
outage — see the boundary below.

## Consequences

- `token list`, `list` (including `--rotation unclassified`), `versions` and `rotation <path>` run
  with the service up and without the master key. A monitoring job needs neither a maintenance
  window nor the deployment's highest-value secret in its environment.
- The CLI writes no `list` entries anymore. A trail consumer counting them sees CLI listings
  disappear; API listings are unchanged.
- The audited answer to "is this token valid" belongs on the server, where the caller is
  authenticated and the entry can name a real identity instead of `cli:$USER` — that is issue #3's
  `GET /v1/tokens`, and this record deliberately does not preempt it. The lock-free CLI listing is
  the unaudited host-side fallback, not the replacement.
- On `StoreError::Locked`, the commands the running service can answer (`get`, `put`, `delete`,
  `export`) name the live route in the refusal. The hint announces and never routes: a CLI that
  silently called the API when it found a lock file would make one command mean two identities.
- `audit tail` still opens a session (lock, master key) while recording nothing. It falls under this
  principle — audit rows are plaintext — and is left as is for now, because its session comment
  claims output-guard duties this record does not adjudicate. Named here so the next reader files a
  change, not a surprise.

## Rejected alternatives

**Keep auditing the listings.** Keeps the outage, and keeps recording something the affected party
can bypass with one `sqlite3` invocation. The principle "reads included" was right where it was
coined — for `get`, whose entry is unbypassable — and wrong where it was stretched.

**Lock-free *and* audited.** Structurally impossible; writing the entry advances the chain, which
needs the lock. Stating this plainly is most of this record's value.

**Route to the API when the lock is held.** The same command would then act as the local operator
with the master key, or as an authenticated token identity, decided by whether a lock file exists.
If routing is ever built, it announces itself; today the `Locked` refusal names the route and stops.
