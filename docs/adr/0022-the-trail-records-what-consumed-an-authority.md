# ADR-22 — The trail records what consumed an authority

| | |
|---|---|
| **Status** | **Accepted 2026-08-22, built the same day.** The four listings — `list`, `versions`, `rotation <path>` without a class, `token list` — run read-only: no lock, no master key, no audit entry. Rationale sharpened later the same day, after review asked whether the API should shed its listing and audit-read entries too: it should not, and the record now says why |
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

**This record revises a deliberate decision, not an accident.** Auditing `ciphr list` was in the
CLI's very first commit, with its reasoning stated in place: *"The trail should say the same thing
whether a listing came through the API or from the host: a channel that records less is a channel
someone will use for that reason."* That sentence was right to be written and is answered below —
by the format's own rule, with a new record rather than by pretending the old decision was never
made.

`token list` was also the principle's own outlier: it recorded nothing, and still paid the lock and
the master key for having opened a session. The worst of both worlds — downtime **and** no entry.

The two goals exclude each other, and that is the fact this record exists to state. Recording an
entry advances the chain; advancing the chain needs the lock; the lock is what the outage is. A
listing cannot be both lock-free and audited.

## Decision

The trail records what **consumed an authority**, and an entry is written where its price is
already paid.

- `get` spends the master key and stays audited, fail-closed, session-bound — as does every
  mutation and every per-secret read in `export` and `dump`. Honestly said: this entry is
  **cooperative**, not unbypassable. Whoever holds the master key and the file decrypts everything
  offline and writes nothing, and the threat model puts that reader outside the boundary on purpose
  (A5). The entry is kept because the trail's first job is reconstructing *legitimate* activity —
  "who read this" in the normal case — and because a value command pays the session's price anyway:
  host reads of values are rare, deliberate, and worth an outage.
- The **plaintext-metadata listings** — `list`, `versions`, `rotation <path>` read, `token list` —
  lose their entry, because for them the price was the answer itself. Their columns are plaintext
  in the database file; they consume no key and change no state. These four take
  `SqliteStore::open_read_only`: no lock, no master key, no entry — and therefore they answer while
  the service runs, which is when the questions get asked.

`backup`, `audit anchor`, `audit verify` and `audit cut` were already in this class, on the same
grounds; this record generalizes their reasoning instead of leaving it per-command. And the
host-side regime was never the complete fabric it was believed to be: `audit tail` — reading the
trail on the host — has recorded nothing since the first commit, alongside the four above. This
record does not cut a hole into "audit everything"; it draws a straight line through an edge that
was already ragged, and says where the line is.

## Rationale

**What decides is the price, not the bypass.** An entry advances the chain, the chain needs the
lock, and the lock is an outage at exactly the moment the question is asked. For the listings that
price bought nothing measurable and cost the product its answer — and the measured consequence is
in the 2026-08-21 field report: an operator, needing token state with the service up, opened a
second read-only `sqlite3` connection beside the running server. **The old rule manufactured the
very "channel that records less" its comment warned about** — unrecorded, unsupported, and used for
precisely the predicted reason. Making the read-only path official replaces that workaround with
the same access, minus the going-around.

**Bypassability is the tiebreaker, not the foundation.** Whoever can run the CLI against the file
can read the same rows with `sqlite3` and leave nothing, so the listing entry only ever recorded
the polite. That argument alone would prove too much — it applies to `get` as well, as the Decision
concedes — which is why it breaks ties instead of carrying the decision: where the price is already
paid (`get`, mutations), a cooperative entry is kept for the trail's reconstruction value; where
the price is the answerability of the question itself (the listings), a cooperative entry does not
justify it.

**Conditional recording was rejected on its own.** "Audit when the lock is free, go read-only when
it is held" looks like the compromise and is worse than either end: an entry that exists only when
the server happened to be down makes the *absence* of an entry meaningless, and a trail whose
silences cannot be interpreted has lost the property the chain exists to protect. Always or never;
always is the outage; hence never — for these four.

## Where the strictness stays, and why it is not "too strict"

Review asked the mirror question: if the CLI's listing entries measured politeness, should the API
shed its `list` entries and its `sys/audit` read entry too — are listings not harmless, since they
serve names and never values? No, and the asymmetry is the whole principle. At the API boundary
**both factors flip at once**: the caller cannot read the database file, so the entry is one nobody
affected can route around — there it genuinely measures access, not politeness — and the server
already holds the lock and the chain head, so recording is free. No outage, no trade. Host-side
lean and API-side strict is not an inconsistency; it is the same rule — *record where the entry is
unbypassable by its subject and its price is already paid* — evaluated on both sides of the
boundary.

Two of those API entries are worth defending by name, because they are the ones the question
proposed to drop:

- **The `list` entry is the honeypot layer's reconnaissance record.** Bait paths appear in
  `GET /v1/list` like any secret — bait that announces itself is not bait — and ADR-15 deliberately
  made enumeration trip nothing: *"Enumerating a name is not taking the bait."* Those two choices
  only compose safely because the listing is recorded: the entry is the **only trace** of the
  enumeration phase, and after a trip it is what answers "who ever saw that this path exists". A
  listing reveals no value to the caller, but it hands the caller the map — and the entry is how
  the map-pulling is seen. Silent-but-recorded is the designed pair to trips-on-value; dropping the
  record would un-design it.
- **The `sys/audit` read entry is the most valuable one in the trail.** Issue #5 already names
  audit read an oracle: the trail says which paths legitimate consumers actually fetch, which is
  the same information as which paths are safe to touch without tripping bait — a partial defeat of
  the detection layer from inside the authorization model. An identity that pulls `sys/audit`
  before touching secrets has written the most incriminating entry it can write. Removing that
  entry would blind the trail exactly where it watches its own watchers, to save a record that
  costs nothing.

What "too strict" actually costs at the API is volume, not wrongness — a polling viewer writes
`sys/audit` read entries on every poll. That is a retention problem with an existing answer
(`audit cut` bounds the queryable trail; the archive keeps the evidence), not a reason to stop
recording.

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
- `audit tail` still opens a session (lock, master key) while recording nothing. It falls under
  this principle — audit rows are plaintext — and is left as is for now, because its session
  comment claims output-guard duties this record does not adjudicate. Named here so the next reader
  files a change, not a surprise.

## Rejected alternatives

**Keep auditing the CLI listings.** Keeps the outage, and keeps recording something the affected
party can bypass with one `sqlite3` invocation — which the field report shows happening in
practice, unrecorded either way. The founding principle "reads included" keeps its ground where the
price is paid anyway (`get`, `export`, `dump`) and gives it up where the price was the answer.

**Lock-free *and* audited.** Structurally impossible; writing the entry advances the chain, which
needs the lock. Stating this plainly is most of this record's value.

**Route to the API when the lock is held.** The same command would then act as the local operator
with the master key, or as an authenticated token identity, decided by whether a lock file exists.
If routing is ever built, it announces itself; today the `Locked` refusal names the route and stops.

**Un-audit the API's listings and audit read, for symmetry.** Rejected above at length: at the API
neither of this record's two reasons applies — the entry is unbypassable by its subject and costs
no outage — and both entries carry weight the host-side ones never did: the `list` entry is the
only trace of enumeration in a design where enumeration deliberately does not trip, and the
`sys/audit` entry watches the one read that maps the detection layer. Symmetry of rules, not
symmetry of outcomes.
