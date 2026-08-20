# ADR-18 — One rule for the environment variable name of a secret

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-08-20 |
| **Affects** | `ciphr-core`, `ciphr-cli`, `ciphr-sdk`, ADR-14, phase 7 |

## Context

A secret reaches a process as an environment variable, so something decides what that variable is
called. Three things will decide it: `ciphr export` does today, the SDK will when a consumer asks for
its secrets as an environment (plan section 13, route C), and `ciphr run` will if ADR-14 is accepted
(route B). ADR-14 named the requirement itself, as one of the four conditions it left open: the
routes "must answer it the same way or the same secret will arrive under two names depending on which
route a service takes".

The convention was already chosen and already implemented — **the last path segment**, so
`infra/service-a/DB_PASSWORD` becomes `DB_PASSWORD`. It is a good convention: the last segment is the
name the consuming process already uses, so the common case needs no mapping table. Nothing here
revisits it.

What was not decided is what happens when the convention cannot deliver, and the implementation in
`ciphr-cli` answered both cases by not noticing them:

1. **Two paths can want the same name.** Under one prefix, `infra/a/db/PASSWORD` and
   `infra/a/cache/PASSWORD` both reduce to `PASSWORD`. `ciphr export --prefix infra/a --format dotenv`
   emitted two `PASSWORD=` lines; in a `.env` file, and equally in the file a runner reads from
   `$GITHUB_ENV`, the second wins. **A service then receives a valid secret that is the wrong one, and
   nothing reports anything** — both reads are in the audit trail as successful, because both reads
   *were* successful. Of the failure modes available to this project, that is the worst one: it is
   silent, it looks correct from every side, and the audit trail agrees.
2. **A legal path segment is not necessarily a legal variable name.** A segment may contain `-`, `.`,
   and letters from any script. `infra/a/db-password` exported as `db-password='…'`, a line no shell
   can source — and one that this program's own `import --from-dotenv` refuses, so a corpus could
   leave through one door and not come back through the other.

Neither was reachable in the migration that has run so far, which is why neither had been found. Both
become reachable the moment phase 7 fetches by prefix at startup, which is precisely what routes B
and C do.

## Decision

**One rule, in `ciphr-core`, called by everything that produces a name.** `EnvVarName` is
constructible only through validation, and the set-level assignment refuses a set rather than
repairing it:

- **The name is the last path segment.** Unchanged, and now stated in a record instead of a method.
- **A name is refused if it is not a portable variable name** — an ASCII letter or `_` first, then
  ASCII letters, digits and `_`. Narrower than what some container runtimes tolerate, deliberately:
  a name only the runtime accepts is a name the shell in the same image cannot read, and learning
  that at deploy time is worse than learning it here.
- **A set is refused if two paths produce the same name**, and the error names **both** paths.
  Naming one leaves the operator to find the other, and the pair is the whole content of the problem.
- **Both are refusals, not repairs.** A derived name — `PASSWORD_2`, or one qualified by its parent
  segment — is a name no consumer asked for, and the operator would have to discover the mapping by
  reading the output instead of stating it.
- **Nothing is emitted when a set is refused.** The check runs before the first byte, which matters
  most for `--format actions-env`: a value printed before its `::add-mask::` is a leak, so the
  refusal has to precede the whole rendering rather than interrupt it.

`import --from-dotenv` validates its keys with the same rule, so the round trip holds: every name the
export can produce, the import accepts.

## Why this is in `ciphr-core`

The same argument ADR-9 makes for path normalization, with a smaller blast radius. Three components
derive this name from the same path; a second copy of the rule is how they begin to disagree, and the
disagreement would surface as a service receiving a secret under a name it does not read — an outage
that looks like a missing secret rather than like a naming bug.

The blast radius is genuinely smaller than ADR-9's: a divergence here misroutes a value into a name,
it does not authorize an access. That is why this is a normal ADR and not a hard rule in `AGENTS.md`.

## What this rule does not govern

`ciphr export --format json` is keyed by the full path and produces no variable name, so it is
subject to neither refusal. A secret at `infra/a/db-password` is exportable as JSON and not as
`dotenv`. That asymmetry is the honest one: JSON promises a path, `dotenv` promises something a shell
can read, and only one of those promises can be kept for that path.

Nothing about **rotation classes** is settled here. The open `--rotation-map` question (plan section
11) is the same shape — one flag for a corpus that mixes values — but it is about what a secret *is*,
not about what it is called, and it stays open.

## Consequences

- **`ciphr export` can now fail where it previously succeeded**, in exactly the two cases above. For
  the collision that is the point: the alternative is the wrong secret. For the unusable name it
  means a path that has to be renamed, or exported as JSON, before it can be exported as an
  environment.
- **`import --from-dotenv` refuses a key beginning with a digit**, which it previously accepted.
  `1FOO=x` is a line no shell can source; accepting it would create a path the export can never
  render.
- **ADR-14's fourth condition is met.** `ciphr run` inherits the rule by calling it, and the same
  applies to the SDK helper. One of the four things that had to be true before `ciphr run` can be
  accepted is now true, and it is the one shared with route C.
- **A prefix fetch has a failure mode that is not a network error.** A consumer asking for its whole
  prefix as an environment can be refused by its own secret layout — which is the correct time to
  find out, and has to be documented where phase 7 is documented rather than left to a stack trace.

## Rejected alternatives

**Qualify a colliding name with its parent segment** (`DB_PASSWORD`, `CACHE_PASSWORD`). Produces
names that exist nowhere in the consuming service, and the mapping is then a property of what else
happens to be under the prefix — add a third secret and an existing name changes. A name a consumer
reads must not depend on its neighbours.

**Let the last one win, and warn.** The current behaviour with a message. A warning on standard error
during a container start is a line nobody reads, and the failure it warns about is the delivery of a
wrong secret.

**Keep the rule in `ciphr-cli` and duplicate it in the SDK.** Cheaper by one module and precisely the
thing ADR-14 warned about. The two copies would agree on the day they were written.

**A mapping table or a `--name` flag.** Not rejected on merit — it is the only thing that lets a
collision be resolved rather than avoided, and it may well arrive. It is rejected as part of *this*
decision, because the fail-closed rule has to exist first: a mapping flag on top of a silent
overwrite would let the collision through whenever the flag was forgotten.
