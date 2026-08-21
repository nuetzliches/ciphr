# Rotating secrets that do not want to be rotated

**Status:** current as of 2026-08-21. The classification is implemented, stored, readable and
filterable from the CLI, returned by the API, settable over the API since 2026-08-21, filterable
over the API since 2026-08-21, and shown by the viewer.

Rotation is the operational promise of a secret store, and versioning makes it *easier* to get wrong,
not harder: write a new version, the next deploy renders it, and data encrypted under the old value is
unreadable. The store cannot know which secrets survive that. So the classification is part of the
data model from the start — retrofitting it onto an existing corpus means opening every service to find
out what its password actually does.

The field is **metadata only**. It never affects an authorization decision, so a wrong classification
is an operational problem and never an access-control one.

## The classes

| Class | Meaning |
|---|---|
| `unclassified` | **The default.** Nobody has said. Treated as needing care, because the classes that destroy data look exactly like this one from the outside. |
| `rotatable` | The normal case. A new value takes effect and nothing is lost. |
| `seed-only` | Read once, when something is first initialized. Later changes do not reach the running system. |
| `breaks-data` | Encrypts data at rest. A new value makes existing data unreadable. |
| `volume-bound` | Must match the value a persistent volume was initialized with. |
| `invalidates-sessions` | Rotation works, but discards all sessions and derived tokens. |

The advice for each class also lives in the code, on `Rotation::advice`, so that the CLI and the UI can
show it at the moment of the decision rather than in a document nobody opens under pressure. The
viewer does not keep its own copy of it: `GET /v1/versions/{path}` carries the class, the
`needs_care` flag and the advice text, so the browser shows the same words the CLI prints. That is
deliberate duplication of *wording*, not of truth: a test asserts every class that needs care carries
more than a one-line explanation.

## What to do per class

### `unclassified`

Find out. This class is not a verdict, it is the absence of one, and it is what every secret written
without an explicit class carries.

Until 2026-08-20 the default was `rotatable`, which meant the shortest path through `put` and
`import` wrote "safe to rotate" on a secret nobody had examined — and made the corpus unauditable,
because a deliberate `rotatable` and an untouched default were the same value in the same column.
They are now different, which turns one question into an answerable one:

```sh
ciphr list --rotation unclassified          # what has nobody looked at yet
ciphr rotation infra/service-a/DB_PASSWORD  # what does this one say, and why
```

**Both of those need the service stopped**, because the CLI takes the exclusive store lock. The same
question against a running service goes over the API, which is the form a rotation review actually
wants — the answer is needed while everything is up, not during a maintenance window:

```
GET /v1/list/infra?rotation=unclassified
```

Every path in the response was authorized individually against `list`, and the class comes back on
each row. Without the filter the whole listing carries its classes, which is the same question asked
the other way round: not *which are unclassified* but *what is the state of this prefix*.

Databases created before that date had every such secret rewritten to `unclassified` by migration
005 — including the ones somebody *had* deliberately marked `rotatable`, because nothing recorded
which was which. Classes other than `rotatable` were left untouched: nobody types `breaks-data` by
accident, so those rows carried a real decision.

### `rotatable`

Write a new version, redeploy the consumers, confirm they picked it up. Nothing special.

### `seed-only`

This is the class that produces the most confusion, because rotating it **appears to work**. The store
happily holds the new value, the deploy succeeds, and the running system keeps using the old one —
which is now recorded nowhere. The two drift apart silently.

Examples: a database's initial root password, an admin account created on first boot, a cluster join
token consumed at bootstrap.

Change the value **in the initialized system first**, using whatever mechanism that system offers
(`ALTER USER`, an admin UI, a management command), and only then record the new value here. The store
follows reality; it does not drive it.

### `breaks-data`

The dangerous one. This value is an encryption key for data at rest — a field-level encryption key, a
key for encrypted columns, a token-signing key that also decrypts stored tokens. Writing a new version
and restarting means the existing data cannot be read again.

- Use the application's own key-change procedure if it has one; it will re-encrypt as it goes.
- If it does not, treat the rotation as a data migration: export, rotate, re-import.
- **Keep the previous version.** A restore from a backup taken before the rotation needs the value that
  was current then. Never crypto-shred an old version of a `breaks-data` secret while any backup that
  predates the rotation is still within its retention window.
- If the data is genuinely disposable — a cache, a rebuildable index — say so explicitly before
  proceeding, rather than discovering it afterwards.

### `volume-bound`

The value has to match what the persistent volume was initialized with. Rotating in the store alone
gives you a mismatch, and the usual outcome is a container that refuses to start — which is the good
case, because it fails loudly instead of writing inconsistent data.

Either change it inside the volume as well, or recreate the volume and accept the data loss knowingly.

### `invalidates-sessions`

Rotation works exactly as advertised; the cost is that every session and every derived token becomes
invalid. Users get signed out, integrations need new tokens, and anything holding a long-lived derived
credential breaks until it re-authenticates.

Schedule it. This is the one class where the right answer is usually "yes, but not at 14:00 on a
Tuesday".

## Classifying an existing secret

Ask what happens to *existing data and sessions* if the value changes while the system is running:

1. Nothing, once consumers restart → `rotatable`
2. Nothing, because nothing reads it any more → `seed-only`
3. Existing stored data becomes unreadable → `breaks-data`
4. A mounted volume stops matching → `volume-bound`
5. Sessions and derived tokens die → `invalidates-sessions`

When two apply, take the more severe. A value that both encrypts data and invalidates sessions is
`breaks-data`: the classification exists to make someone stop and think, and the more alarming label is
the one that achieves that.

When unsure, leave it `unclassified` and treat it as `breaks-data` until someone checks — the cost of
being wrong in that direction is a delayed rotation, and in the other direction it is lost data.
Writing `rotatable` to clear a listing is the one move to avoid: it is indistinguishable from the
answer somebody arrived at by looking, which is precisely the ambiguity the class was introduced to
remove.

## Recording a class while the service runs

Four ways to set one, and the fourth is the only one that does not need the service stopped:

```sh
ciphr rotation infra/service-a/DB_KEY breaks-data   # the standalone reclassification
ciphr put infra/service-a/DB_KEY --rotation breaks-data
ciphr import --from-dotenv ./.env --prefix infra/service-a --rotation breaks-data
```

```http
PUT /v1/secrets/infra/service-a/DB_KEY
{ "value": "…", "rotation": "breaks-data" }
```

All three CLI forms open a session and therefore take the store lock, so they run with the service
down — see [cli.md](cli.md). That is the reason the API carries the field at all: migrating an
existing estate one service at a time is the case `PUT` exists for, and without the field the
no-downtime import produced a store where every value said `unclassified` — *nobody has looked at
this* — and making it honest cost exactly the downtime the API path had just avoided.

**Absent means unchanged**, both ways round: a new path written without the field still lands
`unclassified`, and a value written over an existing classification does not reset it. An unknown
class is a `400` and never a default, because defaulting a typo would turn it into "safe to rotate".
Setting it needs `write` on the path and nothing more — the class is metadata and reaches no
authorization decision, so naming what a value is safe for is not a broader privilege than setting
the value.

Two things to know when it is used against a service somebody else deploys. The class is applied
*after* the version exists, so a failed classification leaves the value written and answers with an
error — a retry then writes a second version of the same value. And a service older than the field
ignores it the way any unknown property is ignored, in silence: one `GET /v1/versions/{path}` after
the first import confirms the field arrived, rather than an estate quietly staying `unclassified`.

## Who changed the classification, and when

Setting a class writes a `classify` entry into the audit trail, naming the path and whoever did
it — the operator for the CLI forms, the calling identity for the API one.
It is its own action rather than a `write`, because it produces no version and would otherwise be
invisible among the value writes — and downgrading a class to `rotatable` is the step that comes
immediately before a rotation that destroys data. Reading a class records a `list`, like any other
metadata read.

A `PUT` that carries a class therefore writes **two** entries, `write` and `classify`, and that is
the same rule rather than an exception to it: one entry for the value, one for the claim about it.

## What is not automated

Nothing here is enforced. The store records the class and will warn; it does not refuse a write, and
it should not — refusing would make the field an authorization mechanism, and a mistake in metadata
would then become an outage. The safeguard is that the warning arrives before the irreversible step,
and that the previous version is still there.
