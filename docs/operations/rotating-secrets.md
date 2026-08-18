# Rotating secrets that do not want to be rotated

**Status:** current as of 2026-08-18, phase 1. The classification is implemented and stored; the CLI
and UI warnings that will surface it arrive in phases 3 and 5.

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
| `rotatable` | The normal case, and the default. A new value takes effect and nothing is lost. |
| `seed-only` | Read once, when something is first initialized. Later changes do not reach the running system. |
| `breaks-data` | Encrypts data at rest. A new value makes existing data unreadable. |
| `volume-bound` | Must match the value a persistent volume was initialized with. |
| `invalidates-sessions` | Rotation works, but discards all sessions and derived tokens. |

The advice for each class also lives in the code, on `Rotation::advice`, so that the CLI and the UI can
show it at the moment of the decision rather than in a document nobody opens under pressure. That is
deliberate duplication of *wording*, not of truth: a test asserts every class that needs care carries
more than a one-line explanation.

## What to do per class

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

When unsure, do not guess `rotatable` because it is the default. An unclassified secret is better
handled as `breaks-data` until someone checks — the cost of being wrong in that direction is a
delayed rotation, and in the other direction it is lost data.

## What is not automated

Nothing here is enforced. The store records the class and will warn; it does not refuse a write, and
it should not — refusing would make the field an authorization mechanism, and a mistake in metadata
would then become an outage. The safeguard is that the warning arrives before the irreversible step,
and that the previous version is still there.
