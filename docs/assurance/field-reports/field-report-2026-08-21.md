# Field report 2026-08-21: three gaps a rollout hit

**Status:** written 2026-08-21 against `v0.4.0`, from the operating side of a private deployment.

This is not a review and does not claim a review's coverage. It records three places where the
product made an operational question harder than it had to be, found while doing two ordinary
things: diagnosing a sign-in that stopped working, and planning the migration of an existing estate
of forge secrets into ciphr service by service.

Each finding says what was observed, what the code does, and what is asked for. The last section
says what is deliberately *not* being asked for, so that nothing already decided gets relitigated
by accident.

## 1. Credential state cannot be read while the service runs

**Observed.** A `kind = "human"` token stopped working. The trail recorded the attempts correctly:
`unauthenticated`, `401`, empty principal. That is the designed behaviour — `ciphr-store/src/tokens.rs`
makes a wrong secret, an expired token and a revoked token produce the same error and the same
timing, so that probing learns nothing, and that property is worth keeping.

The consequence is that the operator's question is never "why was it refused". It is **"is this
credential still valid"** — and that question has no answer today that does not stop the service:

- `ciphr token list --identity <name>` is what [`operations/cli.md`](../../operations/cli.md) presents,
  and it reaches the store through `SqliteStore::open` → `prepare` → `migrations::apply`. Whether
  applying migrations against a live database happens to be harmless is not a thing to establish
  during an incident.
- **No `v1` endpoint carries credential metadata at all.** `Identities` is `name`/`kind`/`policies`;
  `/v1/health` carries seal state and audit devices. Neither says when a credential expires, when it
  was last used, or whether it was revoked. So the authenticated path cannot answer it either.

What actually produced the answer was a second, read-only SQLite connection opened alongside the
running service: `expires_at`, `revoked_at` and `last_used_at` are plaintext columns, and `WAL`
plus `busy_timeout` make that safe. It worked — and it is exactly the kind of go-around-the-product
workaround this project avoids everywhere else.

**The argument for changing it is already in the codebase.** The doc comment on `open_read_only`
says requiring more "would mean the trail can only be checked with the service stopped, which is
the opposite of when a check is wanted." That sentence is written about the audit trail. It applies
word for word to credential state.

**Asked for, in order of preference:**

1. Let the read-only commands take the read-only path. `token list` needs no master key and writes
   nothing. Today only `audit verify`, `audit anchor` and `audit cut` use `open_read_only` — the
   pattern exists and is deliberate; this is one more caller.
2. Failing that: state in `operations/cli.md` **which commands need the service stopped**. A reader
   cannot currently tell, and the page reads as though `token list` were as cheap as `audit tail`.

## 2. Nothing warns the holder before a token expires

**Observed.** The token above had an 8 h TTL. After the moment of issue, nothing said so again —
not the viewer holding it, not `/v1/health`, not any response the holder sees. It worked, and then
one morning it did not, and by design that looks identical to a bad paste.

For a machine identity, a TTL is a policy someone set deliberately and can monitor from outside.
For a token a person pastes into a browser, the holder is the only party who could act on a warning
in time, and the holder is the one party the system never tells.

**Asked for:** a value the presenter can see — the expiry of the *presenting* token, on a response
the viewer already makes, so it can show "expires in N days" beside sign-out.

This does not weaken the indistinguishability in finding 1: it tells an already-authenticated holder
about their own credential, which they could learn by waiting anyway. It says nothing to an
unauthenticated prober about anyone else's.

## 3. A value written over the API cannot carry its rotation class

**Context.** Migrating an existing estate into ciphr, one service at a time, values that are
`rotatable` first.

`PUT /v1/secrets/{path}` works against the running service, so the import itself needs no downtime —
which is the whole reason the API path is attractive for a migration. But `SecretInput` has exactly
one property, `value`. The rotation class that `0.3.0` introduced, with `unclassified` as its
deliberately pessimistic default, can only be set through `ciphr rotation <path> <class>` — a CLI
write, and therefore the service stopped.

So the no-downtime import produces a store in which **every imported value says "nobody has looked
at this"**, and making it honest costs exactly the downtime the API path just avoided. The two
features pull against each other, and the pessimistic default is what makes it visible instead of
quietly optimistic — which is the default working as intended, and the reason this is worth fixing
rather than tolerating.

**Asked for:** an optional `rotation` property on `SecretInput`. Absent means unchanged, so a new
path still lands `unclassified` and nothing about the default moves. The caller already holds
`write`; naming the class is not a broader privilege than setting the value.

## What is deliberately not asked for

- **`--rotation-map` on the CLI import.** Plan §11 already says no, and the per-path loop is not
  where the friction is. The missing API field in finding 3 is.
- **A `deny_reason` that separates expired from wrong.** That is the property, not a defect.
  Finding 1 asks for an operator-side answer precisely so the wire behaviour can stay as it is.
- **Write capability for a fetching machine identity.** Read-only for the identity that pulls
  values at deploy time is right and should stay.

## Provenance

Findings 1 and 2 come from a real failed sign-in and the store row behind it. Finding 3 comes from
reading `openapi.yaml` and the CLI against a throwaway store built from the `0.4.0` image and
deleted afterwards; the class-setting path was read in the source, not exercised against a running
service. No claim here rests on a changelog entry alone.
