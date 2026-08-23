# ADR-23 — The control plane is its own capability

| | |
|---|---|
| **Status** | **Accepted 2026-08-23, built the same day.** `inspect` and `revoke` join the five secret verbs; a rule that names `sys/` and grants a secret capability is refused when the policy file loads — in the loader, not in the evaluator, which still does not know the reserved prefix exists. Built together with [ADR-24](0024-revocation-is-the-one-write-the-api-may-do.md), so a deployment edits its policy file once. The conditions at the end of this record are all discharged |
| **Date** | 2026-08-23 |
| **Affects** | `ciphr-core` (the capability set), `ciphr-policy` (its *loader*, deliberately not its evaluator), `ciphr-server`'s reserved routes, every policy file that reaches `sys/`, `docs/authorization.md`, `openapi.yaml`, issues #5, #14 and #3 |

## Context

`Capability` has five variants (`crates/ciphr-core/src/capability.rs`) and every one of them is a
verb about a **secret** at a path: read a value, write a version, soft-delete one, list paths,
restore one. The reserved prefix then reuses the same set for something else entirely —
`sys/audit`, `sys/identities`, `sys/policies`, `sys/surface`, `sys/honeypots`, and `sys/tokens` if
issue #3 lands. So `read` means two different kinds of thing, and **only the path separates them.**

`ciphr-policy` does not know the reserved prefix exists. There is no reference to `RESERVED_PREFIX`
or `is_reserved` anywhere in that crate, and that is deliberate: one code path decides every access,
and the evaluator has no business carrying a special case. The consequence is that the separation is
a property of how a policy file happens to be written:

```toml
[[policy.rule]]
path         = "**"
capabilities = ["read"]
```

`**` matches one or more segments (`crates/ciphr-core/src/pattern.rs`, pinned at specificity 0 by
`a_bare_multi_wildcard_matches_every_path`), and `sys/audit` is two segments. That rule therefore
grants the audit trail, the identity inventory and the whole policy structure along with every
secret — and it is the shape somebody writes for a break-glass identity meaning *"all the
secrets"*.

**This record revises a decision that was written down, not an oversight.**
[`docs/authorization.md`](../authorization.md) carries a section titled *"A broad wildcard reaches
`sys/`, and that is a decision rather than an inheritance"*, and it names the counter-rule that
already works:

```toml
[[policy.rule]]
path         = "sys/**"
capabilities = []
```

One literal segment beats zero (decision rule 2) and an empty set is an explicit denial that beats
any less specific permission (rule 4), so it wins over `**` entirely. Issue #5 states the
conclusion this record starts from: **the question was never expressibility. It is which way the
default points.**

Three things make the current direction worth reversing rather than documenting again, and they are
#5's, in increasing order of how specific they are to this project:

1. **`sys/policies` is the map of the authorization model.** Whoever reads it knows what to attack
   and, more usefully, what is not protected.
2. **`sys/audit` is an oracle against the detection layer.** The trail says which paths legitimate
   consumers actually fetch, which is the same information as which paths they never fetch — and
   ADR-15's placement rule is that bait belongs exactly there. Audit read is therefore a partial
   defeat of the honeypot layer from *inside* the authorization model rather than around it.
   ADR-22 already leans on this: the `sys/audit` read entry is called the most valuable one in the
   trail for the same reason.
3. **The set grows.** #3 adds `sys/tokens` — the token inventory, including which credentials have
   never been used, which is a good list of the ones nobody would notice being used.

**And this project has decided this exact question once before**, in
`crates/ciphr-core/src/rotation.rs`, about why the default rotation class is `Unclassified` rather
than `Rotatable`:

> Two consequences followed: the path of least resistance was the destructive one, and "is the
> corpus classified?" was unanswerable, because a deliberate `rotatable` and an untouched default
> were the same byte in the same column.

Both halves transfer exactly. The path of least resistance — a broad `read` — grants the control
plane, and nobody wrote down that they wanted it. And *"which identities can read the audit
trail?"* is not answerable by grepping for a capability today; it is answerable only by evaluating
every rule against every reserved path, because an identity that reaches `sys/audit` does so
through a pattern that does not mention it.

**Issue #14 forces the second half of the question.** A revoke endpoint needs a capability, and
there is none for the control plane. Inventing one inside #14 would answer this question twice, in
two places, at two dates.

## Decision

**Two new capabilities. Seven in total, and every one of them names one kind of thing.**

| Capability | What it authorizes |
|---|---|
| `read`, `write`, `delete`, `list`, `undelete` | A **secret** at a path. Unchanged, and now *only* that |
| `inspect` | **Reading** a control-plane path: `sys/audit`, `sys/identities`, `sys/policies`, `sys/surface`, `sys/honeypots`, and `sys/tokens` when #3 lands |
| `revoke` | **Revoking a token** (`sys/tokens`). The one control-plane mutation this project intends to have; issuing stays offline (#14) |

```toml
[[policy.rule]]
path         = "sys/audit"
capabilities = ["inspect"]

[[policy.rule]]
path         = "sys/tokens"
capabilities = ["inspect", "revoke"]
```

**A secret capability under the reserved prefix is a refusal to start.** A rule that grants `read`,
`write`, `delete`, `list` or `undelete` on a path under `sys/` no longer means what it says, so the
policy file is refused with the rule and the replacement named. It is not accepted and quietly
denied.

**The evaluator does not change, and must not.** The separation is carried by the capability set,
not by a prefix rule in the decision path — `ciphr-policy`'s evaluator stays ignorant of
`RESERVED_PREFIX`, and the path axis keeps the reserved paths apart from each other exactly as it
does today (`crates/ciphr-policy/tests/decision_table.rs`: *"reading the audit trail grants nothing
else under `sys/`"*).

**The refusal is a load-time validation, and that distinction is the whole reason it is allowed to
know the prefix.** Deciding an access stays one code path with no special case; refusing a *file*
before any access is decided is a different job, and it is the job that can afford to know that
`sys/` is not an ordinary prefix. Whoever implements it should keep those two apart deliberately
rather than by accident.

## Rationale

**The mirror of a sentence this project already wrote.** `docs/authorization.md` says of the
reserved prefix that storage refuses a real secret there so that *"a rule about `sys/audit` [stays]
a rule about the audit trail: if a secret could live at that path, one grant would silently
authorize two different things."* This record is that sentence one level up: one **capability**
authorized two different kinds of thing, and only the path name kept them apart.

**Why a verb per mutation rather than a general one.** `inspect` + `admin` was the tempting shape —
one mutation verb covering revoke now and whatever comes later, no retrofit. It was rejected for the
reason ADR-20 exists one layer up: *off means absent, and turning something on is naming it.* A
general verb grows at upgrade time, so an identity granted `admin` today can do more tomorrow
without anyone touching the policy file. With `revoke`, a second control-plane mutation has to be
named to be granted. The cost is accepted and stated: that second mutation gets its own verb and its
own amendment to this record, and the set has to be defended against becoming a verb per handler.

**Why not `write` on `sys/tokens`.** It is the smaller set, and it reintroduces the defect: `write`
would mean "a new secret version" or "revoke a token" depending on the path. Fixing an overloaded
capability by overloading a different one is not a fix.

**Why not one `control` verb.** On `sys/tokens` a single grant would authorize reading the token
inventory *and* revoking — read and mutate conflated on one path, which is the same complaint in a
smaller box. And revoke rights are a denial-of-service on every consumer, not a lesser sibling of
reading.

**Why the break is loud.** The affected shape is in this repository's own fixtures: the auditor
identity is granted `read` on `sys/audit`. Under the new meaning that grant authorizes nothing, and
a monitoring identity that silently sees nothing after an upgrade is the failure mode the project
treats as worse than an outage — a wrong sentence next to right code survives longer than wrong
code, because nothing executes it. The usual objection to refusing at startup is that it turns an
upgrade into an outage; **since `0.8.0` that objection is weaker**, because
`ciphr-server --check-config` reports configuration, policies and surface without a store and
without a master key, so this refusal is reachable in review, before the file reaches a host.

**What it buys beyond the default.** After this, *"which identities read the audit trail"* is
`grep inspect` over the policy file. Today it is an evaluation of every rule against every reserved
path — the same unanswerability the rotation default was changed to fix.

## Consequences

- **Breaking for policy files that reach the control plane through a secret capability.** One edit
  per file, and the server names the rule. Nothing else about a policy file changes: no new syntax,
  no migration, no schema change, no change to the store, the chain or the lock.
- `Capability::ALL` grows to seven, so the unknown-capability message that lists the known ones
  changes, and `/v1/policies` and `openapi.yaml` gain the two values.
- The repository's own fixtures move: the auditor identity gets `inspect` on `sys/audit`, and
  `decision_table.rs` gains rows for both new capabilities — including the one that matters most,
  that `read` on `**` reaches no reserved path any more.
- `docs/authorization.md`'s wildcard section is rewritten. The `sys/** = []` rule stops being the
  answer and becomes a belt-and-braces note for a deployment that wants the denial stated in its own
  file.
- **Issue #14's revoke endpoint has its capability**, and issue #3's `GET /v1/tokens` becomes
  `inspect` on `sys/tokens`. Neither needs to invent one.
- A deployment that granted the control plane deliberately — through `**` and nothing else — loses
  it until it says so. That is the point of the record and not a side effect of it.

## What building it requires

1. `inspect` and `revoke` in `Capability`, `ALL`, `as_str`, `parse`, and the error that lists the
   known set.
2. The load-time refusal, in the policy loader rather than in the evaluator: a rule granting a
   secret capability under `RESERVED_PREFIX` is refused, naming the rule, the capability and the
   replacement. Reachable from `--check-config` with no store and no key.
3. The reserved routes in `crates/ciphr-server/src/api.rs` authorize `inspect` instead of `read`.
4. Fixtures, `decision_table.rs`, `docs/authorization.md`, `openapi.yaml`, and an upgrade note that
   says the refusal is a one-time edit and how to make it.
5. Released together with #14's revoke endpoint, so a deployment edits its policy file once.

## Rejected alternatives

**The evaluator learns the reserved prefix** (a pattern that does not name `sys` does not match
under it). Smaller blast radius — everyone who already names reserved paths explicitly notices
nothing — but it puts the special case in the one place this design keeps free of one, and it makes
the meaning of a pattern depend on where it points rather than on what it says.

**A report instead of a change.** Print which identity reaches which reserved path, recommend
`sys/** = []`, change no semantics. Non-breaking, and it answers the second half of #5's complaint.
Rejected as the *whole* answer because it leaves the default pointing the wrong way — the identical
argument the rotation default settled. It survives as a by-product: with `inspect`, that report is a
grep.

**`inspect` + `admin`**, and **`inspect` + reusing `write`**, and **one `control` verb** — argued
above under Rationale.

**Grandfathering the old meaning behind a switch.** Two authorization semantics in the field at the
same time, which is what ADR-3's *one code path decides every access* exists to prevent — and the
switch would never be removed.
