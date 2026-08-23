# Authorization, as implemented

**Status:** implemented and tested as of 2026-08-18, re-read against the code on 2026-08-20, scope
guidance and the enforcement layer of the reserved prefix corrected 2026-08-21, guidance on broad
wildcards and the reserved prefix added 2026-08-21, the control plane given capabilities of its own
2026-08-23 (ADR-23, ADR-24).
Describes the code in `crates/ciphr-policy` and the pattern matcher in `crates/ciphr-core`. **Every
authorization decision the service makes goes through this** — the sentence here used to say there
was no HTTP server yet and that the semantics were what it *would* call, which stopped being true
with phase 3 and stayed on the page until 2026-08-20.

## The policy file

```toml
[[identity]]
name     = "deploy-runner"
kind     = "machine"          # or "human"
policies = ["infra-read"]

[[policy]]
name = "infra-read"

  [[policy.rule]]
  path         = "infra/**"
  capabilities = ["read", "list"]

  [[policy.rule]]
  path         = "infra/ciphr/**"
  capabilities = []           # explicit denial: no self-access
```

Policies live in version control and are loaded from configuration. There is no policy-write API
(ADR-3), so a permission change is a commit with an author, a diff, and a reviewer — the commit
history is itself part of the audit trail.

`capabilities` is **required**, including when empty. An omitted list would be ambiguous between
"denies everything" and "I forgot to write it", and those two readings are opposites in exactly the
case that matters.

## The seven capabilities

**Five are about a secret** — `read`, `write`, `delete`, `list`, `undelete` — and **two are about
the control plane**: `inspect` reads a reserved path, `revoke` revokes a token. There is **no
`admin`**: administration happens through configuration and the CLI on the host, so there is no
privileged capability to be obtained by finding a gap in a policy file.

| Capability | Authorizes |
|---|---|
| `read`, `write`, `delete`, `list`, `undelete` | A secret at a path, and nothing else |
| `inspect` | Reading `sys/audit`, `sys/identities`, `sys/policies`, `sys/surface`, `sys/honeypots`, `sys/tokens` |
| `revoke` | Revoking a token (`sys/tokens`), through `POST /v1/tokens/{id}/revoke` where that entry is on ([ADR-24](adr/0024-revocation-is-the-one-write-the-api-may-do.md)) |

Control-plane access goes through the same evaluator as everything else, as those virtual paths. One
authorization mechanism, one code path — the split is carried by the capability, **not** by a special
case in the evaluator.

Nothing under `sys/` can be a real secret, and **storage is what refuses it** — not the HTTP layer,
which would leave the CLI free to plant one. That is what keeps a rule about `sys/audit` a rule
about the audit trail: if a secret could live at that path, one grant would silently authorize two
different things.

### A broad wildcard does not reach `sys/`, and that changed on 2026-08-23

Until then `read` was one capability for two kinds of object — a secret's value and the control
plane — with only the path separating them. Since `**` matches one or more segments,

```toml
  [[policy.rule]]
  path         = "**"
  capabilities = ["read"]
```

granted the audit trail, the identity inventory and the whole policy structure along with every
secret. That is rarely what the author of such a rule means, and it matters more than it looks:
`sys/policies` is the map of the authorization model, and `sys/audit` says which paths legitimate
consumers actually fetch — which is the same as saying which paths they never fetch, and that is
precisely where [ADR-15](adr/0015-honeypots-and-what-a-tripwire-may-do.md) says bait belongs.

**[ADR-23](adr/0023-the-control-plane-is-its-own-capability.md) turned the default around.** The rule
above now grants every secret and no reserved path at all, because `read` is a capability about
secrets. Reaching the control plane means saying so:

```toml
  [[policy.rule]]
  path         = "sys/audit"
  capabilities = ["inspect"]
```

**A rule that names `sys/` and asks for a secret capability is refused when the file loads**, with the
capability that is meant instead. It is not accepted and quietly denied — the reader who would find
out otherwise is a monitoring identity that silently stopped seeing anything. The refusal is a
load-time validation and the *evaluator* still does not know the reserved prefix exists: deciding an
access is one code path with no special case, and refusing a file before any access is decided is a
different job.

`ciphr-server --check-config <file>` runs that validation with no store and no master key, so the
edit is findable in review rather than on the host. A refused rule is exit `1`; a host without a store
is exit `3`, so a review pipeline fails on the file and not on the mount
([upgrade.md](operations/upgrade.md)).

**The fence rule still works and is now belt and braces:**

```toml
  [[policy.rule]]
  path         = "sys/**"
  capabilities = []
```

One literal segment beats zero (rule 2 below) and an empty capability set is an explicit denial that
beats any less specific permission (rule 4). Nothing needs it any more — a secret grant does not
reach `sys/` regardless — and a deployment that wants the denial stated in its own file can keep it.


## The pattern language, in full

- `*` matches **exactly one** segment.
- `**` matches **one or more** segments, and only as the **last** segment.
- Everything else is a literal segment, compared byte for byte after NFC normalization, case
  sensitive.

That is all of it. No regular expressions, no character classes, no negation, no alternation.

Three restrictions are tighter than the plan required, each for a reason:

| Restriction | Why |
|---|---|
| `**` only at the end | A middle `**` turns matching into a backtracking search. Restricted to the tail, matching is a single linear scan that can be verified by reading it. |
| No partial wildcards (`ab*` is rejected) | Prefix matching invites `db*` to mean more than its author read into it. |
| `**` does not match zero segments | `infra/**` covers `infra/a`, not `infra`. A rule about a subtree should not silently also be a rule about the thing containing it. |

Patterns and secret paths are normalized by **the same function**, in the same module. That is ADR-9
as a fact of the code rather than a promise: two normalizations that disagree by one edge case are an
authorization bypass, and the cheapest guarantee that they cannot disagree is that there is only
one. Secret paths additionally reject `*` outright, so a literal can never be mistaken for a
wildcard.

## The decision, in four rules

1. **Deny by default.** No matching rule means denial. An unknown identity means denial.
2. **Most specific match wins.** Specificity is the number of literal segments, so `infra/ciphr/**`
   (two) beats `infra/**` (one).
3. **On a tie, denial wins.** Equally specific rules that disagree produce a denial.
4. **An empty capability set is an explicit denial** and beats any less specific permission.

Rules 2 to 4 are what make "everything under `infra`, except our own secrets" expressible as two
rules. Rule 3 exists because the alternative — deciding conflicts by file order — would make the
meaning of a policy depend on where someone happened to paste it.

Every decision carries the rule that produced it, and every denial carries a reason
(`unknown-identity`, `no-matching-rule`, `not-granted`, `tie`). A log line that says "denied" and
nothing else cannot be acted on.

### The consequence worth knowing before writing a policy

The most specific matching rule wins **entirely**. It does not inherit capabilities from broader
rules. In the example above, adding

```toml
  [[policy.rule]]
  path         = "infra/service-a/CACHE_KEY"
  capabilities = ["write"]
```

gives that path `write` and takes away the `read` that `infra/**` granted, because the narrower rule
is now the one that decides. Write out the full set on the narrow rule:
`capabilities = ["read", "write"]`.

This is the behaviour most likely to surprise, and it is deliberate: capabilities accumulating
across specificity levels would mean a denial could be undone by adding an unrelated broad grant
somewhere else in the file.

### The second thing worth knowing: specificity counts literals, not breadth

Specificity is **the number of literal segments** in a pattern. Nothing else — not how long the
pattern is, not where the literals sit, not how many paths it can match. Two patterns that look
very differently broad can therefore be equally specific:

```toml
  [[policy.rule]]
  path         = "infra/**"                 # 1 literal: "infra"
  capabilities = ["read"]

  [[policy.rule]]
  path         = "*/*/*/DB_PASSWORD"        # 1 literal: "DB_PASSWORD"
  capabilities = []
```

For `infra/host-a/service-b/DB_PASSWORD` **both** patterns match and **both** have specificity 1.
Rule 3 applies: equally specific rules that disagree produce a denial, with the reason `tie`.

That is safe — it fails closed and it is deterministic — but it is not what the author of those two
rules expected. They wrote a broad grant and a narrow exception, and the evaluator sees two rules of
equal weight. The `tie` in the audit trail is the only clue, and it reads like a defect.

**How to write it so it does what you meant.** A cross-cutting exception has to be at least as
specific as the grant it is meant to override, which means spelling out the literals:

```toml
  [[policy.rule]]
  path         = "infra/*/*/DB_PASSWORD"    # 2 literals: "infra" and "DB_PASSWORD"
  capabilities = []
```

Now the exception is specificity 2, beats `infra/**` at 1, and wins outright. Both versions deny
the read — what changes is *why*, and that is the whole difference:

| Exception written as | Specificity | Recorded reason |
|---|---|---|
| `*/*/*/DB_PASSWORD` | 1, a tie with `infra/**` | `tie` — the evaluator could not tell which rule was meant |
| `infra/*/*/DB_PASSWORD` | 2, beats `infra/**` | `not-granted` — the narrow rule decided, as intended |

The second is not merely better documented. A tie is fragile: it holds only as long as no third rule
of the same specificity appears, and it denies **every** capability where the two rules disagree,
including ones nobody intended to touch. An explicit specificity ordering keeps deciding the same
way when the file grows.

**Why it is not simply fixed.** Counting positions instead of segments — a literal near the front
weighing more than one at the back — would match intuition here and would have to justify itself in
every other case. Any such change alters authorization outcomes rather than clarifying them, and the
current rule has the property that matters: when it cannot tell which rule was meant, it refuses.
Recorded as a documented sharp edge rather than smoothed over.

## Choosing the scope of a machine identity

Whether an identity gets a sub-path (`infra/host-a/**`) or a list of exact paths is two questions
rather than one, and separating them is most of the answer:

- **the grant** — what the policy permits;
- **the fetch** — what the consumer asks for (`--path` against `--prefix`,
  `Client::environment_of` against `Client::environment`).

They are independent, and they are not equally worth changing.

### Fetch by name wherever the set is known when the consumer is written

Two failure modes belong to fetching by prefix alone, and neither of them is a policy problem.

**The set can shrink silently.** `GET /v1/list` authorizes every path it would return, which is what
stops a caller from learning a name they may not read — and it is the same property that makes a
prefix set variable. Remove `list` from one path and the listing is one entry shorter; `environment`
refuses only an *empty* result, so a consumer starts with one variable missing and nothing says so.
Fetching by name has no equivalent, because `POST /v1/export` refuses the whole request on a single
denial rather than returning a partial answer: a path the identity may not read is an error before
startup instead of a service that came up wrong.

**A change for one service can stop another.** The variable name is the last path segment
([ADR-18](adr/0018-one-rule-for-the-variable-name.md)), and a set in which two paths want the same
name is refused entirely. Under a prefix fetch the set is "whatever exists under this prefix", so a
secret written for one service can refuse the fetch of another at its next start. It is loud —
`ciphr-run` exits `125` — but it couples changes that have nothing to do with each other. A named set
does not change when the store does.

`--path` also needs only `read`, where `--prefix` needs `list` as well. The narrower grant arrives
with the narrower fetch at no extra cost.

### Exact grants buy one thing, and a narrower prefix buys most of it

What a list of exact paths gives that `infra/host-a/**` does not is that **the set does not grow
without a decision**. A secret written under that prefix next month is readable by an existing token
the moment it exists, and nobody chose that; with exact paths it takes an edit to the policy file,
which under [ADR-3](adr/0003-policies-from-configuration.md) is a commit and therefore a record.

Most of that is already bought by making the prefix narrower. Between `infra/<host>/**` and
`infra/<host>/<service>/**` the silently growing set shrinks from "everything on this host" to "more
secrets for this service", and the second is usually a set that genuinely belongs to the identity
fetching it. What exact paths add beyond that is the remainder at the full price: one policy commit
per secret, and a second place — the consumer's list of names — that can drift from the first. That
drift is loud, so it costs effort rather than risk.

A side benefit worth naming: the rule most likely to surprise, that the most specific match wins
entirely and inherits nothing, can only bite where patterns overlap. A set of exact rules does not
overlap.

Two things exact grants do **not** buy. They do not reduce what a compromised *service* can read — it
already holds its own values — only what a stolen *token* reaches afterwards. And they change nothing
about the audit trail, which records one entry per secret served either way.

### The consequence for bait

A honeypot secret trips only after the policy **allowed** the read
([ADR-15](adr/0015-honeypots-and-what-a-tripwire-may-do.md), property 2), so bait has to sit where an
identity is authorized and never fetches. Exact grants close that gap by definition: the identity may
read exactly what it reads, bait outside that produces a denial, and a denial trips nothing.

**Exact grants and honeypot secrets are alternatives rather than complements.** Honeypot tokens are
unaffected. A deployment that scopes exactly keeps the ordinary denial in the trail as its signal —
an identity asking for a path it never wants is nearly as unambiguous — but that is a different
mechanism from the one ADR-15 describes, and choosing one closes the other.

### The recommendation

1. **Fetch by name** wherever the set of secrets is known when the consumer is written. It is cheap,
   and it closes both failure modes above.
2. **Grant per service rather than per host**, and reserve exact paths for the values whose blast
   radius is worth a commit each.
3. **Decide the bait question with it** rather than afterwards: a deployment that scopes exactly is
   choosing honeypot tokens over honeypot secrets.

Human identities sit outside this. The viewer is useful because it can see the trail and the
inventory, and that is a broad grant by definition — which is the case where the reserved-prefix
fence above is worth writing, so that the grant covers the control plane because somebody said so
rather than because a wildcard reached it.

## What the tests establish

| Claim | Where |
|---|---|
| Every documented case decides as documented | `crates/ciphr-policy/tests/decision_table.rs` — 22 rows, extended whenever the evaluator changes |
| `**` is at least as permissive as `*`, and specificity counts literals | `crates/ciphr-core/tests/pattern_properties.rs` |
| Normalization is idempotent and its rules hold for arbitrary input | `crates/ciphr-core/tests/path_properties.rs`, plus the fuzz targets |
| A malformed file loads not at all rather than partially | unit tests in `crates/ciphr-policy/src/model.rs` |
| An allow always names the rule that granted it | `fuzz/fuzz_targets/policy_file.rs` |

The decision table is the artifact to read first: the semantics are four sentences, and the table is
what those four sentences do to concrete inputs.

## What this does not do

- **No conditions.** No time windows, no request attributes, no rate limits. If those become
  necessary, that is the trigger to revisit ADR-2 — deliberately, with the OPA/Rego escalation
  option on the table — not to grow the language incrementally.
- **No roles or groups.** An identity lists its policies. With a handful of identities, a layer of
  indirection would cost more clarity than it saves.
- **No runtime changes.** A policy change requires a deploy. That is the trade ADR-3 makes for
  reviewability, and it is the wrong trade at a few hundred identities.
- **Nothing about authentication.** Which token maps to which identity is phase 3. This crate takes
  an identity name and answers a question about it.
