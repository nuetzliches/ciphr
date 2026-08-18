# Authorization, as implemented

**Status:** implemented and tested as of 2026-08-18 (phase 2). Describes the code in
`crates/ciphr-policy` and the pattern matcher in `crates/ciphr-core`. There is no HTTP server yet,
so nothing calls this in production; the semantics below are what it will call.

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

## The five capabilities

`read`, `write`, `delete`, `list`, `undelete`. There is **no `admin`**: administration happens
through configuration and the CLI on the host, so there is no privileged capability to be obtained
by finding a gap in a policy file.

Administrative reads go through the same evaluator as everything else, as the virtual paths
`sys/audit`, `sys/identities`, and `sys/policies`. One authorization mechanism, one code path.

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
