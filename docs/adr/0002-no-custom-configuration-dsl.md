# ADR-2 — No custom configuration DSL

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-08-18 |
| **Affects** | `ciphr-policy`, server configuration |

## Context

Server configuration and policies both need a file format. A purpose-built language would fit the
domain closely and read well — for policies in particular, a small DSL is an attractive idea.

## Decision

`ciphr.toml` for server configuration, and policies as an explicitly typed TOML structure. No
hand-written lexer, parser, or compiler.

## Rationale

In some systems a custom DSL is the right call. In a job scheduler, a parser bug means a job fires
at the wrong time — bad, but visible. Here the same code would sit **in the authorization path**,
where a parser bug is an authorization bypass, and an authorization bypass in a secret manager is
silent. That is the wrong place for homegrown novelty.

TOML rather than YAML, because YAML performs implicit type coercion — `no` becomes `false`,
unquoted scalars become numbers — which is a poor property for a file that decides who may read
what.

## Consequences

- Policies are more verbose than a DSL would be. Accepted deliberately.
- The typed structure is the schema: an unknown key is an error, not a silently ignored line.
- Complex conditions (time windows, request attributes) are not expressible. If they ever become
  necessary, that is the trigger to revisit this decision — not to grow a DSL incrementally.

## Rejected alternatives

**A custom policy DSL.** Parser code in the authorization path, written once and reviewed by the
person who wrote it.

**OPA/Rego through `regorus`.** A general-purpose policy interpreter in the authorization path is
overkill for path-based capabilities. It remains the escalation option if complex conditions are
ever required, and at that point it is a better answer than a homegrown DSL.
