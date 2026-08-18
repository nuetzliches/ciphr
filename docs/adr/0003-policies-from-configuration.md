# ADR-3 — Policies come from configuration, not through the API

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-08-18 |
| **Affects** | API surface, `ciphr-policy`, admin UI |

## Context

Vault and its descendants let policies be written at runtime through the API. That is convenient at
scale: onboarding a new consumer needs no deploy.

## Decision

Policies are loaded from configuration and live in version control. There is no policy-write API in
v1. Identities and policies are administered through configuration and the CLI on the host.

## Rationale

Two effects, both of which matter more than the convenience given up.

*Reviewability.* A policy change becomes a commit: it has an author, a diff, a reviewer, and a
history. For a system whose purpose is to answer "who could read what, and when", the commit
history of the policy file is itself part of the audit trail.

*Attack surface.* A policy-write API is the most dangerous API a secret manager can expose —
whoever reaches it grants themselves everything. Not having it removes an entire class of
escalation.

## Consequences

- A policy change requires a deploy. For a handful of identities that is the right trade; at a few
  hundred it would not be.
- The admin UI is read-only for identities and policies (ADR-11, ADR-12). It can make
  misconfiguration visible, but not creatable.
- `/v1/policies` and `/v1/identities` exist as **read** endpoints, authorized through the ordinary
  policy evaluator as the virtual paths `sys/policies` and `sys/identities`. There is no `admin`
  capability anywhere in the system.

## Rejected alternatives

**The Vault model** — policies mutable at runtime through the API. Retrofittable if the number of
identities ever demands it. The point at which to revisit is when policy edits become frequent
enough that people start avoiding them.
