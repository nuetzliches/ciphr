# Why build this, and when to stop

Writing a secret manager is a bad idea by default. This document records why it was chosen anyway,
what it is measured against, and — most importantly — the condition under which abandoning it is the
correct decision rather than a failure.

## What was evaluated

The starting point was not "let us build a secret manager". It was a survey of what already exists,
with one hard requirement: **gap-free access auditing must be available without a commercial
licence**, because an audit trail that can be switched off by billing is not an audit trail.

All findings below were verified on 2026-08-18 against source code and upstream documentation rather
than secondary sources, and versions were current on that date. They will age; re-check before
relying on them.

| Candidate | Version | Licence | Auditing |
|---|---|---|---|
| **OpenBao** | v2.6.1 | MPL-2.0 | **Included and fail-closed.** No enterprise directory, no licence-feature code, UI in-tree |
| Vault Community | v2.0.4 | BUSL-1.1 | Included, but no static seal and PKCS#11 only in the commercial edition — so no unattended restart on-premises |
| Infisical CE | v0.162.20 | mixed | **Absent, and silently so.** See below |
| Conjur OSS | v1.27.0 | LGPL-3.0 | Included; no web UI, release cadence roughly quarterly |
| Passbolt CE | current | AGPL-3.0 | A paid-tier feature |
| SOPS | v3.13.3 | MPL-2.0 | **Impossible by design.** Whoever holds the key decrypts without leaving a trace |

### The Infisical finding, in detail, because it is instructive

Infisical's community edition does not merely hide audit logs in the UI. Without a licence key,
`getDefaultOnPremFeatures()` returns `auditLogs: false` and `auditLogsRetentionDays: 0`, and the
ingest path contains this guard:

```ts
if (!plan?.auditLogsRetentionDays) return null;
```

`0` is falsy, so records are dropped before they are written. The result is a system that looks like
it is recording accesses and records nothing. Several secondary sources state the opposite — that the
community edition includes audit logs — which is why this was checked against the source.

Self-hosting also requires PostgreSQL *and* Redis, and the pricing page places self-hosted deployment
under an enterprise licence with a price on request.

## The conclusion that matters

**OpenBao meets the requirement completely and at no cost.** That is the honest result of the
evaluation, and this project therefore has to measure itself against what OpenBao gives away for
free — not against the weakest candidate in the table.

Building instead was a product decision, made in full knowledge of that: a system small enough to be
read end to end, with an audit trail as its centre rather than a feature, a data model that carries
rotation risk as a first-class field, and an integration story shaped around CI rather than around a
general-purpose secrets platform. Whether that is worth the effort is a judgement call. It is
recorded here as a judgement call, not as a necessity.

## The exit condition

A self-built secret manager has one unpleasant property: **its failures are silent.** A broken
scheduler is noticed within hours. A broken authorization check may never be noticed at all.

So the exit is defined up front:

> If this project starts to struggle at the cryptographic or authorization layer, abandoning it in
> favour of OpenBao is the correct decision, not persevering.

Three commitments keep that option real:

1. **`ciphr dump --format portable` ships in v1.** A migration must never fail because of a
   proprietary file format. This is insurance, and insurance bought after the fire is worthless.
2. **External review of `ciphr-crypto` and `ciphr-policy` before the first production use.** Those
   two crates *are* the project; everything else is packaging. Self-review is not sufficient. If no
   review can be arranged, that in itself is an argument for falling back to OpenBao.
3. **No feature creep towards Vault.** PKI, SSH certificate authorities, KMIP, and high availability
   are non-goals. The moment one of them is genuinely needed, OpenBao is the right answer and this
   project is not.

## What OpenBao taught this design

Three properties were adopted outright, and the reasoning is worth keeping visible:

- **Fail-closed auditing.** "OpenBao considers a request to be successful if it can log to *at least*
  one configured audit device." An access that could not be logged but happened anyway is worse than
  an access that failed.
- **A static seal with an unseal abstraction.** Unattended restart is a hard operational requirement;
  the abstraction is what keeps a stronger mechanism available later.
- **The limits of memory protection in a garbage-collected runtime.** OpenBao removed `mlock` support
  because the Go runtime copies memory as it sees fit. That finding is the strongest argument in
  ADR-1, and it comes from the reference product itself.

If ciphr is ever retired, OpenBao is where its data goes. The design assumes that as a possibility
rather than treating it as a defeat.
