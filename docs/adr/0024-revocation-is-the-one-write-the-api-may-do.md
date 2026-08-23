# ADR-24 — Revocation is the one write the API may do

| | |
|---|---|
| **Status** | **Accepted 2026-08-23, built the same day.** `POST /v1/tokens/{token_id}/revoke`, behind the `token_revoke` runtime entry, authorized as `revoke` on `sys/tokens`, recorded with the token as the entry's subject. Built together with [ADR-23](0023-the-control-plane-is-its-own-capability.md), whose `revoke` capability it needs. Every condition at the end of this record is discharged |
| **Date** | 2026-08-23 |
| **Affects** | ADR-3's boundary (a named exception, not a repeal), ADR-20's entry list (a fourth entry), `ciphr-server`, `docs/operations/honeypots.md`, `docs/operations/cli.md`, `openapi.yaml`, issue #14 |

## Context

Revoking a leaked credential requires **stopping the secrets service.** `ciphr token revoke` goes
through `Session::open`, which takes the exclusive store lock, and the running server holds that
lock for its whole lifetime. So the only way to invalidate one token today is: stop the service,
revoke, start it again — taking down every consumer in order to answer a request nobody planned.

Issue #14 filed it, and everything about it that could be fixed without a decision has been:
`docs/operations/honeypots.md:239` now says plainly that *"this step stops the service"*, the
`Locked` refusal names the live route where one exists, and ADR-22 took the read half — token state
is answerable while the service runs. What is left is the write, and it cannot be moved without
deciding something.

**The mechanics leave exactly one place for it.** The lock is not SQLite's; it exists because the
audit chain's head lives in the writing process's memory, and a second writer collides on a sequence
number until the process restarts — measured once, with one `ciphr put` beside a running server
(`crates/ciphr-store/src/lock.rs`). The process that holds the head is the server. So a revocation
that does not need an outage is a revocation the **server** performs, which means an endpoint.

**And an endpoint is what ADR-3 rules out.** `crates/ciphr-cli/src/session.rs` states it: *"A CLI
that spoke HTTP would need a second, privileged API to do its job, which is the API this project
deliberately does not have."* That sentence is the reason this is an ADR and not a task.

Two facts decide it rather than balance it:

- **The server already checks revocation live.** `AppState::authenticate` authenticates against the
  store per request, so a revoked token stops working on the next call. The mechanism for instant
  revocation is built; only the path that writes the row is missing.
- **An incident cannot be scheduled.** Issuing a credential is routine and a planned window is a
  defensible answer for it — which is why it stays where it is. Revocation is asked for at the one
  moment when taking the service down is most expensive, and `honeypots.md` fires exactly then.

## Decision

**One route, and it is the only write the API may do.**

```
POST /v1/tokens/{token_id}/revoke
```

- **Authorized as `revoke` on `sys/tokens`** (ADR-23). Nothing else grants it; a broad secret grant
  cannot reach it, which is the property ADR-23 exists to establish.
- **Behind a runtime surface entry, `token_revoke`** (ADR-20). Off until a deployment names it with
  a date and a reason, and off means the route is never registered — a `404` from the fallback, not
  a handler that decides to refuse.
- **Recorded as `Action::RevokeToken`**, through the ordinary `authorize_and_record` path, so the
  entry names the **authenticated identity** rather than the self-declared `cli:$USER` the host path
  records. That is a better entry than the one it replaces, not merely an equal one.
- **No master key is involved.** Revocation sets `revoked_at` on a row; nothing is decrypted,
  derived or wrapped. The endpoint therefore widens no key exposure — it is the one control-plane
  mutation that does not.
- **Idempotent, by the SQL that already exists.** `revoke_token` writes
  `COALESCE(revoked_at, now)`, so a second call does not move the timestamp. A retry after a network
  failure is safe, which for an incident tool matters more than elegance.
- **`POST … /revoke`, not `DELETE`.** The row stays and the token remains in the inventory with its
  history; `DELETE` would promise that the credential disappears, and the trail needs it not to.

**What stays outside, and this list is the exception's boundary rather than a roadmap:**

- **Issuing.** It needs the master key to derive the pepper, and it *creates* a credential. Planned
  downtime is the answer, as today.
- **`revoke-all` for an identity.** One request that invalidates every credential of an identity is
  an availability weapon, and the per-token route composes to the same effect with one entry per
  token — which is what `Action::RevokeToken`'s own record says the trail needs. It stays on the
  host.
- **Everything else in the control plane.** No policy writes, no identity creation, no honeypot
  latch clearing, no `audit cut`. ADR-3 stands for all of it.

**ADR-3 is amended, not repealed.** Its subject — that policies and identities come from
configuration and not from the API — is untouched by this record. What is narrowed is the sentence
about a privileged API: there is now exactly one privileged write, it is optional, it is capability-
gated, it uses no key, and it is named here.

## Rationale

**The alternative is a runbook step that takes the service down, and it is the runbook that fires
during a compromise.** `honeypots.md` documents the outage honestly, which is the right thing to do
about a limitation and not an answer to it. A deployment following it during a trip stops the
service — and while the service is stopped, the stolen credential is answered nothing either, so the
outage buys a fraction of what it costs.

**Why an entry rather than always-on.** A deployment that does not want a privileged write path over
HTTP should not have one, and ADR-20 gives that shape a name: off means absent, and turning it on is
a recorded decision with a date and a reason. It also puts the cost sentence in front of whoever is
deciding — since `0.8.0`, `--check-config` prints what each *absent* entry costs, so an operator
reading the surface report sees "revoking a leaked credential means stopping the service" as the
price of leaving it off.

**Why a runtime entry rather than a build entry.** ADR-20 reserves the build kind for a claim about
absence — *"a deployment must be able to prove the code is not there rather than merely not
called"* — and the pull is real here: a compiled-but-unregistered handler makes the claim "not
reachable" instead of "not there". It was rejected on who pays. A build entry is off in the default
build, so the deployment that needs revocation without an outage would have to build and publish a
derived image — and that deployment is precisely the one pulling published artefacts, as the field
report of 2026-08-23 shows. Paying for the strongest claim with the fix itself is the wrong trade for
a route that reads nothing, creates nothing and touches no key. **The condition for revisiting is
stated:** if this route ever grows a second operation, or if any write that uses the master key is
proposed for the API, it becomes a build entry and the claim goes back to being about the binary.

**A denied or impossible revocation still writes an entry, and that is not a bug to fix later.** The
entry records what was *authorized*, which is what every other route records; a revocation of a
token id that does not exist is an authorized attempt that changed nothing, and answers `404`. Nobody
should read such an entry as evidence that the token existed — said here so that the next reader
files a question rather than a defect.

## Consequences

- **`sys/tokens` becomes a reserved virtual path**, ahead of issue #3's read route, which will
  authorize `inspect` on the same path. One path, two capabilities, and the path axis keeps it apart
  from `sys/audit` as it does for every other reserved name.
- The surface list grows to **four entries**, so `/v1/surface`, the `--check-config` report and
  `ciphr surface show` all gain a row — and `ci/check-surface-entries.sh` requires the CLI to know
  the new name too.
- `docs/operations/honeypots.md` step 3 gains the version that does not stop the service, **without
  losing the one that does**: the outage is still the answer for a deployment that leaves the entry
  off, and the runbook has to say which case the reader is in.
- `docs/operations/cli.md` keeps *"`token issue`, `token revoke` and `token revoke-all` all require
  stopping the service"* for the host path, and points at the route where one is configured. The CLI
  does not gain an HTTP client: it announces the alternative and never takes it, exactly as ADR-22
  left it.
- A deployment that turns the entry on accepts that a token holder with `revoke` on `sys/tokens` can
  invalidate credentials over the network. That is the cost the entry's reason field exists to
  record.
- No schema change, no migration, no change to the lock, the chain, or the store's revocation SQL.

## What building it requires

1. ADR-23 first, or at least in the same release: without `revoke` there is nothing to authorize
   against, and inventing a capability here would answer ADR-23's question twice.
2. The `token_revoke` entry in `ciphr-server`'s `ENTRIES` **and** in the CLI's list, with its cost
   sentence — `check-surface-entries.sh` fails otherwise, which is the gate doing its job.
3. The route, registered only when the entry is on, authorizing `revoke` on `sys/tokens` and
   recording `Action::RevokeToken` with the token id in the entry.
4. A test that the route is **absent** without the entry — a `404` from the fallback and not a
   refusing handler — beside the ones that exercise it with and without the capability.
5. `openapi.yaml`, `honeypots.md`, `cli.md`, and an upgrade note that names the entry, its cost, and
   that leaving it off changes nothing.

## Rejected alternatives

**Leave it as it is, and keep the outage.** The cheapest option, and it keeps the attack surface at
zero: no privileged write over HTTP at all. Rejected because the cost lands entirely inside an
incident, and because the mechanism for instant revocation already exists — the service checks
revocation on every request, and only the write is missing. Documenting an outage is not the same as
choosing one.

**Revoke *and* issue over the API.** Consistent, and it would end the question rather than narrowing
it. Rejected on blast radius: issuing needs the master key in the request path and *creates*
credentials, which is the most powerful operation in the system. A planned window is an adequate
answer for an operation that can be planned.

**A CLI that routes to the API when it finds the lock held.** Tempting and already rejected once
(ADR-22): the same command would mean local master-key authority recorded as `cli:$USER`, or an
authenticated identity with a capability check, decided by whether a lock file exists. If routing is
ever built it announces itself.

**`DELETE /v1/tokens/{id}`.** Reads as "the token disappears", and the row must not — the inventory
and the trail both need it. Revocation is a state change, and the verb should say so.

**A general `POST /v1/tokens/{id}` with a body that says what to do.** One route that grows
operations is how the exception stops being one. Each control-plane mutation gets its own route, its
own capability and its own record, or it does not exist.
