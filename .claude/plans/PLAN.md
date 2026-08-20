# ciphr — Implementation Plan

| | |
|---|---|
| **Date** | 2026-08-18 |
| **Status** | Draft. No code written yet. |
| **Background** | Evaluated OpenBao, Vault Community, Infisical CE, Conjur OSS. Result: OpenBao meets the requirement completely. Building this is a product decision, not a workaround. |

`ciphr` is an internal secret manager for machine identities: key/value secrets, gap-free
access auditing, and path-based authorization. The name contains *CI* — the primary consumer
is a build and deploy pipeline, not a human.

---

## 1. Goal and Non-Goals

### Goal

Three properties that a pipeline built on forge-native secrets plus rendered `.env` files
cannot provide:

1. **Gap-free access auditing.** It is traceable who read which secret, and when.
2. **Per-identity access control.** The deploy runner for service A cannot reach the secrets
   of service B.
3. **A single source of truth.** Today every value exists twice — once as a forge secret and
   once as a line in an `.env` file on the host.

### Non-Goals

| Non-goal | Rationale |
|---|---|
| Password manager for humans | Different threat model (client-side crypto, browser clients), different audience. Use a dedicated tool. |
| Bitwarden-compatible API | See ADR-4. Incompatible with the audit goal, plus ~1.26 MB of foreign compatibility surface. |
| Feature parity with Vault | PKI, SSH CA, KMIP, HA. If those are ever needed, OpenBao is the right answer, not this project. |
| Multi-tenancy | One organization, one trust boundary. Namespaces would be a data-model feature, not a security boundary. |
| High availability | Single instance. Failure impact is bounded, see section 17. |

### Developer experience

Added 2026-08-18, after the fact. The three goals above are security properties, and until this
section existed usability was not a criterion anywhere in this plan. The word "convenience" appeared
exactly once, as a reason to *reject* something (ADR-11). That is the rule from `AGENTS.md` working
as intended — decisions are argued from security criteria, not from what feels pleasant — and it is
also why nobody went looking for the ergonomic gap that ADR-14 records. An unstated goal produces no
findings.

What developer experience means here, in order of weight:

1. **Getting a value into a process without it resting on disk.** The one item that is also a
   security property, and the one this plan was missing. See ADR-14 and section 13.
2. **The audit usable without the CLI.** Already the done-condition of phase 5, already scoped in
   section 15.
3. **CLI ergonomics.** Errors that say what to do next, `--dry-run` wherever a mistake is expensive,
   shell completion. Cheap, and it belongs to whichever phase touches the command anyway rather than
   to a phase of its own.

What it explicitly does **not** mean. These are decisions, not deferrals, and a request for any of
them is a request to revisit an ADR rather than to schedule work:

| Not this | Because |
|---|---|
| Managing secrets, policies, identities, or tokens through a web form | ADR-3 rules out a policy-write API — the most dangerous API this project could have. Section 15 rules out the rest: the UI reads, and everything that writes stays with the CLI and the API |
| Environments, folders, projects | Multi-tenancy is a non-goal. The path *is* the hierarchy |
| Sharing links, secret exchange between people | That is a password manager, and the first non-goal in the table above |

One comparison, stated plainly because it will otherwise be made implicitly: the tools this project
was measured against are built for teams of developers self-serving secrets across projects and
environments. This one serves a handful of humans and a set of machines. Copying their ergonomics
would import answers to problems this system does not have, while missing the one it does — which is
precisely what happened until ADR-14.

**Timing.** Nothing here is built before phase 4. Item 2 is already scheduled, item 3 rides along
with whatever touches the command, and item 1 needs a decision *before* phase 7, because it changes
what that phase is.

---

## 2. Why Build This — and the Condition Under Which It Fails

The evaluation of existing tools concluded that OpenBao meets the requirement completely and
at no cost. This project therefore has to measure itself against what OpenBao delivers for
free.

Concretely: **if this project starts to struggle at the crypto or authorization layer,
abandoning it in favour of OpenBao is the correct decision, not persevering.** The plan keeps
that option open by shipping a neutral export format from the start (section 11) — a
migration must never fail because of a proprietary file format.

A self-built secret manager has one unpleasant property: **its failures are silent.** A broken
scheduler is noticed within hours; a broken authorization check may never be noticed. That is
why section 19 (security guidelines) and the testing requirements in section 18 are the core
of this effort, not decoration.

---

## 3. Threat Model

Stated explicitly, because everything that follows is derived from it.

### Assumed adversaries

| # | Adversary | Capability | Defence in v1 |
|---|---|---|---|
| A1 | Network participant on the local network | HTTP requests to the listener | Authentication required, deny by default, no anonymous endpoint except `/health` |
| A2 | Compromised container on the same bridge network | Network access, possible traffic capture | TLS terminated at the listener (ADR-8), token auth |
| A3 | Compromised deploy runner | Holds a valid deploy token | Policy limited to that runner's paths; every access audited |
| A4 | Reader of the database file (backup, stolen disk) | Full ciphertext | Envelope encryption; the database is worthless without the master key |
| A5 | Root on the host | Everything: process memory, `.env`, database | **Not defended against.** Deliberate boundary, see below |
| A6 | Internal user with partial access | Valid identity, limited policy | Policy evaluation, audit, no escalation path through the API |
| A7 | Browser context of the admin UI (XSS, malicious npm dependency) | Runs in the tab of a signed-in human | UI is read-only, reveal is per-value, strict CSP, no `v-html`, token in `sessionStorage` rather than a cookie (section 15) |
| A8 | LLM client at the MCP server | Valid token, but responses flow into model context and provider logs | Plaintext only via opt-in capability on narrow paths, metadata by default; MCP context marked in the audit (section 16) |
| A9 | Anonymous reporter at `POST /v1/report` | Unauthenticated requests carrying a candidate value, and whatever volume they can generate | Identical response for a match and a miss, so the endpoint is no oracle; size and rate limits applied *before* the audit write and the store lock; one monotonic metadata write per matched version; no path to any tripwire tier above `alert`; off unless a deployment enables it (section 23) |

### Deliberately not defended against

- **Root on the host (A5).** Whoever is root reads the master key from the service `.env` and
  from process memory. The same is true for OpenBao with a static seal, and it is the
  consequence of choosing unattended startup (ADR-5). Moving this boundary requires Shamir
  unsealing or an HSM — both retrofittable without changing the data format.
- **A compromised build pipeline.** Whoever replaces the image wins. The countermeasure is
  supply-chain hygiene (section 19), not application code.
- **Side channels beyond timing in token comparison.** No protection against cache timing or
  Spectre-class attacks.

### Explicitly defended against, because these are the most common real-world leaks

- **Secret in a log.** Structurally prevented: secret-bearing types implement neither `Debug`,
  `Display` nor `Serialize` (section 19). This is the primary reason for the language choice.
- **Secret in an error message.** Error types never carry values, only paths and identities.
- **Secret in a core dump or swap.** `ZeroizeOnDrop`, memory limits equal to swap limits in
  the container runtime, core dumps disabled.
- **Ciphertext relocation.** A ciphertext cannot be copied from path A to path B, because path
  and version are bound as AAD (section 5).

---

## 4. Architecture Decisions

Short form per decision: what, why, what was rejected. Moves to `docs/adr/` as individual
files at project start. ADR-1 through ADR-10 concern the core and are listed here; ADR-11 and
ADR-12 (UI) live in section 15, ADR-13 (MCP) in section 16 — next to their context, but of
equal standing and likewise one file each in `docs/adr/`.

### ADR-1 — Language: Rust (edition 2024)

**Decision:** Rust.

**Rationale.** The case is closer than it looks. Go has real advantages: cryptography in the
standard library — one maintained implementation, and since Go 1.24 a FIPS-140-3 validated
module in pure Go — and a considerably smaller dependency surface. Both are genuine security
benefits, not footnotes.

Rust wins anyway, because of one property that is **unreachable in principle** in Go:
deterministic erasure and non-printability of key material. `zeroize` guarantees overwriting
via `Drop` and compiler fences; `secrecy::SecretBox` turns accidentally logging a secret into
a **compile error**, because the type cannot be formatted. In Go, a `fmt.Printf("%+v", cfg)`
prints the master key — and that is the single most common real-world cause of leaks.

The star witness is OpenBao itself, from its RFC on removing `mlock`:

> "go's garbage collector can and will move and copy memory as it sees fit. `mlock` on a
> go-managed buffer just prevents the original memory location from being swapped out to disk,
> but does nothing to the copies that the go runtime will periodically create."

The reference product, written in Go, concludes that it cannot stop secrets from being copied
around memory uncontrollably — and removes the protection entirely as a result.

Go's advantages are dissolved through discipline: a hard dependency budget, `cargo-deny`, and
`#![forbid(unsafe_code)]`. FIPS-validated primitives are available in Rust through
`aws-lc-rs`, just not in the standard library.

**Rejected:** Go (see above). Not considered: anything with a garbage collector and no wipe
guarantee.

### ADR-2 — No custom configuration DSL

**Decision:** `ciphr.toml` for server configuration, policies as an explicitly typed TOML
structure. No hand-written lexer, parser, or compiler.

**Rationale.** In a job scheduler, a custom DSL can be the right call — a parser bug there
means a job fires at the wrong time. Here the same code would sit **in the authorization
path**, and a parser bug becomes an authorization bypass. That is the wrong place for
homegrown novelty. TOML rather than YAML, because YAML has implicit type coercion
(`no` → `false`) that is dangerous in a policy file.

**Rejected:** a custom DSL. OPA/Rego via `regorus` — an interpreter in the authorization path
is overkill for path-based capabilities; it stays an escalation option should complex
conditions ever be required.

### ADR-3 — Policies from configuration, not through the API

**Decision:** Policies are loaded from configuration and live in version control. No
policy-write API in v1.

**Rationale.** Policy changes become reviewable and gain a history — the commit history is
itself an audit trail. At the same time this removes the most dangerous write API there is.
Downside: a policy change requires a deploy. For a handful of identities, that is the right
trade.

**Rejected:** the Vault model (policies mutable at runtime through the API). Retrofittable if
the number of identities demands it.

### ADR-4 — No Bitwarden-compatible API

**Decision:** A small API of our own.

**Rationale.** Two independent reasons.

*Size:* Vaultwarden needs **1.26 MB of Rust** for the Bitwarden server API and still does not
implement all of it — `organizations.rs` alone is 112 KB, `ciphers.rs` 78 KB, `accounts.rs`
63 KB, plus `emergency_access`, `sends`, `two_factor`, `push`, `icons`. That is the size of an
entire mid-sized Rust workspace, spent on foreign compatibility.

*Architecture — the actual reason:* Bitwarden is zero-knowledge. Per its whitepaper, "all
encryption is done locally" and "the server never stores and cannot access your master
password or your cryptographic keys." If the server cannot decrypt, it cannot hand a
plaintext secret to a CI job that authenticates with a token — every consumer would have to
hold key material, which makes per-identity access control cosmetic and reduces the audit to
"who fetched which blob". Once fetched, the blob is decryptable offline forever, with no
server-side revocation. That is precisely the weakness that ruled out file-based encryption
tools such as SOPS.

**Rejected:** Bitwarden API compatibility; merging with an existing password manager.

### ADR-5 — Seal: static key from the environment, behind a trait

**Decision:**

```rust
trait Seal {
    fn unseal(&self) -> Result<RootKey>;
    fn rewrap(&self, key: &RootKey) -> Result<SealedRootKey>;
    fn id(&self) -> &str;
}
```

v1 implements `StaticEnvSeal` (master key from `CIPHR_MASTER_KEY`). `ShamirSeal`,
`Pkcs11Seal` and `TransitSeal` are anticipated but not built.

**Rationale.** Unattended startup is the precondition for deploys not depending on a human
being available. The key therefore sits in the same `chmod 600` service `.env` that already
holds other signing secrets — no regression against the status quo, but also **no
cryptographic gain**: trust shifts onto the forge secret store and file permissions. This is
an availability decision, and it belongs in the README as such, not in a footnote.

The trait is the actual substance of this decision: it keeps the move to Shamir or an HSM open
**without a data format change** — because the master key only wraps the root key (section 5),
so a seal change is a re-wrap of a single record.

**Rejected:** Shamir with manual unsealing in v1 (availability). Both mechanisms in v1 (two
security-critical paths, both of which would need full test coverage).

### ADR-6 — Auth: machine identities with tokens

**Decision:** Identities with assigned policies, authentication via bearer tokens. Auth
methods behind a trait so OIDC can follow.

**Rationale.** Reduces the number of long-lived secrets in the forge to **one** (the bootstrap
token of the deploy runner). Every access is attributed to an identity — which is what makes
the audit meaningful in the first place.

**Rejected for v1:** OIDC — better from a security standpoint, because no long-lived secret
would be needed at all. Forgejo has supported OIDC for Actions since v15.0 (workflow key
`enable-openid-connect`, requires runner > v12.5.0), so this is concretely implementable. It
stays out of v1 regardless (a second security-critical auth path), but it is first on the
post-v1 list — details in section 14. mTLS — would require a certificate authority, exactly
the piece of PKI that section 1 keeps out.

### ADR-7 — Storage: SQLite behind a store trait

**Decision:** `rusqlite` with WAL, migrations as numbered SQL files. A `Store` trait so
PostgreSQL remains possible later.

**Rationale.** The data volume of a secret store is tiny and the access patterns are trivial.
SQLite is one of the most thoroughly tested codebases in existence, backup is a `VACUUM INTO`
plus an existing file-backup job, and it introduces **no network dependency** — a database
outage would otherwise take the secret store down with it. The database is not a trust anchor
in any case: it contains nothing but ciphertext.

Deliberately **not** `sqlx`: macro-based query checking adds little here and pulls a large
async layer into the dependency surface.

**Rejected:** PostgreSQL (network dependency, more attack surface). Raft or an embedded KV
store (consensus code is its own class of bug, worth it only with genuine HA requirements).

### ADR-8 — TLS terminates at the service, not at the reverse proxy

**Decision:** The listener terminates TLS itself (`rustls`). The reverse proxy connects over
HTTPS with a pinned internal certificate.

**Rationale.** Services on a shared container network commonly speak plaintext behind a
reverse proxy, and for most of them that is acceptable. For a secret store it is not: on a
shared bridge network a compromised neighbouring container (A2) is a realistic adversary, and
the content of these connections is plaintext secrets. The cost is one certificate plus a line
of proxy configuration.

**Rejected:** plaintext behind the proxy like everything else. This deviation from convention
is intentional and must be justified in the README.

### ADR-9 — HTTP stack: axum, but narrow

**Decision:** `axum` (on `hyper`), `rustls`, `rusqlite`. No `sqlx`, no broad `tower-http`
middleware stack.

**Rationale.** This corrects an earlier idea of hand-rolling routing on `hyper`. Hand-written
path routing is its own class of bug in a service whose authorization is **path-based**: any
divergence between routing normalization and policy normalization is an authorization bypass.
A widely used, well-tested router is safer here than a few dependencies fewer. The dependency
budget is spent elsewhere — at the database layer and in middleware.

**Consequent rule:** path normalization exists **exactly once** in the codebase and is shared
by the router and the policy evaluator. That is a testing requirement, not a style note.

### ADR-10 — Port `:4400`

**Decision:** API on `:4400`.

**Rationale.** Avoids `:8200` (Vault/OpenBao — no confusion should both ever run side by
side), `:9090` (Prometheus) and `:8080`.

---

## 5. Cryptographic Design

**Ground rule: no custom constructions.** Only AEAD with established primitives, composed
according to the standard envelope-encryption pattern.

### Key hierarchy

```
CIPHR_MASTER_KEY          (32 B, from the environment, never persisted)
        |  AES-256-GCM, AAD = "ciphr/root-key/v1" || root_key_id
        v
  Root Key (RK)           (32 B, generated at `init`, stored wrapped)
        |  AES-256-GCM, AAD = "ciphr/dek/v1" || dek_id
        v
  Data Encryption Key     (32 B, ONE per secret version)
        |  AES-256-GCM, AAD = canonical(path) || version || dek_id
        v
  Secret plaintext
```

### Rationale for the individual choices

**Why the root key as an intermediate step?** So that a master key change — or a seal change
per ADR-5 — re-wraps exactly **one** record instead of re-encrypting every secret. Without
that indirection, key rotation would be a full rewrite of the entire database, which is to say
something nobody ever dares to do.

**Why one DEK per secret version?** Three effects. The blast radius of a compromised DEK is a
single version. Crypto-shredding a version is deleting its wrapped DEK, without touching other
versions. And — the most important point — **nonce reuse becomes structurally impossible**:
each DEK encrypts exactly one payload, so exactly one nonce exists per key. This is the only
construction in which the best-known GCM footgun *cannot* occur.

**Why AES-256-GCM and not XChaCha20-Poly1305?** Hardware acceleration is available on the
target platform, and AES-256-GCM is FIPS-approved, which keeps the `aws-lc-rs` FIPS mode
option open. XChaCha20's main advantage — a large nonce that makes random collisions
practically impossible — is moot given the one-DEK-per-version design.

**Why bind path and version as AAD?** So that an adversary with database write access cannot
copy the ciphertext of `infra/service-a/db-password` into the row for
`infra/service-b/db-password`. Without AAD binding that would be a silent privilege transfer;
with it, decryption fails.

**Token storage.** Tokens are high-entropy (256 bits of randomness), so password hashing
(Argon2id) is **wrong** here — it costs CPU time on every request and buys nothing when no
dictionary attack is possible. What is stored is `HMAC-SHA256(pepper, token_secret)`, where
the pepper is derived from the root key. Effect: a database-only leak does not permit offline
verification, because the pepper is reconstructible only with the master key.

**Token format.** `cph_<id:8 chars><secret:43 chars base64url>`:

- The `cph_` prefix makes tokens recognizable to secret scanners (gitleaks, GitHub secret
  scanning) — an accidentally committed token gets found instead of quietly rotting.
- The leading, **non-secret** `id` allows a database lookup without a table scan over HMACs.
  The secret part is then compared in constant time (`subtle`).

**Argon2id** is needed only for human passwords. Since v1 has no password login, it does not
appear in v1.

### Crypto dependencies (v1)

| Purpose | Crate |
|---|---|
| AEAD | `aes-gcm` (RustCrypto); keep the `aws-lc-rs` FIPS option open |
| HMAC / hash | `hmac`, `sha2` |
| Randomness | `rand` with `OsRng` — **never** a deterministic RNG in production paths |
| Wiping | `zeroize` |
| Secret types | `secrecy` |
| Constant-time comparison | `subtle` |
| TLS | `rustls` |

---

## 6. Policy Model

Path-based capabilities, deny by default. Small enough that one person can review the
evaluator in full.

```toml
[[identity]]
name     = "deploy-runner"
kind     = "machine"
policies = ["infra-read"]

[[policy]]
name = "infra-read"

  [[policy.rule]]
  path         = "infra/**"
  capabilities = ["read", "list"]

  [[policy.rule]]
  path         = "infra/ciphr/**"
  capabilities = []          # explicit denial: no self-access
```

### Semantics — binding, because ambiguity here is an authorization bug

- **Deny by default.** No matching rule means denial.
- **Globs:** `*` covers **exactly one** path segment, `**` covers one or more segments. No
  regular expressions, no character classes.
- **Most specific match wins.** Specificity is the number of literal segments. On a tie,
  denial wins.
- **Empty `capabilities` is an explicit denial**, not the absence of a rule — and it beats any
  less specific permission.
- **Path normalization exactly once in the codebase** (ADR-9): no `..`, no `//`, no trailing
  slash, NFC normalized, case sensitive. Router and evaluator call the same function.

### Capabilities in v1

`read`, `write`, `delete`, `list`, `undelete`. Administration (identities, policies) does not
go through the API but through configuration and the CLI on the host (ADR-3) — so there is no
`admin` capability that could be obtained by trickery.

### Testing requirement

Property tests over path matching (normalization is idempotent; `**` subsumes `*`; specificity
is a total order), a table of positive and negative cases updated on every change to the
evaluator, and a fuzzer against path normalization.

---

## 7. Audit Design

The reason this project exists — and therefore the component with the strictest requirements.

### Fail-closed

If writing to **all** configured audit devices fails, the request is rejected with `503` and
**no secret is served**. Adopted from OpenBao, because the alternative is the trap that ruled
out other candidates: an access that could not be logged but happened anyway is worse than an
access that failed.

The audit record is created **before** the response is sent, not after.

Operational consequence: a full audit volume takes the service down. That is intended and
requires monitoring (section 17) — it is not a defect to be optimized away later.

### Hash chain

Every entry carries `prev_hash`, and the record is bound via
`SHA-256(prev_hash || canonical_json(payload))`. This makes subsequent modification or
deletion of individual entries **detectable** rather than merely unlikely. A documented
recovery path for a broken chain is part of this from the start, not an afterthought.

### Contents of an entry

Recorded: timestamp (UTC), sequence number, `prev_hash`, identity (id and name), action,
normalized path, secret version, decision (`allow`/`deny`), name of the matching policy rule,
request id, client IP, user agent, HTTP status.

**Never recorded:** the secret value, key material, or the token (only its non-secret `id`).
Enforced by the payload struct containing only formattable types, while secret types have no
`Serialize` — a violation is a compile error.

### Devices in v1

`sqlite` (its own table) and `file` (JSON Lines). Size-based rotation, `SIGHUP` reopens the
file. `syslog` and `http` later.

### Retention, and the anchor at the cut

Deleting old entries is not an option; archiving them is. The chain verifies a gap-free
sequence, so removing entries makes everything after them unverifiable from genesis, and
`audit verify` reports the hole as `SequenceGap` — a tampering signal. An audit trail that
routinely claims tampering is one nobody reads, which is why a time-based retention policy
cannot simply be pointed at the queryable device.

The required shape:

1. **The queryable device (`sqlite`) is bounded**, so `/v1/audit` and the UI stay small and
   fast.
2. **The archive device (`file`) is unbounded** and rotates by size; rotated files go to the
   deployment's backup. The evidence stays complete, just not queryable.
3. **At every cut, the head hash, its sequence number, and the date are recorded outside the
   store.** Verification then starts from that anchor instead of from genesis.

Point 3 pays for itself twice. An anchor outside the store is the only defence against a
forward rewrite — anyone who can write the store can recompute every hash forward, and the
chain then verifies — so retention and that defence are the same operation when they are done
together, and two separate ones when they are not.

**All three are built.** `ciphr audit cut --keep N --anchor FILE --archive FILE` bounds the
`sqlite` device, and it does the three as one operation because doing any of them alone is the
mistake. It verifies the chain, then establishes that every record it would remove is in the
archive — matched by the hash of the line, so a match is byte-identical — then appends the
anchor at the cut and syncs it *before* the delete, and appends an anchor over the remainder
after. Every refusal happens before anything is removed. `audit_cut` (migration 004) holds the
sequence number and hash the cut ended at, so the routine `verify` on a cut store does not
report tampering; that row is a claim by whoever can write the store, and the anchor at the same
sequence is what turns it into evidence — `verify --anchor` compares the two and says which
answer it got.

Three properties of the cut are decisions rather than implementation:

- **It is a command, not something the service does.** A cut has to be anchored outside the
  store, and the service is what an anchor exists to be independent of. An anchor the service
  wrote about its own trail is worth nothing against the service.
- **It needs neither the store lock nor the master key**, like `anchor` and `verify`, so it runs
  against a live service. Retention that needs downtime does not get scheduled, and an unrun
  bound is not one.
- **It never empties the table.** An empty queryable log has no head, and a service resuming
  from no head would begin a second chain at sequence one in a table that had a million records.

`--keep` is a count rather than an age: the bound it answers is the size of the queryable
device, and age-based retention belongs on the archive, where the host's tooling already does
it. The fill-level health check (section 17) remains necessary — it is what catches a schedule
that is not keeping up.

---

## 8. Data Model

Migrations as `NNN_name.sql`, monotonically numbered, additive, registered in numeric order.

| Table | Contents |
|---|---|
| `meta` | Schema version, `sealed_root_key`, `root_key_id`, `seal_id` |
| `secrets` | `id`, normalized `path` (unique), `current_version`, `rotation`, timestamps |
| `secret_versions` | `secret_id`, `version`, `wrapped_dek`, `dek_nonce`, `ciphertext`, `nonce`, `created_at`, `created_by`, `deleted_at` |
| `identities` | `id`, `name` (unique), `kind`, `created_at`, `disabled_at` |
| `tokens` | `token_id` (unique), `identity_id`, `hmac`, `expires_at`, `created_at`, `last_used_at`, `revoked_at` |
| `audit_log` | `seq`, `ts`, `prev_hash`, `hash`, `payload` |

Deletion is a soft delete (`deleted_at`); genuine destruction goes through crypto-shredding
(deleting `wrapped_dek`) and therefore takes effect in backups too, once the backup chain has
rotated.

### The `rotation` field

Not every secret can be rotated safely. Rotating some of them destroys data. Since the
operational promise of a secret store is rotation, and versioning makes the mistake *easier*
rather than harder — write a new version, the next deploy renders it, the data is
unreadable — the classification belongs in the data model:

| Value | Meaning |
|---|---|
| `unclassified` | **Default since 2026-08-20.** Nobody has said. Counts as needing care. |
| `rotatable` | Normal case. |
| `seed-only` | Only evaluated on first start (database seeding); later changes have no effect |
| `breaks-data` | Encrypts data at rest — a new value makes existing data unreadable |
| `volume-bound` | Must match the value a persistent volume was initialized with |
| `invalidates-sessions` | Rotation works, but discards all sessions and derived tokens |

`rotation` is pure metadata and does **not** influence authorization — it drives warnings in
the CLI and the UI. It is in v1 deliberately, because classifying an existing corpus after the
fact is far more tedious than carrying the field from the start.

**The default was `rotatable` until 2026-08-20, and that was a defect in this table.** A default
is what a value gets when nobody decides, and `rotatable` is a decision — "safe to rotate" — so
every secret written without an explicit class asserted the one property whose being wrong destroys
data, and the shortest path through `put` and `import` was the one that asserted it. It also made
the phase 6 criterion below unverifiable: a deliberate `rotatable` and an untouched default were
indistinguishable. `unclassified` is the absence of an answer, it counts as needing care, and
`ciphr list --rotation unclassified` is what makes "is the corpus classified?" a question with an
answer. Migration 005 rewrote existing `rotatable` rows and left every other class alone.

---

## 9. Crate Layout

```
ciphr/
├── crates/
│   ├── ciphr-core/       Domain types, path normalization, secret wrappers
│   ├── ciphr-crypto/     Envelope encryption, Seal trait, known-answer vectors
│   ├── ciphr-store/      Store trait + SQLite + migrations
│   ├── ciphr-policy/     TOML → typed → evaluator
│   ├── ciphr-audit/      Audit trait, hash chain, devices
│   ├── ciphr-server/     axum API, auth middleware, handlers
│   ├── ciphr-cli/        CLI — against the store directly, not through the SDK
│   ├── ciphr-sdk/        Rust client
│   ├── ciphr-run/        Route B wrapper: fetch, then exec (ADR-14) — SDK consumer
│   └── ciphr-mcp/        MCP server, post-v1 (section 16) — pure SDK consumer
├── ui/                   Vue 3 + TypeScript + Vite
│                         own image, optionally deployable (ADR-11, section 15)
├── docs/
│   ├── adr/              ADR-1 … ADR-13 as individual files
│   ├── threat-model.md
│   └── why-build-this.md
├── openapi.yaml
├── AGENTS.md   CHANGELOG.md   SECURITY.md   README.md
├── Dockerfile   Dockerfile.ui   docker-compose.yml
└── deny.toml
```

**Correction, 2026-08-20.** The line above used to read "`ciphr-cli` (uses the SDK)". It never did
and it should not: the CLI holds the master key, takes the store lock, and runs `init`, `put` and
`token issue`, none of which exist over the API and none of which should. The SDK is the client for
consumers *outside* the process that owns the database — route C, the MCP server (ADR-13), and
`ciphr run` if ADR-14 is accepted. A CLI routed through the API would need a running service in
order to initialize one.

`ciphr-crypto` and `ciphr-policy` are the two crates that must stay fully reviewable — they
get a line budget and no dependencies beyond those named in section 5.

---

## 10. API v1

Kept small. Every endpoint except `/health` requires authentication.

| Method | Path | Capability |
|---|---|---|
| `GET` | `/v1/health` | — (no secret, no identity) |
| `GET` | `/v1/secrets/*path` | `read` |
| `PUT` | `/v1/secrets/*path` | `write` |
| `DELETE` | `/v1/secrets/*path` | `delete` |
| `GET` | `/v1/versions/*path` | `list` |
| `GET` | `/v1/list/*prefix` | `list` |
| `POST` | `/v1/export` | `read` on **every** path served |
| `GET` | `/v1/audit` | `read` on `sys/audit` |
| `GET` | `/v1/identities` | `read` on `sys/identities` |
| `GET` | `/v1/policies` | `read` on `sys/policies` |

`/v1/export` serves several secrets in one call and produces **one audit entry per secret
served**, not one per call — otherwise bulk retrieval would be a blind spot in the audit.

`/v1/health` returns seal state and audit device state, but no inventory counts: an
unauthenticated endpoint does not reveal how many secrets exist.

**`/v1/health` states what the process enforces, not only that it is alive.** Recorded
2026-08-18. The design has no switch that turns a security property off — TLS is a non-optional
field, there is no feature flag in the workspace, and the one relaxation that exists (`--force`
on secret output) suspends a heuristic for a single invocation rather than disabling a property.
The constructive counterpart to that strictness is a service that *says* what it is enforcing,
so an operator can check it from outside rather than trusting a claim in a README:

- **Seal state** — already specified above, and already returned.
- **Audit device state, per device.** Presently the endpoint lists the device names captured at
  startup and nothing about whether any of them still accepts records. `AuditSink::record`
  returns the failures and the server discards them, so a device that has been failing for a
  month is invisible. This is the third of the three monitoring checks in section 17, and it
  cannot currently be built.
- **Transport** — that TLS is terminated here, and the certificate's expiry, so a renewal
  deadline is monitorable rather than a surprise.

The constraint from the paragraph above still binds: this endpoint is unauthenticated, so it may
report *what is enforced* and never *what is stored*. A device name, a boolean, and an expiry
date are properties of the process. A count of secrets, a path, or an identity is not.

**Administrative read endpoints run through the same policy evaluator:** `/v1/audit`,
`/v1/identities` and `/v1/policies` are authorized as the virtual paths `sys/audit`,
`sys/identities`, `sys/policies` — there is no second authorization mechanism and no `admin`
capability. They are strictly read-only (ADR-3); writing identities and policies stays with
configuration and the CLI. The `sys/` prefix is **reserved** as a secret path: `PUT` and
`DELETE` on `sys/**` are rejected with `400`, so the virtual paths can never collide with real
secrets.

**Why `/v1/versions/*path` rather than `/v1/secrets/*path/versions`:** with a catch-all path,
a secret named `foo/versions` would be indistinguishable from the version listing for `foo` —
exactly the routing/policy divergence ADR-9 warns about. Suffix parsing on catch-all routes is
therefore forbidden in general; every operation gets its own prefix.

`POST /v1/auth/oidc/login` is reserved for the OIDC auth method (section 14, post-v1) and does
not exist in v1 — but the path is listed as reserved in `openapi.yaml` from v1 on, so it does
not get claimed for something else by accident.

**Reserved the same way, for phases 8 and 9:** `GET /v1/honeypots` (section 22), `POST /v1/report`
and `GET /v1/leaks` (section 23), plus the virtual paths `sys/honeypots` and `sys/leaks`. The virtual
names cost nothing to reserve now and are already unusable as secrets, because `sys/**` is refused
for writes. `POST /v1/report` is the one reservation that matters beyond tidiness: it is the only
route in the design that will ever be unauthenticated besides `/v1/health`, and reserving it names
that fact in the API document rather than leaving it to be discovered when the route appears.

---

## 11. CLI

```
ciphr init                          # generate root key, create database
ciphr put   infra/host/svc/JWT_SECRET --rotation invalidates-sessions
ciphr get   infra/host/svc/JWT_SECRET
ciphr list  infra/
ciphr export --path infra/host/svc --format dotenv
ciphr import --from-dotenv ./.env --prefix infra/host/svc --dry-run
ciphr identity add deploy-runner --policy infra-read
ciphr token issue deploy-runner --ttl 90d
ciphr audit tail
ciphr audit verify                  # verify the hash chain
ciphr audit anchor --out FILE       # record the head outside the store, section 7
ciphr audit verify --anchor FILE    # and check the chain against it
ciphr audit cut --keep N --anchor FILE --archive FILE   # bound the queryable trail, section 7
ciphr dump --format portable        # exit path, see section 2
```

**`ciphr run` is not on this list, and that is the decision rather than an omission.** It is
`ciphr-run`, its own crate and its own binary, because it is bind-mounted into images this
project does not own: its dependency list is what guarantees no store, cryptography or
master-key code can be reached from inside a foreign container, and the four global options
above (`--database`, `--master-key-env`, `--master-key-file`, `--policies`) have no business
in that context. See ADR-14, accepted 2026-08-20.

```
ciphr-run --url URL --token-file FILE --ca PEM --prefix PATH -- COMMAND [ARGS...]
```

`import --from-dotenv` is the migration tool for an existing corpus: non-interactive, and
`--dry-run` shows the target paths without writing. It reads a file and therefore does not
violate the argument rule below.

**Two corrections from the first real migration, 2026-08-19.** Both were found downstream, and
both are stated here because this paragraph is what a reader plans against.

`--rotation-map` **does not exist**, and the decision on 2026-08-20 was to leave it that way for
now. `ImportArgs` has `--rotation`, which sets one class for the whole import, and section 8 exists
precisely because one corpus mixes classes -- a single `.env` was observed carrying both
`volume-bound` and `rotatable`. The safe order remains: import with the most dangerous class present
and then downgrade per path with `ciphr rotation`, never the reverse.

What changed instead is the thing underneath it. The problem the map was meant to solve is that one
import cannot express several classes; the *larger* problem was that an import expressing **no**
class silently claimed the safest one. Fixing the default (section 8) removes the damage; the map
only removes typing. So it is deliberately deferred: with `unclassified` as the default and
`ciphr list --rotation unclassified` to enumerate what is left, the map is ergonomics, and its shape
is better decided against a real corpus than in advance. If it is built, a TOML file mapping name to
class is the form to prefer over a repeatable flag -- it is reviewable and can live in the
deployment's own repository, and ADR-2 already rules out inventing a syntax for it.

`--from-dotenv` presumed there is a file; **`--stdin` was added on 2026-08-20** and reads the same
format with the same parser, so a corpus that has no `.env` on disk does not have to acquire one to
be migrated. That closes the mechanical half of the gap.

The other half is not a gap in the tool and cannot be closed by one: **a forge does not give a
secret back.** An import's only possible sources are a rendered file, a process that can produce the
values, or the operator. For a value whose only copy lives in a forge, the documented answer is to
generate a new one, `put` it, and switch the consumer -- a deliberate rotation rather than a copy,
which also retires a value that has been in every job log's blast radius for years. The exception is
a value that cannot be regenerated (`breaks-data`, `volume-bound`), which has to be recovered from
the system holding it. `docs/operations/cli.md` carries this as a procedure.

Two rules. Values are **never** accepted as arguments — they would end up in shell history and
in `/proc` — but via stdin or an interactive prompt. And output containing secrets checks
whether stdout is a TTY; piped output without an explicit `--force` produces a warning.

`dump --format portable` is deliberately part of v1: it is the insurance against the scenario
in section 2.

---

## 12. Configuration

```toml
# Required, and first: `policies` is a top-level key, and in TOML a bare key written
# after a table header belongs to that table. Further down it would land inside
# `[seal]` and be refused. Identities and policies themselves: see section 6.
policies = "/etc/ciphr/policies.toml"

[server]
listen = "0.0.0.0:4400"

[server.tls]
cert = "/etc/ciphr/tls/cert.pem"
key  = "/etc/ciphr/tls/key.pem"

[storage]
backend = "sqlite"
path    = "/var/lib/ciphr/store.db"

[seal]
type = "static_env"
env  = "CIPHR_MASTER_KEY"

[[audit]]
type = "sqlite"

[[audit]]
type        = "file"
path        = "/var/log/ciphr/audit.jsonl"
rotate_size = "64MB"
```

The server **refuses to start** if no audit device is configured. A secret store without an
audit trail is a configuration error in this project, not an operating mode.

---

## 13. Secret Consumption Patterns

How a consumer gets a value out of ciphr and into a process without leaving plaintext behind.
This section is product documentation, because getting it wrong silently undoes the point of
the whole exercise.

### The blind spot: the `.env` file is not the only plaintext copy

The obvious idea — render an `.env`, then delete it after startup — is ineffective. Container
runtimes resolve environment values at container creation and bake them into the container
configuration. After that, plaintext exists in three places:

1. The rendered `.env` file — the one people think of.
2. The container configuration on disk, readable via the runtime's inspect command.
3. `/proc/<pid>/environ` of the running process.

Switching from interpolation to an env-file directive does **not** help: the value is baked
into the container config either way. Anyone who eliminates only (1) has not reduced the
attack surface, only the feeling of it. Note that (2) is readable by everyone with access to
the container runtime socket, which is typically a broader set of principals than root.

### Three routes, depending on the image

**A — natively file-capable.** The image reads the value from a file (a `*_FILE` convention, a
keystore, or similar). A `tmpfs` mount is then enough: no plaintext on disk, nothing in the
container config. The cheapest route where it is available. Widely supported examples include
PostgreSQL (`POSTGRES_PASSWORD_FILE`) and Elasticsearch (any variable with a `_FILE` suffix,
since 7.6).

**B — entrypoint wrapper.** The image only understands environment variables. A wrapper
entrypoint fetches the values, sets them in its own process environment, and `exec`s the real
entrypoint. Result: nothing on disk, nothing in the container config — the value exists only
in `/proc/<pid>/environ`, which is where it has to be anyway. Costs one derived image per
third-party service.

That cost is the problem with route B, and it is the route that applies to the most images.
**ADR-14 was accepted on 2026-08-20 and built as `ciphr-run`** — one statically linked binary
(3,347,368 bytes stripped, musl, verified static), bind-mounted, `entrypoint:` overridden —
which removes the derived image entirely.

Two things a deployment has to take from that record rather than from this paragraph. The
entrypoint pin is unchanged: overriding `entrypoint:` still means recording what it was, and
that value still drifts when the base image moves — **a rebuild traded for a pin**. And the
child can still read the token file, because `exec` does not change the filesystem view, so
**route B makes per-service token scoping matter more than it did**: a token scoped to the
prefix the service receives gives away nothing it did not already get, while a per-host token
covering several services means a compromised service can read the others'.

**C — the application itself.** For software you control, the clean route is for the
application to fetch its secrets from ciphr at startup. This is the actual justification for
shipping `ciphr-sdk` (section 9). A useful side effect: the audit entry then carries the
identity of the *service* rather than that of the deploy runner, which makes the audit
considerably more informative.

### What this does not solve

`/proc/<pid>/environ` and process memory remain readable to root — that is A5 in section 3 and
stays outside the threat model deliberately. The gain is that plaintext no longer rests on
disk, no longer lands in filesystem backups, and is no longer exposed through the container
runtime's inspect API.

### The consumer on another host

All three routes assume the consumer runs where the service is reachable. A deployment that
terminates TLS at the service (ADR-8) and publishes no port beyond its own host has no route at
all for a consumer elsewhere, and that decides which values can be **retired** rather than
merely re-homed: a value with several consumers stops being duplicated only once *every* one of
them can fetch it, so a single consumer out of reach keeps the old copy alive and authoritative.
A path prefix for shared values buys ordering while that is true, not retirement — it is not
wrong, it just promises something the topology does not yet supply.

Three decisions stand between here and a consumer beyond the service's own network, and none of
them has been made: network exposure, a certificate for a name that a foreign host resolves
(ADR-8, and the CA distribution in section 14), and handing a token across a trust boundary.
Route C is the same corner from the other side — an application that fetches its own secrets has
to reach the service from wherever it runs. What this bounds is **phase 7**, not phase 6: a
deploy that renders configuration from one reachable runner and copies it onward can retire a
forge secret for a host that never reaches the service itself. Runtime fetching cannot be
delegated that way, which is why the routes above are where the topology starts to bite.

### The honest target

Every host still needs one credential to authenticate to ciphr, and it lives in a file. The
realistic end state is **one secret per host**, not zero, plus auditing, plus rotation, plus a
bounded blast radius per token. That is an excellent trade — but it should not be sold as
"no more secrets on the host", neither internally nor in a README.

---

## 14. CI Integration: Secrets in Pipelines, Runner-Agnostic

How an arbitrary CI job gets its secrets — on a self-hosted GitHub Actions runner, a Forgejo
runner, a Gitea act_runner, or something more exotic.

### Three-layer principle

1. **Transport:** the API is plain HTTPS plus a bearer token (section 10). The minimal client
   is therefore `curl` — there is **no** runner-specific agent, no plugin, no forge
   integration as a precondition. That is the property that makes this runner-agnostic.
2. **Authentication:** two routes. A bootstrap token (the baseline, works everywhere) and OIDC
   federation (where the forge supports it, the long-lived secret disappears entirely).
3. **Consumption in the job:** CLI export formats, a composite action for the Actions family,
   and a documented curl fallback for everything else.

### Auth support matrix (verified 2026-08-18)

| Forge / runner | OIDC possible? | Notes |
|---|---|---|
| **Forgejo ≥ 15.0**, runner > 12.5.0 | **Yes — verified** | Workflow key `enable-openid-connect` (not GitHub's `permissions: id-token: write`); injects `ACTIONS_ID_TOKEN_REQUEST_URL`/`_TOKEN`; `iss = <instance>/api/actions`, `sub = repo:<owner/repo>:ref:<ref>` or `…:pull_request`, `aud` selectable per request |
| **GitHub Actions, self-hosted runner** | **Yes** | The ID token is always issued by GitHub's cloud (`token.actions.githubusercontent.com`), regardless of where the runner sits. Requires `permissions: id-token: write`. Validation needs outbound HTTPS from the ciphr host for the JWKS fetch |
| **Gitea** | **No** (as of 2026-08) | No native OIDC for Actions (go-gitea/gitea #26383, #33681); `ACTIONS_RUNTIME_TOKEN` is not a standards-compliant OIDC token. Token baseline only |
| Woodpecker, Jenkins, host cron | No | Token baseline |

Two consequences. First, **the bootstrap token stays the v1 baseline** — it is needed anyway
(Gitea, host scripts, anything without OIDC), and it is the only route that works identically
on every runner. Second, OIDC is no longer a vague future item but concretely implementable,
so it is **first on the post-v1 list** (section 18) while staying out of v1: a second
security-critical auth path that would have to be fully tested contradicts the v1 discipline
of ADR-5.

### Baseline: one token per repository identity

- **One identity per repository** (`ci-<repo>`), not per runner and not one for everything.
  That is the granularity at which the audit is meaningful: "repository X read secret Y."
- The token lives as a native secret of the respective forge — exactly one per repository. All
  other values move into ciphr. The workflow's `env:` block shrinks to `CIPHR_TOKEN` plus the
  non-secret variables (URL, CA).
- Policy shape: `ci/<repo>/**` read and list; where a CI job needs deployment values, the
  relevant `infra/**` path as well. Deny-by-default handles the rest.
- **Shorter TTLs for CI tokens than for the deploy runner** (say 30d rather than 90d) — they
  are spread across more systems. Rotation via `token issue` plus a forge secret update; with
  OIDC this disappears entirely.

### OIDC design (post-v1, behind the auth trait from ADR-6)

```toml
[[auth.oidc]]
name     = "forgejo"
issuer   = "https://git.example.com/api/actions"   # JWKS via OIDC discovery, cached
audience = "ciphr"                                  # mandatory, compared exactly

  [[auth.oidc.binding]]
  sub      = "repo:acme/widget:ref:refs/heads/main"  # exact or glob per section 6 rules
  identity = "ci-widget"
```

- Flow: the job fetches the forge ID token (`audience=ciphr`) and exchanges it at
  `POST /v1/auth/oidc/login` for a **short-lived** ciphr token (TTL ≤ 15 min, not persisted as
  a long-lived identity). Everything after that behaves like token auth.
- `aud` is mandatory and checked exactly — otherwise any forge token issued for a third-party
  service would also be valid here (confused deputy).
- The verified `sub` claim goes **into the audit entry**, in addition to the identity.
- Multiple issuers in parallel (an internal forge plus GitHub), one `[[auth.oidc]]` block
  each.
- Glob bindings (`repo:acme/*:ref:refs/heads/main`) use the same matching semantics and **the
  same code** as the policy evaluator (section 6) — a second matcher would be the same class
  of bug as a second path normalizer.
- **Check before enabling:** Forgejo shipped a security fix because the `…/idtoken` endpoint
  issued tokens without verifying `enable-openid-connect` (relevant for fork pull requests).
  The fix landed before the v15.0.0 release, so any v15.0.x contains it — verify for other
  forges accordingly.

### Consumption in the job — and the masking trap

**Values fetched at runtime are not masked automatically by any forge.** Only native forge
secrets are. A bare `curl | jq` writes secrets into the job log on any `set -x` or debug echo.
Masking is therefore part of the product, not of the documentation:

- `ciphr export --format actions-env` first emits `::add-mask::<value>` for each value (per
  line for multi-line values), then writes the variables to the file named by `$GITHUB_ENV`.
  Forgejo and Gitea runners honour the same convention, being act-based.
- Composite action `ciphr-action` (one repository, usable from GitHub, Forgejo and Gitea
  workflows — the syntax is identical): inputs `url`, `token` **or** `oidc: true`, `paths`,
  `format`. Downloads the pinned, checksum-verified static CLI binary (musl build) or falls
  back to curl.
- The curl fallback is a documented first-class route in `openapi.yaml` — for Woodpecker,
  Jenkins, and anything that does not speak Actions syntax:
  `curl --cacert "$CIPHR_CA" -H "Authorization: Bearer $CIPHR_TOKEN" …/v1/export`.
- Verification point for phase 3: `::add-mask::` demonstrably effective on Forgejo runners and
  act_runner (both are act derivatives, but that is to be proven, not assumed).

### Network reality

- A LAN-only deployment is reachable only by runners inside that network. Cloud-hosted runners
  are then deliberately out of scope — a property of the threat model (A1), not a shortcoming
  of the design.
- OIDC against the GitHub issuer requires outbound HTTPS from the ciphr host (JWKS fetch,
  cached with a TTL). An internal forge issuer is reachable locally; an internet outage must
  not break internal CI auth.
- Per ADR-8, CI clients need the internal CA certificate or its pin — distributed as a
  **non-secret** CI variable (`CIPHR_CA`) or action input. `-k`/insecure appears in no
  documentation and no example, not even "just for testing".

---

## 15. Admin UI

Guiding principle: **the UI is a viewer, not an administrator.** It makes the audit trail
usable — the actual purpose of the project (section 1) — and adds no attack surface to the
core.

### ADR-11 — The UI is an optional, independently deployable package

**Decision:** The UI is **not** embedded in the server binary. It is a static bundle shipped
as its **own container image** (`ciphr-ui`, a static file server), talking to the ordinary
public API over HTTPS. The server has no `serve-ui` mode, no `rust-embed`, no template engine,
no cookie or session code.

**Rationale.** Three reasons, in order.

*Attack surface.* Embedded asset serving brings static file handling, content-type sniffing,
caching headers, and cookie/CSRF questions into precisely the process that holds plaintext
secrets. A directory-traversal bug in the asset handler would then be a bug in the secret
server. Kept separate, the worst UI bug is a bug in a container that owns nothing but HTML.

*Optionality that is real, not nominal.* "Optional" should mean that whoever does not deploy
the UI does not **run its code** — not merely that a route is switched off. The service is
fully functional without the UI; the UI is an additive stack.

*Independent release cadence.* A UI fix (an npm advisory, a layout change) does not force a
new server image and therefore no restart of the secret server. That coupling would be most
expensive for exactly the service whose restart demands the most care.

**Rejected:** `rust-embed` into the server binary (single-artifact convenience, but violates
all three points above). A UI with its own backend-for-frontend (another service that sees
plaintext secrets — precisely what the separation avoids).

**Consequent rule:** the UI uses **only** documented v1 endpoints from section 10. An endpoint
that exists solely for the UI is a design error — the CLI must be able to do everything the UI
can. That keeps the API honest and the UI replaceable.

### ADR-12 — UI auth: token paste in v1, SSO afterwards

**Decision:** Sign-in by pasting a personal token (identity with `kind = "human"`, issued via
the CLI, short TTL). No password, no server-side session, no cookie. The token lives in
`sessionStorage` and is gone when the tab closes.

**Rationale.** v1 deliberately has no password path (section 5: Argon2id does not appear in
v1). A local user store with password hashing, a reset flow, and lockout logic would be a
second security-critical auth path for a viewing tool — the wrong effort-to-risk ratio. Token
paste costs **zero new server code**: it is the same bearer auth as for machines, just with an
identity of kind `human`.

`sessionStorage` rather than `localStorage`, because a token that survives closing the tab
becomes a permanent secret on shared workstations. No cookie, because without cookies the
entire CSRF class disappears.

**After v1:** the forge as an OAuth2/OIDC provider for UI login. That inherits MFA and account
lockout from the forge and removes the last manually distributed human token. It uses **the
same** OIDC validation as the Actions method (section 14) — one implementation, two callers.
Which is why the order "Actions OIDC first, then UI SSO" is also the cheaper one.

**Rejected:** local passwords (a second auth path, see above). Forge SSO immediately (would
pull the OIDC work forward and couple UI login to forge availability before the core is
finished).

### Scope: read-only with explicit reveal

| Area | Scope |
|---|---|
| **Audit browser** | The main purpose. Filter by identity, path, action, decision, time range; chain verification status (`prev_hash`) shown per page |
| **Secret browser** | Tree view over paths, metadata, version history — **no plaintext by default** |
| **Reveal** | The plaintext of a value only after an explicit click, one at a time, never in lists. Produces an ordinary audit entry via `GET /v1/secrets/*path` |
| **Identities & policies** | Read-only view: which identity holds which policy, which rule matches which path. Makes misconfiguration visible without making it creatable |
| **Health** | Seal state, audit device state |

What the UI **cannot** do: change policies or identities (ADR-3 — that would require a
policy-write API, the most dangerous API of all), issue or revoke tokens, write or delete
secrets. Everything that writes stays with the CLI and the API.

This restriction is not a stopgap. It keeps the path through which an XSS finding could act
limited to "read what the signed-in human is allowed to read anyway".

### Frontend security requirements

Binding, because a UI holding plaintext secrets in the DOM has its own class of failure:

- **Reveal is always a single action.** No "show all", no plaintext in lists or in exports
  from the UI. A bulk reveal would be a bulk audit entry and a bulk leak risk at once.
- **Strict CSP**, served by the UI container: `default-src 'none'`, `script-src 'self'`,
  `connect-src` restricted to the API origin, no `unsafe-inline`, no `unsafe-eval`. Vite build
  without inline scripts.
- **No `v-html`** on any path carrying server data. A CI grep gate, like the `println!` rule
  in section 19.
- Revealed plaintext is removed from component state when leaving the view and never lands in
  global state, `localStorage`, or a URL.
- **No service worker, no offline cache.** A cached secret is a secret without an expiry date.
- A separate `npm audit` and dependency budget for `ui/`, distinct from the Rust budget.
  Frontend dependency sprawl would otherwise quietly undercut the supply-chain discipline of
  section 19.

### Deployment

A separate `ciphr-ui` service in the same stack, with its own hostname or a path prefix on the
same host — that choice is settled together with the CORS question. It needs **no** volume,
**no** `.env`, and **no** access to the database or master key. Not deploying it costs nothing
but the UI.

The UI talks to the API **from the browser**, not server-side. That means either same-origin
routing through the reverse proxy (recommended: `/` → UI container, `/v1/*` → ciphr, avoiding
CORS entirely) or an explicit, narrow CORS allowlist on the server.

---

## 16. MCP Server (post-v1)

Planned, but explicitly **after** v1 — recorded here so v1 does not build anything that blocks
it later.

### Purpose and boundaries

An MCP server makes ciphr accessible to agents: "which secrets does service X have?", "who
accessed `infra/**` last week?", "is the audit chain intact?". This is primarily an **audit
and inventory tool** — the area where an agent adds real value without plaintext ever needing
to flow.

### ADR-13 — MCP as a separate process, stateless, Streamable HTTP

**Decision:** A separate `ciphr-mcp` binary in its own container, speaking **Streamable HTTP**
(the current MCP transport, not the superseded HTTP+SSE). **Stateless**: no server-side
session state, no session-id binding to local storage, every request fully authorized on its
own. It is a **pure client** of the public v1 API — no database access, no master key, no
cryptography.

**Rationale.** Stateless here is not merely an MCP convention but a security property: a
server without session state cannot hold a token or a revealed secret between requests. There
is no cache to read out. It is also restartable at will and horizontally replicable, should
that ever be needed.

Being a pure API client upholds the guarantee from ADR-11: **exactly one process in the system
holds plaintext secrets and key material** — the server. The UI and MCP are interchangeable
attachments.

**Rejected:** an MCP endpoint in the main server (same reasons as ADR-11, plus: MCP clients
are LLM-driven and therefore the least predictable request source in the system). stdio
transport as the only route (works only on the same machine; the goal is network clients).
HTTP+SSE (superseded).

### Auth and the LLM-specific hazard

The MCP server holds **no** identity of its own. The calling user's token is passed through
(`Authorization` header per request), and everything is authorized against **their** policy
and audited under **their** identity. An MCP server with its own far-reaching identity would
be a confused deputy — and the audit would show the same meaningless identity for every
access.

**Plaintext is opt-in, not the default.** Everything an MCP tool returns lands in the model
context and potentially in provider logs — a trust boundary the HTTP API does not have.
Therefore:

- Default tools return **only** metadata, listings, and audit queries. An agent can explore
  the inventory completely without a single value flowing.
- Plaintext reads exist only for identities whose policy **explicitly** permits it, and only
  on narrowly scoped paths. Mechanism: a dedicated capability (name to be fixed during
  implementation) — not a special case in the evaluator, but a regular member of the
  capability set from section 6, so evaluation remains a single code path.
- Every such retrieval is a single audit entry, additionally marked with the MCP context. This
  makes it possible to distinguish afterwards what a human read from what flowed into a model.
- Audience and provenance checks analogous to section 14, once OIDC is in place.

### Tools (draft)

`list_secrets(prefix)`, `get_secret_metadata(path)`, `list_versions(path)`,
`query_audit(filter)`, `verify_audit_chain()`, `describe_policy(identity)`, `health()` — all
metadata-based. Plus `read_secret(path)` **only** under the opt-in rule above.

### What v1 must get right for this

None of this is extra work — these are properties v1 should have anyway, recorded here as
commitments:

1. **A complete `openapi.yaml` from phase 3** (already in section 20) — the MCP server is
   derived from it, not written alongside it.
2. **Audit queries with usable filters** in the API, not just `tail` in the CLI. Without
   server-side filters the MCP server would have to search the audit client-side and pull
   large volumes into the model.
3. **Metadata endpoints without value access** — a `HEAD` or metadata result on
   `/v1/secrets/*path` returning existence, version, and timestamps without decrypting the
   value. Useful for the UI as well (secret browser without plaintext).
4. **No server state that presupposes a session** — already the case, since bearer auth is
   stateless.

---

## 17. Operations

**Memory and swap.** Set the container's memory limit and swap limit to the same value, so
this container cannot be swapped to disk. Key material in swap survives `ZeroizeOnDrop`.

**Backup.** The SQLite file through the existing file-backup job. The master key is **not** in
the backup — without it the backup is worthless, with it in the same backup it would be
pointless. A break-glass copy of the master key belongs in a human-oriented password manager
plus an offline copy. A restore drill belongs in the regular backup audit cycle.

**Monitoring.** Three health checks, all three necessary:

1. `/v1/health` reachable.
2. **Seal state.** A sealed service responds but is non-functional — an HTTP 200 check alone
   cannot distinguish that from "healthy".
3. **Audit device state and audit volume fill level.** Because of fail-closed, a full disk is
   a total outage, not a logging gap. **This check is not buildable against the current
   `/v1/health`** — see section 10: the endpoint lists configured device names, not their state,
   and the server discards the failures the audit sink reports to it.

**Failure impact.** If ciphr fails, **all services keep running** — their configuration is
already on their hosts. Only new deploys are affected. This is why a single instance is
defensible, and it should be documented exactly this way, so that nobody panics and starts
copying the master key around during an incident.

Note that this changes once consumption pattern A or B from section 13 is in use: those
services fetch their values at **startup**, so a restart during a ciphr outage will fail.
Running containers are unaffected. That is the deliberate counter-entry to the security gain.

---

## 18. Implementation Phases

Every phase ends with something testable. The order is deliberately "crypto first, HTTP last"
— the decisions that are hard to correct come first.

| Phase | Contents | Done when |
|---|---|---|
| **0** | Repository skeleton, ADRs, threat model, `deny.toml`, CI scaffolding | CI is green on an empty workspace |
| **1** | `crypto` + `store` + `seal` | Known-answer tests for the envelope scheme; round-trip property tests; master key rotation demonstrated; no HTTP |
| **2** | `policy` + `audit` | Property tests for path matching, fuzzer on normalization; `audit verify` detects a tampered chain; fail-closed proven by test |
| **3** | `server` + auth + `cli` | End-to-end locally: `init`, `put`, `get`, `export`; all export formats including `actions-env` with `::add-mask::` (section 14); `import --from-dotenv` with `--dry-run`; constant-time comparison demonstrated; OpenAPI complete |
| **4** | First production integration | One low-risk service draws its secrets from ciphr; the way back is tested; masking demonstrated on a real runner |
| **5** | Vue UI as its own image (section 15) | The audit is usable without the CLI; the server stack demonstrably runs **without** the UI container; CSP active, `v-html` gate green |
| **6** | Migrate remaining services and CI jobs | Long-lived forge secrets reduced to one token per repository/host; every value classified (`rotation`) — checkable since 2026-08-20 with `ciphr list --rotation unclassified` returning nothing |
| **7** | Consumption patterns from section 13: `tmpfs` for class A, entrypoint wrappers for class B, SDK integration for first-party services | No plaintext secret left at rest on disk and none in the container config — except the bootstrap token per host |
| **8** | Honeypots and tripwires (section 22) | A honeypot token authenticates nothing and is refused exactly as any other invalid credential, while producing a distinct audit action and a `tripped` flag on `/v1/health`; a honeypot secret read through the API trips the same way without changing the response the reader sees; `disable-identity` revokes exactly the tripping identity's tokens; `freeze` survives a restart, closes only the routes section 22 names, and is cleared on the host alone; a test proves no tier above `alert` is reachable without an authenticated request |
| **9** | Leak reports (section 23) | `POST /v1/report` answers `202` for a match and a miss alike and `429` at a limit; a match sets `leaked_at` on the version and shows up in `/v1/leaks` and `ciphr leak list`; a miss leaves nothing behind but a counter; the limiter refuses before any audit device is touched and before the store lock is taken; `ciphr leak reindex` covers versions written before the migration; a test proves `leaked` changes no authorization decision |

**Before phase 4 — the first production use — an external review** of `ciphr-crypto`,
`ciphr-policy`, and the path, pattern, and secret code in `ciphr-core`. These crates *are* the
project; everything else is packaging.

**The scope is three crates, not the two this section named until 2026-08-19.** Path
normalization and the glob matcher live in `ciphr-core`, and normalization is the single function
ADR-9 identifies as the place where routing and authorization can silently disagree — a review
scoped from the earlier wording would have missed that surface entirely.
`docs/security-review.md` carries the full scope and a falsification criterion per claim.

Self-review is not sufficient here, and operational experience does not substitute either. The
two find different things: running the service surfaced a defect in the audit chain that no
reading of the crypto would have caught. But it exercises the paths a deployment happens to
take, and an attacker is not restricted to those.

**This requirement binds the project, not an operator.** Nothing in the software refuses to hold
a real secret because a review is outstanding, and a deployment may decide the risk is
acceptable for what it holds. That decision is legitimate, and it belongs in that deployment's
own documentation — dated, saying what it covers and what would reverse it. What this repository
must not do is restate the requirement as satisfied because someone chose to proceed: the status
in `docs/security-review.md` changes when a review has happened and for no other reason. If no
review can be arranged at all, that is an argument for falling back to OpenBao (section 2).

**After v1, in this order:**

1. **OIDC auth method** (verified as implementable for Forgejo and GitHub — eliminates the
   long-lived CI tokens, section 14).
2. **UI SSO** (ADR-12) — reuses the validation from item 1, so it is cheapest immediately
   afterwards.
3. **MCP server** (section 16). Requires a complete `openapi.yaml`, server-side audit filters,
   and metadata endpoints from v1.
4. **Transit engine** (encryption as a service for applications that only need an HMAC or
   encryption key, without ever holding one).
5. Shamir seal, dynamic secrets, HA.

**How phases 8 and 9 sit against that list.** They are independent of it: neither needs OIDC, an SSO
session, or the MCP server, and none of those five items needs them. Two constraints fix where they
can go.

*The earliest.* Both add surface in the places the outstanding review exists for — phase 8 in the
authentication path, phase 9 in a new key derivation plus the only unauthenticated request path that
reaches the store — so neither may precede the external review that is already a precondition of
phase 4. Building a tripwire into an authentication path nobody outside this project has read is the
wrong order, and it is the order that feels productive.

*The sequence between them.* Phase 8 first, and not because it is smaller. It needs no new
cryptography, it reuses `revoke_identity_tokens` and the token machinery as they stand, and it
addresses A3 — which is the adversary phases 4 and 6 actually create, as one token per repository
and per host spreads across the estate. Phase 9 then strengthens it: the blind index turns "this bait
is in the wild" into a lookup. Phase 8 does not depend on that, and phase 9 without phase 8 would
ship the anonymous endpoint before the thing that makes its strongest signal legible.

The honest note against putting phase 8 earlier: honeypot tokens are worth most in the window
*before* OIDC removes long-lived CI tokens, which argues for pulling them forward into phase 6, when
those tokens proliferate. That argument loses to the review constraint above, and it loses only to
that. If the review lands before phase 6 completes, planting an `alert`-tier honeypot token during
the migration is the natural moment and the plan should be re-read at that point rather than
followed.

---

## 19. Security Guidelines for Implementation

Not style questions — CI-enforced, because otherwise they erode.

**The type system as a wall**

- `#![forbid(unsafe_code)]` in **every** crate. An exception would require justification and
  review; none is anticipated.
- Every secret-bearing value sits in `SecretBox` or `Zeroizing`. These types implement neither
  `Debug`, `Display` nor `Serialize`. Logging a secret is therefore a compile error rather
  than a code-review question.
- Error types never carry values — only paths, identities, and error classes.

**Crypto hygiene**

- No custom constructions. Only the primitives from section 5, only in the documented standard
  pattern.
- Randomness exclusively from `OsRng`. A deterministic RNG in a production path is a bug, not
  an optimization.
- All comparisons of tokens, HMACs, and tags in constant time (`subtle`).
- Known-answer tests for the envelope scheme, so that a later refactor cannot silently break
  compatibility.

**Supply chain**

- `cargo-deny` in CI: license allowlist, advisory database, prohibition of unmaintained and
  duplicate crates.
- A hard dependency budget. Every new dependency is a review decision with a justification in
  the pull request — especially in `crypto` and `policy`.
- `cargo auditable`, so the bill of materials sits inside the binary.
- Reproducible builds; image tags pinned, never `latest`.

**CI gates (all blocking)**

`cargo test --workspace` · `cargo clippy -- -D warnings` · `cargo fmt --check` ·
`cargo deny check` · `cargo audit` · a fuzzer smoke run against path normalization · a grep
gate against `println!`/`dbg!` in library crates · a grep gate against `v-html` in `ui/`.

**Explicitly not done**

- No debug endpoint that dumps configuration or state.
- No "test mode" that skips authentication. Tests get real identities.
- No plaintext secrets in test fixtures that look like real ones — that only creates
  secret-scanner noise.

---

## 20. Preparing for Possible Publication

The project starts private. These points cost nothing now and would be expensive later:

- **Licensing decided up front.** Retroactive relicensing requires the consent of every
  contributor — trivial with one author, not with five. Chosen: `MIT OR Apache-2.0`.
- **English from commit one** for code, comments, commits, API documentation, and the
  changelog.
- **No deployment specifics in the core.** No organization-specific domains, no forge
  assumptions, no host paths in `crates/`. Integration lives in the deployment layer, not in
  the product.
- **`SECURITY.md` and a disclosure process must exist before publication**, not after. A
  public secret manager without a reporting channel is irresponsible.
- **Write `docs/threat-model.md` publication-ready from the start.** For a security product
  that is a quality signal — and it forces honesty about the boundaries (A5).
- **Maintain `openapi.yaml` and `CHANGELOG.md` from phase 3 on**, rather than reconstructing
  them afterwards.

---

## 21. Risks and Open Questions

| Risk | Assessment | Mitigation |
|---|---|---|
| **Crypto or authorization bug in a self-built system** | High, and failures are silent | Established primitives only; external review before phase 4; keep the fallback to OpenBao open (`dump --format portable`) |
| **Fail-closed causes an outage** | Medium | Three health checks including fill level; rotation; a generous volume |
| **Master key loss = total loss** | High | Break-glass copy in a password manager plus offline; restore drill in the backup cycle |
| **Bootstrap circularity** | Medium | The service's own configuration must never come from itself; documented at the deployment layer |
| **Single instance** | Low in v1, rises with section 13 patterns | Running services are independent; only deploys block — and, after adopting startup-time fetching, restarts |
| **Project stalls halfway** | Real | Each phase ends with something usable; after phase 4 it is in production, even without a UI |
| **Phase 6 mistaken for the goal** | Real, and the most likely misconception | Migrating away from forge secrets leaves plaintext on the host; section 13 and phase 7 are what change that |
| **Rotating a non-rotatable secret destroys data** | Medium, impact high | `rotation` classification in the data model from v1, warnings in CLI and UI (section 8) |
| **Dependency surface of Rust** | Medium | `cargo-deny`, dependency budget, narrow stack (ADR-9) |
| **XSS in the UI reveals secrets** | Medium | UI read-only, single-value reveal, strict CSP, no `v-html` (CI gate), `sessionStorage` instead of a cookie, separate npm budget (section 15) |
| **MCP pulls secrets into model contexts and provider logs** | High, once the MCP server exists | Plaintext opt-in per identity and path, metadata by default; MCP context marked in the audit; token passed through rather than a service identity (section 16) |
| **The report endpoint becomes a confirmation oracle** | High if it answers, and low-entropy values are where it hurts | It never answers: `202` for a match and a miss alike, and the match is visible only on the authenticated side (section 23) |
| **An anonymous endpoint drives the audit volume** | Medium likelihood, total impact — fail-closed makes a full volume an outage | Size and rate limits ahead of the audit write and the store lock, one aggregate entry per window rather than one per refusal, a concurrency cap, and off by default (section 23) |
| **A tripwire becomes an availability weapon** | Medium, and it is the failure mode a kill switch invites | `alert` is the default tier and the only one an anonymous report can reach; `freeze` is opt-in per honeypot, serves `/v1/health` and the trail throughout, and is cleared only on the host (section 22) |
| **The blind index makes low-entropy values guessable offline** | Low, and bounded by the master key | The index key derives from the root key, so anyone who can attack the index can already decrypt every value; what the index genuinely adds is that a database reader sees which values are duplicates (section 23, A4) |

### Answered since, and where the answer lives

- **Source of the TLS certificate for ADR-8** — answered 2026-08-18 at the deployment layer: a
  dedicated CA with a mounted leaf, pinned by CA rather than by leaf, and no ACME client in the
  service. Written up as **ADR-17** on 2026-08-19, together with the recurring counter-proposal it
  rejects — public names for the internal services and certificates from a public CA over ACME
  DNS-01, where only the challenge record is public. It is rejected because `--cacert` *replaces*
  the trust set rather than extending it, so the private CA is one key under this deployment's
  control where the WebPKI is roughly 150 roots, on the one hop whose content is plaintext secrets;
  and because ACME there would publish internal names to CT, require a DNS credential able to
  rewrite public DNS, and put an account key and a writable certificate path next to the plaintext.
  Three consequences belong here. First, because the pin is the CA, a leaf can be replaced without
  touching a single client — the service needs nothing beyond loading two PEM files, which it
  already does. Second, **the leaf has to carry the loopback name in its SAN**, because ADR-8
  forbids `--insecure` in every example and the container health check speaks to the service over
  TLS. Third, **the CA carries X.509 name constraints and goes into no system or browser trust
  store** — an unconstrained root in a trust store is the attack surface the counter-proposal is
  actually reaching for, and it is the one thing a private CA can genuinely get wrong. CA
  distribution to CI clients stays what section 14 says it is: a non-secret variable.
- **UI origin** — same-origin through the reverse proxy. The certificate for that origin is
  **not** a second leaf from the internal CA, which is what this list said until 2026-08-19: the
  client there is a browser whose trust store must not be touched, and a private leaf reaches it
  only through an installed root or through a click-through warning on the page where someone
  pastes a bearer token (ADR-12). It gets a publicly resolvable name and a public certificate over
  ACME DNS-01 at the proxy instead (ADR-17), which also makes that renewal automatic rather than an
  operational task. The proxy's own hop to ciphr keeps the internal leaf, so the machine path is
  untouched and still does not depend on any of this. Deferred until section 15 is built, not open.
- **`::add-mask::` on a Forgejo runner** — measured 2026-08-18 on a real runner rather than
  simulated: effective for every ordinary case, with one measured exception under `set -x`,
  where bash re-quotes a value containing a single quote or a tab and the runner's literal
  substring match therefore misses it (`docs/review-2026-08-18.md`, finding 9). **act_runner is
  still unproven** — "both are act derivatives" is the assumption this list refused to make
  about the Forgejo runner, and it stays refused here.

### Open questions that still need work

1. **Where a deployment keeps its anchor file, and what runs the cut.** The cut from section 7
   is built; nothing here decides where it is pointed. Beside the database the anchor file is
   decoration — whoever can rewrite the trail can rewrite it too — so the open question is which
   host, backup, or append-only share holds it, and that is a deployment decision recorded where
   the deployment is documented. The second half is the schedule: a bound nothing runs is not a
   bound, and the fill-level check is what catches a schedule that is not keeping up.
2. **Whether the service ever serves a consumer outside its own network** (section 13). Three
   decisions in one — network exposure, a certificate for a name a foreign host resolves, a token
   across a trust boundary — and the answer bounds how far phase 7 can reach.
3. **Name of the MCP plaintext capability** (section 16) — an implementation detail, but it
   must be a regular capability in the set from section 6, not a special case in the
   evaluator.
4. **Prove `::add-mask::` on act_runner** (section 14) — the Forgejo half is measured, above.
5. **Whether the value index of section 23 is written unconditionally.** Writing it on every `put`
   keeps the corpus matchable and makes `leak reindex` a one-time migration rather than a recurring
   chore; writing it only where reporting is enabled keeps a value-derived column out of databases
   that will never use it. The recommendation is unconditional, with the duplicate-visibility cost
   stated where the schema is documented — a half-indexed corpus is the more dangerous state, because
   a miss then means nothing and the endpoint cannot say so. Decide before the migration in phase 9,
   not during it.
6. **Whether `POST /v1/report` gets its own listener.** A drop box only reports what its reporters can
   reach, and an internal-only drop box reports nothing an internal identity could not already have
   produced in the audit trail. Exposing it means a listener on a different boundary from the
   authenticated API, which is the same three-part decision as question 2 — network exposure, a
   certificate for a name a foreign host resolves, and what crosses a trust boundary — and it has to
   be answered with it rather than separately.

---

## 22. Honeypots and Tripwires

Planned, not built. ADR-15 carries the decision; this section carries the design. **Numbered after
section 21 rather than inserted before it:** section numbers are cited by number from `AGENTS.md`,
the ADRs, `openapi.yaml`, the changelog and the operations documents, and renumbering would
invalidate every one of those references to buy an ordering nicety.

### The requirement

A3 — a compromised deploy runner holding a valid token — is defended by policy and recorded by the
audit trail, and neither of those *notices*. The trail records the accesses; a human has to read it
and recognize that the pattern is wrong. Section 2 names the unpleasant property this project has:
its failures are silent. A honeypot is the cheapest way to make one class of them loud.

Bait, in two shapes:

- **A honeypot token.** A credential in the documented format that authenticates nothing. It is
  planted where a credential should not be but often is: a repository, a job log, an old `.env` on a
  host, a wiki page. Presenting it is proof that someone read something they should not have.
- **A honeypot secret.** A real path holding a real-looking, useless value that no legitimate
  consumer reads. Reading its *value* through the API is proof that an identity is enumerating
  rather than fetching what it needs.

The two catch different things and neither replaces the other. The token catches whoever scraped a
place secrets end up in; the secret catches whoever is already inside with a valid identity.

### What must be true of bait

- **Indistinguishable from the real thing.** A honeypot token has the same `cph_` prefix, the same
  length, and the same alphabet, and it fails exactly as every other invalid token does: `401`, the
  same body, no hint. A honeypot secret's read returns the ordinary response shape with no extra
  field. Bait that announces itself is decoration.
- **No timing difference.** Recognizing a honeypot token happens on the same code path and with the
  same constant-time comparison as any other token, so an attacker holding several credentials
  cannot measure which one is bait. `crates/ciphr-store/src/tokens.rs` already has
  `every_kind_of_invalid_token_looks_the_same`; the honeypot case belongs inside it rather than
  beside it.
- **No special case in the evaluator.** A honeypot secret is authorized by the policy like any other
  path (section 6). The trigger fires *after* an allow, on a value actually served. A rule in the
  evaluator that knew about honeypots would be exactly the exception the capability set exists to
  avoid.
- **Visible where it must be, invisible where it must not.** The honeypot flag appears on the
  administrative read path (`/v1/honeypots`, `ciphr honeypot list`) and never on the value path, in
  `/v1/list`, or in `/v1/versions`. An operator has to be able to tell bait from a real secret — a
  colleague who rotates the honeypot because it looks stale has destroyed it — and a caller must
  not.
- **The trigger fires on a value read through the API, and not on a host operation.** `ciphr dump
  --format portable` and `ciphr export` on the host decrypt by design (sections 2 and 11); a backup
  that trips every honeypot every night is a honeypot nobody believes. `list` and `versions` do not
  fire either — enumerating a name is not taking the bait.

### Three tiers, and their blast radius

A trigger is worth what its worst case costs, so each tier is named together with what it does when
it fires on the wrong thing. **The tier is set per honeypot**, and the default is the mildest one.

| Tier | What happens | Cost of a false positive |
|---|---|---|
| `alert` | A distinct audit action, a `tripped` flag with a timestamp on `/v1/health`, and a marker file the deployment's monitoring can watch | A page, and nothing else |
| `disable-identity` | Additionally revokes every token of the identity that tripped it — `revoke_identity_tokens` already exists | That identity's deploys fail until a token is reissued on the host |
| `freeze` | Additionally refuses every value read and every write, for every identity, until it is cleared on the host | Every deploy fails; running services are unaffected (section 17) |

**Alerting does not mean an outbound connection.** No SMTP client, no webhook, no notifier in the
process that holds the master key: each of those is a new egress path out of the one container the
threat model most wants to keep quiet, and a new dependency in the crates that are hardest to
review. The alert is a fact on `/v1/health` and an entry in the audit trail, and the monitoring
section 17 already requires is what turns it into a page. Same reasoning that keeps the audit
devices to `sqlite` and `file` in v1.

**What `freeze` closes, precisely**, because a half-defined kill switch is worse than none:

- Refused with `503`: `GET /v1/secrets`, `POST /v1/export`, `PUT`, `DELETE`. No value leaves and
  nothing changes.
- Still open: `/v1/health`, which says it is frozen and since when; `/v1/audit`, `/v1/list`,
  `/v1/versions`, `/v1/identities`, `/v1/policies`. A freeze exists to stop exfiltration, and
  whoever is investigating needs the trail more than ever. None of those serves a value.
- Unaffected: the CLI on the host. A freeze that locks out the operator is a self-inflicted incident
  with no way back.
- **It survives a restart**, recorded in the store rather than in memory. A freeze an attacker
  clears by crashing the process fires once and never again.
- **It is cleared on the host and nowhere else** — `ciphr lockdown clear`, audited, never through
  the API — and it never clears itself on a timer. A tripwire that resets quietly turns an incident
  into a blip in a graph nobody kept.

### What may never trip a tier above `alert`

An anonymous request. Section 23's drop box accepts candidate values from whoever can reach it, and
a reported honeypot value is the strongest single signal this system can produce: bait that was
never legitimately readable is in the wild. It is still only an `alert`. A value the reporter
already holds must not be able to revoke an identity's tokens or freeze the service, or the report
endpoint becomes a remote off switch operated by whoever holds a leaked value. The corollary is that
`disable-identity` and `freeze` require an authenticated request that took the bait, because those
tiers act on the identity that tripped them.

### API, CLI, configuration, data model

| Method | Path | Capability |
|---|---|---|
| `GET` | `/v1/honeypots` | `read` on `sys/honeypots` |

`sys/honeypots` is a virtual path through the ordinary evaluator, like `sys/audit` — no new
capability and no second authorization mechanism (sections 6 and 10). `PUT` and `DELETE` under
`sys/**` are already refused, so the name cannot collide with a real secret.

`/v1/health` gains `tripped` and `frozen`. Both are properties of the process and therefore
permitted on an unauthenticated endpoint by the rule in section 10, and neither names a path or an
identity: *that* a tripwire fired is what the process is doing, *which* bait was taken is what is
stored, and that stays behind `/v1/honeypots` and the audit trail.

CLI: `ciphr honeypot add <path> --tier <alert|disable-identity|freeze>`, `ciphr honeypot list`,
`ciphr token issue <identity> --honeypot`, `ciphr lockdown status`, `ciphr lockdown clear`.

Configuration: none. A honeypot is data — a flag on a secret or on a token — not a listener setting,
so there is no `[honeypot]` table that can drift out of step with the store.

Data model, additively: `secrets.honeypot_tier TEXT NULL`, `tokens.honeypot INTEGER NOT NULL DEFAULT
0`, and a `tripwire` table recording each trip (`ts`, `kind`, `path` or `token_id`, `identity`,
`tier`, `cleared_at`), so that the freeze state and its cause survive a restart.

Audit actions: `honeypot-triggered`, `lockdown-engaged`, `lockdown-cleared`. Additive variants of
`Action`; verification hashes the stored payload text, so adding them does not disturb an existing
chain.

### What this does not solve

- **A targeted attacker who reads only what they came for is not caught.** Honeypots detect
  indiscriminate behaviour — enumeration, scraping, a stolen credential tried everywhere. That is
  what most real compromise looks like, and it is not what the most capable adversary looks like.
- **Bait has to be planted where secrets actually leak**, which is a deployment activity and belongs
  in that deployment's own documentation, not here. This repository can only make bait cheap to
  create and impossible to distinguish.
- **A honeypot secret is bait only while nobody depends on it.** The first service that reads it by
  mistake turns it into a source of false positives, and what prevents that is the visibility rule
  above, not anything in the code.

---

## 23. Leak Reports: an Anonymous Drop Box

Planned, not built. ADR-16 carries the decision.

### The requirement

A value that has escaped is worth more to whoever finds it than to whoever owns it, and the finder
usually holds no token here: a developer who spotted a key in a job log, a colleague who found an
`.env` in a support attachment, someone reading a public repository. Today none of them can tell
this system anything. The value comes back as a message to a human, if it comes back at all, and the
store keeps serving it as current.

So: one unauthenticated endpoint that accepts a candidate secret value and, on a match, marks the
version it matched as `leaked` — evidence for an operator that a rotation is overdue, produced by
whoever already has the value.

### The oracle problem, and the decision that removes it

An endpoint that answers "yes, that is one of mine" is a confirmation oracle. For a high-entropy
value that costs little; the requester already had it. For a low-entropy one it is a guessing
machine: submit `hunter2`, then the fifty thousand most common passwords, and every hit names a live
value.

Rate limits turn that into a slow guessing machine. Section 10 already contains the sentence that
decides it properly: an unauthenticated endpoint may report *what the process enforces* and never
*what is stored*. A match is what is stored.

**The endpoint therefore never answers the question.** `202 Accepted` with an empty body for a match
and a miss alike; `429` when a limit is reached, because a limiter is a property of the process;
`400` for a body that is not the documented shape. The lookup runs the same way either way, so there
is no timing difference to measure.

The cost is real and belongs here rather than in a footnote: a reporter learns that the report was
accepted and nothing about whether it mattered. A drop box is what is left once an oracle is ruled
out. The operator-facing half — `/v1/leaks`, `ciphr leak list`, the audit trail — is where a report
becomes visible, and that half is authenticated.

### Matching without decrypting: a blind index

Matching a candidate against the corpus must not mean decrypting the corpus. A deterministic index
per stored value makes it one lookup:

- A key derived from the root key, by the same pattern and with a different `info` string than
  `TokenPepper::derive` already uses. It is not a new construction, and the crate it lives in is
  already in the mandatory review scope of `docs/security-review.md`.
- `index = HMAC-SHA256(key, value_bytes)`, computed on write, stored on the version, indexed in
  SQLite. One HMAC per write on the write path; one indexed lookup and one constant-time comparison
  per report on the read path.

What that adds to the database, stated plainly rather than assumed away:

- **Two versions holding the same value get the same index.** A reader of the database file (A4)
  learns which secrets duplicate each other without learning a value. That is new information, and
  duplicate values across services are exactly what a migration leaves behind.
- **With the index key, a dictionary attack on a low-entropy value is offline and fast.** The key
  derives from the root key, so anyone who can run that attack can already decrypt every value
  directly. The index adds no exposure that holding the master key does not already grant (A4, A5).
- **Without the key it is an HMAC under an unknown key** — no more useful than the ciphertext beside
  it.

Rejected: decrypting every current version per report, which turns an anonymous request into a
full-corpus decryption and hands out a denial-of-service lever. Rejected: a truncated index or a
Bloom filter for compactness — both produce false positives, and a false `leaked` mark on a
`breaks-data` secret (section 8) invites precisely the rotation that destroys data.

**Coverage.** Versions written before the migration have no index and cannot match. `ciphr leak
reindex` computes them on the host with the master key, audited as one entry recording how many
versions were indexed; it serves nothing and takes no value out of the process. Until it has run, a
report against an older value is a miss — and because the endpoint answers a miss and a match
identically, it is a silent one. The reindex is part of enabling the feature, not an optimization.

### What `leaked` means, and the one thing it must never do

The mark sits on the **version**, because a value is what leaked. Rotation writes a new version,
which is not marked, so the mark ages out through the operation that answers it — and there is
therefore no command that clears it. An erasable leak mark is a piece of evidence with a delete
button.

`leaked` is metadata and does **not** influence authorization. `rotation` follows the same rule in
section 8 for tidiness; here it is load-bearing. If a leaked mark refused reads, anyone who knows a
value could refuse it to everybody, anonymously, and this endpoint would be a remote switch for
turning off any secret whose value has ever been seen. The mark drives a warning in the CLI and the
UI, an audit entry, and a row in `/v1/leaks`. Nothing reads it to decide anything.

### Limits, and why they are load-bearing

This is the first request path in the design that reaches the store without an identity, and the
service is fail-closed on the audit trail. Both facts point at one failure: an anonymous request
that writes an audit entry is an anonymous request that consumes audit volume, and a full audit
volume is a total outage rather than a logging gap (section 7). The limiter is not politeness — it
is what keeps an unauthenticated endpoint from being a lever on availability.

Ordered, because the order *is* the design:

1. **Body size**, capped before parsing (4 KiB by default). A value that does not fit is a value
   this endpoint cannot report, which is an acceptable limit for a drop box.
2. **The limiter, before anything is recorded and before the store lock is taken.** A refused report
   writes no audit entry and touches no database; it increments a counter.
3. **One aggregate audit entry per window** stating how many reports were refused, rather than one
   entry per refusal. Same reasoning as `explain_the_gap` in `crates/ciphr-server/src/state.rs`: the
   trail says what happened without letting whoever caused it choose how much gets written.
4. **A concurrency cap** of one or two permits for the endpoint, so anonymous traffic cannot starve
   authorized requests at the store mutex — secret reads and writes go through that same lock.
5. **A matched report is audited in full and writes one row.** `leaked_at` is set once and is
   monotonic, so a repeated report of the same value changes nothing and costs one lookup.
6. **Off by default in configuration.** The only unauthenticated write path in the system is one a
   deployment turns on deliberately.

**Per-IP buckets are weaker than they look, and the reason is already in the code.**
`request_context` in `crates/ciphr-server/src/api.rs` deliberately ignores `X-Forwarded-For`,
because a header a client controls is a header a client can lie in. The bucket therefore keys on the
connection address, and behind a reverse proxy every reporter shares one bucket. Where the endpoint
is reached through a proxy, **the global budget is the real defence** and the per-IP bucket is a
courtesy to well-behaved clients.

### What the audit records, and what it must not

Recorded: that a report arrived, whether it matched, the matched path and version if it did, the
client address as the listener saw it, and the report's own random identifier. Channel `report`, so
reports stay filterable and are never mistaken for an identity's access.

**Never recorded: anything derived from the submitted value** — not the index, not a prefix of it,
not its length. The `file` device rotates into a backup, which is protected less carefully than the
database, and a fingerprint of an attacker-chosen candidate written there permanently is a
dictionary target that outlives the value it describes. A matched entry names the path, which the
trail records for every other access anyway.

The optional `context` field — free text saying where the value was found — is the one thing that
makes a report actionable, and it is attacker-controlled text. Capped at 256 characters, kept only
on a match, and stored on the row rather than in the audit payload, so an anonymous party cannot
append chosen text to the hash chain.

### API, CLI, configuration, data model

| Method | Path | Capability |
|---|---|---|
| `POST` | `/v1/report` | — (no identity; limits instead) |
| `GET` | `/v1/leaks` | `read` on `sys/leaks` |

`sys/leaks` is a virtual path, as in section 22. No new capability.

CLI: `ciphr leak list` and `ciphr leak reindex`. No `ciphr leak clear`, for the reason above.

```toml
[report]
enabled  = false
max_body = "4KB"
per_ip   = { requests = 5,   per = "1m" }
global   = { requests = 100, per = "1h" }
```

Data model, additively, on `secret_versions`: `value_index BLOB NULL` with an index on it,
`leaked_at INTEGER NULL`, `leak_reports INTEGER NOT NULL DEFAULT 0`, `leak_context TEXT NULL`.

Audit actions: `report`, `leak-marked`, and one for the aggregate refusal entry.

### What this does not solve

- It finds a value somebody brings back. It finds nothing about a value nobody noticed, which is
  most of them.
- A report proves a value was somewhere it should not have been. It says nothing about who put it
  there; the trail's history of reads is the only thing that narrows that, which is an argument for
  the retention design in section 7 rather than for this endpoint.
- **A miss is evidence of nothing.** An unindexed older version, a re-encoded value, a trailing
  newline — all of them miss, and the endpoint's deliberate silence means a reporter cannot tell
  "not ours" from "we cannot tell yet".
