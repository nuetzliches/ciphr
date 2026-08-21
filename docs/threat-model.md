# Threat model

**Status:** current as of 2026-08-21, `v0.4.0` released, phases 0-3 and 7 in it, and phase 8 built and
unreleased. The adversaries and boundaries are settled. **A3 gains an optional detection** rather than
a new defence: the `honeypot_alert` entry (ADR-15, ADR-20) is absent from a default build, and where a
deployment turns it on, taking bait is a signal that needs no interpretation. The boundary itself does
not move — a compromised runner still holds a valid token and still reads what its policy allows. The cryptographic, storage, authorization, audit and transport defences
exist. **A7 now describes a component that is built:** every countermeasure in that row is
implemented in `ui/` and the ones that can be gated are gated — see [ui.md](ui.md). **A8 still
describes one that is not:** the MCP server is post-v1, and its row is a design commitment rather
than a description. **A9 describes nothing that exists, and as of 2026-08-20 nothing that is
scheduled:** the leak-report endpoint is phase 9, and ADR-16 is deferred — it is worth its cost only
where somebody holding no token can reach it. **There is no unauthenticated endpoint here except
`/v1/health`**, and that sentence is now expected to stay true rather than to expire. The row stays
because the record stays: it is the only anonymous request path this design would ever have, what
defends it was decided before anyone built it, and a deferral is not a reason to lose that.

Everything in the design is derived from this document, so it is stated first and stated plainly —
including the parts where the answer is "not defended against". A security product that lists only
the attacks it stops is marketing.

The subject is ciphr as a whole: the server that holds plaintext secrets and key material, the
database, the CLI, the optional read-only UI, and the optional MCP server.

## What is being protected

1. **Secret plaintext**, at rest and in transit.
2. **Key material** — the master key, the root key, and the per-version data keys.
3. **The integrity and completeness of the audit trail.** This is a protected asset in its own
   right: the project exists to answer "who read what, and when", and an audit trail that can be
   silently truncated answers nothing.
4. **The correctness of authorization decisions.**

## Adversaries

| # | Adversary | Capability | Defence in v1 |
|---|---|---|---|
| A1 | Network participant on the local network | HTTP requests to the listener | Authentication required, deny by default, no anonymous endpoint except `/v1/health` |
| A2 | Compromised container on the same bridge network | Network access, possible traffic capture | TLS terminated at the listener (ADR-8), token authentication |
| A3 | Compromised deploy runner | Holds a valid deploy token | Policy limited to that runner's paths; every access audited. **Detection is optional and off by default:** the `honeypot_alert` entry turns a read of bait into a signal that needs no interpretation (ADR-15). It catches enumeration and a credential tried everywhere; it does not catch a runner that reads only what it came for, which is what the audit trail is still for. |
| A4 | Reader of the database file (backup, stolen disk) | Full ciphertext | Envelope encryption; the database is worthless without the master key |
| A5 | Root on the host | Everything: process memory, the environment file, the database | **Not defended against.** Deliberate boundary, see below |
| A6 | Internal user with partial access | A valid identity with a limited policy | Policy evaluation, audit, no escalation path through the API |
| A7 | Browser context of the admin UI (XSS, malicious npm dependency) | Runs in the tab of a signed-in human | UI is read-only, reveal is per value, strict CSP, no `v-html`, token in `sessionStorage` rather than a cookie |
| A8 | LLM client at the MCP server | A valid token, but responses flow into model context and provider logs | Plaintext only through an opt-in capability on narrow paths, metadata by default; MCP context marked in the audit trail |
| A9 | Anonymous reporter at `POST /v1/report` | Unauthenticated requests carrying a candidate secret value, and whatever volume they can generate | Identical response for a match and a miss, so the endpoint is no oracle; size and rate limits applied before the audit write and before the store lock; one monotonic metadata write per matched version, read by nothing that makes a decision; no path to any tripwire tier above `alert`; off unless a deployment enables it |

## Deliberately not defended against

**Root on the host (A5).** Whoever is root reads the master key wherever the seal keeps it — the
mounted file for `type = "static_file"`, the environment for the variable form — and reads it from
process memory either way. The same is true of OpenBao with a static seal; it is the consequence of
choosing unattended startup (ADR-5). Moving this boundary requires split-key unsealing or a hardware
module — both retrofittable without a change to the data format, because the master key wraps
exactly one record.

**A compromised build pipeline.** Whoever replaces the image wins. The countermeasure is
supply-chain hygiene — pinned dependencies, `cargo-deny` and `cargo audit` as blocking gates, action
hashes rather than action tags, base images by digest rather than by tag — not application code.

**Reproducible builds are named in plan section 19 and are not implemented.** That is a sequencing
decision rather than an oversight, and it is stated here because the entry above would otherwise
read as a list of things that are all in place. While the repository is private, every build is
internal: nobody outside can obtain the source, rebuild the image and compare it, so reproducibility
would be a property that no one is in a position to check. It buys something the moment the
repository is public and a third party can verify that a published image corresponds to the source
it claims to come from — **that is the point at which this paragraph has to change**, and the
`apt-get install` in the runtime stage of the `Dockerfile` is the first thing that will have to give
way for it.

**Side channels beyond timing in credential comparison.** Token, HMAC, and tag comparisons are
constant-time. There is no protection against cache-timing or Spectre-class attacks.

**Denial of service.** A single instance with fail-closed auditing can be taken offline by filling
the audit volume or by load. That is bounded on purpose: running services keep running, only new
deploys are affected (see *Availability* below).

**And the fill needs no credential** (stated 2026-08-21, finding F5 of the review; the paragraph
above read as though it took one). Every request with a missing or invalid token writes an audit
entry — deliberately, because brute force that leaves no trace is worse — so anyone who can reach
the listener can grow the audit store at line rate until the volume is full, at which point
fail-closed auditing refuses everything. The two facts compose, and each of them is a decision this
document defends. What follows from them is a deployment requirement rather than a code change:

- **Reach is the control.** This endpoint has no reason to be reachable from anywhere but the
  network that deploys from it. Our own instance has no published port and every deploy runs through
  a runner on the LAN, which is the same reasoning that deferred ADR-16.
- **Rate-limit unauthenticated 401s upstream**, where a reverse proxy can drop them before they
  become entries.
- **Alert on audit growth**, not only on free space. Growth is the signal that arrives early enough
  to act on; a full volume is the outage itself.

## Explicitly defended against, because these are the leaks that actually happen

**A secret in a log.** Structurally prevented: secret-bearing types implement neither `Debug`,
`Display` nor `Serialize`, so logging one is a compile error. Library crates may not write to stdout
or stderr at all, enforced by a lint and a CI gate. This is the primary reason for the language
choice (ADR-1).

**A secret in an error message.** Error types carry paths, identities, and error classes — never
values.

**A secret in a core dump or in swap.** `ZeroizeOnDrop` on key material, memory limit equal to swap
limit in the container runtime, core dumps disabled. The language cannot solve this alone; part of
it is an operational requirement.

**Ciphertext relocation.** A ciphertext cannot be moved from path A to path B, because the
normalized path and the version are bound as additional authenticated data. An adversary with
database write access gets a decryption failure instead of a silent privilege transfer.

**An access that is not recorded.** If no configured audit device accepts the record, the request is
refused and no secret is served, and the record is written before the response is produced. Bulk
endpoints write one entry per secret served, never one per call — a collective entry for a bulk read
would be exactly the blind spot that disqualified other candidates during evaluation.

**Undetected tampering with the audit trail.** Entries form a hash chain, so removing or altering
one is detectable. `ciphr audit verify` checks the chain, and a documented recovery path for a
broken chain is part of the design rather than an afterthought.

**Authorization drift between routing and policy.** Path normalization exists exactly once and is
called by both the router and the policy evaluator (ADR-9). Property tests and a fuzzer cover it.

## Trust boundaries

```
                     ┌─────────────────────────────────────────┐
   CI runner ───────▶│ ciphr-server                            │
   host script ─────▶│  the only process holding plaintext      │──▶ SQLite (ciphertext only)
   ciphr CLI ───────▶│  and key material                       │──▶ audit devices (append-only)
   ciphr-ui  ───────▶│                                         │
   ciphr-mcp ───────▶└─────────────────────────────────────────┘
        ▲                          ▲
        │                          │
   browser tab (A7)         master key from the
   LLM client (A8)          environment (A5 reads it)
```

Everything to the left of the server is a client with a token and a policy. The UI and the MCP
server hold no key material, no database access, and no identity of their own — which is what keeps
"exactly one process holds plaintext" true (ADR-11, ADR-13).

## Availability, stated as part of the model

If ciphr is unavailable, **running services keep running** — their configuration is already on their
hosts. Only new deploys are blocked. That is what makes a single instance defensible.

This changes once services fetch their secrets at startup rather than having them rendered into
files: then a restart during a ciphr outage fails. Running containers remain unaffected. That is the
deliberate counter-entry to the security gain, and it should be understood before adopting the
pattern, not after.

Fail-closed auditing means a full audit volume is a total outage rather than a logging gap. That is
intended, and it is why fill level is a monitored metric rather than a footnote — together with the
*rate* of growth, because an unauthenticated peer can drive it (finding F5, above).

## The honest end state

Every host still needs one credential to authenticate to ciphr, and it lives in a file. The
realistic outcome is **one secret per host**, not zero — plus an audit trail, plus rotation, plus a
bounded blast radius per token. That is an excellent trade, and it should not be described as
"no more secrets on the host".
