# OIDC federation: letting a job authenticate without a stored token

**Status:** implemented as of 2026-08-26 ([ADR-26](../adr/0026-oidc-federation.md)); on `main` and
not yet in a release. Off in every deployment that has not named the `oidc_login` surface entry. The
key-rotation procedure below is the part of this page to read *before* turning it on, because it is
the one that will page somebody.

A workload presents an ID token its forge issued and receives a ciphr token that lives minutes. The
long-lived bearer token in a file on that host is no longer needed for it.

**What this does not remove.** A runner that cannot federate, and every human, still uses
`ciphr token issue`. Federation reduces the number of long-lived credentials; it does not reach zero,
and the deployments where it reaches zero are the ones where every consumer is a forge job.

## What you are trusting when you turn this on

One sentence, because it is the sentence: **a signature from a provider you name is accepted in place
of a credential this system issued.** Everything below follows from that.

- Whoever can make that provider issue a token with the bound claims can obtain a ciphr token for the
  bound identity. On a forge, that is whoever can run a workflow on the branch the binding names.
- **Check your forge before enabling.** Forgejo shipped a security fix because its `…/idtoken`
  endpoint issued tokens without verifying `enable-openid-connect`, which mattered for fork pull
  requests; the fix landed before v15.0.0, so any v15.0.x has it. Verify the equivalent for any other
  provider. A forge that hands an ID token to a fork's workflow makes a binding on `sub` mean less
  than it reads.
- The exchange **cannot widen an authority**. The identity, its policies and the lifetime ceiling all
  come from configuration, so the worst an exchange can produce is a credential for an identity a
  binding already names. That is the property that makes this the second write the API may do at all
  (ADR-26).

## Turning it on

Two halves, and the server refuses to start with only one of them — an entry with no provider is a
route that refuses everything, and providers with the entry off are key material nothing can reach.

```toml
[[surface]]
entry    = "oidc_login"
accepted = "2026-08-26"
reason   = "one CI runner per host, so a bootstrap token per host was the largest standing credential count"

[[auth.oidc]]
name         = "forge"
issuer       = "https://forge.example/api/actions"
audience     = "ciphr"
ttl          = "15m"
skew_seconds = 60

[[auth.oidc.key]]
alg = "RS256"
kid = "1a2b3c"
n   = "…the modulus, unpadded base64url…"
e   = "AQAB"

[[auth.oidc.binding]]
identity = "ci-widget"
claims   = { sub = "repo:acme/widget:ref:refs/heads/main" }
```

`issuer` is compared byte for byte against the token's `iss`, including a trailing slash. `audience`
is mandatory and compared exactly: without it, a token the provider issued for some other service
would be valid here.

Then confirm what the file resolves to, on a host or in review — this needs no store:

```sh
ciphr-server --check-config /etc/ciphr/config.toml
```

The report gains a `federation:` section listing the providers. It is printed in the half of the
report that holds without this host, which is where it belongs: these are somebody else's signing
keys, and review is the place to notice one that should not be there.

### Getting the keys in

There is no JWKS fetch, and that is deliberate — it would be the first outbound request from the
process that holds plaintext secrets, and this build links no public root certificates, so it could
not make one (ADR-26, ADR-17). The keys are copied in by hand:

```sh
curl -s "https://forge.example/api/actions/.well-known/jwks.json" | jq '.keys'
```

Take `kid`, `n` and `e` for an `RSA` key, or `kid`, `x` and `y` for an `EC` key on P-256, and write
them into `[[auth.oidc.key]]` with the matching `alg`. The values are copied verbatim: they are
unpadded base64url, and standard base64's `+` and `/` are a different alphabet — the server refuses a
key that is not in the right one, at startup, naming the field.

A provider that publishes several keys can have all of them configured. Each needs its own `kid`, and
two keys sharing one is a refusal to start.

### Which claims to bind on

Whatever identifies the job, exactly. Claims are compared by **exact string equality**, all of the
ones a binding lists, and **there is no wildcard** — the reasoning is in ADR-26, and the short form is
that a claim value is not a path, so the one glob matcher this project has is the wrong tool and a
second one is out of the question.

```toml
# One identity per repository is the granularity that makes the trail readable.
[[auth.oidc.binding]]
identity = "ci-widget"
claims   = { sub = "repo:acme/widget:ref:refs/heads/main", repository = "acme/widget" }
```

Consequences worth knowing before you write the first one:

- **Several branches means several bindings.** That is a file with a diff and a reviewer, which is
  ADR-3's argument for configuration in the first place.
- **A binding may not select on `iss`, `aud`, `exp`, `nbf` or `iat`.** Those are verified rather than
  matched, and a binding on one would state the same rule twice in two places that can disagree. The
  server refuses it.
- **Two bindings that both match one token is a refusal at request time**, recorded as
  `ambiguous-binding`. Identical claim sets are refused at startup; two bindings selecting on
  *different* claim names can still both match a token carrying all of them, and there is no honest
  way to pick between them.
- **A binding must name an identity the policy file has.** Otherwise the server refuses to start —
  the same refusal `ciphr token issue` gives, for the same reason: a credential with no rules behind
  it reads as working and authorizes nothing.

## In the job

The workflow asks its forge for an ID token with `audience=ciphr`, posts it, and uses what comes back.

```sh
CIPHR_TOKEN=$(curl -sf --cacert "$CIPHR_CA" \
    -H 'Content-Type: application/json' \
    --data "{\"id_token\": \"$FORGE_ID_TOKEN\", \"ttl_seconds\": 300}" \
    "$CIPHR_URL/v1/auth/oidc/login" | jq -r .token)
```

`ttl_seconds` is optional and can only *reduce* the lifetime. A job that knows it will finish in five
minutes asking for five minutes is the cheapest improvement available here, and asking for more than
the configured ceiling gets the ceiling rather than an error.

The response also carries `token_id` and `identity`. Print both: `token_id` is what the audit trail
names, so a build log and the trail can be joined without the token ever appearing in either, and
`identity` is how a workflow that federated into the wrong binding finds out here rather than as a
`403` on its next request.

**Everything after the exchange is ordinary token authentication**, so `ciphr-ci`, `ciphr-run` and the
SDK all take the result with no changes. Note that this adds one dependency to the start path: a
consumer that federates needs the vault reachable to authenticate as well as to fetch. See
[availability.md](availability.md).

## When the provider rotates its signing key

**This is the failure this feature adds, and it is the one to have a plan for.** A provider rotates,
your configuration still names the old `kid`, and every exchange is refused from that moment.

What it looks like: `POST /v1/auth/oidc/login` answering `401`, jobs failing at their first step, and
**nothing in the audit trail** — because an unverifiable signature is not recorded (see the next
section). What still works: every token already issued until it expires, and every bootstrap
credential. So this degrades to the situation before federation rather than to an outage, which is the
one thing about it that is good news.

The procedure is the ordinary configuration change:

1. Read the provider's JWKS and add the new key as another `[[auth.oidc.key]]`. **Add, do not
   replace** — during a rotation the provider signs with the new key and tokens signed with the old
   one are still in flight.
2. `ciphr-server --check-config` on the file.
3. Deploy and restart. The keys are resolved at startup and are immutable afterwards, on purpose: a
   process that could be told who to trust at runtime is a process whose trust an adversary can
   change.
4. Remove the old key on the next ordinary change, once nothing signed with it can still be valid.

**Getting ahead of it.** Providers that rotate on a schedule publish both keys before the switch, so a
job that reads the JWKS and diffs it against your configuration turns this from an incident into a
pull request. There is nothing in this repository that does that, and there deliberately is not — it
belongs in the environment's own repository, next to the deploy that would carry the change.

## Reading the trail

A successful exchange is one entry, `federate-token`:

| Field | What it holds |
|---|---|
| `principal.name` | `oidc:<provider>` — the actor is the provider, because no credential of this system was presented |
| `subject.name` | the identity the binding named |
| `subject.token_id` | the credential that was minted, as every later access will carry it |
| `detail` | `sub: <the verified claim>` — the only field that says *which* job this was |
| `path` | `sys/tokens` |

A refused exchange is the same action with `allowed: false` and a `deny_reason` of `expired`,
`not-yet-valid`, `audience-mismatch`, `no-binding`, `ambiguous-binding`, `missing-expiry` or
`missing-subject`. The wire answer is one `401` that explains nothing, whichever it was — a caller
that learns why it was refused learns something about the configuration.

**The presented token is never in the trail.** Neither is any part of it.

### What is deliberately not recorded, and why

**A token whose signature does not verify leaves no entry at all.** A forged signature, an issuer no
provider matches, and a string that is not a token: none of them are recorded.

The reason is that this route is unauthenticated, and the trail is fail-closed. An entry per attempt
would let anybody on the network write into it — fill it, or push one device into refusing, and every
request afterwards is a `503`. The router fallback and the request-body extractor already refuse to
write for an anonymous caller for exactly this reason, and ADR-16 deferred a whole phase over the same
cost.

The consequence, said plainly so it is not discovered later: **the trail cannot tell you how many
attacks this route has seen.** Counting refusals at this endpoint is a job for whatever fronts the
listener. What the trail answers is the question it exists for — who federated, as what, and on whose
word.

### Counting credentials

`ciphr token list` shows a federated credential like any other, with `created_by` of
`oidc:<provider>` and an expiry it always has.

In the trail, **a federated mint is `federate-token` and is not also `issue-token`.** So counting
credentials created means counting both actions: `issue-token`, plus the allowed `federate-token`
entries. A monitor that counts one of them gets a number that looks right.

## Turning it off

Remove the `[[surface]]` stanza and the `[[auth.oidc]]` providers together — either half alone is a
refusal to start — and restart. The route stops existing, `POST /v1/auth/oidc/login` answers `404`
from the fallback, and any credential an exchange already minted stays valid until it expires or is
revoked. Revoke the ones you do not want to wait out:

```sh
ciphr token list --identity ci-widget
```

Both halves of that are the ordinary token lifecycle: revocation over the API where `token_revoke` is
on ([ADR-24](../adr/0024-revocation-is-the-one-write-the-api-may-do.md)), and on the host with a
service stop where it is not.
