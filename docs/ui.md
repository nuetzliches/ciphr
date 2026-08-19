# The viewer

**Status:** current as of 2026-08-19, phase 5. Built and running: the five views below, the strict
Content-Security-Policy, and the container that serves them. Sign-in is a pasted token; SSO is
post-v1 (ADR-12).

A read-only browser view of a ciphr deployment: the audit trail, secret metadata with a per-value
reveal, identities, policies, and health. It is what makes the audit trail usable without the CLI,
which is the point of the project rather than a convenience.

## What it is not

It cannot write. No secret is created, updated, or deleted; no policy or identity is changed; no
token is issued or revoked. That is not a stopgap — a policy-write API is the most dangerous API this
project could have (ADR-3), and refusing to have one is what keeps the blast radius of an XSS finding
at "read what the signed-in human is allowed to read anyway".

It is also not part of the service. The viewer is a separate container serving static files (ADR-11).
The server has no `serve-ui` mode, no embedded assets, and no template engine, so a bug in asset
handling cannot be a bug in the process that holds plaintext secrets. Not deploying the viewer costs
nothing but the viewer.

## Signing in

A personal token for an identity of kind `human`, issued with the CLI:

```sh
ciphr token issue alice --ttl 8h
```

Paste it into the sign-in field. What follows:

- The token is checked against the shape `cph_` + 8 characters of identifier + 43 of secret **before**
  any request is made, so a truncated paste fails locally instead of producing an audit entry for an
  authentication that never had a chance.
- It is held in `sessionStorage` and is gone when the tab closes. Not `localStorage`: a token that
  survives closing the tab is a permanent secret on a shared workstation.
- There is no cookie, which removes the entire CSRF class rather than mitigating it.
- The header shows the token's non-secret eight-character identifier — the same one the audit trail
  records, so what you see in the viewer can be tied to the entries your own reads produce.
- Any `401` drops the token and returns to the sign-in form. An expired or revoked token therefore
  looks like a sign-out rather than a wall of identical failures.

Your identity's policy decides everything you can see. The viewer holds no privileges of its own.

## The five views

**Audit.** Filter by identity, exact path, decision, and time; page forward with `after_seq` rather
than an offset, so a growing trail does not shift under you. Filters are applied by the service,
because the alternative is pulling the whole trail to answer a question about part of it. Clicking an
entry shows the record exactly as stored, with its hash.

**Secrets.** A prefix is required — the API lists under a prefix and authorizes every returned path
individually, so there is no call that means "everything", and an empty result is indistinguishable
from an empty prefix. Selecting a path shows its versions, who wrote them, and whether a version is
deleted or destroyed. **Reveal** reads one value, and produces the same audit entry a machine read
would.

**Identities** and **Policies.** Read-only views of the policy file as loaded, including each rule's
specificity — the number of literal segments, which is what decides between two matching rules. The
most specific match wins entirely and inherits nothing, and an empty capability list is an explicit
denial; both are labelled as such rather than left to be inferred.

**Health.** Seal state, where this process read its master key, and per-device audit state. The
per-device state is the part worth having on a screen: auditing is fail-closed, so one accepting
device is enough for requests to succeed, which makes a second device that has quietly stopped
accepting records invisible from outside. `nothing written yet` is a third state and not a healthy
one — it means the process has recorded nothing since it started.

## What the chain badge does and does not prove

The audit view checks that a page of records is a **run**: consecutive sequence numbers, each record
naming its predecessor's hash. That detects a page which does not hang together.

It does **not** recompute hashes. The endpoint returns the exact bytes that were hashed, so a client
*could* — but doing it in the browser means re-serializing parsed JSON and hoping the encoder agrees
with the server's byte for byte. A second implementation of the hashed form is the same class of
mistake as a second path normalizer (ADR-9), and its failure mode is worse than useless: a viewer that
cries tampering over an escaping difference is one whose warnings get ignored.

With a narrowing filter applied the check is skipped and says so. A filtered page is a selection of
records rather than a run, so gaps between them are expected and prove nothing.

The full check is `ciphr audit verify`. The one that survives a forward rewrite is
`ciphr audit verify --anchor` against a head recorded outside the store — see
[operations/audit-trail.md](operations/audit-trail.md).

## Security properties, and where each is enforced

| Property | How |
|---|---|
| Reveal is one value, one action | A single `revealed` ref in `SecretsView.vue`; a second reveal replaces the first. No bulk form exists in the viewer even though `/v1/export` does |
| Plaintext leaves state when you leave the view | Views are switched with `v-if`, so leaving destroys the component; `onUnmounted` clears the value as well |
| Plaintext never reaches a URL, `localStorage`, or global state | Routing carries a view name and nothing else; nothing writes a value anywhere |
| No copy button | Deliberate. The clipboard is a place a value survives the tab, the session, and the reader's attention, with no expiry. Taking a value somewhere is what the CLI is for |
| Strict CSP | `default-src 'none'`, `script-src 'self'`, `connect-src 'self'`, no `unsafe-inline`, no `unsafe-eval`. Defined once in `vite.config.ts`, sent as a header by the container (`nginx.conf`) and injected into the **built** document, so a bundle served by something else keeps it. CI fails if the built document loses it or gains an `unsafe-` keyword |
| No `v-html`, no `innerHTML` | `ci/check-no-v-html.sh`, a blocking CI gate |
| No inline styles | `style-src 'self'` refuses them; the build emits one stylesheet and the code uses classes, never `:style` |
| No service worker, no offline cache | None is registered, `main.ts` unregisters any it finds from an earlier deployment, and the container refuses to serve one. A cached response to a secret read is a secret without an expiry date |
| Only documented v1 endpoints | ADR-11's consequent rule: an endpoint existing for the viewer alone would mean the CLI could not do something the viewer can |
| Its own dependency budget | `ci/check-ui-budget.sh`: exactly one runtime dependency (`vue`), a ceiling on the whole tree, no install scripts, every package resolved from the public registry with an integrity hash |

`frame-ancestors` is in the header only, deliberately: browsers ignore it in a `<meta>` element and
log an error saying so, and a page that complains about its own policy on every load teaches whoever
reads that console to ignore it. Framing is refused by the header and by `X-Frame-Options`.

**The dev server runs without the policy, and that is not a gap being tolerated quietly.** `npm run
dev` does not serve the built artifact — it assembles the page in the browser, and Vite's HMR client
applies styles by creating elements at runtime, which `style-src 'self'` refuses. With the policy in
the source document, development means an unstyled page and a console full of violations, and the fix
a developer reaches for under that pressure is `unsafe-inline` in production. So the policy is
injected at build time instead, and what gets verified — in CI and by hand — is the built bundle,
which is what a deployment serves.

## Running it in development

```sh
cd ui
npm ci
npm run dev            # http://localhost:4401, proxying /v1 to https://localhost:4400
```

The dev server proxies `/v1` so that development runs same-origin, the shape the deployment uses. It
does **not** disable certificate verification — ADR-8 says `--insecure` appears in no example, not
even for testing — so point Node at the deployment's CA:

```sh
NODE_EXTRA_CA_CERTS=/path/to/ca.crt npm run dev
CIPHR_URL=https://ciphr.internal:4400 npm run dev    # a service somewhere else
```

`npm run build` type checks with `vue-tsc` and then builds; the container build runs the same script,
so an image cannot be produced from code that does not type check.

## Deploying it

Two containers behind one reverse proxy, one origin:

```
https://ciphr.example/          →  ciphr-ui:8080     (this container)
https://ciphr.example/v1/*      →  ciphr:4400        (the service)
```

Same-origin is the recommendation because it removes CORS entirely, and the service has no CORS
support to configure. The viewer's `connect-src 'self'` assumes exactly this shape.

The container holds nothing: no volume, no configuration file, no `.env`, no access to the database or
the master key. It runs as an unprivileged user on port 8080 and serves static files — it does not
proxy `/v1` itself, because a second route to the secret service inside a container whose job is HTML
is a route nobody would remember to secure.

The viewer is released on its own cadence (`.github/workflows/release-ui.yml`, tags `ui-v*`). That is
ADR-11's third argument made concrete: an npm advisory or a layout fix must not force a new server
image, and therefore not a restart of the service whose restart demands the most care.
