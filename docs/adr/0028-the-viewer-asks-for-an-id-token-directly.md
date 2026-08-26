# ADR-28 — The viewer asks for an ID token directly, because its own policy forbids the alternative

| | |
|---|---|
| **Status** | **Accepted 2026-08-26, built the same day.** `response_type=id_token`, nonce-bound, exchanged at `POST /v1/auth/oidc/login`. Completes the half [ADR-12](0012-ui-auth-token-paste.md) scheduled and leaves its mechanism prediction intact — one OIDC validation, two callers |
| **Date** | 2026-08-26 |
| **Affects** | [ADR-12](0012-ui-auth-token-paste.md) (its "After v1" section, now built), [ADR-26](0026-oidc-federation.md) (the server half, unchanged), [ADR-11](0011-ui-is-an-optional-separate-package.md) (why the configuration is the viewer's), `ui/`, `docs/ui.md`, issue #53 |

## Context

ADR-12 decided token paste for v1 and named SSO as next, with the mechanism already chosen: *"It uses
**the same** OIDC validation as the Actions authentication method — one implementation, two callers —
which is why the order 'Actions OIDC first, then UI SSO' is also the cheaper one."* ADR-26 built the
Actions half. So the server side of this needed nothing: a human identity is one whose `kind` is
`human` in the policy file, a binding names it like any other, and `POST /v1/auth/oidc/login` does not
know the difference.

**What ADR-12 did not predict is how the ID token reaches the browser**, and that turned out to be
the decision. The current recommendation, and what anybody would reach for, is authorization code
with PKCE. Its second leg is a request from the browser to the *provider's* token endpoint — and this
page is served under `default-src 'none'; connect-src 'self'`, so a cross-origin `fetch` from it is a
broken page rather than a slow one.

That policy is not incidental to the viewer. It is most of what makes ADR-11's argument work: the
worst a bug in this container can do is bounded by what the page is allowed to talk to.

## Decision

**`response_type=id_token`, bound by a `nonce`, returned in the URL fragment.**

- The viewer generates a `nonce` and a `state` from the browser's CSPRNG, keeps both in
  `sessionStorage`, and navigates to the provider's authorization endpoint.
- The provider returns to the viewer's own document with the ID token in the fragment.
- The viewer checks `state`, decodes the payload **without trusting it** and checks `nonce`, clears
  the fragment with `history.replaceState`, and posts the token to
  `POST /v1/auth/oidc/login`.
- What comes back is an ordinary ciphr token, held in `sessionStorage` exactly as a pasted one is.

**No CSP change, no cross-origin request, and no outbound call from the service.**

**The provider's details are the viewer's own configuration**, read from `/sso.json` on its own
origin. Absent is the ordinary case: no file, no button, token paste unchanged. That follows ADR-11
twice over — the viewer is an optional container and must not make a provider mandatory, and a route
on the service carrying this would have been an endpoint that exists for the UI alone.

## Rationale

The three ways to get an ID token into this page, and what each costs:

**Widen `connect-src` to the provider's origin.** The strictest line in the viewer's policy becomes
deployment-specific and has to be templated at container start — so the thing that is currently a
static, checked-in string becomes a value assembled per deployment, which is where a `'self'` turns
into a `*` one day under time pressure. It also needs the provider to send CORS headers on its token
endpoint, which several do not, so it is not even reliably available.

**Let the server exchange the code.** The cleanest browser flow, and it puts an outbound HTTP client
and public-CA trust into the process that holds plaintext secrets. ADR-17 refused that position for
an ACME client and ADR-26 refused it again for a JWKS fetch, both times because *"ADR-8 exists to
remove positions like that, not to add one"*. Taking it here, for a sign-in convenience in the
component that is deliberately optional, would be the weakest case of the three to spend it on.

**Ask for the ID token.** Costs what is written in the Consequences, and nothing structural.

**The nonce is what makes this defensible rather than merely convenient**, and it is checked in the
browser because that is the only place that can check it. It answers *"was this token minted for the
request this tab made"*; the server is stateless, so an expected nonce passed to it would be one the
caller declared. What the browser does **not** do is decide whether the token is genuine: it decodes
the payload without verifying anything, and the server — the only party with the provider's keys —
verifies the signature, the audience, the times and the binding afterwards.

## Consequences

- **The ID token passes through `location.hash`**, so it reaches this page's session-history entry. A
  fragment is never transmitted to a server, and the fragment is cleared before the exchange request
  is made, so the window is the length of one function — but the browser's own history is a place it
  briefly was, and that is more than the pasted-token flow ever put anywhere.
- **OAuth 2.1 discourages this response type, and this record does not pretend otherwise.** The
  objection it makes is about access-token leakage through exactly that channel. What is obtained
  here is an ID token, bound to a nonce, spent immediately, and useless to anyone who cannot also
  reach the exchange endpoint with the deployment's configured audience — the narrow case where the
  objection is weakest. It remains an objection, and it is the first thing to revisit if the CSP
  question is ever answered differently.
- **The provider must permit `response_type=id_token` for this client.** Some do not, and for those
  deployments the viewer offers token paste and nothing else — which is the state every deployment is
  in today.
- **A human's long-lived pasted token is gone where this is used**, which was the point: ADR-12's own
  consequence list said *"Human tokens are distributed by hand and have short lifetimes. That is
  friction, and it is the reason SSO is next rather than eventual."*
- **`sessionStorage` gains two more keys**, the nonce and the state. Neither is a secret and both are
  removed as soon as the response is checked; a browser that refuses storage gets a refusal to start
  the flow rather than a flow that cannot check its own response.
- **Coverage debt.** `ui/` is in the "unreviewed by anyone" list in `docs/security-review.md` and this
  does not change that. What a reviewer should attack here is the order in `idTokenFromFragment`:
  the fragment is cleared before anything is awaited, and every path that returns a token has
  compared both `state` and `nonce` first.

## Rejected alternatives

**Code with PKCE, either half.** Above. Both are better flows and each costs something this project
spent an ADR protecting.

**A server route that hands the viewer its provider details.** It would put the authorize endpoint
and the client identifier on an unauthenticated endpoint — neither is a secret, both appear in the
redirect anyway — but ADR-11's rule is not about secrecy: *"No endpoint that exists solely for the UI.
If the UI needs it, the CLI needs it too."* The CLI does not need this, so the viewer configures
itself.

**A second mechanism for human identities.** ADR-12 asked the question and answered it, and issue #53
asked it again: *"whether a human identity federated through #50's machinery is the same mechanism
with a different `kind`, or a second one. One mechanism is less code and a wider blast radius on a
bug."* One mechanism, and the blast radius is accepted deliberately — a second verifier for human
tokens would be a second place where "is this token acceptable" is decided, which is the shape of
mistake this project is most careful about elsewhere.
