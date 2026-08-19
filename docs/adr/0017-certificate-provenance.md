# ADR-17 — Certificate provenance: a private CA for machines, a public certificate for the browser

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-08-19 |
| **Affects** | deployment, `ui/`, CI clients |

## Context

ADR-8 left one thing open: where the certificate comes from. That was answered at the deployment
layer on 2026-08-18 — a dedicated CA, a mounted leaf, the pin on the CA rather than on the leaf, and
no ACME client in the service.

The counter-proposal keeps coming back, and it deserves a written answer rather than a repeated
conversation: give the internal services publicly resolvable names and take their certificates from a
public CA over ACME. With DNS-01 nothing needs to be reachable from outside — only the challenge
record is public — so the objection "that exposes the service" does not apply. The real question
underneath it is whether running a private CA is itself the larger attack surface.

It is not, for the machine path, and it is for the browser path. This record says why, and what the
private CA has to satisfy for that answer to hold.

## Decision

Three parts, and the third revises a plan note rather than an ADR.

1. **The machine path keeps the private CA.** CI clients and the reverse proxy reach ciphr over a
   leaf from a CA this deployment owns, pinned at the CA. The service acquires no ACME client.
2. **That CA carries X.509 name constraints** limiting it to the deployment's internal names and the
   loopback name, and it is **never installed in a system or browser trust store**. It travels as the
   non-secret `CIPHR_CA` variable and is passed with `--cacert`.
3. **The browser path does not use it.** The viewer is served under a publicly resolvable name with a
   certificate from a public CA, obtained by ACME DNS-01 at the reverse proxy. This replaces the note
   in plan section 21 that gave the UI a second leaf from the same CA.

## Rationale

*The trust set is what matters, not the word "CA".* `curl --cacert` **replaces** the trust store for
that call; it does not extend it. The set of keys that can authenticate ciphr to a CI client is
therefore exactly one, and it is one this deployment holds. Public certificates would make that set
the WebPKI's roots — around 150 of them, any single mis-issuance sufficing. For the one hop whose
content is plaintext secrets, that is the wider trust set, not the narrower one.

*The private CA is not a running service.* It signs two leaves in its lifetime. The key is a file,
kept offline, used by hand. "Operating a CA" would describe an online issuing endpoint; that is not
what this is, and section 1 of the plan rules the PKI feature out for the same reason.

*What a private CA genuinely risks is the trust store,* which is why point 2 is part of the decision
and not advice. A root installed system-wide is a universal key for everything that machine speaks —
that, and not the CA as such, is the attack vector the counter-proposal is reaching for. Name
constraints close the remainder: rustls/webpki enforces them, so even a leaked constrained key cannot
mint a name outside this deployment.

*What ACME would cost on the machine path,* in the order the costs actually bite:

- **Certificate Transparency publishes every issued certificate.** Internal hostnames, service names
  and, over time, the host inventory become searchable. A wildcard hides the names at the price of
  one key covering everything.
- **DNS-01 needs a credential that can rewrite public DNS.** That is a larger key than the CA key,
  it has to live on a host, and the store it would belong in is the one being bootstrapped.
- **An ACME client puts outbound internet access, an account key, and a writable certificate path
  into the process that holds plaintext secrets** — or into the proxy, which then holds the ability
  to obtain a certificate for the name the CI clients trust. ADR-8 exists to remove positions like
  that, not to add one.
- **Renewal becomes an external dependency for a fail-closed service.** An expired certificate is an
  outage here, and WebPKI lifetimes are shortening — the CA/Browser Forum has certificate lifetime
  stepping down toward 47 days by 2029. A private leaf can be issued for years. ADR-8's warning that
  expiry will eventually surprise someone stands either way; ACME trades a monitoring task for a
  dependency, it does not delete the problem.

*The browser path inverts every one of those.* The client is a browser whose trust store must not be
touched, and a private leaf leaves only two ways to reach it: install the root — the thing point 2
forbids, and unconstrained across everything that machine does — or accept a click-through warning on
precisely the page where someone pastes a bearer token (ADR-12). Training a user to click through a
certificate warning on the token-paste page undoes more than the certificate protects. Against that,
publishing one viewer hostname to CT is cheap, and renewal there is automated rather than manual.

## Consequences

- One deployment now has two certificate sources. The viewer's renews itself; the service's is
  manual and stays in monitoring, as ADR-8 already requires.
- **The service is unaffected.** It loads two PEM files (`crates/ciphr-server/src/tls.rs`) and needs
  nothing else — which is the property that made the CA-level pin worth choosing, since a leaf can be
  replaced without touching a client.
- The leaf still has to carry the loopback name in its SAN: `--insecure` appears in no example, and
  the container health check speaks to the service over TLS.
- Same-origin routing (ADR-11) still holds and now spans both sources: the browser reaches `/` and
  `/v1/*` under the public name, so the public certificate covers the API *as the browser sees it*,
  while the proxy's own hop to ciphr keeps the private leaf. CI clients never use the public name.
- **If the CA has already been issued without name constraints, it is re-issued before the
  deployment holds real secrets,** and `CIPHR_CA` is redistributed. Constraints cannot be retrofitted
  to an existing certificate.
- Publishing a viewer hostname is a deployment fact, not a code change; whoever runs a private
  deployment decides whether the viewer gets a public name at all, and a deployment that answers no
  keeps the click-through problem and should say so in its own runbook.

## Rejected alternatives

**Public certificates everywhere, via ACME DNS-01.** The proposal this record answers. It widens the
trust set on the hop that carries secrets, publishes internal names to CT, and requires a DNS
credential and an ACME client near the plaintext.

**The private CA everywhere, including the browser.** Consistent, and cheaper by one moving part, but
it reaches the browser only through a system trust store or a warning users learn to dismiss.

**Pinning the leaf instead of the CA.** Rejected downstream already: every rotation would touch every
client, which turns a routine renewal into a coordinated change.

**An online issuing CA (step-ca or similar).** An issuing service is a larger thing to run and secure
than a signing key that is used twice, and it needs its own authentication story — for a deployment
whose entire certificate demand is two leaves.
