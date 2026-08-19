# ADR-8 — TLS terminates at the service, not at the reverse proxy

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-08-18 |
| **Affects** | `ciphr-server`, deployment |

## Context

The common pattern for a service behind a reverse proxy is to terminate TLS at the proxy and speak
plaintext HTTP on the internal container network. For most services that is an acceptable trade: one
certificate to manage, less configuration, and the internal network is treated as trusted.

## Decision

The listener terminates TLS itself, using `rustls`. The reverse proxy connects to it over HTTPS with
a pinned internal certificate.

## Rationale

The content of these connections *is* plaintext secrets. On a shared container network, a
compromised neighbouring container is a realistic adversary (A2 in the threat model), and the
"internal network is trusted" assumption is precisely what fails in that scenario. Everything the
rest of the design does to keep plaintext off disk is undone if it crosses a bridge network in the
clear.

The cost is one certificate plus a line of proxy configuration. That is a small price for removing an
entire eavesdropping position.

## Consequences

- This deviates from the surrounding convention on purpose, and the deviation must be stated in the
  README so nobody "fixes" it later.
- Clients need the internal CA certificate or its pin. It is distributed as a **non-secret** CI
  variable or action input. `-k` / `--insecure` appears in no documentation and no example, not even
  as a testing shortcut.
- Certificate renewal becomes an operational task for this service, with an expiry that will
  eventually surprise someone. It belongs in monitoring.
- The source of the certificate is still open: an internal CA at the reverse proxy, or a mounted
  self-signed certificate with pinning. That choice also determines CA distribution to CI clients and
  interacts with the UI origin question (ADR-11).

**Answered since.** That last bullet is settled in
[ADR-17](0017-certificate-provenance.md) — a name-constrained private CA for the machine path, a
public certificate for the browser. It is left standing as written, because the format keeps the
open question where it was open.

## Rejected alternatives

**Plaintext behind the proxy, like everything else.** Cheaper and conventional, but it leaves secrets
readable to any container that can observe the bridge network.
