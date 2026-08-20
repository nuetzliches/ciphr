# Freeze: what it closes, and how it ends

**Nothing here is implemented.** ADR-15 requires this document *before* the code, because
`docs/operations/` is for the things that are hard to undo and a service that refuses to serve is
exactly that. Written 2026-08-20, alongside the design review of ADR-15 and ADR-16.

A freeze is the severe tier of a tripwire. One piece of bait, marked `freeze`, was read through a
value route by an authenticated identity — and from that moment the service serves no values to
anybody until a human clears it on the host.

Read this before choosing that tier for anything.

## What a freeze closes, precisely

A half-defined kill switch is worse than none, so the list is exhaustive.

| | |
|---|---|
| **Refused with `503`** | `GET /v1/secrets`, `POST /v1/export`, `PUT`, `DELETE`. No value leaves and nothing changes. |
| **Still served** | `/v1/health`, which says it is frozen and since when; `/v1/audit`, `/v1/list`, `/v1/versions`, `/v1/identities`, `/v1/policies`. None of those serves a value, and whoever is investigating needs the trail more than ever. |
| **Unaffected** | The CLI on the host. A freeze that locks out the operator is a self-inflicted incident with no way back. |

Two properties that are not conveniences:

- **It survives a restart**, because it is recorded in the store rather than in memory. A freeze an
  attacker clears by crashing the process fires once and never again.
- **It never clears itself.** No timer, no backoff. A tripwire that resets quietly has, in effect,
  not fired.

## What it costs while it is on

Every deploy fails, on every target that fetches from this service. **Already-running services are
unaffected** — they hold their values in their own environment, so a freeze stops the next deploy
rather than the current fleet. That is the whole reason the tier is survivable: the blast radius is
"nothing new ships", not "production stops".

Be honest about one thing when picking the tier: if a single machine identity serves every deploy
target, then `disable-identity` already costs every deploy, and `freeze` adds only the identities
that do not exist yet. The middle tier is worth what the identity set makes it worth.

## Recognizing a false positive

The expected shape of a false positive is: **every deploy started failing at once, and nothing else
is wrong.** Distinguish it from an outage in this order.

1. **Ask `/v1/health`.** It says whether the service is frozen and since when. An outage does not.
2. **Read the trail entry.** `honeypot-triggered` names the bait, the identity, and the tier. That is
   the whole diagnosis, and it is one query.
3. **Check where the bait lives.** If the honeypot secret sits under a prefix that any consumer
   fetches — `ciphr-run --prefix`, `client.environment(prefix)`, or a deploy helper built on
   `POST /v1/export` — then this is a false positive **by construction**, not a judgement call: those
   consumers read the value of every path under their prefix, every time they start. The bait was
   unplaceable there. Move it to a path nobody deploys before turning the tier back on.
4. **Only then decide** whether an identity did something it had no reason to do.

A honeypot that fires on the nightly backup, or on a deploy, is a honeypot that gets switched off in
week two — and then it is not protecting anything while still looking as though it does.

## Clearing it

On the host, and nowhere else:

```sh
ciphr lockdown status     # what fired, when, and which bait
ciphr lockdown clear      # audited; the only way out
```

There is no API route for this, deliberately. The freeze exists because something reached the API
with a valid credential; a way out through the same door would be a way out for whoever caused it.

**Read the trail before clearing.** Clearing is one command and takes a second; reconstructing what
happened after the incident has been tidied away takes an afternoon, and the reason the tier exists
is that somebody should have to look.

## Before you set `freeze` on any bait

- `alert` is the default because it costs a page and nothing else. Choose it unless there is a
  written reason.
- `freeze` hands an availability lever to any identity that can read a path. It is the right choice
  when exfiltration is a worse outcome than a stopped pipeline — which is a real situation, and a
  decision that belongs in the deployment's own documentation with a date next to it.
- No anonymous request can reach this tier. A reported value (`POST /v1/report`) only ever alerts, and
  a trip latches per piece of bait, so neither a report nor a repeated read is a way to hold the
  service down from outside.
