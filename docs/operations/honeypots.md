# Honeypots: planting bait, and what to do when it fires

**Status:** written 2026-08-21, describing the `alert` tier as built. The severe tiers of
[ADR-15](../adr/0015-honeypots-and-what-a-tripwire-may-do.md) are designed and not built, and
[freeze.md](freeze.md) says why.

A honeypot turns one class of silent failure into a loud one. The audit trail records every
access and *notices* nothing: a compromised deploy runner holding a valid token reads what
its policy allows, the trail dutifully records it, and whether anybody realizes depends on
a human reading the trail and recognizing that the pattern is wrong. Bait that no legitimate
consumer touches turns a read into a signal that needs no interpretation — there is no
benign reason to take it.

Two kinds, catching different things. A **honeypot token** catches whoever scraped a place
credentials end up in. A **honeypot secret** catches whoever is already inside with a valid
identity and is enumerating rather than fetching what they need.

## Before you plant anything

**Three things have to be true, or the bait is decoration.**

1. **The service has to be built with the entry.** `honeypot_alert` is a Cargo feature,
   absent from the default binary. Check `GET /v1/health`: the `surface` array names the
   entries this instance contains, and `tripped` is present only when it has this one.

   ```sh
   curl --cacert "$CIPHR_CA" https://ciphr.internal:4400/v1/health | jq '.surface, .tripped'
   ```

   A default build records taking the bait as an ordinary rejected credential and pages
   nobody. Nothing warns you about this at planting time except the CLI's own output,
   because the CLI cannot see the service's build.

   **Every published artefact answers that check with `no`, and the build has to come from
   here.** `Dockerfile` and both release workflows build without `--features`, so no
   released image and no released binary contains this entry — and that will stay true
   unless this paragraph says otherwise, because a feature-enabled image is a *second*
   artefact and the decision in the next paragraph has to be made before there is one:

   ```sh
   cargo build --release --locked --features honeypot_alert --bin ciphr-server
   ```

   For a container, the same in a derived image — copy `Dockerfile`, add the flag to its
   `cargo build` line, and publish it under a tag of your own. `ciphr-server --check-config
   <file>` on the result reports `honeypot_alert  build` as on rather than "not in this
   binary", which is the check that the build and the configuration agree before anything
   is planted.

   **Making that build is a decision about running unreviewed code, and it is the reason
   the default artefact stays the default.** The accepted external review read the
   authentication path before bait existed;
   [../security-review.md](../security-review.md) marks C11, C12 and D10 — the three
   claims that describe this entry — as newer than the acceptance. A deployment whose risk
   acceptance was written about the reviewed core is extending it when it builds this, and
   that is a deliberate act rather than a step in a runbook. Deciding *not* to costs
   nothing: bait nobody can detect is the only thing lost, and a deployment that plants
   none loses nothing at all.

2. **The configuration has to name it**, with the date you accepted the cost and the reason:

   ```toml
   [[surface]]
   entry    = "honeypot_alert"
   accepted = "2026-08-21"
   reason   = "bait under infra/_runner; Gatus pages on /v1/health tripped"
   ```

   The server **refuses to start** if the feature is compiled in and this is missing, and
   equally if this is present and the feature is not. The second refusal is the one that
   matters: without it a deployment could believe it had detection, have written down when
   and why, and have none — and nothing would ever say so, because bait that cannot fire
   looks exactly like bait nobody took.

3. **Something has to poll `/v1/health` and page a human.** This is the step this software
   cannot check and cannot do. The alert is a fact on an endpoint and an entry in the trail;
   whatever turns that into somebody's phone ringing is outside this process by design
   (ADR-15 rejects an outbound connection from the one container that should talk to
   nobody). **A tripwire whose entire output is a field nobody reads is not a tripwire** —
   it is the anchor-file failure in another shape. Wire the monitoring first.

   What to poll, and the two ways this particular field is read wrong — `tripped` is *absent*
   rather than `false` in a build without the entry — is in [monitoring.md](monitoring.md).

## Where bait goes, which is the part that decides whether it works

**Bait must sit outside every prefix any consumer fetches.** This is not decoration and it
is the rule most likely to be got wrong, because the instinct puts bait next to the real
secrets — which is exactly where it cannot go.

`ciphr-run --prefix`, `client.environment(prefix)`, and anything built on `POST /v1/export`
list a prefix and then read **the value of every path under it**. Those are value routes, so
bait under a fetched prefix is read with a valid identity, through a value route, on every
service start. Not by an operator's mistake — by the ordinary consumption pattern.

**Whether a prefix is fetched is a question about the code that fetches, not about the
policy.** Those are two different sets, and the gap between them is where bait belongs. A
machine identity is typically authorized over more prefixes than any consumer actually
reads: the credentials the deploy machinery itself uses, for instance, which no service ever
pulls into its own environment. Bait there is authorized for the identity that would be
compromised, untouched by every ordinary fetch, and next to the most attractive material in
the corpus — which is where an enumerator goes first.

Establishing that a prefix is unfetched means reading the fetching code. A helper that lists
a prefix and exports everything it got back will read bait the policy file gives no hint
about; a helper that filters that list against the names its consumer declares will not.

**Under an `infra/<host>/<service>/<KEY>` scheme, that means a `<service>` level nobody
deploys.** Never beside the real secrets of a real service.

**And a honeypot secret needs a gap between what an identity may read and what it does
read.** The trigger fires after the policy *allowed* the read, so an identity granted exact
paths has no such gap: bait outside its grants produces a denial, and a denial trips
nothing. Scoping exactly and planting honeypot secrets are therefore alternatives rather
than complements — see [authorization.md](../authorization.md). Honeypot *tokens* are
unaffected either way.

## Planting

A honeypot secret is a real secret with a real-looking value, marked afterwards:

```sh
printf 'aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' |
  ciphr put infra/_runner/AWS_DEPLOY_KEY
ciphr honeypot add infra/_runner/AWS_DEPLOY_KEY
```

The value should be worth taking and useless if taken. `ciphr honeypot add` refuses a path
that holds nothing: a tier on an empty path is bait that answers `404` to whoever takes it.

A honeypot token is planted where a credential should not be but often is — an old `.env` on
a host, a job log, a wiki page, a repository somebody archived:

```sh
ciphr token issue deploy-runner --honeypot
```

The identity is required and must exist. It grants nothing; it is what names *which* bait
was taken in the trail. Give the bait an identity that makes the placement plausible.

**What is visible where.** `ciphr honeypot list` and `GET /v1/honeypots` are the only places
the flag appears. It is absent from `ciphr list`, `ciphr get`, `GET /v1/list` and
`GET /v1/versions`, because bait that announces itself to a caller is not bait. The
administrative view exists for the opposite failure: a colleague who cannot tell bait from a
real secret eventually rotates it or builds a service on it, and either destroys it.

## What does not trip

Worth knowing before you write an alert rule, because a honeypot that fires on the nightly
backup is a honeypot that gets switched off in week two.

- **Host operations.** `ciphr get`, `ciphr export`, `ciphr dump --format portable` decrypt by
  design and cannot trip — the trigger lives in the server, so the CLI cannot reach it.
- **Listing and version history.** `GET /v1/list` and `GET /v1/versions` name a path without
  serving its value. Enumerating a name is not taking the bait.
- **A refused read.** Bait outside an identity's grants produces `403` and trips nothing.
- **A second read of bait already tripped.** The trip latches per piece of bait until it is
  cleared, so one compromised consumer reading the same bait every minute pages once. Every
  read is still in the audit trail — the latch bounds the paging, not the record.

## When it fires

**`/v1/health` says `tripped: true` and how many trips are open. It never says which bait.**
That is deliberate: an unauthenticated endpoint may report what the process is doing and not
what is stored. To find out what was taken:

```sh
ciphr honeypot list                    # on the host: which bait, and which is TAKEN
ciphr audit tail -n 50                 # the trail, where the trip is authoritative
```

Or over the API, with `read` on `sys/honeypots`:

```sh
curl --cacert "$CIPHR_CA" -H "Authorization: Bearer $CIPHR_TOKEN" \
     https://ciphr.internal:4400/v1/honeypots
```

**The audit entry is the record, not the flag and not the row.** Look for
`honeypot-triggered`. Its `detail` says what was attempted (`attempted: read`), and:

- For a **honeypot secret**, `principal` is the identity that read it and `path` is the
  bait. Someone with a valid credential read something nothing needs. Treat the credential
  as compromised.
- For a **honeypot token**, there is no `principal` — bait authenticates nothing — and
  `subject` carries the identity the bait was issued for plus its token id. Someone read the
  place you planted it. Treat that place as exposed, and everything that was ever in it.

`client_ip` is on the entry when the listener was told one, which is the first thing worth
looking at and the reason [ADR-16](../adr/0016-leak-reports-are-a-one-way-drop-box.md)'s F2
finding was fixed before this shipped.

### Then

1. **Do not clear it yet.** The latch is what stops the page repeating; clearing it before
   you have read the trail loses nothing recorded but does lose the "is this still
   happening" signal.
2. **Work out which credential or which place.** The trail says which, above. `ciphr token
   list` runs read-only against the live service (ADR-22) — expiry, revocation state and
   last use are readable now, before anything is stopped — so the decision of *which* token
   to revoke is made with the service up.
3. **Revoke — and this step stops the service.** `ciphr token revoke <id>` for one
   credential, `ciphr token revoke-all <identity>` for all of an identity's. Both write a
   row and an audit entry, so both open a session and take the store lock the running
   server holds: **stop the service, revoke, start it again.** The outage is part of this
   runbook, not an accident of it — plan the sequence so everything else here is done
   first, and know that while the service is stopped, the stolen credential is answered
   nothing either. There is no revocation over the API (issue #14 tracks whether there
   should be), and no automatic revocation: ADR-15 designed `disable-identity` and
   deliberately did not build it, because where one machine identity serves every deploy
   target, revoking it stops every deploy — an availability lever whose trigger condition
   is "somebody read a path".
4. **Then clear, so the bait can fire again:**

   ```sh
   ciphr honeypot clear
   ```

   This sets a cleared timestamp and deletes nothing; both the old trip and the next one
   stay on record. It is on the host and nowhere else — there is no route that clears a
   tripwire, for the reason ADR-3 gives policies: a guard reachable through the door it
   guards is not a guard. And it never happens on a timer, because a tripwire that resets
   quietly has, in effect, not fired.

## A false positive

The likeliest cause by far is placement: bait under a prefix something fetches. The trail
tells you — the same identity, on every deploy, at the same times. Move the bait rather than
loosening the rule:

```sh
ciphr honeypot remove infra/service-a/OLD_KEY   # the secret stays; only the mark goes
```

The second likeliest is a colleague who found the value and used it because it looked real.
That is what `ciphr honeypot list` is for, and it is an argument for telling the team that
bait exists and where the list is — not for making it visible to callers.

## What this does not solve

**A targeted attacker who reads only what they came for is not caught.** Honeypots detect
indiscriminate behaviour: enumeration, scraping, a stolen credential tried everywhere. That
is what most real compromise looks like, and it is not what the most capable adversary looks
like.

**Bait has to be planted where secrets actually leak**, which is knowledge about your
deployment and not about this software. This repository can only make bait cheap to create
and impossible for a caller to distinguish.

**A honeypot secret is bait only while nobody depends on it.** The first service that reads
it by mistake turns it into a source of false positives, and what prevents that is the
placement rule and the visible list — not anything in the code.
