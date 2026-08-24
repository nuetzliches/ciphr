# Field report 2026-08-21 (b): what the 0.5.0 rollout hit

**Status:** written 2026-08-21 against `v0.5.0`, from the operating side of a private deployment,
after upgrading it. The second report of that day — [the first](field-report-2026-08-21.md) was
written against `v0.4.0` and before this upgrade, and section 0 below says what became of it.

This is not a review and does not claim a review's coverage. It records what an upgrade to `0.5.0`
cost an operator who read `docs/operations/upgrade.md` first and did what it said, plus two claims
the product makes about itself that the code does not support.

Every measurement below comes from the published `0.5.0` image, on one throwaway store and one
throwaway network, both deleted afterwards. Where something was read rather than run, it says so.

## 0. What became of the three findings of the first report

- **Finding 3 (a value written over the API cannot carry its rotation class) is built.**
  `SecretInput` takes an optional `rotation`, absent means unchanged in both directions, and an
  unknown class is a `400` parsed before the authorization entry. That is the shape that was asked
  for and slightly better than what was asked for. Read from `openapi.yaml` and the changelog and
  **not** exercised: the estate this mattered for is not imported yet, so no claim here rests on
  running it.
- **Finding 1 (credential state cannot be read while the service runs) is half done, and the
  documented half is the one that shipped.** `docs/operations/cli.md` now says outright that all
  four token commands need the service stopped, `list` included, and spells out the consequence —
  which was preference 2 of that finding, and it removes the trap where the page read as though
  `token list` were as cheap as `audit tail`. Preference 1 did not happen: `TokenCommand::List`
  still goes through `open(cli)`, so a read that records nothing still takes the lock and still
  applies migrations. The finding stands as it was written; this report does not restate it.
- **Finding 2 (nothing warns the holder before a token expires) is untouched.** No response carries
  the expiry of the presenting credential — `expires_at` and `expires_in` appear nowhere in
  `openapi.yaml`. Stands as written.

## 1. Nothing tells an operator which entries are *off*

**Observed.** After the upgrade, four routes exist only where the configuration names them. The
operator's question after a `404` is therefore new and permanent: *is this route missing because
this build never had it, or because this deployment did not name it?* Nothing in the product answers
it.

Measured, same server and same requests, two configurations — the second is the file that started
`0.4.0`, unchanged:

| Request | with both stanzas | with the `0.4.0` file |
|---|---|---|
| `GET /v1/health` → `surface` | `["viewer_api","bulk_export"]` | `[]` |
| `GET /v1/audit`, `/v1/identities`, `/v1/policies` | `401` | `404`, body **0 bytes** |
| `POST /v1/export` | `401` | `404`, body **0 bytes** |
| `GET /v1/surface` | `401` | `401` |
| `GET /v1/nonsense` (a typo) | `404`, body 0 bytes | `404`, body 0 bytes |

The last row is the finding. An entry that is off is byte-identical to a path that never existed,
which is exactly what ADR-20 wants on the wire — *off means absent, never dormant* — and this report
does not ask for that to change. What is missing is the answer on the other side:

- **`GET /v1/health`** carries the active names. Empty is both "this deployment turned nothing on"
  and, to a reader who does not know the version's entry list, "this build has no entries".
- **`GET /v1/surface`** returns the records of active entries, and empty is the ordinary answer.
- **`ciphr surface show <config>`** prints the stanzas *in the file*, each with the cost of its
  absence. A file with no stanzas prints one line — `<file> turns nothing on. That is the ordinary
  configuration.` — which is true, well judged, and still does not say what "nothing" was chosen
  from.
- **`ciphr-server --check-config <file>`** prints `configuration and policies are usable`, and says
  nothing about surface at all.

So the closed list of entry names — `surface::ENTRIES`, which exists precisely so that "what can a
deployment turn on" is a question with an answer rather than a search — is the one thing no
interface prints. The answer is in the binary and reaches nobody.

**The `--check-config` case is the sharp one, because the upgrade note recommends the command for
this release specifically:** *"run `ciphr-server --check-config` … that release adds two refusals
about surface entries, and it is also the one that makes four existing routes conditional on the
configuration — so the file that started the previous version can be a file this one declines, and a
`404` on the viewer is a quieter way to find out than a process that will not start."* Measured
against exactly that: the `0.5.0` binary accepts the previous version's file without a word, because
a *missing* runtime stanza is legal. The command a careful operator is told to run before stopping
anything cannot detect the mistake this release made possible.

**Asked for, in order of preference:**

1. **`--check-config` prints the resolved surface** — active entries, and the known entries this
   configuration did not name. It has `Active` and `ENTRIES` in hand; this is output, not mechanism,
   and it makes the recommendation in `upgrade.md` true.
2. **`ciphr surface show` does the same for the file**, marking the unnamed ones as off with their
   cost sentence. That sentence is the one thing an operator deciding about an entry wants to read,
   and today it is only printed for entries already decided in favour of.
3. Failing both: name the mapping somewhere a running deployment can reach. `openapi.yaml` carries
   `x-surface-entry` per route, which is the right data in the wrong place for an incident.

**Why it is worth output rather than an operator's care.** The failure mode of a forgotten stanza is
silent on both sides. The viewer serves its files, stays healthy in monitoring, and shows nothing —
the container is fine and the configuration next to it is not. A consumer that fetches secrets over
HTTP gets a `404` where it expected `200` and reports it as *the service is unreachable*, which sends
the operator to the network and the service, in that order, and neither is wrong. The only loud path
is a consumer that treats a missing value as fatal, and that is a property of the consumer.

For what it is worth, the monitoring side of this is workable today: a check on
`len([BODY].surface) == 2` against `/v1/health` catches the dropped stanza, and that is what this
deployment now runs. It is a count and not a set membership because the monitor's condition language
cannot express the latter — a limitation of the monitor, not of this project. It is mentioned only to
say that the endpoint carries enough for the *positive* assertion. The negative one is the gap.

## 2. The cost sentence of `bulk_export` describes a route that does not exist

**Observed.** `bulk_export` ships with this cost, and `GET /v1/surface` serves it to whoever asks
what the deployment gave up:

> Route B and route C fetch by named path instead of by prefix, one request each, and `ciphr-run`
> refuses with exit code 125 rather than starting a service without its secrets. **The upside is the
> one ADR-15 cares about: a deployment whose consumers name their paths has no fetched prefixes for
> bait to stay out of.**

`openapi.yaml` says the same in the route's description (*"Turning it off is also what removes
fetched prefixes"*), the upgrade note repeats it as advice (*"Take the loss where you can"*), and
`api.rs` introduces the entry as *"the route that reads the value of every path under a prefix"*.

**`POST /v1/export` does not read by prefix.** `ExportRequest` has one property, `paths`, required,
`minItems: 1` — and the schema says why, in the same file: *"named explicitly rather than by prefix:
an export is the operation most likely to hand over more than intended."* Two statements in one
document, and only one of them matches the handler.

**What that does to a deployment's decision.** Prefix-fetching is a property of the *caller*, not of
this route. A consumer that lists a prefix (`GET /v1/list/{prefix}` — not an entry, therefore not
switchable) and then reads everything the listing returned covers exactly that prefix, with or
without `bulk_export`: turning the entry off converts one request into N `GET /v1/secrets/{path}`
calls over the same paths, producing the same coverage, the same one-audit-entry-per-secret, and more
round trips. Bait gains nothing. Conversely, a consumer that names its paths already has ADR-15's
property while the entry is *on*, and turning it off buys it nothing either.

So the sentence points a deployment at the one lever that cannot move what it claims to move, and
does it in the place ADR-20 designed for the purpose: the recorded cost is the input to the decision,
and `GET /v1/surface` exists to put it in front of an operator. It is also the one artefact a
deployment cannot correct locally — it ships compiled in.

**Asked for:** the sentence, the route description and the `api.rs` comment say what the route does
(several named paths in one call, one audit entry each) and what its absence costs (N requests
instead of one, and `ciphr-run` refusing with 125). If the fetched-prefix property matters to ADR-15
— and the placement rule in `honeypots.md` reads as though it does — then the thing that would have
to become switchable is `GET /v1/list/{prefix}`, or nothing.

**Not asked for:** making `/v1/list` an entry. This deployment's own consumer needs it, and ADR-20
is explicit that the set of entries stays small. The point is the claim, not the lever.

## 3. The `0.5.0` rollback is two-part, and the upgrade note has one part

**Observed.** The `0.5.0` note says schema 6 is a one-way door and that a `0.4.0` binary refuses a
schema-6 database, so a rollback needs the restore. Both true, both measured:

```
ciphr-server: store: database schema version 6 is newer than the supported 5
```

The other half is not in the note. `Config` has `deny_unknown_fields`, so the configuration `0.5.0`
requires is a configuration `0.4.0` cannot parse:

```
ciphr-server: invalid configuration in …: TOML parse error at line 82, column 3
   |
82 | [[surface]]
   |   ^^^^^^^
unknown field `surface`, expected one of `server`, `storage`, `seal`, `policies`, `audit`
```

An operator who follows the note — back up, then roll the image back if it goes wrong — gets a TOML
parse error in a moment they believe is about the database, and the message names a stanza the
upgrade note told them to add. The refusal is right and the order is even helpful (it fires before
the store is touched). The sentence is what is missing.

**Asked for:** one sentence in the `0.5.0` section — a rollback to `0.4.0` needs the `[[surface]]`
stanzas removed as well as the database restored, because the older binary rejects unknown top-level
keys. This is the class of thing `upgrade.md` says it exists for: *"the person upgrading two versions
later needs the same four sentences that mattered the first time."*

## 4. `honeypots.md` precondition 1 cannot be met with a published artefact

**Observed.** The runbook leads with three things that must be true, and the first is *"the service
has to be built with the entry"*, with a `curl` for checking whether it is. Nothing says how to get
such a build. `Dockerfile` runs `cargo build --release --locked --bin ciphr-server --bin ciphr` with
no build argument and no feature, and neither release workflow passes `--features`. So every
published image and every release binary answers that check with `no`, and the runbook's first step
is a dead end for anyone who is not building from source and does not know Cargo.

Measured on the published `0.5.0` image, which is the artefact this deployment runs:
`GET /v1/honeypots` → `404` with an empty body, and `/v1/health` carries no `tripped`. Both correct,
and both exactly what a deployment that wanted bait would see with no explanation available.

**Asked for:** name the build in `honeypots.md` step 1 — `cargo build --release --features
honeypot_alert`, or a `Dockerfile` build argument — and say plainly that the published images are
default builds and always will be unless that changes. One sentence and one command.

**Worth stating, because it is the reason this is a small finding rather than a request:** this
deployment is *not* asking for a feature-enabled image. Turning the entry on here would mean a second
artefact, and the surface it adds is newer than the accepted review — `docs/security-review.md` marks
C11, C12 and D10 as uncovered, and this deployment's risk acceptance was written about the reviewed
core. That is a decision to make deliberately later, and the runbook shape is right for it. It just
stops one step too early.

## What is deliberately not asked for

- **A distinguishable `404` for an inactive route.** The bare fallback is the point: off means the
  route is absent, and a handler that answers `404` from inside itself is the dormant-flag failure
  ADR-20 rejects. Finding 1 asks for output on the operator's side precisely so the wire behaviour
  can stay as it is.
- **A refusal when a runtime entry is unnamed.** Off is a legitimate deployment, and most
  deployments should have `viewer_api` off. A `--check-config` that failed on an absent entry would
  make the default state an error.
- **Any change to the indistinguishability of authentication failures**, and any change to the
  pessimistic rotation default. Both were settled in the first report and are settled here too.

## Provenance

Findings 1, 3 and 4 were produced by upgrading a running deployment and by running the published
`0.5.0` image against a throwaway store on a throwaway network — a server started twice with two
configurations, and the requests in the table above issued from a second container. The `0.4.0`
refusals were produced the same way, against the store the `0.5.0` server had already migrated.
Everything was deleted afterwards. Finding 2 comes from reading `openapi.yaml`, `surface.rs`,
`api.rs` and `upgrade.md` against each other; the claim that turning the entry off would not change
what a listing-then-reading consumer covers is an argument about a caller, not a measurement of one.
No claim here rests on a changelog entry alone.
