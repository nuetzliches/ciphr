# Field report 2026-08-23 (b): `0.9.0`'s mandatory edit meets a check that cannot gate a review

**Status:** written 2026-08-23 against `v0.9.0`, from the operating side of a private deployment, after
upgrading `0.8.0 -> 0.9.0` and making the `inspect` edit. The fifth report from this deployment; the
fourth was [2026-08-23](field-report-2026-08-23.md) and this release answers all of it.

Not a review. One finding is the same shape as finding 2 of the last report — a status about something
other than what the caller asked — and `0.9.0` raises its stakes rather than lowering them, because the
thing it now tells operators to check in review is a *mandatory* edit. The other two are small: an
error message that names an OS error where it could name the requirement, and a bootstrap wrinkle in
the new revocation path that is only visible from the operating side.

**What the deployment did**, for context: upgraded to `0.9.0`, changed its one affected rule
(`sys/**` from `read` to `inspect`) in the same commit as the pin, and left both new surface entries
off. Store, policy set and viewer are otherwise unchanged: one machine identity, one human identity,
six secrets.

## 0. What `0.9.0` closed, and one thing it got right that is worth saying

- **The capability split is the right cut, and the refusal is the right shape.** This deployment's
  `viewer` policy had exactly the affected rule. The message earned its place:

  ```
  policy file: policy 'viewer', rule 'sys/**': 'read' is a capability about a secret, and
  'sys/**' names the control plane. Since ADR-23 reading a control-plane path is 'inspect' and
  revoking a token is 'revoke'; a rule under 'sys/' may grant only those. Replace 'read' rather
  than removing the rule, or the identity loses the access it was written for
  ```

  It names the policy, the rule and the capability meant, and the last clause is the part that
  prevents the wrong fix: deleting the rule also loads, and the viewer would then show nothing.
  Refusing rather than silently denying is the correct direction for exactly the reason ADR-23 gives.
- **All four findings of the fourth report are in** (`--check-config` in halves, `state` exit `3`,
  the backup destination message, the namespace note). The exclude list in this deployment's backup
  job now branches on `3`.
- **The HTTP/1.1 narrowing is the kind of finding a deployment cannot make.** We would never have
  looked at the ALPN list of our own listener; that it advertised `h2` through a transitive feature,
  on the process that holds plaintext secrets, is worth the release on its own. Measured here after
  the upgrade: `HTTP/1.1 200` where `0.8.0` answered `HTTP/2 200`, same client, same command.
- Both new entries are off and behave as documented: `/v1/audit` answers `401` (route present,
  `viewer_api` on) and `/v1/tokens` answers `404` (absent, not a refusing handler). `/v1/health`
  still lists two entries, so the monitoring condition on that list needed no change.

## 1. `--check-config` cannot gate a review, and `0.9.0` is the release that needs it to

**Observed**, `v0.9.0`, three runs. Only the two `.toml` files are mounted in the first two — the
"findable in review" case that [upgrade.md](../../operations/upgrade.md) now advertises:

```
A) old policy (sys/** with read), no store   -> exit 1   + the refusal quoted above
B) fixed policy (inspect), no store          -> exit 1   file half complete, then
                                                "store: the store is not initialized"
                                                "the sections above are about the file and hold
                                                 without this host"
C) fixed policy, store ro + audit rw + key   -> exit 0   "store: ready (schema 6, seal static, …)"
```

**A and B are the same status.** A pipeline that runs the command upgrade.md tells it to run — new
binary, policy file, nothing mounted — cannot tell "this policy file is refused" from "this machine
has no store", and the difference is the entire point of the check on a review host. What is left is
parsing the report, and the file half is a dozen lines of prose including the honeypot entry's cost
paragraph.

**Why this is worse than in the previous report, not better.** `0.8.0` split the report so the file
half holds without a host; that was the ask and it landed. `0.9.0` then made a *mandatory* policy edit
whose whole safety net is that same check, and pointed at review as the place to run it:

> Run `ciphr-server --check-config <file>` against the new binary and the policy file — since `0.8.0`
> that needs neither a store nor a master key, so this is findable in review.

Findable, yes. **Gateable, no** — and a check that a pipeline cannot fail on is a check somebody
remembers to read.

**The precedent is this project's own, from the same day.** `ciphr state` had a status about rows the
caller must not have, and `0.8.0` gave it `3` for "listing complete, pre-flight failed", keeping `1`
for a real failure and leaving `2` to clap. `--check-config` has the identical shape: the file half is
a pure function of the file, the store half is about a host that may deliberately not be there.

**Ask, in preference order.**

1. **A distinct exit code for "file half usable, host half not"** — the `state` treatment, one
   number, no output parsing. The current sentence *"Exit is unchanged: zero when the store is ready,
   non-zero when it is not"* stays true for every existing caller; only the no-store case moves off
   `1`.
2. `--check-config --json`, if a machine-readable report is wanted anyway. More work, and it also
   answers the prose-parsing half.
3. Failing both: say in `upgrade.md` that a pipeline must branch on output rather than status, so the
   next person writes that guard deliberately instead of discovering the need. This is the least
   valuable option, and it is what this deployment did — our deploy script mounts the real store
   read-only so that exit `0` means *config usable and this host ready*, which works on the host and
   is exactly what a review host cannot do.

## 2. The host half needs write access to the audit directory, and says so as an OS error

**Observed** while wiring the above, `0.8.0` and unchanged in `0.9.0` — everything mounted read-only,
which is the safe instinct for a command whose name says *check*:

```
audit device: cannot open /var/log/ciphr/audit.jsonl: Read-only file system (os error 30)
  the sections above are about the file and hold without this host
```

The behaviour is defensible: the file device is checked by opening it the way it will be opened, and
that is an append. The *message* is the finding — it names an OS error at the path, so the first
reading is "the audit device is broken", when the fact is "this check needs the directory writable and
it was mounted read-only". One clause would fix it, in the shape the rest of this project's messages
already have: *the file audit device is opened for append, so this directory must be writable by the
service user; it was mounted read-only*.

Worth it because of who reads it: whoever is pre-flighting a host they have deliberately given as
little access as possible. In our deploy the fix was mounting the store `:ro` and the audit directory
read-write as the service uid — obvious in hindsight, ten minutes in practice.

## 3. Turning on the outage-free revocation costs an outage

`token_revoke` exists because `ciphr token revoke` takes the exclusive store lock the running server
holds, so revoking a leaked credential is stop-revoke-start — an outage at the one moment nobody
planned for. Right problem, and ADR-24's boundary looks sound from here.

**But the path in has the shape it removes.** Using it requires an identity with `revoke` on
`sys/tokens` and a token for that identity, and `token issue` stays on the host, in a session, behind
the same lock:

> Issuing stays on the host because it needs the master key and *creates* a credential

So enabling the feature that removes the outage from revocation requires taking that outage once, to
issue the credential that will use it. That is not wrong — it is the ADR-3 boundary and we would not
argue for a write path that mints credentials — but it belongs in the runbook next to the entry,
because the operator who reaches for this is mid-incident with a leaked token and does not want to
discover it there. **Ask:** one line in [honeypots.md](../../operations/honeypots.md) step 3 and in the
`token_revoke` section of `upgrade.md` — *issue the revoking identity's token before you need it; it
needs the same stop that revocation used to need.* And, if it is cheap, have `--check-config` (or
`ciphr surface show`) note when `token_revoke` is on while no identity holds `revoke`: an entry that
is on and unreachable is the same class of quiet as a stanza that was forgotten.

## 4. What this deployment still owes

Unchanged, and stated so it is not mistaken for something the project is missing: **the restore drill
with the real break-glass key has not been run.** The half that needs no key was exercised again in
passing — a pre-upgrade copy taken with the `0.8.0` binary, 339968 bytes, before the `0.9.0` pin
moved. The other half is fetching the master key from where it actually lives and opening a restored
store with it, and no test in this repository can do that for us.
