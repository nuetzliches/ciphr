# The `ciphr` command

**Status:** implemented and tested as of 2026-08-19 (phase 3). Every command below works. Deployment
— containers, reverse proxy, certificates — is phase 4 and not described here yet.

The CLI works on the **local** store, with the master key from a file or from the environment. It does not go through
the HTTP API, and that is deliberate: initializing a store, issuing a token, shredding a version,
verifying the chain, and exporting for migration all need the master key and have no endpoint by
design (ADR-3). A CLI that spoke HTTP would need a privileged API to do its job — the API this
project does not have.

Remote access is `curl` (see `openapi.yaml`) or, from phase 7, the SDK.

## Two rules that shape every command

**A value is never an argument.** There is no `--value` flag, and adding one would be a regression.
An argument lands in shell history and in `/proc/<pid>/cmdline`, where every other process on the
host can read it while the command runs. Values come from standard input:

```sh
printf %s "$VALUE" | ciphr put infra/service-a/DB_PASSWORD
ciphr put infra/service-a/TLS_KEY < key.pem
```

There is no interactive prompt either. Disabling terminal echo would need another dependency, and
prompting *with* echo writes the secret into the scrollback of whoever typed it. Piping is the one
route that leaves no copy behind. A trailing newline is stripped once, so `printf %s` and
`echo` both do the right thing; supply two if the value genuinely ends in one.

**A secret is not written to a pipe unasked.** `get`, `export`, `dump`, and `token issue` refuse
when output is not a terminal, because that is how a secret reaches a log, a CI transcript, or a
shell history through `$(…)`. Pass `--force` when it is intended:

```sh
ciphr get infra/service-a/DB_PASSWORD                 # refuses, tells you why
ciphr get infra/service-a/DB_PASSWORD --force > /tmp/x # deliberate
```

`export --format actions-env` is exempt: writing into the runner's environment file *is* its
purpose.

## Global options

| Option | Default | What it is for |
|---|---|---|
| `--database`, `-d` | `ciphr.db` | The store. |
| `--master-key-env` | `CIPHR_MASTER_KEY` | Variable holding 64 hexadecimal characters. |
| `--master-key-file` | — | File holding the key instead. Preferred where the deployment allows it; cannot be combined with the variable. See [master-key.md](master-key.md). |
| `--policies` | `policies.toml` | Needed by `token issue`, which checks the identity exists. |
| `--audit-file` | — | Also append this session's audit entries to a JSON Lines file. |

## Starting a store

```sh
# preferred: the key in a file the deployment mounts
printf %s "$(openssl rand -hex 32)" > /run/secrets/ciphr-master-key
chmod 0600 /run/secrets/ciphr-master-key
ciphr --database /var/lib/ciphr/store.db --master-key-file /run/secrets/ciphr-master-key init

# or from the environment
export CIPHR_MASTER_KEY=$(openssl rand -hex 32)
ciphr --database /var/lib/ciphr/store.db init
```

`init` refuses on a store that already has a root key: initializing twice would orphan every secret
in it. The first audit entry of a store is its own creation, so the chain starts at something rather
than at nothing.

Read [master-key.md](master-key.md) before the first real secret goes in. The short version: keep a
break-glass copy outside the host, and never in the same backup as the database.

## Everyday commands

```sh
printf %s "$V" | ciphr put infra/service-a/DB_PASSWORD
printf %s "$V" | ciphr put infra/service-a/JWT_SECRET --rotation invalidates-sessions

ciphr get infra/service-a/DB_PASSWORD
ciphr get infra/service-a/DB_PASSWORD --version 2
ciphr list infra
ciphr versions infra/service-a/DB_PASSWORD
ciphr rotation infra/service-a/DB_KEY breaks-data      # prints what to do instead
```

Every one of these is audited, including the metadata ones. The trail says the same thing whether an
access came through the API or from the host — a channel that records less is a channel someone will
use for that reason.

## Deleting, and destroying

```sh
ciphr delete infra/service-a/OLD_TOKEN                 # reversible
ciphr undelete infra/service-a/OLD_TOKEN --version 3
ciphr destroy infra/service-a/OLD_TOKEN --version 3 --yes
```

`destroy` deletes the version's wrapped data key. The value cannot be recovered afterwards by
anyone — including from a backup taken after the shred, which is the point. `--yes` is required, and
there is no HTTP equivalent.

Before destroying a version of a `breaks-data` secret, read
[rotating-secrets.md](rotating-secrets.md): a restore from a backup that predates a rotation needs
the value that was current then.

## Exporting into a process

```sh
ciphr export --prefix infra/service-a --format dotenv --force > .env
ciphr export --path infra/a/ONE --path infra/b/TWO --format json --force
ciphr export --prefix ci/widget --format actions-env --github-env
```

The variable name is the **last path segment**: `infra/service-a/DB_PASSWORD` becomes
`DB_PASSWORD`. Each exported secret produces its own audit entry, exactly as the bulk endpoint does.

`dotenv` single-quotes values and escapes embedded quotes, which is the one form that needs no
reasoning about what the shell will do with `$`, backticks, or backslashes.

### The masking trap

**No forge masks a value fetched at runtime.** Only its own native secrets are masked. A bare
`curl | jq` puts secrets in the job log the moment anyone adds `set -x` — and that log is usually
readable by more people than the secret store is.

`--format actions-env` therefore emits `::add-mask::` for every value **before** anything else, then
writes the assignments. The order is the whole point: a mask registered after a value has been
printed masks nothing that already went out. Multi-line values get one mask per line, because
runners match literal strings, and are assigned with a heredoc whose delimiter includes the variable
name so a value containing `EOF` cannot end its own block.

With `--github-env` the assignments go to the file named by `$GITHUB_ENV` and only the masks reach
standard output. Verifying that `::add-mask::` is honoured by a Forgejo runner and by act_runner is
a phase 4 task — both are act derivatives, but that is to be proven rather than assumed.

## Migrating a `.env` file in

```sh
ciphr import --from-dotenv ./.env --prefix infra/service-a --dry-run
ciphr import --from-dotenv ./.env --prefix infra/service-a --rotation rotatable
```

`--dry-run` prints target paths and value *lengths*, never values: it is something people run to
check their work, often with someone else looking at the screen. A line the parser cannot read stops
the import rather than being skipped — a partially moved corpus surfaces as a broken deploy much
later. Comments, blank lines, `export` prefixes, and quoted values are handled; `$VAR` references
are **not** expanded, because storing the expansion would store something the file does not say.

## Tokens

```sh
ciphr token issue deploy-runner --ttl 90d
ciphr token list --identity deploy-runner
ciphr token revoke A1b2C3d4
ciphr token revoke-all deploy-runner
```

The identity must exist in the policy file: identities are defined there (ADR-3), and issuing a
token for a name nobody granted anything produces a credential that authenticates and can do
nothing.

The token is printed **once**. What the database holds is
`HMAC-SHA256(pepper, secret)`, and the pepper is derived from the root key — so a stolen database
does not permit offline verification of guessed tokens, and no `ciphr token show` can exist.

A TTL needs a unit: `90d`, `12h`, `30m`, `3600s`. A bare number is refused rather than assumed to be
seconds, because "90" meaning seconds when days were intended is a token that expires mid-deploy.
Prefer shorter lifetimes for CI than for a host: those tokens are spread across more systems.

`revoke-all` is what to reach for when an identity is compromised — one call, rather than listing
tokens and hoping the list was complete.

## The audit trail

```sh
ciphr audit tail -n 50
ciphr audit verify

# record the head somewhere the writer of this store cannot reach
ciphr audit anchor --out /mnt/evidence/ciphr-anchors.jsonl

# and check the chain against the newest anchor in that file
ciphr audit verify --anchor /mnt/evidence/ciphr-anchors.jsonl
```

`verify` recomputes every hash and checks that each record chains to its predecessor. What it proves
and what it does not is printed with the result and explained in
[audit-trail.md](audit-trail.md): a verified chain shows no entry was removed, edited, or reordered,
and it does **not** show that nobody rewrote the chain forward.

`anchor` is what closes that. It writes one JSON line — sequence number, hash, timestamp — to
standard output and appends it to `--out`, so a scheduled job can pipe the record on without
filtering prose out of it; everything a person reads goes to standard error. Both commands read
**without the store lock and without the master key**, so they work while the server is running, and
`anchor` deliberately records no audit entry of its own: it would move the head it just wrote down.
Where the file lives is the whole value of the exercise — on the same host as the database, an anchor
proves nothing.

### Bounding it

```sh
# keep the newest 50 000 entries queryable; the rest must already be in the archive
ciphr audit cut --keep 50000 \
  --anchor /mnt/evidence/ciphr-anchors.jsonl \
  --archive /var/lib/ciphr/audit.jsonl

# see what that would do, and do none of it
ciphr audit cut --keep 50000 --anchor … --archive … --dry-run
```

The `audit_log` table grows for as long as the store exists, and because auditing is fail-closed a
full volume stops the service serving secrets. `cut` is the bound. Both file arguments are required,
and each answers a different objection to removing audit records:

- **`--anchor`** is where the anchor at the cut goes. Removing the oldest records leaves a chain that
  no longer starts at sequence one, so what remains can only be verified from the point the cut ended
  at — and if that point lives only in the store, it is a claim by whoever can write the store.
  The command appends **two** lines: the anchor at the cut, and one over what survived.
- **`--archive`** is the file device's file, rotated siblings included. Every record the cut would
  remove has to be in there byte for byte, or the cut is refused. The queryable copy may be bounded;
  the evidence may not be thrown away. `--assume-archived` replaces that check with an assumption,
  for a deployment whose lines are shipped off the host as they are written or whose rotated files
  are compressed and therefore unreadable here — it says what it is trusting on every run.

`--keep` is a count, not an age. The bound it answers is how large the queryable table is;
age-based retention belongs on the archive, where the host's log tooling already does it.

Like `anchor` and `verify`, `cut` needs **neither the store lock nor the master key**, so it runs
against a live service — a retention job that needed downtime would not get scheduled, and then the
bound would not exist. It writes no audit entry of its own for the same reason `anchor` does not, and
its record in the store is the `audit_cut` row. A trail shorter than `--keep` is reported and exits
zero; every refusal happens before anything is removed.

The reason this is a command and not something the service does on a schedule: a cut has to be
anchored outside the store, and the service is the thing an anchor exists to be independent of. An
anchor the service wrote about its own trail is worth nothing against the service.

## Rotating the master key

```sh
ciphr rotate-master-key --new-key-file /run/secrets/ciphr-master-key.new
# or
export CIPHR_NEW_MASTER_KEY=$(openssl rand -hex 32)
ciphr rotate-master-key --new-key-env CIPHR_NEW_MASTER_KEY
```

The old and the new key may come from different kinds of source, which is how a deployment moves from
the environment to a file: read the old one from the variable, write the new one to the file, rotate.

One record changes and nothing is re-encrypted — that is what the root key exists for. Keep the old
key until a restart with the new one has been confirmed; the window between the rewrite and a
successful restart is the one where having discarded it too early would be unrecoverable.

## Leaving

```sh
ciphr dump --format portable --force > ciphr-export.json
```

Every value in that file is plaintext. Treat the file as the secret store itself: it is the one
artifact that is exactly as sensitive as the database plus the master key.

It exists on purpose. If this project ever struggles at the cryptographic or authorization layer,
moving to OpenBao is the correct decision, and a migration must not fail because of a proprietary
file format. Insurance bought after the fire is worthless, which is why this shipped in v1 rather
than being left for the day it is needed.
