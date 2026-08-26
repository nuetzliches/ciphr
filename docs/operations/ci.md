# Secrets in a CI job: `ciphr-ci`, and the masking trap

**Status:** implemented and tested as of 2026-08-25, current as of `v0.13.0`
([ADR-25](../adr/0025-the-ci-side-fetch-is-its-own-binary.md)). Both `ciphr-ci` and `action.yml` are
covered by tests that run the real binary against the real service.

**The example below pins `v0.12.0`, on purpose, and will not follow every release.** The tag and both
checksums are real and that release's assets are still there, which is all a workflow needs — and the
alternative is what the last three releases did: new binaries have new numbers, so each one turned the
block back into placeholders until somebody filled them in again. A block that oscillates between
numbers and placeholders teaches a reader to distrust it. Pin a newer tag when there is a reason to,
take both numbers from that release's job summary, and change all three together. **Both architectures**, since 2026-08-24 (issue #4): every commit builds and runs `ciphr-ci` and
`ciphr-run` as static binaries on a native amd64 and a native arm64 runner, and a release attaches an
asset for each. What is *measured* about the masking is narrower than what runs,
and the section on that says exactly where the line is.

This is route A: a build or deploy job that needs values at runtime. Route B is a container that only
understands environment variables ([`wrapper.md`](wrapper.md)); route C is an application that fetches
its own ([`../../crates/ciphr-sdk/src/lib.rs`](../../crates/ciphr-sdk/src/lib.rs)).

## The one thing to know before writing a workflow

**No forge masks a value fetched at runtime.** Only its own native secrets are masked. A job that
reads a value with `curl | jq` has that value in its log the moment anybody adds `set -x` or a debug
echo — and a job log is usually readable by more people than the secret store is.

That is why fetching is a program rather than a documented `curl` line. `ciphr-ci` emits
`::add-mask::` for every value **before** it emits anything else, one mask per line for multi-line
values, and writes the assignments into the runner's environment file with a heredoc delimiter drawn
from the OS CSPRNG and checked against the value. Those rules are shared with `ciphr export` on a host
— one implementation, one set of tests, in `ciphr-export`.

## The shortest useful step

```yaml
- name: Fetch secrets
  uses: nuetzliches/ciphr@v0.12.0
  with:
    url: ${{ vars.CIPHR_URL }}
    ca: ${{ vars.CIPHR_CA }}                # not a secret: the internal CA, as PEM
    token: ${{ secrets.CIPHR_TOKEN }}       # the one forge secret that stays
    paths: ci/widget/DB_PASSWORD ci/widget/API_KEY
    version: v0.12.0
    sha256-amd64: d11c662f9e5ee7d790eb03512ff298e6e785772915b75b24c9df69d3eb44100f
    sha256-arm64: e6b91c4f1ec66bfaf694adca0abaf63d9f4860b5b0392677e919ecadbf643591

- name: Deploy
  run: ./deploy.sh                          # DB_PASSWORD and API_KEY are in the environment
```

Pin the tag in both places: the action and the asset it downloads should come from the same release,
so a workflow cannot end up verifying one version's checksum against another version's binary. **The
two numbers belong to the tag above**, one per architecture — a release means three edits in this
block, not one, and a tag bumped without its checksums is the failure the two inputs exist to
catch.

The variable name is the **last path segment**: `ci/widget/DB_PASSWORD` becomes `DB_PASSWORD`
([ADR-18](../adr/0018-one-rule-for-the-variable-name.md)). A set in which two paths want the same name
is refused whole rather than delivered with one of them missing.

`version` and the two checksums are how the binary is fetched and checked, and the download step uses
`gh`. **The architecture is the runner's, not a choice:** the step reads `uname -m`, downloads the
matching asset and verifies it against the checksum for that architecture — which is why there are two
inputs rather than one that can only be right about one of them. A runner of any other architecture is
refused rather than handed a binary that would produce `exec format error` inside the step that was
supposed to deliver secrets.

Two situations need `binary:` instead, which points at a `ciphr-ci` already on the runner and
downloads nothing: a self-hosted image that bakes the file in, and any runner without the GitHub CLI
— which is most non-GitHub runners. **Whether `gh` is present on a Forgejo or Gitea runner is not
something this project has measured**, so the honest instruction for those is `binary:` plus a step
that fetches the file however that forge does it.

## Without the action

The action is a wrapper; the binary is the product. Anything that can run a shell can call it
directly, which is the route for Woodpecker, Jenkins, a host cron job, or a forge whose action syntax
this project has not looked at:

```sh
install -m 0600 /dev/null "$RUNNER_TEMP/ciphr-token"
printf %s "$CIPHR_TOKEN" > "$RUNNER_TEMP/ciphr-token"

ciphr-ci --url "$CIPHR_URL" \
         --token-file "$RUNNER_TEMP/ciphr-token" \
         --ca /etc/ciphr/ca.crt \
         --path ci/widget/DB_PASSWORD \
         --format actions-env --github-env
```

**There is no flag that takes the token itself**, and there will not be one: an argument is in
`/proc/<pid>/cmdline` while the process runs and in the log of any runner that echoes command lines.

`--format dotenv` writes a `.env` file and `--format json` a document keyed by full path. Both put
values on standard output, so both refuse a pipe unless `--force` says that is intended — the same
rule `ciphr get` and `ciphr export` follow on a host:

```sh
ciphr-ci --url "$CIPHR_URL" --token-file "$RUNNER_TEMP/ciphr-token" --ca /etc/ciphr/ca.crt          --prefix ci/widget --format dotenv --force > .env
```

**The action does not offer those two**, and refuses rather than passing `--force` for you: standard
output on a runner is the job log, and an action that redirected nothing while forcing values onto
that stream would be printing secrets into the one record it cannot redact afterwards. The
redirection is the caller's, so the invocation is too.

## Without a binary at all

The API is HTTPS plus a bearer token, so `curl` is a complete client and always has been. Use this
where a binary cannot be placed on the runner — and read the paragraph after it before you do.

```sh
set -eu    # and not `set -x`: see the measurement section below

# One secret, by path. The value is JSON-encoded, so `jq -r` is what unescapes it.
value=$(curl --fail --silent --show-error \
             --cacert "$CIPHR_CA" \
             -H "Authorization: Bearer $CIPHR_TOKEN" \
             "$CIPHR_URL/v1/secrets/ci/widget/DB_PASSWORD" | jq -er '.value')

# A whole prefix is two requests, because there is no "export a prefix" operation:
# list authorizes every path it returns, then each path is read.
curl --fail --silent --show-error \
     --cacert "$CIPHR_CA" \
     -H "Authorization: Bearer $CIPHR_TOKEN" \
     "$CIPHR_URL/v1/list/ci/widget" | jq -r '.paths[]'
```

**What this leaves the job to do, and what it costs:**

- **The masking.** Nothing above emits `::add-mask::`, so the value is in the log the first time
  anybody prints it. Doing it correctly is more than one `printf`: masks before anything else, one
  per line for a multi-line value, and — if the value goes into `$GITHUB_ENV` — a heredoc delimiter
  the value cannot reproduce. That last one is not a style question: a delimiter somebody can guess
  lets a value close its own assignment and define variables for later steps, which is finding F2 of
  [`review-2026-08-21-current-tree.md`](../assurance/reviews/review-2026-08-21-current-tree.md). `ciphr-ci` exists
  because that belongs in tested code rather than in every workflow that copies this block.
- **The status codes.** `--fail` turns them into a non-zero exit and loses which one it was. `401`
  is the token, `403` is the policy, `404` is the path, and **`503` means the audit trail could not
  be written — no secret was served and nothing changed**, which is a deployment outage rather than
  something to retry past. Add `--write-out '%{http_code}'` if the job should tell them apart.
- **An empty listing is not an empty prefix.** `GET /v1/list` authorizes every path it returns, so a
  token without `list` there gets `{"paths":[]}` and a `200`. A job that treats that as "nothing to
  fetch" starts with no secrets and fails later, somewhere else.

## Where the binary comes from

**As a release asset**, named after its target triple — `ciphr-ci-x86_64-unknown-linux-musl` and
`ciphr-ci-aarch64-unknown-linux-musl` — each beside its own `.sha256`. The checksums are also printed
into the release run's job summary, which is where to read them *before* downloading anything. The
name carries the triple so that a second architecture arrives beside the first rather than renaming
it; that qualification was made while amd64 was the only one, which is what makes today additive.

Statically linked, so the job's image does not matter: a glibc runner, an Alpine container job and a
self-hosted machine somebody set up years ago all run the same file.

**There is deliberately no image for this one**, unlike `ciphr-run`. The wrapper needs a registry
channel because the host that mounts it authenticates to a registry and not to the forge. A job
always holds a credential for the forge it runs on, so the asset is the natural channel here and a
second one would be a second thing to keep in step.

## The token, and how much it can do

**One identity per repository** (`ci-<repo>`), not one per runner and not one for everything. That is
the granularity at which the trail is worth reading: *repository X read secret Y at 09:14*.

```sh
ciphr token issue ci-widget --ttl 30d
```

Shorter lifetimes for CI than for a host — those tokens are spread across more systems. The identity
has to exist in the policy file first; issuing one for a name nobody granted anything produces a
credential that authenticates and can do nothing.

A policy shape that fits the step above:

```toml
[[identity]]
name     = "ci-widget"
kind     = "machine"
policies = ["ci-widget"]

[[policy]]
name = "ci-widget"

  [[policy.rule]]
  path         = "ci/widget/**"
  capabilities = ["read"]
```

`read` alone is enough for `paths:`. Add `list` only if the workflow uses `prefix:`.

**Put the token file in the runner's temporary directory, not in the workspace.** The wrapper's rule
applies here too and for a sharper reason: the workspace holds checked-out code, and whoever can write
into the directory a token lives in can put *their* token there at mode 0600 and have the fetch run
under an identity they control. `$RUNNER_TEMP` is per-job; the action writes there and removes the
file when the step ends, including when the fetch fails.

## `paths` or `prefix`

`paths` needs only `read`; `prefix` needs `list` as well and takes whatever exists under the prefix at
that moment. Prefer `paths` wherever the set is known when the workflow is written, for two reasons
that belong to the prefix form alone:

- **A listing that shrinks does so silently.** `GET /v1/list` authorizes every path it returns, so
  removing one path's `list` capability makes the set one shorter. An *empty* result is refused; an
  incomplete one is not, and the job then runs with a variable missing.
- **Somebody else's new secret can break this job.** The name is the last path segment, so a secret
  added for a neighbouring service under the same prefix can make the next run refuse on a collision.

## A name can decide how the next steps run, and those names are refused

Since 2026-08-24, F4 of [the full-repository review](../assurance/reviews/review-2026-08-24-full-repository.md). The
same rule as the wrapper's, and it bites harder here: `$GITHUB_ENV` sets variables for **every step
that follows**, not for one program. That is the shape of CVE-2020-15228 — the reason GitHub Actions
stopped letting a workflow set variables through a log directive.

`ciphr-ci` refuses a fetched secret whose name is read by a loader or a runtime before the program
starts: `LD_*`, `DYLD_*`, `NODE_OPTIONS`, `PYTHONPATH`, `PYTHONSTARTUP`, `RUBYOPT`, `PERL5OPT`,
`BASH_ENV`, `JAVA_TOOL_OPTIONS`, `PATH`, `IFS`. **Before the fetch**, so a set that will be refused
costs no reads and leaves no audit entries — and nothing is written to the environment file.

With `paths:` the names are the ones the workflow lists, so this can only fire on something the
workflow itself asked for. With `prefix:` the names come from the store, which is exactly the case the
rule exists for: whoever may write under that prefix would otherwise choose an environment variable
name for every later step of the job.

## What a failure looks like

**Exit `1`, a message on standard error, and nothing written.** One code for every failure this
program has: a workflow step that fails fails the job, and there is no second interpretation to
encode. What the code carries is the guarantee — the whole set is rendered before anything is emitted,
so a refused fetch, an unusable name or a colliding pair leaves the job's environment exactly as it
was. A step with `continue-on-error` does not continue with half a configuration.

The messages that are worth recognizing:

| What it says | What happened |
|---|---|
| `nothing is visible under …` | The prefix is empty **or** this token has no `list` capability there. The service cannot tell those apart and neither can the program |
| `this identity may not do that to one of: …` | A `403`. With the bulk route on, the service refuses the whole set without saying which path — deliberately, so an export cannot map what a caller may read |
| `POST /v1/export is not available on this deployment` | Only from a direct SDK call; the fetch itself handles this (see below) |
| `the token file … is mode 0644 and world-readable` | The credential is readable by whoever else is on that runner |
| `--github-env was given but GITHUB_ENV is not set` | Not a job step, or a runner without environment files. Refused before anything is fetched |

## It works on a deployment that named no optional route

`POST /v1/export` is a surface entry ([ADR-20](../adr/0020-optional-surface.md)) and is **off unless a
deployment names it**. Since 2026-08-24 that is not a decision a job has to wait for: the fetch reads
through the bulk route where it exists and falls back to one `GET /v1/secrets/{path}` per path where it
does not.

Two things do not change with the route, and one does:

- **The audit trail is identical.** The bulk route writes one entry per secret served rather than one
  per call, so the trail says the same thing either way.
- **The capabilities are identical.** `read` per path, `list` additionally for a prefix.
- **A refusal reads differently.** The bulk route refuses whole. Read one at a time, the paths before
  the refused one have already been served and audited, and the error names the path that was refused.
  Nothing new is disclosed — `GET /v1/secrets/{path}` answers per path for anyone holding a token — but
  a trail that stops halfway is what a partial fetch looks like.

**The bulk route is bounded, and the fallback is not.** It refuses an export naming more than **256
paths**, naming one path twice, or returning more than a mebibyte of values in total. A job fetching a
prefix wider than that gets a refusal naming the limit and has to ask in more than one step; the
per-path fallback has no such bound, because a request per path is already one unit of work per path.
Nothing chunks silently — a fetch split behind the caller's back is a fetch whose trail the caller
cannot predict.

## What is measured, and what is only claimed

**Measured on a Forgejo runner on 2026-08-18**, with `forgejo-runner exec -i -self-hosted` — the same
binary and execution mode a job uses — against values differing in a single character. Masking held in
every case the format exists for: the same step, across steps through `$GITHUB_ENV`, multi-line values,
a value inside a composed URL, and a value in the stderr of a failing command. The multi-line round
trip was checked by comparing SHA-256 digests rather than by printing anything.

**It does not hold under `set -x`, which is the case masking exists for.** A runner matches a mask as a
literal substring, and bash re-quotes an argument before xtrace prints it: a value containing a single
quote renders as `'part'\''part'` — bytes inserted in the middle — and one containing a tab as
`$'a\tb'`. Both reach the log in clear text. Everything else survives: a space, `$`, a backtick, a
double quote and a backslash all render inside single quotes untouched, and multi-line values survive
because the mask is emitted per line. So the rule for a job holding fetched values is **`set -x` off**,
not "the mask will catch it".

**act_runner is not claimed.** "Both are act derivatives" is precisely the assumption this project
refused to make about the Forgejo runner before measuring it. Measuring needs a Gitea runner to measure
on; where there is none, the alternative to measuring is assuming.

## What this does not solve

The values are in the job's environment, which is where the job wanted them — so they are readable by
everything that step runs, and by anything that can read `/proc/<pid>/environ` on that runner. A
runner is a machine somebody administers, and that somebody is not necessarily whoever owns the
secrets the job fetched. What ciphr adds is that the value has an owner, an expiry, a policy and a
trail entry naming which repository read it, not that it stops being a secret in a process.

**A secret that has left ciphr is the pipeline's problem.** The trail records that a job read a value,
never what the job did with it afterwards.
