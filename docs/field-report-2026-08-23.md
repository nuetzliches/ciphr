# Field report 2026-08-23: `0.7.0` in place, and two checks that answer beside the question

**Status:** written 2026-08-23 against `v0.7.0`, from the operating side of a private deployment,
after upgrading to it and rebuilding that deployment's backup exclusions around `ciphr state
--exclude`. The fourth report from this deployment; the earlier three are
[2026-08-21](field-report-2026-08-21.md), [2026-08-21 (b)](field-report-2026-08-21-b.md) and
[2026-08-22](field-report-2026-08-22.md).

Not a review. Two of the four findings are about a check whose verdict is about something other
than what the caller asked — a configuration check gated on storage, and a listing whose exit code is
about rows the caller must not have. One is a missing row in a failure table, and one is a note with
no ask attached.

**What the deployment did**, so the findings have a context: upgraded `0.6.1` -> `0.7.0` (pre-flight
first, backup with the old binary, no schema move), replaced the backup job's hand-written exclusion
list with `ciphr state --exclude`, and moved three more values out of the forge and into the store,
which brings this deployment to five paths held here and four forge secrets deleted.

## 0. What `0.7.0` closed, since a report should say so

- **`--json` and `--exclude` arrived and are in the job.** The exclusion list is now derived from
  `[storage] path` instead of being a line somebody wrote once. **The first thing it did was find
  something:** the hand-written list named only `store.db.lock`, so `store.db-shm` had been in every
  snapshot this deployment ever took. Nobody noticed for the same reason nobody noticed the lock —
  a wrong exclusion list produces no error, only a slightly larger archive and a restore surprise.
  It was found by the tool's report about the configuration, not by a person re-reading a script.
- **`init` passes `--audit-file` now.** Read in the tree, not assumed: the `Session::open(...)
  .with_audit(cli.audit_file.as_deref())` in the init path closes the gap where every archive began
  at sequence 2 with a `prev_hash` naming a record the file never held. This deployment's store keeps
  its gap, which is correct and is what a hash chain means; new stores will not have it.
- **The read-write correction in [backup.md](operations/backup.md) matches what the job already
  does.** This deployment had moved to a read-write source and `--user 999:999` a day earlier, for
  the same reason now written there — but the *prose* beside the job still carried the old claim, in
  two of its own documents. Both corrected. A wrong sentence next to right code survives longer than
  a wrong line of code, because nothing executes it.
- **The core-dump refusal cost nothing here**, and was measured rather than hoped: `ulimit -c 0` in
  the `0.7.0` image, `ulimit -c` reading `0` afterwards, before the pin moved. The container
  definition had carried `ulimits: core: 0` since day one as a second latch; `0.7.0` makes it the
  first one.
- **`Cache-Control: no-store` is on every response**, confirmed in the handshake after the upgrade.

## 1. `--check-config` answers the loud question without a store and the quiet one only with

**Observed**, `v0.7.0`, configuration and policy file mounted, no store present. Two configurations,
and the difference between them is the finding:

```
$ ciphr-server --check-config /etc/ciphr/ciphr.toml        # a surface stanza missing its reason
ciphr-server: invalid configuration in /etc/ciphr/ciphr.toml: TOML parse error at line 87
exit=1

$ ciphr-server --check-config /etc/ciphr/ciphr.toml        # a healthy configuration
ciphr-server: store: the store is not initialized
exit=1
```

**A broken file is diagnosed without a store; a correct one cannot be confirmed without one.** The
deserialization refusals — unknown field, a surface stanza without its date or reason — land before
storage is touched, and those are exactly the changes that would fail loudly at startup anyway. What
needs a store is the positive verdict and, with it, the surface report:

> **Read its surface report and not only its exit code.** The mistake this release makes possible is
> a *forgotten* stanza, and that file is legal: the command exits zero on it […]

That advice is sound, and it is the case the store gate blocks. A forgotten stanza parses cleanly, so
the parse-level half says nothing about it; the surface report is the only place the question is
answered, and it prints after the store opens. **The check that needs no store catches what would
have been caught anyway, and the check for the silent failure is the one that needs one.**

A validator that wants that answer has to first make a store exist at the path the configuration
names and seal it under the key the configuration names — `init` wants a real 64-hex key, so the
fabrication is not free either. This deployment's deploy script does exactly that on every run:
scratch directory, `chown` to the service uid, `ciphr init`, `--check-config`, delete. It uses the
production master key, because that was the obvious route; it need not have — any key would do, since
the store being validated against is one the script created seconds earlier. **That is the point:
the gate is satisfiable by fabrication, so it is not protecting anything, and the fabrication is what
every validator has to build.**

**Why this is worth something rather than an inconvenience.** The surface report is a pure function
of the file. A configuration edit is exactly the kind of change that wants review before it reaches a
host — and there, with no store and no key, the one report that catches a forgotten stanza is out of
reach. Where it *is* cheap to run — on the host, where the store exists — the file is already about
to be used. The discipline the report exists to support is therefore enforceable only at the last
moment before it is needed.

**Ask:** separate the two questions the command answers at once. Report configuration, policies and
surface without opening storage, and make store readiness its own labelled section or its own flag.
Then a change that edits `ciphr.toml` can be checked in review by the same binary that will run it,
with no key and no store — which is what would make [upgrade.md](operations/upgrade.md)'s advice
something a pipeline can follow rather than something a person has to remember on the host.

## 2. `state --exclude` fails on rows a backup job must never be shown

**Observed**, `v0.7.0`, the store and audit directories mounted, the TLS material and the master key
deliberately not:

```
$ ciphr state --exclude /etc/ciphr/ciphr.toml
/var/lib/ciphr/store.db-shm
/var/lib/ciphr/store.db.lock
ciphr: /etc/ciphr/ciphr.toml is not a usable configuration: 3 file(s) this configuration requires
are not there
exit=1
```

The listing is complete and correct. The exit code is about three rows the caller did not ask for and
must not have: the two TLS files and the seal file. [backup.md](operations/backup.md) is the reason
they are not mounted — *keep the key somewhere this backup is not* — so the deployment that follows
the guidance most strictly is the one whose backup job can never see a zero here.

The documentation states the current behaviour as a decision, and the decision is defensible in
general:

> Both forms exit non-zero on a missing required file, exactly as the table does: the pre-flight half
> of this command does not depend on who is reading its output.

**What the specific case adds.** The `never` rows are derived from `[storage] path` alone; whether
the TLS leaf or the key file exists cannot change them. So `--exclude` fails on a fact that is not
about its own output, in the one caller — an unattended job — that has no human to interpret the
difference. The job this deployment wrote therefore ignores the exit code by design and validates the
*output* instead: non-empty, every line an absolute path, and the store lock among them, because the
lock is the only exclusion whose absence breaks a **restore** rather than merely bloating an archive.
Writing that guard felt like re-implementing a check the tool had just performed.

**Ask, in preference order.** A distinct exit code for "listing complete, pre-flight failed" (say `2`),
so a caller can tell the two apart without parsing text — this keeps the pre-flight half exactly as
documented. Failing that, a flag to select the listing without the pre-flight. Least preferred, and
mentioned only because it is the smallest change: say in [cli.md](operations/cli.md) that a job
consuming `--exclude` should branch on output rather than status, so the next person writes the guard
deliberately instead of discovering the need.

## 3. A missing row: `ciphr backup` when the destination is not writable by the service uid

**Observed**, taking the pre-upgrade copy as the documentation now recommends — source read-write,
running as the service uid — into a directory owned by the operator's login account (`0775`):

```
ciphr: database error: unable to open database: /out/ciphr-store-pre-0.7.0.sqlite
```

The message names the destination, and every other sentence around it at that moment is about the
source: the row above it in the table is `ciphr backup` against a read-only *source*, whose message
is `unable to open database file`. The first guess is therefore that the store could not be read.

**The causal part is what makes it worth a row:** this failure is *created* by following the fix for
the previous one. Running as the service uid is the advice; the operator's own directory is not
writable by that uid; so the natural destination fails. The fix is one `chown` on a destination
subdirectory — the same shape the job already needed for its staging directory, which is where this
deployment had already learned it once and did not connect the second time.

**Ask:** a row in *What breaks, and how it will look* — `ciphr backup` writing into a directory the
service uid cannot write, what it looks like, and that the destination is the thing to check. If the
error is cheap to wrap, naming the directory rather than the file would end the guess entirely.

## 4. A note with no ask: `--exclude` speaks the service's namespace

Recorded because the next containerized consumer will hit it, not because it is the tool's problem to
solve. `--exclude` prints the paths the configuration names, which are the paths inside the *service's*
mount namespace. A backup job in its own container sees the same files under different paths, so the
list has to be translated before it can be handed to anything. Untranslated, every exclusion silently
matches nothing — a failure with no symptom, which is the same class of quiet wrongness that the
hand-written list had.

This deployment translates through both containers' mount tables via the container runtime, so the
mapping is not written down anywhere twice. That is the right place for it: the tool cannot know it.
One sentence in [backup.md](operations/backup.md) — *if the job runs in a different mount namespace,
these paths need translating* — would be enough, and would have saved the ten minutes spent
confirming that an exclusion which matches nothing looks exactly like an exclusion that works.

## 5. What this deployment still owes

Unchanged from the last report, and stated so that it is not mistaken for something the project is
missing: **the restore drill with the real break-glass key has not been run.** The half that needs no
key was done again in passing this week — a copy taken with the old binary before the upgrade, 320
entries verified on it, head at 320. The other half is fetching the master key from where it actually
lives and opening a restored store with it, and no test in this repository can do that for us. The
project's [restore test](../crates/ciphr-server/tests/restore.rs) covers what it can; the missing
half is ours.
