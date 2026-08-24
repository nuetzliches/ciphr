# Review of `v0.5.1`, from the deployment that filed the report it answers

**Status:** written 2026-08-21 against `v0.5.0..v0.5.1`, by the operator of the private deployment
whose [field report](../field-reports/field-report-2026-08-21-b.md) this release addresses. **Not a security review
and not related to [`security-review.md`](../../security-review.md):** nothing here reads crypto, policy
evaluation, the store, or the honeypot code, and nothing here extends any acceptance. It reviews the
diff that answers a report, and the artefact that answers it in production.

**What was read:** the whole `v0.5.0..v0.5.1` diff, plus the code the corrected cost sentence makes
claims about (`ciphr-run`'s two fetch modes, `Client::environment`/`environment_of`, `RunError::code`)
and the two files the new gate compares. **What was run:** the published `0.5.1` image, on this
deployment and on a throwaway store beside it. **What was not run:** `cargo test`, `cargo clippy`,
the new CI gates. Where a claim below rests on reading rather than running, it says so.

## Verdict

All four findings are answered, and two of them more thoroughly than they were asked. The corrected
`bulk_export` sentence is **accurate against the code it describes** — verified, see below — and the
release does the harder half of correcting a shipped claim: [`upgrade.md`](../../operations/upgrade.md)
tells a deployment that turned the entry off *for the wrong reason* that it paid a real cost for a
property it never got, which is the part a changelog entry alone would have left undone.

Three things are worth changing. None blocks anything, none is a defect a deployment can hit today,
and the first is the same class of thing this release exists to fix: **a new doc comment claims a
property the code does not have.**

## Verified rather than taken on trust

**The corrected cost sentence is true.** It now says turning `bulk_export` off costs `ciphr-run`
entirely, because both of its modes fetch through that route. Read end to end:
`ciphr-run --prefix` calls `Client::environment`, which lists and then calls `environment_of`;
`--path` calls `environment_of` directly; `environment_of` calls `Client::export`, which is the only
caller of `POST /v1/export` in the SDK. A failure there becomes `RunError`, and every variant except
`Exec` maps to exit code `125`. So both halves of the sentence hold, including the exit code.

**The correction is complete.** Every remaining mention of "fetched prefixes" in the tree is a correct
one — bait must sit outside a prefix some consumer fetches, which is a property of the consumer.
`ADR-15`, `honeypots.md` and the two ADR reviews were already saying it that way; the five places that
said the wrong thing are the five that changed.

**The output is compatible with the consumers that read it.** `--check-config` still prints
`configuration and policies are usable` as its first line, byte for byte, and appends the surface
report after a blank line. This deployment's `deploy-service.sh` logs that output verbatim on every
configuration change, so the block simply grew; anything grepping the first line is untouched. Worth
saying because it was not inevitable.

**Deployed and measured.** Pin moved `0.5.0` → `0.5.1` in one deploy. `user_version` stayed at **6**
(the counter-check to "nothing migrates"), `/v1/health` unchanged apart from what was expected, and
`--check-config` against the live configuration prints `surface: 2 of 3 entries on (ADR-20)` with
`honeypot_alert` as `off … not named by this configuration, and not in this binary`. On a
configuration naming nothing it lists all three as off **and exits zero** — which is right, and which
is why the monitoring responsibility stays where it was.

## 1. `Kind::as_str` did not replace the copy it was added to prevent

`surface.rs` gains `Kind::as_str` with this reasoning:

> Here rather than in whatever prints it, so a report on the host and a response on the wire cannot
> end up calling the same thing by two names.

**The response on the wire still has its own copy.** `SurfaceEntryResponse::from`
(`crates/ciphr-server/src/api.rs`, unchanged in this release) builds `kind` with its own
`match … { Kind::Build => "build", Kind::Runtime => "runtime" }`. So after this release there are two
hand-written spellings, and the new one is used only by `--check-config` — the comment describes the
state the change was meant to create rather than the one it created.

There is a third, latent: `Kind` derives `Serialize` with `#[serde(rename_all = "lowercase")]` and
`ActiveEntry` derives `Serialize`, but the only wire path is the hand-built response struct above.
Grepping the workspace, neither derive is reached. A serde attribute describing a wire format that no
wire uses is the dormant-flag shape `0.5.0` removed a check for: it looks like the thing that decides
the JSON, and it is not.

**Suggested:** `kind: active.kind.as_str()` in the `From` impl, and either drop the two `Serialize`
derives or make `Kind`'s serialize through `as_str` so the attribute cannot disagree with the
function. One line each, and then the comment is true.

## 2. The new gate bounds names, and `kind` is load-bearing

`ci/check-surface-entries.sh` compares the entry **names** in the two lists, and says plainly that it
does not compare cost text. That is a good gate with an honest scope. But the CLI's copy carries a
third field the gate does not check:

```rust
Known { name: "honeypot_alert", kind: "build", cost: "…" }
```

`kind` is what tells an operator whether a stanza can turn the entry on at all. A runtime entry that
is off can be turned on by editing the file; a build entry cannot, and needs a different artefact. If
the CLI's copy drifts — an entry that becomes a build entry upstream, or a new row typed as `runtime`
because that is what the row above says — then `surface show` prints `(runtime, not named by this
file)` for something no file can name into existence. That is precisely the distinction the server's
new report is careful to draw ("not named by this configuration, **and not in this binary**"), lost in
the interface an operator reaches first, because the host is where a configuration gets edited.

**Suggested:** compare the pairs, not the names. The extraction already reads both files; a second
`grep` for `kind:` and a comparison of `name kind` lines is a few lines more and closes the field that
changes meaning rather than wording.

**And a note on the route not taken.** The comment this release replaced said: *"if it grows, that is
the moment to move the list into `ciphr-core` as data rather than to copy it twice."* The list grew
from one row to three, and the response was a gate instead. **That is the right call, and the reason
deserves to be written down where the next reader looks:** `ci/check-core-no-features.sh` — which
arrived with `0.5.0`, after that comment — makes the core route unavailable. It fails on any
`surface::`, `mod surface` or `use …surface…` in `ciphr-crypto`, `ciphr-policy` or `ciphr-core`, and
ADR-20 property 1 means it in spirit as well as in regex: the reviewed core is not supposed to know
that entries exist. So the old plan was already illegal when its trigger fired.

What remains, if the duplication ever earns more than a gate: a data-only crate outside the reviewed
core that both sides depend on, or one shared source file `include!`d by both (no dependency edge, one
text). Both keep `compiled_in: cfg!(feature = "honeypot_alert")` where it belongs, in the crate that
has the feature. Neither is worth doing for three rows — but "we chose the gate because the core is
closed to this" is a sentence that belongs next to the gate.

## 3. The cost sentence became a decision input in two implementations

Before this release the CLI printed a cost sentence only beside entries a deployment had already
named — a decision already made. Now it prints it for the entries that are **off**, which is the
sentence somebody deciding reads. That was the ask, and it is the right change. It also moves the
copy that the gate deliberately does not check into the decision path.

The mitigation named in the code is that `GET /v1/surface` serves the sentence the server was built
with. True, and it is the right authority — but it needs a running service, a token and a network hop,
which is not the situation of somebody reading `surface show` on a host with the service stopped. The
two texts are each pinned by a test (`the_bulk_export_cost_does_not_claim_to_remove_fetched_prefixes`
in the CLI, `off_carries_the_cost_and_on_carries_the_record` in the server binary), and each test
asserts a **fragment**: nothing asserts that the two copies are the same string. A half-edited
sentence passes both.

**Suggested, in order of cost:** extend the gate to compare the cost text with whitespace normalized
(the two files wrap differently, which is why it was excluded — but `tr -s '[:space:]'` makes them
comparable); or accept the drift explicitly in the gate's header, naming the fragment tests as the
bound rather than `/v1/surface`, which an operator at the host cannot reach.

## Smaller notes

- **`surface: 2 of 3 entries on`** counts an entry this binary cannot have. The `off` line explains
  it two lines later, but the headline reads as though one more were available to switch on. `2 of 3
  entries on (1 not in this binary)` would settle it in the line people quote.
- **`wrap` measures bytes** (`line.len()`), so a cost sentence with any non-ASCII character wraps
  early. Every current sentence is ASCII and this is cosmetic — noting it because the sentences are
  prose and prose acquires an em dash eventually. It is also the second implementation of the same
  wrapping (`wrap` in the server binary, `wrap_cost` in the CLI); harmless, same shape as finding 2.
- **`surface show` splits its framing from its content.** `<file> turns nothing on. That is the
  ordinary configuration.` goes to stderr, and the off list goes to stdout. In the run captured here
  the framing line landed *after* the list it frames. Ordering between the two streams is not defined,
  so the fix is to pick one: print the context on stdout with the list, or print it last on purpose.
- **`--check-config`'s active line prints half the record.** The comment above it says *"The record
  each entry was named with, and not its cost"*; the line prints name, kind and `accepted`, and not
  the reason. Not asking for the reason — on a host the operator has the file open — but the comment
  should say `accepted` rather than "the record".
- **The gate's extraction is broad.** `names()` matches any indented `name: "…"` literal in either
  file, so an unrelated literal added to `ciphr-cli/src/main.rs` later would fail the gate for a
  reason its message does not describe. The failure is loud, so this is a footnote, not a finding.

## Done particularly well, since a review that only lists faults misreads the release

- **The corrected claim is pinned by asserting the old one is gone**, not merely that the new one is
  present (`!flattened.contains("has no fetched prefixes for bait to stay out of")`, with the message
  *"the claim the code does not support is back"*). That is the strongest available form for a
  correction, and it is what makes this class of defect non-recurring rather than fixed once.
- **`honeypots.md` puts the decision before the command.** Precondition 1 now carries the build line
  *and* the paragraph saying that making that artefact extends a risk acceptance written about
  reviewed code. The order matters: a runbook that gave the command first would have made the
  decision look like a step.
- **Both new gates state what they do not check**, and each says why in terms of what would break if
  they were wrong. The `check-core-no-features.sh` exclusion of prose is the model case, and the new
  scripts follow it.
- **The `0.5.1` upgrade note addresses the harm rather than the text.** "A deployment that turned
  `bulk_export` off *for that reason* has paid a real cost for a property it did not get" is the
  sentence a deployment needs, and it is followed by what to do rather than by an apology.

## What this review does not cover

`ciphr-crypto`, `ciphr-policy`, the store and its migrations, the honeypot code (absent from the
artefact this deployment runs, and marked as uncovered in `security-review.md` besides), the SDK
beyond reading the re-exported list against the signatures that need it, the fuzz targets, and every
CI gate other than the two added here. No claim is made about the security properties of anything, and
nothing here should be read as extending any review's coverage.

## Provenance

The `v0.5.0..v0.5.1` diff was read in full. The claims about `ciphr-run` and the SDK come from reading
`crates/ciphr-run/src/main.rs`, `crates/ciphr-run/src/error.rs` and `crates/ciphr-sdk/src/client.rs`,
not from running them. The claim that neither `Serialize` derive on `Kind`/`ActiveEntry` is reached
comes from grepping the workspace for `ActiveEntry` and for the wire construction, and would be worth
a compiler's opinion before acting on it. The measurements come from the published `0.5.1` image: one
run against this deployment's live configuration and one against a configuration naming no entry, both
through a throwaway store that was deleted afterwards. Nothing here rests on the changelog.
