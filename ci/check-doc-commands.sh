#!/bin/sh
# Gate: a command a document tells someone to run exists.
#
# `docs/README.md` promises that "operational procedures name exact commands and
# exact file paths, and say which of them do not exist yet". Every other
# documentation discipline here is enforced by a script; that one was left to
# habit, and it is the sentence this gate turns into a check.
#
# It exists because of a measured failure rather than a hypothetical one. ADR-7
# said "backup is `VACUUM INTO` plus an existing file-backup job" for three
# releases while no subcommand did it and the runtime image had no `sqlite3`, so
# a deployment following the record reached for `cp` -- which on a live
# write-ahead-logged database is the one backup mistake with no error attached to
# it. A gate cannot judge a prose claim about a capability, and this one does not
# pretend to. What it can do is refuse the narrower and more common version: a
# document handing somebody a command line for a command that is not there.
#
# ── What is checked, and what deliberately is not ────────────────────────────
#
# **Only inside fenced code blocks.** Prose says "ciphr is a secret manager" and
# "ciphr keeps its own trail", and a scan over prose finds `is` and `keeps` as
# subcommands. Measured over this repository the prose version produced 28
# candidates of which 0 were real; restricted to code fences it produced 2, both
# genuine and both explainable. That ratio is the whole reason for the
# restriction: a gate that cries wolf gets worked around rather than obeyed.
#
# **Only the first word after `ciphr`.** `ciphr audit verifyy` passes this gate.
# Validating nested subcommands means teaching a shell script clap's tree, and
# the failure it would catch is a typo inside a command that exists -- which is
# visible the first time anybody runs the line. The failure this catches is a
# command that never existed, which is invisible until an incident.
#
# **Nothing about flags, arguments, or whether the line would work.** `ciphr get
# --nonsense` passes. This asks one question: does the subcommand exist.
#
# **ADRs are exempt**, on the same reasoning `ci/check-doc-dates.sh` uses for
# them. An ADR records a proposal as it was made -- ADR-14 writes `ciphr run` in
# its own code block and then says twelve lines later that the built thing is a
# binary named `ciphr-run`. Rewriting the proposal would falsify the record.
#
# ── The allowlist ────────────────────────────────────────────────────────────
#
# A document may name a command that does not exist when it says so. The
# allowlist below is how it declares that, with a reason, per document -- the
# same shape as the `Changelog-Exempt:` and `Docs-Date-Exempt:` trailers, and
# for the same reason: an opt-out that costs nothing to write is not a gate.
set -eu

cd "$(dirname "$0")/.."

cli='crates/ciphr-cli/src/main.rs'

# Documents whose unbuilt commands are declared as unbuilt in the document
# itself. One line per pair, `<file> <command> # <reason>`.
allowed=$(cat <<'LIST'
docs/operations/freeze.md lockdown # ADR-15's freeze tier is not built; the page says so in its third line
LIST
)

# ── The real subcommands ─────────────────────────────────────────────────────
# From the `Command` enum rather than from `--help`, so this runs without a
# build. `check-surface-entries.sh` reads Rust source for the same reason.
# CamelCase becomes the kebab-case clap derives.
real=$(awk '
    /^enum Command \{/ { inside = 1; next }
    inside && /^\}/     { exit }
    inside && /^    [A-Z][A-Za-z]*( *\{|,|\()/ {
        name = $1
        sub(/[({,].*$/, "", name)
        print name
    }
' "$cli" | sed -E 's/([a-z0-9])([A-Z])/\1-\2/g' | tr '[:upper:]' '[:lower:]' | sort -u)

if [ -z "$real" ]; then
    echo "check-doc-commands: found no subcommands in $cli; the enum shape changed" >&2
    exit 1
fi

# ── What the documents tell people to run ────────────────────────────────────
# The first non-flag word after `ciphr`. Global options all take a value, so a
# token starting with `-` skips itself and the token after it.
status=0

for doc in $(find docs README.md -name '*.md' | grep -v '^docs/adr/' | sort); do
    claims=$(awk '
        /^```/ { fence = !fence; next }
        !fence { next }
        {
            for (i = 1; i <= NF; i++) {
                if ($i != "ciphr") continue
                for (j = i + 1; j <= NF; j++) {
                    if (substr($j, 1, 1) == "-") { j++; continue }
                    print $j
                    break
                }
                break
            }
        }
    ' "$doc" | tr -d '`",;)' | grep -E '^[a-z][a-z-]*$' | sort -u || true)

    for claim in $claims; do
        if echo "$real" | grep -qxF "$claim"; then
            continue
        fi
        if echo "$allowed" | grep -q "^$doc $claim "; then
            continue
        fi
        echo "check-doc-commands: $doc names \`ciphr $claim\`, which is not a subcommand" >&2
        status=1
    done
done

if [ "$status" -ne 0 ]; then
    cat >&2 <<'MSG'

check-doc-commands: a document hands somebody a command that does not exist.

An operational procedure naming a command nobody can run is worse than no
procedure: it is followed, it fails, and the failure happens during whatever
made somebody open the document.

Either the command should exist, or the document should say that it does not.
If the document already says so, add it to the allowlist in this script with a
reason -- the reason is what a later reader needs, and it is the only thing
that distinguishes a declared gap from an oversight.

MSG
    exit 1
fi

echo "check-doc-commands: ok ($(echo "$real" | wc -l | tr -d ' ') subcommands)"
