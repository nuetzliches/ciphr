#!/bin/sh
# Gate: a document that changed says so in its own status line.
#
# `check-docs.sh` asks whether a date exists and whether it is in the future.
# Neither question catches the failure that actually happens: a document is
# edited, its content moves, and the date at the top stays where it was. The
# reader is then told the page is current as of a day on which it did not yet say
# what it says.
#
# That is not hypothetical here. `docs/threat-model.md` and `docs/README.md` were
# both edited on 2026-08-20 while claiming to be current as of 2026-08-19, and
# `docs/operations/audit-trail.md` once gained forty lines without its date
# moving. Measured over v0.1.0..HEAD before this gate was written, the rule below
# would have fired ten times, every one of them on a real change.
#
# ── What is checked, and what deliberately is not ────────────────────────────
#
# **Only documents with a `**Status:**` line.** That line means "current as of",
# which is a claim that ages. ADRs are excluded for the opposite reason: their
# date records when a decision was made, and amending the record later does not
# move the decision. A gate that demanded otherwise would be asking authors to
# falsify history.
#
# **Only changes of more than SMALL lines.** Adding a row to an index does not
# invalidate a status date, and the four times this rule would have fired on such
# a change are the four smallest in the measurement above -- the separation
# between noise and substance was clean at three lines, so that is where it sits.
# Like the wrapper's size budget, the number is a trigger and not a judgement
# about meaning. The opt-out below is for everything it gets wrong.
#
# **Nothing about accuracy.** A document can carry today's date and be wrong.
# What this makes impossible is the specific case where the document itself
# records that it was edited after the day it claims to describe.
#
# ── Opting out ───────────────────────────────────────────────────────────────
#
# Per commit, with a trailer that states a reason:
#
#     Docs-Date-Exempt: cross-reference only, the described system is unchanged
#
# The reason is mandatory and this script only checks that one is present -- it
# cannot judge whether it is a good one, and a human reading the history can. An
# opt-out that costs nothing to write is not a gate. This mirrors
# `Changelog-Exempt:` exactly, because a second convention for the same idea is
# one more thing to remember.
#
# Usage:
#   sh ci/check-doc-dates.sh                 # the commit at HEAD
#   sh ci/check-doc-dates.sh <base> <head>   # every commit in base..head
#   sh ci/check-doc-dates.sh <base>..<head>  # the same range, one argument
set -eu

cd "$(dirname "$0")/.."

# Changes at or below this many lines (added plus removed) are not held to the
# rule. See the header for where the number comes from.
SMALL=3

case $# in
    0) base=''; head='HEAD' ;;
    1) case "$1" in
           *..*) base=${1%%..*}; head=${1#*..} ;;
           *)    base=''; head="$1" ;;
       esac ;;
    2) base="$1"; head="$2" ;;
    *) echo "check-doc-dates: usage: $0 [<base> [<head>] | <base>..<head>]" >&2
       exit 2 ;;
esac

[ -n "$head" ] || head='HEAD'

# A base of all zeros is how a forge spells "there was nothing here before". A
# base that is not in this clone means it is too shallow to read the range.
# Neither is a reason to fail, and both are worth saying out loud so that a
# passing run is not mistaken for a range that was examined.
if [ -n "$base" ]; then
    case "$base" in
        *[!0]*) ;;
        *) echo "check-doc-dates: no previous commit for this ref; checking $head alone"
           base='' ;;
    esac
fi

if [ -n "$base" ] && ! git rev-parse --verify --quiet "$base^{commit}" >/dev/null; then
    echo "check-doc-dates: $base is not in this clone (shallow?); checking $head alone" >&2
    base=''
fi

if [ -n "$base" ]; then
    commits=$(git rev-list --no-merges "$base".."$head")
else
    commits=$(git rev-list --no-merges -1 "$head")
fi

if [ -z "$commits" ]; then
    echo "check-doc-dates: no commits to check"
    exit 0
fi

status=0

for commit in $commits; do
    # A trailer with something after the colon exempts the whole commit.
    if git show -s --format='%B' "$commit" |
        grep -qiE '^Docs-Date-Exempt:[[:space:]]*[^[:space:]]'; then
        continue
    fi

    committed=$(git show -s --format=%ad --date=short "$commit")

    for file in $(git show --name-only --format='' "$commit" |
                      grep '^docs/.*\.md$' |
                      grep -v '^docs/adr/' || true); do
        # Deleted in this commit, or not a document with a status line.
        # The newest date on the line, not the first. A status line legitimately
        # carries two -- "implemented as of X, re-read against the code on Y" --
        # and the claim it makes about currency is the later one. Taking the
        # first would fail exactly the documents whose authors were most precise
        # about what they had checked and when. ISO dates sort chronologically,
        # which is the third reason this format is insisted on.
        claimed=$(git show "$commit:$file" 2>/dev/null |
                      grep -m1 '^\*\*Status:' |
                      grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' |
                      sort |
                      tail -1 || true)
        [ -n "$claimed" ] || continue

        changed=$(git show --numstat --format='' "$commit" -- "$file" |
                      awk '{ print $1 + $2 }')
        # A rename or a binary line reports `-`; treat anything unparseable as
        # small rather than failing on it.
        case "$changed" in
            ''|*[!0-9]*) continue ;;
        esac
        [ "$changed" -gt "$SMALL" ] || continue

        # Compared as numbers rather than as strings: POSIX `test` has no defined
        # lexicographical operator, and an ISO date with its dashes removed is an
        # integer that sorts the same way the date does. That is most of the
        # reason to insist on the format.
        if [ "$(echo "$claimed" | tr -d '-')" -lt "$(echo "$committed" | tr -d '-')" ]; then
            echo "check-doc-dates: $(git show -s --format='%h %s' "$commit")" >&2
            echo "    $file changed by $changed lines and still says $claimed" >&2
            echo "    (that commit is dated $committed)" >&2
            status=1
        fi
    done
done

if [ "$status" -ne 0 ]; then
    cat >&2 <<'MSG'

check-doc-dates: a document changed without its status line moving.

The line says "current as of <date>", which is a claim about when the document
last described the system. A reader who cannot trust it has no way to judge
whether the page is worth believing, and an out-of-date date is worse than none
because it looks like an answer.

Move the date in the `**Status:**` line, in the same commit as the change.

If the change genuinely does not affect what the document describes -- a fixed
link, a cross-reference, a typo -- say so in the commit message:

    Docs-Date-Exempt: <reason>

MSG
    exit 1
fi

echo "check-doc-dates: ok"
