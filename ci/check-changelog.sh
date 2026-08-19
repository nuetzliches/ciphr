#!/bin/sh
# Gate: a commit that changes shipped code also changes the changelog.
#
# CHANGELOG.md says of itself that it "is updated in the same commit as the
# change it describes". That rule held through three phases and then quietly did
# not: 0f711ce fixed a real defect -- `init` ignored `--audit-file`, so the first
# record of every chain reached one device only -- and left no trace in the
# changelog. The one sentence an operator needs from that fix, that stores which
# are already initialized keep the gap, existed only in a commit body.
#
# Every other documentation discipline here is enforced by a script. This one was
# the exception, and it is the one that eroded. That is the whole argument.
#
# What counts as shipped code is `crates/` and nothing else. Deployment files,
# CI, and documentation are deliberately outside it: a changelog that records
# every comment fix is one nobody reads, and a gate that fires on noise gets
# worked around rather than obeyed. Widening the trigger is a one-line change
# below, and should be a deliberate one.
#
# Opting out is per commit, with a trailer that states a reason:
#
#     Changelog-Exempt: pure refactor, no observable behaviour
#
# The reason is mandatory and the gate only checks that one is present -- it
# cannot judge whether it is a good one, and a human reading the history can.
# An opt-out that costs nothing to write is not a gate.
#
# Usage:
#   sh ci/check-changelog.sh                 # the commit at HEAD
#   sh ci/check-changelog.sh <base> <head>   # every commit in base..head
#   sh ci/check-changelog.sh <base>..<head>  # the same range, one argument
#
# Merge commits are skipped: they introduce no change of their own, and the
# commits they bring in are checked on their own terms.
set -eu

cd "$(dirname "$0")/.."

# The paths whose change requires a changelog entry.
shipped='crates/'
changelog='CHANGELOG.md'

case $# in
    0) base=''; head='HEAD' ;;
    1) case "$1" in
           *..*) base=${1%%..*}; head=${1#*..} ;;
           *)    base=''; head="$1" ;;
       esac ;;
    2) base="$1"; head="$2" ;;
    *) echo "check-changelog: usage: $0 [<base> [<head>] | <base>..<head>]" >&2
       exit 2 ;;
esac

[ -n "$head" ] || head='HEAD'

# A base of all zeros is how a forge spells "there was nothing here before" -- a
# new branch, or the first push. A base that is not a commit we have means the
# clone is too shallow to read the range. Neither is a reason to fail: check the
# head commit and say which of the two happened, so a passing run is not mistaken
# for a range that was actually examined.
if [ -n "$base" ]; then
    case "$base" in
        *[!0]*) ;;
        *) echo "check-changelog: no previous commit for this ref; checking $head alone"
           base='' ;;
    esac
fi

if [ -n "$base" ] && ! git rev-parse --verify --quiet "$base^{commit}" >/dev/null; then
    echo "check-changelog: $base is not in this clone (shallow?); checking $head alone" >&2
    base=''
fi

if [ -n "$base" ]; then
    commits=$(git rev-list --no-merges "$base".."$head")
else
    commits=$(git rev-list --no-merges -1 "$head")
fi

if [ -z "$commits" ]; then
    echo "check-changelog: no commits to check"
    exit 0
fi

status=0

for commit in $commits; do
    files=$(git show --name-only --format='' "$commit")

    echo "$files" | grep -q "^$shipped" || continue
    echo "$files" | grep -qxF "$changelog" && continue

    # A trailer with something after the colon. `git show -s --format=%B` gives
    # the raw message, so this sees the trailer exactly as it was written.
    if git show -s --format='%B' "$commit" |
        grep -qiE '^Changelog-Exempt:[[:space:]]*[^[:space:]]'; then
        continue
    fi

    subject=$(git show -s --format='%h %s' "$commit")
    echo "check-changelog: $subject" >&2
    echo "    changes $shipped and does not touch $changelog" >&2
    status=1
done

if [ "$status" -ne 0 ]; then
    cat >&2 <<'MSG'

check-changelog: shipped code changed without a changelog entry.

CHANGELOG.md is updated in the same commit as the change it describes. An entry
that trails its change by a commit is a window in which the changelog is wrong,
and an entry written later is written by someone reconstructing what happened.

Write the entry under [Unreleased] and amend it into the commit. Say what an
operator has to do about it -- an upgrade note that exists only in a commit body
is one nobody reads.

If the change genuinely has no observable effect, say so in the commit message:

    Changelog-Exempt: <reason>

MSG
    exit 1
fi

echo "check-changelog: ok"
