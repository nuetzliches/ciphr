#!/bin/sh
# Gate: every document under `docs/` and `.claude/plans/` carries a date, and no
# date is in the future.
#
# `.claude/plans/` is here because leaving it out cost something measurable.
# `PLAN.md` is the full specification, amended twenty-two times across four
# releases, and its status line read "Draft. No code written yet." throughout --
# for three days after the release that made it four. Nothing caught it, because
# the two documentation gates scanned `docs/` and a specification does not live
# there. A gate whose scope is the directory rather than the claim tells the
# reader that the claim is only checked in some places.
#
# Documentation decays quietly, and a secret manager whose manual is wrong
# produces confident mistakes. This cannot check whether a document is accurate.
# What it can check is that a reader is able to *question* it: an undated document
# offers no way to judge whether it describes the current system.
#
# A future date fails too. It is the signature of a copy-pasted header or an
# intention to update later, and both make the date worse than none.
set -eu

cd "$(dirname "$0")/.."

today=$(date -u +%Y-%m-%d)
status=0

# Two roots rather than a wider pattern: everything under `.claude/` is not
# documentation -- only the plans are -- and a repository-wide sweep would pull
# in whatever tooling puts there next.
for doc in $(find docs .claude/plans -name '*.md' | sort); do
    dates=$(grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' "$doc" || true)

    if [ -z "$dates" ]; then
        echo "check-docs: $doc carries no date (YYYY-MM-DD)" >&2
        status=1
        continue
    fi

    for date in $dates; do
        # Compared as numbers rather than as strings: POSIX `test` has no defined
        # lexicographical operator, and an ISO date with its dashes removed is an
        # integer that sorts the same way the date does. That is most of the
        # reason to insist on the format.
        if [ "$(echo "$date" | tr -d '-')" -gt "$(echo "$today" | tr -d '-')" ]; then
            echo "check-docs: $doc claims the future date $date (today is $today)" >&2
            status=1
        fi
    done
done

if [ "$status" -eq 0 ]; then
    echo "check-docs: ok"
fi
exit "$status"
