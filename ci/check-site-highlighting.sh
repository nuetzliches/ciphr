#!/bin/sh
# Gate: the code blocks in `site/` are what the highlighter produces.
#
# The colouring on those pages is generated, and the generated markup is in the
# tree rather than in a build output. That is deliberate: `pages.yml` uploads
# `site/` exactly as it is, three of the four pages run no script at all, and
# `site/README.md` makes that a claim about the project rather than an
# implementation detail. A highlighter running in the reader's browser would
# spend the one property those pages exist to demonstrate on colouring text that
# never changes.
#
# What that trade costs is the thing this gate pays for. Generated markup sitting
# in the tree can be edited by hand, and it goes stale the moment somebody
# changes an example and does not re-run the tool. Both failures are silent and
# neither is visible in a diff — a reviewer reading `<span class="t-key">` cannot
# tell whether it is what the mapping would produce.
#
# So the tool is idempotent and this runs it with `--check`: it regenerates every
# block from the plain code inside it and fails if the result differs from what
# is committed. The same run also fails on a `<pre>` that names no language, on a
# language the mapping does not know, and — the one that matters most — on any
# block whose tokens do not reassemble into the exact text they came from. A
# reader copies these blocks into a terminal.
#
# `ci/site-highlight` is a separate package for the reason `ui/` is one: it has
# its own toolchain and its own dependency budget, and it must not end up inside
# `site/`, because `pages.yml` would publish `node_modules` with the pages.
set -eu

cd "$(dirname "$0")/.."

if [ ! -d site ]; then
    echo "check-site-highlighting: no site/ directory — nothing to check"
    exit 0
fi

if ! command -v node >/dev/null 2>&1; then
    echo >&2 "check-site-highlighting: node runs the highlighter, and it is not on PATH"
    exit 1
fi

# Not installed is a different failure from stale, and saying so is the
# difference between a one-line fix and reading this script.
if [ ! -d ci/site-highlight/node_modules ]; then
    echo >&2 "check-site-highlighting: ci/site-highlight has no node_modules."
    echo >&2 "Run: cd ci/site-highlight && npm ci --ignore-scripts"
    exit 1
fi

node ci/site-highlight/highlight.mjs --check
