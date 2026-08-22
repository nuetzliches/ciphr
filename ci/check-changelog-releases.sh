#!/bin/sh
# Gate: the released version has a section in the changelog, and every section
# has a link.
#
# `15191e1` deleted the line `## [0.5.1] — 2026-08-21` while inserting its own
# entries at that position. Nothing complained: `cargo fmt`, `clippy`, the tests
# and every other gate here are indifferent to a markdown heading, and
# `check-changelog.sh` only asks whether the file was touched at all. The result
# was a tree whose `Cargo.toml` said `0.5.1` while its changelog's newest release
# was `0.5.0` -- so everything `0.5.1` shipped sat under `[Unreleased]`, and the
# next release heading would have claimed it. The link section had the same hole
# from the other side: `[0.5.1]` was never defined, and `[Unreleased]` still
# compared against `v0.5.0`.
#
# The invariant is checkable because it holds in both states this repository is
# ever in, and needs neither a tag nor a network:
#
#   * between releases, `Cargo.toml` carries the last released version, and that
#     version's section exists;
#   * in a release commit, `Cargo.toml` carries the new version, and the release
#     commit is exactly the one that adds that section.
#
# So: the workspace version has a section, it is the newest section, every
# section has a link definition and every link definition has a section, and
# `[Unreleased]` compares from the newest released version. A heading deleted by
# accident fails the first rule; the link half of the same accident fails the
# third and fourth.
#
# What this does not check, deliberately:
#
#   * whether the entries under a heading describe what that version shipped.
#     That is what a reader is for, and no script can judge it.
#   * whether a section's date is the day the tag was pushed. `check-docs.sh`
#     makes that argument about documents; a changelog date that is a day off is
#     not the failure this exists to prevent.
#   * git tags. CI checks out at a depth that may not have them, and a gate that
#     passes because it found nothing to compare is worse than no gate.
#
# Usage:
#   sh ci/check-changelog-releases.sh
set -eu

cd "$(dirname "$0")/.."

changelog='CHANGELOG.md'
manifest='Cargo.toml'

# The workspace version, from `[workspace.package]`. Anchored on the section so
# a dependency's `version = "…"` further down cannot be read as the product's.
version=$(awk '
    /^\[workspace\.package\]$/ { in_section = 1; next }
    /^\[/                      { in_section = 0 }
    in_section && /^version[[:space:]]*=/ {
        gsub(/^version[[:space:]]*=[[:space:]]*"|"[[:space:]]*$/, "")
        print
        exit
    }
' "$manifest")

if [ -z "$version" ]; then
    echo "check-changelog-releases: no [workspace.package] version in $manifest" >&2
    exit 1
fi

# The release headings, newest first, in the order they appear.
headings=$(sed -n 's/^## \[\([0-9][0-9.]*\)\].*/\1/p' "$changelog")

if [ -z "$headings" ]; then
    echo "check-changelog-releases: $changelog has no release headings" >&2
    exit 1
fi

newest=$(echo "$headings" | sed -n '1p')
status=0

if ! echo "$headings" | grep -qxF "$version"; then
    echo "check-changelog-releases: $manifest says $version, and $changelog has no '## [$version]' section" >&2
    status=1
elif [ "$newest" != "$version" ]; then
    echo "check-changelog-releases: $changelog's newest section is $newest, but $manifest says $version" >&2
    status=1
fi

# Every heading needs a link definition, and every definition a heading. The
# two directions catch different accidents: a deleted heading whose link
# survived, and a release that never got its compare link.
links=$(sed -n 's/^\[\([0-9][0-9.]*\)\]:.*/\1/p' "$changelog")

for release in $headings; do
    echo "$links" | grep -qxF "$release" && continue
    echo "check-changelog-releases: '## [$release]' has no '[$release]: …' link definition" >&2
    status=1
done

for link in $links; do
    echo "$headings" | grep -qxF "$link" && continue
    echo "check-changelog-releases: '[$link]: …' defines a link to a section that does not exist" >&2
    status=1
done

# `[Unreleased]` compares from the newest release. When that is stale it points
# at a diff a reader takes for "everything not yet released" and gets one
# release too much -- which is how the deleted heading stayed invisible.
unreleased=$(sed -n 's/^\[Unreleased\]:.*compare\/v\([0-9][0-9.]*\)\.\.\..*/\1/p' "$changelog")

if [ -z "$unreleased" ]; then
    echo "check-changelog-releases: no '[Unreleased]: …compare/v<version>...' link in $changelog" >&2
    status=1
elif [ "$unreleased" != "$newest" ]; then
    echo "check-changelog-releases: [Unreleased] compares from v$unreleased, but the newest release is $newest" >&2
    status=1
fi

if [ "$status" -ne 0 ]; then
    cat >&2 <<'MSG'

check-changelog-releases: the changelog cannot say what a released version shipped.

A version with no section of its own leaves its entries under [Unreleased],
where the next release heading will claim them -- and the commit body becomes
the only record of what an operator actually received. That is the state this
gate exists to make impossible, because nothing else here notices a heading.

A release commit changes four things together: the version in Cargo.toml, the
[Unreleased] heading becoming the new version's, a fresh empty [Unreleased]
above it, and the link section at the bottom.

MSG
    exit 1
fi

count=$(echo "$headings" | wc -l | tr -d ' ')
if [ "$count" = 1 ]; then
    noun='release'
else
    noun='releases'
fi

echo "check-changelog-releases: ok ($version is newest, $count $noun, links complete)"
