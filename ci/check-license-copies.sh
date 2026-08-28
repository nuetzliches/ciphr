#!/bin/sh
# Gate: the viewer's copies of the licence texts are the licence texts.
#
# `LICENSE-MIT` and `LICENSE-APACHE` exist twice in this repository, at the root
# and under `ui/`, and the duplication is not an accident to clean up later. The
# viewer image is built with `ui/` as its whole context -- "it has no business
# being able to see the crates", `release-ui.yml` -- so a file outside that
# directory cannot enter that image. The image has to carry the terms it is
# distributed under, which leaves exactly two options: widen the context, or keep
# a copy. Widening it to reach two text files would give the viewer's build
# reach over the entire source tree, which is a strictly worse trade.
#
# What a copy costs is that it can drift, and a drifted licence text is a
# deployment holding an image whose stated terms are not this project's terms.
# Nobody edits a licence text on purpose, which is exactly why nobody would
# notice: the plausible way this breaks is a search-and-replace across the tree,
# or one of the two files being updated when the project's licensing changes.
#
# So: byte for byte, or this fails. It costs two `cmp` calls.
set -eu

cd "$(dirname "$0")/.."

if [ ! -d ui ]; then
    echo "check-license-copies: no ui/ directory yet — nothing to check"
    exit 0
fi

status=0

for name in LICENSE-MIT LICENSE-APACHE; do
    if [ ! -f "$name" ]; then
        echo >&2 "check-license-copies: $name is missing from the root of the repository"
        status=1
        continue
    fi
    if [ ! -f "ui/$name" ]; then
        echo >&2 "check-license-copies: ui/$name is missing, so the viewer image would ship without it"
        status=1
        continue
    fi
    if ! cmp -s "$name" "ui/$name"; then
        echo >&2 "check-license-copies: ui/$name differs from $name"
        status=1
    fi
done

if [ "$status" -ne 0 ]; then
    cat >&2 <<'MSG'

check-license-copies: the viewer ships a licence text this project does not have.

`ui/` is the whole build context of the viewer image, so it keeps its own copy of
each licence text. The two copies have to be identical, because what an image
states about its own terms is not a place for a near-miss.

To fix: `cp LICENSE-MIT ui/LICENSE-MIT` and the same for LICENSE-APACHE. If the
project's licensing is what changed, both copies move in the same commit.

MSG
    exit 1
fi

echo "check-license-copies: ok (LICENSE-MIT, LICENSE-APACHE)"
