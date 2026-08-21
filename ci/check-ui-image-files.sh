#!/bin/sh
# Gate: every tracked path in ui/ reaches a build stage of the viewer image.
#
# `ui/Dockerfile` copies named paths rather than the whole context, and that is
# the right default: it is why editing a component does not re-resolve the
# dependency tree, and why nothing that happens to be lying in the directory
# rides into the image. The cost is that adding a file to the package is two
# changes, and forgetting the second one fails silently.
#
# It did fail silently. `ui/public/favicon.svg` was committed, referenced by
# `index.html`, and listed in `ui/README.md`, and no image ever contained it: the
# COPY list did not name `public/`, and Vite skips a public directory it cannot
# find without saying so. The bundle built, type checked, carried its policy, and
# served a 404 for its own icon.
#
# Every gate passed while that was true, and the reason is the thing worth fixing
# rather than the favicon: CI builds from the whole tree and the image builds from
# the list, and nothing compared the two. The document-level checks in
# `.github/workflows/ci.yml` examine the built bundle because that is what a
# deployment serves -- but the bundle CI builds is not the bundle the image
# serves, so they cannot see this class at all.
#
# Hence the rule, which is static and costs milliseconds: a tracked top-level
# path under ui/ is either named by a COPY in `ui/Dockerfile`, or listed here as
# deliberately absent. A new directory the build reads fails this until one of the
# two is true.
set -eu

cd "$(dirname "$0")/.."

if [ ! -d ui ]; then
    echo "check-ui-image-files: no ui/ directory yet — nothing to check"
    exit 0
fi

if ! command -v git >/dev/null 2>&1; then
    echo >&2 "check-ui-image-files: git is needed to list the package, and it is not on PATH"
    exit 1
fi

dockerfile=ui/Dockerfile

# Paths that deliberately never enter a build stage, each for a reason a reader
# can check:
#
#   Dockerfile     the recipe, not an input to it
#   .dockerignore  read by the daemon to build the context, never copied into it
#   README.md      documentation for whoever builds the image, not for the image
#
# `nginx.conf` is deliberately not here: it *is* copied, into the second stage,
# and the check below finds it there. Adding a path to this list is a deliberate
# commit that says why, the same rule the dependency ceiling follows.
excluded='Dockerfile .dockerignore README.md'

# The COPY sources, one per line. `--from=` lines are skipped: their source is an
# earlier stage rather than the build context, so they say nothing about what the
# context has to contain. The destination is a COPY's last field, so every field
# before it is a source.
copied=$(
    grep -E '^COPY ' "$dockerfile" |
        grep -v -- '--from=' |
        sed 's/^COPY //' |
        awk '{ for (i = 1; i < NF; i++) print $i }'
)

# Top-level names only. What matters is whether a COPY reaches the path at all --
# a directory arrives whole, so checking every file inside it would report the
# same omission once per file.
paths=$(git -C ui ls-files | cut -d/ -f1 | sort -u)

status=0

for path in $paths; do
    case " $excluded " in
        *" $path "*) continue ;;
    esac

    # A directory may be written with or without its trailing slash, and both
    # mean the same thing to Docker.
    if printf '%s\n' "$copied" | grep -qxF "$path" ||
        printf '%s\n' "$copied" | grep -qxF "$path/"; then
        continue
    fi

    echo >&2 "check-ui-image-files: ui/$path is named by no COPY in $dockerfile"
    status=1
done

if [ "$status" -ne 0 ]; then
    cat >&2 <<'MSG'

check-ui-image-files: the viewer image would not contain a file the package has.

ui/Dockerfile copies named paths, so a new file or directory does not reach the
image until it is named there. The failure this prevents is not a broken build --
it is a bundle that builds, passes every other gate, and then 404s for something
its own document asks for.

Either name it in a COPY in ui/Dockerfile, or, if it genuinely belongs outside
the image, add it to `excluded` in this script with the reason.

MSG
    exit 1
fi

echo "check-ui-image-files: ok"
