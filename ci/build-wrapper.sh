#!/bin/sh
# Build `ciphr-run` as a static binary and hold it to a size budget.
#
# This is the artefact route B mounts (ADR-14): one file, bind-mounted into an
# image this project does not own, with `entrypoint:` overridden. Two properties
# have to hold for that to work at all, and neither is checked by `cargo build`
# succeeding:
#
#   * It has to be *statically* linked. Bind-mounting a binary into a foreign
#     image only works if it needs nothing from that image -- no libc, no
#     loader. `ldd` saying "statically linked" is the check; the musl target
#     gives it, and this script verifies rather than assumes.
#
#   * It has to stay small enough that mounting it is uncontroversial. The
#     budget is not a performance concern. It is a review trigger: a binary that
#     doubles has acquired a dependency, and this is where that gets noticed
#     instead of during a deploy.
#
# Measured on 2026-08-20 with the pinned toolchain: 3,347,368 bytes stripped.
# The budget below is set at roughly 1.5x that, so ordinary growth passes and a
# new dependency of any size does not.
set -eu

cd "$(dirname "$0")/.."

TARGET=x86_64-unknown-linux-musl
BUDGET=5242880 # 5 MiB
OUT=${1:-target/wrapper}

if ! rustup target list --installed | grep -qx "$TARGET"; then
    echo "build-wrapper: adding the $TARGET target" >&2
    rustup target add "$TARGET"
fi

cargo build --release --locked -p ciphr-run --target "$TARGET"

built="target/$TARGET/release/ciphr-run"
mkdir -p "$OUT"
binary="$OUT/ciphr-run"

# Stripped, because this is the file a deployment mounts and the symbols buy a
# reader of a core dump nothing that the debug build does not.
strip "$built" -o "$binary"

size=$(wc -c < "$binary" | tr -d ' ')

# `ldd` on a static binary reports it as such rather than failing, so the string
# is the check. `file` is not used: its wording varies between versions.
linkage=$(ldd "$binary" 2>&1 || true)
case "$linkage" in
*"statically linked"* | *"not a dynamic executable"*) ;;
*)
    echo "build-wrapper: $binary is not statically linked:" >&2
    echo "$linkage" >&2
    exit 1
    ;;
esac

if [ "$size" -gt "$BUDGET" ]; then
    echo "build-wrapper: $binary is $size bytes, over the budget of $BUDGET" >&2
    echo "build-wrapper: a jump this size is a new dependency; decide on it rather than raising the number" >&2
    exit 1
fi

# The checksum belongs next to the binary, because a deployment that fetches one
# file has no other way to know it got the right one.
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$OUT" && sha256sum ciphr-run > ciphr-run.sha256)
fi

echo "build-wrapper: ok -- $size bytes, statically linked, budget $BUDGET"
