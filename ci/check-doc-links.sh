#!/bin/sh
# Gate: a relative link in a Markdown file points at something that exists, and
# a link *text* that is written as a path points at the same thing.
#
# `check-doc-index.sh` asks whether a document is reachable from an index. This
# asks the question one level down: whether the links themselves still land.
# They are different failures with the same cause -- the tree moves and the prose
# does not -- and the second one is the quieter of the two, because a link that
# lands nowhere looks exactly like a link that works until somebody clicks it.
#
# ── The measurement ──────────────────────────────────────────────────────────
#
# Taken at `0b364ee`, the commit that added the index gate, and every one of
# these was made by the move that gate came with:
#
#   * **One target pointed at nothing.** `field-report-2026-08-23.md` moved from
#     `docs/` down to `docs/assurance/field-reports/`, two levels, and kept its
#     link to `../crates/ciphr-server/tests/restore.rs`. Ten other lines in that
#     same file were updated. This one was not, and nothing said so.
#   * **Eight link texts named a path that no longer existed.** The href was
#     rewritten to `../assurance/reviews/…` and the visible text was left at
#     `../review-…`. A reader sees a path that resolves to nothing; the click
#     works, so the mistake survives every reading that does not compare the two
#     halves of the link.
#
# Neither is catchable by reading a diff: the first is one unchanged line among
# ten changed ones, and the second *looks* like a correct link from either half
# alone.
#
# ── What is checked, and what deliberately is not ────────────────────────────
#
# **Relative targets only.** An `http(s)://` or `mailto:` link is somebody else's
# uptime, and a gate that fails the build because a third party reorganised their
# site is a gate people learn to skip. A bare `#fragment` is in-page and is not
# resolved either -- this checks that files exist, not that headings do.
#
# **A fragment on a relative target is stripped, not verified.**
# `upgrade.md#0110` has to name a file that exists; whether that file still has
# that heading is not asked, for the same reason the index gate does not ask
# whether the sentence beside a link is true.
#
# **A link text is checked only when it is written as a relative path** -- when
# it begins with `../` or `./`. That is the form that claims to be resolvable.
# The dominant style here is the basename, `[upgrade.md](docs/operations/upgrade.md)`,
# and that is not a path claim and is not touched: sixty-odd links are written
# that way on purpose, and failing them would make this gate a style rule
# wearing a correctness argument.
#
# **Code is quoted to be read, not followed.** A fenced block and an inline code
# span are removed before the line is scanned. This repository documents its own
# link conventions, so a page explaining what a broken link looks like would
# otherwise fail for containing the example -- `AGENTS.md` does exactly that, and
# a gate that cannot be written about is a gate that gets worked around.
#
# **Every Markdown file in the repository**, not only `docs/`. `README.md`,
# `AGENTS.md`, `SECURITY.md`, `CHANGELOG.md` and `site/README.md` link into the
# tree as much as anything under `docs/` does, and the changelog is the file most
# likely to point at something that has since moved.
#
# **Not `.claude/plans/`, `node_modules`, `target` or `ui/dist`.** The first is a
# specification with its own lifecycle; the rest are generated or vendored and
# are not this repository's prose.
#
# ── Resolution ───────────────────────────────────────────────────────────────
#
# `[ -e "$dir/$target" ]` and nothing cleverer. The kernel resolves `..` in the
# middle of a path, so no normaliser is needed, and this avoids `realpath
# --relative-to`, which is GNU coreutils -- the same reasoning
# `check-doc-index.sh` gives for doing its own prefix arithmetic. A gate that
# only runs on one distribution's userland is a gate somebody cannot reproduce
# locally.
set -eu

cd "$(dirname "$0")/.."

status=0
checked=0
failures=$(mktemp)
trap 'rm -f "$failures"' EXIT

files=$(find . -name '*.md' \
    -not -path './node_modules/*' \
    -not -path './*/node_modules/*' \
    -not -path './target/*' \
    -not -path './ui/dist/*' \
    -not -path './.git/*' \
    -not -path './.claude/*' |
    sed 's|^\./||' | sort)

for file in $files; do
    case "$file" in
        */*) dir="${file%/*}" ;;
        *) dir='.' ;;
    esac

    # One `line<TAB>[text](target)` per match.
    #
    # Fenced blocks and inline code spans are removed first, and that is not
    # tidiness: this repository documents its own link conventions, so a page
    # explaining what a *broken* link looks like would otherwise fail the gate
    # for containing the example. `AGENTS.md` does exactly that. Code is quoted
    # to be read, not followed.
    #
    # `[^][]*` for the text keeps a nested bracket from swallowing the rest of
    # the line, and `[^) \t]*` for the target is what makes a target with a space
    # in it simply not match -- which is correct, because Markdown does not
    # accept one either.
    awk '
        /^[ \t]*```/ { fenced = !fenced; next }
        fenced { next }
        {
            line = $0
            gsub(/`[^`]*`/, "", line)
            while (match(line, /\[[^][]*\]\([^) \t]*\)/)) {
                print NR "\t" substr(line, RSTART, RLENGTH)
                line = substr(line, RSTART + RLENGTH)
            }
        }
    ' "$file" 2>/dev/null | while IFS="$(printf '\t')" read -r number link; do

        text="${link%%](*}"
        text="${text#[}"
        target="${link##*](}"
        target="${target%)}"

        case "$target" in
            http://* | https://* | mailto:* | '#'*) continue ;;
        esac

        # A fragment is stripped: the file has to exist, the heading is not this
        # gate's business.
        path="${target%%#*}"
        [ -n "$path" ] || continue

        if [ ! -e "$dir/$path" ]; then
            echo "$file:$number: target does not exist: $target" >> "$failures"
        fi

        # A link text written as a relative path is a second claim about the
        # tree, and it is the half a rewrite forgets. Backticks are stripped
        # first: the text is often quoted as code.
        bare=$(printf '%s' "$text" | tr -d '`')
        case "$bare" in
            ../* | ./*)
                if [ ! -e "$dir/${bare%%#*}" ]; then
                    echo "$file:$number: link text names a path that does not exist: $bare (target is $target)" >> "$failures"
                fi
                ;;
        esac
    done

    checked=$((checked + 1))
done

if [ -s "$failures" ]; then
    sort -u "$failures" >&2
    echo >&2
    echo "check-doc-links: a link points at something that is not there." >&2
    echo "A moved file needs its links moved with it -- including the text, where the text is a path." >&2
    status=1
fi

if [ "$status" -eq 0 ]; then
    echo "check-doc-links: ok ($checked files, every relative link resolves)"
fi

exit "$status"
