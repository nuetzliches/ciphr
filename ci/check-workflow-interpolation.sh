#!/bin/sh
# Gate: no workflow expression is substituted into a shell script.
#
# F1 of `docs/assurance/reviews/review-2026-08-24-full-repository.md`. A `${{ … }}` inside a `run:`
# block is not an argument and not a variable -- the expression is substituted
# into the script *before* the shell sees it, so its value becomes program text.
# Quoting it with shell quotes is not escaping: a value containing an apostrophe
# closes the quote and everything after it is syntax.
#
# The values that matter here are ref names, which whoever can create a tag
# chooses. Git accepts `'`, `;` and `$(…)` in a ref name -- the review confirmed
# that with `git check-ref-format` rather than assuming it. The jobs those refs
# reach hold package-write credentials, so a repository writer who cannot
# otherwise publish anything gets to run commands in a job that can.
#
# The fix at each site is the same: put the value in `env:` and read it as a
# shell variable. Then the shell receives data, and no value can become syntax.
#
# ── What is checked ──────────────────────────────────────────────────────────
#
# Every `${{` that appears inside a `run:` block scalar, in any workflow. Not
# just the attacker-controlled ones: `matrix.target` and `github.repository` are
# fixed by the workflow and the repository, and a gate that had to judge which
# expressions are safe would be a gate arguing with itself on every change. The
# rule is mechanical because it can be, and `env:` costs two lines.
#
# Expressions outside `run:` -- in `with:`, `env:`, `if:`, `name:` -- are fine
# and are the point: that is where a value goes to become data.
set -eu

cd "$(dirname "$0")/.."

found=$(
    for file in .github/workflows/*.yml .forgejo/workflows/*.yml; do
        [ -f "$file" ] || continue
        awk -v file="$file" '
            # A one-line `run:` is a script too, and the shorter form is the one
            # that looks harmless. Checked before the block-scalar case, because
            # `run: |` also matches "run: followed by something".
            /^[[:space:]]*run:[[:space:]]*[^|>[:space:]]/ {
                if (index($0, "${{") > 0) {
                    line = $0
                    sub(/^[[:space:]]+/, "", line)
                    print file ":" NR ": " line
                }
                inside = 0
                next
            }
            # `run: |` (or `>`) opens a block scalar. Everything indented deeper
            # than the key belongs to it.
            /^[[:space:]]*run:[[:space:]]*[|>]/ {
                inside = 1
                match($0, /^[[:space:]]*/)
                indent = RLENGTH
                next
            }
            inside {
                line = $0
                # A blank line inside a block scalar stays inside it.
                if (line ~ /^[[:space:]]*$/) next
                match(line, /^[[:space:]]*/)
                if (RLENGTH <= indent) { inside = 0; next }
                if (index(line, "${{") > 0) {
                    sub(/^[[:space:]]+/, "", line)
                    print file ":" NR ": " line
                }
            }
        ' "$file"
    done
)

if [ -n "$found" ]; then
    echo "check-workflow-interpolation: a workflow expression is substituted into a shell script." >&2
    echo >&2
    echo "$found" >&2
    cat >&2 <<'MSG'

Move the value into the step's `env:` and read it as a shell variable:

    - name: …
      env:
        REF: ${{ github.ref }}
      run: |
        case "$REF" in …

A `${{ … }}` inside `run:` is substituted before the shell parses the script, so
the value becomes program text. Shell quotes do not escape it -- a ref name may
contain an apostrophe, and Git allows one.
MSG
    exit 1
fi

echo "check-workflow-interpolation: ok (no expression reaches a shell script)"
