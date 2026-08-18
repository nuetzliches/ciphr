#!/bin/sh
# Entrypoint for the ciphr container.
#
# Runs as root just long enough to do two things the process itself cannot, then
# drops to the unprivileged user. Everything after `gosu` holds plaintext
# secrets and key material, and none of it needs root.
set -eu

# ── No core dumps ────────────────────────────────────────────────────────────
# A core dump of this process contains the master key, the root key, and every
# value that was in flight. `ZeroizeOnDrop` wipes memory the process is finished
# with; it cannot help with a snapshot taken while the process is alive. Plan
# section 3 lists this among the leaks that are defended against, and this is
# where that defence is applied.
#
# Set here rather than in the container definition because a limit belongs with
# the process it protects: a deployment that forgets a `ulimits:` entry would
# otherwise silently lose the protection.
ulimit -c 0 2>/dev/null || echo "ciphr: could not disable core dumps" >&2

# ── Data directory ───────────────────────────────────────────────────────────
# Only when it is actually wrong. An unconditional recursive chown on every
# start would rewrite the ownership of a database this script has no business
# touching, and would hide a mount that was wired up incorrectly.
if [ "$(stat -c '%U' /var/lib/ciphr)" != "ciphr" ]; then
    echo "ciphr: taking ownership of /var/lib/ciphr" >&2
    chown -R ciphr:ciphr /var/lib/ciphr
fi

# ── Key material: narrow enough, and readable by the service ─────────────────
# Two checks, because the two failures look nothing alike and only one of them
# is obvious.
#
# Too wide is the one people expect. Checked rather than corrected: a private
# key arriving world-readable means the deployment put it there that way, and
# quietly fixing it would make the mistake permanent and invisible.
#
# **Unreadable is the likelier mistake.** `install -o root -g root -m 0600` is
# the reflex for a private key, and it produces a file this service cannot open
# -- mode 600 owned by root, while the process runs as `ciphr`. Without this
# check the failure surfaces later as "Permission denied (os error 13)" from
# the TLS loader, which reads like a broken certificate rather than a wrong
# owner.
if [ -f /etc/ciphr/tls/key.pem ]; then
    mode=$(stat -c '%a' /etc/ciphr/tls/key.pem)
    case "$mode" in
        600|400) : ;;
        *)
            echo "ciphr: /etc/ciphr/tls/key.pem has mode $mode; expected 600 or 400" >&2
            exit 1
            ;;
    esac

    if ! gosu ciphr test -r /etc/ciphr/tls/key.pem; then
        owner=$(stat -c '%U:%G' /etc/ciphr/tls/key.pem)
        echo "ciphr: /etc/ciphr/tls/key.pem is mode $mode but owned by $owner;" >&2
        echo "       the service runs as 'ciphr' and cannot read it." >&2
        echo "       Install it with: install -o 999 -g 999 -m 0600 key.pem ..." >&2
        exit 1
    fi
fi

# `exec` so the service is PID 1 and receives SIGTERM directly. Without it a
# shell would sit in between, the signal would not reach the server, and the
# graceful shutdown that exists to answer already-audited requests would never
# run.
exec gosu ciphr "$@"
