#!/usr/bin/env bash
# Phase 3 -- install the broker binaries, config and systemd units.
#
# Idempotent: safe to re-run after rebuilding.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BROKER_USER="${BROKER_USER:-faramir-broker}"
OPERATOR="${OPERATOR:-${SUDO_USER:-$(id -un)}}"
GROUP="${DEV_GROUP:-dev}"
BIN="${FARAMIR_BIN:-$REPO/bin}"
# Outside every home: the keeper and the executor read this tree as system
# services, before any home is necessarily mounted.  Phase 1 creates it.
WORKTREE="${WORKTREE:-/srv/faramir/worktree}"
# Point this at etc/examples/<workload>.toml to install the configuration for a
# real workload rather than the starter.
# A relative path resolves against the repo, so the documented invocation works
# from any directory.
CONFIG="${CONFIG:-etc/config.toml}"
[[ $CONFIG = /* ]] || CONFIG="$REPO/$CONFIG"

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
# Before anything is installed: a typo here would otherwise surface as a bare
# "cannot stat" once the binaries and hook are already on the host.
[[ -f $CONFIG ]] || { echo "no such config: $CONFIG" >&2; exit 1; }
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

# The binaries are built ahead of time, so this script needs no toolchain and
# no interpreter on the target host.  Build them with `make build` first.
say "checking for built binaries in ${BIN}"
missing=()
for b in faramir faramir-broker faramir-keeper faramir-exec faramir-mcp faramir-guard; do
  [[ -x "$BIN/$b" ]] || missing+=("$b")
done
if ((${#missing[@]})); then
  echo "not built: ${missing[*]}" >&2
  echo "run 'make build' (needs Go), or set FARAMIR_BIN to a directory holding them" >&2
  exit 1
fi

say "binaries -> /usr/local/bin"
for b in faramir faramir-broker faramir-keeper faramir-exec faramir-mcp; do
  install -m 0755 "$BIN/$b" "/usr/local/bin/$b"
done
say "hook -> /usr/local/libexec/faramir"
install -d -m 0755 /usr/local/libexec/faramir
install -m 0755 "$BIN/faramir-guard" /usr/local/libexec/faramir/faramir-guard
# Next to the hook rather than under /etc/faramir, so it travels with the thing
# that reads it.  A patterns file the hook cannot read is worse than none: it
# falls back to a built-in list that is silently weaker.
install -m 0644 "$REPO/agent/hooks/deny-patterns.txt" /usr/local/libexec/faramir/deny-patterns.txt
# Sourced by the shell the hook rewrites into, so it is read, never executed.
install -m 0644 "$REPO/agent/hooks/wrap.sh" /usr/local/libexec/faramir/wrap.sh

say "docs -> /usr/local/share/doc/faramir"
install -d -m 0755 /usr/local/share/doc/faramir
install -m 0644 "$REPO/README.md" /usr/local/share/doc/faramir/README.md
install -m 0644 "$REPO"/docs/*.md /usr/local/share/doc/faramir/

# Three services read config.toml from here, so the directory belongs to none
# of them.  The age key is protected by its own mode, not by this one.
install -d -m 0755 -o root -g root /etc/faramir
install -d -m 0750 -o "$BROKER_USER" -g "$BROKER_USER" /var/log/faramir

# The working tree appears in the config as [secrets] files, written @WORKTREE@
# so that this is the one substitution.  It is the only place the path appears:
# the units do not name it, and no config key relocates a command any more.
#
# sed's replacement side treats \ and & specially and would also eat the
# delimiter, and a worktree path is arbitrary, so escape all three rather than
# refusing paths that contain them.
worktree_escaped="$(printf '%s' "$WORKTREE" | sed 's/[\\&|]/\\&/g')"

substitute() {
  # Never redirect onto the destination: the shell truncates it before sed
  # runs, so a failure would leave an empty config behind and every later run
  # would take the "keeping existing" branch and preserve it forever.
  local src="$1" dst="$2" tmp
  tmp="$(mktemp "${dst}.XXXXXX")"
  if ! sed "s|@WORKTREE@|${worktree_escaped}|g" "$src" >"$tmp"; then
    rm -f "$tmp"; return 1
  fi
  if grep -q '@WORKTREE@' "$tmp"; then
    rm -f "$tmp"
    echo "substitution left a @WORKTREE@ placeholder in ${dst}" >&2
    return 1
  fi
  chown root:root "$tmp"
  chmod 0644 "$tmp"
  mv "$tmp" "$dst"
}

# Reading a config needs the broker's own parser: quoting styles and trailing
# comments have to be read the way the broker reads them, or a config that is
# perfectly correct is refused by a check of its own.
config_parses() {
  "$BIN/faramir-broker" -c "$1" --parse-only 2>/dev/null
}

# Before anything is written to the host: a CONFIG that does not parse should
# abort here, not halfway through.
config_parses "$CONFIG" || {
  say "cannot read ${CONFIG}: it does not parse as a faramir config"
  exit 1
}

if [[ -f /etc/faramir/config.toml ]]; then
  say "keeping existing /etc/faramir/config.toml (new default at config.toml.dist)"
  # Substituted, not copied verbatim: the message above invites an operator to
  # move this into place, and a .dist still carrying @WORKTREE@ would start a
  # broker that manages no secrets file and therefore redacts nothing.
  substitute "$CONFIG" /etc/faramir/config.toml.dist || exit 1
  if ! config_parses /etc/faramir/config.toml; then
    say "WARNING: the installed /etc/faramir/config.toml does not parse;"
    say "         the broker will not start until it does"
  fi
else
  say "config ${CONFIG#"$REPO"/} -> /etc/faramir/config.toml (worktree ${WORKTREE})"
  substitute "$CONFIG" /etc/faramir/config.toml || exit 1
fi

say "systemd units"
for unit in faramir-broker.socket faramir-broker.service \
            faramir-keeper.socket faramir-keeper.service \
            faramir-exec.socket faramir-exec.service; do
  install -m 0644 "$REPO/systemd/${unit}" "/etc/systemd/system/${unit}"
done

# /run/faramir belongs to tmpfiles, not to a RuntimeDirectory= on any unit:
# systemd chowns a RuntimeDirectory recursively and would rewrite the ownership
# systemd itself gave the sockets in it.  See the file's own comment.
install -m 0644 "$REPO/systemd/faramir.tmpfiles.conf" /etc/tmpfiles.d/faramir.conf

# No drop-ins.  The units name no working tree: the broker and the keeper only
# read it, which ProtectSystem=strict already allows, and the executor is
# granted /home and /srv/faramir, which covers both shipped locations, with
# modes deciding what it can actually write.  The tree's path lives in the
# config and nowhere else.  A tree outside both needs a drop-in extending
# ReadWritePaths= on faramir-exec.service.

# systemd may not be running (container, chroot, image build).  Install the
# units anyway; just do not pretend to have started anything.
if systemctl is-system-running --quiet 2>/dev/null || [[ -d /run/systemd/system ]]; then
  HAVE_SYSTEMD=1
  systemctl daemon-reload
  systemd-tmpfiles --create /etc/tmpfiles.d/faramir.conf
else
  HAVE_SYSTEMD=0
  say "systemd is not running here; units installed but not started"
fi

if [[ $HAVE_SYSTEMD -eq 1 && -f /etc/faramir/age.key ]]; then
  # Nothing in this block is fatal, under set -e or otherwise: a unit that will
  # not start is exactly when the --check gate below and systemd-analyze have
  # something to say, and aborting here would replace their output with a raw
  # systemctl error.
  #
  # The keeper and the executor first: the broker talks to both.
  systemctl enable --now \
    faramir-keeper.socket faramir-exec.socket faramir-broker.socket || true
  # Restart, not just enable --now: an already-active socket keeps whatever
  # ownership its file was left with, and the services below have to pick up
  # the new listeners anyway.
  systemctl restart \
    faramir-keeper.socket faramir-exec.socket faramir-broker.socket || true
  for unit in faramir-keeper faramir-exec faramir-broker; do
    systemctl restart "${unit}.service" || true
  done
  for unit in faramir-keeper.service faramir-exec.service faramir-broker.service; do
    say "systemd-analyze security ${unit}"
    systemd-analyze security "$unit" || true
  done
elif [[ ! -f /etc/faramir/age.key ]]; then
  say "NOT starting faramir: /etc/faramir/age.key is missing."
  say "Run install/20-sops-init.sh first, then:"
  say "  systemctl enable --now faramir-keeper.socket faramir-exec.socket faramir-broker.socket"
fi

say "validating the installed config as ${BROKER_USER}"
# As the broker's own uid, not root: --check opens the SSH keys and the secrets
# files itself, and root reads what the broker cannot.  A key left root:root
# would otherwise pass here and leave every brokered command unable to
# authenticate against any host.
runuser -u "$BROKER_USER" -- \
  /usr/local/bin/faramir-broker -c /etc/faramir/config.toml --check || {
  say "validation FAILED -- fix /etc/faramir/config.toml, or lengthen any secret"
  say "reported under not_redactable, before enabling the unit"
  exit 1
}

cat <<EOF

Phase 3 acceptance (run these):
  cat /proc/\$(pgrep -u ${BROKER_USER} -f faramir-broker | head -1)/environ
      -> No such file or directory   (ProtectProc=invisible)
  test -w /run/faramir/broker.sock && echo writable
      -> writable                    (group ${GROUP} access works)
EOF
