#!/usr/bin/env bash
# Phase 3 -- install the broker binaries, config and systemd units.
#
# Idempotent: safe to re-run after rebuilding.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BROKER_USER="${BROKER_USER:-faramir-broker}"
AGENT_USER="${AGENT_USER:-agent}"
GROUP="${DEVWORK_GROUP:-devwork}"
BIN="${FARAMIR_BIN:-$REPO/bin}"
# Derive from the passwd entry when the account exists, so this agrees with
# 40-agent-config.sh for a home that is not /home/<user>.  getent exits 2 for a
# missing account, which pipefail would turn into a silent abort before the
# EUID check below has had a chance to say anything useful.
AGENT_HOME="$(getent passwd "$AGENT_USER" | cut -d: -f6)" || AGENT_HOME=""
WORKTREE="${WORKTREE:-${AGENT_HOME:-/home/${AGENT_USER}}/work/repo}"
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

say "docs -> /usr/local/share/doc/faramir"
install -d -m 0755 /usr/local/share/doc/faramir
install -m 0644 "$REPO/README.md" /usr/local/share/doc/faramir/README.md
install -m 0644 "$REPO"/docs/*.md /usr/local/share/doc/faramir/

# Three services read config.toml from here, so the directory belongs to none
# of them.  The age key is protected by its own mode, not by this one.
install -d -m 0755 -o root -g root /etc/faramir
install -d -m 0750 -o "$BROKER_USER" -g "$BROKER_USER" /var/log/faramir

# Left over from installs that placed the patterns under the config directory,
# where the agent uid could not read them.
# CLEANUP (added 2026-08-05): remove once every host has run this script once.
rm -f /etc/faramir/deny-patterns.txt /etc/secretd/deny-patterns.txt
# Left over from the Python implementation, which shipped a library tree.
# CLEANUP (added 2026-08-06): remove once every host has run this script once.
rm -rf /usr/local/lib/faramir
rm -f /usr/local/libexec/faramir/pretooluse-guard.py

# The working tree appears in the config more than once -- [exec] default_cwd
# and [secrets] files -- and the bind mounts below make exactly one path visible
# to the three units.  The shipped configs write it as @WORKTREE@, so this is
# one substitution.
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
# comments have to be read the way the broker reads them, or the checks below
# fire on configs that are perfectly correct.
configured_cwd() {
  "$BIN/faramir-broker" -c "$1" --print-default-cwd 2>/dev/null || return 1
}

# Is $1 reachable inside the tree bound into the units?  A plain prefix test
# would accept "${WORKTREE}-old" and "${WORKTREE}EVIL", which are different
# trees that the bind mount does not make visible at all; requiring the
# separator is what distinguishes those from a real subdirectory.
under_worktree() {
  [[ $1 == "$WORKTREE" || $1 == "$WORKTREE"/* ]]
}

# Before anything is written to the host: a CONFIG that does not parse should
# abort here, not halfway through.
configured_cwd "$CONFIG" >/dev/null || {
  say "cannot read ${CONFIG}: it does not parse as a faramir config"
  exit 1
}

if [[ -f /etc/faramir/config.toml ]]; then
  say "keeping existing /etc/faramir/config.toml (new default at config.toml.dist)"
  # Substituted, not copied verbatim: the message above invites an operator to
  # move this into place, and a .dist still carrying @WORKTREE@ would start a
  # broker whose every command fails with "cwd does not exist".
  substitute "$CONFIG" /etc/faramir/config.toml.dist || exit 1
  if ! existing="$(configured_cwd /etc/faramir/config.toml)"; then
    say "WARNING: the installed /etc/faramir/config.toml does not parse;"
    say "         the broker will not start until it does"
  elif ! under_worktree "$existing"; then
    say "WARNING: [exec] default_cwd is ${existing} but this install binds ${WORKTREE}"
    say "         commands will fail with 'cwd does not exist' until they agree;"
    say "         edit /etc/faramir/config.toml"
  fi
else
  say "config ${CONFIG#"$REPO"/} -> /etc/faramir/config.toml (worktree ${WORKTREE})"
  substitute "$CONFIG" /etc/faramir/config.toml || exit 1
  # A CONFIG that names the tree literally rather than through the placeholder
  # is installed unchanged, and would then disagree with the bind mounts below.
  # Refuse at install time rather than letting every command fail with "cwd
  # does not exist" later.
  installed="$(configured_cwd /etc/faramir/config.toml)" || installed=""
  if ! under_worktree "$installed"; then
    rm -f /etc/faramir/config.toml
    say "[exec] default_cwd is ${installed:-unset}, which is not inside ${WORKTREE}."
    say "Write the tree as @WORKTREE@ in ${CONFIG}, or re-run with"
    say "WORKTREE=${installed}."
    say "No config was written; the binaries and hook above are already installed."
    exit 1
  fi
fi

say "systemd units"
for unit in faramir-broker.socket faramir-broker.service \
            faramir-keeper.socket faramir-keeper.service \
            faramir-exec.socket faramir-exec.service; do
  install -m 0644 "$REPO/systemd/${unit}" "/etc/systemd/system/${unit}"
done

# /home is an empty tmpfs inside all three units, so the working tree has to be
# bound in explicitly.  Each unit hardcodes the default; bind the configured
# tree too, or an install with AGENT_USER or WORKTREE set starts clean and then
# fails at runtime -- the keeper reporting every ref as missing, the executor
# with "cwd does not exist".  Bind*Paths= are lists, so these append.
#
# The executor gets it read-write because commands run there; the other two get
# it read-only, because neither has any business writing the agent's tree.
say "worktree bind mounts -> ${WORKTREE}"
for unit in faramir-broker faramir-keeper; do
  install -d -m 0755 "/etc/systemd/system/${unit}.service.d"
  cat >"/etc/systemd/system/${unit}.service.d/10-worktree.conf" <<EOF
# Written by install/30-install-broker.sh.  Regenerated on every run.
[Service]
BindReadOnlyPaths=-${WORKTREE}
EOF
  chmod 0644 "/etc/systemd/system/${unit}.service.d/10-worktree.conf"
done
install -d -m 0755 /etc/systemd/system/faramir-exec.service.d
cat >/etc/systemd/system/faramir-exec.service.d/10-worktree.conf <<EOF
# Written by install/30-install-broker.sh.  Regenerated on every run.
[Service]
BindPaths=-${WORKTREE}
EOF
chmod 0644 /etc/systemd/system/faramir-exec.service.d/10-worktree.conf

# Left over from the commit-then-sync arrangement, which no longer exists: the
# broker executes the working tree directly.
# CLEANUP (added 2026-08-06): remove once every host has run this script once.
rm -f /etc/systemd/system/faramir-broker.service.d/10-sync-source.conf

# systemd may not be running (container, chroot, image build).  Install the
# units anyway; just do not pretend to have started anything.
if systemctl is-system-running --quiet 2>/dev/null || [[ -d /run/systemd/system ]]; then
  HAVE_SYSTEMD=1
  systemctl daemon-reload
else
  HAVE_SYSTEMD=0
  say "systemd is not running here; units installed but not started"
fi

if [[ $HAVE_SYSTEMD -eq 1 && -f /etc/faramir/age.key ]]; then
  # The keeper and the executor first: the broker talks to both.
  systemctl enable --now \
    faramir-keeper.socket faramir-exec.socket faramir-broker.socket
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

say "validating the installed config"
/usr/local/bin/faramir-broker -c /etc/faramir/config.toml --check || {
  say "validation FAILED -- fix /etc/faramir/config.toml, or lengthen any secret"
  say "reported under not_redactable, before enabling the unit"
  exit 1
}

cat <<EOF

Phase 3 acceptance (run these):
  sudo -u agent cat /proc/\$(pgrep -u ${BROKER_USER} -f faramir-broker | head -1)/environ
      -> No such file or directory   (ProtectProc=invisible)
  sudo -u agent test -w /run/faramir/broker.sock && echo writable
      -> writable                    (group ${GROUP} access works)
EOF
