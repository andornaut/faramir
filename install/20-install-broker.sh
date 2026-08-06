#!/usr/bin/env bash
# Phase 3 -- install the broker code, config and systemd units.
#
# Idempotent: safe to re-run after editing the source.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BROKER_USER="${BROKER_USER:-faramir-broker}"
AGENT_USER="${AGENT_USER:-agent}"
GROUP="${DEVWORK_GROUP:-devwork}"
LIB="${FARAMIR_LIB:-/usr/local/lib/faramir}"
# Derive from the passwd entry when the account exists, so this agrees with
# 40-agent-config.sh for a home that is not /home/<user>.  getent exits 2 for a
# missing account, which pipefail would turn into a silent abort before the
# EUID check below has had a chance to say anything useful.
AGENT_HOME="$(getent passwd "$AGENT_USER" | cut -d: -f6)" || AGENT_HOME=""
WORKTREE="${WORKTREE:-${AGENT_HOME:-/home/${AGENT_USER}}/work/repo}"
# The starter policy allows two commands, both of them demonstrations.  Point
# this at etc/examples/<workload>.toml to install a policy for a real workload.
CONFIG="${CONFIG:-$REPO/etc/config.toml}"

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

say "python check"
python3 - <<'PY'
import sys
if sys.version_info < (3, 11):
    sys.exit(f"faramir needs Python >= 3.11 (tomllib); found {sys.version.split()[0]}")
PY

say "library -> ${LIB}/faramir"
install -d -m 0755 "$LIB"
rm -rf "${LIB:?}/faramir"
install -d -m 0755 "${LIB}/faramir"
install -m 0644 "$REPO"/src/faramir/*.py "${LIB}/faramir/"

say "binaries -> /usr/local/bin"
install -m 0755 "$REPO/bin/faramir-broker" /usr/local/bin/faramir-broker
install -m 0755 "$REPO/bin/faramir-keeper" /usr/local/bin/faramir-keeper
install -m 0755 "$REPO/bin/faramir-exec" /usr/local/bin/faramir-exec
install -m 0755 "$REPO/bin/faramir" /usr/local/bin/faramir
install -m 0755 "$REPO/bin/faramir-mcp" /usr/local/bin/faramir-mcp

say "hook -> /usr/local/libexec/faramir"
install -d -m 0755 /usr/local/libexec/faramir
install -m 0755 "$REPO/agent/hooks/pretooluse-guard.py" /usr/local/libexec/faramir/pretooluse-guard.py
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

# [sync] source must name the worktree this install was given, not the default
# baked into the shipped config.  The bind mount below makes only that one path
# visible to the broker, so a source pointing anywhere else fails every sync.
# Read it as TOML rather than pattern-matching the line: quoting styles and
# trailing comments have to be read the way the broker reads them, or the
# warning below fires on configs that are perfectly correct.  An absent key is
# reported as <unset>, which is a config the broker refuses to load while sync
# is enabled, so it warns here too.
configured_source() {
  FARAMIR_LIB="$LIB" python3 - "$1" <<'PY'
import sys, tomllib
sys.path.insert(0, __import__("os").environ["FARAMIR_LIB"])
from faramir.config import SyncConfig

try:
    with open(sys.argv[1], "rb") as fh:
        raw = tomllib.load(fh)
except (OSError, tomllib.TOMLDecodeError) as exc:
    sys.exit(f"cannot read {sys.argv[1]}: {exc}")
section = raw.get("sync")
section = section if isinstance(section, dict) else {}
print(section.get("source", SyncConfig.source) or "<unset>")
PY
}

if [[ -f /etc/faramir/config.toml ]]; then
  say "keeping existing /etc/faramir/config.toml (new default at config.toml.dist)"
  install -m 0644 -o root -g root "$CONFIG" /etc/faramir/config.toml.dist
  # No -n guard: an absent source key is itself a mismatch worth warning about.
  if existing="$(configured_source /etc/faramir/config.toml)" &&
     [[ $existing != "$WORKTREE" ]]; then
    say "WARNING: [sync] source is ${existing} but this install binds ${WORKTREE}"
    say "         sync will fail until they match; edit /etc/faramir/config.toml"
  fi
else
  say "config ${CONFIG#"$REPO"/} -> /etc/faramir/config.toml (sync source ${WORKTREE})"
  install -m 0644 -o root -g root "$CONFIG" /etc/faramir/config.toml
  awk -v worktree="$WORKTREE" '
    /^\[sync\]/ { in_sync = 1 }
    /^\[/ && !/^\[sync\]/ { in_sync = 0 }
    in_sync && /^[[:space:]]*source[[:space:]]*=/ {
      print "source = \"" worktree "\""; next }
    { print }' /etc/faramir/config.toml >/etc/faramir/config.toml.new
  chown root:root /etc/faramir/config.toml.new
  chmod 0644 /etc/faramir/config.toml.new
  mv /etc/faramir/config.toml.new /etc/faramir/config.toml
fi

say "systemd units"
for unit in faramir-broker.socket faramir-broker.service \
            faramir-keeper.socket faramir-keeper.service \
            faramir-exec.socket faramir-exec.service; do
  install -m 0644 "$REPO/systemd/${unit}" "/etc/systemd/system/${unit}"
done

# /home is an empty tmpfs inside the unit, so the sync source has to be bound in
# explicitly.  The unit hardcodes the default; bind the configured worktree too,
# or an install with AGENT_USER or WORKTREE set starts clean and then fails
# every sync at runtime.  BindReadOnlyPaths= is a list, so this appends.
say "sync source bind mount -> ${WORKTREE}"
install -d -m 0755 /etc/systemd/system/faramir-broker.service.d
cat >/etc/systemd/system/faramir-broker.service.d/10-sync-source.conf <<EOF
# Written by install/20-install-broker.sh.  Regenerated on every run.
[Service]
BindReadOnlyPaths=-${WORKTREE}
EOF
chmod 0644 /etc/systemd/system/faramir-broker.service.d/10-sync-source.conf

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
  say "Run install/30-sops-init.sh first, then:"
  say "  systemctl enable --now faramir-keeper.socket faramir-exec.socket faramir-broker.socket"
fi

say "validating the installed config"
FARAMIR_LIB="$LIB" /usr/local/bin/faramir-broker -c /etc/faramir/config.toml --check || {
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
