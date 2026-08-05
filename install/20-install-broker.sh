#!/usr/bin/env bash
# Phase 3 -- install the broker code, config and systemd units.
#
# Idempotent: safe to re-run after editing the source.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BROKER_USER="${BROKER_USER:-secretd}"
AGENT_USER="${AGENT_USER:-agent}"
GROUP="${DEVWORK_GROUP:-devwork}"
LIB="${SECRETD_LIB:-/usr/local/lib/secretd}"
# Derive from the passwd entry when the account exists, so this agrees with
# 40-agent-config.sh for a home that is not /home/<user>.  getent exits 2 for a
# missing account, which pipefail would turn into a silent abort before the
# EUID check below has had a chance to say anything useful.
AGENT_HOME="$(getent passwd "$AGENT_USER" | cut -d: -f6)" || AGENT_HOME=""
WORKTREE="${WORKTREE:-${AGENT_HOME:-/home/${AGENT_USER}}/work/ansible-ctrl}"

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

say "python check"
python3 - <<'PY'
import sys
if sys.version_info < (3, 11):
    sys.exit(f"secretd needs Python >= 3.11 (tomllib); found {sys.version.split()[0]}")
PY

say "library -> ${LIB}/secretd"
install -d -m 0755 "$LIB"
rm -rf "${LIB:?}/secretd"
install -d -m 0755 "${LIB}/secretd"
install -m 0644 "$REPO"/src/secretd/*.py "${LIB}/secretd/"

say "binaries -> /usr/local/bin"
install -m 0755 "$REPO/bin/secretd" /usr/local/bin/secretd
install -m 0755 "$REPO/bin/secure-run" /usr/local/bin/secure-run
install -m 0755 "$REPO/bin/secretd-mcp" /usr/local/bin/secretd-mcp

say "hook -> /usr/local/libexec/secretd"
install -d -m 0755 /usr/local/libexec/secretd
install -m 0755 "$REPO/agent/hooks/pretooluse-guard.py" /usr/local/libexec/secretd/pretooluse-guard.py
# Next to the hook, not in /etc/secretd: the hook runs as the agent uid, which
# cannot traverse /etc/secretd (0750 secretd:secretd).  A patterns file it
# cannot read means it silently falls back to a much weaker built-in list.
install -m 0644 "$REPO/agent/hooks/deny-patterns.txt" /usr/local/libexec/secretd/deny-patterns.txt

say "docs -> /usr/local/share/doc/secretd"
install -d -m 0755 /usr/local/share/doc/secretd
install -m 0644 "$REPO/README.md" /usr/local/share/doc/secretd/README.md
install -m 0644 "$REPO"/docs/*.md /usr/local/share/doc/secretd/

install -d -m 0750 -o "$BROKER_USER" -g "$BROKER_USER" /etc/secretd
install -d -m 0750 -o "$BROKER_USER" -g "$BROKER_USER" /var/log/secretd

# Left over from installs that placed the patterns under /etc/secretd, where the
# agent uid could not read them.
# CLEANUP (added 2026-08-05): remove once every host has run this script once.
rm -f /etc/secretd/deny-patterns.txt

# [sync] source must name the worktree this install was given, not the default
# baked into the shipped config.  The bind mount below makes only that one path
# visible to the broker, so a source pointing anywhere else fails every sync.
# Read it as TOML rather than pattern-matching the line: quoting styles,
# trailing comments and an absent key (which means SyncConfig's default, not
# "no source") all have to be read the way the broker reads them, or the
# warning below fires on configs that are perfectly correct.
configured_source() {
  SECRETD_LIB="$LIB" python3 - "$1" <<'PY'
import sys, tomllib
sys.path.insert(0, __import__("os").environ["SECRETD_LIB"])
from secretd.config import SyncConfig

try:
    with open(sys.argv[1], "rb") as fh:
        raw = tomllib.load(fh)
except (OSError, tomllib.TOMLDecodeError) as exc:
    sys.exit(f"cannot read {sys.argv[1]}: {exc}")
section = raw.get("sync")
section = section if isinstance(section, dict) else {}
print(section.get("source", SyncConfig.source))
PY
}

if [[ -f /etc/secretd/config.toml ]]; then
  say "keeping existing /etc/secretd/config.toml (new default at config.toml.dist)"
  install -m 0640 -o root -g "$BROKER_USER" "$REPO/etc/config.toml" /etc/secretd/config.toml.dist
  # No -n guard: an absent source key means SyncConfig's default, which is
  # exactly the mismatch worth warning about on a non-default install.
  if existing="$(configured_source /etc/secretd/config.toml)" &&
     [[ $existing != "$WORKTREE" ]]; then
    say "WARNING: [sync] source is ${existing} but this install binds ${WORKTREE}"
    say "         sync will fail until they match; edit /etc/secretd/config.toml"
  fi
else
  say "config -> /etc/secretd/config.toml (sync source ${WORKTREE})"
  install -m 0640 -o root -g "$BROKER_USER" "$REPO/etc/config.toml" /etc/secretd/config.toml
  awk -v worktree="$WORKTREE" '
    /^\[sync\]/ { in_sync = 1 }
    /^\[/ && !/^\[sync\]/ { in_sync = 0 }
    in_sync && /^[[:space:]]*source[[:space:]]*=/ {
      print "source = \"" worktree "\""; next }
    { print }' /etc/secretd/config.toml >/etc/secretd/config.toml.new
  chown root:"$BROKER_USER" /etc/secretd/config.toml.new
  chmod 0640 /etc/secretd/config.toml.new
  mv /etc/secretd/config.toml.new /etc/secretd/config.toml
fi

say "systemd units"
install -m 0644 "$REPO/systemd/secretd.socket" /etc/systemd/system/secretd.socket
install -m 0644 "$REPO/systemd/secretd.service" /etc/systemd/system/secretd.service

# /home is an empty tmpfs inside the unit, so the sync source has to be bound in
# explicitly.  The unit hardcodes the default; bind the configured worktree too,
# or an install with AGENT_USER or WORKTREE set starts clean and then fails
# every sync at runtime.  BindReadOnlyPaths= is a list, so this appends.
say "sync source bind mount -> ${WORKTREE}"
install -d -m 0755 /etc/systemd/system/secretd.service.d
cat >/etc/systemd/system/secretd.service.d/10-sync-source.conf <<EOF
# Written by install/20-install-broker.sh.  Regenerated on every run.
[Service]
BindReadOnlyPaths=-${WORKTREE}
EOF
chmod 0644 /etc/systemd/system/secretd.service.d/10-sync-source.conf

# systemd may not be running (container, chroot, image build).  Install the
# units anyway; just do not pretend to have started anything.
if systemctl is-system-running --quiet 2>/dev/null || [[ -d /run/systemd/system ]]; then
  HAVE_SYSTEMD=1
  systemctl daemon-reload
else
  HAVE_SYSTEMD=0
  say "systemd is not running here; units installed but not started"
fi

if [[ $HAVE_SYSTEMD -eq 1 && -f /etc/secretd/age.key ]]; then
  systemctl enable --now secretd.socket
  systemctl restart secretd.service || true
  say "systemd-analyze security secretd.service"
  systemd-analyze security secretd.service || true
elif [[ ! -f /etc/secretd/age.key ]]; then
  say "NOT starting secretd: /etc/secretd/age.key is missing."
  say "Run install/30-sops-init.sh first, then: systemctl enable --now secretd.socket"
fi

say "validating the installed config"
SECRETD_LIB="$LIB" /usr/local/bin/secretd -c /etc/secretd/config.toml --check || {
  say "config validation FAILED -- fix /etc/secretd/config.toml before enabling the unit"
  exit 1
}

cat <<EOF

Phase 3 acceptance (run these):
  sudo -u agent cat /proc/\$(pgrep -u ${BROKER_USER} -f secretd | head -1)/environ
      -> No such file or directory   (ProtectProc=invisible)
  sudo -u agent test -w /run/secretd/sock && echo writable
      -> writable                    (group ${GROUP} access works)
EOF
