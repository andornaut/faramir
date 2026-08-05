#!/usr/bin/env bash
# Phase 3 -- install the broker code, config and systemd units.
#
# Idempotent: safe to re-run after editing the source.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BROKER_USER="${BROKER_USER:-secretd}"
GROUP="${DEVWORK_GROUP:-devwork}"
LIB="${SECRETD_LIB:-/usr/local/lib/secretd}"

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

if [[ -f /etc/secretd/config.toml ]]; then
  say "keeping existing /etc/secretd/config.toml (new default at config.toml.dist)"
  install -m 0640 -o root -g "$BROKER_USER" "$REPO/etc/config.toml" /etc/secretd/config.toml.dist
else
  say "config -> /etc/secretd/config.toml"
  install -m 0640 -o root -g "$BROKER_USER" "$REPO/etc/config.toml" /etc/secretd/config.toml
fi

say "systemd units"
install -m 0644 "$REPO/systemd/secretd.socket" /etc/systemd/system/secretd.socket
install -m 0644 "$REPO/systemd/secretd.service" /etc/systemd/system/secretd.service

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
