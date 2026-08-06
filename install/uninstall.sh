#!/usr/bin/env bash
# Remove the broker.  Leaves accounts, /etc/faramir and the audit log alone --
# deleting the age key would make every sops file in the repo unreadable, and
# that is not a decision a teardown script should make for you.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

say "stopping services"
systemctl disable --now \
  faramir-broker.socket faramir-broker.service \
  faramir-keeper.socket faramir-keeper.service 2>/dev/null || true
rm -f /etc/systemd/system/faramir-broker.socket /etc/systemd/system/faramir-broker.service
rm -f /etc/systemd/system/faramir-keeper.socket /etc/systemd/system/faramir-keeper.service
rm -rf /etc/systemd/system/faramir-broker.service.d
systemctl daemon-reload

say "removing binaries and library"
rm -f /usr/local/bin/faramir-broker /usr/local/bin/faramir-keeper \
      /usr/local/bin/faramir /usr/local/bin/faramir-mcp
rm -rf /usr/local/lib/faramir /usr/local/libexec/faramir /usr/local/share/doc/faramir

# The project was called secretd before; a host installed then still has those
# units enabled and would keep serving a second broker on the old socket.
# CLEANUP (added 2026-08-05): remove once every host has been reinstalled.
say "removing any pre-rename secretd install"
systemctl disable --now secretd.socket secretd.service 2>/dev/null || true
rm -f /etc/systemd/system/secretd.socket /etc/systemd/system/secretd.service
rm -rf /etc/systemd/system/secretd.service.d
rm -f /usr/local/bin/secretd /usr/local/bin/secure-run /usr/local/bin/secretd-mcp
rm -rf /usr/local/lib/secretd /usr/local/libexec/secretd /usr/local/share/doc/secretd
systemctl daemon-reload

cat <<'EOF'

Left in place on purpose:
  /etc/faramir/age.key      deleting it makes every sops file unreadable
  /etc/faramir/config.toml
  /var/log/faramir/         the unredacted audit log
  users agent, faramir-broker and faramir-keeper, group devwork

Remove those by hand if you really mean to, and note that the agent account's
~/.claude/settings.json still points at the (now missing) PreToolUse hook --
a missing hook command does not block anything, so clean it up too.
EOF
