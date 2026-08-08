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
  faramir-keeper.socket faramir-keeper.service \
  faramir-exec.socket faramir-exec.service 2>/dev/null || true
rm -f /etc/systemd/system/faramir-broker.socket /etc/systemd/system/faramir-broker.service
rm -f /etc/systemd/system/faramir-keeper.socket /etc/systemd/system/faramir-keeper.service
rm -f /etc/systemd/system/faramir-exec.socket /etc/systemd/system/faramir-exec.service
rm -rf /etc/systemd/system/faramir-broker.service.d \
       /etc/systemd/system/faramir-keeper.service.d \
       /etc/systemd/system/faramir-exec.service.d
systemctl daemon-reload
# The sockets are gone with the units above, so the directory holds nothing.
rm -f /etc/tmpfiles.d/faramir.conf
rm -rf /run/faramir

say "removing binaries"
rm -f /usr/local/bin/faramir-broker /usr/local/bin/faramir-keeper \
      /usr/local/bin/faramir-exec /usr/local/bin/faramir /usr/local/bin/faramir-mcp
rm -rf /usr/local/libexec/faramir /usr/local/share/doc/faramir

cat <<'EOF'

Left in place on purpose:
  /etc/faramir/age.key      deleting it makes every sops file unreadable
  /etc/faramir/config.toml
  /etc/faramir/config.d/     per-consumer settings merged over it
  /var/log/faramir/         the audit log
  users agent, faramir-broker, faramir-keeper and faramir-exec, group dev

Remove those by hand if you really mean to, and note that the agent account's
~/.claude/settings.json still points at the (now missing) PreToolUse hook --
a missing hook command does not block anything, so clean it up too.
EOF
