#!/usr/bin/env bash
# Remove the broker.  Leaves accounts, /etc/secretd and the audit log alone --
# deleting the age key would make every sops file in the repo unreadable, and
# that is not a decision a teardown script should make for you.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

say "stopping services"
systemctl disable --now secretd.socket secretd.service 2>/dev/null || true
rm -f /etc/systemd/system/secretd.socket /etc/systemd/system/secretd.service
systemctl daemon-reload

say "removing binaries and library"
rm -f /usr/local/bin/secretd /usr/local/bin/secure-run /usr/local/bin/secretd-mcp
rm -rf /usr/local/lib/secretd /usr/local/libexec/secretd /usr/local/share/doc/secretd

cat <<'EOF'

Left in place on purpose:
  /etc/secretd/age.key      deleting it makes every sops file unreadable
  /etc/secretd/config.toml
  /var/log/secretd/         the unredacted audit log
  users agent and secretd, group devwork

Remove those by hand if you really mean to, and note that the agent account's
~/.claude/settings.json still points at the (now missing) PreToolUse hook --
a missing hook command does not block anything, so clean it up too.
EOF
