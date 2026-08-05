#!/usr/bin/env bash
# Phase 1 -- accounts and repo permissions.
#
# This is the part that actually protects the secrets.  Everything later is
# ergonomics and blast-radius reduction on top of uid separation.
#
#   uid <operator>   normal user, holds nothing special
#   uid agent        runs the coding agent; member of group devwork
#   uid secretd      holds the age key and the SSH keys; executes commands
#   group devwork    shared access to the repo working tree
set -euo pipefail

OPERATOR="${OPERATOR:-${SUDO_USER:-$(id -un)}}"
AGENT_USER="${AGENT_USER:-agent}"
BROKER_USER="${BROKER_USER:-secretd}"
GROUP="${DEVWORK_GROUP:-devwork}"
WORKTREE="${WORKTREE:-/home/${AGENT_USER}/work/ansible-ctrl}"

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

say "group ${GROUP}"
getent group "$GROUP" >/dev/null || groupadd "$GROUP"

say "user ${AGENT_USER} (agent)"
if ! id -u "$AGENT_USER" >/dev/null 2>&1; then
  useradd -m -G "$GROUP" -s /bin/bash "$AGENT_USER"
else
  usermod -aG "$GROUP" "$AGENT_USER"
fi

# The broker needs a real, writable home: it holds the SSH keys used to reach
# managed hosts, and Ansible insists on creating ~/.ansible/tmp.  It must NOT
# be under /home -- the service unit sets ProtectHome=tmpfs, which would make it
# invisible to the very process that needs it.
BROKER_HOME="${BROKER_HOME:-/var/lib/secretd}"
say "user ${BROKER_USER} (broker, no login, home ${BROKER_HOME})"
if ! id -u "$BROKER_USER" >/dev/null 2>&1; then
  useradd -r -m -d "$BROKER_HOME" -G "$GROUP" -s /usr/sbin/nologin "$BROKER_USER"
else
  usermod -aG "$GROUP" "$BROKER_USER"
  current_home="$(getent passwd "$BROKER_USER" | cut -d: -f6)"
  if [[ $current_home != "$BROKER_HOME" ]]; then
    say "moving ${BROKER_USER} home from ${current_home:-none} to ${BROKER_HOME}"
    usermod -d "$BROKER_HOME" "$BROKER_USER"
  fi
fi
install -d -m 0700 -o "$BROKER_USER" -g "$BROKER_USER" "$BROKER_HOME"
install -d -m 0700 -o "$BROKER_USER" -g "$BROKER_USER" "${BROKER_HOME}/.ssh"

say "operator ${OPERATOR} joins ${GROUP}"
id -u "$OPERATOR" >/dev/null 2>&1 && usermod -aG "$GROUP" "$OPERATOR"

if [[ -d $WORKTREE ]]; then
  say "shared working tree ${WORKTREE}"
  chgrp -R "$GROUP" "$WORKTREE"
  chmod -R g+rwX "$WORKTREE"
  # setgid so files created by either account inherit the group
  find "$WORKTREE" -type d -exec chmod g+s {} +
else
  say "SKIP ${WORKTREE} (does not exist yet -- rerun after cloning the repo)"
fi

# Without umask 002 the two accounts fight over every new file.  This is the
# single most likely thing to make an operator abandon the setup.
for profile in "/home/${AGENT_USER}/.bashrc" "$(getent passwd "$OPERATOR" | cut -d: -f6)/.bashrc"; do
  [[ -f $profile ]] || continue
  if ! grep -q '^umask 002' "$profile"; then
    say "umask 002 -> ${profile}"
    printf '\n# shared devwork tree: let group members edit each other'"'"'s files\numask 002\n' >>"$profile"
  fi
done

install -d -m 0750 -o "$BROKER_USER" -g "$BROKER_USER" /etc/secretd
install -d -m 0750 -o "$BROKER_USER" -g "$BROKER_USER" /var/log/secretd
install -d -m 0755 -o "$BROKER_USER" -g "$GROUP" /srv/ansible-ctrl

cat <<EOF

Phase 1 acceptance (run these):
  sudo -u ${AGENT_USER} cat /etc/secretd/age.key        -> Permission denied
  sudo -u ${AGENT_USER} ls ~${OPERATOR}/.ssh            -> Permission denied
  sudo -u ${AGENT_USER} touch ${WORKTREE}/.perm-check   -> succeeds

Note: ${AGENT_USER} and ${OPERATOR} must log out and back in for the new group
membership to take effect.
EOF
