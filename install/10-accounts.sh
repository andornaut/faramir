#!/usr/bin/env bash
# Phase 1 -- accounts and repo permissions.
#
# This is the part that actually protects the secrets.  Everything later is
# ergonomics and blast-radius reduction on top of uid separation.
#
#   uid <operator>       normal user, holds nothing special
#   uid agent            runs the coding agent; member of group devwork
#   uid faramir-keeper   holds the age key; execs nothing but sops
#   uid faramir-broker   holds the SSH keys and the audit log; policy+redaction
#   uid faramir-exec     forks brokered commands; holds nothing
#   group devwork        shared access to the repo working tree
#
# Three uids rather than one because anything a uid can read, a command running
# as that uid can read.  The keeper's key and the broker's audit log and SSH
# keys each sit behind a boundary the child cannot cross.
#
# All three service accounts join devwork, because all three need the working
# tree: the keeper decrypts the sops files in it, the broker stats them, and
# brokered commands run in it.  That is read/write on files the agent already
# owns; it is not access to anything the agent could not reach itself.  The
# boundaries that matter are file modes, not this group.
set -euo pipefail

OPERATOR="${OPERATOR:-${SUDO_USER:-$(id -un)}}"
AGENT_USER="${AGENT_USER:-agent}"
BROKER_USER="${BROKER_USER:-faramir-broker}"
KEEPER_USER="${KEEPER_USER:-faramir-keeper}"
EXEC_USER="${EXEC_USER:-faramir-exec}"
GROUP="${DEVWORK_GROUP:-devwork}"
# WORKTREE's default needs the agent's real home, which the account below may
# not have yet, so it is resolved after the account exists.
WORKTREE="${WORKTREE:-}"

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
# Read the passwd entry rather than assuming /home/<user>, so all three install
# scripts agree for an account whose home is somewhere else.
AGENT_HOME="$(getent passwd "$AGENT_USER" | cut -d: -f6)" || AGENT_HOME=""
[[ -n $AGENT_HOME ]] || { echo "no home for ${AGENT_USER} after useradd" >&2; exit 1; }
WORKTREE="${WORKTREE:-${AGENT_HOME}/work/repo}"

# The broker needs a real, writable home: it holds the SSH keys used to reach
# managed hosts, and Ansible insists on creating ~/.ansible/tmp.  It must NOT
# be under /home -- the service unit sets ProtectHome=tmpfs, which would make it
# invisible to the very process that needs it.
BROKER_HOME="${BROKER_HOME:-/var/lib/faramir-broker}"
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

# The keeper holds the age key and nothing else.  No shell, and a home only
# because sops writes ~/.config.  It must not share a uid with anything that
# executes a command.  devwork only so sops can read the encrypted files in the
# working tree; the key itself is 0400 and in no group at all.
KEEPER_HOME="${KEEPER_HOME:-/var/lib/faramir-keeper}"
say "user ${KEEPER_USER} (keeper, no login, home ${KEEPER_HOME})"
if ! id -u "$KEEPER_USER" >/dev/null 2>&1; then
  useradd -r -m -d "$KEEPER_HOME" -G "$GROUP" -s /usr/sbin/nologin "$KEEPER_USER"
else
  usermod -aG "$GROUP" "$KEEPER_USER"
fi
install -d -m 0700 -o "$KEEPER_USER" -g "$KEEPER_USER" "$KEEPER_HOME"

# The uid every brokered command runs as.  No shell; a home because Ansible
# creates ~/.ansible/tmp unconditionally.  devwork so commands can run in the
# working tree and write to it -- what it must NOT be in is the broker's or the
# keeper's group, which is what the check below is for.
EXEC_HOME="${EXEC_HOME:-/var/lib/faramir-exec}"
say "user ${EXEC_USER} (executor, no login, home ${EXEC_HOME})"
if ! id -u "$EXEC_USER" >/dev/null 2>&1; then
  useradd -r -m -d "$EXEC_HOME" -G "$GROUP" -s /usr/sbin/nologin "$EXEC_USER"
else
  usermod -aG "$GROUP" "$EXEC_USER"
fi
install -d -m 0700 -o "$EXEC_USER" -g "$EXEC_USER" "$EXEC_HOME"
# Where SSH keys go when [ssh] keys is left empty.  Prefer listing them in
# [ssh] keys instead: the broker then holds them and hands the executor only an
# agent socket, so a brokered command can authenticate without being able to
# read, copy or exfiltrate a key that opens the whole fleet.
install -d -m 0700 -o "$EXEC_USER" -g "$EXEC_USER" "${EXEC_HOME}/.ssh"
for forbidden in "$BROKER_USER" "$KEEPER_USER"; do
  if id -nG "$EXEC_USER" 2>/dev/null | tr ' ' '\n' | grep -qx "$forbidden"; then
    say "WARNING: ${EXEC_USER} is in ${forbidden}; remove it, that is the boundary"
  fi
done

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
for profile in "${AGENT_HOME}/.bashrc" "$(getent passwd "$OPERATOR" | cut -d: -f6)/.bashrc"; do
  [[ -f $profile ]] || continue
  if ! grep -q '^umask 002' "$profile"; then
    say "umask 002 -> ${profile}"
    printf '\n# shared devwork tree: let group members edit each other'"'"'s files\numask 002\n' >>"$profile"
  fi
done

# 0755: the broker, the keeper and the agent all read config.toml from here, so
# the directory cannot belong to any one of them.  What protects the age key is
# its own mode (0400 ${KEEPER_USER}), not the directory it sits in.
install -d -m 0755 -o root -g root /etc/faramir
install -d -m 0750 -o "$BROKER_USER" -g "$BROKER_USER" /var/log/faramir

cat <<EOF

Phase 1 acceptance (run these):
  sudo -u ${AGENT_USER} cat /etc/faramir/age.key        -> Permission denied
  sudo -u ${BROKER_USER} cat /etc/faramir/age.key       -> Permission denied
  sudo -u ${EXEC_USER} cat /etc/faramir/age.key         -> Permission denied
  sudo -u ${EXEC_USER} cat /var/log/faramir/raw.log     -> Permission denied
  sudo -u ${AGENT_USER} ls ~${OPERATOR}/.ssh            -> Permission denied
  sudo -u ${AGENT_USER} touch ${WORKTREE}/.perm-check   -> succeeds
  sudo -u ${EXEC_USER} touch ${WORKTREE}/.perm-check    -> succeeds

Note: ${AGENT_USER} and ${OPERATOR} must log out and back in for the new group
membership to take effect.
EOF
