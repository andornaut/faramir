#!/usr/bin/env bash
# Phase 1 -- accounts and repo permissions.
#
# This is the part that actually protects the secrets.  Everything later is
# ergonomics and blast-radius reduction on top of uid separation.
#
#   uid <operator>       runs the coding agent; member of group dev
#   uid faramir-keeper   holds the age key; execs nothing but sops
#   uid faramir-broker   holds the SSH keys and the audit log; policy+redaction
#   uid faramir-exec     forks brokered commands; holds nothing
#   group dev            shared access to a tree brokered commands run in
#
# Three uids rather than one because anything a uid can read, a command running
# as that uid can read.  The keeper's key and the broker's audit log and SSH
# keys each sit behind a boundary the child cannot cross.
#
# All three service accounts join dev.  The keeper decrypts the sops files in
# /etc/faramir/secrets and the broker stats them there, both of which the group
# grants; brokered commands run wherever their caller was, which is what the
# executor needs it for.  That is access to files the operator already owns; it
# is not access to anything the operator could not reach themselves.  The
# boundaries that matter are file modes, not this group.
set -euo pipefail

OPERATOR="${OPERATOR:-${SUDO_USER:-$(id -un)}}"
BROKER_USER="${BROKER_USER:-faramir-broker}"
KEEPER_USER="${KEEPER_USER:-faramir-keeper}"
EXEC_USER="${EXEC_USER:-faramir-exec}"
GROUP="${DEV_GROUP:-dev}"

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

say "group ${GROUP}"
getent group "$GROUP" >/dev/null || groupadd "$GROUP"

# No account for the coding agent.  It runs as the operator, because the work it
# is asked to do is the operator's: their checkouts, their gh credential, their
# commits.  A separate uid could reach none of that, and every route to giving
# it access ends up handing it the operator's files by another name.
#
# What that gives up is a kernel boundary around the agent process, and what
# replaces it is not a weaker version of the same thing: the secrets this
# project exists to protect are behind the keeper and the broker, which the
# operator's uid cannot read either.  See docs/scope.md.

# The broker needs a real, writable home: it holds the SSH keys used to reach
# managed hosts, and Ansible insists on creating ~/.ansible/tmp.  Under /var/lib
# rather than /home because that is where a service account's state belongs, and
# because the unit grants itself that path with StateDirectory=.
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
# executes a command.  dev only so sops can read the encrypted files in
# /etc/faramir/secrets; the key itself is 0400 and in no group at all.
KEEPER_HOME="${KEEPER_HOME:-/var/lib/faramir-keeper}"
say "user ${KEEPER_USER} (keeper, no login, home ${KEEPER_HOME})"
if ! id -u "$KEEPER_USER" >/dev/null 2>&1; then
  useradd -r -m -d "$KEEPER_HOME" -G "$GROUP" -s /usr/sbin/nologin "$KEEPER_USER"
else
  usermod -aG "$GROUP" "$KEEPER_USER"
fi
install -d -m 0700 -o "$KEEPER_USER" -g "$KEEPER_USER" "$KEEPER_HOME"

# The uid every brokered command runs as.  No shell; a home because Ansible
# creates ~/.ansible/tmp unconditionally.  dev so commands can run in the
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

# Without umask 002 the operator and a brokered command fight over every new
# file in a shared tree.  This is the single most likely thing to make an
# operator abandon the setup, and it is here rather than in `faramir share-tree`
# because it is a property of the account, not of any one directory.
profile="$(getent passwd "$OPERATOR" | cut -d: -f6)/.bashrc"
if [[ -f $profile ]] && ! grep -q '^umask 002' "$profile"; then
  say "umask 002 -> ${profile}"
  printf '\n# shared dev tree: let group members edit each other'"'"'s files\numask 002\n' >>"$profile"
fi

# 0755: the broker, the keeper and the agent all read config.toml from here, so
# the directory cannot belong to any one of them.  What protects the age key is
# its own mode (0400 ${KEEPER_USER}), not the directory it sits in.
install -d -m 0755 -o root -g root /etc/faramir

# The managed sops files.  Configuration an operator authors and the daemons
# read at startup, which is what /etc is for, and outside every home so the
# broker comes up with a full value set at boot rather than an empty one.
#
# 2770 root:${GROUP}: the operator edits these with sops and the keeper decrypts
# them, both through the group and neither needing sudo.  setgid so a file
# either of them creates stays readable by the other.  The ciphertext's own mode
# is 0640; what keeps it secret is the age key, which is not here.
install -d -m 2770 -o root -g "$GROUP" /etc/faramir/secrets
install -d -m 0750 -o "$BROKER_USER" -g "$BROKER_USER" /var/log/faramir

cat <<EOF

Phase 1 acceptance (run these):
  sudo -u ${BROKER_USER} cat /etc/faramir/age.key       -> Permission denied
  sudo -u ${EXEC_USER} cat /etc/faramir/age.key         -> Permission denied
  sudo -u ${EXEC_USER} cat /var/log/faramir/audit.log   -> Permission denied
  sudo -u ${EXEC_USER} ls ~${OPERATOR}                  -> Permission denied

The coding agent runs as ${OPERATOR}: there is no account of its own, and no
boundary around it.  What the boundaries below still hold is the age key and the
values decrypted from it, which ${OPERATOR} cannot read either.

No tree is shared here.  Nothing needs one: the managed sops files are under
/etc and a brokered command runs where its caller was.  To run commands in a
tree that is inside ${OPERATOR}'s home, give the executor a path to it:

  faramir share-tree <directory>

Note: ${OPERATOR} must log out and back in for the new group membership to take
effect.
EOF
