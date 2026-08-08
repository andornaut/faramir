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
#   group dev            shared access to the repo working tree
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

# Where brokered commands run, and the only thing that still needs a tree: the
# secrets moved to /etc/faramir/secrets, so neither the keeper nor the broker
# reads a working tree any more.  A tree inside a home is fine here, because the
# executor forks a command only after its caller asked for one, by which point
# the caller has logged in and the home is mounted.
WORKTREE="${WORKTREE:-/srv/faramir/worktree}"

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

# The working tree.  Owned by the operator, who works in it; group dev because
# brokered commands run here, and the operator and a brokered command have to be
# able to edit each other's files.  The managed sops files are not here: they
# are in /etc/faramir/secrets, which the keeper and the broker reach through the
# same group but by their own path.
#
# It does not have to sit outside the homes, but it does have to be reachable by
# two uids that are not the operator's.  A home is 0700, so a tree inside one is
# unreachable until those uids are given traversal, which is what the ACL below
# is for.  Outside the homes (the default) nothing is needed.
install -d -m 2770 -o "$OPERATOR" -g "$GROUP" "$WORKTREE"
say "shared working tree ${WORKTREE}"
chgrp -R "$GROUP" "$WORKTREE"
chmod -R g+rwX "$WORKTREE"
# setgid on every directory, so a file either the operator or a brokered command
# creates stays readable and writable by the other.
find "$WORKTREE" -type d -exec chmod g+s {} +

# A tree inside the operator's home needs the executor and the broker to be able
# to walk down to it.  The executor forks the command there; the broker stats
# the requested cwd before accepting the request, and traversal is exactly what
# a stat on a path inside a 0700 home requires.  The keeper is the one account
# that needs nothing: it reads the sops files from /etc/faramir/secrets and its
# unit sets ProtectHome=true.
#
# An ACL naming those uids rather than "chmod o+x": the mode bit would hand
# traversal to every account on the machine, including any service or container
# uid, where the ACL grants it to exactly the accounts that have to have it and
# leaves "other" at nothing.
#
# Traversal only, never read: it passes through the home without being able to
# list it.  Note this is a permission, not a mount: it holds nothing open, so an
# encrypted home still unmounts at logout.  What does hold one open is a
# brokered command that is running at the time.
OPERATOR_HOME="$(getent passwd "$OPERATOR" | cut -d: -f6)" || OPERATOR_HOME=""
if [[ -n $OPERATOR_HOME && $WORKTREE == "$OPERATOR_HOME"/* ]]; then
  # The executor is the one that has to be here: it forks the command in this
  # directory.  The broker is granted alongside it only so that an unreachable
  # cwd is reported clearly; it treats its own permission error there as the
  # executor's business, so a home that will not take the second entry still
  # works.  The keeper needs none of it: its files are under /etc and its unit
  # sets ProtectHome=true.
  TRAVERSE_USERS=("$EXEC_USER" "$BROKER_USER")
  if ! command -v setfacl >/dev/null 2>&1; then
    say "WARNING: ${WORKTREE} is inside ${OPERATOR_HOME} and setfacl is missing."
    say "         Install the acl package, or move the tree outside the home:"
    say "         the broker and the executor cannot reach it as things stand."
  else
    say "traversal for ${TRAVERSE_USERS[*]}: ${OPERATOR_HOME} -> ${WORKTREE}"
    # Every component from the home down to the tree's parent.  The tree itself
    # is group-owned above, so it needs nothing here.
    component="$OPERATOR_HOME"
    remainder="${WORKTREE#"${OPERATOR_HOME}"/}"
    acl_spec=""
    for u in "${TRAVERSE_USERS[@]}"; do acl_spec+="${acl_spec:+,}u:${u}:x"; done
    while :; do
      # One setfacl call granting both, because on ecryptfs only the first write
      # against an inode lands: two calls would leave the second account out.
      setfacl -m "$acl_spec" "$component" 2>/dev/null || true
      # Read it back rather than trusting the exit status.  On ecryptfs setfacl
      # returns 0 and does nothing whenever the directory already carries an
      # ACL: the first write lands, every later one is silently dropped, and
      # even -b does not clear it.  A grant that cannot be corrected, reported
      # as success, is how a service ends up unable to read a file that
      # everything says it should.
      missing=""
      acl_now="$(getfacl -p --omit-header "$component" 2>/dev/null || true)"
      for u in "${TRAVERSE_USERS[@]}"; do
        grep -q "^user:${u}:" <<<"$acl_now" || missing+="${missing:+ }${u}"
      done
      if [[ -n $missing ]]; then
        say "WARNING: ${component} did not take an ACL entry for ${missing}."
        say "         setfacl reported success; the filesystem dropped it."
        say "         An ecryptfs directory accepts one ACL and no edits, so"
        say "         this cannot be fixed in place.  Either put the tree"
        say "         outside the home, or give this one directory"
        say "         'chmod o+x' and accept that every uid can then traverse"
        say "         it.  Nothing below is reachable that its own mode does"
        say "         not already allow."
        break
      fi
      # Stop at the tree's parent: the tree itself is group-owned above, and
      # every component before it needs traversal or the walk is pointless.
      [[ $remainder == */* ]] || break
      component="${component}/${remainder%%/*}"
      remainder="${remainder#*/}"
      [[ -d $component ]] || break
    done
  fi
fi

# Without umask 002 the operator and a brokered command fight over every new
# file in the tree.  This is the single most likely thing to make an operator
# abandon the setup.
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
  sudo -u ${EXEC_USER} touch ${WORKTREE}/.perm-check    -> succeeds

The coding agent runs as ${OPERATOR}: there is no account of its own, and no
boundary around it.  What the boundaries below still hold is the age key and the
values decrypted from it, which ${OPERATOR} cannot read either.

Note: ${OPERATOR} must log out and back in for the new group membership to take
effect.
EOF
