#!/usr/bin/env bash
# Make one directory usable by brokered commands.  Not a numbered phase: run it
# per tree, whenever you want one, as root.
#
#   share-tree.sh ~/src/github.com/andornaut/ansible-ctrl
#
# Nothing here needs a tree of its own.  The managed sops files are under /etc
# and a brokered command runs where its caller was, so faramir names no
# directory anywhere.  What a tree does need, if commands are going to run in
# it, is two things this script does:
#
#   shared    the operator and a brokered command both write there, so the tree
#             is group-owned and setgid, which with umask 002 keeps them from
#             fighting over every file either one creates
#   reachable a home is 0700, so faramir-exec cannot enter a tree inside one
#             until it has execute access on every directory above it
#
# A tree outside the homes needs only the first, and gets it.
set -euo pipefail

OPERATOR="${OPERATOR:-${SUDO_USER:-}}"
GROUP="${DEV_GROUP:-dev}"
BROKER_USER="${BROKER_USER:-faramir-broker}"
EXEC_USER="${EXEC_USER:-faramir-exec}"

usage() {
  sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
  echo
  echo "usage: share-tree.sh <directory> [directory...]"
}

[[ $# -gt 0 ]] || { usage >&2; exit 2; }
case "$1" in -h|--help) usage; exit 0 ;; esac

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -n $OPERATOR && $OPERATOR != root ]] || {
  echo "set OPERATOR to the account that works in the tree" >&2; exit 1; }
getent group "$GROUP" >/dev/null || {
  echo "no such group: ${GROUP}; run install/10-accounts.sh first" >&2; exit 1; }

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }

OPERATOR_HOME="$(getent passwd "$OPERATOR" | cut -d: -f6)" || OPERATOR_HOME=""

# grant_traversal <tree>
#
# Execute-only, on every directory from the home down to the tree's parent.  Not
# "chmod o+x", which hands the same traversal to every account on the machine,
# including any service or container uid; the ACL names the accounts that have
# to have it and leaves "other" at nothing.  It grants no read: these uids pass
# through the home without being able to list it.
#
# The executor is the one that has to be here, since it forks the command in the
# tree.  The broker is granted alongside it only so an unreachable directory is
# reported clearly; it treats its own permission error there as the executor's
# business, so a home that will not take the second entry still works.
grant_traversal() {
  local tree="$1" component remainder acl_spec missing acl_now u
  local -a users=("$EXEC_USER" "$BROKER_USER")

  if ! command -v setfacl >/dev/null 2>&1; then
    say "WARNING: ${tree} is inside ${OPERATOR_HOME} and setfacl is missing."
    note "Install the acl package, or keep the tree outside the home:"
    note "${EXEC_USER} cannot reach it as things stand."
    return
  fi

  say "traversal for ${users[*]}: ${OPERATOR_HOME} -> ${tree}"
  acl_spec=""
  for u in "${users[@]}"; do acl_spec+="${acl_spec:+,}u:${u}:x"; done

  component="$OPERATOR_HOME"
  remainder="${tree#"${OPERATOR_HOME}"/}"
  while :; do
    # One call granting both.  On ecryptfs only the first write against an inode
    # lands, so two calls would drop the second account and report success.
    setfacl -m "$acl_spec" "$component" 2>/dev/null || true
    # Read back rather than trusting the exit status, for the same reason: that
    # filesystem returns 0 and changes nothing once a directory carries an ACL.
    missing=""
    acl_now="$(getfacl -p --omit-header "$component" 2>/dev/null || true)"
    for u in "${users[@]}"; do
      grep -q "^user:${u}:" <<<"$acl_now" || missing+="${missing:+ }${u}"
    done
    if [[ -n $missing ]]; then
      say "WARNING: ${component} did not take an ACL entry for ${missing}."
      note "setfacl reported success; the filesystem dropped it.  An ecryptfs"
      note "directory accepts one ACL and no edits, so this cannot be fixed in"
      note "place.  Either keep the tree outside the home, or give this one"
      note "directory 'chmod o+x' and accept that every uid can then traverse"
      note "it.  Note that with umask 002 in force the files below are mode"
      note "0664, so that opens the home rather than a path through it."
      break
    fi
    # Stop at the tree's parent: the tree itself is group-owned below, and every
    # directory before it needs traversal or the walk is pointless.
    [[ $remainder == */* ]] || break
    component="${component}/${remainder%%/*}"
    remainder="${remainder#*/}"
    [[ -d $component ]] || break
  done
}

for tree in "$@"; do
  [[ $tree = /* ]] || tree="$(cd "$(dirname "$tree")" && pwd)/$(basename "$tree")"

  install -d -m 2770 -o "$OPERATOR" -g "$GROUP" "$tree"
  say "shared ${tree} with ${GROUP}"
  chgrp -R "$GROUP" "$tree"
  chmod -R g+rwX "$tree"
  # setgid on every directory, so a file either the operator or a brokered
  # command creates stays readable and writable by the other.
  find "$tree" -type d -exec chmod g+s {} +

  if [[ -n $OPERATOR_HOME && $tree == "$OPERATOR_HOME"/* ]]; then
    grant_traversal "$tree"
  fi
done

cat <<EOF

Check it from the tree:
  cd ${1}
  faramir run -- pwd

A brokered command runs where its caller was, so that is the whole test: it
either reports this directory or names what it could not reach.
EOF
