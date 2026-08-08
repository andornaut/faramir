#!/usr/bin/env bash
# Phase 4 -- register the broker with the account the coding agent runs as.
#
# That account is the operator's own.  The hook it installs is what redacts the
# output of everything the agent runs, so a session without it is a session
# where only brokered commands are covered.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The account the coding agent runs as.  SUDO_USER by default: a phase run by
# hand with sudo is being run by that account.
OPERATOR="${OPERATOR:-${SUDO_USER:-}}"
# getent exits 2 for a missing account, and pipefail would abort here before
# the check below could report it.
OPERATOR_HOME="$(getent passwd "$OPERATOR" | cut -d: -f6)" || OPERATOR_HOME=""
# No tree is enrolled here.  Enrolment is per project and is two file copies,
# so a phase that blesses one directory would only be picking a favourite: the
# recipe is printed at the end instead.

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -n $OPERATOR && $OPERATOR != root ]] || {
  echo "set OPERATOR to the account the coding agent runs as" >&2; exit 1; }
[[ -n $OPERATOR_HOME ]] || { echo "no such user: $OPERATOR" >&2; exit 1; }
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

# Two scopes, because the two things installed here do not have the same cost.
#
# The Read deny rules go in the operator's home: they refuse to open key
# material wherever the agent is working, and they take nothing away, so there
# is no reason to make a project opt into them.
#
# The hook goes in the project.  It rewrites every Bash command so the output
# can be redacted, and a rewritten command cannot be matched by any Bash
# permission rule, so the hook approves what its deny list did not refuse.  For
# that project, Bash is auto-approved.  That is worth it where managed
# credentials are in play and is not worth it everywhere, which is the whole
# reason it is a per-project decision rather than an account-wide one.
#
# Both keep whatever they find: a settings file is the operator's to edit, and
# overwriting one loses hooks and permissions this project knows nothing about.

# install_settings <dir> <owner> <source> <label>
install_settings() {
  local dir="$1" owner="$2" source="$3" label="$4" settings="$1/.claude/settings.json" group
  # The primary group, which is only the username on distributions that make
  # per-user groups.  Where it is shared (users, staff), naming the user as the
  # group fails, and under set -e that aborts the phase.
  group="$(id -gn "$owner")"
  # Only created, never re-owned: an existing .claude is the account's own, and
  # chowning or chmodding it here would rewrite whatever it had.
  [[ -d ${dir}/.claude ]] || install -d -m 0700 -o "$owner" -g "$group" "${dir}/.claude"
  if [[ ! -f $settings ]]; then
    install -m 0600 -o "$owner" -g "$group" "$source" "$settings"
    say "${label} -> ${settings}"
    return
  fi
  install -m 0600 -o "$owner" -g "$group" "$source" "${settings}.dist"
  say "keeping existing ${settings}; wrote settings.json.dist beside it to merge"
}

say "Read deny rules -> operator's home"
install_settings "$OPERATOR_HOME" "$OPERATOR" "$REPO/agent/claude/settings.json" "deny rules"

# An install from before the hook moved has it in the home, where it covers
# every project including the ones that never opted in.  Left in place it keeps
# working, so this reports it rather than editing a file the operator owns.
if [[ -f ${OPERATOR_HOME}/.claude/settings.json ]] &&
   grep -q faramir-guard "${OPERATOR_HOME}/.claude/settings.json"; then
  say "NOTE: ${OPERATOR_HOME}/.claude/settings.json registers faramir-guard."
  say "      That is the old account-wide arrangement: it redacts everywhere,"
  say "      and auto-approves Bash everywhere with it.  The hook is now"
  say "      installed per project instead.  Remove the hooks block there to"
  say "      get Bash permissions back outside the projects that opted in."
fi

cat <<EOF

Phase 4 done.  The Read deny rules are installed; no project is enrolled yet.

Enrol one, and understand what it costs: in an enrolled project every Bash
command is redacted, and every Bash command is auto-approved, because a
rewritten command matches no permission rule and the deny list becomes the only
thing that refuses one.  Projects you do not enrol keep their Bash prompts and
get no redaction.

  cd <project>
  install -d -m 0700 .claude
  cp ${REPO}/agent/claude/settings.project.json .claude/settings.json
  cp ${REPO}/agent/claude/mcp.json .mcp.json
  cat ${REPO}/agent/claude/CLAUDE.md.snippet >>CLAUDE.md

The hook and the filesystem permissions are the enforcement layer; the agent
instructions are only there so it does not waste turns discovering the tool.
Deleting them must not change what is reachable -- if it does, something above
is wrong.

Verify the hook fires:
  echo '{"tool_name":"Bash","tool_input":{"command":"printenv"}}' \\
    | /usr/local/libexec/faramir/faramir-guard
EOF
