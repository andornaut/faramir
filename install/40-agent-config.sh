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
# WORKTREE is where the MCP registration and the CLAUDE.md snippet go.  It is
# passed in by the installer; the config no longer names a tree to fall back on,
# because a brokered command runs where its caller was rather than in one
# directory a config file chose.
WORKTREE="${WORKTREE:-/srv/faramir/worktree}"

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -n $OPERATOR && $OPERATOR != root ]] || {
  echo "set OPERATOR to the account the coding agent runs as" >&2; exit 1; }
[[ -n $OPERATOR_HOME ]] || { echo "no such user: $OPERATOR" >&2; exit 1; }
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

# install_settings <home> <owner>
#
# Keeps whatever it finds: a settings file is the operator's or the agent's to
# edit, and overwriting one loses hooks and permissions this project knows
# nothing about.  What it will not do is stay silent about a home whose settings
# do not register the hook, because that home is one where the redactor covers
# nothing the broker did not run itself.
install_settings() {
  local home="$1" owner="$2" settings="$1/.claude/settings.json" group
  # The primary group, which is only the username on distributions that make
  # per-user groups.  Where it is shared (users, staff), naming the user as the
  # group fails, and under set -e that aborts the phase.
  group="$(id -gn "$owner")"
  # Only created, never re-owned: an existing ~/.claude is the account's own,
  # and chowning or chmodding it here would rewrite whatever it had.
  [[ -d ${home}/.claude ]] || install -d -m 0700 -o "$owner" -g "$group" "${home}/.claude"
  if [[ ! -f $settings ]]; then
    install -m 0600 -o "$owner" -g "$group" "$REPO/agent/claude/settings.json" "$settings"
    say "settings + hook -> ${settings}"
    return
  fi
  install -m 0600 -o "$owner" -g "$group" \
    "$REPO/agent/claude/settings.json" "${settings}.dist"
  if grep -q faramir-guard "$settings"; then
    say "${settings} already registers the hook; wrote settings.json.dist beside it"
  else
    say "WARNING: ${settings} does not register faramir-guard."
    say "         Merge the hooks block from ${settings}.dist, or this account's"
    say "         commands run with nothing redacting their output."
  fi
}

say "settings + hook registration"
install_settings "$OPERATOR_HOME" "$OPERATOR"

if [[ -d $WORKTREE ]]; then
  say "MCP server registration -> ${WORKTREE}/.mcp.json"
  if [[ -f ${WORKTREE}/.mcp.json ]]; then
    say "keeping existing .mcp.json -- add the 'faramir' entry from agent/claude/mcp.json"
  else
    install -m 0664 -o "$OPERATOR" -g "${DEV_GROUP:-dev}" \
      "$REPO/agent/claude/mcp.json" "${WORKTREE}/.mcp.json"
  fi

  say "CLAUDE.md"
  if [[ -f ${WORKTREE}/CLAUDE.md ]] && grep -q faramir_run "${WORKTREE}/CLAUDE.md"; then
    say "CLAUDE.md already mentions faramir_run; leaving it alone"
  else
    cat "$REPO/agent/claude/CLAUDE.md.snippet" >>"${WORKTREE}/CLAUDE.md"
    chown "$OPERATOR:${DEV_GROUP:-dev}" "${WORKTREE}/CLAUDE.md"
  fi
else
  say "SKIP ${WORKTREE} (does not exist)"
fi

cat <<EOF

Phase 4 done.

The hook and the filesystem permissions are the enforcement layer; CLAUDE.md is
only there so the agent does not waste turns discovering the tool. Deleting
CLAUDE.md must not change what is reachable -- if it does, something above is
wrong.

Verify the hook fires:
  echo '{"tool_name":"Bash","tool_input":{"command":"printenv"}}' \\
    | /usr/local/libexec/faramir/faramir-guard
EOF
