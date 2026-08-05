#!/usr/bin/env bash
# Phase 6 -- register the broker with the agent account.
#
# Installs into ~agent/.claude, owned by agent.  Deliberately NOT a bind mount
# or symlink of the operator's ~/.claude: a session that can write agent config
# paths can persist hooks or MCP servers that run under different privileges on
# the next launch.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT_USER="${AGENT_USER:-agent}"
AGENT_HOME="$(getent passwd "$AGENT_USER" | cut -d: -f6)"
WORKTREE="${WORKTREE:-${AGENT_HOME}/work/ansible-ctrl}"

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -n $AGENT_HOME ]] || { echo "no such user: $AGENT_USER" >&2; exit 1; }
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

say "settings + hook registration -> ${AGENT_HOME}/.claude/settings.json"
install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_USER" "${AGENT_HOME}/.claude"
if [[ -f ${AGENT_HOME}/.claude/settings.json ]]; then
  say "existing settings.json found; writing settings.json.dist instead -- merge by hand"
  install -m 0600 -o "$AGENT_USER" -g "$AGENT_USER" \
    "$REPO/agent/claude/settings.json" "${AGENT_HOME}/.claude/settings.json.dist"
else
  install -m 0600 -o "$AGENT_USER" -g "$AGENT_USER" \
    "$REPO/agent/claude/settings.json" "${AGENT_HOME}/.claude/settings.json"
fi

if [[ -d $WORKTREE ]]; then
  say "MCP server registration -> ${WORKTREE}/.mcp.json"
  if [[ -f ${WORKTREE}/.mcp.json ]]; then
    say "keeping existing .mcp.json -- add the 'secretd' entry from agent/claude/mcp.json"
  else
    install -m 0664 -o "$AGENT_USER" -g "${DEVWORK_GROUP:-devwork}" \
      "$REPO/agent/claude/mcp.json" "${WORKTREE}/.mcp.json"
  fi

  say "CLAUDE.md"
  if [[ -f ${WORKTREE}/CLAUDE.md ]] && grep -q secure_run "${WORKTREE}/CLAUDE.md"; then
    say "CLAUDE.md already mentions secure_run; leaving it alone"
  else
    cat "$REPO/agent/claude/CLAUDE.md.snippet" >>"${WORKTREE}/CLAUDE.md"
    chown "$AGENT_USER:${DEVWORK_GROUP:-devwork}" "${WORKTREE}/CLAUDE.md"
  fi
else
  say "SKIP ${WORKTREE} (does not exist)"
fi

cat <<EOF

Phase 6 done.

The hook and the filesystem permissions are the enforcement layer; CLAUDE.md is
only there so the agent does not waste turns discovering the tool. Deleting
CLAUDE.md must not change what is reachable -- if it does, something above is
wrong.

Verify the hook fires:
  echo '{"tool_name":"Bash","tool_input":{"command":"printenv"}}' \\
    | /usr/local/libexec/secretd/pretooluse-guard.py
EOF
