#!/usr/bin/env bash
# Remove the canary secrets tests/agents/setup.sh created, and the files a run
# leaves in /tmp. Run as the operator, under sudo.
#
#   sudo tests/agents/teardown.sh
#
# Safe to run twice: a store file that is not there is reported and not an
# error. It removes one file, agent-canaries.sops.yml, and never touches another
# in the store.
set -euo pipefail

STORE_NAME=agent-canaries

if [ "$(id -u)" -ne 0 ]; then
    echo "$0: run this under sudo" >&2
    exit 1
fi

# --force: the canaries are worthless by construction, and a teardown that stops
# on a prompt leaves them served.
faramir vault rm --force "$STORE_NAME" || true

remaining=$(faramir refs | grep '^faramir://agenttest/' || true)
if [ -n "$remaining" ]; then
    echo "$0: canary refs are still served:" >&2
    echo "$remaining" >&2
    echo "Reload the daemons and look again." >&2
    exit 1
fi

# What a run is told to write, and nowhere else. A canary the agent wrote out
# and did not clean up is a plaintext file, worthless but still one.
rm -f /tmp/faramir-agent-test-*
echo "Canaries removed. /tmp/faramir-agent-test-* cleaned up."
