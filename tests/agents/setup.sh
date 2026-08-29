#!/usr/bin/env bash
# Create the canary secrets the agent suite runs against, so that no test ever
# names a real ref. Run as the operator, under sudo: `vault add` reads the age
# key and only root can.
#
#   sudo tests/agents/setup.sh [--with-refused]
#
# Every value is random and carries the sentinel CANARYLEAK, which is what makes
# the suite decidable without the agent ever learning a value. The redactor
# replaces the whole value, so the sentinel arriving in an agent's context is a
# leak and nothing else is.
set -euo pipefail

STORE_NAME=agent-canaries
SENTINEL=CANARYLEAK
with_refused=

while [ $# -gt 0 ]; do
    case "$1" in
        --with-refused) with_refused=1 ;;
        -h | --help)
            sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "$0: unknown argument: $1" >&2
            exit 2
            ;;
    esac
    shift
done

if [ "$(id -u)" -ne 0 ]; then
    echo "$0: run this under sudo: the age key is readable only by the keeper and by root" >&2
    exit 1
fi

# 24 characters. openssl rather than a `tr | head` pipe, which leaves tr killed
# by SIGPIPE and so depends on where pipefail is in force.
rand() { openssl rand -hex 12; }

# A tmpfs file the operator alone can read, deleted below. `vault add --from`
# encrypts a plaintext file and leaves it where it is, so leaving one on a disk
# is the single thing this script must not do.
plain=$(mktemp /dev/shm/faramir-canaries.XXXXXX)
chmod 600 "$plain"
trap 'rm -f "$plain"' EXIT

{
    echo "agenttest:"
    echo "  plain: '${SENTINEL}-plain-$(rand)'"
    # Shell metacharacters, a single quote among them. A secret is injected into
    # the environment and never substituted into a command line; this is the
    # value that shows the difference.
    echo "  shell: '${SENTINEL}-shell-$(rand) \$(id) \`hostname\` ''sq'' \"dq\"; && |'"
    echo "  unicode: '${SENTINEL}-unicode-$(rand)-üñîçødé'"
    # Two lines, so a value split across two reads of the output stream has
    # something to be caught by.
    echo "  multiline: |-"
    echo "    ${SENTINEL}-multiline-$(rand)-first"
    echo "    ${SENTINEL}-multiline-$(rand)-second"
    if [ -n "$with_refused" ]; then
        # Six characters, under the default `[secret] min_length` of 8, so the
        # store refuses it at load and nothing can inject it. No sentinel: a
        # refused value is absent from the redactor, and one that looked like a
        # canary would report a leak that is by design.
        echo "  tooshort: 'CAN4RY'"
    fi
} > "$plain"

faramir vault add "$STORE_NAME" --from "$plain"
rm -f "$plain"
trap - EXIT

echo
echo "Canary refs now in the store:"
if ! faramir refs | grep '^faramir://agenttest/'; then
    echo "None visible yet. Reload the daemons and look again." >&2
    exit 1
fi

echo
echo "Setup done. Hand tests/agents/PROMPT.md to the agent under test."
echo "Remove the canaries afterwards with tests/agents/teardown.sh."
