#!/usr/bin/env python3
"""PreToolUse hook: deny Bash commands that would put a secret in the context.

This is an enforcement layer that also teaches.  A deterministic block plus a
corrective message that names ``faramir_run`` changes behaviour far more
reliably than prose in a config file -- and unlike prose, it still works if the
model never reads CLAUDE.md.

It is *not* the security boundary.  The agent uid cannot read the age key, the
SSH keys, or the broker's ``/proc`` entries no matter what this hook does; if
this file were deleted, no secret could still reach the model provider.  What
the hook buys is a useful error instead of a confusing one, and a context
window that does not fill up with encrypted blobs.

Reads the hook payload on stdin, writes a PreToolUse decision on stdout.
"""

from __future__ import annotations

import json
import os
import re
import sys

# Next to the hook rather than under /etc/faramir: this runs as the agent uid,
# which cannot traverse /etc/faramir (0750 faramir-broker:faramir-broker).  A patterns file
# the hook cannot read is worse than no patterns file, because the fallback
# below is silently weaker.
PATTERNS_FILE = os.environ.get(
    "FARAMIR_DENY_PATTERNS", "/usr/local/libexec/faramir/deny-patterns.txt"
)

# Used if the patterns file is missing, so a broken install still fails closed.
# Keep this in step with agent/hooks/deny-patterns.txt: a fallback that is
# weaker than the shipped list turns an install problem into a silent gap.
FALLBACK = [
    r"ansible-vault\s+(view|decrypt|edit|rekey)",
    r"\bsops\s+(decrypt|-d|--decrypt|-i\s+.*-d)",
    r"\bage\s+(-d|--decrypt)",
    r"\bage-keygen\b",
    r"\bop\s+read\b",
    r"\bpass\s+show\b",
    r"\bgopass\s+show\b",
    r"\bvault\s+(read|kv\s+get)\b",
    r"\bprintenv\b",
    r"\benv\b(?!.*\|)",
    r"\bset\s*$",
    r"\bdeclare\s+-x\b",
    r"/proc/\d+/environ",
    r"/proc/self/environ",
    r"\b(cat|less|more|head|tail|bat|xxd|od|strings)\b.*"
    r"(vault|secrets?\.|\.env|age\.key|id_[re]d?sa|\.pem\b|credentials)",
    r"\b(cat|less|more|head|tail)\b.*/etc/faramir",
    r"\bfind\b.*-name.*(age\.key|\.env|id_rsa)",
    r"/var/log/faramir",
    r"\bjournalctl\b.*faramir",
    r"\bsudo\b.*(\bfaramir-(broker|keeper|exec)\b|-u\s+faramir)",
]

ADVICE = (
    "Blocked: this command would put a credential (or an encrypted blob) into "
    "the conversation, where it would be sent to the model provider.\n\n"
    "Use the faramir_run tool instead — it runs the command as a separate uid "
    "that holds the keys and returns output with secrets replaced by "
    "«SECRET:ref» tokens. Secrets are named, never pasted:\n\n"
    "    faramir_run(cmd=[\"printenv\", \"ROUTER_PW\"],\n"
    "                env_refs={\"ROUTER_PW\": \"secret://home/router/admin\"})\n\n"
    "Call faramir_list_secrets to see the available names. You do not need the "
    "value of a secret to use it, and you will not be given one."
)


def load_patterns() -> list[tuple[str, re.Pattern[str]]]:
    try:
        with open(PATTERNS_FILE, encoding="utf-8") as fh:
            raw = [
                line.strip()
                for line in fh
                if line.strip() and not line.lstrip().startswith("#")
            ]
    except OSError:
        raw = FALLBACK
    out = []
    for pattern in raw:
        try:
            out.append((pattern, re.compile(pattern, re.IGNORECASE)))
        except re.error:
            continue  # a typo in the list must not disable the whole hook
    return out


def command_of(payload: dict) -> str:
    tool_input = payload.get("tool_input") or {}
    parts = [tool_input.get("command") or ""]
    # Some clients send argv arrays; check those too.
    argv = tool_input.get("args")
    if isinstance(argv, list):
        parts.extend(str(a) for a in argv)
    return " ".join(p for p in parts if p)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0  # never block on a payload we do not understand

    if payload.get("tool_name") not in ("Bash", "BashOutput"):
        return 0

    command = command_of(payload)
    if not command:
        return 0

    # faramir is the sanctioned path; do not match patterns inside it.  Stop at
    # the first separator: anything past it is a separate command that the
    # prefix does not sanction, and consuming it would let `faramir status;
    # printenv` through untouched.
    stripped = re.sub(
        r"(?:^|(?<=[;&|\n]))\s*(sudo\s+)?faramir\b[^;&|\n]*", "", command
    )

    for pattern, compiled in load_patterns():
        if compiled.search(stripped):
            json.dump(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": (
                            f"{ADVICE}\n\n(matched deny pattern: {pattern})"
                        ),
                    }
                },
                sys.stdout,
            )
            sys.stdout.write("\n")
            return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
