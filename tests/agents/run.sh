#!/usr/bin/env bash
# Run the agent self-test under one coding agent, or under all of them, headless.
#
#   tests/agents/run.sh <agent|all> <enrolled-tree>
#
# The tree is an argument because it is the operator's real project and this
# repository does not name it. Reports and transcripts land in $OUT, one pair per
# agent: the report is what the agent wrote, the log is everything it printed.
#
# The model is pinned per agent rather than left to each agent's own
# configuration, so that a report says something about faramir and not about
# whichever model that agent happened to be set to. See modelfor.
set -uo pipefail

AGENTS="agy claude codex kilo opencode pi"

# How long one agent gets. The suite asks for 40 to 60 cases, and the runs that
# finished took twelve to twenty minutes, so this is headroom over a working run
# rather than a target. What it is really for is the other end: an agent that
# wedges holds a slot until something stops it, and in an `all` run six start at
# once. agy is given the same figure through its own flag, its default being 90
# minutes, which is long enough to spend an afternoon producing nothing.
TIMEOUT=${FARAMIR_AGENT_TIMEOUT:-30m}

# Reports live outside /tmp/faramir-agent-test-*, which is the scratch namespace
# every agent is told to delete at the end of its run and which teardown.sh
# removes wholesale. A report directory inside it is deleted by the first agent
# to finish, taking the other five with it.
OUT=${FARAMIR_AGENT_OUT:-/tmp/faramir-agent-reports}

usage() {
    echo "usage: $0 <${AGENTS// /|}|all> <enrolled-tree>" >&2
    exit 2
}

[ $# -eq 2 ] || usage
slug=$1
tree=$2
[ -d "$tree" ] || {
    echo "$0: not a directory: $tree" >&2
    exit 2
}
# Both paths are made absolute here and used absolute everywhere after, because
# `one` runs with the tree as its working directory: a relative $OUT would write
# half the output into the tree that headless.md declares read-only, and a
# relative tree handed to `opencode --dir` would resolve against itself.
tree=$(cd -- "$tree" && pwd) || exit 2
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
mkdir -p "$OUT" || exit 2
OUT=$(cd -- "$OUT" && pwd) || exit 2

# modelfor names the model each agent runs under, overridable per agent with
# FARAMIR_AGENT_MODEL_<SLUG>. Anthropic, OpenAI, Google and OpenRouter.
#
# Not the strongest each agent can reach. Three Opus runs cost more than a round
# is worth, so only claude carries one, as the anchor a cheaper report is read
# against. What a cheap model costs instead is confabulation: rows that were
# reasoned rather than run. PROMPT.md answers that with a rule rather than a
# model, and a surprising row still wants checking against the host.
#
# The names are not interchangeable between agents, and each was checked against
# the agent that takes it, with a question whose answer was not in the prompt:
#
#   agy       offers no Opus, and takes a reasoning level as part of the name
#   codex     runs against a ChatGPT account, which serves `gpt-5.6-terra` and
#             refuses every other 5.6 spelling tried: sol, sol-pro, terra-pro,
#             luna-pro. Verify a model with a question whose answer is not in
#             the prompt: codex echoes the prompt, so asking it to reply with a
#             fixed word matches that echo and every model looks supported
#   pi        reaches a provider only through OpenRouter, so the name carries
#             that prefix
#   kilo      answers PAID_MODEL_AUTH_REQUIRED for its own `kilo/` provider,
#             which is a separate sign-in from the OpenRouter one it does hold.
#             So the openrouter/ spelling works where the kilo/ spelling of the
#             same model does not
modelfor() {
    local slug=$1 override
    override=FARAMIR_AGENT_MODEL_${slug^^}
    if [ -n "${!override:-}" ]; then
        echo "${!override}"
        return
    fi
    case $slug in
    agy) echo gemini-3.7-flash-high ;;
    claude) echo claude-opus-5 ;;
    codex) echo gpt-5.6-terra ;;
    kilo) echo openrouter/google/gemini-3.7-flash ;;
    opencode) echo openrouter/google/gemini-3.7-flash ;;
    pi) echo openrouter/google/gemini-3.7-flash ;;
    esac
}

# one runs a single agent, in the tree, with the flags that agent needs to work
# unattended. Every one of these was arrived at by watching a run fail without
# it, so none of them is decoration:
#
#   opencode, kilo   auto-reject every permission request without --auto, and
#                    the run ends on the first tool call
#   agy              gives up at --print-timeout, five minutes by default,
#                    so it is given $TIMEOUT there as well as around it
#   codex            has to be unsandboxed, or the guard's rewrite cannot run
#   claude           has no prompt to answer in print mode, so the permission
#                    mode is the whole of its configuration here
one() {
    local slug=$1 tree=$2 prompt=$3
    local report=$OUT/$slug.md log=$OUT/$slug.log
    local model rc
    model=$(modelfor "$slug")

    # A previous run's report left in place would be read as this one's, so it
    # goes before the run rather than after it, the log being truncated anyway.
    rm -f "$report"
    echo "=== $slug: starting $(date -Is) on $model ===" >"$log"
    cd "$tree" || return 1
    case $slug in
    agy) timeout "$TIMEOUT" agy -p "$prompt" --model "$model" --dangerously-skip-permissions --print-timeout "$TIMEOUT" >>"$log" 2>&1 ;;
    claude) timeout "$TIMEOUT" claude -p "$prompt" --model "$model" --permission-mode bypassPermissions >>"$log" 2>&1 ;;
    codex) timeout "$TIMEOUT" codex exec --dangerously-bypass-approvals-and-sandbox -m "$model" "$prompt" >>"$log" 2>&1 ;;
    kilo) timeout "$TIMEOUT" kilo run --auto -m "$model" "$prompt" >>"$log" 2>&1 ;;
    opencode) timeout "$TIMEOUT" opencode run --auto --dir "$tree" -m "$model" "$prompt" >>"$log" 2>&1 ;;
    pi) timeout "$TIMEOUT" pi -p --model "$model" "$prompt" >>"$log" 2>&1 ;;
    *)
        echo "$0: unknown agent: $slug" >&2
        return 2
        ;;
    esac
    rc=$?
    # 124 is what `timeout` returns when it fired, which is worth saying: an
    # agent that buffers its output prints nothing when killed, so a truncated
    # run and a broken one leave the same empty log. collect.sh reads this line
    # to tell those apart, so the wording is not free to change.
    if [ "$rc" -eq 124 ]; then
        echo "=== $slug: killed at the $TIMEOUT timeout ===" >>"$log"
    fi
    echo "=== $slug: exit $rc at $(date -Is) ===" >>"$log"

    # The exit code is not the verdict. agy, codex and pi have each returned 2
    # from a run that finished and wrote a full report, so what says a run
    # succeeded is a report, and the code goes in the log for whoever reads it.
    #
    # claude, agy and pi print nothing until they finish, so a run killed part
    # way leaves the log empty and the report file is all there is. codex,
    # opencode and kilo stream, so for those the log is the fuller record.
    if [ ! -s "$report" ]; then
        echo "($slug wrote no report; $slug.log is all there is)" >"$report"
    fi
    return "$rc"
}

# The prompt is the committed plan plus the headless conditions plus the two
# facts that differ per agent. Built once per agent so each gets a body that
# differs only in those two facts.
promptfor() {
    local slug=$1
    # PROMPT.md's own placeholder as well as headless.md's. It is written for a
    # reader who picks their own name, and an unattended agent given the file
    # verbatim takes "<you>" for the name: six of them then share one scratch
    # path and one cleanup glob, which is the collision the placeholder exists to
    # prevent.
    sed "s|<you>|$slug|g" "$here/PROMPT.md"
    printf '\n---\n\n'
    sed "s|AGENTSLUG|$slug|g" "$here/headless.md"
    # The backticks are markdown the agent reads, not command substitution, so
    # the format string stays single-quoted and the values arrive through %s.
    # shellcheck disable=SC2016
    printf '\nYour agent slug is `%s`. Write your report to `%s`.\n' "$slug" "$OUT/$slug.md"
    # shellcheck disable=SC2016
    printf '\nThe faramir repository, holding `tests/agents/canary.env`, is at\n`%s`. Your working directory is the enrolled tree, `%s`,\nand that is where the testing happens.\n' \
        "$(cd "$here/../.." && pwd)" "$tree"
}

if [ "$slug" = all ]; then
    for a in $AGENTS; do
        one "$a" "$tree" "$(promptfor "$a")" &
    done
    wait
    echo
    echo "reports in $OUT. Read them with:"
    echo "    $here/collect.sh $OUT"
    exit 0
fi

case " $AGENTS " in
*" $slug "*) ;;
*) usage ;;
esac
one "$slug" "$tree" "$(promptfor "$slug")"
