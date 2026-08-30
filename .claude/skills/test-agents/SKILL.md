---
name: test-agents
description: Run faramir's agent suite (tests/agents/run.sh) across every coding agent against an enrolled tree, then read the round with collect.sh and summarize it. Invoke when the user asks to run the agent tests, run a full agent test, run all agents, or summarize an agent round.
---

# test-agents - Run faramir's agent suite across every agent

Asking to run the agent tests is the instruction to do this work. Do not ask
whether to proceed.

`tests/agents/README.md` says what the suite is, what each agent needs, and how
to read what it produces. Read it first. This file is the procedure only.

## Hard constraints

- **Never name a real ref.** The four `agenttest/` canaries are the only refs a
  test may name, and a canary value is never read, quoted or written anywhere.
- **Never run `setup.sh` or `teardown.sh` yourself.** Both are the operator's,
  under sudo. Ask, and say what for.
- **Never block the foreground on a run.** Use `run_in_background`, then do
  other work: a round takes 20 to 30 minutes.
- **Never write the enrolled tree's path into anything committed.** It is an
  argument for the same reason.

## 1. Preflight

```sh
faramir status | head -40                 # build, and the canaries are loadable
faramir refs | grep agenttest             # four refs
git -C <tree> status --porcelain          # the tree the agents will read
pgrep -af 'tests/agents/run.sh'           # another session's round
git log --oneline -1                      # what the round is a round of
```

| Check | What to do about it |
| --- | --- |
| `status.build` behind `git log -1` | The round tests the installed build, not HEAD. Say so and ask before running |
| Fewer than four `agenttest/` refs | Ask the operator to run `sudo tests/agents/setup.sh` |
| Another round in flight | Stop. Two rounds share `$FARAMIR_AGENT_OUT` and one deletes the other's reports |
| The tree is dirty | Fine, and worth a line in the summary |

Archive the previous round, which the run would otherwise overwrite:

```sh
mv /tmp/faramir-agent-reports /tmp/faramir-agent-reports.prev-$(date +%m%d-%H%M)
```

## 2. Run

```sh
tests/agents/run.sh all <enrolled-tree>
```

An agent that dies in the first minute has hit its provider rather than
faramir, which the README's model section covers. Once the provider side is
fixed, re-run that one alone: it writes only its own pair, so it can run beside
the rest of the round.

```sh
tests/agents/run.sh <agent> <enrolled-tree>
```

Substituting a model changes what the report says something about, so put the
substitution to the operator rather than choosing one.

## 3. Collect

```sh
tests/agents/collect.sh
```

## 4. Report

Check a surprising row against the host before repeating it, for the reason
under "What a run produces".

- The leak scan's verdict, first and plainly. It is the only thing that gates.
- Per agent: rows, pass and fail counts, and the state where it produced none.
- The new findings, marking which you verified against the host and which are
  the agent's own reading.
- Rows already in `settled.txt`, as a count.
- What the round could not cover: section G, and any agent that did not run.

Findings are not fixes. Report them and stop, unless asked for more.

## 5. Recommend

Every round ends with recommendations, in three groups:

| Group | Drawn from | What a good item says |
| --- | --- | --- |
| Fixes | The `FAIL` rows | The file, the change, and what else that change touches |
| Friction | The `FRICTION` rows and any row that cost a turn | What would have let the agent do the same work without the extra turn, and whether refusing it was right |
| Settled gaps | The rows `settled.txt` claimed | Which accepted behaviour is still costing turns, and what would close it without weakening a rule |

The agents are asked for these themselves, from what they already did rather
than from anything they research: their reports carry a recommendations section
and an answer per verdict. Read those before writing your own, say where they
agree, and say plainly where you checked one against the host and it did not
hold. An agent's proposed cause is a hypothesis: verify the mechanism before
repeating it, because a report can be right that something happened and wrong
about why.

Recommendations are not a licence to implement. Put them to the operator.
