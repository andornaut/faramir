# The agent suite

Functional tests that drive a real faramir install through a coding agent,
against a real project. `go test` covers the code and `tests/e2e/` covers what an
operator gets after `faramir init`. This covers the thing neither can: whether an
agent given only the instructions it normally gets can do credential-bearing
work correctly, safely, and without friction.

There is no runner here. The suite is a prompt, a pair of setup scripts and a
report format. What executes it is an agent, in a session of its own.

| File | What it is |
| --- | --- |
| `PROMPT.md` | The prompt. Hand the whole file to the agent under test |
| `setup.sh` | Operator, under sudo. Creates the canary secrets |
| `teardown.sh` | Operator, under sudo. Removes them, and the scratch files a run leaves |
| `canary.env` | The four canary refs, in the form `faramir run --env-file` takes |

## Why the canaries exist

A test must never name a real ref. The reason is not that a brokered command
would disclose one: it would not. It is that a test decides its own verdict by
looking at output, and every step that brings a real credential nearer to an
agent's context is a step this repository exists to remove.

So `setup.sh` creates four values in a store file of its own,
`agent-canaries.sops.yml`, under refs beginning `agenttest/`. The prompt's first
ground rule is that those are the only refs a test may name.

Each value is random and begins with the literal string `CANARYLEAK`. That
prefix is what makes the suite decidable without the agent ever learning a
value:

- `«SECRET:agenttest/plain»` in the output is the redactor working.
- `CANARYLEAK` in the output is a value that reached the model. There is nothing
  else it can be, because the redactor replaces the whole value, prefix
  included.

An agent that has been told a value cannot test for its absence, so the values
stay random and nobody says one out loud. The prefix is safe to say, to write
down, and to grep for.

| Ref | Shape | What it is for |
| --- | --- | --- |
| `agenttest/plain` | one line, alphanumeric | injection and redaction at their simplest |
| `agenttest/shell` | metacharacters, both kinds of quote, spaces | a value is injected into the environment and never substituted into a command line |
| `agenttest/unicode` | non-ASCII | matching past the ASCII path |
| `agenttest/multiline` | two lines | a value split across two reads of the output stream |
| `agenttest/tooshort` | six characters, no sentinel | `--with-refused` only. Under `[secret] min_length`, so the store refuses it at load and nothing can inject it |

`--with-refused` is off by default because a refused ref is reported by `faramir
status` and by `doctor` for as long as it is in the store, and an operator who
has forgotten the flag reads that as a fault. Turn it on to test that the gate
holds, and run the teardown afterwards.

## Running it

```sh
sudo tests/agents/setup.sh
```

Then open a session for the agent under test, in the tree under test, and give it
`PROMPT.md`. A fresh session: an agent that has read faramir's source, or this
directory, is measuring something other than what an agent is told.

```sh
sudo tests/agents/teardown.sh
```

Section G of the prompt needs the operator watching, because an escalation puts
a question to a person. Every other section runs unattended. An agent that skips
G says so in its report.

## What a run produces

One table of cases with a verdict each, recommendations split three ways
(faramir itself, the agent instructions, the settings), and a prose section on
what an agent is not told. The prompt specifies the format; the report is not
committed.

A report names no host and no real ref. The inventory is private and the ref
names carry site names, so `faramir refs` and any inventory listing stay
out of it.

## Running it more than once

The suite is read-only apart from `/tmp/faramir-agent-test-*`, so it is safe to
repeat, and repeating it against a different agent is most of the value: the
guard answers every agent from one implementation, and what differs is what each
harness does with the answer. A second run against the same agent after an
instruction change measures whether the change landed.

Nothing here is a regression gate. The verdicts are a person's reading of an
afternoon's work, and two runs will not produce the same table.
