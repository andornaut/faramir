# faramir

[![CI](https://github.com/andornaut/faramir/actions/workflows/release.yml/badge.svg)](https://github.com/andornaut/faramir/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A secrets broker for local AI coding agents: it runs the commands that need credentials and keeps the values out of the agent's context. Those commands run as a uid that holds nothing.

```console
$ faramir run --env ROUTER_PW=faramir://home/router/admin -- printenv ROUTER_PW
«SECRET:home/router/admin»
faramir run: redacted «SECRET:home/router/admin»×1; log_id=w5vq7dbf00002c
```

## Supported agents

Four get full redaction: what the agent runs in an enrolled project is rewritten into a brokered command, and its output comes back with every value replaced.

Agent | Registered in | Enrolment cost
--- | --- | ---
[Claude Code](https://claude.com/product/claude-code) | `PreToolUse` hook and MCP server in the tree; deny rules in `~/.claude/settings.json` | Bash is approved without asking, except what the deny list refuses. That list names credential disclosure and nothing destructive. [Cost per permission mode](docs/design.md#what-this-gives-up)
[opencode](https://open-code.ai/) | [`tool.execute.before` plugin](https://open-code.ai/en/docs/plugins) and `opencode.json` in the tree; deny patterns in `~/.config/opencode/opencode.json` | None: there is no allow to return, so a plugin that has not denied has not approved
[Kilo Code](https://kilo.ai/) | [Same plugin API](https://kilo.ai/docs/automate/extending/plugins) under `.kilo/plugin/`, loaded by the CLI and the VS Code extension; `kilo.json` and `~/.config/kilo/kilo.json` | Same as opencode
[Pi](https://pi.dev/) | [`tool_call` extension](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/extensions.md) under `.pi/extensions/`. Pi ships no MCP, so the extension registers the two tools itself | None. Project-local extensions load only once the project is trusted, so a tree Pi has not been trusted in is unguarded
[Antigravity](https://antigravity.google/) | MCP server in `.agents/mcp_config.json`; credentials section in `.agents/rules/faramir.md` and `~/.gemini/GEMINI.md` | None, and no redaction either. **Partial support**, see below

Choosing agents with `--agent`, repeatable on `init` and `init-project`:

- Names are `antigravity`, `claude`, `kilocode`, `opencode` and `pi`.
- The default is `auto`: whichever agents are already there, which `init` asks of your home and `init-project` of the tree.
- A name configures that agent regardless and composes, so `--agent auto --agent pi` is "whatever is installed, plus pi".
- Pi and Antigravity get no account-wide rule file. Pi has nowhere to put one, so the same rules are compiled into its extension; Antigravity's permission lists are the IDE's own state.

Each agent is also told what those rules refuse and why, in the file it reads for every project ([which file, per agent](docs/layout.md)).

> [!WARNING]
> **Antigravity is partial support.** [Its hooks](https://antigravity.google/docs/hooks) allow, deny or ask and cannot change a tool call's arguments, so there is nothing to rewrite a command with and nothing redacts what comes back. An enrolment leaves it the broker's tools and the instructions to use them; a command it runs itself reaches the model with the value in it. Enrolling one warns that this is what was installed.

## What it protects against

> [!IMPORTANT]
> The broker keeps plaintext out of model context. It does not contain a compromised agent.

**Acceptance invariant:** if every instruction the agent is given were deleted, no secret could reach the model provider. Every enforcement point is a uid boundary, a file mode, or a hook.

### Prevented

Failure | How
--- | ---
**Accidental disclosure.** `printenv`, a vault read, `-vvv`, a `debug: var=` task | No account can read the key material, yours included; output is redacted before the agent sees it
**Passive discovery.** Reading an age key, an SSH key, or a daemon's `/proc/<pid>/environ` | Uid separation plus `ProtectProc=invisible`. Named for the agent because that is who it holds against: two brokered commands share one uid and can read each other
**Casual prompt injection.** Instructions to print or exfiltrate credentials | The agent process never holds them
**Master key loss.** The master key decrypts every managed file retroactively | It lives in a uid that executes nothing; no brokered command can read it, reach the keeper's socket, or receive it in its environment

### Not prevented

Failure | Why
--- | ---
**Adversarial exfiltration.** Transforming a value (`\| rev`, `\| sha256sum`) defeats redaction | The child chooses the encoding of its own output, so the matcher cannot be completed
**Blast radius.** A brokered command runs anything the executor's uid can | Out of scope. That uid is the bound. With `--allow-sudo` it may also *ask* to become root, answered per command by a human
**Root persistence by the *approved* command** | Configuring a host and backdooring it are the same primitives. A *second, unapproved* command cannot ride the escalation, the broker serialising approved runs
**Every managed value, not only the injected ones.** `env_refs` scopes one command's environment, not what a brokered command can reach | The executor is in the client group, so a brokered command is itself a broker client: it can ask for a second command with any ref injected. Redaction still covers what comes back through the broker
**Network egress** | Out of scope. No iptables, namespaces or proxy allowlist
**Anything at rest** | The uid boundaries hold only while the machine runs; full-disk encryption is the measure. `--allow-sudo` mints no credential, so a stolen disk carries nothing that can sudo here
**Unenrolled projects.** The value set is global | A command in a project you never enrolled can print a managed value uncaught

## How it works

One binary. The daemons, the MCP server and the guard are subcommands of it, separated by the uid each unit runs its subcommand as.

uid | Runs | Holds
--- | --- | ---
you | the coding agent, and `faramir run` | nothing secret
`faramir-broker` | `faramir broker` | plaintext values in memory, SSH keys, and with `--allow-sudo` the pending questions
`faramir-exec` | `faramir exec` | nothing
`faramir-keeper` | `faramir keeper`, and nothing but sops | the age master key

One call, end to end:

1. The request reaches `/run/faramir/broker.sock` carrying a ref, never a value. `cmd` is an array; there is no allowlist.
2. The broker asks the keeper over a socket only it can open. The keeper execs sops and returns values; the key stays in that uid.
3. The broker creates a PTY, hands the slave to the executor over `/run/faramir/exec.sock`, and the executor forks the command as `faramir-exec`: value in the environment, never in `argv`.
4. Output returns through the broker's end of the PTY. Every managed secret becomes `«SECRET:ref»` before the agent sees a byte.
5. The audit log records what ran, against which refs, and what came back. Tokens only, operator-readable only.

**SSH keys** are held by the broker in an `ssh-agent` it owns; the child gets only `SSH_AUTH_SOCK`, so it can authenticate and cannot read a key. The broker relays, forwarding only `REQUEST_IDENTITIES` and `SIGN_REQUEST`. A brokered command may forward that relay onward with `ssh -A`.

**Allowing sudo** is off by default and adds no credential; see [below](#allowing-sudo-on-the-controller).

### Redaction

- The value set is **every managed secret**, not only the injected ones, so a host printing a credential nothing injected is still covered. A `[[secret.link]]` entry adds a credential another tool owns, read where that tool keeps it.
- Children run on a PTY, so programs behave normally and writes to `/dev/tty` are captured. The cost is that stdout and stderr arrive merged.
- ANSI escapes are stripped before matching; base64, base32, hex, URL, JSON and shell quoting are matched as encodings; a streaming overlap buffer catches a value split across reads.
- Tokens are stable, so the model can reason about a secret across turns.
- Two things are outside the value set: a value shorter than `[secret] min_length`, refused at load because it would match inside ordinary words, and the age key, which no child can obtain. `--allow-sudo` adds nothing, escalation minting no credential.

Detail in [docs/redaction.md](docs/redaction.md).

### The audit log

Every brokered command is recorded: what ran, against which refs, and what came back. The log holds tokens rather than values, is readable by the broker and root alone, and is logrotate's to bound.

- A brokered command writes two records under one `log_id`: `run_started` when the child runs, and `run` when it ends or when it never ran.
- A command that cannot be recorded does not run. The broker checks the log can be written before starting anything, and refuses with `no_audit`.

What a record is made of, and the rules a command does not state: [docs/operating.md](docs/operating.md).

## Installation

Requires [systemd](https://systemd.io/) and [sops](https://github.com/getsops/sops); Go to build. The binary is static, so the host needs no interpreter. The agent's session needs `XDG_RUNTIME_DIR`: the hook captures output before redacting it and will not write that anywhere another account can read, so a session without one refuses every Bash command.

```bash
make build
sudo ./bin/faramir init
```

`init` creates the accounts and groups, mints the age key, installs the binary, the deny list and the docs, renders the config and the systemd units, and starts the sockets. Idempotent, so it is also the upgrade, and it never migrates: it writes what this version wants and leaves an older layout's leftovers alone. A re-run with a flag left out keeps what the install already uses rather than reverting to the default.

Every flag, what a re-run adopts, and where the config directory may not go: [docs/installing.md](docs/installing.md).

### Checking an install

```bash
sudo faramir doctor
```

Reports whether the install is doing its job, and as root what each account can reach. Without root it still runs, reporting what it could not ask as unasked. What it checks, and how every command finds the install: [docs/operating.md](docs/operating.md).

## Usage

### Onboarding a project

1. Put the values in one sops file under `/etc/faramir/secrets`, named after what consumes them. The store is that directory, so a file put there is picked up on the next refresh (10 seconds by default).
2. Have the project read each credential from an environment variable rather than a file or a vault of its own. Most tools already work this way; Ansible needs `lookup('env', 'NAME')`.
3. Write the refs beside the project, one `NAME=faramir://ref` per line.
4. `cd <project> && sudo faramir init-project`. Shares the tree so a brokered command can run in it, and configures whichever agents it already carries.

Enrol the projects where managed credentials are in play, not every tree; `--hook=false` shares one without the hook. A brokered command runs where its caller was, so nothing needs a tree of its own.

```bash
faramir refs
faramir run --env TOKEN=faramir://svc/token -- printenv TOKEN   # -> «SECRET:svc/token»
```

#### With Ansible

```text
/etc/faramir/secrets/ansible-ctrl.sops.yml   the values, outside every checkout
group_vars/all/vars.yml                      committed: var -> lookup('env', 'NAME')
faramir.env                                  NAME=faramir://ref, one per line
```

`sudo faramir init-project` writes the agent configuration and shares the tree. The other three are yours to place, and none needs configuring. Walk-through: [docs/ansible-sops.md](docs/ansible-sops.md).

#### Other cases

Only step 3 differs.

What you are running | Step 3
--- | ---
A deploy or release script | Already reads `$TOKEN`. Nothing to change
A cloud or infra CLI (`aws`, `terraform`, `flyctl`) | Name its documented environment variables; drop the credentials file
A database task | `PGPASSWORD`, `MYSQL_PWD`. The connection string goes in `argv`, the password never does
A registry push | `bash -lc 'printf %s "$TOKEN" \| docker login -u me --password-stdin'`
An HTTP call | `curl -H "Authorization: Bearer $TOKEN"` inside `bash -lc`, so the shell expands it
A tool needing a credentials *file* | Have the command write it, use it, remove it. Injection is environment-only
A credential another tool already owns (`~/.npmrc`, `gh`) | Skip step 1. Link it instead of copying it in, so rotating it stays that tool's business: [linked secrets](docs/configuration.md#linked-secrets)
Something over SSH | Nothing for the value: `init` renders `[ssh] key` and the child gets `SSH_AUTH_SOCK`. Name the remote login, a bare `ssh host` asking for `faramir-exec`, and pin the host keys with `init --known-hosts`
Redaction only, no secret | Skip steps 3 and 4. `faramir redact -- ./script.sh`, or use it as a filter

- A pipeline is requested explicitly as `["bash", "-lc", "…"]`; the broker never hands a string to a shell.
- A bare command name is looked up on `[command.env] PATH`. Venv, pipx and shim directories belong there.
- Anything that wants to decrypt sops itself does not onboard. It gets named values instead.

### Running commands

```bash
faramir status                          # config path, sources, ref count
faramir refs                            # ref names, never values
faramir run --env NAME=faramir://ref -- CMD
faramir run --env-file deploy.env -- ansible-playbook site.yml
faramir run --quiet -C ~/src/project -t 120 -- CMD
kubectl get secret -o yaml | faramir redact
faramir redact -- ./deploy.sh
```

`faramir run` | Effect
--- | ---
`--env NAME=faramir://ref` | Once per secret
`--env-file FILE` | `NAME=faramir://ref` per line, `#` comments
`--quiet` | Suppress the redaction summary on stderr. Not why a `sudo` was refused: that is printed either way, being what says whether running the command again is worth anything
`--cwd`/`-C`, `--timeout`/`-t` | Working directory, runtime ceiling
`--socket`, `--json` | On every broker-facing command

- The child's exit code is faramir's own. A broker that is not running exits 69 (`EX_UNAVAILABLE`).
- **`faramir redact` writes nothing it could not redact**, in either shape. A chunk the broker cannot cover is withheld, the stream stops there, and the exit status is non-zero: for `-- CMD` the child's own status when it failed, else 1. Chunks already redacted are kept, so a broker lost mid-stream truncates rather than empties.
- Both `--env` and `--env-file` refuse a literal value and a name that cannot be an environment variable. One file refuses a name given twice with different refs; across sources a later `--env-file` beats an earlier one, and `--env` beats both. A bad line is reported with file and line, and the offending value never appears.

### Allowing sudo on the controller

A brokered command runs as `faramir-exec`, which has no sudo, so a playbook that also configures the controller has to leave it out with `--limit '!controller'`. `sudo faramir init --allow-sudo` closes that split: no password, a PAM service that asks the broker, and one question per run answered by `sudo faramir approve ID`. An approved command gets real root and can make it permanent, so approving is trusting *that command* with permanent root.

- How to run it: [docs/operating.md](docs/operating.md#allowing-sudo-on-the-controller)
- Why it is shaped this way: [docs/design.md](docs/design.md#allowing-sudo-on-the-controller)
- With Ansible: [docs/ansible-sops.md](docs/ansible-sops.md#4-becoming-root-on-the-controller)

### Operator commands

**Every operator command is refused to the coding agent's shell**, with sudo and without. An agent may run `run`, `redact`, `status` and `refs`; the rest act on the install rather than through it.

Group | Commands
--- | ---
The install | `init`, `init-project`, `doctor`, `reload`, `uninstall`
The managed store | `vault add`, `vault ls`, `vault rm`, `vault edit`
Who can decrypt it | `recipient add`, `recipient rm`, `recipient ls`, `recipient reseal`
A secret another tool owns | `link add`, `link rm`, `link ls`
The record, and sudo | `logs`, `escalations`, `approve`, `deny`

All need root except `doctor`, which degrades, and the two that only read: `recipient ls` and `link ls`. What each does, and which ops are root-only at the broker: [docs/operating.md](docs/operating.md).

### MCP tools

Tool | Parameters
--- | ---
`faramir_run` | `cmd` (array, required), `env_refs`, `cwd`, `timeout_sec`
`faramir_refs` | none. Ref names only, and where `faramir_run`'s `env_refs` come from

Two, and meant to stay two: a tool is for what an agent has to be told, everything else is a subcommand. Pi registers the same two from its extension. Wire protocol: [docs/protocol.md](docs/protocol.md).

## Configuration

Settings live in `<config-dir>/config.toml`, which `init` rewrites on every run from [etc/config.toml.tmpl](etc/config.toml.tmpl). It is faramir's file: change a value with the flag that sets it, and a re-run keeps what it finds.

There is no command allowlist. A brokered command is bounded by the executor's uid, then by `[command.env] PATH`, `[command] max_timeout_sec`, the output cap and `[secret] min_length`. Reference: [docs/configuration.md](docs/configuration.md).

## Documentation

Doc | Covers
--- | ---
[docs/ansible-sops.md](docs/ansible-sops.md) | Pointing `group_vars` at the environment
[docs/configuration.md](docs/configuration.md) | Every setting, which flag sets it, what `--check` fails on
[docs/design.md](docs/design.md) | Why the agent runs as the operator, how the rewrite works, what enrolment costs
[docs/installing.md](docs/installing.md) | Every `init` flag, what a re-run adopts, where the config directory may not go
[docs/layout.md](docs/layout.md) | Every path the install creates, with its mode and owner
[docs/operating.md](docs/operating.md) | Checking an install, every operator command, [the rules a command does not state](docs/operating.md#rules-a-command-does-not-state), adding an age recipient
[docs/protocol.md](docs/protocol.md) | Request and response shapes on the socket
[docs/redaction.md](docs/redaction.md) | What the redactor covers, and what it cannot

## Developing

Target | Does
--- | ---
`make build` | A static binary into `bin/`
`make test` | The whole suite. Needs no sops installed
`make coverage` | Race-enabled suite plus per-function report
`make fmt` | Apply the import and format rules CI checks
`make lint` | `golangci-lint`
`make shellcheck` | The shell scripts, as CI checks them
`make e2e` | The functional suites against a real install in a container
`make check` | The linters, the whole Go suite, and the end-to-end suites
`make install`, `make uninstall` | Copy the binary to `/usr/local/bin` and remove it. Both use sudo

- Everything under `systemd/`, `etc/`, `agent/` and `docs/` is embedded into the binary by `assets.go`, so `init` installs a host without a checkout, and the `.tmpl` files are the shipped files themselves. That decides where a new document goes: operator documentation in `docs/`, which ships, and developer documentation at the root, which does not.
- Tests live where the logic does. Most of what the broker does is decide, so `internal/server` substitutes the executor; `internal/executor` uses a real child, the PTY and the streaming redactor meaning nothing against synthetic bytes.
- The Go suite runs under one uid, so it never covers the uid boundary. That is real only on a host, which is what `sudo faramir doctor` and [tests/e2e](tests/e2e/README.md) are for. Adversarial exfiltration is asserted nowhere, as [Not prevented](#not-prevented) says.
- The tests need cgroup v2 with `cgroup.kill` (kernel 5.14 or newer) and a cgroup the test process can subdivide, every brokered command being confined to its own. `make test` supplies one with `systemd-run --user --scope`; without it a couple of dozen tests skip, so the run ends by naming what it did not check. On a runner with no such scope, delegate a cgroup first, as [the test workflow](.github/workflows/test.yml) does. cgroup v1 is unsupported.
- The suite needs no `sops` on `PATH`: `internal/sopstest` builds a stand-in from the sops libraries, imported only from `_test.go`. CI fails the build on a `getsops` import reaching `./cmd/faramir`.
- The opencode and Kilo Code plugins are the only shipped logic that is not Go, so node drives the shipped file against a stand-in guard, covering the rewrite, the refusal, a tool that is not a shell, and each way of failing closed. Skipped where node is absent. No test covers a running opencode or Kilo Code, or Bun.
