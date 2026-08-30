# faramir

[![Release](https://github.com/andornaut/faramir/actions/workflows/release.yml/badge.svg)](https://github.com/andornaut/faramir/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/license/MIT)

A secrets broker for AI coding agents: it runs the commands that need credentials and keeps the values out of the agent's context. Those commands run as a uid that holds nothing.

```console
$ faramir run --env ROUTER_PW=faramir://home/router/admin -- printenv ROUTER_PW
«SECRET:home/router/admin»
faramir run: redacted «SECRET:home/router/admin»×1; log_id=w5vq7dbf00002c
```

> [!IMPORTANT]
> **One install per host, and it serves one operator.** Every member of the client group is the same caller to the broker: one value set, one SSH key, one executor uid, one `agent_user` on every record. A second operator needs a second host.

## Supported agents

All seven get full redaction: what the agent runs is rewritten into a brokered command, and its output comes back with every value replaced. `faramir init` installs that everywhere the agent works, except on Claude Code and Codex, where routing costs a permission and so is taken one tree at a time.

Agent | Registered in | Enrolment cost
--- | --- | ---
[Antigravity CLI](https://antigravity.google/docs/cli/) (`agy`) | `PreToolUse` hook in `~/.gemini/config/hooks.json`; deny rules in `~/.gemini/antigravity-cli/settings.json`; credentials section in `.agents/rules/faramir.md`, the tree's own `AGENTS.md` and `~/.gemini/GEMINI.md` | None: the permission check runs before the hook, so the guard's allow approves nothing that was going to prompt
[Antigravity IDE](https://antigravity.google/) | The same hook and the same prose. No account-wide rule file: the hook refuses its file tools instead | None
[Claude Code](https://claude.com/product/claude-code) | Deny rules and a deny-only `PreToolUse` hook in `~/.claude/settings.json`; the routing hook and a credentials section in `CLAUDE.md` in the tree | Bash is approved without asking, except what the deny list refuses. That list names credential disclosure and nothing destructive. [Cost per permission mode](docs/coding-agents.md#claude-code)
[Codex](https://developers.openai.com/codex/cli/) | A deny-only `PreToolUse` hook in `~/.codex/hooks.json`; the routing hook in `.codex/hooks.json` and a credentials section in `AGENTS.md` in the tree | The same as Claude Code, and only where Codex is run with approvals on. It has no rule file an install can write, so that hook is what refuses its file tools, `apply_patch` included
[Kilo Code](https://kilo.ai/) | [`tool.execute.before` plugin](https://kilo.ai/docs/automate/extending/plugins) in `~/.config/kilo/plugin/`, loaded by the CLI and the VS Code extension; deny patterns in `~/.config/kilo/kilo.json` | None: there is no allow to return, so a plugin that has not denied has not approved
[opencode](https://open-code.ai/) | [The same plugin API](https://open-code.ai/en/docs/plugins) in `~/.config/opencode/plugin/`; deny patterns in `~/.config/opencode/opencode.json` | Same as Kilo Code
[Pi](https://pi.dev/) | [`tool_call` extension](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/extensions.md) in `~/.pi/agent/extensions/` | None. Installed in a home rather than a tree, which Pi loads for every project without the project being trusted

Choosing agents with `--agent`, repeatable on `init` and `init-project`:

- Names are `agy`, `antigravity`, `claude`, `codex`, `kilocode`, `opencode` and `pi`. `agy` is the Antigravity CLI and `antigravity` the IDE; they share one tree enrolment, so naming either writes the same files.
- The default is `auto`: whichever agents are already there, which `init` asks of your home and `init-project` of the tree. Codex is asked of your home either way, a tree carrying nothing of its own for it.
- A name configures that agent regardless and composes, so `--agent auto --agent pi` is "whatever is installed, plus pi".
- Claude Code and the Antigravity CLI are the only two that refuse a path from a rule file of their own. Pi and the Antigravity IDE have none an install can write; Codex has none either, its own `.rules` files being an exec policy that decides commands and names no path; and opencode's and Kilo Code's are not refusals: an entry of `deny` is put to the operator as a prompt, and an autonomous run approves it. So faramir refuses those five itself, from the plugin, the extension or the hook, and the Antigravity CLI is refused twice.

Each agent is also told what those rules refuse and why, in the file it reads for every project ([which file, per agent](docs/layout.md)). What each agent gets, feature by feature, is [the table in docs/coding-agents.md](docs/coding-agents.md#what-each-agent-gets); what each contract makes of the rewrite is the rest of that page.

> [!NOTE]
> **Antigravity is covered by its hooks.** [Its `PreToolUse` hook](https://antigravity.google/docs/hooks) returns `overwrite`, a shallow merge into the tool call's own arguments whose merged form is what runs, so a command is routed through the broker and comes back redacted. The same hook refuses a file tool that names key material, which is what covers the IDE: its permission lists are its own state rather than a file an install can write, so there are no deny rules to fall back on there. The CLI has both.
>
> `faramir init` writes that hook into `~/.gemini/config/hooks.json`, which both halves read for every workspace, so a tree nobody enrolled is covered too. No hook goes into a tree.
>
> What an enrolment writes into a *tree* is the credentials section, which for Antigravity means `.agents/rules/faramir.md` as well as the tree's own file. Both load a tree's customizations only once that tree is a project they have opened, so until then that file is there and inert, which enrolling says. The hook is not conditional on it.

One agent needs something from you before any of this holds.

> [!IMPORTANT]
> **Codex has two conditions faramir cannot meet for you.** It skips a hook it has not been told to trust and says nothing when it does, so what `faramir init` writes is inert until you start Codex once and trust it. And it must run without its own sandbox (`codex --dangerously-bypass-approvals-and-sandbox`): sandboxed, it is refused the broker socket, and the wrapper fails closed, so every command's output is withheld rather than redacted. Both commands say so on every run. The detail is in [coding-agents.md](docs/coding-agents.md#codex).

## What it protects against

> [!IMPORTANT]
> The broker keeps plaintext out of model context. It does not contain a compromised agent.

**Acceptance invariant:** if every instruction the agent is given were deleted, no secret could reach the model provider. Every enforcement point is a uid boundary, a file mode, or a hook.

### Prevented

Failure | How
--- | ---
**Accidental disclosure.** `printenv`, a vault read, `-vvv`, a `debug: var=` task | No account can read the key material, yours included; output is redacted before the agent sees it, whichever command printed it
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
**Credentials faramir does not manage.** An SSH private key, a `.pem`, a `.env`, an `~/.aws/credentials` | The deny rules cover this install's own paths. Anything faramir does not write is yours to declare with [`faramir block`](docs/configuration.md#blocked-paths), and an install that declares none refuses none

## How it works

One binary. The daemons and the guard are subcommands of it, separated by the uid each unit runs its subcommand as. The agent reaches the broker through that same binary: there is no server to register and nothing to install per project for it.

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
- Children run on a PTY, so programs behave normally, and they get no controlling terminal, so `/dev/tty` cannot be opened at all: a prompt that would have gone there falls back to stderr, which the redactor is reading. The cost is that stdout and stderr arrive merged.
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

### Pre-compiled binary

Archives are published on the
[releases page](https://github.com/andornaut/faramir/releases): one per tagged
version, plus a `dev` release rebuilt on every push to `main`. Linux only, since
the broker reads peer credentials with `SO_PEERCRED` and the executor allocates
PTYs with `TIOCGPTN`.

Platform | Asset
--- | ---
Linux x86_64 | `faramir_linux_x86_64.tar.gz`
Linux arm64 | `faramir_linux_arm64.tar.gz`

The archive carries `LICENSE` and `README.md` alongside the binary, so name the
binary rather than extracting everything into the current directory. `init`
installs it, so there is nothing to copy into place first:

```bash
tar -xzf faramir_linux_x86_64.tar.gz faramir
sudo ./faramir init
```

### Compile from source

```bash
make build
sudo ./bin/faramir init
```

### What init does

`init` creates the accounts and groups, mints the age key, installs the binary, the deny list and the docs, renders the config and the systemd units, and starts the sockets. It is idempotent, so it is also the upgrade, and a re-run with a flag left out keeps what the install already uses rather than reverting to the default.

Every flag, what a re-run adopts, and where the config directory may not go: [docs/installing.md](docs/installing.md).

## Getting Started

A bare host to a redacted command, in six steps. Each names the section that carries the detail.

1. **Install the binary**, from [an archive](#pre-compiled-binary) or [a build](#compile-from-source). `init` puts it in `/usr/local/bin` itself, so there is nothing to copy into place first.
2. **Provision the host** with `sudo faramir init`. It creates the accounts, mints the age key, renders the config and the units, and starts the sockets. [What it does](#what-init-does), and [every flag](docs/installing.md).
3. **Check it** with `sudo faramir doctor`. It reports whether the install is doing its job, and as root what each account can reach. Without root it still runs, reporting what it could not ask as unasked rather than as passing. [What it checks](docs/operating.md#checking-an-install).
4. **Name what this machine should block.** A fresh install refuses its own files and nothing else, so your SSH key is readable by your agent until you say otherwise. [Below](#naming-what-this-machine-should-block).
5. **Enrol a project** with `cd <project> && sudo faramir init-project`, in the trees where managed credentials are in play rather than in every tree. [What an enrolment writes, and the three steps before it](#onboarding-a-project).
6. **Run something.** `faramir refs` names what the broker serves, and `faramir run` is how a command receives one:

```bash
faramir refs
faramir run --env TOKEN=faramir://svc/token -- printenv TOKEN   # -> «SECRET:svc/token»
```

### Naming what this machine should block

**A fresh install blocks its own files and nothing else.** Everything under `<config-dir>`, the managed store, `/var/log/faramir`, `/usr/local/libexec/faramir` and the three service accounts' directories, at the paths this host uses. That is the whole of it: faramir does not guess at what else you keep, so `~/.ssh`, `~/.gnupg` and `~/.aws/credentials` are refused to your agent only once you say so.

Say so once, in one command. This one is deliberately broad: delete the lines that do not apply to this machine, and add the ones that do.

```bash
sudo faramir block add \
    --path ~/.ssh --path ~/.gnupg --path ~/.aws \
    --path ~/.config/sops/age --path ~/.age \
    --path ~/.local/share/keyrings --path ~/.netrc \
    --command 'op read' --command 'pass show'
```

Two forms, each named by its own flag, and they mix in one command. Neither is the default, so a bare argument is refused rather than read as a path.

**Name the directory, not the files in it.** `--path ~/.ssh` refuses every key under it, including the one named `identity` and whatever an `IdentityFile` line points at. A list of file names covers the ones you thought of.

Your agent's shell is refused a declared path named at all. `--strict` says the same of a **brokered** command, which is otherwise still allowed to change the file where it stands:

```bash
sudo faramir block add --path ~/.private --strict
```

That covers `ls` and `chmod` as well as `cat`, so nothing converges the path any more. It is the wrong flag for a key something has to rotate, which is why it is off unless you ask.

Form | Blocks | Matched against
--- | --- | ---
`--path` | one file or directory on this host, and everything under it | the path as written, so it is absolute and in its shortest form
`--command` | what may not be run, written as it would be typed | where a command starts, so `grep` naming one is left alone

A path reaches the agent's file tools and its shell alike; a command is nothing a file tool can name, so it reaches the shell. **The broker holds the same entries**, so a brokered command cannot print a declared file either, that being the one route no rule file reaches. It also refuses a brokered command that names one of faramir's own directories, an approved escalation running as root, where a file mode refuses nothing. The two sides answer differently. Your agent's shell is refused a declared path named at all, whatever the command would do with it. A brokered command is refused the ones that would print the file, and left alone otherwise, moving it and writing over it included: it has to be able to *use* a credential, and the programs that read one without printing it are not a list anybody could finish. [How that line falls](docs/configuration.md#the-brokered-route).

`faramir block ls` lists everything in force, the rules faramir carries itself included. It is one of the three operator commands that need no root, beside `reader ls` and `link ls`.

A fleet declares these where it declares everything else: every `block` command is idempotent and reports what changed with `--json`, so a configuration manager can name the whole list on every converge. [What each form matches, and what a wide one costs](docs/configuration.md#blocked-paths).

## Usage

### Onboarding a project

1. **Write the values**, one file per thing that consumes them. `sudo faramir vault add NAME` creates `NAME.sops.yml` in the secrets directory, taking the content from an editor faramir picks, on a `0600` file in a tmpfs, so no plaintext reaches a disk. That editor runs as root over the decrypted value, so what runs has to be a program no account but root can change: `--editor`, `$VISUAL` and `$EDITOR` each name one by absolute path with no arguments, and each is held to that check ([how the editor is chosen](docs/operating.md#choosing-the-editor)). Nothing restarts: the next refresh picks the file up. A credential another tool already owns is [linked](docs/integrations.md#linking-a-credential-another-tool-owns) instead of copied in.
2. **Have the project read each credential from an environment variable** rather than a file or a vault of its own. Most tools already work this way; Ansible needs `lookup('env', 'NAME')`.
3. **Write the refs beside the project**, one per line, in a file that holds refs and never values: [the two line forms](docs/integrations.md#onboarding-in-three-steps).
4. **`cd <project> && sudo faramir init-project`.** Shares the tree so a brokered command can run in it, and configures whichever agents it already carries.

`faramir init` installs the guard into the agent's home, where it holds in every directory: a command the deny list names is refused wherever the agent is working, which is what a `[[secret.block]]` entry is for. An enrolment adds the credentials section to the tree's own instructions file, and to a file of its own for the two agents that read a name that is not it ([which name](docs/layout.md)), and shares the tree so the broker's account can reach it. For Claude Code it also registers the routing hook, that being the one agent where routing costs a permission and so the one thing still taken tree by tree.

What to run in one: [below](#running-commands).

Per-tool recipes, the `faramir link` types and selectors, SSH keys, and a worked Ansible example: [docs/integrations.md](docs/integrations.md).

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
`--env NAME=faramir://ref` | Once per secret, or a bare `NAME` meaning `faramir://NAME`
`--env-file FILE` | `NAME=faramir://ref` per line, or a bare `NAME` meaning `faramir://NAME`. `#` starts a comment, at the start of a line or after whitespace
`--quiet` | Suppress the redaction summary on stderr. Only that: why a `sudo` was refused is printed either way, and so is every note saying the output is not what the command produced, truncation among them
`--cwd`/`-C` | Where the command runs. A relative path is resolved against the caller's directory, which is also the default
`--timeout`/`-t` | How long before the broker kills it: a duration (`90s`, `5m`) or a bare number of seconds, in whole seconds. Defaults to `[command] timeout_sec`, and `max_timeout_sec` is the ceiling
`--json` | The raw response, on every broker-facing command but `redact`, whose output is the redaction itself

- `--stdin`/`-i` sends what you pipe in to the command, up to 128 KiB; more than that is refused rather than cut, and a larger input belongs in a file the command opens itself. Without the flag a pipeline is refused rather than dropped: `faramir run` does not own the file on its own standard input, so a `while read ... done < hosts.txt` loop and an `ssh host 'faramir run …'` session keep theirs.
- Flags after the program name are the program's own: parsing stops at the first non-flag word, so a `--` still works and is not required.
- The child's exit code is faramir's own. A run whose exit status was lost keeps its output and reports a non-zero stand-in code, saying so on stderr. A broker that is not running exits 69 (`EX_UNAVAILABLE`), and one at its concurrency limit exits 75 (`EX_TEMPFAIL`), which is the one refusal that the same request survives a moment later. A program that is not there exits 127 and one that is there and cannot be run exits 126, which is what a shell gives for each. Every other refusal exits 1, and a usage error exits 2.
- **`faramir redact` writes nothing it could not redact**, in either shape. A chunk the broker cannot cover is withheld, the stream stops there, and the exit status is non-zero: for `-- CMD` the child's own status when it failed, else 1. Chunks already redacted are kept, so a broker lost mid-stream truncates rather than empties.
- Both `--env` and `--env-file` refuse a literal value and a name that cannot be an environment variable. A name given twice with different refs is refused, within a file, across files, and across `--env` flags, the bare and the mapping form counting as the same name; `--env` still overrides `--env-file`. A bad line is reported with file and line, and the offending value never appears. A bare name is held to both rules, so a word that is not a usable variable name or not a ref a store can hold is refused where it is written rather than becoming a ref nothing serves.

### Allowing sudo on the controller

A brokered command runs as `faramir-exec`, which has no sudo, so a playbook that also configures the controller has to leave it out with `--limit '!controller'`. `sudo faramir init --allow-sudo` closes that split: no password, a PAM service that asks the broker, and one question per run answered by `sudo faramir sudo approve ID`. An approved command gets real root and can make it permanent, so approving is trusting *that command* with permanent root.

**Works with either sudo.** Ubuntu ships two from 25.10 on, and `init` probes the `sudo` alternatives group and writes the arrangement that sudo can read. It needs `sudo` 1.9.11 or `sudo-rs` 0.2.9, and writes nothing if the host is older. What each arrangement touches: [the two sudos](docs/escalation.md#the-two-sudos).

- How to run it: [docs/escalation.md](docs/escalation.md)
- Why it is shaped this way: [docs/design.md](docs/design.md#allowing-sudo-on-the-controller)
- With Ansible: [docs/integrations.md](docs/integrations.md#becoming-root-on-the-controller)

### Operator commands

**Every operator command that changes the install or needs root is refused to the coding agent's shell**, with sudo and without. The four that only describe it are not: [which commands, and what each does](docs/operating.md#operator-commands).

Group | Commands
--- | ---
The install | `doctor`, `init`, `init-project`, `reload`, `uninstall`
The managed store | `vault add`, `vault edit`, `vault ls`, `vault rm`
Who can decrypt it | `reader add`, `reader ls`, `reader reseal`, `reader rm`
A secret another tool owns | `link add`, `link ls`, `link rm`
A path, name or command blocked from the agent | `block add`, `block ls`, `block rm`
The record, and sudo | `logs`, `sudo approve`, `sudo ls`, `sudo reject`, `sudo watch`

`init`, `init-project` and the four `link` and `block` edits are idempotent and report what changed with `--json`, so a configuration manager can name every entry on every run.

### What the agent runs

Command | What it is for
--- | ---
`faramir run --env NAME=faramir://ref -- program args` | Runs the command with the value injected, and returns its output with each one replaced by `«SECRET:ref»`
`faramir refs` | The names that exist, values never. Where `run`'s `--env` refs come from

These two are how a value reaches a command; `redact`, `status`, `version`, `help` and `completion` are open to the agent as well, and every other subcommand acts on the install and is the operator's. There is nothing to register: the binary is installed for the account, so the route is the same in every directory on the host, enrolled or not. Wire protocol: [docs/protocol.md](docs/protocol.md).

## Configuration

Settings live in `<config-dir>/config.toml`, which `init` rewrites on every run from [etc/config.toml.tmpl](etc/config.toml.tmpl). It is faramir's file: change a value with the flag that sets it, and a re-run keeps what it finds.

There is no command allowlist. A brokered command is bounded by the executor's uid, then by `[command.env] PATH`, `[command] max_timeout_sec`, the output cap and `[secret] min_length`. Reference: [docs/configuration.md](docs/configuration.md).

## Documentation

Doc | Covers
--- | ---
[docs/integrations.md](docs/integrations.md) | Wiring a tool to the broker: per-tool recipes, linked credentials, SSH, and Ansible end to end
[docs/configuration.md](docs/configuration.md) | Every setting, which flag sets it, what `--check` fails on
[docs/design.md](docs/design.md) | Why the agent runs as the operator, how the rewrite works, what it gives up
[docs/coding-agents.md](docs/coding-agents.md) | What varies between the agents, how the rules reach each, what enrolling one costs
[docs/installing.md](docs/installing.md) | Every `init` flag, what a re-run adopts, where the config directory may not go
[docs/layout.md](docs/layout.md) | Every path the install creates, with its mode and owner
[docs/escalation.md](docs/escalation.md) | Granting `sudo` to a brokered command, answering a question, what the grant costs
[docs/operating.md](docs/operating.md) | Checking an install, every operator command, [the rules a command does not state](docs/operating.md#rules-a-command-does-not-state), adding an age recipient
[docs/protocol.md](docs/protocol.md) | Request and response shapes on the socket
[docs/redaction.md](docs/redaction.md) | What the redactor covers, and what it cannot

## Developing

Target | Does
--- | ---
`make build` | A static binary into `bin/`
`make test` | Everything that tests this: the Go suite and the end-to-end suites
`make e2e` | The end-to-end suites alone, against a real install in a container
`make coverage` | Race-enabled Go suite plus per-function report
`make fuzz` | Every fuzz target, `FUZZTIME` each (default 30s). Time-boxed rather than finished, so it is run by hand rather than by CI
`make fmt` | Apply the import and format rules CI checks
`make lint` | golangci-lint and ShellCheck. CI's Lint job also runs markdownlint and `goreleaser check`, which this tree asks for no tooling for
`make shellcheck` | The shell scripts alone, as CI checks them
`make install`, `make uninstall` | Copy the binary to `/usr/local/bin` and remove it. Both use sudo

- Everything under `systemd/`, `etc/`, `agent/` and `docs/` is embedded into the binary by `assets.go`, so `init` installs a host without a checkout, and the `.tmpl` files are the shipped files themselves. That decides where a new document goes: operator documentation in `docs/`, which ships, and developer documentation at the root, which does not.
- Tests live where the logic does. Most of what the broker does is decide, so `internal/server` substitutes the executor. `internal/executor` drives a real child where the PTY and the streaming redactor mean nothing against synthetic bytes, and tests the rune and truncation rules directly, those being properties of the bytes: a test that needs a cgroup to run does not run everywhere.
- The Go suite runs under one uid, so it never covers the uid boundary. That is real only on a host, which is what `sudo faramir doctor` and [tests/e2e](tests/e2e/README.md) are for. Adversarial exfiltration is asserted nowhere, as [Not prevented](#not-prevented) says.
- The tests need cgroup v2 with `cgroup.kill` (kernel 5.14 or newer) and a cgroup the test process can subdivide, every brokered command being confined to its own. `make test` supplies one with `systemd-run --user --scope`; without it a couple of dozen tests skip, so the run ends by naming what it did not check. On a runner with no such scope, delegate a cgroup first, as [the test workflow](.github/workflows/test.yml) does. cgroup v1 is unsupported.
- The suite needs no `sops` on `PATH`: `internal/sopstest` builds a stand-in from the sops libraries, imported only from `_test.go`. What keeps them out of the shipped binary is `cmd/faramir/nosops_test.go`, which walks `go list -deps` and carries a positive control, so the check cannot pass by matching nothing.
- The shipped logic that is not Go is the plugin opencode and Kilo Code load, Pi's extension, and the shell of `wrap.sh` and the PAM helper. Node drives the two rendered files against a stand-in guard, covering the rewrite, the refusal, a tool that is not a shell, and each way of failing closed; skipped where node is absent. The shell is ShellCheck's, and [tests/e2e](tests/e2e/README.md) runs all of it against a real install. No test covers a running opencode, Kilo Code or Pi, or Bun.
