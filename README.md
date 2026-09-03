# faramir

[![Release](https://github.com/andornaut/faramir/actions/workflows/release.yml/badge.svg)](https://github.com/andornaut/faramir/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/license/MIT)

A secrets broker for AI coding agents. Commands that need credentials run as a separate uid with the values in their environment, and their output is redacted before the agent sees it.

```console
$ faramir run --env ROUTER_PW=faramir://home/router/admin -- printenv ROUTER_PW
«SECRET:home/router/admin»
faramir run: redacted «SECRET:home/router/admin»×1; log_id=w5vq7dbf00002c
```

> [!IMPORTANT]
> **One install per host, serving one operator.** Every member of the client group is the same caller to the broker: one value set, one SSH key, one executor uid, one `agent_user` on every audit record. A second operator needs a second host.

## Supported agents

For every agent, the command the agent runs is rewritten into a brokered command, and the output comes back with every managed value replaced. `faramir init` installs this in the agent's home, so it applies in every directory.

Claude Code and Codex differ. Their hook returns a permission decision, so a hook that rewrites a command must also approve it, and that approval suppresses the Bash permission prompt for every command the deny list does not name. `faramir init` installs only a deny-only hook in their home. `faramir enrol` writes the routing hook into the tree, so the prompt is given up per tree, by the operator.

Agent | Registered in | Enrolment cost
--- | --- | ---
[Antigravity CLI](https://antigravity.google/docs/cli/) (`agy`) | `PreToolUse` hook in `~/.gemini/config/hooks.json`; deny rules in `~/.gemini/antigravity-cli/settings.json`; credentials section in `.agents/rules/faramir.md`, the tree's `AGENTS.md` and `~/.gemini/GEMINI.md` | None: the permission check runs before the hook, so the hook's allow approves nothing
[Antigravity IDE](https://antigravity.google/) | The same hook and the same files. No account-wide rule file: the hook refuses its file tools instead | None
[Claude Code](https://claude.com/product/claude-code) | Deny rules and a deny-only `PreToolUse` hook in `~/.claude/settings.json`; in the tree, the routing hook in `.claude/settings.local.json` and a credentials section in `CLAUDE.md` | Bash no longer prompts in an enrolled tree, except for what the deny list refuses. The list names credential disclosure only. [Cost per permission mode](docs/coding-agents.md#claude-code)
[Codex](https://developers.openai.com/codex/cli/) | A deny-only `PreToolUse` hook in `~/.codex/hooks.json`; in the tree, the routing hook in `.codex/hooks.json` and a credentials section in `AGENTS.md` | Same as Claude Code, when Codex runs with approvals on. Codex has no rule file, so the hook alone refuses its file tools, `apply_patch` included
[Kilo Code](https://kilo.ai/) | [`tool.execute.before` plugin](https://kilo.ai/docs/automate/extending/plugins) in `~/.config/kilo/plugin/`, loaded by the CLI and the VS Code extension; deny patterns in `~/.config/kilo/kilo.json` | None: a plugin cannot return an allow
[opencode](https://open-code.ai/) | [The same plugin API](https://open-code.ai/en/docs/plugins) in `~/.config/opencode/plugin/`; deny patterns in `~/.config/opencode/opencode.json` | Same as Kilo Code
[Pi](https://pi.dev/) | [`tool_call` extension](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/extensions.md) in `~/.pi/agent/extensions/` | None: Pi loads an extension from the home for every project, without the project being trusted

Choose agents with `--agent`, repeatable on `init` and `enrol`:

- Names: `agy`, `antigravity`, `claude`, `codex`, `kilocode`, `opencode`, `pi`. `agy` is the Antigravity CLI and `antigravity` the IDE. They share one tree enrolment, so naming either writes the same files.
- The default is `auto`: whichever agents are already present. `init` looks in your home, `enrol` in the tree. Codex is detected from your home either way, since a tree carries nothing of its own for it.
- A name configures that agent whether or not it is present, and composes with `auto`: `--agent auto --agent pi` means "whatever is installed, plus pi".

Faramir refuses a declared path itself for all seven agents, from its hook, plugin or extension. Claude Code and the Antigravity CLI also refuse it from a rule file of their own, which applies in some permission modes where the hook applies in all. The other five have no rule file that can refuse a path: Pi and the Antigravity IDE have none an install can write, Codex's `.rules` files decide commands and cannot name a path, and opencode's and Kilo Code's `deny` entries prompt rather than refuse, so an autonomous run approves them.

Each agent is also told what the rules refuse and why, in the file it reads for every project ([which file, per agent](docs/layout.md)). [docs/coding-agents.md](docs/coding-agents.md#what-each-agent-gets) lists what each agent gets, feature by feature, and how each agent's hook contract shapes the rewrite.

> [!NOTE]
> **Antigravity is covered by its hooks.** [Its `PreToolUse` hook](https://antigravity.google/docs/hooks) returns `overwrite`, a shallow merge into the tool call's arguments, and the merged form is what runs: the command goes through the broker and comes back redacted. The same hook refuses a file tool that names key material. The IDE depends on this, since its permission lists are internal state rather than a file an install can write. The CLI has both.
>
> `faramir init` writes the hook into `~/.gemini/config/hooks.json`, which the CLI and the IDE both read for every workspace, so an unenrolled tree is covered too. No hook goes into a tree.
>
> An enrolment writes the credentials section into the tree: `.agents/rules/faramir.md` and the tree's own instructions file. Antigravity loads a tree's customizations only after it has opened that tree as a project. Until then the files are inert, and `enrol` says so. The hook does not depend on them.

Codex needs two things from you before any of this applies.

> [!IMPORTANT]
> **Codex has two conditions faramir cannot meet for you.** Codex silently skips a hook it has not been told to trust, so what `faramir init` writes does nothing until you start Codex once and trust the hook. And Codex must run without its own sandbox (`codex --dangerously-bypass-approvals-and-sandbox`): sandboxed, it cannot reach the broker socket, the wrapper fails closed, and every command's output is withheld instead of redacted. Both commands print a reminder on every run. Details in [coding-agents.md](docs/coding-agents.md#codex).

## What it protects against

> [!IMPORTANT]
> The broker keeps plaintext out of model context. It does not contain a compromised agent.

**Acceptance invariant:** if every instruction the agent is given were deleted, no secret could reach the model provider. Every enforcement point is a uid boundary, a file mode, or a hook.

### Prevented

Failure | How
--- | ---
**Accidental disclosure.** `printenv`, a vault read, `-vvv`, a `debug: var=` task | No account can read the key material, yours included. Output is redacted before the agent sees it, whichever command printed it
**Passive discovery.** Reading an age key, an SSH key, or a daemon's `/proc/<pid>/environ` | Uid separation plus `ProtectProc=invisible`. This holds against the agent. Two brokered commands share one uid and can read each other
**Casual prompt injection.** Instructions to print or exfiltrate credentials | The agent process never holds them
**Master key loss.** The master key decrypts every managed file | It lives in a uid that executes nothing. No brokered command can read it, reach the keeper's socket, or receive it in its environment

### Not prevented

Failure | Why
--- | ---
**Adversarial exfiltration.** Transforming a value (`\| rev`, `\| sha256sum`) defeats redaction | The child chooses the encoding of its own output, so no matcher can be complete
**Blast radius.** A brokered command runs anything the executor's uid can | Out of scope. That uid is the bound. With `--allow-sudo` it may also *ask* to become root, and a human answers per command
**Root persistence by the *approved* command** | Configuring a host and backdooring it use the same primitives. A *second, unapproved* command cannot ride the escalation: the broker serialises approved runs
**Every managed value, not only the injected ones.** `env_refs` scopes one command's environment, not what a brokered command can reach | The executor is in the client group, so a brokered command is itself a broker client and can ask for a second command with any ref injected. Redaction still covers what comes back through the broker
**Network egress** | Out of scope. No iptables, namespaces or proxy allowlist
**Anything at rest** | The uid boundaries hold only while the machine runs. Full-disk encryption is the measure. `--allow-sudo` mints no credential, so a stolen disk carries nothing that can sudo here
**Unenrolled trees.** The value set is global | A command in a tree you never enrolled can print a managed value uncaught
**Credentials faramir does not manage.** An SSH private key, a `.pem`, a `.env`, an `~/.aws/credentials` | The deny rules cover this install's own paths. Declare anything else with [`faramir block`](docs/configuration.md#blocked-paths). An install that declares nothing refuses nothing

## How it works

One binary. The daemons and the guard are subcommands of it, each run by a systemd unit as its own uid. The agent reaches the broker through the same binary: there is no server to register and nothing to install per project.

uid | Runs | Holds
--- | --- | ---
you | the coding agent, and `faramir run` | nothing secret
`faramir-broker` | `faramir broker` | plaintext values in memory, SSH keys, and with `--allow-sudo` the pending questions
`faramir-exec` | `faramir exec` | nothing
`faramir-keeper` | `faramir keeper`, and nothing but sops | the age master key

One call, end to end:

1. The request reaches `/run/faramir/broker.sock` carrying a ref, never a value. `cmd` is an array; there is no allowlist.
2. The broker asks the keeper over a socket only it can open. The keeper execs sops and returns values. The key stays in the keeper's uid.
3. The broker creates a PTY, hands the slave to the executor over `/run/faramir/exec.sock`, and the executor forks the command as `faramir-exec`, with the value in the environment and never in `argv`.
4. Output returns through the broker's end of the PTY. Every managed secret becomes `«SECRET:ref»` before the agent sees a byte.
5. The audit log records what ran, against which refs, and what came back. Tokens only, readable by the operator only.

**SSH keys** are held by the broker in an `ssh-agent` it owns. The child gets only `SSH_AUTH_SOCK`, so it can authenticate but cannot read a key. The broker relays only `REQUEST_IDENTITIES` and `SIGN_REQUEST`. A brokered command may forward the relay onward with `ssh -A`.

**Allowing sudo** is off by default and adds no credential. See [below](#allowing-sudo-on-the-controller).

### Redaction

- The value set is **every managed secret**, not only the injected ones, so a host that prints a credential nothing injected is still covered. A `[[secret.link]]` entry adds a credential another tool owns, read from where that tool keeps it.
- Children run on a PTY, so programs behave normally. They get no controlling terminal, so `/dev/tty` cannot be opened: a prompt that would have gone there falls back to stderr, which the redactor reads. The cost is that stdout and stderr arrive merged.
- ANSI escapes are stripped before matching. base64, base32, hex, URL, JSON and shell quoting are matched as encodings. A streaming overlap buffer catches a value split across reads.
- Tokens are stable, so the model can reason about a secret across turns.
- Outside the value set: a value shorter than `[secret] min_length` (refused at load, since it would match inside ordinary words), a value of 16 KiB or more (refused at load, for the cost of matching it), and the age key, which no child can obtain. `--allow-sudo` adds nothing: escalation mints no credential.

Details in [docs/redaction.md](docs/redaction.md).

### The audit log

Every brokered command is recorded: what ran, against which refs, and what came back. The log holds tokens, not values. Only the broker and root can read it, and logrotate bounds it.

- A brokered command writes two records under one `log_id`: `run_started` when the child starts, and `run` when it ends or when it never ran.
- A command that cannot be recorded does not run. The broker checks that the log is writable before starting anything, and refuses with `no_audit` if it is not.

What a record contains, and the rules a command does not state: [docs/operating.md](docs/operating.md).

## Installation

Requires [systemd](https://systemd.io/) and [sops](https://github.com/getsops/sops), and Go to build. The binary is static, so the host needs no interpreter. The agent's session needs `XDG_RUNTIME_DIR`: the hook writes captured output there before redacting it, and refuses every Bash command rather than write it where another account could read it.

### Pre-compiled binary

Archives are on the [releases page](https://github.com/andornaut/faramir/releases): one per tagged version, plus a `dev` release rebuilt on every push to `main`. Linux only: the broker reads peer credentials with `SO_PEERCRED` and the executor allocates PTYs with `TIOCGPTN`.

Platform | Asset
--- | ---
Linux x86_64 | `faramir_linux_x86_64.tar.gz`
Linux arm64 | `faramir_linux_arm64.tar.gz`

The archive also holds `LICENSE` and `README.md`, so extract only the binary. `init` installs it, so there is nothing to copy into place first:

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

`init` creates the accounts and groups, mints the age key, installs the binary, the deny list and the docs, renders the config and the systemd units, and starts the sockets. It is idempotent, so it is also the upgrade. A re-run that leaves a flag out keeps the value the install already uses rather than reverting to the default.

Every flag, what a re-run adopts, and where the config directory may not go: [docs/installing.md](docs/installing.md).

## Getting Started

From a bare host to a redacted command in six steps.

1. **Install the binary**, from [an archive](#pre-compiled-binary) or [a build](#compile-from-source). `init` puts it in `/usr/local/bin` itself.
2. **Provision the host** with `sudo faramir init`. [What it does](#what-init-does), and [every flag](docs/installing.md).
3. **Check it** with `sudo faramir doctor`. It reports whether the install works and, as root, what each account can reach. Without root it still runs, and reports what it could not check as unasked rather than as passing. [What it checks](docs/operating.md#checking-an-install).
4. **Declare what this machine should block.** A fresh install refuses only its own files, so your SSH key stays readable to your agent until you declare it. [Below](#declaring-blocked-paths-and-commands).
5. **Enrol a tree** with `cd <tree> && sudo faramir enrol`, in each tree where managed credentials are used. [What an enrolment writes, and the three steps before it](#onboarding-a-project).
6. **Run something.** `faramir refs` lists what the broker serves, and `faramir run` gives a command one:

```bash
faramir refs
faramir run --env TOKEN=faramir://svc/token -- printenv TOKEN   # -> «SECRET:svc/token»
```

### Declaring blocked paths and commands

**A fresh install blocks its own files and nothing else**: `<config-dir>`, the managed store, `/var/log/faramir`, `/usr/local/libexec/faramir` and the three service accounts' directories. `~/.ssh`, `~/.gnupg` and `~/.aws/credentials` are refused to your agent only once you declare them.

This example is deliberately broad: delete the lines that do not apply to this machine, and add the ones that do.

```bash
sudo faramir block add \
    --path ~/.ssh --path ~/.gnupg --path ~/.aws \
    --path ~/.config/sops/age --path ~/.age \
    --path ~/.local/share/keyrings --path ~/.netrc \
    --command 'op read' --command 'pass show'
```

`--path` and `--command` mix in one command. A bare argument is refused rather than read as a path.

Form | Blocks | Matched against
--- | --- | ---
`--path` | one file or directory on this host, and everything under it | the path as written, so it must be absolute and in its shortest form
`--command` | what may not be run, written as it would be typed | the start of a command, so `grep` naming one is left alone

**Name the directory, not the files in it.** `--path ~/.ssh` refuses every key under it, including one named `identity` and whatever an `IdentityFile` line points at. A list of file names covers only the ones you thought of.

**A symlink is recorded at both names.** A rule matches the path a command names, so a dotfiles-managed config blocked under `~/.config/app/config.json` alone stays readable under the checkout path it points at. `block add` resolves the path and writes the target as a second entry; `block rm` on the one you declared takes both away.

**A path rule reaches the agent's file tools and its shell; a command rule reaches the shell only.** The broker holds the same entries, so a brokered command cannot print a declared file either. The broker also refuses a brokered command that names one of faramir's own directories, because an approved escalation runs as root, where a file mode refuses nothing.

**The two sides refuse differently.** The agent's shell is refused any command that names a declared path, whatever the command would do with it. A brokered command is refused only the commands that would print the file, and may still move it or write over it: it has to be able to use a credential, and the programs that read one without printing it cannot be listed in full. [How that line is drawn](docs/configuration.md#the-brokered-route). `--strict` extends the shell's rule to brokered commands:

```bash
sudo faramir block add --path ~/.private --strict
```

That refuses `ls` and `chmod` as well as `cat`, so nothing can rotate the file. It is the wrong flag for a key something has to rotate, which is why it is off by default.

`faramir block ls` lists everything in force, including the rules faramir carries itself. It runs without root, as do `reader ls`, `link ls` and `doctor`, which reports less without root.

Every `block` command is idempotent and reports what changed with `--json`, so a configuration manager can declare the whole list on every converge. [What each form matches, and what a wide one costs](docs/configuration.md#blocked-paths).

## Usage

### Onboarding a project

1. **Write the values**, one file per thing that consumes them. `sudo faramir vault add NAME` creates `NAME.sops.yml` in the secrets directory. The content comes from an editor faramir opens on a `0600` file in a tmpfs, so no plaintext reaches a disk. The editor runs as root over the decrypted value, so it must be a program only root can change: `--editor`, `$VISUAL` and `$EDITOR` each name one by absolute path with no arguments ([how the editor is chosen](docs/operating.md#choosing-the-editor)). Nothing restarts: the next refresh picks the file up. A credential another tool already owns is [linked](docs/integrations.md#linking-a-credential-another-tool-owns) instead of copied in.
2. **Have the project read each credential from an environment variable** rather than a file or a vault of its own. Most tools already work this way; Ansible needs `lookup('env', 'NAME')`.
3. **Write the refs beside the project**, one per line, in a file that holds refs and never values: [the two line forms](docs/integrations.md#onboarding-in-three-steps).
4. **`cd <tree> && sudo faramir enrol`.** Shares the tree so a brokered command can run in it, writes the credentials section into the tree's instructions file ([which file, per agent](docs/layout.md)), and for Claude Code and Codex registers the routing hook in the tree.

What to run in an enrolled tree: [below](#running-commands).

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
`--stdin`/`-i` | Send what you pipe in to the command, up to 128 KiB. More is refused rather than cut; a larger input belongs in a file the command opens itself
`--quiet` | Suppress the redaction summary on stderr. Only that: why a `sudo` was refused is printed either way, and so is every note saying the output is not what the command produced, truncation included
`--cwd`/`-C` | Where the command runs. A relative path is resolved against the caller's directory, which is also the default
`--timeout`/`-t` | How long before the broker kills it: a duration (`90s`, `5m`) or a bare number of seconds, in whole seconds. Defaults to `[command] timeout_sec`; `max_timeout_sec` is the ceiling
`--json` | The raw response. Every broker-facing command accepts it except `redact`, whose output is the redaction itself

- Without `--stdin`, a pipeline is refused rather than dropped: `faramir run` does not own the file on its standard input, so a `while read ... done < hosts.txt` loop and an `ssh host 'faramir run …'` session keep theirs. An anonymous pipe every writer has closed with nothing in it is not refused, since that is what a program driving `faramir run` as a subprocess hands it. A FIFO stays refused, since another writer can open one after the last has closed.
- Flags after the program name belong to the program. Parsing stops at the first non-flag word, so `--` works but is not required.
- `--env` and `--env-file` both refuse a literal value and a name that cannot be an environment variable. A name given twice with different refs is refused, within a file, across files, and across `--env` flags; the bare and the mapping form count as the same name. `--env` still overrides `--env-file`. A bad line is reported with file and line, and the offending value never appears. A bare name must be both a usable variable name and a ref a store can hold.
- **`faramir redact` writes nothing it could not redact**, in either form. A chunk the broker cannot cover is withheld, the stream stops there, and the exit status is non-zero: for `-- CMD` the child's own status when it failed, otherwise 1. Chunks already redacted are kept, so a broker lost mid-stream truncates the output rather than emptying it.

Exit code | Meaning
--- | ---
the child's | The command ran. A run whose exit status was lost keeps its output, reports a non-zero stand-in code, and says so on stderr
69 (`EX_UNAVAILABLE`) | The broker is not running
75 (`EX_TEMPFAIL`) | The broker is at its concurrency limit. The one refusal the same request may pass a moment later
126, 127 | The program cannot be run, or is not there, as a shell reports them
2 | Usage error
1 | Every other refusal

### Allowing sudo on the controller

A brokered command runs as `faramir-exec`, which has no sudo, so a playbook that also configures the controller has to leave it out with `--limit '!controller'`. `sudo faramir init --allow-sudo` closes that gap: no password, a PAM service that asks the broker, and one question per run answered by `sudo faramir sudo approve ID`. An approved command gets real root and can make it permanent, so approving is trusting *that command* with permanent root.

**Works with either sudo.** Ubuntu ships two from 25.10 on. `init` probes the `sudo` alternatives group and writes the arrangement that sudo can read. It needs `sudo` 1.9.11 or `sudo-rs` 0.2.9, and writes nothing on an older host. What each arrangement touches: [the two sudos](docs/escalation.md#the-two-sudos).

- How to run it: [docs/escalation.md](docs/escalation.md)
- Why it is shaped this way: [docs/design.md](docs/design.md#allowing-sudo-on-the-controller)
- With Ansible: [docs/integrations.md](docs/integrations.md#becoming-root-on-the-controller)

### Operator commands

**Every operator command that changes the install or needs root is refused to the coding agent's shell**, with sudo and without. The four that only describe the install are allowed: [which commands, and what each does](docs/operating.md#operator-commands).

Group | Commands
--- | ---
The install | `doctor`, `enrol`, `init`, `reload`, `uninstall`
The managed store | `vault add`, `vault edit`, `vault ls`, `vault rm`
Who can decrypt it | `reader add`, `reader ls`, `reader reseal`, `reader rm`
A secret another tool owns | `link add`, `link ls`, `link rm`
A path, name or command blocked from the agent | `block add`, `block ls`, `block rm`
The record, and sudo | `logs`, `sudo approve`, `sudo ls`, `sudo reject`, `sudo watch`

`init`, `enrol` and the four `link` and `block` edits are idempotent and report what changed with `--json`, so a configuration manager can declare every entry on every run.

### What the agent runs

Command | What it is for
--- | ---
`faramir run --env NAME=faramir://ref -- program args` | Runs the command with the value injected, and returns its output with each value replaced by `«SECRET:ref»`
`faramir refs` | The names that exist, never the values. Where `run`'s `--env` refs come from

These two are how a value reaches a command. `redact`, `status`, `version`, `help` and `completion` are open to the agent as well, and so are the four that only describe the install: `doctor`, `block ls`, `link ls` and `reader ls`. Every other subcommand is the operator's. Nothing is registered per project: the binary is installed for the account, so the route is the same in every directory on the host, enrolled or not. Wire protocol: [docs/protocol.md](docs/protocol.md).

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
`make test` | Everything: the Go suite and the end-to-end suites
`make e2e` | The end-to-end suites alone, against a real install in a container
`make coverage` | Race-enabled Go suite plus per-function report
`make fuzz` | Every fuzz target, `FUZZTIME` each (default 30s). Time-boxed rather than exhaustive, so it is run by hand rather than by CI
`make fmt` | Apply the import and format rules CI checks
`make lint` | golangci-lint and ShellCheck. CI's Lint job also runs markdownlint and `goreleaser check`, which need no tooling from this tree
`make shellcheck` | The shell scripts alone, as CI checks them
`make install`, `make uninstall` | Copy the binary to `/usr/local/bin` and remove it. Both use sudo
`make clean` | Remove `bin/`, `dist/` and `coverage.txt`

- Everything under `systemd/`, `etc/`, `agent/` and `docs/` is embedded into the binary by `assets.go`, so `init` installs a host without a checkout, and the `.tmpl` files are the shipped files themselves. Operator documentation goes in `docs/`, which ships. Developer documentation goes at the root, which does not.
- Tests live beside the logic they cover. Most of what the broker does is decide, so `internal/broker` substitutes the executor. `internal/execclient` drives a real child, because the PTY and the streaming redactor cannot be tested against synthetic bytes, and tests the rune and truncation rules directly. A test that needs a cgroup does not run everywhere.
- The Go suite runs under one uid, so it never covers the uid boundary. That is real only on a host, which is what `sudo faramir doctor` and [tests/e2e](tests/e2e/README.md) are for. Adversarial exfiltration is asserted nowhere, as [Not prevented](#not-prevented) says.
- The tests need cgroup v2 with `cgroup.kill` (kernel 5.14 or newer) and a cgroup the test process can subdivide, since every brokered command is confined to its own. `make test` supplies one with `systemd-run --user --scope`. Without it a couple of dozen tests skip, and the run ends by naming what it did not check. On a runner with no such scope, delegate a cgroup first, as [the test workflow](.github/workflows/test.yml) does. cgroup v1 is unsupported.
- The suite needs `sops` on `PATH`. `internal/sopstest` builds its encrypted fixtures by running it, not by linking it, so the sops libraries are absent from the module as well as from the binary: the keeper execs sops, and linking it anywhere would pull in the AWS, GCP, Azure and Vault SDKs. A missing binary fails the suites that need one rather than skipping them, because those suites hold sops' own resolution of a creation rule, which guards against a `.sops.yaml` planted in the agent's tree. `cmd/faramir/nosops_test.go` asserts both halves: nothing the command reaches links sops, and `go.mod` requires no getsops module.
- The shipped logic that is not Go is the plugin opencode and Kilo Code load, Pi's extension, and the shell of `wrap.sh` and the PAM helper. Node drives the two rendered files against a stand-in guard, covering the rewrite, the refusal, a tool that is not a shell, and each way of failing closed. Skipped where node is absent. ShellCheck covers the shell, and [tests/e2e](tests/e2e/README.md) runs all of it against a real install. No test covers a running opencode, Kilo Code or Pi, or Bun.
