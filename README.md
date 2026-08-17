# faramir

[![CI](https://github.com/andornaut/faramir/actions/workflows/release.yml/badge.svg)](https://github.com/andornaut/faramir/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A secrets broker for local AI coding agents: it runs the commands that need credentials and keeps the values out of the agent's context. Those commands run as a uid that holds nothing.

```console
$ faramir run --env ROUTER_PW=secret://home/router/admin -- printenv ROUTER_PW
«SECRET:home/router/admin»
faramir run: redacted «SECRET:home/router/admin»×1; log_id=w5vq7dbf00002c
```

## Supported agents

Four get full redaction: what the agent runs in an enrolled project is rewritten into a brokered command, and its output comes back with every value replaced. Antigravity gets less.

Agent | Registered in | Enrolment cost
--- | --- | ---
[Claude Code](https://claude.com/product/claude-code) | `PreToolUse` hook and MCP server in the tree; deny rules in `~/.claude/settings.json` | Bash is approved without asking, except what the deny list refuses. That list names credential disclosure and nothing destructive. [Cost per permission mode](docs/design.md#what-this-gives-up)
[opencode](https://open-code.ai/) | [`tool.execute.before` plugin](https://open-code.ai/en/docs/plugins) and `opencode.json` in the tree; deny patterns in `~/.config/opencode/opencode.json` | None: there is no allow to return, so a plugin that has not denied has not approved. Whether its `bash` rules see the command or the rewrite is undocumented
[Kilo Code](https://kilo.ai/) | [Same plugin API](https://kilo.ai/docs/automate/extending/plugins) under `.kilo/plugin/`, loaded by the CLI and the VS Code extension; `kilo.json`, and `~/.config/kilo/kilo.json` | Same as opencode
[Pi](https://pi.dev/) | [`tool_call` extension](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/extensions.md) under `.pi/extensions/`. Pi ships no MCP, so the extension registers the two tools itself and shells out to the CLI | None. Project-local extensions load only once the project is trusted, so a tree Pi has not been trusted in is unguarded
[Antigravity](https://antigravity.google/) | MCP server in `.agents/mcp_config.json`; the credentials section in `.agents/rules/faramir.md` and `~/.gemini/GEMINI.md` | None, and no redaction either. **Partial support**, see below

`--agent` is repeatable on `init` and `init-project`, defaulting to `auto`: whichever agents are already there, which `init` asks of your home and `init-project` of the tree. A name configures that agent regardless and composes, so `--agent auto --agent pi` is "whatever is installed, plus pi". The names are `antigravity`, `claude`, `kilocode`, `opencode` and `pi`. Pi and Antigravity get no account-wide rule file: Pi has nowhere to put one, so the same rules are compiled into its extension, and Antigravity's permission lists are the IDE's own state rather than a file an install may write.

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
**Root persistence by the *approved* command** | Configuring a host and backdooring it are the same primitives. A *second, unapproved* command cannot ride the approval, the broker serialising approved runs
**Every managed value, not only the injected ones.** `env_refs` scopes one command's environment, not what a brokered command can reach | The executor is in the client group, so a brokered command is itself a broker client: it can ask for a second command with any ref injected, and the two share a uid. Redaction still covers what comes back through the broker
**Network egress** | Out of scope. No iptables, namespaces or proxy allowlist
**Anything at rest** | The uid boundaries hold only while the machine runs; full-disk encryption is the measure. `--allow-sudo` is the exception, minting no credential, so a stolen disk carries nothing that can sudo here
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

**SSH keys** are held by the broker and loaded into an `ssh-agent` it owns; the child gets only `SSH_AUTH_SOCK`, so it can authenticate and cannot read a key. `ssh-agent` refuses any peer uid but its own, so the broker relays, forwarding only `REQUEST_IDENTITIES` and `SIGN_REQUEST`. A brokered command may forward that relay onward with `ssh -A`, letting the host it connects to sign while the connection is open.

**Allowing sudo** is off by default and adds no credential; see [below](#allowing-sudo-on-the-controller).

### Redaction

The value set is **every managed secret**, not only the injected ones, so a managed host printing a credential nothing injected is still covered. Children run on a PTY, so programs behave normally and writes to `/dev/tty` are captured; the cost is that stdout and stderr arrive merged. ANSI escapes are stripped before matching, an expanded set of encodings is matched (base64, base32, hex, URL, JSON, shell quoting), and a streaming overlap buffer catches a value split across reads. Tokens are stable, so the model can reason about a secret across turns.

Two things are not in the value set: a value shorter than `[secrets] min_length`, refused at load because it would match inside ordinary words, and the age key, which no child can obtain. `--allow-sudo` adds nothing to it, approval minting no credential. Detail in [docs/redaction.md](docs/redaction.md).

### The audit log

Every field of a record is chosen by the account the log exists to hold to account, so the record's bounds are decided where it is built:

- One record is one line within `[audit] max_record_bytes`, counted in encoded bytes: `<`, `>`, `&` and every control character cost six apiece as JSON.
- An append is exclusive and all-or-nothing. A write that lands short is taken back, so a torn line cannot swallow the record after it.
- Every `log_id` is distinct: the second it was minted in, the writer's nonce, and a counter that only advances. Fourteen characters, and it carries no readable time, every record saying when it happened in a field of its own.
- An exec writes two records under one `log_id`: `exec_started` when the child runs and `exec` when it ends.

A command that cannot be recorded does not run: the broker checks the log can be written before starting anything, and refuses with `no_audit` otherwise. The file itself is logrotate's to bound.

## Installation

Requires [systemd](https://systemd.io/) and [sops](https://github.com/getsops/sops); Go to build. The binary is static, so the host needs no interpreter. The agent's session needs `XDG_RUNTIME_DIR`: the hook captures output before redacting it and will not write that anywhere another account can read, so a session without one refuses every Bash command.

```bash
make build
sudo ./bin/faramir init
```

`init` creates the accounts and groups, mints the age key, installs the binary, the deny list and the docs, renders the config and the systemd units, and starts the sockets. Idempotent, so it is also the upgrade. It installs and never migrates, writing what this version wants and leaving an older layout's leftovers alone.

**A re-run keeps what the install already uses.** A flag left out is taken from the install rather than from the compiled-in default:

Flag left out | Taken from
--- | ---
`--broker-user`, `--keeper-user`, `--exec-user` | each unit's `User=`
`--client-group`, `--ssh-key` | the installed `config.toml`
`--secrets-group` | the group owning `<config-dir>/secrets`

`init` reports what it adopted before writing with it, and a flag still outranks it. A `config.toml` that is there and will not parse stops the run whatever flags it was given.

`faramir init --help` carries each flag in full. What they are for:

Flag | Default | Sets
--- | --- | ---
`--agent-user NAME` | `$SUDO_USER`, then you | The account the coding agent runs as. It owns the checkouts brokered commands run in, so root is refused
`--client-group NAME` | the install's, then `dev` | The group admitted to the broker socket and group-owning an enrolled tree
`--secrets-group NAME` | the install's, then the keeper's own group | The group owning the ciphertext. `doctor` fails if the operator is in it
`--config-dir DIR` | [found the usual way](docs/operating.md#checking-an-install) | Where `config.toml`, `config.d/`, the age key and the managed sops files live. Absolute, its parent must exist, and a *different* one is refused without `--move-config`
`--move-config` | off | Consent to that move. The refs the old directory served leave the value set
`--broker-user`, `--exec-user`, `--keeper-user` | the install's, then `faramir-broker`, `faramir-exec`, `faramir-keeper` | The three service accounts, created if missing. No two may share a name
`--age-recipient KEY` | none | An age **public** key that may also decrypt the store, repeatable. An identity is refused, `.sops.yaml` being world-readable. Read only at the install that creates that file; changing it later is [Adding a recipient](docs/operating.md#adding-a-recipient)
`--ssh-key PATH` | the install's, then `<config-dir>/id_ed25519` | Where the keypair the broker lends lives. One is minted either way, so this relocates rather than enables. An existing key is adopted rather than replaced, and must be `faramir-broker`-owned `0600` with its `.pub` beside it at `0644`
`--known-hosts PATH` | none | A `known_hosts` file copied to `<exec-home>/.ssh/known_hosts` and replaced whole each run. One that is not a `known_hosts` file is refused
`--agent NAME` | `auto` | Which agents get deny rules and a credentials section in this home ([which file, per agent](docs/layout.md)). Finding no agent writes nothing and says so
`--allow-sudo` | off | Lets a brokered command *ask* to become root, through a password-required sudoers entry and a PAM service of faramir's own. Not passing the flag takes it back. [What it writes](docs/operating.md#the-decision-is-made-at-init-per-host)
`--notify-command ARG` | none | Announces a waiting approval, one argument per flag. Must name `{prompt}` or `{id}`; needs `--allow-sudo`
`--socket PATH` | `$FARAMIR_SOCKET`, then `/run/faramir/broker.sock` | Which broker to ask where the install is, so it decides which install a flagless re-run provisions
`--dry-run` | off | Report what would change and write nothing. The one form that does not need root
`--json` | off | The report as JSON, one entry per step with a `changed` flag

The deny rules `--agent` installs refuse the file tools against key material by name and suffix (`id_ed25519`, `.pem`, `.env*`, credentials and sops files) and against the sops, age and faramir config directories.

The units are sandboxed, so the config directory is not a free choice. `init` refuses whitespace and `%`, which systemd splits and expands in `Environment=`. A directory under `/tmp` or `/var/tmp` installs and then finds nothing, `PrivateTmp=true` giving each unit its own; nothing refuses it at install time, and the daemons fail to load when they start.

### Checking an install

```bash
sudo faramir doctor
```

Reports whether the install is doing its job, and as root what each account can reach. Without root it still runs, reporting what it could not ask as unasked. What it checks, and how every command finds the install: [docs/operating.md](docs/operating.md).

## Usage

### Onboarding a project

1. Put the values in one sops file under `/etc/faramir/secrets`, named after what consumes them. `[secrets] patterns` globs that directory, so it is picked up on the next refresh (5 seconds by default).
2. Have the project read each credential from an environment variable rather than a file or a vault of its own. Most tools already work this way; Ansible needs `lookup('env', 'NAME')`.
3. Write the refs beside the project, one `NAME=secret://ref` per line.
4. `cd <project> && sudo faramir init-project`. Shares the tree so a brokered command can run in it, and configures whichever agents it already carries.

Enrol the projects where managed credentials are in play, not every tree. `--hook=false` shares one without the hook. A brokered command runs where its caller was, so nothing needs a tree of its own. A secrets file the glob does not reach needs naming in a drop-in: `patterns = ["/srv/other/x.sops.yml"]`.

```bash
faramir list-secrets
faramir run --env TOKEN=secret://svc/token -- printenv TOKEN   # -> «SECRET:svc/token»
```

#### With Ansible

```text
/etc/faramir/secrets/ansible-ctrl.sops.yml   the values, outside every checkout
group_vars/all/vars.yml                      committed: var -> lookup('env', 'NAME')
faramir.env                                  NAME=secret://ref, one per line
```

`sudo faramir init-project` writes the agent configuration and shares the tree. The other three are yours to place, and none needs a drop-in: a file is managed by being in the secrets directory. Full walk-through in [docs/ansible-sops.md](docs/ansible-sops.md).

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
Something over SSH | Nothing for the value: `init` renders `[ssh] key` and the child gets `SSH_AUTH_SOCK`. Name the remote login, a bare `ssh host` asking for `faramir-exec`, and pin the host keys with `init --known-hosts`
Redaction only, no secret | Skip steps 3 and 4. `faramir redact -- ./script.sh`, or use it as a filter

- A pipeline is requested explicitly as `["bash", "-lc", "…"]`; the broker never hands a string to a shell.
- A bare command name is looked up on `[exec.base_env] PATH`. Venv, pipx and shim directories belong there.
- Anything that wants to decrypt sops itself does not onboard. It gets named values instead.

### Running commands

```bash
faramir status                          # config path, sources, ref count
faramir list-secrets                    # ref names, never values
faramir run --env NAME=secret://ref -- CMD
faramir run --env-file deploy.env -- ansible-playbook site.yml
faramir run --quiet -C ~/src/project -t 120 -- CMD
kubectl get secret -o yaml | faramir redact
faramir redact -- ./deploy.sh
```

`faramir run` | Effect
--- | ---
`--env NAME=secret://ref` | Once per secret
`--env-file FILE` | `NAME=secret://ref` per line, `#` comments
`--quiet` | Suppress the redaction summary on stderr. Not why a `sudo` was refused: that is printed either way, being what says whether running the command again is worth anything
`--cwd`/`-C`, `--timeout`/`-t` | Working directory, runtime ceiling
`--socket`, `--json` | On every broker-facing command

- The child's exit code is faramir's own. A broker that is not running exits 69 (`EX_UNAVAILABLE`).
- **`faramir redact` writes nothing it could not redact**, in either shape. A chunk the broker cannot cover is withheld, the stream stops there, and the exit status is non-zero: for `-- CMD` that is the child's own status when it failed, and 1 when it succeeded, the command having run and only its output being missing. Chunks already redacted are kept, so a broker lost mid-stream truncates rather than empties.
- Both `--env` and `--env-file` refuse a literal value and a name that cannot be an environment variable. One file refuses a name given twice with different refs; across sources a later `--env-file` wins over an earlier one, and `--env` wins over both. A bad line is reported with file and line, and the offending value never appears.

### Allowing sudo on the controller

A brokered command runs as `faramir-exec`, which has no sudo, so a playbook that also configures the controller has to leave it out with `--limit '!controller'`. `sudo faramir init --allow-sudo` closes that split without moving the boundary: no password, a PAM service that asks the broker, and one question per run answered by `sudo faramir approve ID`. The seam nothing closes is that an approved command gets real root and can make it permanent, so approving is trusting *that command* with permanent root.

How to run it: [docs/operating.md](docs/operating.md#allowing-sudo-on-the-controller). Why it is shaped this way: [docs/design.md](docs/design.md#allowing-sudo-on-the-controller). With Ansible: [docs/ansible-sops.md](docs/ansible-sops.md#4-becoming-root-on-the-controller).

### Operator commands

All need root except `doctor`, which degrades.

Command | Does
--- | ---
`sudo faramir init-project [DIR]` | Enrols one working tree, `DIR` defaulting to the current working directory. [Shares the tree](docs/layout.md), registers the hook and the MCP server in each enrolled agent's settings, and writes the credentials section into the tree's agent instructions file. A home directory, `/`, and anything above a home are refused, symlinks resolved first
`sudo faramir doctor` | Reports whether the install is doing its job, and as root what each account can reach
`sudo faramir edit FILE` | Opens a managed sops file, decrypting to a `0600` file in a root-owned tmpfs and re-encrypting on the way out. `FILE` is any name the `[secrets] patterns` globs reach. `--editor` names the editor, `--age-key` the key
`sudo faramir rekey [FILE...]` | Re-encrypts to the recipients `<config-dir>/.sops.yaml` names now: every managed file unless some are named. `--dry-run` writes nothing. [What it preserves and refuses](docs/operating.md#adding-a-recipient)
`sudo faramir logs [LOG-ID]` | Recent audit records, one row each: the log id, local time, op, outcome, values stood in for, and the command. With an id, one record in full. `--count`/`-n` bounds what is parsed as well as printed; `--json` prints records rather than rows; `--watch` prints the last `-n` and then each record as it is written, following the log across a rotation and waiting for it on a host where nothing has been brokered yet. It reads the log `[audit] log_path` names and takes no path of its own. Printed as found rather than redacted again, the log holding no value. Rotated files are not searched
`sudo faramir approvals [--watch]` | Lists the approval a brokered command is waiting on. `--watch` waits for questions, answers them from that terminal, and reports how each approved run ended
`sudo faramir approve ID` | Say yes. The id is required: an approval that names no command is one nobody judged
`sudo faramir deny [ID]` | Say no. The id is optional, one question being outstanding at a time
`sudo faramir reload` | Stops the daemons, so the next brokered command starts them on a changed `config.d` drop-in. All three are socket activated
`sudo faramir uninstall` | Removes the broker from the install it finds. Leaves the accounts, the config, the secrets, the key and the audit log, and says so: deleting the age key would make every managed sops file unreadable, retroactively

`approvals`, `approve` and `deny` are root-only at the broker too, checked with `SO_PEERCRED`: the account the coding agent runs as must not answer what the agent asked for.

### MCP tools

Tool | Parameters
--- | ---
`faramir_run` | `cmd` (array, required), `env_refs`, `cwd`, `timeout_sec`
`faramir_list_secrets` | none. Ref names only, and where `faramir_run`'s `env_refs` come from

Two, and meant to stay two. A tool is for what an agent has to be told; everything else is a subcommand. Pi registers the same two from its extension; both lists are asserted by count.

Wire protocol: [docs/protocol.md](docs/protocol.md).

## Configuration

Settings live in `<config-dir>/config.toml`, which `init` rewrites on every run from [etc/config.toml.tmpl](etc/config.toml.tmpl), and in `config.d/*.toml` drop-ins, which it never touches. Edit a drop-in.

There is no command allowlist. What bounds a brokered command is the executor's uid, and then `[exec.base_env] PATH`, `[exec] max_timeout_sec`, `[exec] max_output_bytes` and `[secrets] min_length`. [docs/configuration.md](docs/configuration.md) is the reference.

## Documentation

Doc | Covers
--- | ---
[docs/ansible-sops.md](docs/ansible-sops.md) | Pointing `group_vars` at the environment
[docs/configuration.md](docs/configuration.md) | Every setting, what a drop-in may set, what `--check` fails on
[docs/design.md](docs/design.md) | Why the agent runs as the operator, how the rewrite works, what enrolment costs
[docs/layout.md](docs/layout.md) | Every path the install creates, with its mode and owner
[docs/operating.md](docs/operating.md) | Checking an install, [the rules a command does not state](docs/operating.md#rules-a-command-does-not-state), adding an age recipient
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
`make install` | `sudo faramir init` for this host, passing `INIT_ARGS`
`make verify` | `sudo faramir doctor`

- Everything under `systemd/`, `etc/`, `agent/` and `docs/` is embedded into the binary by `assets.go`, so `init` installs a host without a checkout. The `.tmpl` files are the shipped files themselves. That decides where a new document goes: operator documentation in `docs/`, which ships, and developer documentation at the root, which does not.
- Tests live where the logic does. Most of what the broker does is decide, and none of that needs a socket or a child process, so `internal/server` substitutes the executor. `internal/executor` uses a real child, the PTY and the streaming redactor only meaning anything against real bytes.
- The suite runs in a temp directory under one uid, so it covers the protocol, the PTY hand-off and the redactor, but never the uid boundary. That boundary is only real on a host, which is what `sudo faramir doctor` and [tests/e2e](tests/e2e/README.md) are for. Adversarial exfiltration is asserted nowhere, as [Not prevented](#not-prevented) says.
- The tests need cgroup v2 with `cgroup.kill` (kernel 5.14 or newer) and a cgroup the test process can subdivide, every brokered command being confined to its own. The `make test` targets run the suite under `systemd-run --user --scope`, which inherits the delegation systemd gives `user@.service`. Without it roughly sixty tests skip and the run still prints `ok`, so each target ends by naming what it did not check. Where that scope is unavailable, an unprivileged CI runner in a root-owned service cgroup, hand the process a delegated one first, as [the test workflow](.github/workflows/test.yml) does. Older kernels and cgroup v1 are unsupported.
- The suite needs no `sops` on `PATH`: `internal/sopstest` builds a stand-in from the sops libraries, imported only from `_test.go`, which keeps sops out of the shipped binary; CI fails the build on a `getsops` import reaching `./cmd/faramir`.
- The opencode and Kilo Code plugins are the only shipped logic that is not Go, so they are run rather than read: node drives the shipped file against a stand-in guard, covering the rewrite, the refusal, a tool that is not a shell, and each way of failing closed. Skipped where node is absent. No test covers a running opencode or Kilo Code, or Bun, the runtime both load a plugin under.
