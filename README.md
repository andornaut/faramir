# faramir

A secrets broker for local AI coding agents: it runs the commands that need credentials and keeps the values out of the agent's context. Those commands run as a uid that holds nothing.

```console
$ faramir run --env ROUTER_PW=secret://home/router/admin -- printenv ROUTER_PW
«SECRET:home/router/admin»
[faramir] redacted «SECRET:home/router/admin»×1; log_id=2026-08-05T14:22:01Z-a91f00002c
```

Agent | Redaction | Registration | Enrolment cost | Mitigation
--- | --- | --- | --- | ---
[Claude Code](https://claude.com/product/claude-code) | Full | `PreToolUse` in `.claude/settings.json`, MCP server in `.mcp.json`, account-wide keys in `~/.claude/settings.json` | Every Bash command is approved without asking, except what the deny list refuses — and that list names credential disclosure, nothing destructive, so whatever prompting stood between the agent and `rm -rf` is gone. Other tools prompt as before; no permission mode exempts a project: [what enrolment costs in each](docs/design.md#what-this-gives-up). | Run in [auto mode](https://code.claude.com/docs/en/permission-modes), whose classifier reads the rewritten command rather than matching a rule against it. Extend the deny list.
[Gemini CLI](https://geminicli.com/docs/hooks/reference/) | Full | Hooks and `mcpServers` in `.gemini/settings.json`; deny rules a `.toml` under `~/.gemini/policies/`. | None: there is no allow to return, so a hook that has not denied has not approved. | n/a
[opencode](https://open-code.ai/) | Full | [`tool.execute.before` plugin](https://open-code.ai/en/docs/plugins) under `.opencode/plugins/`, MCP server in `opencode.json`, account-wide `permission` deny patterns in `~/.config/opencode/opencode.json`. | None, as Gemini. Whether its `bash` rules see the command or the rewrite is undocumented. | If commands start prompting as the wrapper rather than as themselves, the rules see the rewrite: a rule naming `source /usr/local/libexec/faramir/wrap.sh *` is what decides them from then on.
[Kilo Code](https://kilo.ai/) | Full | [Same plugin API](https://kilo.ai/docs/automate/extending/plugins) under `.kilo/plugin/`, loaded by both the CLI and the VS Code extension. MCP server in `kilo.json`, deny patterns in `~/.config/kilo/kilo.json`. | Same as opencode. | Same as opencode.
[Pi](https://pi.dev/) | Full | [`tool_call` extension](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/extensions.md) under `.pi/extensions/`, TypeScript. No MCP registration: Pi ships none, so a command needing credentials is `faramir run`, which the extension rewrites like any other. | None: the extension blocks or rewrites and approves nothing, so the agent prompts as it would have. Project-local extensions load only once the project is trusted, so a tree Pi has not been trusted in is unguarded. | Confirm project trust when Pi asks, or the extension never loads.

Enrol with `faramir init-project --agent claude --agent gemini`, repeatable, defaulting to `claude`. The names are `claude`, `gemini`, `opencode`, `kilocode` and `pi`. [Antigravity](https://antigravity.google/) is not supported: its hooks decide and cannot rewrite.

## What it protects against

> [!IMPORTANT]
> The broker keeps plaintext out of model context. It does not contain a compromised agent.

**Acceptance invariant:** if every instruction the agent is given were deleted, no secret could reach the model provider. Every enforcement point is a uid boundary, a file mode, or a hook.

### Prevented

Failure | How
--- | ---
**Accidental disclosure.** `printenv`, a vault read, `-vvv`, a `debug: var=` task. | No account can read the key material, yours included; output is redacted before the agent sees it.
**Passive discovery.** The agent reading an age key, an SSH key, or the `/proc/<pid>/environ` of a daemon or a running brokered command. | Uid separation plus `ProtectProc=invisible`. Named for the agent because that is who it holds against: two brokered commands share one uid and can read each other, per **Every managed value** below.
**Casual prompt injection.** Instructions to print or exfiltrate credentials. | The agent process never holds them.
**Master key loss.** The master key decrypts every managed file retroactively. | It lives in a uid that executes nothing; no brokered command can read it, reach the keeper's socket, or receive it in its environment.

### Not prevented

Failure | Why
--- | ---
**Adversarial exfiltration.** Transforming a value (`\| rev`, `\| sha256sum`) defeats redaction. | The child chooses the encoding of its own output, so the matcher cannot be completed.
**Blast radius.** A brokered command runs anything the executor's uid can. | Out of scope. That uid is the bound. With [`init --allow-sudo`](#allowing-sudo-on-the-controller) it may also *ask* to become root, which a human answers per command; the uid is still what it can do unasked.
**Root persistence by the *approved* command.** With `--allow-sudo`, the one command a human approves gets real root and can make it permanent. | Unfixable: configuring a host and backdooring it are the same primitives. Approving one is trusting *that command* with permanent root, exactly as `sudo ansible-playbook` by hand is. A *second, unapproved* command cannot ride the approval, the broker serialising approved runs. [The full argument](#allowing-sudo-on-the-controller).
**Every managed value, not only the injected ones.** `env_refs` scopes what the broker puts in one command's environment, not what a brokered command can reach. | The executor is in the client group, so a brokered command is itself a broker client: it can ask for a second command with any ref injected, and the two share a uid, so it can read that one's `/proc/<pid>/environ`. Redaction still covers what comes back through the broker, so getting a value out needs a channel of the command's own: **Adversarial exfiltration**.
**Network egress.** No iptables, namespaces or proxy allowlist. | Out of scope.
**Anything at rest.** Nothing here encrypts the disk. | The uid boundaries only hold while the machine is running; full-disk encryption is the measure. The sudo grant is the exception, and only because it can be: `--allow-sudo` mints no credential at all, so a stolen disk carries nothing that can sudo here.
**Unenrolled projects.** The value set is global. | A command in a project you never enrolled can print a managed value uncaught.

## How it works

One binary, `faramir`. The daemons, the MCP server and the guard are subcommands of it, separated by the uid each unit runs its subcommand as.

uid | Runs | Holds
--- | --- | ---
you | the coding agent, and `faramir run` | nothing secret
`faramir-broker` | `faramir broker` | plaintext values in memory, SSH keys, and with `--allow-sudo` the pending questions
`faramir-exec` | `faramir exec` | nothing
`faramir-keeper` | `faramir keeper`, and nothing but sops | the age master key

The age key decrypts every managed file retroactively, so it lives in a uid that executes nothing.

One call, end to end:

1. The request reaches `/run/faramir/broker.sock` carrying a ref, never a value. `cmd` is an array; there is no allowlist.
2. The broker asks the keeper over a socket only it can open. The keeper execs sops and returns values; the key stays in that uid.
3. The broker creates a PTY, hands the slave to the executor over `/run/faramir/exec.sock`, and the executor forks the command as `faramir-exec`: value in the environment, never in `argv`.
4. Output returns through the broker's end of the PTY. Every managed secret becomes `«SECRET:ref»` before the agent sees a byte.
5. The audit log records what ran, against which refs, and what came back. Tokens only, operator-readable only.

**SSH keys** are held by the broker and loaded into an `ssh-agent` it owns; the child gets only `SSH_AUTH_SOCK`, so it can authenticate and cannot read a key. `ssh-agent` refuses any peer uid but its own, so the broker relays, forwarding only `REQUEST_IDENTITIES` and `SIGN_REQUEST`. A brokered command may forward that relay onward with `ssh -A`, which lets the host it connects to sign with the key while the connection is open: its own choice, and it could already sign anything itself, but the reach is a managed host rather than this one.

**Allowing sudo**, on a host installed with `--allow-sudo`, keeps the same boundary without holding anything: there is no password. The executor gets a password-required sudoers entry pointed at a PAM service of faramir's own, whose authentication step asks the broker whether a human approved the brokered command making the call. The `sudo` waits until `sudo faramir approve ID` answers (root only, checked with `SO_PEERCRED`), and a yes covers that command's sudos until it exits. Off by default, and an install that never asked for it grants nothing. See [Allowing sudo on the controller](#allowing-sudo-on-the-controller).

### Redaction

Detail in [docs/redaction.md](docs/redaction.md).

1. **The value set is every managed secret**, not only the injected ones, refreshed when a managed file's mtime changes.
2. **Children run on a PTY**, so programs behave normally and writes to `/dev/tty` are captured. Consequence: stdout and stderr arrive merged.
3. **ANSI escapes are stripped before matching.**
4. **An expanded value set is matched**: raw, base64, URL-encoded, JSON-escaped, shell-quoted.
5. **Streaming uses an overlap buffer**, so a value split across reads is still caught.
6. **Values too short to redact are refused at load.** A short value matches inside ordinary words, and blanking those at random is a fault in this program rather than in the secret. The broker names each refusal; the agent is told nothing.
7. **Tokens are stable**, so the model can reason about a secret across turns.

The age key is not in the value set: no child can obtain it. Neither is anything from `--allow-sudo`, approval minting no credential.

### The audit log

Every field of a record is chosen by the account the log exists to hold to account, so what bounds a record is decided where it is built:

1. **One record is one line, and no line exceeds `[audit] max_record_bytes`** — counted in encoded bytes, because `<`, `>`, `&` and every control character cost six apiece as JSON, and a cap counted before encoding is a cap whose meaning the command picks. A record keeps the head and the tail of a run and says what it dropped between them; any other long field is cut to fit.
2. **An append is exclusive and all-or-nothing.** Writers take a lock, and a write that lands short is taken back, so a torn line cannot swallow the record appended after it.
3. **Every `log_id` is distinct**, carrying the writer's nonce and a counter that only advances.

A command that cannot be recorded does not run: the broker checks the log can be written before it starts anything, and refuses with `no_audit` otherwise. The file itself is logrotate's to bound, and `faramir doctor` checks that logrotate is installed, names the right log, and has applied the rule.

### Design and layout

[docs/design.md](docs/design.md) has the table of what was chosen and what each choice costs, with the reasoning behind the ones that cost the most. [docs/layout.md](docs/layout.md) has every path the install creates with its mode and owner, what `--config-dir` moves, and what enrolling a working tree changes.

## Installation

Requires [systemd](https://systemd.io/) and [sops](https://github.com/getsops/sops); Go to build. The binary is static, so the host needs no interpreter. The agent's session needs `XDG_RUNTIME_DIR`: the hook captures output before redacting it and will not write that anywhere another account can read, so a session without one refuses every Bash command.

```bash
make build
sudo ./bin/faramir init
```

`init` creates the accounts and groups, mints the age key, installs the binary, the deny list and the docs, renders the config and the systemd units, and starts the sockets. Idempotent, so it is also the upgrade: re-run it after a rebuild and it reports what changed.

**A re-run keeps what the install already uses.** A flag left out is taken from the install rather than from the compiled-in default:

Flag left out | Taken from
--- | ---
`--broker-user`, `--keeper-user`, `--exec-user` | each unit's `User=`
`--client-group`, `--ssh-key` | the installed `config.toml`
`--secrets-group` | the group owning `<config-dir>/secrets`

`init` reports what it adopted before writing with it, and a flag still outranks it. A `config.toml` that is there and will not parse stops the run whatever flags it was given: fix it, or remove it for a fresh install.

Flag | Default | What to give it
--- | --- | ---
`--operator-user NAME` | `$SUDO_USER`, then you | An existing login account, the one your coding agent runs as. It owns the checkouts brokered commands run in, so root is refused.
`--client-group NAME` | [what the install uses](#installation), then `dev` | A group name, created if missing, doing two jobs: it admits a caller to the broker socket, and `init-project` group-owns a tree with it so the broker can stat a request's cwd and `faramir-exec` can run there.
`--secrets-group NAME` | [what the install uses](#installation), then `faramir-keeper` | A group name, created if missing. It owns the ciphertext in `<config-dir>/secrets`; the keeper is its only member, so asking for a value by name and reading its file stay different privileges. The operator is deliberately out of it, and `doctor` fails if they are in it. The default is the keeper's own group.
`--config-dir DIR` | [found the usual way](docs/operating.md#checking-an-install) | An absolute path for `config.toml`, `config.d/`, the age key and the managed sops files. Left out, it re-provisions the install this host already has. Naming a *different* one moves the daemons onto it and is refused without `--move-config`. It must be mounted before the daemons read it, and its parent must exist.
`--move-config` | off | Consent to the move above. The old directory is left as it stands, but the refs it served leave the value set, so a brokered command that prints one of those values prints it. `init` names the directory it left behind.
`--broker-user`, `--exec-user`, `--keeper-user` NAME | [what the install uses](#installation), then `faramir-broker`, `faramir-exec`, `faramir-keeper` | Service account names, created if missing. Rename them freely; no two may share a name.
`--age-recipient KEY` | none | An age **public** key, repeatable, listed in `.sops.yaml` beside the keeper's so a backup of the ciphertext opens without the keeper's key; the private half is yours to hold. An identity is refused, `.sops.yaml` being world-readable. Only read at the install that creates the file; see [Adding a recipient](docs/operating.md#adding-a-recipient).
`--ssh-key PATH` | [what the install uses](#installation), then `<config-dir>/id_ed25519` | Where the keypair the broker lends to brokered commands lives. One is minted either way, so this relocates rather than enables. Put the public half `init` prints into `authorized_keys` on each managed host. An existing key at the path is adopted, not replaced; it must already be `faramir-broker`-owned `0600` or `init` refuses it.
`--known-hosts PATH` | none | A `known_hosts` file pinned for the executor, copied to `<exec-home>/.ssh/known_hosts` and replaced whole on each run, so the file you name is the authority. A copy, the executor being unable to read your `0700 ~/.ssh`; one that is not a `known_hosts` file is refused.
`--agent NAME` | every agent | `claude`, `gemini`, `opencode`, `kilocode` or `pi`, repeatable. Installs that agent's deny rules into your own settings. Naming none installs them for every agent: those rules refuse the file tools, covering the key material under `~/.ssh` and `~/.config/sops` that no uid boundary reaches, and an agent installed later finds them already there. `pi` has none of its own, its extension being what refuses a tool call.
`--allow-sudo` | off | The one place the executor's reach grows: a **password-required** sudoers entry for `faramir-exec` and a private PAM service whose authentication step asks the broker whether a human approved the brokered command. There is no password, so nothing that can sudo on this host exists at rest or in memory. Not passing the flag takes it all back. [What it grants and what it costs](#allowing-sudo-on-the-controller).
`--dry-run` | off | Reports what would change and writes nothing.
`--json` | off | Prints the report as JSON, one entry per step with a `changed` flag.

The units are sandboxed, so the config directory is not a free choice. `init` refuses whitespace and `%`, which systemd splits and expands in `Environment=`. It writes into `/tmp` and `/var/tmp`, but `PrivateTmp=true` gives each unit its own, so the daemons find nothing and say so.

`init` installs and never migrates: it writes what this version wants and leaves an older layout's leftovers alone.

### Checking an install

```bash
sudo faramir doctor
```

Reports whether the install is doing its job, and as root what each account can reach. What it checks, what a run without sudo cannot ask, and how every command finds the install: [docs/operating.md](docs/operating.md).

## Usage

### Onboarding a project

1. Put the values in one sops file under `/etc/faramir/secrets`, named after what consumes them. `[secrets] patterns` globs that directory, so it's picked up on the next refresh (`[secrets] refresh_interval_sec`, 5 seconds by default).
2. Have the project read each credential from an environment variable, rather than from a file or a vault of its own. Nothing in the project decrypts anything: `faramir run` puts the value in the environment and the project reads `$NAME`. Most tools already work this way; Ansible needs `lookup('env', 'NAME')`.
3. Write the refs beside the project, one `NAME=secret://ref` per line.
4. `cd <project> && sudo faramir init-project`. Shares the tree so a brokered command can run in it, and writes each enrolled agent's settings and the instructions block. This causes Claude Code (the default) to auto-redact in Bash commands (and auto-approve them too). Add `--agent gemini`, `--agent opencode` or `--agent kilocode` for other agents.

Enrol the projects where managed credentials are in play, not every tree. `--hook=false` shares one without the hook. A brokered command runs where its caller was, so nothing needs a tree of its own.

A secrets file the glob does not reach still needs naming, in a drop-in of its own: `patterns = ["/srv/other/x.sops.yml"]`. Entries accumulate across `config.d` and are deduplicated after expansion.

```bash
faramir list-secrets
faramir run --env TOKEN=secret://svc/token -- printenv TOKEN   # -> «SECRET:svc/token»
```

The value reached the child, and came back as a token.

#### Using faramir with Ansible

```text
/etc/faramir/secrets/ansible-ctrl.sops.yml   the values, outside every checkout
group_vars/all/vars.yml                      committed: var -> lookup('env', 'NAME')
faramir.env                                  NAME=secret://ref, one per line
.claude/settings.json, .mcp.json             written by init-project
```

`sudo faramir init-project` writes the last line and shares the tree. The other three are yours to place, and none of them needs a drop-in: a file is managed by being in the secrets directory.

Full walk-through in [docs/ansible-sops.md](docs/ansible-sops.md): the `lookup('env', …)` mapping, why the secrets must stay out of `group_vars/`, and the SSH key arrangement.

#### Other cases

Only step 3 differs.

What you are running | Step 3
--- | ---
A deploy or release script | Already reads `$TOKEN`. Nothing to change.
A cloud or infra CLI (`aws`, `terraform`, `flyctl`) | Name its documented environment variables; drop the credentials file.
A database task | `PGPASSWORD`, `MYSQL_PWD`. The connection string goes in `argv`, the password never does.
A registry push | `bash -lc 'printf %s "$TOKEN" \| docker login -u me --password-stdin'`
An HTTP call | `curl -H "Authorization: Bearer $TOKEN"` inside `bash -lc`, so the shell expands it.
A tool needing a credentials *file* | Have the command write it, use it, remove it. Injection is environment-only.
Something over SSH | Nothing for the value: `init` renders `[ssh] key` and the child gets `SSH_AUTH_SOCK`. Name the remote login, since a bare `ssh host` asks for `faramir-exec`, and pin the host keys with `init --known-hosts`.
Redaction only, no secret | Skip steps 3 and 4. `faramir redact -- ./script.sh`, or use it as a filter.

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
`--env NAME=secret://ref` | Once per secret.
`--env-file FILE` | `NAME=secret://ref` per line, `#` comments.
`--quiet` | Suppress the redaction summary on stderr.
`--cwd`/`-C`, `--timeout`/`-t` | Working directory, runtime ceiling.
`--socket`, `--json` | On every broker-facing command.

- The child's exit code is faramir's own. A broker that is not running exits 69 (`EX_UNAVAILABLE`).
- **`faramir redact` writes nothing it could not redact**, in either shape. A chunk the broker cannot cover is withheld, the stream stops there, and the exit status is non-zero: for `-- CMD` that is the child's own status when it failed, and 1 when it succeeded, because the command ran and only its output is missing. Chunks already redacted are kept, so a broker lost mid-stream truncates the output rather than emptying it; one that was never up fails on the first chunk and writes nothing.
- Both `--env` and `--env-file` refuse a literal value and a name that cannot be an environment variable.
- One file refuses a name given twice with different refs. Across sources, a later `--env-file` wins over an earlier one, and `--env` wins over both.
- A bad line is reported with file and line. The offending value never appears.

### Allowing sudo on the controller

A brokered command runs as `faramir-exec`, which has no sudo, so a playbook that also configures the controller has to leave it out with `--limit '!controller'`. `sudo faramir init --allow-sudo` closes that split without moving the boundary, by the mechanism [above](#how-it-works): no password, a PAM service that asks the broker, and one question per run answered by `sudo faramir approve ID`. Whether a host allows sudo at all is a per-host choice made at `init`; re-running without the flag takes it back.

The one seam nothing closes: an approved command gets real root and can make it permanent, exactly as `sudo ansible-playbook` by hand can. Approving is trusting *that command* with permanent root, so keep it operator-owned and read-only to brokered commands.

How to install, run and watch it: [docs/operating.md](docs/operating.md#allowing-sudo-on-the-controller). Why it is shaped this way: [docs/design.md](docs/design.md#allowing-sudo-on-the-controller). Wiring Ansible to it: [docs/ansible-sops.md](docs/ansible-sops.md#4-becoming-root-on-the-controller).

### Operator commands

Command | Does
--- | ---
`sudo faramir init-project [DIR]` | Enrols one working tree, `DIR` defaulting to the current directory. [Shares the tree](docs/layout.md), registers the hook and the MCP server in each enrolled agent's settings, and splices the credentials section into its instructions. `--agent` is repeatable, default `claude`. A home directory, `/`, and anything above a home are refused, symlinks resolved first: sharing a home would hand `~/.ssh` to every brokered command. `faramir doctor` re-checks it.
`sudo faramir doctor` | Reports whether the install is doing its job, and as root what each account can reach. See [Checking an install](docs/operating.md#checking-an-install).
`sudo faramir edit FILE` | Opens a managed sops file, decrypting to a `0600` file in a root-owned tmpfs and re-encrypting on the way out. `FILE` is any name the `[secrets] patterns` globs reach, so a file dropped into the secrets directory is editable at once. `--age-key` names the key to decrypt with, `--editor` the editor to run.
`sudo faramir rekey [FILE...]` | Re-encrypts managed sops files to the recipients `<config-dir>/.sops.yaml` names now — every managed file unless some are named. Preserves each file's owner and mode, skips one already sealed to the rule, and refuses a rule that leaves out the keeper's own key. `--dry-run` writes nothing. See [Adding a recipient](docs/operating.md#adding-a-recipient).
`sudo faramir logs` | Recent audit records, one row each: short id, local time, op, outcome, how many values it stood in for, and the command (a redact shows the text's size, an edit or rekey the managed file). `faramir logs ID` prints one record in full, adding the caller, the cwd, the refs, the per-token counts, and the output as recorded. Root only, the log being `0600 faramir-broker`; printed as found rather than redacted again, the log holding no value. `-n` bounds what is parsed and not only what is printed. A line that will not parse is skipped and counted on stderr. Rotated files are not searched.
`sudo faramir approvals [--watch]` | List the approval a brokered command is waiting on. Root only, as `approve` and `deny` are: the broker checks `SO_PEERCRED`, because the account the coding agent runs as must not be able to answer what the agent asked for. `--watch` waits for questions and answers them from that terminal, `yes` and nothing shorter approving. See [Allowing sudo on the controller](docs/operating.md#allowing-sudo-on-the-controller).
`sudo faramir approve ID` | Say yes to that question. The id is required: an approval that names no command is one nobody judged.
`sudo faramir deny [ID]` | Say no. The id is optional, one question being outstanding at a time, so a bare `deny` refuses the one that is waiting.
`sudo faramir reload` | Stops the daemons, so the next brokered command starts them on a changed `config.d` drop-in. All three are socket activated.
`sudo faramir uninstall` | Removes the broker from the install it [finds the usual way](docs/operating.md#checking-an-install). Leaves the accounts, the config, the secrets, the key and the audit log, and says so: deleting the age key would make every managed sops file unreadable, retroactively.

### MCP tools

Tool | Description
--- | ---
`faramir_run(cmd, env_refs, cwd, timeout_sec)` | Run a command with secrets bound to environment variables.
`faramir_list_secrets()` | Ref names only.
`faramir_status()` | Config path, loaded files, ref count.

Wire protocol: [docs/protocol.md](docs/protocol.md).

### Notes

The operational rules that are not obvious from a command's own output, from restart order to what a brokered `ssh` logs in as: [docs/operating.md](docs/operating.md#rules-a-command-does-not-state).

## Configuration

[etc/config.toml.tmpl](etc/config.toml.tmpl) is what `init` renders, on every run, and it is commented. There is no command allowlist. What bounds a brokered command is the executor's uid, and then `[exec.base_env] PATH`, `[exec] max_timeout_sec`, `[exec] max_output_bytes` and `[secrets] min_length`.

Settings live in `<config-dir>/config.toml`, which `init` rewrites every run, and in `config.d/*.toml` drop-ins, which it never touches. Edit a drop-in.

[docs/configuration.md](docs/configuration.md) is the reference: every setting a drop-in may set and every one it may not, how lists merge, what `faramir broker --check` fails on, and the invariants no setting changes.

## Documentation

Doc | Covers
--- | ---
[docs/ansible-sops.md](docs/ansible-sops.md) | Pointing `group_vars` at the environment
[docs/configuration.md](docs/configuration.md) | Every setting, what a drop-in may set, what `--check` fails on
[docs/design.md](docs/design.md) | Why the agent runs as the operator, how the rewrite works, what enrolment costs
[docs/layout.md](docs/layout.md) | Every path the install creates, with its mode and owner
[docs/operating.md](docs/operating.md) | Checking an install, the operational notes, adding an age recipient
[docs/protocol.md](docs/protocol.md) | Request and response shapes on the socket
[docs/redaction.md](docs/redaction.md) | What the redactor covers, and what it cannot

## Developing

```bash
make build           # a static binary into bin/
make coverage        # race-enabled suite plus per-function report
make fmt             # apply the import and format rules CI checks
make lint            # golangci-lint
make test            # whole suite; needs no sops installed
make test-e2e        # end-to-end against a real broker in a temp dir
make test-unit       # everything except end-to-end
```

- Everything under `systemd/`, `etc/`, `agent/` and `docs/` is embedded into the binary by `assets.go`, so `init` installs a host without a checkout. The `.tmpl` files are the shipped files themselves, so what you read is what the install writes. That decides where a new document goes: operator documentation in `docs/`, which ships and installs, and developer documentation at the root, which does not.
- Tests live where the logic does. Most of what the broker does is decide, and none of that needs a socket or a child process, so `internal/server` substitutes the executor. `internal/executor` uses a real child, because the PTY and the streaming redactor only mean anything against real bytes.
- The suite runs in a temp directory under one uid, so it covers the protocol, the PTY hand-off and the redactor, but never the uid boundary. That boundary is only real on a host, which is what `sudo faramir doctor` is for. Adversarial exfiltration is asserted nowhere, as [Not prevented](#not-prevented) says.
- Every brokered command is confined to its own cgroup and reaped there, with no process-group fallback, and the tests exercise that same path: they need cgroup v2 with `cgroup.kill` (kernel 5.14 or newer) and a cgroup the test process can subdivide. Run directly, they inherit whatever cgroup your shell is in; where that is not writable (an unprivileged CI runner in a root-owned service cgroup), hand the process a delegated one first, as [the test workflow](.github/workflows/test.yml) does. Older kernels and cgroup v1 are unsupported, by the tool and so by the tests.
- The suite needs no `sops` on `PATH`: `internal/sopstest` builds a stand-in from the sops libraries, imported only from `_test.go`, which keeps sops out of the shipped binary; CI fails the build on a `getsops` import reaching `./cmd/faramir`.
- The opencode and Kilo Code plugins are the only shipped logic that is not Go, so they are run rather than read: node drives the shipped file against a stand-in guard, covering the rewrite, the refusal, a tool that is not a shell, and each way of failing closed. Skipped where node is absent. No test covers a running opencode or Kilo Code, or Bun, which is the runtime both load a plugin under.
