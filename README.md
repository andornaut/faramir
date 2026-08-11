# faramir

A secrets broker for local AI coding agents: it runs the commands that need credentials and keeps the values out of the agent's context.

The commands that need credentials run as a uid that holds nothing.

```console
$ faramir run --env ROUTER_PW=secret://home/router/admin -- printenv ROUTER_PW
«SECRET:home/router/admin»
[faramir] redacted «SECRET:home/router/admin»×1; log_id=2026-08-05T14:22:01Z-a91f
```

Agent | Redaction | Registration | Enrolment cost | Mitigation
--- | --- | --- | --- | ---
[Claude Code](https://claude.com/product/claude-code) | Full | `PreToolUse` in `.claude/settings.json`, MCP server in `.mcp.json`, account-wide keys in `~/.claude/settings.json` | Every Bash command is approved without asking, except what the deny list refuses. That list names credential disclosure and nothing destructive, so whatever prompting stood between the agent and `rm -rf` is gone and nothing here replaces it. Every other tool prompts as before, and no permission mode exempts a project: [what enrolment costs in each](docs/design.md#what-this-gives-up). | Run in [auto mode](https://code.claude.com/docs/en/permission-modes), where a classifier model reviews the command before it runs: it reads the rewritten text rather than matching a rule against it, so the rewrite does not blind it. Extend the deny list.
[Gemini CLI](https://geminicli.com/docs/hooks/reference/) | Full | Hooks and `mcpServers` are both keys of `.gemini/settings.json`. Deny rules are a `.toml` under `~/.gemini/policies/`, the settings key that used to do this being deprecated: regexes against the tool's arguments, tested against rendered paths but not a running Gemini CLI. | None: there is no allow to return, so a hook that has not denied has not approved. | n/a
[opencode](https://open-code.ai/) | Full | [`tool.execute.before` plugin](https://open-code.ai/en/docs/plugins), JS, under `.opencode/plugins/`, mutating `output.args`. MCP server in `opencode.json`, account-wide `permission` deny patterns in `~/.config/opencode/opencode.json`. | None: a plugin that has not thrown has not approved either. Its `bash` rules match the command text, and whether they see the command or the rewrite is undocumented. | If commands start prompting as the wrapper rather than as themselves, the rules see the rewrite: a rule naming `source /usr/local/libexec/faramir/wrap.sh *` is what decides them from then on.
[Kilo Code](https://kilo.ai/) | Full | [Same plugin API](https://kilo.ai/docs/automate/extending/plugins) under `.kilo/plugin/`, loaded by both the CLI and the VS Code extension. MCP server in `kilo.json`, deny patterns in `~/.config/kilo/kilo.json`. | Same as opencode. | Same as opencode.

Enrol with `faramir init-project --agent claude --agent gemini`, repeatable, defaulting to `claude`. The names are `claude`, `gemini`, `opencode` and `kilocode`.

[Antigravity](https://antigravity.google/) is not supported: its hooks decide and cannot rewrite.

## What it protects against

> [!IMPORTANT]
> The broker keeps plaintext out of model context. It does not contain a compromised agent.

**Acceptance invariant:** if every instruction (e.g. via AGENTS.md) the agent is given were deleted, no secret could reach the model provider. Every enforcement point is a uid boundary, a file mode, or a hook.

### Prevented

Failure | How
--- | ---
**Accidental disclosure.** `printenv`, a vault read, `-vvv`, a `debug: var=` task. | No account can read the key material, yours included; output is redacted before the agent sees it.
**Passive discovery.** Reading an age key, an SSH key, another process's `/proc/<pid>/environ`. | Uid separation plus `ProtectProc=invisible`.
**Casual prompt injection.** Instructions to print or exfiltrate credentials. | The agent process never holds them.
**Master key loss.** The master key decrypts every managed file retroactively. | It lives in a uid that executes nothing; no brokered command can read it, reach the keeper's socket, or receive it in its environment.

### Not prevented

Failure | Why
--- | ---
**Adversarial exfiltration.** Transforming a value (`\| rev`, `\| sha256sum`) defeats redaction. | The child chooses the encoding of its own output, so the matcher cannot be completed.
**Blast radius.** A brokered command runs anything the executor's uid can. | Out of scope. That uid is the bound. With [`init --allow-sudo`](#allowing-sudo-on-the-controller) it may also *ask* to become root, which a human answers per command; the uid is still what it can do unasked.
**Root persistence by the *approved* command.** With `--allow-sudo`, the one command a human approves gets real root and can make it permanent. | Not prevented, and unfixable: configuring a host and backdooring it are the same primitives, so an approved command that is hostile (a compromised playbook, a bad Galaxy role) installs its own persistence — setuid binary, `systemd` unit, `cron`, `sudoers`. Approving one is trusting *that command* with permanent root, exactly as `sudo ansible-playbook` by hand is. A *second, unapproved* command can't ride the approval — the broker serialises approved runs so nothing else runs as `faramir-exec` during the window — but the approved one is on you. [The full argument](#allowing-sudo-on-the-controller).
**Network egress.** No iptables, namespaces or proxy allowlist. | Out of scope.
**Anything at rest.** Nothing here encrypts the disk. | The uid boundaries only hold while the machine is running. Full-disk encryption is the measure; the age key is a file like any other to someone holding the drive. The sudo grant is the exception, and only because it can be: `--allow-sudo` mints no credential at all, so a stolen disk carries nothing that can sudo here.
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

**SSH keys** are held by the broker and loaded into an `ssh-agent` it owns; the child gets only `SSH_AUTH_SOCK`, so it can authenticate and cannot read a key. `ssh-agent` refuses any peer uid but its own, so the broker relays, forwarding only `REQUEST_IDENTITIES` and `SIGN_REQUEST`.

**Allowing sudo**, on a host installed with `--allow-sudo`, keeps the same boundary without holding anything: there is no password. The executor gets a password-required sudoers entry pointed at a PAM service of faramir's own, whose authentication step asks the broker whether a human approved the brokered command making the call. The child gets only a token naming its own run. The `sudo` waits until `sudo faramir approve` answers — root, checked with `SO_PEERCRED`, so the account the agent runs as cannot answer for itself — and a yes covers that command's sudos until it exits. See [Allowing sudo on the controller](#allowing-sudo-on-the-controller). Off by default, and an install that never asked for it grants nothing.

### Redaction

Detail in [docs/redaction.md](docs/redaction.md).

1. **The value set is every managed secret**, not only the injected ones, refreshed when a managed file's mtime changes.
2. **Children run on a PTY**, so programs behave normally and writes to `/dev/tty` are captured. Consequence: stdout and stderr arrive merged.
3. **ANSI escapes are stripped before matching.**
4. **An expanded value set is matched**: raw, base64, URL-encoded, JSON-escaped, shell-quoted.
5. **Streaming uses an overlap buffer**, so a value split across reads is still caught.
6. **Values too short to redact are refused at load.** Length only: a short value matches inside ordinary words, and blanking those at random is a fault in this program rather than in the secret. The broker names each refusal; the agent is told nothing.
7. **Tokens are stable**, so the model can reason about a secret across turns.

The age key is not in the value set: no child can obtain it. Neither is anything from `--allow-sudo`, for a simpler reason than a rule — approval mints no credential, so there is nothing to redact.

### Design and layout

[docs/design.md](docs/design.md) has the table of what was chosen and what each choice costs, with the reasoning behind the ones that cost the most. [docs/layout.md](docs/layout.md) has every path the install creates with its mode and owner, what `--config-dir` moves, what a brokered command can and cannot reach, and what enrolling a working tree changes.

## Installation

Requires [systemd](https://systemd.io/) and [sops](https://github.com/getsops/sops); Go to build. The binary is static, so the host needs no interpreter. The agent's session needs `XDG_RUNTIME_DIR`: the hook captures output before redacting it and will not write that anywhere another account can read, so a session without one refuses every Bash command.

```bash
make build
sudo ./bin/faramir init
```

`init` creates the accounts and groups, mints the age key, installs the binary, the deny list and the docs, renders the config and the systemd units, and starts the sockets. Idempotent, so it is also the upgrade: re-run it after a rebuild and it reports what changed.

**A re-run keeps what the install already uses.** `config.toml` is rendered from this run's values and a drop-in may not set the install-owned ones, so a flag left out is taken from the install rather than from the compiled-in default:

Flag left out | Taken from
--- | ---
`--broker-user`, `--keeper-user`, `--exec-user` | each unit's `User=`
`--client-group`, `--ssh-key` | the installed `config.toml`
`--secrets-group` | the group owning `<config-dir>/secrets`

`init` reports what it adopted before writing with it, and a flag still outranks it. A `config.toml` that is there and will not parse stops the run whatever flags it was given, no daemon being able to load it either: fix it, or remove it for a fresh install.

Flag | Default | What to give it
--- | --- | ---
`--operator-user NAME` | `$SUDO_USER`, then you | An existing login account, the one your coding agent runs as. It owns the checkouts brokered commands run in, so root is refused. Anything escalating without sudo has to pass this.
`--client-group NAME` | [what the install uses](#installation), then `dev` | A group name, created if missing. One group doing two jobs: it admits a caller to the broker socket, and `init-project` group-owns a tree with it so the broker can stat a request's cwd and `faramir-exec` can run there. The operator is in it for the first, the broker and the executor for the second, the keeper for neither. The executor therefore reaches the broker socket, which buys it nothing: it can request the same injection the agent can, redacted and audited the same way.
`--secrets-group NAME` | [what the install uses](#installation), then `faramir-keeper` | A group name, created if missing. It owns the ciphertext in `<config-dir>/secrets`, and the keeper is the only account in it, so asking for a value by name and reading the file it came from stay different privileges. Not who may *use* a secret: the operator is deliberately out of this group, and `doctor` fails if they are in it. The default is the keeper's own group, so it follows `--keeper-user`.
`--config-dir DIR` | [found the usual way](docs/operating.md#checking-an-install) | An absolute path for `config.toml`, `config.d/`, the age key and the managed sops files. Left out, it re-provisions the install this host already has. Naming one provisions that directory instead, which on a host installed elsewhere is a second install beside the first. It has to be mounted before the daemons read it, and its parent has to exist: this is the one directory faramir creates whose parent can be yours, and creating one would hand it to root.
`--broker-user`, `--exec-user`, `--keeper-user` NAME | [what the install uses](#installation), then `faramir-broker`, `faramir-exec`, `faramir-keeper` | Service account names, created if missing. Rename them freely; no two may share a name.
`--age-recipient KEY` | none | An age public key, repeatable, listed in `.sops.yaml` beside the keeper's so a backup of the ciphertext opens without the keeper's key. No identity is minted: the private half is yours to hold, and it opens a backup only if it outlives whatever took the keeper's key. The **public** half, checked before anything is written: `.sops.yaml` is world-readable, so an identity pasted here would hand the key that opens the secrets to every account on the host. Only read at the install that creates the file; see [Adding a recipient](docs/operating.md#adding-a-recipient).
`--ssh-key PATH` | [what the install uses](#installation), then `<config-dir>/id_ed25519` | Where the identity the broker lends to brokered commands lives. One is minted either way, so this relocates rather than enables. Its public half must reach `authorized_keys` on every managed host; `init` prints it every run. An existing key at the path is adopted, not replaced, which is how you bring your own; it must already be `faramir-broker`-owned `0600` or `init` refuses it rather than chowning a key that may be yours. It names a keypair: the broker holds both halves and signs with the private one.
`--known-hosts PATH` | none | A `known_hosts` file pinned for the executor, copied to `<exec-home>/.ssh/known_hosts`. A copy, the executor being unable to read your `0700 ~/.ssh`, and safe to copy where an ssh config is not: public host keys carry no directive that executes anything. Replaced whole on each run, `HashKnownHosts` leaving entries unmatchable by name to merge, so the file you name is the authority. One that is not a `known_hosts` file is refused before anything is written, which catches a path that reaches a private key.
`--agent NAME` | none | `claude`, `gemini`, `opencode` or `kilocode`, repeatable. Installs that agent's deny rules into your own settings. Naming none installs none.
`--allow-sudo` | off | A switch, and the one place the executor's reach grows. It grants `faramir-exec` a **password-required** sudoers entry on this host, writes the private PAM service that entry authenticates through, and renders `[sudo]`, so a brokered command can *ask* to become root and a human answers per command. There is no password: the PAM service's authentication step asks the broker, so nothing that can sudo on this host exists at rest or in memory. Not passing the flag removes the grant and the service, locks the account and drops the section, which is how you take it back. [What it buys and what it costs](#allowing-sudo-on-the-controller).
`--dry-run` | off | A switch. Reports what would change and writes nothing.
`--json` | off | A switch. Prints the report as JSON, one entry per step with a `changed` flag.

The units are sandboxed, so the config directory is not a free choice. `init` refuses whitespace and `%`, which systemd splits and expands in `Environment=`. It writes into `/tmp` and `/var/tmp`, but `PrivateTmp=true` gives each unit its own, so the daemons find nothing and say so.

`init` installs and never migrates: it writes what this version wants and leaves an older layout's leftovers alone.

### Checking an install

```bash
sudo faramir doctor
```

Reports whether the install is doing its job, and as root what each account can reach. What it checks, what a run without sudo cannot ask, and how every command finds the install: [docs/operating.md](docs/operating.md).

## Usage

### Onboarding a project

1. Put the values in one sops file under `/etc/faramir/secrets`, named after what consumes them. `[secrets] files` globs that directory, so it's picked up on the next refresh (`[secrets] refresh_interval_sec`, 5 seconds by default).
2. Have the project read each credential from an environment variable, rather than from a file or a vault of its own. Nothing in the project decrypts anything: `faramir run` puts the value in the environment and the project reads `$NAME`. Most tools already work this way; Ansible needs `lookup('env', 'NAME')`.
3. Write the refs beside the project, one `NAME=secret://ref` per line.
4. `cd <project> && sudo faramir init-project`. Shares the tree so a brokered command can run in it, and writes each enrolled agent's settings and the instructions block. This causes Claude Code (the default) to auto-redact in Bash commands (and auto-approve them too). Add `--agent gemini`, `--agent opencode` or `--agent kilocode` for other agents.

Enrol the projects where managed credentials are in play, not every tree. `--hook=false` shares one without the hook. A brokered command runs where its caller was, so nothing needs a tree of its own.

A secrets file the glob does not reach still needs naming, in a drop-in of its own: `files = ["/srv/other/x.sops.yml"]`. Entries accumulate across `config.d` and are deduplicated after expansion.

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
- **`faramir redact` writes nothing it could not redact**, in either shape. A chunk the broker cannot cover is withheld, the stream stops there, and the exit status is non-zero: for `-- CMD` that is the child's own status when it failed, and 1 when it succeeded, because the command ran and only its output is missing. Chunks already redacted are kept, so a broker lost mid-stream truncates the output rather than emptying it; a broker that was never up fails on the first chunk and writes nothing at all.
- Both `--env` and `--env-file` refuse a literal value and a name that cannot be an environment variable.
- One file refuses a name given twice with different refs. Across sources, a later `--env-file` wins over an earlier one, and `--env` wins over both.
- A bad line is reported with file and line. The offending value never appears.

### Allowing sudo on the controller

A brokered command runs as `faramir-exec`, which has no sudo, so a playbook that also configures the controller has to leave it out with `--limit '!controller'`. `sudo faramir init --allow-sudo` closes that split without moving the boundary: the executor gets a password-required sudoers entry pointed at a PAM service of faramir's own, whose auth step asks the broker whether a human approved the brokered command making the call. There is no credential — the answer is a decision — and `sudo faramir approve` (root, checked with `SO_PEERCRED`) answers it, one question per run.

Whether a host allows sudo at all is a deliberate, per-host choice made at `init`: **on**, and this host's executor is sandboxed as a uid that can become root on approval; **off** (the default), and it grants nothing. Re-running `init` without the flag takes it back.

The one seam nothing closes: an approved command gets real root and can make it permanent, exactly as `sudo ansible-playbook` by hand can. Approving is trusting *that command* with permanent root, so keep it operator-owned and read-only to brokered commands.

How to install, run and watch it, and the full caveat: [docs/operating.md](docs/operating.md#allowing-sudo-on-the-controller). Why it is shaped this way: [docs/design.md](docs/design.md#allowing-sudo-on-the-controller). Wiring Ansible to it: [docs/ansible-sops.md](docs/ansible-sops.md#4-becoming-root-on-the-controller).
### Operator commands

Command | Does
--- | ---
`sudo faramir init-project [DIR]` | Enrols one working tree, `DIR` defaulting to the current working directory. [Shares the tree](docs/layout.md), registers the hook and the MCP server in each enrolled agent's settings, and splices the credentials section into its instructions. `--agent` is repeatable, default `claude`. The client group comes from the installed config, [found the usual way](docs/operating.md#checking-an-install). A home directory, `/`, and anything above a home are refused, symlinks resolved first: sharing a home would hand `~/.ssh` and `~/.config/sops/age/keys.txt` to every brokered command, and the walk is not reversible. `faramir doctor` re-checks it.
`sudo faramir doctor` | Reports whether the install is doing its job, and as root what each account can reach. See [Checking an install](docs/operating.md#checking-an-install).
`sudo faramir edit FILE` | Opens a managed sops file, decrypting to a `0600` file in a root-owned tmpfs and re-encrypting on the way out. `FILE` is any name the `[secrets] files` globs reach, so a file dropped into the secrets directory is editable at once. `--age-key` names the key to decrypt with, `--editor` the editor to run.
`sudo faramir rekey [FILE...]` | Re-encrypts managed sops files to the recipients `<config-dir>/.sops.yaml` names now, which is how a changed creation rule reaches values encrypted before it changed. Every managed file unless some are named. Preserves each file's owner and mode, skips one already sealed to the rule, and refuses a rule that leaves out the keeper's own key. `--dry-run` writes nothing. See [Adding a recipient](docs/operating.md#adding-a-recipient).
`sudo faramir logs` | Recent audit records, or the one a short id names: id, local time, op, outcome, duration, how many values it stood in for, and the command; a redact reports the text's size instead, an edit or a rekey the managed file, a rekey also naming the recipients on each side, and an ask_approval whether it was approved, by whom, and which command's record it belongs to. Not brokered, and refused as any other account: the log is `0600 faramir-broker`. Printed as found rather than redacted again, the log holding no value. Rotated files are not searched.
`sudo faramir approve [--watch]` | Answer an approval a brokered command asked for. Root only: the broker checks `SO_PEERCRED`, because the account the coding agent runs as must not be able to approve what the agent asked for. `--watch` waits for questions and answers them from that terminal; without it, what is waiting is listed and `faramir approve ID` (or `--deny ID`) answers one. See [Allowing sudo on the controller](docs/operating.md#allowing-sudo-on-the-controller).
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
- The suite runs in a temp directory under one uid, so it covers the protocol, the PTY hand-off and the redactor, but never the uid boundary. That boundary is only real on a host, which is what `sudo faramir doctor` is for. Adversarial exfiltration is asserted nowhere; a value piped through `rev` reaches the caller transformed, as [Not prevented](#not-prevented) says.
- Every brokered command is confined to its own cgroup and reaped there, with no process-group fallback, so the executor refuses to run where it cannot make one — and the tests exercise that real path. They need cgroup v2 with `cgroup.kill` (kernel ≥ 5.14) and a cgroup the test process can subdivide, exactly as a real install grants the executor unit `Delegate=`. Run directly, they inherit whatever cgroup your shell is in; where that is not writable (an unprivileged CI runner in a root-owned service cgroup), hand the process a delegated one first — [the test workflow](.github/workflows/test.yml) does this with `mkdir`/`chown` under `/sys/fs/cgroup` and moving the shell in. Older kernels and cgroup v1 are unsupported, by the tool and so by the tests.
- The suite needs no `sops` on `PATH`: `internal/sopstest` builds a stand-in from the sops libraries. It is imported only from `_test.go`, which keeps sops out of the shipped binary; CI fails the build on a `getsops` import reaching `./cmd/faramir`.
- The opencode and Kilo Code plugins are the only shipped logic that is not Go, so they are run rather than read: node drives the shipped file against a stand-in guard, covering the rewrite, the refusal, a tool that is not a shell, and each way of failing closed. Skipped where node is absent. No test covers a running opencode or Kilo Code, or Bun, which is the runtime both load a plugin under.
