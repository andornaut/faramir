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
[Claude Code](https://claude.com/product/claude-code) | Full | `PreToolUse` in `.claude/settings.json`, MCP server in `.mcp.json`, account-wide keys in `~/.claude/settings.json` | ⚠️ Every Bash command is approved without asking, except what the deny list refuses. That list names credential disclosure and nothing destructive, so whatever prompting stood between the agent and `rm -rf` is gone and nothing here replaces it. Every other tool prompts as before, and `acceptEdits` does not exempt a project: it auto-accepts `Write` and `Edit` and leaves Bash prompting, which is the same cost. | Run in [auto mode](https://code.claude.com/docs/en/permission-modes), where a classifier model reviews the command before it runs: it reads the rewritten text rather than matching a rule against it, so the rewrite does not blind it. Extend the deny list.
[Gemini CLI](https://geminicli.com/docs/hooks/reference/) | Full | Hooks and `mcpServers` are both keys of `.gemini/settings.json`. Deny rules are a `.toml` under `~/.gemini/policies/`, the settings key that used to do this being deprecated: regexes against the tool's arguments, tested against rendered paths but not a running Gemini CLI. | None: there is no allow to return, so a hook that has not denied has not approved. | n/a
[opencode](https://open-code.ai/) | Full | [`tool.execute.before` plugin](https://open-code.ai/en/docs/plugins), JS, under `.opencode/plugins/`, mutating `output.args`. MCP server in `opencode.json`, account-wide `permission` deny patterns in `~/.config/opencode/opencode.json`. | None: a plugin that has not thrown has not approved either. ⚠️ Its `bash` rules match the command text, and whether they see the command or the rewrite is undocumented. | If commands start prompting as the wrapper rather than as themselves, the rules see the rewrite: a rule naming `source /usr/local/libexec/faramir/wrap.sh *` is what decides them from then on.
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
**Blast radius.** A brokered command runs anything the executor's uid can. | Out of scope. That uid is the bound.
**Network egress.** No iptables, namespaces or proxy allowlist. | Out of scope.
**Anything at rest.** Nothing here encrypts the disk. | The uid boundaries only hold while the machine is running. Full-disk encryption is the measure; the age key is a file like any other to someone holding the drive.
**Unenrolled projects.** The value set is global. | A command in a project you never enrolled can print a managed value uncaught.

## How it works

One binary, `faramir`. The daemons, the MCP server and the guard are subcommands of it, separated by the uid each unit runs its subcommand as.

uid | Runs | Holds
--- | --- | ---
you | the coding agent, and `faramir run` | nothing secret
`faramir-broker` | `faramir broker` | plaintext values in memory, SSH keys
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

### Redaction

Detail in [docs/redaction.md](docs/redaction.md).

1. **The value set is every managed secret**, not only the injected ones, refreshed when a managed file's mtime changes.
2. **Children run on a PTY**, so programs behave normally and writes to `/dev/tty` are captured. Consequence: stdout and stderr arrive merged.
3. **ANSI escapes are stripped before matching.**
4. **An expanded value set is matched**: raw, base64, URL-encoded, JSON-escaped, shell-quoted.
5. **Streaming uses an overlap buffer**, so a value split across reads is still caught.
6. **Values too short to redact are refused at load.** Length only: a short value matches inside ordinary words, and blanking those at random is a fault in this program rather than in the secret. How strong a credential is stays the operator's call. The broker names each refusal; the agent is told nothing.
7. **Tokens are stable**, so the model can reason about a secret across turns.

The age key is not in the value set: no child can obtain it.

### Design decisions

Decision | Choice | Rationale
--- | --- | ---
Isolation | Uid separation plus systemd hardening. No containers. | Network isolation is a non-goal, and it was the main thing containers made easy. A sandbox confines what a child sees; it is not a substitute for a uid that holds nothing.
How the roles are separated | `User=` in three units, all starting one binary. | The uid is what the kernel checks against `0400 faramir-keeper` and against a socket's group. Separate executables check nothing extra.
Filesystem isolation | None beyond file modes and `ProtectSystem=strict`. | A home the executor may not read is one the mode already refuses; one it may read, the agent can read directly.
Where commands run | The agent's working tree, directly. | A promotion gate buys an immutable snapshot and a commit sha, both properties against a deliberate agent, which is out of scope.
Who executes | The broker, as its own uid. | If the client execs, plaintext lives in a process the agent owns.
Who holds the key | A separate uid that executes nothing. | A key the broker can load is a key any brokered command can read.
Who forks the child | A third uid, given the PTY slave over `SCM_RIGHTS`. | Anything the forking uid can reach, the child can reach.
Command allowlist | None. | Any rule permitting an interpreter is reachable in one step through `bash`, which a usable policy must permit.
How a program gets values | `env_refs`, read from the environment. | The alternative is handing the program the master key.
Secrets at rest | sops plus age. | Encrypted YAML in the repo, per-key diffs, no network round trip.
Redaction | Custom, over the whole value set. | Off-the-shelf injectors mask only what they injected; a managed host can print a credential the broker never injected.
Agent interface | Unix socket exposed as MCP tools plus a CLI. | A distinct tool is more discoverable to a model than a documented convention.
Enforcement | Hook plus filesystem permissions. | Instructions to the agent are ergonomics, not a boundary.

### Layout

```text
/usr/local/bin/faramir        the only binary; every role is a subcommand
/usr/local/libexec/faramir/   the deny list and wrap.sh, rendered per install

/run/faramir/broker.sock      socket-activated, 0660 root:<client-group>
/run/faramir/keeper.sock      socket-activated, 0660 root:faramir-broker
/run/faramir/exec.sock        socket-activated, 0660 root:faramir-broker
/run/faramir/ssh-agent.sock   optional, 0660 faramir-broker:faramir-exec
<config-dir>/age.key          0400 faramir-keeper:faramir-keeper
<config-dir>/id_ed25519       0600 faramir-broker:faramir-broker, the key it lends; .pub 0644
<config-dir>/secrets/         2750 root:faramir-keeper, the managed sops files
<config-dir>/.sops.yaml       0644 root:root, the creation rule; above the secrets directory, not in it
<config-dir>/config.toml      0644 root:root, faramir's own, rewritten every run
<config-dir>/config.d/        0755 root:root, yours and each consumer's, merged over it
<any tree you enrol>          2770 <operator>:<client-group>, setgid; faramir init-project
~faramir-broker/.ssh/         0700 faramir-broker, the keys it lends through the agent
/var/log/faramir/             0750 faramir-broker:faramir-broker, LogsDirectoryMode=
/var/log/faramir/audit.log    0600 faramir-broker:faramir-broker; faramir logs reads it
/etc/logrotate.d/faramir      0644 root:root, weekly, 8 kept, early at 16MB
```

`--config-dir` moves the config, the secrets directory and the age key off `/etc` together; the audit log stays where it is. `faramir status` reports the paths in use.

A brokered command can write the working tree and reach the broker socket, its output redacted and audited like any other. It cannot reach the age key by any route: the modes above are what refuse the key file, the secrets directory, the keeper socket, the audit log and the SSH keys, no request returns the key, and nothing puts `SOPS_AGE_KEY` in its environment.

`0400 faramir-keeper` keeps the operator out of the key wherever it sits: owning the directory is permission to unlink the file, not to read it, so replacing the key buys denial of service rather than disclosure, secrets encrypted to the replaced key decrypting for nobody. Nothing starts the keeper at boot either; its unit is triggered only by its socket.

A tree inside a 0700 home needs traversal for `faramir-exec`. `faramir init-project` grants it by group: every directory from the home down becomes the client group and group-executable, execute only, so those uids pass through without listing what they pass. Never `chmod o+x`, which grants the same to every account on the machine. Everyone in the group gets that traversal, so keep membership to the accounts that need it. A directory already traversable by `other` is left alone; one whose group is something else is taken over, costing that group whatever the group bits gave it, and `init-project` says so. Membership is a permission, not a mount, so an encrypted home still unmounts at logout, though a brokered command running at the time holds it open.

The tree itself gets more than traversal: `2770` and group-readable and group-writable throughout, because a brokered command runs in it and writes to it. A whole tree, so a `.env` or a `.pem` sitting in the checkout is shared along with the code.

## Installation

Requires [systemd](https://systemd.io/) and [sops](https://github.com/getsops/sops); Go to build. The binary is static, so the host needs no interpreter.

```bash
make build
sudo ./bin/faramir init
```

`init` creates the accounts and groups, mints the age key, installs the binary, the deny list and the docs, renders the config and the systemd units, and starts the sockets. Idempotent, so it is also the upgrade: re-run it after a rebuild and it reports what changed.

Flag | Default | What to give it
--- | --- | ---
`--operator-user NAME` | `$SUDO_USER`, then you | An existing login account, the one your coding agent runs as. It owns the checkouts brokered commands run in, so root is refused. Anything escalating without sudo has to pass this.
`--client-group NAME` | `dev` | A group name, created if missing. One group doing two jobs: it admits a caller to the broker socket, and `init-project` group-owns a tree with it so the broker can stat a request's cwd and `faramir-exec` can run there. The operator is in it for the first, the broker and the executor for the second, the keeper for neither. The executor therefore reaches the broker socket, which buys it nothing: it can request the same injection the agent can, redacted and audited the same way.
`--secrets-group NAME` | `faramir-keeper` | A group name, created if missing. It owns the ciphertext in `<config-dir>/secrets`, and the keeper is the only account in it, so asking for a value by name and reading the file it came from stay different privileges. Not who may *use* a secret: the operator is deliberately out of this group, and `doctor` fails if they are in it. The default is the keeper's own group, so it follows `--keeper-user`.
`--config-dir DIR` | `/etc/faramir` | An absolute path for `config.toml`, `config.d/`, the age key and the managed sops files. It has to be mounted before the daemons read it, and its parent has to exist: this is the one directory faramir creates whose parent can be yours, and creating one would hand it to root.
`--broker-user`, `--exec-user`, `--keeper-user` NAME | `faramir-broker`, `faramir-exec`, `faramir-keeper` | Service account names, created if missing. Rename them freely; no two may share a name.
`--age-recipient KEY` | none | An age public key, repeatable, listed in `.sops.yaml` beside the keeper's so a backup of the ciphertext opens without the keeper's key. No identity is minted: the private half is yours to hold, and it opens a backup only if it outlives whatever took the keeper's key. The **public** half, checked before anything is written: `.sops.yaml` is world-readable, so an identity pasted here would hand the key that opens the secrets to every account on the host. Only read at the install that creates the file; see [Adding a recipient](#adding-a-recipient).
`--ssh-key PATH` | `<config-dir>/id_ed25519` | Where the identity the broker lends to brokered commands lives. One is minted either way, so this relocates rather than enables. Its public half must reach `authorized_keys` on every managed host; `init` prints it every run. An existing key at the path is adopted, not replaced, which is how you bring your own; it must already be `faramir-broker`-owned `0600` or `init` refuses it rather than chowning a key that may be yours. It names a keypair: the broker holds both halves and signs with the private one.
`--agent NAME` | none | `claude`, `gemini`, `opencode` or `kilocode`, repeatable. Installs that agent's deny rules into your own settings. Naming none installs none.
`--dry-run` | off | A switch. Reports what would change and writes nothing.
`--json` | off | A switch. Prints the report as JSON, one entry per step with a `changed` flag.

The units are sandboxed, so the config directory is not a free choice. `init` refuses whitespace and `%`, which systemd splits and expands in `Environment=`. It writes into `/tmp` and `/var/tmp`, but `PrivateTmp=true` gives each unit its own, so the daemons find nothing and say so.

`init` installs and never migrates: it writes what this version wants and leaves an older layout's leftovers alone.

### Adding a recipient

`--age-recipient` is read once, at the install that creates `.sops.yaml`. `init` keeps that file afterwards, so passing the flag to an installed host adds nothing: applying a changed rule means re-encrypting every managed value, which is not something a re-run of the installer should do behind your back.

A run that keeps the file reads it back, reports the recipients it actually lists as `age_recipients`, and warns naming any key you asked for that is not in there. `doctor` answers the same question about a host nobody is installing.

`faramir edit` does not apply a changed rule either, and for the same reason: it re-encrypts to the recipients a file already carries, so an edit cannot drop a reader mid-edit.

Applying one is two steps, both as root:

```bash
sudoedit /etc/faramir/.sops.yaml   # add the key under `- age:`
sudo faramir rekey                 # re-encrypt the secrets to what it now says
```

The first decides who can read files sops creates from then on. The second brings the files that already exist into line, decrypting each with the keeper's key and re-sealing it to the rule. Name files to do only some; `--dry-run` reports what would change and writes nothing.

- **The ownership and mode are preserved.** This is why `rekey` exists rather than a loop over `sops updatekeys`, which rewrites in place with no regard for either: a managed file that stops being readable by the secrets group is one the keeper cannot open.
- **A rule that drops the keeper's own key is refused**, before anything is decrypted. Re-encrypting to it would leave secrets nothing on the host can open, and re-running cannot undo that. This is the same drift `init` and `doctor` warn about: replace `age.key` (restored from a backup, or re-minted after the file was unlinked) and the rule still names the old recipient, so every value encrypted from then on is one the keeper cannot read.
- **Files already sealed to the rule are skipped.** Re-encrypting rewrites the data key even when the recipients are identical, so a rekey that did not compare first would make every file look changed.
- **Dropping a recipient is the same two steps**, and reaches no copy of the ciphertext that somebody already holds. Treat what that key could read as read.
- **A hand-written `.sops.yaml` with more than one creation rule is refused**, the recipients then depending on which `path_regex` a file matches. Use `sops updatekeys` per file, or `--sops-config` to name a single-rule file.
- **With the keeper's key as the only recipient there is nothing to keep in step.** `edit` decrypts and re-encrypts with `<config-dir>/age.key` every time, and `rekey` never needs running. The cost is that the key is the only way in: losing it loses every managed value, retroactively, and a second recipient is the backup that avoids it.

### Checking an install

```bash
sudo faramir doctor
```

A broker serving zero refs and a client group with members nobody recognises both look healthy otherwise. `doctor` checks what exists only once the install is on a host: the age key unreadable by every account but the keeper, the operator's own `~/.ssh` and `~/.config/sops` unreadable by the executor, the secrets group the keeper's alone, the config `[exec.base_env]` comes from unwritable by the operator, the binary and the deny list unwritable by it too, the keeper and executor sockets closed to the accounts that must not open them while the broker's is open to the operator, the audit log and the SSH keys unreadable by the executor while it can still authenticate, `ProtectProc` hiding the broker's environment, the `.sops.yaml` creation rule listing the keeper's own recipient rather than one it used to have, and a managed value injected into a real command coming back as its token.

Two checks need another uid: the broker's own `--check`, and asking each account what it can reach. Each is asked as the account it is about, root bypassing file modes so the same question from root answers itself. Without sudo those two report as unchecked rather than as passing.

The config path comes from the running broker; `--config-dir` overrides, for when the broker is what is wrong.

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
Something over SSH | Nothing. `init` renders `[ssh] key`; the child gets `SSH_AUTH_SOCK`.
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

### Operator commands

Command | Does
--- | ---
`sudo faramir init-project [DIR]` | Enrols one working tree, `DIR` defaulting to the current working directory. Shares the tree (group-owned and setgid, so you and a brokered command stop overwriting each other's ownership, and group-executable down from a `0700` home so the executor can enter), registers the hook and the MCP server in each enrolled agent's settings, and splices the credentials section into its instructions. `--agent` is repeatable, default `claude`. The client group comes from the installed config. A home directory, `/`, and anything above a home are refused, symlinks resolved first: sharing a home would hand `~/.ssh` and `~/.config/sops/age/keys.txt` to every brokered command, and the walk is not reversible. `faramir doctor` re-checks it.
`sudo faramir doctor` | Reports whether the install is doing its job, and as root what each account can reach. See [Checking an install](#checking-an-install).
`sudo faramir edit FILE` | Opens a managed sops file, decrypting to a `0600` file in a root-owned tmpfs and re-encrypting on the way out. `FILE` is any name the `[secrets] files` globs reach, so a file dropped into the secrets directory is editable at once. `--age-key` names the key to decrypt with, `--editor` the editor to run.
`sudo faramir rekey [FILE...]` | Re-encrypts managed sops files to the recipients `<config-dir>/.sops.yaml` names now, which is how a changed creation rule reaches values encrypted before it changed. Every managed file unless some are named. Preserves each file's owner and mode, skips one already sealed to the rule, and refuses a rule that leaves out the keeper's own key. `--dry-run` writes nothing. See [Adding a recipient](#adding-a-recipient).
`sudo faramir logs` | Recent audit records, or the one a short id names: id, local time, op, outcome, duration, how many values it stood in for, and the command; a redact reports the text's size instead, and an edit or a rekey the managed file, a rekey also naming the recipients on each side. Not brokered, and refused as any other account: the log is `0600 faramir-broker`. Printed as found rather than redacted again, the log holding no value. Rotated files are not searched.
`sudo faramir reload` | Stops the daemons, so the next brokered command starts them on a changed `config.d` drop-in. All three are socket activated.
`sudo faramir uninstall` | Removes the broker. Leaves the accounts, the config, the secrets, the key and the audit log, and says so: deleting the age key would make every managed sops file unreadable, retroactively.

### MCP tools

Tool | Description
--- | ---
`faramir_run(cmd, env_refs, cwd, timeout_sec)` | Run a command with secrets bound to environment variables.
`faramir_list_secrets()` | Ref names only.
`faramir_status()` | Config path, loaded files, ref count.

Wire protocol: [docs/protocol.md](docs/protocol.md).

### Notes

- **Adding or editing a managed sops file needs no config change**, but both daemons must be running for the new values to be picked up.
- **Changing `config.toml` needs both daemons restarted, keeper first.** Neither re-reads it while running.
- **The keeper must be up before the broker is.** On a cold start there is no previous value set, so a keeper it cannot reach means nothing to redact with, and the broker refuses `exec` and `redact` rather than serving that. Its unit `Requires=` the keeper socket and restarts on failure, so activation normally supplies this. A keeper lost *later* does not stop a running broker: it keeps the set it already has and retries.
- **Run `init` before enrolling a project with opencode or Kilo Code.** Their plugins fail closed, so an installed binary too old to know the agent refuses every command in that project rather than running it unredacted.
- **Children do not inherit the broker's environment.** They get `[exec.base_env]` plus injected secrets. Add what a tool needs there.
- **Interactive prompts fail rather than hang.** Stdin is `/dev/null`. Pass non-interactive flags.
- **Output is truncated** at `[exec] max_output_bytes`; the audit log keeps up to `[audit] max_record_bytes`.
- **The audit log rotates weekly**, 8 kept, compressed, and early at 16MB. `[audit] max_record_bytes` bounds one record, not the file. Delete `/etc/logrotate.d/faramir` to manage it some other way.
- **The audit log holds no value.** Output is recorded after redaction and `argv` is redacted on the way in.
- **There is one SSH key and `init` owns it.** It mints both halves into `<config-dir>`, so the key follows the config into an encrypted home the way the age key does, and `ProtectSystem=strict` leaves that directory read-only to the broker that uses it. A drop-in setting `[ssh] key` is refused; `--ssh-key` is what moves or adopts one.
- **The broker's home is `/var/lib/faramir-broker`**, granted by `StateDirectory=`.
- **Encrypt the disk.** LUKS on the root filesystem covers the age key, the secrets, the audit log and swap in one move.

## Configuration

[etc/config.toml.tmpl](etc/config.toml.tmpl) is what `init` renders, on every run. There is no command allowlist. What bounds a brokered command:

Setting | Effect
--- | ---
`[exec.base_env] PATH` | Where a bare name is looked up, and the only `PATH` the child gets.
`[exec] max_timeout_sec` | How long a command may run.
`[exec] max_output_bytes` | What comes back; the audit log keeps up to `[audit] max_record_bytes`.
`[secrets] min_length` | A value too short to redact is refused at load, so it can be injected by nothing.
the executor's uid | The real bound.

- `allowed_group` admits every member of one group including supplementary membership, and exists on `[server]` alone. `[keeper]` and `[executor]` have one legitimate client each, the broker, named in `allowed_user`; the group form is not a key there and setting it is a hard error naming the alternatives, because the only group in play is the client group, which holds the agent's own uid.
- No config names where a command runs. A brokered command runs where its caller was; a request naming no cwd is refused.
- A mistyped key or `[section]` is a hard error naming the alternatives. Values are range-checked. Zero stays legal where it means something (`kill_grace_sec = 0`, `refresh_interval_sec = 0`).
- **The sockets belong to their units.** Under socket activation the daemons are handed a listening descriptor and never reach the bind path, so `ListenStream=` and `SocketMode=` are what a socket is. No config key is a file mode: `--check` and `doctor` stat the bound socket for its mode rather than reading one. `socket_path` stays, because the broker *dials* the keeper and the executor at it, and because a daemon run outside systemd binds it itself; `init` renders it alongside the unit and a drop-in setting it is refused, since moving it would disconnect the broker from a daemon still listening where it always was. The broker binds its own ssh-agent socket, whose mode is a constant beside the code that sets it rather than a value a drop-in could widen past the group `exec_group` names.
- **Drop-ins.** `/etc/faramir/config.d/*.toml` merge over the base in lexical order. `config.toml` is faramir's own and `init` rewrites it every run, so an edit there is replaced without warning; `init` never touches a drop-in. That is what a drop-in is for: the non-generated place a generated file needs. What it can set is the defaults `init` does not derive: `[exec]` and `[exec.base_env]` entire, `[secrets] files`, `refresh_interval_sec` and `min_length`, `[server] max_concurrency` and `max_request_bytes`, and `[audit] max_record_bytes`. Not `decrypt_command`, which the base file sets and a second source is refused for. In practice you reach for `[exec.base_env]`, since the child inherits nothing else, and `default_timeout_sec` for a command that outruns ten minutes. Tables merge key by key, so one `[secrets] files` does not discard `min_length` and one `[exec.base_env]` variable does not mean restating `PATH`. Scalars replace.

**What init derives, a drop-in may not set.** The rule is the value's provenance, not its section: a value `init` computes from a flag or from the install is `init`'s and is refused outright; a value it writes as a plain default is a starting point, and yours.

Key | Flag it derives from
--- | ---
`[server] socket_path`, and the same on `[keeper]` and `[executor]` | rendered with the `.socket` units
`[server] allowed_group` | `--client-group`
`[keeper] allowed_user`, `[executor] allowed_user` | `--broker-user`
`[keeper] age_key_file` | `--config-dir`
`[keeper] age_key_credential` | rendered with the keeper unit's `LoadCredential=`
`[ssh] ssh_agent`, `[ssh] ssh_add` | resolved on `PATH` at install time; the broker execs them as its own uid
`[ssh] key` | `--ssh-key`
`[ssh] exec_group` | `--exec-user`, resolved to that account's own group at install time
`[ssh] agent_socket`, `[audit] log_path` | no flag: `/run/faramir` and `/var/log/faramir`, fixed at build time. The audit log does not follow `--config-dir`, `{{.LogDir}}` being the broker unit's `ReadWritePaths`

Each is one value, matching the one flag behind it. Two cost something rather than being tidiness: `exec_group` is the group the agent relay's `SO_PEERCRED` check admits, so a drop-in naming the client group there hands the broker's SSH identity to the account the relay exists to keep it from; `ssh_agent` and `ssh_add` are binaries the broker execs as the uid holding every plaintext value. `log_path` is rendered into `logrotate.conf` alongside, so moving one leaves rotation pointed at a file nothing writes.

Everything else is a default. Lists among them split by what they are:

What | Rule | Why
--- | --- | ---
`[secrets] files` | **accumulates**, duplicates collapsed | An inventory with one entry per owner. Replacing would leave the broker holding fewer files than its operator believes, injecting and redacting nothing for the loser. Entries are glob patterns, deduplicated again after expansion, so a drop-in naming a file the base already globs adds nothing.
`[secrets] decrypt_command` | **refused** when two sources set it, naming both | Policy, and the only list left that is. Accumulating would hand the keeper a second way to invoke sops by writing a file that never said so; taking the last would make it depend on filename order.

- Validation runs after merging, so a drop-in is held to every rule the base file is. `faramir status` and `faramir broker --check` report `configs`: the base file and every drop-in that contributed, in merge order.
- Dotfiles are skipped, so an editor's `.#name.toml` lock does not stop the daemons starting.

### The install gate, and the same gate at startup

`faramir broker --check` exits non-zero on anything that leaves the broker protecting less than it appears to.

Fails on | Because
--- | ---
An unknown key or `[section]` | A config that reads as though it took effect.
A value out of range | Same.
A ref too short to redact | Refused at load, so covered by nothing.
A `[secrets] files` entry that named nothing, or a file it named that did not load | Those values are absent from the redactor. A pattern that matches no file is the same failure as a literal path that is not there.
An `[ssh] key` the agent cannot load, passphrase-protected or not on disk | `ssh-add` refuses it, leaving every host unreachable. `init` catches one missing, unreadable by the broker, or without its `.pub`.
`[keeper]` or `[executor] allowed_user` naming an account that is not the broker | Each socket has one legitimate client. The keeper's is the age key by another route, and the executor's runs a command with no policy, no redaction and no audit record. The socket modes still stand in the way, so this is the second of two locks, and a gate that waits for both to be open reports the problem afterwards.
The bound broker socket having world bits | Every account on the host reaches the broker, whatever `allowed_group` says. Stat'ed, not read from the config, so it reflects what the `.socket` unit actually did. Unbound is reported as unchecked.

Secrets on a filesystem that is not mounted yet look exactly like ones never written, and both leave the broker redacting nothing. `--check` and `doctor` tell the two apart; the daemon refuses `exec` and `redact` for either rather than letting a command run unprotected.

Run it as the broker's own account. Run as root it reads what the broker cannot, and a key left `root:root` then passes a gate the broker fails on; the `allowed_user` check is skipped there too, since from root every name compares unequal. `faramir doctor` makes the same check knowing the account names.

**The daemon holds itself to the same rules, and on every request rather than at boot.** `--check` is run by `init` and by `doctor`, and neither runs at boot, so on its own it only ever described the host as it was at install time.

For the secrets it is one rule, and `exec` is held to it because a brokered command's output is redacted against the same set: **the broker serves `exec` and `redact` only while no managed file went unread.** At least one entry matched a file, and every matched file loaded. What those files held does not enter into it, so an install whose operator has not written a secret yet serves, and a ref no file defines is answered by `unknown_secret`. Otherwise the broker refuses with `no_secrets`, naming why. It comes up either way, `status` and `list_secrets` still answering, neither depending on the value set. Checked per request, so a reload that loses a file later is caught too. A keeper that could not be reached is the exception once a set has loaded, what is kept then being the last thing known to be true; a cold start has nothing to keep and refuses.

An `[ssh] key` the agent does not load is logged and not fatal. A value set the broker does not fully hold endangers the output of every command, so those are refused; a key the agent does not hold breaks only commands that reach a managed host, and those fail at the point of use with `ssh`'s own error. Stopping the daemon over it would stop the commands that never touch SSH and remove the process `status` and `doctor` ask. `--check` and `doctor` fail on it, which is where you find out without waiting for a playbook to.

An unset `[ssh] key` is not a failure, being the host that authenticates some other way.

### What no setting changes

- **Nothing the broker starts receives the age key.** No flag grants it; the broker does not hold it to grant. This bounds brokered commands and the agent, not root.
- **Secrets are injected as environment variables only.** Never into `argv`, which is visible in `ps` and `/proc/<pid>/cmdline`.
- **`cmd` is an array.** Never a string handed to `sh -c`.
- **The broker runs the working tree as it is on disk.** No promotion step.
- **`redactions` reports counts, not values.** `log_id` names the audit record, which holds the same tokens.

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

- Everything under `systemd/`, `etc/`, `agent/` and `docs/` is embedded into the binary by `assets.go`, so `init` installs a host without a checkout. The `.tmpl` files are the shipped files themselves, so what you read is what the install writes.
- Tests live where the logic does. Most of what the broker does is decide, and none of that needs a socket or a child process, so `internal/server` substitutes the executor. `internal/executor` uses a real child, because the PTY and the streaming redactor only mean anything against real bytes.
- The suite runs in a temp directory under one uid, so it covers the protocol, the PTY hand-off and the redactor, but never the uid boundary. That boundary is only real on a host, which is what `sudo faramir doctor` is for. Adversarial exfiltration is asserted nowhere; a value piped through `rev` reaches the caller transformed, as [Not prevented](#not-prevented) says.
- The suite needs no `sops` on `PATH`: `internal/sopstest` builds a stand-in from the sops libraries. It is imported only from `_test.go`, which keeps sops out of the shipped binary; CI fails the build on a `getsops` import reaching `./cmd/faramir`.
- The opencode and Kilo Code plugins are the only shipped logic that is not Go, so they are run rather than read: node drives the shipped file against a stand-in guard, covering the rewrite, the refusal, a tool that is not a shell, and each way of failing closed. Skipped where node is absent. No test covers a running opencode or Kilo Code, or Bun, which is the runtime both load a plugin under.

Doc | Covers
--- | ---
[docs/ansible-sops.md](docs/ansible-sops.md) | Pointing `group_vars` at the environment
[docs/design.md](docs/design.md) | Why the agent runs as the operator, how the rewrite works, what enrolment costs
[docs/protocol.md](docs/protocol.md) | Request and response shapes on the socket
[docs/redaction.md](docs/redaction.md) | What the redactor covers, and what it cannot
