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
Claude Code | Full | `PreToolUse` in `.claude/settings.json`, MCP server in `.mcp.json`, account-wide keys in `~/.claude/settings.json` | ⚠️ Every Bash command is approved without asking, except what the deny list refuses. Every other tool prompts as before. | Run in [auto mode](https://code.claude.com/docs/en/permission-modes), where a classifier model reviews the command before it runs: it reads the rewritten text rather than matching a rule against it, so the rewrite does not blind it. Extend the deny list.
[Gemini CLI](https://geminicli.com/docs/hooks/reference/) | Full | Hooks and `mcpServers` are both keys of `.gemini/settings.json`. Deny rules are a `.toml` under `~/.gemini/policies/`, the settings key that used to do this being deprecated: regexes against the tool's arguments, tested against rendered paths but not a running Gemini CLI. | None: there is no allow to return, so a hook that has not denied has not approved. | n/a
[opencode](https://open-code.ai/en/docs/plugins) | Full | `tool.execute.before` plugin, JS, under `.opencode/plugins/`, mutating `output.args`. MCP server in `opencode.json`, account-wide `permission` deny patterns in `~/.config/opencode/opencode.json`. | None: a plugin that has not thrown has not approved either. ⚠️ Its `bash` rules match the command text, and whether they see the command or the rewrite is undocumented. | If commands start prompting as the wrapper rather than as themselves, the rules see the rewrite: a rule naming `source /usr/local/libexec/faramir/wrap.sh *` is what decides them from then on.
[Kilo Code](https://kilo.ai/docs/automate/extending/plugins) | Full | Same plugin API under `.kilo/plugin/`, loaded by both the CLI and the VS Code extension. MCP server in `kilo.json`, deny patterns in `~/.config/kilo/kilo.json`. | Same as opencode. | Same as opencode.

Enrol with `faramir init-project --agent claude --agent gemini`, repeatable, defaulting to `claude`. The names are `claude`, `gemini`, `opencode` and `kilocode`.

n.b. Antigravity is not supported because its hooks decide and cannot rewrite.

## What it protects against

> [!IMPORTANT]
> The broker keeps plaintext out of model context. It does not contain a compromised agent.

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
**Blast radius.** A brokered command runs anything the executor's uid can. | |
**Network egress.** No iptables, namespaces or proxy allowlist. | |
**Anything at rest.** Nothing here encrypts the disk. | The uid boundaries only hold while the machine is running. See [Encryption at rest](#encryption-at-rest).
**Unenrolled projects.** The value set is global. | A command in a project you never enrolled can print a managed value uncaught.

**Acceptance invariant:** if every instruction the agent is given were deleted, no secret could reach the model provider. Every enforcement point is a uid boundary, a file mode, or a hook.

## How it works

One binary, `faramir` and an MCP server.

uid | Runs | Holds
--- | --- | ---
you | the coding agent, and `faramir run` | nothing secret
`faramir-keeper` | `faramir keeper`, and nothing but sops | the age master key
`faramir-broker` | `faramir broker` | plaintext values in memory, SSH keys
`faramir-exec` | `faramir exec` | nothing

The keeper/broker split is the one that matters: the age key decrypts every managed file retroactively, so it lives in a uid that executes nothing.

One call, end to end:

1. The request reaches `/run/faramir/broker.sock` carrying a ref, never a value. `cmd` is an array; there is no allowlist.
2. The broker asks the keeper over a socket only it can open. The keeper execs sops and returns values; the key stays in that uid.
3. The broker creates a PTY, hands the slave to the executor over `/run/faramir/exec.sock`, and the executor forks the command as `faramir-exec`: value in the environment, never in `argv`.
4. Output returns through the broker's end of the PTY. Every managed secret becomes `«SECRET:ref»` before the agent sees a byte.
5. The audit log records what ran, against which refs, and what came back. Tokens only, operator-readable only.

**SSH keys** are held by the broker and loaded into an `ssh-agent` it owns; the child gets only `SSH_AUTH_SOCK`, so it can authenticate and cannot read a key. `ssh-agent` refuses any peer uid but its own, so the broker relays, forwarding only `REQUEST_IDENTITIES` and `SIGN_REQUEST`.

## Install

Requires systemd and [sops](https://github.com/getsops/sops); Go to build. The binary is static, so the host needs no interpreter.

```bash
make build
sudo ./bin/faramir init --operator "$USER"
```

`init` does the whole install and is idempotent, so it is also the upgrade: re-run it after a rebuild and it reports what changed. It creates the accounts and the shared group, mints the age key, installs the binary, the hook's deny list and the docs, renders the config and the systemd units, and starts the sockets.

Flag | Default | What to give it
--- | --- | ---
`--operator NAME` | `$SUDO_USER`, then you | An existing login account, the one your coding agent runs as. It owns the checkouts brokered commands run in, so root is refused. Anything escalating without sudo has to pass this.
`--group NAME` | `dev` | A group name, created if missing. The service accounts join it; `init-project` group-owns a tree with it so `faramir-exec` can reach one.
`--config-dir DIR` | `/etc/faramir` | An absolute path for `config.toml`, `config.d/`, the age key and the managed sops files, which is one path so that the key cannot end up somewhere the store it opens is not. Inside a home works, with [the costs](docs/scope.md); under `/tmp` or `/var/tmp` does not, the units setting `PrivateTmp=true`.
`--broker-user`, `--keeper-user`, `--exec-user` NAME | `faramir-broker`, `faramir-keeper`, `faramir-exec` | Service account names, created if missing. Rename them freely; no two may share a name. `--store-group NAME` names the group owning the store, defaulting to the keeper's own.
`--operator-age-key PATH` | none | A path for your own age identity, minted if missing and listed in `.sops.yaml` beside the keeper's, so you can still read the files you are responsible for. `~/.config/sops/age/keys.txt` is where sops looks. `--age-recipient KEY` adds a public key instead, repeatable, minting nothing.
`--ssh-key PATH` | none | A path for the identity the broker lends to brokered commands, generated if missing. Its public half must reach `authorized_keys` on every managed host; `init` prints it every run.
`--agent NAME` | none | `claude`, `gemini`, `opencode` or `kilocode`, repeatable. Installs that agent's deny rules into your own settings. Naming none installs none.
`--dry-run` | off | Nothing: a switch. Reports what would change and writes nothing.
`--json` | off | Nothing: a switch. Prints the report as JSON, one entry per step with a `changed` flag, for a configuration manager to read.

The units are sandboxed, so where the config directory goes is not a free choice. `init` refuses whitespace and `%`, which systemd splits and expands in `Environment=`; `/tmp` and `/var/tmp` it writes into, but each unit gets a private one, so the daemons find nothing and say so. It relaxes the keeper's `ProtectHome=` when the directory is inside a home, binding back that one directory so the other homes stay invisible.

`init` installs and never migrates: it writes what this version wants and leaves an older layout's leftovers alone. Reconciling those belongs to whatever provisions the host.

- `faramir doctor` answers what an install cannot: whether what landed is doing its job. A broker serving zero refs, an `ssh-agent` holding no key and a shared group with members nobody recognises all look healthy otherwise. It asks the running broker which config it loaded rather than assuming the default; `--config-dir` names one itself, for when the broker is what is wrong.
- `faramir logs` lists the audit log's recent records, or prints the one a short id names. A row is the id, the local time, the op, how it ended and how long it took, how many values it stood in for, and the command; a redact reports the size of the text instead. Root, and not brokered. It prints what it finds rather than redacting again, the log holding no value to begin with. Rotated files are not searched.
- `faramir reload` gets the daemons onto a changed `config.d` drop-in. It stops them rather than restarting them: all three are socket activated, so the next brokered command starts them on the new config.
- `faramir uninstall` leaves the accounts, the config, the store, the key and the audit log alone, and says so. Deleting the age key would make every managed sops file unreadable, retroactively.
- `faramir init-project [DIR]` enrols one working tree, `DIR` defaulting to where you are standing. It shares the tree (group-owned and setgid, so you and a brokered command stop fighting over each other's files, and group-executable down from a `0700` home so the executor can enter), registers the hook and the MCP server in each enrolled agent's settings, and splices the credentials section into its instructions. `--agent` names which agents, repeatable, defaulting to `claude`. The shared group comes from the installed config rather than a flag.
- Enrol the projects where managed credentials are in play, not every tree. `--hook=false` shares one without the hook. A brokered command runs where its caller was, so nothing needs a tree of its own.

## Onboarding a project

Step | Do | Why
--- | --- | ---
1 | Put the values in one sops file under `/etc/faramir/secrets`, named after what consumes them. | Not in a checkout, so a clone or a branch cannot move the store. Under `/etc` it is there at boot; one inside an encrypted home is not, and the broker refuses to start rather than come up redacting nothing. `[secrets] files` globs that directory, so dropping the file in is the whole of naming it: the keeper picks it up on the next refresh, with no config to edit and no daemon to restart.
2 | Point the project's config at environment variables. | It never decrypts anything; it reads `$NAME` however it already does.
3 | Write the refs beside the project, one `NAME=secret://ref` per line. | So a run names refs rather than someone remembering them.
4 | `cd <project> && sudo faramir init-project` | Shares the tree so a brokered command can run in it, and writes each enrolled agent's settings and the instructions block. With Claude Code this is what auto-approves Bash there, which is why it is per project. Add `--agent gemini`, `--agent opencode` or `--agent kilocode` to enrol another agent too.

Step 1 is worth doing alone: a file in the store is redacted out of every command's output from then on, brokered or not.

A store somewhere the glob does not reach still needs naming, in a drop-in of its own: `files = ["/srv/other/x.sops.yml"]`. Entries accumulate across `config.d` and are deduplicated after expansion, so naming a file the base already globs costs nothing.

```bash
faramir list-secrets
faramir run --env TOKEN=secret://svc/token -- printenv TOKEN   # -> «SECRET:svc/token»
```

That proves both halves: the value reached the child, and it came back as a token.

### Worked example: an Ansible control repo

```text
/etc/faramir/secrets/ansible-ctrl.sops.yml   the values, outside every checkout
group_vars/all/vars.yml                      committed: var -> lookup('env', 'NAME')
faramir.env                                  NAME=secret://ref, one per line
.claude/settings.json, .mcp.json             hook and MCP for this repo
```

There is no drop-in: the base config globs `/etc/faramir/secrets/*.sops.yml`, so
the store file is managed by being in the store.

```yaml
# group_vars/all/vars.yml, committed, unencrypted, holds no value
router_password: "{{ lookup('env', 'ROUTER_PW') }}"
```

```bash
faramir run --env-file faramir.env -- ansible-playbook site.yml
```

Whether to commit the refs file is a judgement call: it discloses no value, but maps your variable names onto the store's layout. Full walk-through in [docs/ansible-sops.md](docs/ansible-sops.md).

### Other shapes

Only step 3 differs.

Shape | Step 3
--- | ---
A deploy or release script | Already reads `$TOKEN`. Nothing to change.
A cloud or infra CLI (`aws`, `terraform`, `flyctl`) | Name its documented environment variables; drop the credentials file.
A database task | `PGPASSWORD`, `MYSQL_PWD`. The connection string goes in `argv`, the password never does.
A registry push | `bash -lc 'printf %s "$TOKEN" \| docker login -u me --password-stdin'`
An HTTP call | `curl -H "Authorization: Bearer $TOKEN"` inside `bash -lc`, so the shell expands it.
A tool needing a credentials *file* | Have the command write it, use it, remove it. Injection is environment-only.
Something over SSH | Nothing. List the key in `[ssh] keys`; the child gets `SSH_AUTH_SOCK`.
Redaction only, no secret | Skip steps 3 to 5. `faramir redact -- ./script.sh`, or use it as a filter.

- A pipeline is requested explicitly as `["bash", "-lc", "…"]`; the broker never hands a string to a shell.
- A bare command name is looked up on `[exec.base_env] PATH`. Venv, pipx and shim directories belong there.
- Anything that wants to decrypt sops itself does not onboard. It gets named values instead.

## Usage

```bash
faramir status                          # config path, sources, ref count
faramir list-secrets                    # ref names, never values
faramir run --env NAME=secret://ref -- CMD
faramir run --env-file deploy.env -- ansible-playbook site.yml
faramir run --quiet -C ~/src/project -t 120 -- CMD
kubectl get secret -o yaml | faramir redact
faramir redact -- ./deploy.sh
```

Flag | Effect
--- | ---
`--env NAME=secret://ref` | Once per secret.
`--env-file FILE` | `NAME=secret://ref` per line, `#` comments.
`--quiet` | Suppress the redaction summary on stderr.
`--cwd`/`-C`, `--timeout`/`-t` | Working directory, runtime ceiling.
`--socket`, `--json` | On every broker-facing command.

- The child's exit code is faramir's own. A broker that is not running exits 69 (`EX_UNAVAILABLE`).
- Both `--env` and `--env-file` refuse a literal value and a name that cannot be an environment variable.
- One file refuses a name given twice with different refs. Across sources, a later `--env-file` wins over an earlier one, and `--env` wins over both.
- A bad line is reported with file and line. The offending value never appears.

Tool | Description
--- | ---
`faramir_run(cmd, env_refs, cwd, timeout_sec)` | Run a command with secrets bound to environment variables.
`faramir_list_secrets()` | Ref names only.
`faramir_status()` | Config path, loaded files, ref count.

Wire protocol: [docs/protocol.md](docs/protocol.md).

## Configuration

[etc/config.toml.tmpl](etc/config.toml.tmpl) is what `init` renders, on every run. There is no command allowlist. What bounds a brokered command:

Setting | Effect
--- | ---
`[exec.base_env] PATH` | Where a bare name is looked up, and the only `PATH` the child gets.
`[exec] max_timeout_sec` | How long a command may run.
`[exec] max_output_bytes` | What comes back; the audit log keeps up to `[audit] max_record_bytes`.
`[secrets] min_length` and friends | A value too short or low-entropy to redact is refused at load, so it can be injected by nothing.
the executor's uid | The real bound.

- `allowed_groups` admits every member of a group including supplementary membership. Intended on `[server]`. Leave it empty on `[keeper]` and `[executor]`, whose only legitimate client is the broker, named in `allowed_users`. Both warn at startup when it is not.
- No config names where a command runs. A brokered command runs where its caller was; a request naming no cwd is refused.
- A mistyped key or `[section]` is a hard error naming the alternatives. Values are range-checked. Zero stays legal where it means something (`kill_grace_sec = 0`, `refresh_interval_sec = 0`).
- **Drop-ins.** `/etc/faramir/config.d/*.toml` merge over the base in lexical order, and are where *everything you set* goes. `config.toml` is faramir's own and `init` rewrites it every run, so an edit there is replaced without warning; `init` never touches a drop-in. Tables merge key by key, so one `[secrets] files` does not discard `min_length` and one `[exec.base_env]` variable does not mean restating `PATH`. Scalars replace.

Lists split by what they are:

What | Rule | Why
--- | --- | ---
`[secrets] files`, `[ssh] keys` | **accumulate**, duplicates collapsed | Inventories with one entry per owner. Replacing would leave the broker holding fewer files than its operator believes, injecting and redacting nothing for the loser. `files` entries are glob patterns, deduplicated again after expansion, so a drop-in naming a file the base already globs adds nothing rather than decrypting it twice.
every other list | **refused** when two sources set it, naming both | `allowed_users`, `allowed_groups`, `allowed_uids` and `decrypt_command` are policy. Accumulating would widen what the sockets admit by writing a file that never said so; taking the last would make it depend on filename order.

- Validation runs after merging, so a drop-in is held to every rule the base file is. `faramir status` and `faramir broker --check` report `configs`: the base file and every drop-in that contributed, in merge order.
- Dotfiles are skipped, so an editor's `.#name.toml` lock does not stop the daemons starting.

### The install gate

`faramir broker --check` exits non-zero on anything that leaves the broker protecting less than it appears to.

Fails on | Because
--- | ---
An unknown key or `[section]` | A config that reads as though it took effect.
A value out of range | Same.
A ref too short or low-entropy to redact | Refused at load, so covered by nothing.
A `[secrets] files` entry that named nothing, or a file it named that did not load | Those values are absent from the redactor. A pattern that matches no file is the same failure as a literal path that is not there.
A `[ssh] key` missing, passphrase-protected, or the `.pub` | `ssh-add` refuses it, leaving every host unreachable.

A store on a filesystem that is not mounted yet looks exactly like one that was never written, and both leave the broker redacting nothing. Empty `[ssh] keys` passes.

Run it as the broker's own account. Run as root it reads what the broker cannot, and a key left `root:root` then passes a gate the broker fails on.

### Rules that do not bend

- **Nothing the broker starts receives the age key.** No flag grants it; the broker does not hold it to grant. This bounds brokered commands and the agent, not root.
- **Secrets are injected as environment variables only.** Never into `argv`, which is visible in `ps` and `/proc/<pid>/cmdline`.
- **`cmd` is an array.** Never a string handed to `sh -c`.
- **The broker runs the working tree as it is on disk.** No promotion step.
- **`redactions` reports counts, not values.** `log_id` points into the audit log, which records the same tokens. `sudo faramir logs <log-id>` prints that record; a bare `sudo faramir logs` lists the recent ones.

## Architecture

Decision | Choice | Rationale
--- | --- | ---
Isolation | Uid separation plus systemd hardening. No containers. | Network isolation is a non-goal, and it was the main thing containers made easy. A sandbox confines what a child sees; it is not a substitute for a uid that holds nothing.
How the roles are separated | `User=` in three units, all starting one binary. | The uid is what the kernel checks against `0400 faramir-keeper` and against a socket's group. Separate executables check nothing extra: reaching the key needs the key's mode, reaching the keeper needs its socket, and both are decided by the running uid.
Filesystem isolation | None beyond file modes and `ProtectSystem=strict`. | A home the executor may not read is one the mode already refuses; one it may read, the agent can read directly.
Where commands run | The agent's working tree, directly. | A promotion gate buys an immutable snapshot and a commit sha, both properties against a deliberate agent, which is out of scope.
Who executes | The broker, as its own uid. | If the client execs, plaintext lives in a process the agent owns.
Who holds the key | A separate uid that executes nothing. | A key the broker can load is a key any brokered command can read.
Who forks the child | A third uid, given the PTY slave over `SCM_RIGHTS`. | Anything the forking uid can reach, the child can reach.
Command allowlist | None. | Any rule permitting an interpreter is reachable in one step through `bash`, which a usable policy must permit.
How a program gets values | `env_refs`, read from the environment. | The alternative is handing the program the master key.
Secret store | sops plus age. | Encrypted YAML in the repo, per-key diffs, no network round trip.
Redaction | Custom, over the whole value set. | Off-the-shelf injectors mask only what they injected; a managed host can print a credential the broker never injected.
Agent interface | Unix socket exposed as MCP tools plus a CLI. | A distinct tool is more discoverable to a model than a documented convention.
Enforcement | Hook plus filesystem permissions. | Instructions to the agent are ergonomics, not a boundary.

### Layout

```text
/usr/local/bin/faramir        the only binary; every role below is a subcommand
/usr/local/libexec/faramir/   the deny list and wrap.sh, rendered per install

uid <operator>                you; runs the coding agent, member of group dev
uid faramir-keeper            faramir keeper: holds the age key; execs nothing but sops
uid faramir-broker            faramir broker: policy, redaction, audit log, SSH keys
uid faramir-exec              faramir exec: forks brokered commands; holds nothing

/run/faramir/broker.sock      socket-activated, 0660 root:dev
/run/faramir/keeper.sock      socket-activated, 0660 root:faramir-broker
/run/faramir/exec.sock        socket-activated, 0660 root:faramir-broker
/run/faramir/ssh-agent.sock   optional, 0660 faramir-broker:faramir-exec
<config-dir>/age.key          0400 faramir-keeper:faramir-keeper
<config-dir>/secrets/         2750 root:faramir-keeper, managed sops files and .sops.yaml
<config-dir>/config.toml      0644 root:root, faramir's own, rewritten every run
<config-dir>/config.d/        0644 root:root, yours and each consumer's, merged over it
<any tree you enrol>          2770 <operator>:dev, setgid; faramir init-project
/var/log/faramir/          0750 faramir-broker:faramir-broker, LogsDirectoryMode=
/var/log/faramir/audit.log    0600 faramir-broker:faramir-broker; faramir logs reads it
/etc/logrotate.d/faramir      0644 root:root, weekly, 8 kept, early at 16MB
```

`--config-dir` moves the config, the store and the age key off `/etc` together; the audit log stays where it is. `faramir status` reports the paths in use.

A brokered command cannot:

Cannot | Why
--- | ---
read the age key | 0400 `faramir-keeper`; `dev` is not in that mode.
read the managed sops files | 2750 `root:faramir-keeper`; nothing but the keeper is in that group, the broker included.
open the keeper socket | 0660 `root:faramir-broker`, and it is not in that group.
ask the keeper for the key | there is no such request.
read or truncate the audit log | 0600 `faramir-broker`.
read the SSH keys | 0700 `faramir-broker`; it gets an agent socket.
receive `SOPS_AGE_KEY` | nothing puts it there.

It **can** write the working tree, and reach the broker socket: the response is redacted and audited like any other.

A tree inside a 0700 home needs traversal for `faramir-exec`, which forks the command there. `faramir init-project` grants it by group: every directory from the home down becomes group `dev` and group-executable, execute only, so those uids pass through without being able to list what they pass. Never `chmod o+x`, which grants the same to every account on the machine.

Everyone in the group gets that traversal, so keep membership to the accounts that need it. A directory already traversable by `other` is left alone. One whose group is something else is taken over, which costs that group whatever the group bits gave it, and `init-project` says so when it does.

## Redaction

Detail in [docs/redaction.md](docs/redaction.md).

1. **The value set is every managed secret**, not only the injected ones, refreshed when a managed file's mtime changes.
2. **Children run on a PTY**, so programs behave normally and writes to `/dev/tty` are captured. Consequence: stdout and stderr arrive merged.
3. **ANSI escapes are stripped before matching.**
4. **An expanded value set is matched**: raw, base64, URL-encoded, JSON-escaped, shell-quoted.
5. **Streaming uses an overlap buffer**, so a value split across reads is still caught.
6. **Short or low-entropy values are refused at load.** The broker names them; the agent is told nothing.
7. **Tokens are stable**, so the model can reason about a secret across turns.

The age key is not in the value set: no child can obtain it.

## Verification

```bash
make test            # unit plus end-to-end, no privileges
sudo faramir doctor  # a live deployment, as the uid each claim is about
```

`doctor` is what checks the boundaries, because they only exist once the install is on a host: it establishes that the age key is unreadable by every account but the keeper, that the store group is the keeper's alone, that the operator cannot write the config `[exec.base_env]` comes from, that the keeper and executor sockets are closed to the accounts that must not open them while the broker's is open to the operator, that the audit log and the SSH keys are unreadable by the executor while it can still authenticate, that `ProtectProc` hides the broker's environment, and that a managed value injected into a real command comes back as its token.

It asks each of those as the account it is about, which is why it needs root: root bypasses file modes, so the same question asked from root answers itself. Run without it, the boundary findings are reported as unchecked rather than as passing.

Adversarial exfiltration is not among them and is not meant to be: a value piped through `rev` reaches the caller transformed, which is documented above rather than asserted anywhere.

`make test` runs everything else in a temp directory under a single uid, which exercises the protocol, the PTY hand-off and the redactor, not the uid boundary.

The opencode and Kilo Code plugins are the only shipped logic that is not Go, so they are run rather than read: node drives the shipped file against a stand-in guard, covering the rewrite, the refusal, a tool that is not a shell, and each way of failing closed. Skipped where node is absent. What no test covers is a running opencode or Kilo Code, or Bun, which is the runtime both load a plugin under.

## Operations

- **Editing a managed sops file needs nothing, and so does adding one.** `[secrets] files` globs the store, and the keeper expands it per request, so a file dropped in changes the state the broker polls and is picked up within `refresh_interval_sec`. Both daemons must be running.
- **Changing `config.toml` needs both daemons restarted, keeper first.** Neither re-reads it while running.
- **The keeper must be up before the broker is useful.** With no keeper the broker keeps its previous value set; on a cold start that set is empty and nothing is redacted.
- **Run `init` before enrolling a project with opencode or Kilo Code.** Their plugins fail closed, so an installed binary too old to know the agent refuses every command in that project rather than running it unredacted.
- **`[secrets] files` belongs under `/etc`, not a checkout.** A home is not mounted until login.
- **Children do not inherit the broker's environment.** They get `[exec.base_env]` plus injected secrets. Add what a tool needs there.
- **Interactive prompts fail rather than hang.** Stdin is `/dev/null`. Pass non-interactive flags.
- **Output is truncated** at `[exec] max_output_bytes`; the audit log keeps up to `[audit] max_record_bytes`.
- **The audit log rotates weekly**, 8 kept, compressed, and early at 16MB. `[audit] max_record_bytes` bounds one record, not the file. Delete `/etc/logrotate.d/faramir` to manage it some other way.
- **Encrypt the disk.** See below; the age key is a file like any other to someone holding the drive.
- **The audit log holds no value.** Output is recorded after redaction and `argv` is redacted on the way in.
- **A key the broker cannot use fails `--check`.** Missing, passphrase-protected, or the `.pub`.
- **SSH keys belong in `[ssh] keys`.** Left empty, they must sit in `~faramir-exec/.ssh` where every brokered command can read them.
- **The broker's home is `/var/lib/faramir-broker`**, granted by `StateDirectory=`.

## Encryption at rest

The age key sits beside the config and the store, so all three move together.
Where you put them is what decides the powered-off case:

`--config-dir` | Powered off, with the drive
--- | ---
`/etc/faramir` (default) | the key and the store are both on the root filesystem. Use full-disk encryption.
inside an encrypted home | the disk carries neither, and unlocking is the login that already gates the store.

LUKS on the root filesystem is the measure that does not depend on where
anything ended up, and it covers the audit log, `/var/lib/faramir-broker` and
swap in one move. An encrypted home covers the key and the store and nothing
else.

`0400 faramir-keeper` is what keeps the operator out of the key, and it holds
wherever the key sits: owning the directory is permission to unlink the file,
not to read it. Replacing the key buys denial of service rather than
disclosure, a store encrypted to the replaced key decrypting for nobody. See
[docs/scope.md](docs/scope.md).

Nothing starts the keeper at boot. Its unit is triggered only by its socket, so
a config directory in a home is read after login, when the home is there.

## Development

```bash
make build           # a static binary into bin/
make coverage        # race-enabled suite plus per-function report
make fmt             # apply the import and format rules CI checks
make lint            # golangci-lint
make sizes           # binary size, package count, sops linkage
make test            # whole suite; needs no sops installed
make test-e2e        # end-to-end against a real broker in a temp dir
make test-unit       # everything except end-to-end
```

- Everything under `systemd/`, `etc/`, `agent/` and `docs/` is embedded into the binary by `assets.go`, so `init` installs a host without a checkout. The `.tmpl` files are the shipped files themselves, so what you read is what the install writes.
- Tests live where the logic does. Most of what the broker does is decide, and none of that needs a socket or a child process, so `internal/server` substitutes the executor. `internal/executor` uses a real child, because the PTY and the streaming redactor only mean anything against real bytes.
- The suite needs no `sops` on `PATH`: `internal/sopstest` builds a stand-in from the sops libraries. It is imported only from `_test.go`, which keeps sops out of the shipped binary; CI fails the build on a `getsops` import reaching `./cmd/faramir`.
- sops is executed, not linked: linking pulls its whole key-source tree into the process holding the master key.
- Regexes are RE2. No lookahead, no backreferences. `internal/guard` asserts every shipped pattern compiles and that the file matches the built-in fallback.
- Every subcommand answers `--version` from `internal/version`, and they all answer the same thing: one binary, one version.

Doc | Covers
--- | ---
[docs/redaction.md](docs/redaction.md) | What the redactor covers, and what it cannot
[docs/protocol.md](docs/protocol.md) | Request and response shapes on the socket
[docs/ansible-sops.md](docs/ansible-sops.md) | Pointing `group_vars` at the environment
[docs/scope.md](docs/scope.md) | What this defends, and what it stops trying to
