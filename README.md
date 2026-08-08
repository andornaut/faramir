# faramir

A secret broker for local AI coding agents. It runs the commands that need credentials as a uid that holds nothing, and redacts the output of everything else the agent runs, so no plaintext credential enters the agent's context or reaches a model provider.

```console
$ faramir run --env ROUTER_PW=secret://home/router/admin -- printenv ROUTER_PW
«SECRET:home/router/admin»
[faramir] redacted «SECRET:home/router/admin»×1; log_id=2026-08-05T14:22:01Z-a91f
```

The command ran, the credential reached it, the agent never saw the value.

> [!WARNING]
> **Enrolling a project auto-approves every Bash command in it.**
>
> The hook rewrites each command into a wrapper so the output can be redacted. A rewritten command matches no Bash permission rule, so the hook approves whatever its [deny list](agent/hooks/deny-patterns.txt) did not refuse. This is forced by the mechanism, not a setting.
>
> - Prompts on `Write` and `Edit` do not compensate: Bash does the same things (`sed -i`, `cat >`, `rm`) without asking.
> - Every other tool's permissions are untouched, and faramir adds `Read` deny rules for key material.
> - Enrolment is per project. An unenrolled repo keeps its prompts and gets no redaction.
> - **Under `--dangerously-skip-permissions` this costs nothing**: Bash never prompted, and hook decisions are still honoured, a `deny` included. Enrolling an unattended project is purely additive.
> - `acceptEdits` is not that case. It leaves Bash prompting, so enrolment costs what it costs by default.

## What it protects against

> [!IMPORTANT]
> The broker keeps plaintext out of model context. It does not contain a compromised agent.

### Prevented

Failure | How
--- | ---
Accidental disclosure: `printenv`, a vault read, `-vvv`, a `debug: var=` task | No account can read the key material, yours included; output is redacted before the agent sees it
Passive discovery: reading an age key, an SSH key, another process's `/proc/<pid>/environ` | Uid separation plus `ProtectProc=invisible`
Casual prompt injection: instructions to print or exfiltrate credentials | The agent process never holds them
Loss of the master key, which decrypts every managed file retroactively | It lives in a uid that executes nothing; no brokered command can read it, reach the keeper's socket, or receive it in its environment

### Not prevented

Failure | Why
--- | ---
**Adversarial exfiltration.** Transforming a value (`\| rev`, `\| sha256sum`) defeats redaction. | The child chooses the encoding of its own output, so the matcher cannot be completed. Demonstrated in `verify.sh`, not asserted away.
**Blast radius.** A brokered command runs anything the executor's uid can. | Out of scope, and compounded by Bash auto-approval in enrolled projects.
**Network egress.** No iptables, namespaces or proxy allowlist. | Deliberate. A secret that escapes redaction is unrecoverable.
**Anything at rest.** Nothing here encrypts the disk. | The uid boundaries hold while the machine runs and mean nothing once someone has the drive. See [Encryption at rest](#encryption-at-rest).
**Unenrolled projects.** The value set is global. | A command in a project you never enrolled can print a managed value uncaught. Treat unenrolled as "no redaction", not "safe".

**Acceptance invariant:** if every instruction the agent is given were deleted, no secret could reach the model provider. Every enforcement point is a uid boundary, a file mode, or a hook.

## How it works

uid | Holds | Runs
--- | --- | ---
you | nothing secret | the coding agent
`faramir-keeper` | the age master key | nothing but sops
`faramir-broker` | plaintext values in memory, SSH keys | policy, redaction, the audit log
`faramir-exec` | nothing | brokered commands

The keeper/broker split is the one that matters: the age key decrypts every managed file retroactively, so it lives in a uid that executes nothing.

One call, end to end:

1. The request reaches `/run/faramir/broker.sock` carrying a ref, never a value. `cmd` is an array; there is no allowlist.
2. The broker asks the keeper over a socket only it can open. The keeper execs sops and returns values; the key stays in that uid.
3. The executor forks the command as `faramir-exec` on a PTY the broker created, value in the environment, never in `argv`.
4. Output returns through the broker's end of the PTY. Every managed secret becomes `«SECRET:ref»` before the agent sees a byte.
5. The audit log records what ran, against which refs, and what came back. Tokens only, operator-readable only.

**SSH keys** are held by the broker and loaded into an `ssh-agent` it owns; the child gets only `SSH_AUTH_SOCK`. It can authenticate and cannot read a key. `ssh-agent` refuses any peer uid but its own, so the broker relays, forwarding only `REQUEST_IDENTITIES` and `SIGN_REQUEST`.

## Install

Requires systemd and [sops](https://github.com/getsops/sops); Go to build. Binaries are static, so the host needs no interpreter.

```bash
make build
sudo ./bin/faramir init --operator "$USER"
```

Two commands: the compiler should not run as root, and `init` works on a host with no Go.

`init` does the whole install and is idempotent, so it is also the upgrade: re-run it after a rebuild and it reports what changed. It creates the accounts and the shared group, mints the age key, installs the binaries, the hook and the docs, renders the config and the systemd units, and starts the sockets. It writes the units and the config from one set of values, which is what keeps the group named in `allowed_groups` and the one in `SupplementaryGroups=` from drifting apart: they cannot, because both come from `--group`.

Flag | Does
--- | ---
`--operator NAME` | the account the coding agent runs as. Defaults to `$OPERATOR`, then `$SUDO_USER`. Never root
`--group NAME` | the shared group. Named in the config the sockets check and in the units that reach a working tree
`--config-dir DIR` | where `config.toml` and `config.d/` go. `--secrets-dir DIR` does the same for the sops store
`--binaries DIR` | read the built binaries from here instead of the directory `faramir` itself is in, so you can build on one machine and install on another
`--operator-age-key PATH` | mint an identity for yourself and list it in `.sops.yaml` alongside the keeper's, so you can still read the files you are responsible for
`--ssh-key PATH` | generate the identity the broker lends to brokered commands. Its public half must reach `authorized_keys` on every managed host; `init` prints it every run
`--seal-age-key` | take the age key from a TPM-sealed credential. `--remove-plaintext-age-key` then deletes the file, which is irreversible
`--agent-config` | install the `Read` deny rules into your own Claude settings
`--dry-run` | report what would change and write nothing
`--json` | print the report as JSON, one entry per step with a `changed` flag, for a configuration manager to read

The units are sandboxed, so where the config and the store go is not a free choice. `init` refuses `/tmp` and `/var/tmp` (each unit gets a private one), refuses whitespace and `%` (systemd splits and expands `Environment=`), refuses two service accounts sharing a name (that is the boundary), and relaxes the keeper's `ProtectHome=` for you when either directory is inside a home, binding back only what it must so the other homes stay invisible.

`init` installs and never migrates. It writes what this version wants and leaves anything an older layout put on the host alone, because a repair compiled into it cannot know when every host has run it and would be carried forever. Reconciling that belongs to whatever provisions the host, in something that can be deleted once the fleet has converged.

- `faramir doctor` answers the question an install cannot: whether what landed is doing its job. A broker serving zero refs, an `ssh-agent` holding no key, and a shared group with members nobody recognises all look like a healthy install until something says otherwise. It asks the running broker which config it loaded rather than assuming the default, so it examines the install that is there; `--config-dir` names one itself, which is what to use when the broker is the thing that is wrong.
- `faramir reload` gets the daemons onto a changed `config.d` drop-in. It stops them rather than restarting them: all three are socket activated, so the next brokered command starts them on the new config, and the order they come up in is the order activation gives them (the broker connects to the keeper, which is what decrypts the file list it is then served).
- `faramir uninstall` leaves the accounts, the config, the store, the key and the audit log alone, and says so. Deleting the age key would make every managed sops file unreadable, retroactively.
- `faramir init-project [DIR]` enrols one working tree, and `DIR` defaults to where you are standing. It shares the tree (group-owned and setgid, so you and a brokered command stop fighting over each other's files, and group-executable on every directory down from a `0700` home so the executor can enter), registers the `PreToolUse` hook in that project's own settings, writes `.mcp.json`, and splices the credentials section into its agent instructions. It reads the shared group out of the installed config rather than taking a flag, so a tree cannot end up group-owned by something the sockets do not admit.
- Enrolling is per project because the hook's cost is: it rewrites every Bash command so the output can be redacted, and a rewritten command matches no permission rule, so Bash is auto-approved in that project and the hook's deny list is what refuses one. Worth it where managed credentials are in play; not worth it everywhere. `--hook=false` shares the tree without it. Nothing needs a tree of its own either way: a brokered command runs where its caller was.

## Onboarding a project

Step | Do | Why
--- | --- | ---
1 | Put the values in one sops file under `/etc/faramir/secrets`, named after what consumes them | Not in a checkout, so the store is not something a clone or a branch can move. Keeping it under `/etc` also means it is there at boot; a store inside an encrypted home is not, and the broker refuses to start rather than come up redacting nothing
2 | Name it in `/etc/faramir/config.d/<project>.toml`, then restart `faramir-keeper` and `faramir-broker`, in that order | This is what puts the values in the redaction set. A drop-in rather than the base config, so the project owns the line naming its own store. A restart because neither daemon re-reads its config; the keeper leads because it decrypts the list the broker is served. Step 1 first: a named file that is not there fails the gate, so the drop-in comes after the store, never before
3 | Point the project's config at environment variables | It never decrypts anything; it reads `$NAME` however it already does
4 | Write the refs beside the project, one `NAME=secret://ref` per line | So a run names refs rather than someone remembering them
5 | `cd <project> && sudo faramir init-project` | Shares the tree so a brokered command can run in it, and writes the project's `.claude/settings.json`, `.mcp.json` and instructions block. This is what auto-approves Bash there, so it is a per-project command rather than something the install does to every tree

Step 2 is worth doing alone: a file in `[secrets]` is redacted out of every command's output from then on, brokered or not.

```bash
faramir list-secrets
faramir run --env TOKEN=secret://svc/token -- printenv TOKEN   # -> «SECRET:svc/token»
```

That proves both halves: the value reached the child, and it came back as a token.

### Worked example: an Ansible control repo

```text
/etc/faramir/secrets/ansible-ctrl.sops.yml   the values, outside every checkout
/etc/faramir/config.d/ansible-ctrl.toml      names that file and the SSH key to lend
group_vars/all/vars.yml                      committed: var -> lookup('env', 'NAME')
faramir.env                                  NAME=secret://ref, one per line
.claude/settings.json, .mcp.json             hook and MCP for this repo
```

```toml
# /etc/faramir/config.d/ansible-ctrl.toml, the whole of it
[secrets]
files = ["/etc/faramir/secrets/ansible-ctrl.sops.yml"]

[ssh]
keys = ["/var/lib/faramir-broker/.ssh/id_ed25519"]
```

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
A deploy or release script | Already reads `$TOKEN`. Nothing to change
A cloud or infra CLI (`aws`, `terraform`, `flyctl`) | Name its documented environment variables; drop the credentials file
A database task | `PGPASSWORD`, `MYSQL_PWD`. The connection string goes in `argv`, the password never does
A registry push | `bash -lc 'printf %s "$TOKEN" \| docker login -u me --password-stdin'`
An HTTP call | `curl -H "Authorization: Bearer $TOKEN"` inside `bash -lc`, so the shell expands it
A tool needing a credentials *file* | Have the command write it, use it, remove it. Injection is environment-only
Something over SSH | Nothing. List the key in `[ssh] keys`; the child gets `SSH_AUTH_SOCK`
Redaction only, no secret | Skip steps 3 to 5. `faramir redact -- ./script.sh`, or use it as a filter

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
`--env NAME=secret://ref` | Once per secret
`--env-file FILE` | `NAME=secret://ref` per line, `#` comments
`--quiet` | Suppress the redaction summary on stderr
`--cwd`/`-C`, `--timeout`/`-t` | Working directory, runtime ceiling
`--socket`, `--json` | On every broker-facing command

- The child's exit code is faramir's own. A broker that is not running exits 69 (`EX_UNAVAILABLE`).
- Both `--env` and `--env-file` refuse a literal value and a name that cannot be an environment variable.
- One file refuses a name given twice with different refs. Across sources, a later `--env-file` wins over an earlier one, and `--env` wins over both.
- A bad line is reported with file and line. The offending value never appears.

Tool | Description
--- | ---
`faramir_run(cmd, env_refs, cwd, timeout_sec)` | Run a command with secrets bound to environment variables
`faramir_list_secrets()` | Ref names only
`faramir_status()` | Config path, loaded files, ref count

Wire protocol: [docs/protocol.md](docs/protocol.md).

## Configuration

[etc/config.toml](etc/config.toml) is the starter. There is no command allowlist. What bounds a brokered command:

Setting | Effect
--- | ---
`[exec.base_env] PATH` | Where a bare name is looked up, and the only `PATH` the child gets
`[exec] max_timeout_sec` | How long a command may run
`[exec] max_output_bytes` | What comes back; the audit log keeps up to `[audit] max_record_bytes`
`[secrets] min_length` and friends | A value too short or low-entropy to redact is refused at load, so it can be injected by nothing
the executor's uid | The real bound

- `allowed_groups` admits every member of a group including supplementary membership. Intended on `[server]`. Leave it empty on `[keeper]` and `[executor]`, whose only legitimate client is the broker, named in `allowed_users`. Both warn at startup when it is not.
- No config names where a command runs. A brokered command runs where its caller was; a request naming no cwd is refused.
- A mistyped key or `[section]` is a hard error naming the alternatives. Values are range-checked. Zero stays legal where it means something (`kill_grace_sec = 0`, `refresh_interval_sec = 0`).
- **Drop-ins.** `/etc/faramir/config.d/*.toml` merge over the base in lexical order, which is where the settings belonging to whatever *consumes* the broker go. Tables merge key by key, so naming one `[secrets] files` does not discard `min_length` and adding one `[exec.base_env]` variable does not mean restating `PATH`. Scalars replace.

Lists split by what they are:

What | Rule | Why
--- | --- | ---
`[secrets] files`, `[ssh] keys` | **accumulate**, duplicates collapsed | Inventories with one entry per owner. Two projects each naming their own store both want theirs managed; replacing would leave the broker holding fewer files than its operator believes, injecting nothing for the loser and redacting nothing either.
every other list | **refused** when two sources set it, naming both | `allowed_users`, `allowed_groups`, `allowed_uids` and `decrypt_command` are policy. Accumulating would widen what the sockets admit by writing a file that never said so; taking the last would make it depend on filename order.

- Validation runs after merging, so a drop-in is held to every rule the base file is. `faramir status` and `faramir-broker --check` both report `configs`, the base file and every drop-in that contributed in the order they were merged, which is where to look when a setting is not what you expect.
- Dotfiles are skipped, so an editor's `.#name.toml` lock does not stop the daemons starting.

### The install gate

`faramir-broker --check` exits non-zero on anything that leaves the broker protecting less than it appears to.

Fails on | Because
--- | ---
An unknown key or `[section]` | A config that reads as though it took effect
A value out of range | Same
A ref too short or low-entropy to redact | Refused at load, so covered by nothing
A `[secrets]` file that did not load, including one that is not there | Those values are absent from the redactor
A `[ssh] key` missing, passphrase-protected, or the `.pub` | `ssh-add` refuses it, leaving every host unreachable

Absent is not a lesser failure than unreadable: a store on a filesystem that is not mounted yet looks exactly like one that was never written, and both leave the broker redacting nothing. Empty `[ssh] keys` passes.

Run it as the broker's own account. Run as root it reads what the broker cannot, and a key left `root:root` then passes a gate the broker fails on.

### Rules that do not bend

- **Nothing the broker starts receives the age key.** No flag grants it; the broker does not hold it to grant. This bounds brokered commands and the agent, not root.
- **Secrets are injected as environment variables only.** Never into `argv`, which is visible in `ps` and `/proc/<pid>/cmdline`.
- **`cmd` is an array.** Never a string handed to `sh -c`.
- **The broker runs the working tree as it is on disk.** No promotion step.
- **`redactions` reports counts, not values.** `log_id` points into the audit log, which records the same tokens.

## Architecture

Decision | Choice | Rationale
--- | --- | ---
Isolation | Uid separation plus systemd hardening. No containers. | Network isolation is a non-goal, and it was the main thing containers made easy. A sandbox confines what a child sees; it is not a substitute for a uid that holds nothing.
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
uid <operator>                you; runs the coding agent, member of group dev
uid faramir-keeper            holds the age key; execs nothing but sops
uid faramir-broker            policy, redaction, audit log, SSH keys
uid faramir-exec              forks brokered commands; holds nothing

/run/faramir/broker.sock      socket-activated, 0660 root:dev
/run/faramir/keeper.sock      socket-activated, 0660 root:faramir-broker
/run/faramir/exec.sock        socket-activated, 0660 root:faramir-broker
/run/faramir/ssh-agent.sock   optional, 0660 faramir-broker:faramir-exec
/etc/faramir/age.key          0400 faramir-keeper:faramir-keeper
/etc/faramir/secrets/         2770 root:dev, managed sops files and .sops.yaml
/etc/faramir/config.toml      0644 root:root, read by all three daemons
/etc/faramir/config.d/        0644 root:root, per-consumer settings merged over it
<any tree you enrol>          2770 <operator>:dev, setgid; faramir init-project
/var/log/faramir/audit.log    0600 faramir-broker:faramir-broker
```

`CONFIG_DIR` and `SECRETS_DIR` move the config and the store off `/etc`; the age key and the audit log stay where they are. `faramir status` reports the paths in use.

A brokered command cannot:

Cannot | Why
--- | ---
read `/etc/faramir/age.key` | 0400 `faramir-keeper`; `dev` is not in that mode
open the keeper socket | 0660 `root:faramir-broker`, and it is not in that group
ask the keeper for the key | there is no such request
read or truncate the audit log | 0600 `faramir-broker`
read the SSH keys | 0700 `faramir-broker`; it gets an agent socket
receive `SOPS_AGE_KEY` | nothing puts it there

It **can** write the working tree, which is the point, and reach the broker socket, which buys it nothing: the response is redacted and audited like any other.

A tree inside a 0700 home needs traversal for `faramir-exec`, which forks the command there. `faramir init-project` grants it by group: every directory from the home down becomes group `dev` and group-executable, execute only, so those uids pass through without being able to list what they pass. Never `chmod o+x`, which grants the same to every account on the machine, and with `umask 002` in force the files below are `0664`, so that opens the home rather than a path through it.

The group slot is the one going spare on a home its owner holds outright, and it costs nothing to use: `chgrp` is ordinary inode metadata, so it passes through an encrypted home unchanged and needs no extra tooling. What it does cost is that everyone in the group gets it, so keep membership to the accounts that need it.

A directory already traversable by `other` is left alone: tightening one its owner chose to open is not this command's business. One whose group is something else is taken over, which costs that group whatever the group bits gave it, and `init-project` says so when it does.

## Redaction

Detail in [docs/redaction.md](docs/redaction.md).

1. **The value set is every managed secret**, not only the injected ones, refreshed when a managed file's mtime changes.
2. **Children run on a PTY**, so programs behave normally and writes to `/dev/tty` are captured. Consequence: stdout and stderr arrive merged.
3. **ANSI escapes are stripped before matching.**
4. **An expanded value set is matched**: raw, base64, URL-encoded, JSON-escaped, shell-quoted.
5. **Streaming uses an overlap buffer**, so a value split across reads is still caught.
6. **Short or low-entropy values are refused at load.** The broker names them; the agent is told nothing.
7. **Tokens are stable**, so the model can reason about a secret across turns.

The age key is not in the value set and does not need to be: no child can obtain it.

## Verification

```bash
make test          # unit plus end-to-end, no privileges
sudo make verify   # the matrix, against a live deployment
```

[tests/verify.sh](tests/verify.sh) is the list. It establishes, as the uid that matters, that the age key is unreadable by everyone but the keeper; that the audit log and SSH keys are unreadable by the executor while it can still authenticate; that redaction covers the value set through base64, `-vvv` and `/dev/tty`; that the audit log holds tokens only; and that command resolution refuses a program off `PATH`.

Two checks are demonstrations rather than assertions: piping a secret through `rev` or `cut` reaches the caller transformed. Nothing pins it, because a test that fails when redaction improves is a test that has to be deleted.

`make test` runs everything else in a temp directory under a single uid, which exercises the protocol, the PTY hand-off and the redactor, not the uid boundary.

## Operations

- **Editing a managed sops file needs nothing.** The broker picks it up within `refresh_interval_sec`, asking the keeper to decrypt, so both must be running.
- **Changing `config.toml` needs both daemons restarted, keeper first.** Neither re-reads it while running.
- **The keeper must be up before the broker is useful.** With no keeper the broker keeps its previous value set; on a cold start that set is empty and nothing is redacted.
- **`[secrets] files` belongs under `/etc`, not a checkout.** A home is not mounted until login.
- **Children do not inherit the broker's environment.** They get `[exec.base_env]` plus injected secrets. Add what a tool needs there.
- **Interactive prompts fail rather than hang.** Stdin is `/dev/null`. Pass non-interactive flags.
- **Output is truncated** at `[exec] max_output_bytes`; the audit log keeps up to `[audit] max_record_bytes`.
- **The audit log grows without bound.** Add logrotate; keep it 0600 and `faramir-broker`.
- **Encrypt the disk.** See below; `/etc/faramir/age.key` is a file like any other to someone holding the drive.
- **The audit log holds no value.** Output is recorded after redaction and `argv` is redacted on the way in.
- **A key the broker cannot use fails `--check`.** Missing, passphrase-protected, or the `.pub`.
- **SSH keys belong in `[ssh] keys`.** Left empty, they must sit in `~faramir-exec/.ssh` where every brokered command can read them.
- **The broker's home is `/var/lib/faramir-broker`**, granted by `StateDirectory=`.

## Encryption at rest

`/etc/faramir/age.key` is `0400 faramir-keeper`, which is a *running-system*
boundary. Powered off, it is an ordinary file on an ordinary filesystem, and it
decrypts every managed secret retroactively.

Use full-disk encryption. LUKS on the root filesystem covers the key, the audit
log, `/var/lib/faramir-broker` and swap in one move, and is the only measure
here that survives the drive leaving the building.

### Sealing the key to a TPM

Where a TPM and systemd 250 or later are available, the key can be sealed on its
own, which needs no disk surgery:

```bash
sudo ./bin/faramir init --operator "$USER" --seal-age-key
```

`init` refuses rather than skips when the host has no usable TPM. A security
measure that quietly does not apply is the install that looks healthy and
protects less than it appears to.

The keeper's unit then carries `LoadCredentialEncrypted=` in place of
`LoadCredential=`, and never both: two entries claiming one credential name is a
unit systemd refuses to start. Reverting is a re-run without the flag, rather
than a drop-in somebody has to remember to delete.

`--name=age_key` matters and is what `init` seals under: a credential is bound to
the name it was encrypted under, and the unit asks for `age_key`. The plaintext
then exists only in the unit's credential directory, on tmpfs, readable by that
unit alone.

**The plaintext key is still on disk until you remove it**, and until then this
has bought nothing. `init` says so on every run that seals without removing it.
Pass `--remove-plaintext-age-key` only once you have the key material somewhere
you can re-seal from; it runs last, after the install gate has proved the keeper
is serving values from the sealed credential.

That last part is not optional. Sealing binds to PCR 7 by default, which tracks
Secure Boot policy: change the Secure Boot state or its keys and the blob stops
decrypting, and the only way back is sealing the original key again. Clearing
the TPM does the same. `--tpm2-pcrs=""` binds to no PCRs, trading that
fragility for a blob any boot of this machine can decrypt.

Per-user encryption (ecryptfs, `ecryptfs-setup-private` and friends) does not
work for this. Those unlock at login through PAM, the keeper starts at boot as a
`nologin` account with no session to unlock anything, and `LoadCredential=` is
fatal when its source is missing. Putting the key in the operator's own
encrypted home is worse still: the agent runs as the operator, so the boundary
that made the key unreadable stops existing.

## Development

```bash
make build           # static binaries into bin/
make test            # whole suite; needs no sops installed
make test-unit       # everything except end-to-end
make test-e2e        # end-to-end against a real broker in a temp dir
make lint            # golangci-lint
make fmt             # apply the import and format rules CI checks
make coverage        # race-enabled suite plus per-function report
make sizes           # per-binary size, package count, sops linkage
```

```text
cmd/faramir            CLI, plus keygen
cmd/faramir-broker     policy, redaction, audit log, SSH keys
cmd/faramir-keeper     holds the age key, execs sops, serves values only
cmd/faramir-exec       forks brokered commands, holds nothing
cmd/faramir-mcp        MCP stdio server
cmd/faramir-guard      PreToolUse hook
internal/              implementation; each package doc explains its decisions
internal/e2e           end-to-end suite: a real keeper, executor and broker
internal/install       what `faramir init`, `doctor` and `uninstall` do
systemd/               socket and hardened service unit templates, one pair per daemon
etc/                   the starter config template; per-consumer settings go in config.d
agent/                 deny patterns, settings, the snippet to add to a project
tests/verify.sh        the verification matrix
docs/                  redaction, wire protocol, Ansible, scope
```

- Everything under `systemd/`, `etc/`, `agent/` and `docs/` is embedded into the binaries by `assets.go`, so `init` installs a host without a checkout. The `.tmpl` files are the shipped files themselves rather than a separate set: what you read to understand the install is what the install writes, and `internal/install` has a test asserting every account-bearing directive carries the layout's value rather than a default.
- Tests live where the logic does. Most of what the broker does is decide, and none of that needs a socket or a child process, so `internal/server` substitutes the executor. `internal/executor` uses a real child, because the PTY and the streaming redactor only mean anything against real bytes.
- The suite needs no `sops` on `PATH`: `internal/sopstest` builds a stand-in from the sops libraries. It is imported only from `_test.go`, which keeps sops out of the shipped binaries.
- sops is executed, not linked: linking pulls its whole key-source tree into the process holding the master key.
- Regexes are RE2. No lookahead, no backreferences. `cmd/faramir-guard` asserts every shipped pattern compiles and that the file matches the built-in fallback.
- Every binary answers `--version` from `internal/version`.

Doc | Covers
--- | ---
[docs/redaction.md](docs/redaction.md) | What the redactor covers, and what it cannot
[docs/protocol.md](docs/protocol.md) | Request and response shapes on the socket
[docs/ansible-sops.md](docs/ansible-sops.md) | Pointing `group_vars` at the environment
[docs/scope.md](docs/scope.md) | What this defends, and what it stops trying to
