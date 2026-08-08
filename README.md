# faramir

faramir is a secret broker for local AI coding agents: it runs the commands that need credentials as a uid that holds nothing, and redacts the output of everything else the agent runs, so no plaintext credential enters the agent's context or reaches a model provider

```console
$ faramir run --env ROUTER_PW=secret://home/router/admin -- printenv ROUTER_PW
«SECRET:home/router/admin»
[faramir] redacted «SECRET:home/router/admin»×1; log_id=2026-08-05T14:22:01Z-a91f
```

The command really ran, the credential really reached it, and the agent never saw the value.

> [!WARNING]
> **Enrolling a project auto-approves every Bash command in it.**
>
> To redact output, the `PreToolUse` hook rewrites each command into a wrapper. A rewritten command matches no Bash permission rule, so the hook approves everything its [deny list](agent/hooks/deny-patterns.txt) did not refuse: in an enrolled project you are never prompted before a shell command runs. That is forced by the mechanism, not a setting.
>
> Read this as **Bash is auto-approved here**. Prompts on `Write` and `Edit` do not make up for it, because Bash can do what they do (`sed -i`, `cat >`, `rm`) without asking. They still catch the ordinary case, where an agent doing normal work reaches for the right tool; they stop nothing that means to go around them.
>
> What you keep: every other tool's permissions are untouched, and faramir *adds* `Read` deny rules for key material. What you lose is granular Bash control, in that project only. The hook is registered per project, so a repo you have not enrolled keeps its prompts and gets no redaction. Enrol the ones that handle managed credentials; leave the rest alone.

## What it is for

A coding agent running on your own machine runs real commands, and some of them
need a credential: a deploy script, a `docker login`, a database dump, a call
against a staging API, an `ansible-playbook` run. Everything those commands
print goes back into the agent's context, and from there to a model provider.

That leaves two bad options. Hand the agent the credentials, and every value it
touches is in the transcript. Withhold them, and every task that needs one comes
back to you.

The broker is the third. The agent names a credential by reference and never
holds it:

```console
$ faramir run --env REGISTRY_TOKEN=secret://ci/registry -- ./deploy.sh staging
Authenticating to registry.example.com
Pushed app:4f21c9
[faramir] redacted «SECRET:ci/registry»×2; log_id=2026-08-08T04:58:17Z-a3f4
```

The command ran with the real token, the agent can read the output and fix the
next failure, and no plaintext entered its context. It asks through an MCP tool
rather than the CLI, which is the same broker and the same audit record:

```python
faramir_run(cmd=["./deploy.sh", "staging"],
            env_refs={"REGISTRY_TOKEN": "secret://ci/registry"})
```

In a project you enrol, commands the agent runs on its own are covered too. A
`PreToolUse` hook routes their output through the same redactor, so a credential
printed by something nobody thought to broker still comes back as a token. That
coverage is what costs the Bash prompts, which is why it is enabled per project
rather than everywhere.

## Features

- [Uid separation, not a container](#architecture) - three service accounts, so what a brokered command cannot reach is a kernel boundary rather than a policy
- [The master key lives where nothing executes](#architecture) - no brokered command can read the age key, ask for it, or receive it in its environment
- [Output redaction over the whole value set](#how-redaction-works) - every managed secret, not only the injected ones, so a host that prints its own configuration is covered
- [Commands run as a uid that holds nothing](#architecture) - no key, no audit log, no SSH key, and `cmd` is an array rather than a string handed to a shell
- [Secrets in the environment only](#rules-that-are-not-negotiable) - never substituted into `argv`, which is world-readable in `ps`
- [An operator-only audit log](#operational-notes) - what ran, by whom, against which refs, and what came back, holding no value at all
- [MCP tools and a CLI](#usage) - `faramir_run` for the agent, `faramir run` for you
- [A verification matrix](#verification) - including a demonstration of the boundary it does not defend

## What it protects against

Read this before anything else. Several design choices only make sense against this model, and the project is easy to over-trust.

> [!IMPORTANT]
> The broker keeps plaintext out of model context. It does not contain a compromised agent.

### Prevented

Failure | How it is prevented
--- | ---
Accidental disclosure: `ansible-vault view`, `cat group_vars/all/vault.yml`, `printenv`, `ansible-playbook -vvv`, a `debug: var=` task | No account on the host can read the key material, the operator's included; anything the agent runs has its output redacted before it sees it
Passive discovery: reading the vault password file, an age key, an SSH private key, or another process's `/proc/<pid>/environ` | Unix uid separation plus `ProtectProc=invisible`
Casual prompt injection: instructions telling the agent to print or exfiltrate credentials | The agent process never holds them; there is nothing to print
**Loss of the master key.** The age key decrypts every managed file, retroactively, including everything already in git history. | It lives in a third uid that executes nothing. No brokered command can read the file, connect to the keeper's socket, or receive the key in its environment. See [Architecture](#architecture).

### Not prevented

Failure | Why it is not prevented
--- | ---
**Adversarial exfiltration.** An agent that deliberately transforms a value (`\| rev`, `\| cut -c1-4` across several calls, `\| sha256sum`) defeats output redaction. | Accepted. The matcher cannot be completed: the child chooses the encoding of its own output. [Verification](#verification) demonstrates it rather than asserting it, because "a value we never claimed to catch was not caught" is not a property worth a test.
**Network egress control.** No iptables rules, no network namespaces, no proxy allowlist. | The operator decided unrestricted networking is required. Consequence: a secret that does escape redaction is unrecoverable.
**Filesystem blast radius.** The agent has legitimate write access to the repo; destructive edits are not addressed here. | Separate problem.

**Acceptance invariant:** if every instruction the agent is given were deleted, no secret could reach the model provider. Every enforcement point is a uid boundary, a file mode, or a hook, never the agent choosing to behave.

**There is no command allowlist**, and the invariant above does not need one. Any rule permitting an interpreter (`bash`, `python`, `env`) reaches past every constraint it expresses, so an allowlist buys a rule to write per program and a denial per mistake, and no security property. See [Architecture](#architecture).

## How it works

The agent asks for a command to be run and names each credential by reference. The broker resolves the references, runs the command as a uid that holds nothing, redacts the output, and hands back the result. No plaintext ever exists in a process the agent's uid can read.

Every boundary is a uid or a file mode, so it holds whether or not the agent cooperates.

uid | Holds | Runs
--- | --- | ---
you | nothing secret | the coding agent itself
`faramir-keeper` | the age master key | nothing but sops
`faramir-broker` | plaintext values in memory, SSH keys | policy, redaction, the audit log
`faramir-exec` | nothing | the brokered commands themselves

The split between the keeper and the broker is the one that matters. The age key decrypts every managed file, retroactively, including everything already in git history, so it lives in a uid that executes nothing: the broker can ask for a value and can never read the key, and a brokered command cannot reach the keeper's socket at all.

### One call, end to end

```console
$ faramir run --env ROUTER_PW=secret://home/router/admin -- ansible-playbook site.yml
```

1. The request reaches `/run/faramir/broker.sock` as JSON carrying the reference `secret://home/router/admin`, never a value. `cmd` is an array, never a string handed to a shell, and there is no allowlist: the broker runs what it is asked, as a uid that holds nothing.
2. The broker resolves the reference by asking the keeper over a socket only the broker can open. The keeper execs sops and returns values; the key stays in that uid.
3. The broker asks the executor, over a third socket, to fork the command as `faramir-exec` on a PTY the broker created, with the value in the environment. Never in `argv`, which is world-readable in `ps`.
4. Output comes back through the broker's end of the PTY, and every managed secret is replaced with `«SECRET:ref»` before the agent sees a byte. The redactor is built from the whole value set rather than only what was injected, so a host printing its own configuration is covered as well.
5. The audit log records what ran, against which refs, and what came back. It holds no value, and only the operator can read it.

### SSH keys

Keys that reach managed hosts cannot simply live in the executor's home, or every brokered command could copy a key that opens every managed host. The broker keeps the key files under its own uid, loads them into an `ssh-agent` it owns, and passes the child only `SSH_AUTH_SOCK`: the child can authenticate for as long as the broker runs, and can never read a key. That takes a relay, because `ssh-agent` refuses any peer uid but its own. [Architecture](#architecture) has the shape of it and what the relay will and will not forward.

## Installation

Requires systemd and [sops](https://github.com/getsops/sops) on the host, and Go to
build. Nothing else at runtime: the binaries are static, so the host needs no
interpreter and no libc of a particular vintage.

```bash
make build
sudo make install
```

Two commands because `install` deliberately does not depend on `build`: the
compiler should not run as root, and the installer is meant to work on a host
with no Go at all. It runs the four phases in order. They are numbered in
the order they run and each is idempotent, so a single phase can be re-run on
its own after an edit:

Phase | Does
--- | ---
`10-accounts.sh` | accounts, group, shared tree, `umask 002`
`20-sops-init.sh` | age keypair -> `/etc/faramir/age.key`, `.sops.yaml`
`30-install-broker.sh` | binaries, config, systemd units
`40-agent-config.sh` | `Read` deny rules in your account; hook, MCP registration and agent instructions in the project

Set `CONFIG` to install the configuration for a real workload instead of the
starter:

```bash
make build
sudo CONFIG=etc/examples/ansible-fleet.toml make install
```

Configs are installed verbatim. Every path in one is absolute, and the managed
sops files live in `/etc/faramir/secrets` rather than in any working tree, so
there is nothing to substitute and no placeholder that can reach a running
config.

`WORKTREE` still names the tree phase 1 shares and phase 4 registers the MCP
server in, and defaults to `/srv/faramir/worktree`. It no longer appears in the
config: nothing the broker reads lives there.

`30-install-broker.sh` refuses to run without built binaries and needs no
toolchain on the target, so building on one machine and copying `bin/` to
another works: `sudo FARAMIR_BIN=/opt/faramir/bin make install`.

A `CONFIG` that does not parse is refused before anything is written to the
host.

`install/uninstall.sh` removes the broker and leaves the accounts, `/etc/faramir` and the audit log alone: deleting the age key would make every sops file in the repo unreadable, which is not a decision a teardown script should make for you.

### Migrating from ansible-vault

Migrate each vault file, point `group_vars` at the environment as described in
[docs/ansible-sops.md](docs/ansible-sops.md), and verify before deleting
anything. The encrypted file goes to `/etc/faramir/secrets`, outside any
checkout and somewhere Ansible does not auto-load:

```bash
install/migrate-vault.sh group_vars/all/vault.yml \
    /etc/faramir/secrets/ansible-ctrl.sops.yml
# after adding the file to [secrets] files.  A restart, not a reload:
# neither daemon re-reads config.toml.  Two commands rather than one,
# because systemctl does not order the units it is given and the keeper
# has to lead: it decrypts the list the broker is served.
sudo systemctl restart faramir-keeper
sudo systemctl restart faramir-broker
faramir run --env ROUTER_PW=secret://home/router/admin -- \
    ansible-playbook site.yml --check     # prove it works end to end
```

> [!WARNING]
> **Rotate everything that was ever committed.** `git rm` does not remove the vault blobs from history, and the old vault password still opens them. Rotate every credential, or rewrite history with `git filter-repo`, and rotate anyway if the repo was ever pushed anywhere. Without this you have added a second copy rather than migrated.

Delete the vault password file only after a real playbook run succeeds through the broker, then treat the password as burned.

## Onboarding a project

Nothing about a project moves into faramir. Its secrets move into the managed
store, and the project learns to read them from the environment by name. The
project keeps its own layout, its own runner and its own credentials-shaped
config file; what changes is where the values come from.

Five steps, in order. Steps 1 and 2 are what make redaction cover the project at
all; 3 through 5 are what let a command actually receive a value.

Step | Do | Why it is separate
--- | --- | ---
1 | Put the values in one sops file under `/etc/faramir/secrets`, named after what consumes them | Not in the checkout: a home is not mounted until its owner logs in, so a value set inside one is empty at boot
2 | Add that file to `[secrets] files`, then restart the keeper and the broker, in that order | This is what puts the values in the redaction set, whether or not anything ever injects them. A restart rather than a reload: both daemons read `config.toml` once at startup, so a newly listed file is invisible to a running one. The keeper leads because it decrypts the list the broker is served
3 | Point the project's own config at environment variables | The project never decrypts anything; it reads `$NAME` however it already reads environment
4 | Write the refs down beside the project, one `NAME=secret://ref` per line | So a run names refs rather than someone remembering them
5 | Copy [agent/claude/mcp.json](agent/claude/mcp.json) into the repo as `.mcp.json` | The agent gets `faramir_run` in that checkout

Step 2 is the one worth doing even if you stop there. A file listed in
`[secrets]` is redacted out of every command's output from that point on,
brokered or not, so a project whose credentials you have not finished moving is
still covered against printing them by accident.

Step 5 is two files, and they are one decision. `.mcp.json` gives the agent
`faramir_run`; `.claude/settings.json` registers the hook that redacts
everything else it runs. Both are per-project, and enrolling is what
auto-approves Bash in that repo, per the warning at the top. A project you have not enrolled
keeps its Bash prompts and gets no redaction, so enrol the ones that handle
managed credentials.

The `Read` deny rules are the exception: phase 4 puts those in your own account,
because refusing to open an age key or a `.sops.yml` costs nothing anywhere and
is worth having in every project.

Check the result the same way each time:

```bash
faramir list-secrets                    # the refs are there, values are not
faramir run --env TOKEN=secret://svc/token -- printenv TOKEN
# -> «SECRET:svc/token»
```

That single command proves both halves at once: the value reached the child's
environment, and it came back as a token rather than as itself. Anything else is
a fault worth stopping on.

### Worked example: an Ansible control repo

This is the shape [ansible-ctrl](https://github.com/andornaut/ansible-ctrl)
ended up in, and the reason `etc/examples/ansible-fleet.toml` exists.

```text
/etc/faramir/secrets/ansible-ctrl.sops.yml   the values, outside every checkout
group_vars/all/vars.yml                      committed: var -> lookup('env', 'NAME')
faramir.env                                  NAME=secret://ref, one per line
.mcp.json                                    registers faramir-mcp for this repo
```

The vault file was migrated with `install/migrate-vault.sh`, the broker was
installed with `CONFIG=etc/examples/ansible-fleet.toml`, and the fleet's SSH key
moved into `[ssh] keys` so a playbook can authenticate with a key no brokered
command can read.

Only the mapping file is encrypted-adjacent, and it holds no value:

```yaml
# group_vars/all/vars.yml -- committed, unencrypted, reviewable
router_password: "{{ lookup('env', 'ROUTER_PW') }}"
```

```bash
faramir run --env-file faramir.env -- ansible-playbook site.yml
```

Whether the refs file is committed is a judgement call. It discloses no value,
but it maps the project's variable names onto the store's layout, which is why
ansible-ctrl gitignores its own. [docs/ansible-sops.md](docs/ansible-sops.md)
has the full walk-through, including the two ways an encrypted file ends up
somewhere Ansible auto-loads it and configures hosts with ciphertext.

### Other shapes

Ansible is the worked example, not the boundary. Anything that takes its
credentials from the environment onboards the same way; the differences are all
in step 3.

Shape | Step 3 looks like
--- | ---
A deploy or release script | It already reads `$REGISTRY_TOKEN`. Nothing to change: `faramir run --env REGISTRY_TOKEN=secret://ci/registry -- ./deploy.sh staging`
A cloud or infra CLI (`aws`, `gcloud`, `terraform`, `flyctl`) | Each has documented environment variables. Name those, and drop the credentials file the tool would otherwise read
A database task (`psql`, `pg_dump`, `mysql`) | `PGPASSWORD`, `MYSQL_PWD`. The connection string goes in `argv`, the password never does
A container registry push | `docker login --password-stdin` reads a value the broker put in the environment: `bash -lc 'printf %s "$TOKEN" \| docker login -u me --password-stdin'`
An HTTP call against a staging API | `curl -H "Authorization: Bearer $TOKEN" …` inside a `bash -lc`, so the shell expands it and `argv` never carries it
A tool that insists on a credentials *file* | Have the brokered command write it, use it, and remove it. Injection is environment-only by design, so the file exists only inside that one command's lifetime, as a uid that holds nothing else
Something reached over SSH | Nothing in step 3 at all. List the key in `[ssh] keys` and the child gets `SSH_AUTH_SOCK`; it can authenticate and cannot copy the key
A command that needs no secret, only redacting | Skip steps 3 through 5. `faramir redact -- ./script.sh`, or `… \| faramir redact` as a plain filter

Two rules bound all of them. A pipeline is requested explicitly as
`["bash", "-lc", "…"]`, because the broker never hands a string to a shell on
its own. And a bare command name is looked up on `[exec.base_env] PATH`, so a
venv, pipx or shim install is reached by putting its directory there rather than
by widening anything else.

What does *not* onboard: anything that wants to decrypt sops itself. It would
need the age key, and no process the broker starts ever receives it. Such a tool
gets named values in its environment instead, which is the same thing it would
have derived from the key, minus the ability to read every other managed file.

## Usage

`faramir --help` lists the commands and `faramir <command> --help` gives each
one's options. `run` executes a command with secrets injected, `redact` scrubs
secrets out of text or out of a command's output, `list-secrets` prints ref
names, `status` reports what the broker loaded, and `keygen` mints an age
keypair for the keeper. Every command that talks to the broker takes `--socket`
and `--json`.

```bash
faramir status                       # config path, loaded files, ref count
faramir list-secrets                 # ref names, never values

# Inject one secret, then many
faramir run --env ROUTER_PW=secret://home/router/admin -- printenv ROUTER_PW
faramir run --env-file deploy.env -- ansible-playbook site.yml

# Quiet the redaction summary, run somewhere else, cap the runtime
faramir run --quiet -C /srv/faramir/worktree -t 120 -- ansible-playbook site.yml

# Redact without brokering: as a filter, or around a command you run yourself
kubectl get secret -o yaml | faramir redact
faramir redact -- ./deploy.sh
```

`run` also takes `--quiet` (suppress the redaction summary, which goes to
stderr), `--cwd`/`-C`, `--timeout`/`-t`, and `--env` once per secret. The
child's exit code is `faramir`'s own, so a script can branch on it; a broker
that is not running exits 69 (`EX_UNAVAILABLE`) instead.

A command that needs many credentials takes `--env-file` instead of repeating
`--env`, which is how one gets quietly dropped from one call site:

```bash
faramir run --env-file deploy.env -- ansible-playbook site.yml
```

```text
# deploy.env: NAME=secret://ref, one per line, # for a comment
ROUTER_PW=secret://home/router/admin
API_TOKEN=secret://home/api/token
```

The file holds refs and never values, so it belongs beside the command it
serves. Whether to commit it is a judgement call: it discloses no value, but the
set of refs maps your variable names onto the store's layout. An explicit
`--env` overrides an entry of the same name, so a wrapper can substitute one
without rewriting the file.

Both `--env` and `--env-file` refuse a literal value and a name that cannot be
an environment variable (`export NAME=…` is the usual way in). One file also
refuses a name given twice with two different refs, an ambiguity that file
cannot resolve on its own; across sources the layering above decides instead, so
a later `--env-file` wins over an earlier one and an explicit `--env` wins over
both. A bad line in a file is reported with the file and the line; a bad `--env`
has no location to report. The offending value never appears either way, since
echoing a pasted credential into the terminal is the disclosure the mechanism
exists to prevent.

A bare command name is looked up on `[exec.base_env] PATH`, which is the PATH
the child itself gets, so a tool in a venv or a pipx install is reached by
putting its directory there. Anything else takes an absolute path.

The agent reaches the same broker through MCP tools:

Tool | Description
--- | ---
`faramir_run(cmd=[…], env_refs={NAME: "secret://ref"}, cwd=…, timeout_sec=…)` | Run a command with secrets bound to environment variables
`faramir_list_secrets()` | Ref names only, never values
`faramir_status()` | Config path, the loaded secrets files, and the ref count

The wire protocol behind both is documented in [docs/protocol.md](docs/protocol.md).

### Configuration

[etc/config.toml](etc/config.toml) is the starter configuration. There is no
command allowlist to configure; what still bounds a brokered command is:

Setting | What it does
--- | ---
`[exec.base_env] PATH` | Where a bare command name is looked up, and the only `PATH` the child gets. A venv, pipx or shim directory belongs here.
`[exec] max_timeout_sec` | Ceiling on how long a command may run
`[exec] max_output_bytes` | Ceiling on what comes back; the audit log keeps more of it, up to `[audit] max_record_bytes`
`[secrets] min_length` and friends | A value too short or too low-entropy to redact is refused at load, so it cannot be injected at all
the executor's uid | The real one. See [Architecture](#architecture).

`allowed_groups` admits every member of a named group, supplementary
membership included, because that is how `dev` is granted in the first
place (`usermod -aG`). That is intended on `[server]`, whose socket is
`0660 root:dev` anyway. Leave it empty on `[keeper]` and `[executor]`:
their only legitimate client is the broker, they take it by name in
`allowed_users`, and a peer that reaches the executor socket runs commands
that are neither redacted nor audited. Both daemons log a warning at startup
when it is not empty.

Complete configs for real workloads live in [etc/examples/](etc/examples/), and
each is a drop-in replacement rather than a fragment to merge:

Example | Workload
--- | ---
[ansible-fleet.toml](etc/examples/ansible-fleet.toml) | Running Ansible against managed hosts over SSH, with the broker holding the key

No key names where a command runs. A brokered command runs in the directory its
caller was in, which `faramir run` and the MCP server both send, and a request
that names none is refused. A configured fallback could only relocate such a
request into one checkout, silently, in exactly the case where it matters.

A mistyped key or a mistyped `[section]` is a hard error naming the
alternatives, never a silently ignored line: a config that reads as though it
had taken effect is the failure mode worth spending an error message on.
`[secret]` for `[secrets]` would otherwise leave a broker that manages no files
and therefore redacts nothing.

Values are range-checked for the same reason, because the out-of-range cases do
not fail loudly on their own: `max_concurrency = -1` panics the broker on
startup, `max_concurrency = 0` refuses every request as busy, and
`default_timeout_sec = 0` kills every command the instant it starts, with no
output. Zero stays legal where it means something: `kill_grace_sec = 0` is
"SIGKILL at once", and `refresh_interval_sec = 0` is "check on every request".

### The install gate

`faramir-broker --check` prints what the broker loaded and exits non-zero on
anything that would leave it running and protecting less than it appears to.
Every one of these otherwise produces a healthy-looking install:

Fails on | Because
--- | ---
An unknown key or `[section]` | A config that reads as though it took effect; the error names the alternatives
A value out of range | See above
A ref too short or too low-entropy to redact | It is refused at load, so it can be injected by nothing and covered by nothing
A `[secrets]` file that exists and did not load | Unreadable, or the keeper did not answer. Those values are absent from the redactor, so whatever prints one prints plaintext
A `[ssh] key` that is missing, passphrase-protected, or the `.pub` | `ssh-add` will refuse it, leaving an agent holding nothing and every host unreachable

A `[secrets]` file that does not *exist* passes: that is the normal state of an
install whose secrets have not been migrated yet, and the installer runs the
gate before they have been. An empty `[ssh] keys` passes too, being a
deliberate configuration.

Run the gate as the broker's own account, which is how
`install/30-install-broker.sh` runs it:

```bash
sudo -u faramir-broker faramir-broker -c /etc/faramir/config.toml --check
```

It opens the SSH keys and the secrets files as whatever uid runs it. Run as
root it reads what the broker cannot, and a key left `root:root 0600` then
passes a gate the broker itself fails on, which is the authentication failure
against every host that the two rows above exist to catch.

### Rules that are not negotiable

- **Nothing the broker starts receives the age key.** There is no flag that grants it and the broker does not hold it to grant. Programs that want to decrypt sops themselves cannot; they get named values instead. This bounds brokered commands and the agent, not root: root can read `/etc/faramir/age.key` like any other file, so an unattended root job may legitimately point `SOPS_AGE_KEY_FILE` at it. That is a path rather than a value, so the material is read only by sops itself.
- **Secrets are injected as environment variables only.** There is no way to ask for a value to be substituted into `argv`: argv is visible in `ps`, in `/proc/<pid>/cmdline`, and in the child's own error messages.
- **`cmd` is an array.** The broker never hands a string to `sh -c`. A pipeline is requested explicitly as `["bash", "-lc", "…"]`.
- **The broker runs the working tree as it is on disk.** There is no promotion step: edit, then run. See [Architecture](#architecture) for why a commit-then-sync gate into a second checkout is not one worth having.
- **`redactions` reports counts, not values**, so the caller can confirm a secret reached the right place without seeing it. That is why the operator does not need plaintext either: `log_id` points into the audit log, which records the same tokens.

## Architecture

These decisions were made deliberately; the rationale is recorded so they are not re-litigated by accident.

Decision | Choice | Rationale
--- | --- | ---
Filesystem isolation | None beyond file modes and `ProtectSystem=strict`. | Putting a tmpfs over `/home` and binding the working tree back in protects nothing against this threat model: a home the executor's uid may not read is one the mode already refuses, and a home it may read is one the *agent* uid can read directly, without the broker. It costs the tree's path repeated in a drop-in per unit, each of which has to agree with the config, and an install that comes up clean while every command dies with `cwd does not exist`. The path appears in one place, the config, and the executor names only `/home` and `/srv/faramir` as writable, where modes do the rest.
Isolation | Unix uid separation + systemd hardening. No Docker, Podman or bubblewrap. | Network isolation was the main thing containers made easy, and it is a non-goal. Everything else comes straight from the kernel and systemd. A sandbox confines what a child *sees*; it cannot make a directory its owner can rewrite from outside hold still, and it is not a substitute for a uid that holds nothing.
Where commands run | The agent's own working tree, directly. | A second checkout promoted into by a commit-then-sync gate does not stop the agent getting `debug: var=<secret>` executed: it can commit that and sync it, and verification test 7 shows exactly that content running. What such a gate buys is an immutable snapshot (against an agent editing a file mid-run) and a commit sha in the audit log. Both are properties against a *deliberate* agent, which is out of scope, and the cost is a commit per iteration plus a bind-mount/config pair kept in sync by hand.
Who executes | The broker, as its own uid. Never the caller. | If the client execs, plaintext lives in a process the agent already owns, which is the one place it must not be.
Who holds the key | A separate `faramir-keeper` uid that executes nothing. | A systemd credential is readable by the unit's uid, and every brokered command runs as a broker-adjacent uid. A key the broker can load is a key any command can read.
Who forks the child | A third `faramir-exec` uid, given the PTY slave over `SCM_RIGHTS`. | Anything the forking uid can reach, the child can reach. Forking from the broker would hand every command the audit log and the SSH keys that open every managed host.
Command allowlist | None. | It carries no security property. Bounding `argv[0]` by directory, and a rule's arguments by pattern, is reachable in a single step through any rule permitting `bash`, which a usable policy has to permit for pipelines. What it reliably does instead is refuse every venv, pipx, shim and working-tree script, at a rule per program.
How a program gets its values | Through `env_refs`, read from the environment however that program reads it. | The alternative is letting the program decrypt sops itself, which means handing it the master key. A program that can run arbitrary code, which most build and deploy tools can, then holds the key to everything. No consumer is the shape of the broker.
Secret store | sops + age, replacing ansible-vault. | Encrypted YAML in the repo, per-key diffs, no network round trip.
Redaction | Custom. | `op run` and similar mask only the values *they* injected. A managed host can print a credential the broker never injected, so the redactor is built from the whole value set regardless of injection path.
Agent interface | Unix socket, exposed as an MCP tool (`faramir_run`) plus a thin CLI. | A distinct tool is far more discoverable to a model than a convention documented in prose.
Enforcement | PreToolUse hook + filesystem permissions. | Instructions to the agent are ergonomics, not a security boundary.

### Layout

```text
uid <operator>                you; runs the coding agent, member of group dev
uid faramir-keeper            holds the age key; execs nothing but sops
uid faramir-broker            policy, redaction, audit log, SSH keys
uid faramir-exec              forks brokered commands; holds nothing
group dev                     shared access to the working tree

/run/faramir/broker.sock      socket-activated, 0660 root:dev
/run/faramir/keeper.sock      socket-activated, 0660 root:faramir-broker
/run/faramir/exec.sock        socket-activated, 0660 root:faramir-broker
/run/faramir/ssh-agent.sock   optional, 0660 faramir-broker:faramir-exec
/run/faramir/ssh-agent.sock.private
                              what ssh-agent itself binds, 0600 faramir-broker
/etc/faramir/age.key          0400 faramir-keeper:faramir-keeper
/etc/faramir/config.toml      0644 root:root, read by all three
/srv/faramir/worktree         the working tree, 2770 <operator>:dev:
                              outside every home, because the keeper and the
                              executor read it at boot
/var/log/faramir/audit.log    audit log, 0600 faramir-broker:faramir-broker
```

All three service accounts are in `dev`. The keeper decrypts the sops files in `/etc/faramir/secrets` and the broker stats them there, both `2770 root:dev`; the executor needs the group for the tree a brokered command runs in. That is access to files the agent already owns, and to a directory holding ciphertext the agent cannot decrypt; it is not a route to anything the agent could not reach itself.

Group membership is not enough on its own when the tree sits inside your home, which is 0700, because a uid that cannot traverse a directory cannot open anything beneath it. Phase 1 therefore walks every component from the home down to the tree and grants the keeper, the broker and the executor execute-only access with an ACL, and no read: they pass through without being able to list what they pass. Not `chmod o+x`, which would grant the same thing to every account on the machine. Without it the keeper's `open()` fails with `EACCES` rather than `ENOENT`, which reads as a file that exists and would not decrypt.

On an ecryptfs home that ACL is write-once: the first `setfacl` against an inode applies and every later one is silently ignored, exiting 0 while changing nothing. Phase 1 grants all three uids in one call and reads the result back with `getfacl` for that reason. A tree outside every home (`/srv/faramir/worktree`, the installer's default) needs none of this.

The SSH agent is two sockets for the same reason. OpenSSH's `ssh-agent` calls `getpeereid()` on every connection and closes any whose peer euid is neither root nor its own, so handing its socket to another uid fails at the protocol layer however permissive the mode is: the client connects, the request is dropped, and `ssh-add` reports `communication with agent failed`. So `ssh-agent` binds a private socket only the broker's uid uses, and the broker serves the public one, relaying between the two. That has two consequences:

- **Every upstream connection is the broker's own**, so `ssh-agent`'s uid check decides nothing. The relay makes the `SO_PEERCRED` check itself, and the public socket's mode is a second boundary rather than the only one.
- **The relay reads the protocol rather than piping it.** The agent protocol has no read-only mode, so a connection that can sign can also send `REMOVE_ALL_IDENTITIES` or `ADD_IDENTITY`. Only `REQUEST_IDENTITIES` and `SIGN_REQUEST` are forwarded; the connection ends on anything else.

A brokered command can therefore authenticate, and cannot extract a key, change what the agent holds, or ptrace it.

What keeps a brokered command out of everything else is the ordinary file mode, not a mount namespace. `ProtectSystem=strict` makes the whole hierarchy read-only, and the executor names `/home` and `/srv/faramir` as writable, both shipped locations for the tree. The only thing its uid can actually write there is the group-writable tree itself: your home is 0700, and lifting the read-only mount is not permission.

Three uids, because anything a uid can reach, a command running as that uid can reach. What a brokered command cannot do, and why:

Cannot | Why not
--- | ---
read `/etc/faramir/age.key` | 0400 `faramir-keeper`; `dev` does not appear in that mode
open the keeper socket | 0660 `root:faramir-broker`, and it is not in that group
ask the keeper for the key | there is no such request
read or truncate the audit log | 0600 `faramir-broker`
read the SSH keys for managed hosts | 0700 `faramir-broker`; it gets an agent socket instead
receive `SOPS_AGE_KEY` | nothing puts it there

It **can** write the working tree, which is the point: Ansible drops `.retry` files and fact caches, and a playbook that generates config has to put it somewhere. It can also reach `/run/faramir/broker.sock`, since that is `0660 root:dev`: a brokered command can call the broker back. That buys it nothing. The response is redacted and audited exactly like the agent's own, and every ref it could name is already listed by `faramir_list_secrets`.

The PTY does not move with the fork. The broker creates the pair, sends the slave over `SCM_RIGHTS`, and keeps the master, so redaction, truncation and the audit log stay in the broker and output takes no extra hop.

## Where the agent runs

The coding agent runs as **you**. There is no separate account for it, because the work it is asked to do is yours: your checkouts, your `gh` credential, your commits. A separate uid could reach none of that, and every way of granting it access ends up handing over your files by another name, or copying your credentials into a second account so that one credential becomes two.

What that gives up is a boundary around the agent *process*. What it does not give up is any boundary around the secrets, because those were never the same thing:

Held by | What | Can you read it?
--- | --- | ---
`faramir-keeper` | the age key, `0400` | no
`faramir-broker` | decrypted values, the broker's SSH keys, the audit log | no, except through the broker
`faramir-exec` | nothing; it is where brokered commands run | it cannot read your home

Brokered execution covers the commands the broker runs. It does not cover what an agent reads or executes on its own, and a deny list only covers what somebody thought to name. So the `PreToolUse` hook is registered in each enrolled project and does two things. A command matching the deny list is refused. **Every other command is rewritten** so that its output is redacted: the command itself runs unchanged in your shell, its output goes to a `0600` file on tmpfs, and that file is read back through `faramir redact` and removed.

Same command, same exit status, both streams, and `cd`, `export` and shell functions still persist to the next command, because the wrapper is sourced rather than run in a child. A value the broker knows about comes back as `«SECRET:ref»`. `faramir redact` also works as a plain filter (`… | faramir redact`), and it holds no values itself. [docs/scope.md](docs/scope.md) has the exact form and the wrappers it rules out.

If the broker is unreachable the wrapper warns and passes output through unredacted, rather than breaking every command. A wrapper that fails closed is a wrapper that gets removed.

**Two consequences worth knowing before enrolling a project.** For `Bash`, faramir's deny list replaces the permission system, not merely the prompt: the hook returns `permissionDecision: "allow"`, which skips permission evaluation entirely, so your own `permissions.deny` entries for `Bash` stop being consulted and faramir's list is the only one that applies in that project. Port any `Bash` deny rules you rely on into `agent/hooks/deny-patterns.txt`, remembering that the shipped list is about credential disclosure and names nothing destructive. This is forced rather than chosen: a rewritten command cannot be matched by any rule the permission matcher accepts, so the alternatives are approving it here or prompting on every command forever. `FARAMIR_WRAP_DECISION=ask` picks the second, and prompts on `ls` too, because each rewritten command is a distinct string that no rule can pre-approve.

And an unattended run with `--dangerously-skip-permissions` can rewrite any repository you can; hooks still fire in that mode, so redaction holds, but bounding what it may *change* is a matter of `gh` token scope and branch protection, not of this project.

**Wherever you run a brokered command from has to be reachable by both `faramir-exec` and `faramir-broker`.** The executor forks the command there; the broker stats the directory before accepting the request at all, so a grant to one of them still refuses every command. Outside the homes that is free. Inside your own checkout it takes traversal, which phase 1 grants with an ACL naming those two uids rather than `chmod o+x`, so `other` stays at nothing. The keeper needs none of it: its files are under `/etc` and its unit sets `ProtectHome=true`. See [docs/scope.md](docs/scope.md) for what an encrypted home costs here.

## How redaction works

Full detail in [docs/redaction.md](docs/redaction.md). In short:

1. **The value set is every managed secret**, not just the injected ones, fetched from the keeper and refreshed when a managed file's mtime changes. A managed host can print a credential the broker never injected, which is the case off-the-shelf injectors cannot cover.
1. **Children run on a PTY**, not a pipe: programs behave normally, and writes straight to `/dev/tty` (which is how `ssh` and `sudo` prompt) are captured. Consequence: stdout and stderr arrive merged.
1. **ANSI escapes are stripped before matching**, so a colour code spliced into the middle of a value cannot defeat it.
1. **An expanded value set is matched**: raw, base64 (padded/unpadded, wrapped/unwrapped), URL-encoded, JSON-escaped, shell single- and double-quoted.
1. **Streaming uses an overlap buffer**, so a value split across two reads is still caught.
1. **Short or low-entropy values are refused at load**, because a short password redacted would blank out unrelated output at random. The gate is `[secrets]` minimum length, distinct characters and entropy. The broker will not hold or inject a value that fails it, and names it in the log and in `faramir-broker --check`; the agent is told neither, since a value that is never tokenized is one worth targeting. Lengthen them.
1. **Tokens are stable**: the same secret always renders as `«SECRET:ref»`, so the model can reason about it across turns.

The age key is *not* in the value set, and does not need to be: no child can obtain it, so the property holds by construction rather than by the matcher catching it on the way out. That is the stronger arrangement, because redaction is best-effort and a uid boundary is not.

## Verification

```bash
make test          # unit + end-to-end, no privileges required
sudo make verify   # the matrix below, against the live deployment
```

[tests/verify.sh](tests/verify.sh) is the list; it prints a numbered result per
check, so read it there rather than from a copy here. What it establishes,
running each check as the uid that matters:

- **The age key is unreadable** by anyone but the keeper, the operator and the
  broker included, and no brokered command can obtain it through its
  environment, a systemd credential, or the keeper's socket.
- **The audit log and the broker's SSH keys are unreadable** by the executor, and
  a brokered command can authenticate through the SSH agent without being able
  to read a key or change what the agent holds.
- **Redaction covers the value set**, including through `base64` wrapped and
  not, a `-vvv` playbook run, a `debug: var=` task, and a write straight to
  `/dev/tty`.
- **The audit log holds tokens, never values.**
- **Command resolution** refuses a program that is not on `[exec.base_env]
  PATH` and names the setting, while a script in the working tree runs.
- **The hook is registered and answers**, and `faramir redact` passes ordinary
  text through unchanged while keeping the child's exit status.

Two checks are demonstrations rather than assertions: piping a secret through
`rev`, or through `cut`, reaches the caller transformed. That is the boundary
in [What it protects against](#what-it-protects-against), and `verify.sh`
prints what comes back because operators do not believe it until they watch it
happen. Nothing pins it: a test that fails when redaction gets *better* is a
test that has to be deleted to make progress. What is asserted instead is the
coverage that is claimed, in `internal/redact`.

The permission checks only mean anything against a real deployment. `make test`
runs everything else in a temp directory, with the keeper, the executor and the
broker as separate processes under a single uid: that exercises the protocol,
the PTY hand-off and the redactor, not the uid boundary itself. Properties
needing no deployment are asserted in the Go suite alone, so they run on every
build: the keeper refusing any op but `get_values`, sops failing to decrypt as
a brokered command, a child's environment carrying no key material under any
name and being wiped afterwards, the process group dying when the broker hangs
up, and the concurrency, timeout and output ceilings.

## Operational notes

- **Editing a managed sops file needs nothing.** The broker stats the files it was configured with and picks up an edit within `refresh_interval_sec`, retrying there when the previous attempt could not reach the keeper. It asks the keeper to decrypt, so both services have to be running. One refresh-driven reload runs at a time, which is the only thing bounding `refresh_interval_sec = 0` ("check on every request"). There is no `systemctl reload`: nothing a signal could do here, since the next note is the case that needs anything at all.
- **Changing `config.toml` needs both daemons restarted, the keeper first.** Neither re-reads it while running, so a file added to `[secrets] files` stays invisible until they are restarted, and its values are absent from the redactor until then. The keeper leads because it decrypts the list the broker is served; restarting the broker alone just fetches the old value set again.
- **The keeper and the executor must both be up.** `faramir-broker.service` requires both sockets. With no executor every command fails with `exec_failed`; with no keeper, see below.
- **The keeper must be up before the broker is useful.** With no keeper the broker keeps whatever value set it already had and logs the failure; on a cold start that set is empty, which means nothing gets redacted. It retries on the next request after `refresh_interval_sec`, so a keeper that comes back is picked up on its own. Check `systemctl status faramir-keeper` first when tokens stop appearing.
- **`[secrets] files` may live anywhere the keeper's uid can read.** `ProtectSystem=strict` leaves the whole hierarchy visible and read-only, so a path outside the working tree needs no unit change; its own mode is what decides.
- **The broker's home is `/var/lib/faramir-broker`, not `/home/faramir-broker`.** It needs a writable home, because it holds the SSH keys for managed hosts and `ansible-playbook` creates `~/.ansible/tmp` unconditionally, and `StateDirectory=` is what grants it. `install/10-accounts.sh` sets this up; an account created by hand with `useradd -M` will fail with `Unable to create local directories`.
- **No working tree is named anywhere the broker reads.** The managed sops files are in `/etc/faramir/secrets`, and a brokered command runs where its caller was, so nothing has to agree about a tree's path. The keeper is `ProtectHome=true` because it opens nothing under a home at all. The executor is granted `/home` and `/srv/faramir`, where modes decide what it can write; a caller working outside both needs a drop-in adding that path to its `ReadWritePaths=`.
- **`[secrets] files` belongs under `/etc`, not in a checkout.** A home is not mounted until its owner logs in, so a value set that depends on one is empty at boot and the broker redacts nothing until the first request after login. `/etc/faramir/secrets` is `2770 root:dev`: the operator edits with `sops` and the keeper decrypts, neither needing sudo.
- **Children do not inherit the broker's environment.** The child gets exactly `[exec.base_env]` plus its injected secrets. If a tool works for you but not through the broker, an environment variable is usually the reason. Add it to `base_env` rather than widening anything else.
- **Interactive prompts fail, they do not hang.** The child owns a PTY for output, but its stdin is `/dev/null`, so a command that waits for input gets EOF immediately. Pass the non-interactive flags.
- **Output is truncated** at `[exec] max_output_bytes`. The audit log keeps more of it, up to `[audit] max_record_bytes`, tokenized the same way.
- **The audit log grows without bound.** Add a logrotate rule; keep the mode at 0600 and the owner as `faramir-broker`.
- **The audit log holds no secret value.** Output is recorded after redaction, and `argv` is redacted on the way in, so a value a caller put there does not reach disk either. What you get is who ran what, when, against which refs, and what came back, with the tokens the agent saw. It stays 0600 and operator-only, because the command lines and the ref names are worth protecting on their own. See [docs/redaction.md](docs/redaction.md).
- **A key the broker cannot use fails `--check`.** Missing, passphrase-protected, or naming the `.pub` by mistake: `ssh-add` refuses all three, and the broker then starts with an agent holding nothing, so every socket is active and every playbook fails to authenticate everywhere. See [The install gate](#the-install-gate).
- **SSH keys belong in `[ssh] keys`, not in the executor's home.** Listed there, the broker loads them into an agent it owns and passes the child only `SSH_AUTH_SOCK`, so a brokered command can authenticate without being able to copy a key that opens every managed host. Left empty, the keys must sit in `~faramir-exec/.ssh`, where every brokered command can read them.
- **There is no blast-radius bound.** A brokered command runs anything the executor's uid can run. That uid holds no key, no audit log and no SSH key, which is the property the design rests on, but it does have write access to the working tree, so a destructive command is destructive. See [What it protects against](#what-it-protects-against).

## Limits worth stating plainly

- Redaction is best-effort against *accidents*, not against intent. See [What it protects against](#what-it-protects-against).
- A value too short or too low-entropy to redact is refused at load: the broker will not inject it. It is also absent from the redactor, so if it reaches the output some other way it arrives in plaintext. The broker names which ones; fix them at the source.
- A brokered command still receives the values it asked for, in its environment, because that is the point. What it does with them afterwards is the adversarial-exfiltration row in [What it protects against](#what-it-protects-against).
- The SSH agent lends authentication, not keys, and only while the broker runs. A command can still use it to reach any host those keys open, for as long as it is running. Bound that at the far end with `command=` in `authorized_keys` if it matters.
- With `[ssh] keys` left empty there is no agent, and the keys have to live where the executor's uid can read them. That is a working setup, not a recommended one.
- Git history still contains your old plaintext. See [Migrating from ansible-vault](#migrating-from-ansible-vault).

## Implementation

Go, static binaries, no runtime interpreter, chosen for deployment reach: a
`CGO_ENABLED=0` binary needs only a kernel and systemd, where an interpreter
requirement excludes hosts by vintage. Everything the design rests on is a uid
boundary, a file mode or a systemd directive.

Two choices worth naming:

- **The keeper hands sops a key *path*, not the key.** `SOPS_AGE_KEY_FILE`,
  never `SOPS_AGE_KEY`, which would put the master key in `/proc/<pid>/environ`
  for that process's lifetime. The keeper never reads the key at all, so the
  material is in neither process. `Scrub` matches the `AGE-SECRET-KEY-…` format
  rather than a stored copy.
- **`faramir keygen`** mints an age identity through the linked library, so the
  host needs no `age` binary. It does not replace the sops CLI: the keeper only
  decrypts, and encrypting, editing and rotating still want the real tool
  wherever secrets are authored.

sops itself is executed, not linked. Linking it pulls its whole key-source tree
(AWS KMS, GCP KMS, Azure Key Vault, Vault, PGP) into the process that holds the
master key, because `keyservice` imports every backend unconditionally and Go
cannot tree-shake them out. Executing it keeps that in a separate short-lived
process, well away from the key, and leaves sops upgradable through apt.
`make sizes` reports the current cost.

Regexes are RE2: no lookahead, no backreferences. A pattern in
`agent/hooks/deny-patterns.txt` that wants one has to be rewritten without it,
so `\benv\b(?!.*\|)` is written `\benv\b[^|]*$`. `cmd/faramir-guard` asserts
that every shipped pattern compiles and that the file matches the built-in
fallback, because a pattern that fails to compile is skipped at load and would
silently weaken the list.

The hook exempts a `faramir …` invocation from scanning, so its own arguments
do not trip the list. The exemption requires whitespace after the command name:
`faramir\b` also matches the hyphen in `faramir-broker`, which would exempt
`sudo faramir-keeper …` and leave the deny rule for the daemons unable to fire.
It stops at the first separator and leaves the separator in place, so each call
in a chain is exempted on its own.

## Developing

```bash
make build           # static binaries into bin/
make test            # the whole suite; needs no sops installed
make test-unit       # everything except the end-to-end suite
make test-e2e        # end-to-end against a real broker in a temp dir
make check           # go vet + gofmt
make install         # run the four install phases (root); does NOT build
make verify          # the verification matrix, against the live deployment (root)
make sizes           # per-binary size, package count, and sops linkage
```

Tests live where the logic does, not where it is easiest to reach. Most of
what the broker does is decide: which timeout to use, what environment to
assemble, what to record, when to refuse. None of that needs a socket, a
terminal or a child process, so `internal/server` substitutes the executor and
asserts on what it was handed. `internal/executor` stands up an executor and a
real child, because the PTY and the streaming redactor only mean anything
against bytes a kernel actually delivered. `internal/e2e` is kept for what
genuinely needs the whole stack: a real socket round trip, a real keeper and
sops, a real terminal, and the CLI binary itself.

The rule of thumb: if a test would still pass with the plumbing replaced by a
stub, it belongs a layer down, where its failure names the thing that broke.

The suite needs no `sops` on PATH: `internal/sopstest` uses the real binary when
one is installed and otherwise builds a stand-in from the sops libraries, which
produces genuine sops behaviour. That package is imported only from `_test.go`
files, which is what keeps sops out of the shipped binaries.

```text
cmd/faramir            CLI, plus keygen
cmd/faramir-broker     policy, redaction, audit log, SSH keys
cmd/faramir-keeper     holds the age key, execs sops, serves values only
cmd/faramir-exec       forks brokered commands, holds nothing
cmd/faramir-mcp        MCP stdio server
cmd/faramir-guard      PreToolUse hook
internal/              implementation; each package doc explains its own decisions
internal/e2e           end-to-end suite: a real keeper, executor and broker
systemd/               socket + hardened service units, one pair per daemon
etc/config.toml        starter configuration
agent/                 deny patterns, agent settings, the snippet phase 4 installs
install/               provisioning scripts, one per phase
tests/verify.sh        the verification matrix, against a live deployment
docs/                  how the redactor works; the wire protocol; wiring Ansible to sops
```

Every binary answers `--version` with the same string, from `internal/version`,
so the CLI, the hook and the MCP server can name it without linking the broker.

- [docs/redaction.md](docs/redaction.md) - what the redactor covers, and what it cannot
- [docs/protocol.md](docs/protocol.md) - the request and response shapes on the socket
- [docs/ansible-sops.md](docs/ansible-sops.md) - pointing `group_vars` at the environment
- [docs/scope.md](docs/scope.md) - what this defends and what it stops trying to
