# faramir

faramir is a secret broker for local AI coding agents: it runs commands that need credentials without any plaintext secret entering the agent's context, and therefore without it being transmitted to a model provider

```console
$ faramir run --env ROUTER_PW=secret://home/router/admin -- printenv ROUTER_PW
«SECRET:home/router/admin»
[faramir] redacted «SECRET:home/router/admin»×1; log_id=2026-08-05T14:22:01Z-a91f
```

The command really ran, the credential really reached it, and the agent never saw the value.

## Features

- [Uid separation, not a container](#architecture) - three service accounts, so what a brokered command cannot reach is a kernel boundary rather than a policy
- [The master key lives where nothing executes](#architecture) - no brokered command can read the age key, ask for it, or receive it in its environment
- [Output redaction over the whole value set](#how-redaction-works) - every managed secret, not only the injected ones, so a host that prints its own configuration is covered
- [No command allowlist](#configuration) - the broker runs what it is asked to, as a uid that holds nothing; argv is an array, never a string handed to a shell
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
Accidental disclosure: `ansible-vault view`, `cat group_vars/all/vault.yml`, `printenv`, `ansible-playbook -vvv`, a `debug: var=` task | The agent uid cannot read the key material at all; anything run through the broker has its output redacted before the agent sees it
Passive discovery: reading the vault password file, an age key, an SSH private key, or another process's `/proc/<pid>/environ` | Unix uid separation plus `ProtectProc=invisible`
Casual prompt injection: instructions telling the agent to print or exfiltrate credentials | The agent process never holds them; there is nothing to print
**Loss of the master key.** The age key decrypts every managed file, retroactively, including everything already in git history. | It lives in a third uid that executes nothing. No brokered command can read the file, connect to the keeper's socket, or receive the key in its environment. See [Architecture](#architecture).

### Not prevented

Failure | Why it is not prevented
--- | ---
**Adversarial exfiltration.** An agent that deliberately transforms a value (`\| rev`, `\| cut -c1-4` across several calls, `\| sha256sum`) defeats output redaction. | Accepted. The matcher cannot be completed: the child chooses the encoding of its own output. [Verification](#verification) demonstrates it rather than asserting it, because "a value we never claimed to catch was not caught" is not a property worth a test.
**Network egress control.** No iptables rules, no network namespaces, no proxy allowlist. | The operator decided unrestricted networking is required. Consequence: a secret that does escape redaction is unrecoverable.
**Filesystem blast radius.** The agent has legitimate write access to the repo; destructive edits are not addressed here. | Separate problem.

**Acceptance invariant:** if `CLAUDE.md` were deleted, no secret could reach the model provider. Every enforcement point is a uid boundary, a file mode, or a hook, never the agent choosing to behave.

**There is no command allowlist**, and the invariant above does not need one. There used to be. It was removed rather than widened, because any rule permitting an interpreter (`bash`, `python`, `env`) reached past every constraint it expressed, so what it actually delivered was a rule to write per program and a denial per mistake. See [Architecture](#architecture).

## How it works

The agent asks for a command to be run and names each credential by reference. The broker resolves the references, runs the command as a uid that holds nothing, redacts the output, and hands back the result. No plaintext ever exists in a process the agent's uid can read.

Every boundary is a uid or a file mode, so it holds whether or not the agent cooperates.

uid | Holds | Runs
--- | --- | ---
`agent` | nothing secret | the coding agent itself
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

Keys that reach managed hosts cannot simply live in the executor's home, or every brokered command could copy a key that opens the whole fleet. The broker keeps the key files under its own uid, loads them into an `ssh-agent` it owns, and passes the child only `SSH_AUTH_SOCK`: the child can authenticate for as long as the broker runs, and can never read a key. That takes a relay, because `ssh-agent` refuses any peer uid but its own. [Architecture](#architecture) has the shape of it and what the relay will and will not forward.

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
`40-agent-config.sh` | MCP registration, hook, `CLAUDE.md`

Set `CONFIG` to install the configuration for a real workload instead of the
starter, and `WORKTREE` to the tree it should run in:

```bash
make build
sudo CONFIG=etc/examples/ansible-fleet.toml \
     WORKTREE=/home/agent/work/ansible-ctrl make install
```

`WORKTREE` names the working tree: the one the agent edits and the broker runs
in. The shipped config carries a `@WORKTREE@` placeholder, which the installer
substitutes everywhere it appears (`[exec] default_cwd` and `[secrets] files`)
before binding that one path into all three units, so they cannot disagree.

`30-install-broker.sh` refuses to run without built binaries and needs no
toolchain on the target, so building on one machine and copying `bin/` to
another works: `sudo FARAMIR_BIN=/opt/faramir/bin make install`.

A `CONFIG` that names the tree literally instead of through `@WORKTREE@` is
refused at install time rather than quietly running commands somewhere the
operator did not name.

`install/uninstall.sh` removes the broker and leaves the accounts, `/etc/faramir` and the audit log alone: deleting the age key would make every sops file in the repo unreadable, which is not a decision a teardown script should make for you.

### Migrating from ansible-vault

Migrate each vault file, point `group_vars` at the environment as described in
[docs/ansible-sops.md](docs/ansible-sops.md), and verify before deleting
anything. The encrypted file goes somewhere Ansible does not auto-load, which
is why the destination below is `secrets/` and not `group_vars/`:

```bash
install/migrate-vault.sh group_vars/all/vault.yml secrets/vault.sops.yml
sudo systemctl reload faramir-broker
faramir run --env ROUTER_PW=secret://home/router/admin -- \
    ansible-playbook site.yml --check     # prove it works end to end
```

> [!WARNING]
> **Rotate everything that was ever committed in plaintext.** Moving to sops does not un-leak what is already in the repository. After `git rm`-ing the old vault files, the plaintext-equivalent blobs remain in git history, and anyone with the old vault password can still read them. Rotate every credential that was ever committed, or rewrite history with `git filter-repo` and force-push, and rotate anyway if the repo was ever pushed anywhere. This is not optional cleanup; it is the difference between having migrated and having added a second copy.

The same applies to the vault password file: delete it only after a real playbook run succeeds through the broker, then treat the password as burned.

## Usage

Run `faramir --help` to view the available commands, and `faramir <command> --help` for each one's options:

```text
usage: faramir <command> [options] [-- program [args...]]

Run a credential-bearing command through the secret broker.

Commands:
  run           run a command with secrets injected
  list-secrets  list secret refs (names only)
  status        show broker status
  keygen        mint an age keypair for the keeper
  version       print the version and exit

Run "faramir <command> --help" for that command's own options.

Every command that talks to the broker accepts:
  --socket PATH   broker socket (default /run/faramir/broker.sock; $FARAMIR_SOCKET)
  --json          print the raw response instead of the output

Secrets are injected as environment variables only; they are never substituted
into the command line.
```

```bash
faramir list-secrets
faramir run --env ROUTER_PW=secret://home/router/admin -- printenv ROUTER_PW
faramir run --quiet -C /home/agent/work/repo -t 120 -- ansible-playbook site.yml
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

The file holds refs and never values, so it is ordinary reviewable content that
belongs beside the playbook it serves. An explicit `--env` overrides an entry of
the same name, so a wrapper can substitute one without rewriting the file.

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
`faramir_status()` | Loaded files, ref count, default working directory

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
membership included, because that is how `devwork` is granted in the first
place (`usermod -aG`). That is intended on `[server]`, whose socket is
`0660 root:devwork` anyway. Leave it empty on `[keeper]` and `[executor]`:
their only legitimate client is the broker, they take it by name in
`allowed_users`, and a peer that reaches the executor socket runs commands
that are neither redacted nor audited. Both daemons log a warning at startup
when it is not empty.

Complete configs for real workloads live in [etc/examples/](etc/examples/), and
each is a drop-in replacement rather than a fragment to merge:

Example | Workload
--- | ---
[ansible-fleet.toml](etc/examples/ansible-fleet.toml) | Running Ansible against a fleet of managed hosts, which is what faramir was built for

One key has no default, because a wrong guess would run commands somewhere you
never named. `faramir-broker --check` refuses to load a config that omits it:

Key | Meaning
--- | ---
`[exec] default_cwd` | Where a command runs when the request does not say. This is the working tree, so an edit is live as soon as it is saved.

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
`[exec] default_cwd` missing | A wrong guess would run commands somewhere you never named
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
passes a gate the broker itself fails on, which is the fleet-wide
authentication failure the two rows above exist to catch.

### Rules that are not negotiable

- **Nothing receives the age key.** There is no flag that grants it and the broker does not hold it to grant. Programs that want to decrypt sops themselves, Ansible included, cannot; they get named values instead.
- **Secrets are injected as environment variables only.** There is no way to ask for a value to be substituted into `argv`: argv is visible in `ps`, in `/proc/<pid>/cmdline`, and in the child's own error messages.
- **`cmd` is an array.** The broker never hands a string to `sh -c`. A pipeline is requested explicitly as `["bash", "-lc", "…"]`.
- **The broker runs the working tree as it is on disk.** There is no promotion step: edit, then run. This used to be mediated by a commit-then-`faramir_sync` gate into a separate `/srv` checkout, which was removed; see [Architecture](#architecture) for why it did not buy what it claimed to.
- **`redactions` reports counts, not values**, so the caller can confirm a secret reached the right place without seeing it. That is why the operator does not need plaintext either: `log_id` points into the audit log, which records the same tokens.

## Architecture

These decisions were made deliberately; the rationale is recorded so they are not re-litigated by accident.

Decision | Choice | Rationale
--- | --- | ---
Filesystem isolation | None beyond file modes and `ProtectSystem=strict`. | The three units used to put a tmpfs over `/home` and bind the working tree back in. Against this threat model it protected nothing: a home the executor's uid may not read is one the mode already refuses, and a home it may read is one the *agent* uid can read directly, without the broker. What it cost was the tree's path repeated in three drop-ins that had to agree with the config, and a failure mode where an install came up clean and every command died with `cwd does not exist`. The path now appears in one place, the config, and the executor names only `/home` as writable, where modes do the rest.
Isolation | Unix uid separation + systemd hardening. No Docker, Podman or bubblewrap. | Network isolation was the main thing containers made easy, and it is a non-goal. Everything else comes straight from the kernel and systemd. A sandbox confines what a child *sees*; it cannot make a directory its owner can rewrite from outside hold still, and it is not a substitute for a uid that holds nothing.
Where commands run | The agent's own working tree, directly. | There used to be a `/srv` checkout, promoted into by a commit-then-`faramir_sync` gate. It was justified as stopping the agent from getting `debug: var=<secret>` executed, which it never did: the agent could commit that and sync it, and verification test 7 shows exactly that content running. What it actually bought was an immutable snapshot (against an agent editing a file mid-run) and a commit sha in the audit log. Both are properties against a *deliberate* agent, which is out of scope, and the cost was a commit per iteration plus a bind-mount/config pair that had to be kept in sync by hand.
Who executes | The broker, as its own uid. Never the agent. | If the client execs, plaintext lives in a process owned by the agent uid, which the agent can read.
Who holds the key | A separate `faramir-keeper` uid that executes nothing. | A systemd credential is readable by the unit's uid, and every brokered command runs as a broker-adjacent uid. A key the broker can load is a key any command can read.
Who forks the child | A third `faramir-exec` uid, given the PTY slave over `SCM_RIGHTS`. | Anything the forking uid can reach, the child can reach. Forking from the broker would hand every command the audit log and the SSH keys that open the whole fleet.
Command allowlist | None. | It never carried a security property. `allowed_bin_dirs` bounded `argv[0]` and the per-rule `args_allow`/`cwd_allow` bounded that rule's arguments, but one rule permitting `bash` made all of it reachable in a single step, and the shipped policies had to permit `bash` for pipelines. What it reliably did instead was refuse every venv, pipx, shim and working-tree script, and cost a rule per program. Removed rather than widened.
How Ansible gets its vars | Through `env_refs` and `lookup('env', …)`, like any other program. | Letting Ansible resolve sops itself meant handing it the master key, and Ansible can run arbitrary tasks. Ansible is one consumer of the broker, not the shape of it.
Secret store | sops + age, replacing ansible-vault. | Encrypted YAML in the repo, per-key diffs, no network round trip.
Redaction | Custom. | `op run` and similar mask only the values *they* injected. A managed host can print a credential the broker never injected, so the redactor is built from the whole value set regardless of injection path.
Agent interface | Unix socket, exposed as an MCP tool (`faramir_run`) plus a thin CLI. | A distinct tool is far more discoverable to a model than a convention documented in prose.
Enforcement | PreToolUse hook + filesystem permissions. | Instructions in `CLAUDE.md` are ergonomics, not a security boundary.

### Layout

```text
uid <operator>                normal user, holds nothing special
uid agent                     runs the coding agent; member of group devwork
uid faramir-keeper            holds the age key; execs nothing but sops
uid faramir-broker            policy, redaction, audit log, SSH keys
uid faramir-exec              forks brokered commands; holds nothing
group devwork                 shared access to the working tree

/run/faramir/broker.sock      socket-activated, 0660 root:devwork
/run/faramir/keeper.sock      socket-activated, 0660 root:faramir-broker
/run/faramir/exec.sock        socket-activated, 0660 root:faramir-broker
/run/faramir/ssh-agent.sock   optional, 0660 faramir-broker:faramir-exec
/run/faramir/ssh-agent.sock.private
                              what ssh-agent itself binds, 0600 faramir-broker
/etc/faramir/age.key          0400 faramir-keeper:faramir-keeper
/etc/faramir/config.toml      0644 root:root, read by all three
/home/agent                   0710 agent:devwork, and so is every component
/home/agent/work              below it: pass through, do not list
/home/agent/work/repo         the working tree: agent edits it, commands run in it
/var/log/faramir/audit.log    audit log, 0600 faramir-broker:faramir-broker
```

All three service accounts are in `devwork`, because all three need the working tree: the keeper decrypts the sops files in it, the broker stats them to notice edits, and brokered commands run in it. That is access to files the agent already owns; it is not a route to anything the agent could not reach itself.

Group membership is not enough on its own. The tree sits inside the agent's home, which `useradd` creates 0750 `agent:agent`, and a uid that cannot traverse a directory cannot open anything beneath it. Phase 1 therefore gives `devwork` group-execute on every component from the home down to the tree, and no group-read: they pass through without being able to list the home. Without it the keeper's `open()` fails with `EACCES` rather than `ENOENT`, which reads as a file that exists and would not decrypt.

The SSH agent is two sockets for the same reason. OpenSSH's `ssh-agent` calls `getpeereid()` on every connection and closes any whose peer euid is neither root nor its own, so handing its socket to another uid fails at the protocol layer however permissive the mode is: the client connects and the request is dropped, which `ssh-add` reports as `communication with agent failed`. `ssh-agent` therefore binds a private socket that only the broker's uid uses, and the broker serves the public one, relaying bytes between the two. Every upstream connection is then the broker's own, which also means `ssh-agent`'s uid check no longer decides anything: the relay makes the `SO_PEERCRED` check itself, so the public socket's mode is a second boundary rather than the only one. It also reads the agent protocol rather than piping it: the protocol has no read-only mode, so a connection that can sign can also send `REMOVE_ALL_IDENTITIES` or `ADD_IDENTITY`, and a brokered command could empty the broker's agent or load a key of its own into it. Only `REQUEST_IDENTITIES` and `SIGN_REQUEST` are forwarded, and the connection ends on anything else. The child can therefore authenticate and still cannot extract a key, which the protocol does not offer, change what the agent holds, or ptrace it, since it belongs to another uid.

What keeps a brokered command out of everything else is the ordinary file mode, not a mount namespace. `ProtectSystem=strict` makes the whole hierarchy read-only, and the executor names one writable path, `/home`, where the only thing its uid can actually write is the group-writable tree: homes are 0700 apart from the agent's, which grants `devwork` traversal and nothing else, and `~agent/.claude` is 0700 `agent`.

Three uids, because anything a uid can reach, a command running as that uid can reach. What a brokered command cannot do, and why:

Cannot | Why not
--- | ---
read `/etc/faramir/age.key` | 0400 `faramir-keeper`; `devwork` does not appear in that mode
open the keeper socket | 0660 `root:faramir-broker`, and it is not in that group
ask the keeper for the key | there is no such request
read or truncate the audit log | 0600 `faramir-broker`
read the SSH keys for managed hosts | 0700 `faramir-broker`; it gets an agent socket instead
receive `SOPS_AGE_KEY` | nothing puts it there

It **can** write the working tree, which is the point: Ansible drops `.retry` files and fact caches, and a playbook that generates config has to put it somewhere. It can also reach `/run/faramir/broker.sock`, since that is `0660 root:devwork`: a brokered command can call the broker back. That buys it nothing. The response is redacted and audited exactly like the agent's own, and every ref it could name is already listed by `faramir_list_secrets`.

The PTY does not move with the fork. The broker creates the pair, sends the slave over `SCM_RIGHTS`, and keeps the master, so redaction, truncation and the audit log stay in the broker and output takes no extra hop.

## How redaction works

Full detail in [docs/redaction.md](docs/redaction.md). In short:

1. **The value set is every managed secret**, not just the injected ones, fetched from the keeper and refreshed on mtime change and on `SIGHUP`. A managed host can print a credential the broker never injected, which is the case off-the-shelf injectors cannot cover.
1. **Children run on a PTY**, not a pipe: programs behave normally, and writes straight to `/dev/tty` (which is how `ssh` and `sudo` prompt) are captured. Consequence: stdout and stderr arrive merged.
1. **ANSI escapes are stripped before matching**, so a colour code spliced into the middle of a value cannot defeat it.
1. **An expanded value set is matched**: raw, base64 (padded/unpadded, wrapped/unwrapped), URL-encoded, JSON-escaped, shell single- and double-quoted.
1. **Streaming uses an overlap buffer**, so a value split across two reads is still caught.
1. **Short or low-entropy values are refused at load**: an 8-character floor plus an entropy gate, because a short password would blank out unrelated output at random if redacted. The broker will not hold or inject one, and names it in the log and in `faramir-broker --check`; the agent is told neither, since a value that is never tokenized is one worth targeting. Lengthen them.
1. **Tokens are stable**: the same secret always renders as `«SECRET:ref»`, so the model can reason about it across turns.

The age key is *not* in the value set. It used to be, so that a child which printed it got a token instead of the key. No child can obtain it now, so the property holds by construction rather than by the matcher catching it on the way out, which is the stronger arrangement: redaction is best-effort, and a uid boundary is not.

## Verification

```bash
make test          # unit + end-to-end, no privileges required
sudo make verify   # the matrix below, against the live deployment
```

The numbering is `verify.sh`'s own, so a failure reported there is findable here.

No. | Test | Expected | Covered by
--- | --- | --- | ---
1 | `sudo -u agent cat /etc/faramir/age.key` | Permission denied | `verify.sh`
1b | `sudo -u faramir-broker cat /etc/faramir/age.key` | Permission denied | `verify.sh`
1c | mode and owner of `/etc/faramir/age.key` | `0400 faramir-keeper` | `verify.sh`
1d | `sudo -u agent test -w /run/faramir/keeper.sock` | not writable | `verify.sh`
1e | `faramir run -- bash -lc 'cat /run/credentials/*/age_key'` | no key | `verify.sh`
1f | `faramir run -- bash -lc 'echo $SOPS_AGE_KEY'` | empty | `internal/e2e`, `verify.sh`
1g | `faramir run -- bash -lc 'id -un'` | `faramir-exec` | `verify.sh`
1h | `sudo -u faramir-exec cat /var/log/faramir/audit.log` | Permission denied | `verify.sh`
1i | `faramir run -- bash -lc 'touch <worktree>/x'` | succeeds; commands run where the agent edits | `verify.sh`
1i2 | `sudo -u faramir-exec cat /etc/faramir/age.key` | Permission denied; `devwork` must not grant this | `verify.sh`
1j | `sudo -u faramir-exec test -w /run/faramir/keeper.sock` | not writable | `verify.sh`
1k | `sudo -u faramir-exec test -w /run/faramir/exec.sock` | not writable; no unlogged commands | `verify.sh`
1l | `faramir run -- bash -lc 'ssh-add -l'` | lists keys it cannot read | `internal/sshagent`, `verify.sh`
1m | `sudo -u faramir-exec cat ~faramir-broker/.ssh/id_*` | Permission denied | `verify.sh`
1n | `sudo -u faramir-exec test -w /run/faramir/ssh-agent.sock.private` | not connectable; the keys are reachable only through the relay | `internal/sshagent`, `verify.sh`
1o | `faramir run -- bash -lc 'ssh-add -D'` | refused; the agent still holds its keys | `internal/sshagent`, `verify.sh`
2 | `sudo -u agent cat /proc/$(pgrep -u faramir-broker faramir-broker)/environ` | No such file | `verify.sh`
2b | `sudo -u agent test -w /run/faramir/broker.sock` | writable; `devwork` access works | `verify.sh`
3 | `faramir run -- printenv ROUTER_PW` (env_ref set) | `«SECRET:home/router/admin»` | `internal/e2e`, `verify.sh`
4 | `faramir run -- bash -lc 'printenv ROUTER_PW \| base64'` | redacted | `internal/e2e`, `verify.sh`
5 | `faramir run -- bash -lc 'printenv ROUTER_PW \| base64 -w0'` | redacted | `internal/e2e`, `verify.sh`
6 | `faramir run -- ansible-playbook site.yml -vvv` | no plaintext anywhere | `verify.sh`
7 | playbook containing `debug: var=<secret>` | redacted | `verify.sh`
8 | `faramir run -- <not-on-PATH>` | refused, and the error names `[exec.base_env] PATH` | `internal/resolve`, `internal/server`, `verify.sh`
8b | `faramir run -- <worktree>/script.sh` | runs; a program outside the system directories is not special | `internal/resolve`, `internal/e2e`, `verify.sh`
9a | mode and owner of the audit log | `0600 faramir-broker` | `internal/e2e`, `verify.sh`
9b | `sudo -u agent cat /var/log/faramir/audit.log` | Permission denied | `verify.sh`
9c | the audit log has content | records what ran, tokenized | `internal/e2e`, `verify.sh`
9d/9e | grep the audit log for an injected value | **absent**; the log holds tokens, never values | `internal/server`, `internal/e2e`, `verify.sh`
**10** | **`faramir run -- bash -lc 'printenv ROUTER_PW \| rev'`** | **reaches the caller transformed** | demonstrated by `verify.sh`, not asserted
**11** | **`faramir run -- bash -lc 'printenv ROUTER_PW \| cut -c1-4'`** | **reaches the caller transformed** | demonstrated by `verify.sh`, not asserted

Some properties need no live deployment and are therefore asserted only in the
Go suite, where they can be exercised on every run:

Property | Expected | Covered by
--- | --- | ---
Any keeper request other than `get_values` | refused, and the message says no operation returns key material | `internal/keeper`
`sops --decrypt` run *as* a brokered command | fails for want of key material | `internal/e2e`
Broker hangs up mid-command | the child's process group is killed | `internal/execserver`
A write straight to `/dev/tty` | captured and tokenized, which a pipe would never see | `internal/e2e`
A request over `max_concurrency` | refused as `busy`, not queued, and the slot returns | `internal/server`
`timeout_sec` above `max_timeout_sec` | clamped, which is what bounds how long a slot is held | `internal/server`
The environment the broker assembles | `base_env` plus the requested refs and nothing else, with no `HOME`: the executor supplies that under its own uid | `internal/server`
A child's whole environment | no `AGE-SECRET-KEY` and no `SOPS_AGE_*` under any name | `internal/e2e`
That environment after the run | wiped, so no plaintext copy outlives the request | `internal/server`
Output past `max_output_bytes` | cut and said so, while the PTY keeps draining | `internal/executor`

> [!NOTE]
> **10 and 11 are not defects, and not assertions either.** They are the boundary described in [What it protects against](#what-it-protects-against): an agent that deliberately transforms a value defeats output redaction, and with unrestricted egress that value is gone. `verify.sh` prints what actually comes back, because operators do not believe this until they watch it happen, but nothing pins it: a test that fails when redaction gets *better* is a test that has to be deleted to make progress. What is asserted instead is the coverage that is claimed, in `internal/redact`: base64 padded and unpadded, wrapped and not, URL-encoded, JSON-escaped, shell-quoted, and split across chunk boundaries.

The permission checks in tests 1 through 2b, and 9a/9b, only mean something on a real deployment. `make test` runs everything else in a temp directory, with the keeper, the executor and the broker as separate processes but a single uid: that exercises the protocol, the PTY hand-off and the redactor, not the uid boundary itself.

## Operational notes

- **`systemctl reload faramir-broker`** after editing a sops file it manages; it also picks up mtime changes within `refresh_interval_sec`, and retries within the same interval when the previous attempt could not reach the keeper. The broker stats the files itself and asks the keeper to decrypt, so a reload needs both services running. One refresh-driven reload runs at a time, so concurrent requests do not each start their own; `refresh_interval_sec = 0` means "check on every request" and is bounded only by that.
- **The keeper and the executor must both be up.** `faramir-broker.service` requires both sockets. With no executor every command fails with `exec_failed`; with no keeper, see below.
- **The keeper must be up before the broker is useful.** With no keeper the broker keeps whatever value set it already had and logs the failure; on a cold start that set is empty, which means nothing gets redacted. It retries on the next request after `refresh_interval_sec`, so a keeper that comes back is picked up on its own without a reload. Check `systemctl status faramir-keeper` first when tokens stop appearing.
- **`[secrets] files` may live anywhere the keeper's uid can read.** `ProtectSystem=strict` leaves the whole hierarchy visible and read-only, so a path outside the working tree needs no unit change; its own mode is what decides.
- **The broker's home is `/var/lib/faramir-broker`, not `/home/faramir-broker`.** It needs a writable home, because it holds the SSH keys for managed hosts and `ansible-playbook` creates `~/.ansible/tmp` unconditionally, and `StateDirectory=` is what grants it. `install/10-accounts.sh` sets this up; an account created by hand with `useradd -M` will fail with `Unable to create local directories`.
- **The working tree's path lives in the config and nowhere else.** Moving it means editing `[exec] default_cwd` and `[secrets] files`, or re-running `install/30-install-broker.sh` with a new `WORKTREE`. The units name no tree and the installer writes no drop-ins: the broker and the keeper only read the tree, which `ProtectSystem=strict` already allows, and the executor is granted `/home`, where modes decide what it can actually write. A tree outside `/home` is the one case needing a drop-in, adding its path to the executor's `ReadWritePaths=`.
- **Children do not inherit the broker's environment.** The child gets exactly `[exec.base_env]` plus its injected secrets. If a tool works for you but not through the broker, an environment variable is usually the reason. Add it to `base_env` rather than widening anything else.
- **Interactive prompts fail, they do not hang.** The child owns a PTY for output, but its stdin is `/dev/null`, so a command that waits for input gets EOF immediately. Pass the non-interactive flags.
- **Output is truncated** at `max_output_bytes` (1 MiB default). The audit log keeps more of it, up to `max_record_bytes` (4 MiB default), tokenized the same way.
- **The audit log grows without bound.** Add a logrotate rule; keep the mode at 0600 and the owner as `faramir-broker`.
- **The audit log holds no secret value.** Output is recorded after redaction, and the command line is redacted too, so a value a caller put in `argv` itself does not reach disk either. What you get is who ran what, when, against which refs, and what came back with the same `«SECRET:ref»` tokens the agent saw. It is still 0600 and still operator-only, because the command lines and the ref names are worth protecting on their own. See [docs/redaction.md](docs/redaction.md) for what this costs and why the counts are enough.
- **Do not bind-mount or symlink the operator's `~/.claude` into the agent account.** A session that can write agent config paths can persist hooks or MCP servers that run with different privileges on the next launch.
- **A key the broker cannot use fails `--check`.** Missing, passphrase-protected, or `[ssh] keys` naming the `.pub` by mistake: `ssh-add` refuses all three, and the broker then starts with an agent holding nothing. It logs one warning and carries on, so every socket is active and every playbook fails to authenticate against every host. `--check` reports each key under `ssh.keys` with whether it is readable and usable, as the uid that runs it, so run it as the broker's account. See [The install gate](#the-install-gate).
- **SSH keys belong in `[ssh] keys`, not in the executor's home.** Listed there, the broker loads them into an agent it owns and passes the child only `SSH_AUTH_SOCK`, so a brokered command can authenticate without being able to copy a key that opens the whole fleet. Left empty, the keys must sit in `~faramir-exec/.ssh`, where every brokered command can read them.
- **There is no blast-radius bound.** A brokered command runs anything the executor's uid can run. That uid holds no key, no audit log and no SSH key, which is the property the design rests on, but it does have write access to the working tree, so a destructive command is destructive. See [What it protects against](#what-it-protects-against).

## Limits worth stating plainly

- Redaction is best-effort against *accidents*, not against intent. See [What it protects against](#what-it-protects-against).
- A secret shorter than 8 characters, or with very low entropy, is refused at load: the broker will not inject it. It is also absent from the redactor, so if it reaches the output some other way it arrives in plaintext. The broker tells you which ones; fix them at the source.
- A brokered command still receives the values it asked for, in its environment, because that is the point. What it does with them afterwards is the adversarial-exfiltration row in [What it protects against](#what-it-protects-against).
- The SSH agent lends authentication, not keys, and only while the broker runs. A command can still use it to reach any host those keys open, for as long as it is running. Bound that at the far end with `command=` in `authorized_keys` if it matters.
- With `[ssh] keys` left empty there is no agent, and the keys have to live where the executor's uid can read them. That is a working setup, not a recommended one.
- Git history still contains your old plaintext. See [Migrating from ansible-vault](#migrating-from-ansible-vault).

## Implementation

Go, static binaries, no runtime interpreter. The Python implementation this was
ported from is preserved on the [`python`](../../tree/python) branch; it is
feature-equivalent as of `679dde4` and remains a working broker.

The port exists for deployment reach. Python needed >= 3.11 for `tomllib`, which
excludes Ubuntu 22.04, Debian 11 and RHEL 9; a `CGO_ENABLED=0` binary needs only
a kernel and systemd. Everything the design rests on is a uid boundary, a file
mode or a systemd directive, and those are identical in both.

Two differences from the Python implementation, both deliberate:

- **The keeper hands sops a key *path*, not the key.** Python set `SOPS_AGE_KEY`
  in the child's environment, where `/proc/<pid>/environ` held the master key for
  that process's lifetime. Setting `SOPS_AGE_KEY_FILE` instead means the keeper
  never reads the key at all, so the material is in neither process. `Scrub`
  matches the `AGE-SECRET-KEY-…` format rather than a stored copy.
- **`faramir keygen`** mints an age identity through the linked library, so the
  host needs no `age` binary. It does not replace the sops CLI: the keeper only
  decrypts, and encrypting, editing and rotating still want the real tool
  wherever secrets are authored.

sops itself is executed, not linked. Linking it pulls its whole key-source tree
(AWS KMS, GCP KMS, Azure Key Vault, Vault, PGP) into the process that holds the
master key, because `keyservice` imports all seven backends unconditionally and
Go cannot tree-shake them out; measured, that cost 42 MB and 818 packages in the
keeper. Executing it keeps that in a separate short-lived process and leaves
sops upgradable through apt.

Regexes are RE2, which has no lookahead or backreferences. That mattered in
exactly one place, `agent/hooks/deny-patterns.txt`, where `\benv\b(?!.*\|)`
became `\benv\b[^|]*$`; `cmd/faramir-guard` asserts that every shipped pattern
compiles and that the file matches the built-in fallback, because a pattern that
fails to compile is skipped at load and would silently weaken the list.

The hook exempts a `faramir …` invocation from scanning, so its own arguments
do not trip the list. That exemption requires whitespace after the command
name: `faramir\b` also matches the hyphen in `faramir-broker`, which exempted
`sudo faramir-keeper …` and left the deny rule for the daemons unable to fire
at all. It still stops at the first separator, and leaves the separator in
place so each call in a chain is exempted on its own.

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

All six binaries answer `--version` with the same string: `internal/version`
holds it, so the CLI, the hook and the MCP server can name it without linking
the broker.

- [docs/redaction.md](docs/redaction.md) - what the redactor covers, and what it cannot
- [docs/protocol.md](docs/protocol.md) - the request and response shapes on the socket
- [docs/ansible-sops.md](docs/ansible-sops.md) - pointing `group_vars` at the environment
