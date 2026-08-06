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
- [A default-deny allowlist](#configuration) - the broker prefers no command; a workload is a policy you choose, and argv is an array, never a string handed to a shell
- [Secrets in the environment only](#rules-that-are-not-negotiable) - never substituted into `argv`, which is world-readable in `ps`
- [An operator-only audit log](#operational-notes) - the unredacted stream, which the agent uid cannot read
- [MCP tools and a CLI](#usage) - `faramir_run` for the agent, `faramir run` for you
- [A verification matrix](#verification) - including the two cases that are supposed to leak

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
**Adversarial exfiltration.** An agent that deliberately transforms a value (`\| rev`, `\| cut -c1-4` across several calls, `\| sha256sum`) defeats output redaction. | Accepted. [Verification](#verification) tests 10 and 11 demonstrate this and are asserted in the test suite so nobody quietly "fixes" them and starts believing a stronger property. The matcher cannot be completed: the child chooses the encoding of its own output.
**Network egress control.** No iptables rules, no network namespaces, no proxy allowlist. | The operator decided unrestricted networking is required. Consequence: a secret that does escape redaction is unrecoverable.
**Filesystem blast radius.** The agent has legitimate write access to the repo; destructive edits are not addressed here. | Separate problem.

**Acceptance invariant:** if `CLAUDE.md` were deleted, no secret could reach the model provider. Every enforcement point is a uid boundary, a file mode, or a hook, never the agent choosing to behave.

## Installation

Requires Python >= 3.11 (for `tomllib`), systemd, [age](https://github.com/FiloSottile/age), and [sops](https://github.com/getsops/sops).

```bash
sudo install/10-accounts.sh        # accounts, group, shared tree, umask 002
sudo install/30-sops-init.sh       # age keypair -> /etc/faramir/age.key, .sops.yaml
sudo install/20-install-broker.sh  # code, config, systemd units
sudo install/40-agent-config.sh    # MCP registration, hook, CLAUDE.md
```

The shipped policy allows two commands, both of them demonstrations, so set
`CONFIG` to install a policy for a real workload instead:

```bash
sudo CONFIG=etc/examples/ansible-fleet.toml \
     WORKTREE=/home/agent/work/ansible-ctrl install/20-install-broker.sh
```

`WORKTREE` names the agent's authoring tree: the installer rewrites `[sync] source`
to it and binds that one path into the broker's unit, so the two cannot disagree.

`install/uninstall.sh` removes the broker and leaves the accounts, `/etc/faramir` and the audit log alone: deleting the age key would make every sops file in the repo unreadable, which is not a decision a teardown script should make for you.

### Migrating from ansible-vault

Migrate each vault file, point `group_vars` at the environment as described in [docs/ansible-sops.md](docs/ansible-sops.md), and verify before deleting anything:

```bash
install/migrate-vault.sh group_vars/all/vault.yml group_vars/all/vault.sops.yml
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
usage: faramir [-h] <command> ...

Run a credential-bearing command through the secret broker.

positional arguments:
  <command>
    run         run a command with secrets injected
    list-secrets
                list secret refs (names only)
    sync        git-sync the broker's execution checkout
    status      show broker status

options:
  -h, --help    show this help message and exit

Secrets are injected as environment variables only; they are never substituted
into the command line.
```

```bash
faramir list-secrets
faramir run --env ROUTER_PW=secret://home/router/admin -- printenv ROUTER_PW
faramir sync
```

What you may actually run is whatever the allowlist permits, which is a policy
choice rather than a property of the broker. See [Configuration](#configuration).

The agent reaches the same broker through MCP tools:

Tool | Description
--- | ---
`faramir_run(cmd=[…], env_refs={NAME: "secret://ref"}, cwd=…, timeout_sec=…)` | Run a command with secrets bound to environment variables
`faramir_list_secrets()` | Ref names only, never values
`faramir_sync(ref=…)` | Promote committed work into the execution checkout
`faramir_status()` | Loaded files, ref count, allowlist rule names

The wire protocol behind both is documented in [docs/protocol.md](docs/protocol.md).

### Configuration

[etc/config.toml](etc/config.toml) is the starter policy. It allows `printenv`,
which proves a credential reached the right variable, and `bash`, which is how a
pipeline is requested. It allows nothing else, because which commands a
deployment runs is the operator's decision and not one the broker should make on
your behalf.

Complete configs for real workloads live in [etc/examples/](etc/examples/), and
each is a drop-in replacement rather than a fragment to merge:

Example | Workload
--- | ---
[ansible-fleet.toml](etc/examples/ansible-fleet.toml) | Running Ansible against a fleet of managed hosts, which is what faramir was built for

Two keys have no default, because a wrong guess would run commands, or sync a
checkout, somewhere you never named. `faramir-broker --check` refuses to load a
config that omits them:

Key | Meaning
--- | ---
`[exec] default_cwd` | Where a command runs when the request does not say
`[sync] source`, `[sync] dest` | The tree the agent commits to, and the checkout the broker executes, required whenever `[sync] enabled` is true

### Rules that are not negotiable

- **Nothing receives the age key.** There is no flag that grants it and the broker does not hold it to grant. Programs that want to decrypt sops themselves, Ansible included, cannot; they get named values instead.
- **Secrets are injected as environment variables only.** There is no way to ask for a value to be substituted into `argv`: argv is visible in `ps`, in `/proc/<pid>/cmdline`, and in the child's own error messages.
- **`cmd` is an array.** The broker never hands a string to `sh -c`. A pipeline is requested explicitly as `["bash", "-lc", "…"]`, and that must match the allowlist like anything else.
- **`{{SECRET:ref}}` inside an argument is readability sugar.** It is rewritten to `${VAR}` (a shell *variable reference*) and the variable is injected. It never expands to a value on the broker side.
- **The broker executes committed content.** `/srv/faramir` is the broker's own checkout; the agent authors in its tree, commits, then calls `faramir_sync`. Without this the agent could write `debug: var=<secret>` and ask the broker to run it, an authorized action that no amount of isolation prevents.
- **`redactions` reports counts, not values**, so the caller can confirm a secret reached the right place without seeing it. `log_id` points into the operator-only raw log.
- **`args_allow` constrains the arguments that are present, not how many there are.** A rule that permits exactly one variable name still permits none at all unless it also sets `min_args`. The shipped `printenv` rule sets `min_args = 1` and `max_args = 1` for that reason.

## Architecture

These decisions were made deliberately; the rationale is recorded so they are not re-litigated by accident.

Decision | Choice | Rationale
--- | --- | ---
Isolation | Unix uid separation + systemd hardening. No Docker, Podman or bubblewrap. | Network isolation was the main thing containers made easy, and it is a non-goal. Everything else comes straight from the kernel and systemd.
Who executes | The broker, as its own uid. Never the agent. | If the client execs, plaintext lives in a process owned by the agent uid, which the agent can read.
Who holds the key | A separate `faramir-keeper` uid that executes nothing. | A systemd credential is readable by the unit's uid, and every brokered command runs as a broker-adjacent uid. A key the broker can load is a key any command can read, whatever the allowlist says.
Who forks the child | A third `faramir-exec` uid, given the PTY slave over `SCM_RIGHTS`. | Anything the forking uid can reach, the child can reach. Forking from the broker would hand every command the audit log, the SSH keys and write access to the execution checkout.
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
group devwork                 shared access to the repo working tree

/run/faramir/broker.sock      socket-activated, 0660 root:devwork
/run/faramir/keeper.sock      socket-activated, 0660 root:faramir-broker
/run/faramir/exec.sock        socket-activated, 0660 root:faramir-broker
/run/faramir/ssh-agent.sock   optional, 0660 faramir-broker:faramir-exec
/etc/faramir/age.key          0400 faramir-keeper:faramir-keeper
/etc/faramir/config.toml      0644 root:root, read by all three
/srv/faramir             2750 faramir-broker:faramir-exec, broker writes, exec reads
/home/agent/work/repo         agent's working tree (authoring only)
/var/log/faramir/raw.log      unredacted audit log, 0600 faramir-broker:faramir-broker
```

Three uids, because anything a uid can reach, a command running as that uid can reach. What a brokered command cannot do, and why:

Cannot | Why not
--- | ---
read `/etc/faramir/age.key` | 0400 `faramir-keeper`
open the keeper socket | 0660 `root:faramir-broker`, and it is not in that group
ask the keeper for the key | there is no such request
read or truncate the raw log | 0600 `faramir-broker`
read the SSH keys for managed hosts | 0700 `faramir-broker`; it gets an agent socket instead
write `/srv/faramir` | group has read and execute, not write
receive `SOPS_AGE_KEY` | nothing puts it there

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

No. | Test | Expected | Covered by
--- | --- | --- | ---
1 | `sudo -u agent cat /etc/faramir/age.key` | Permission denied | `verify.sh`
1b | `sudo -u faramir-broker cat /etc/faramir/age.key` | Permission denied | `verify.sh`
1c | `sudo -u agent test -w /run/faramir/keeper.sock` | not writable | `verify.sh`
1d | `faramir run -- bash -lc 'cat /run/credentials/*/age_key'` | no key | `verify.sh`
1e | `faramir run -- bash -lc 'echo $SOPS_AGE_KEY'` | empty | `test_e2e`, `verify.sh`
1f | any keeper request other than `get_values` | refused, no key | `test_keeper`
1g | `faramir run -- bash -lc 'id -un'` | `faramir-exec` | `verify.sh`
1h | `sudo -u faramir-exec cat /var/log/faramir/raw.log` | Permission denied | `verify.sh`
1i | `faramir run -- bash -lc 'touch /srv/faramir/x'` | Permission denied | `verify.sh`
1j | `sudo -u faramir-exec test -w /run/faramir/exec.sock` | not writable | `verify.sh`
1k | broker hangs up mid-command | child's process group is killed | `test_exec`
1l | `faramir run -- bash -lc 'ssh-add -l'` | lists keys it cannot read | `test_ssh`, `verify.sh`
1m | `sudo -u faramir-exec cat ~faramir-broker/.ssh/id_*` | Permission denied | `verify.sh`
2 | `sudo -u agent cat /proc/$(pgrep -u faramir-broker faramir-broker)/environ` | No such file | `verify.sh`
3 | `faramir run -- printenv ROUTER_PW` (env_ref set) | `«SECRET:home/router/admin»` | `test_e2e`, `verify.sh`
4 | `faramir run -- bash -lc 'printenv ROUTER_PW \| base64'` | redacted | `test_e2e`, `verify.sh`
5 | `faramir run -- bash -lc 'printenv ROUTER_PW \| base64 -w0'` | redacted | `test_e2e`, `verify.sh`
6 | `faramir run -- ansible-playbook site.yml -vvv` | no plaintext anywhere | `test_e2e`, `verify.sh`
7 | playbook containing `debug: var=<secret>`, run from the `/srv` checkout | redacted | `test_e2e`, `verify.sh`
7b | playbook that tries to decrypt the sops file itself | fails, no key available | `test_e2e`
8 | `faramir run -- cat /etc/passwd` | denied by allowlist | `test_e2e`, `verify.sh`
8b | `faramir run -- printenv` (no argument) | denied, `min_args` | `test_allowlist`, `verify.sh`
9 | grep the raw log for the value | plaintext present, agent cannot read it | `test_e2e`, `verify.sh`
**10** | **`faramir run -- bash -lc 'printenv ROUTER_PW \| rev'`** | **LEAKS, expected** | asserted in `test_e2e`
**11** | **`faramir run -- bash -lc 'printenv ROUTER_PW \| cut -c1-4'`** | **LEAKS, expected** | asserted in `test_e2e`

> [!NOTE]
> **Tests 10 and 11 are not defects.** They are the boundary described in [What it protects against](#what-it-protects-against): an agent that deliberately transforms a value defeats output redaction, and with unrestricted egress that value is gone. They are asserted *to keep leaking* so that a future change which appears to fix them is caught and forces this document to be revisited rather than silently outgrown.

The permission checks in tests 1 through 2 and 9 only mean something on a real deployment. `make test` runs everything else in a temp directory, with the keeper and the broker as separate processes but a single uid: that exercises the protocol and the split, not the uid boundary itself.

## Operational notes

- **`systemctl reload faramir-broker`** after editing a sops file it manages; it also picks up mtime changes within `refresh_interval_sec`. The broker stats the files itself and asks the keeper to decrypt, so a reload needs both services running.
- **The keeper and the executor must both be up.** `faramir-broker.service` requires both sockets. With no executor every command fails with `exec_failed`; with no keeper, see below.
- **The keeper must be up before the broker is useful.** With no keeper the broker keeps whatever value set it already had and logs the failure; on a cold start that set is empty, which means nothing gets redacted. Check `systemctl status faramir-keeper` first when tokens stop appearing.
- **The keeper needs the sops files visible.** Its unit sets `ProtectHome=true`, so a `[secrets] files` entry under `/home` needs a `BindReadOnlyPaths=` drop-in. Under `/srv`, as shipped, it works as is.
- **The broker's home is `/var/lib/faramir-broker`, not `/home/faramir-broker`.** It needs a writable home, because it holds the SSH keys for managed hosts and `ansible-playbook` creates `~/.ansible/tmp` unconditionally, and the unit sets `ProtectHome=tmpfs`, which would hide a home under `/home` from the very process that needs it. `install/10-accounts.sh` sets this up; an account created by hand with `useradd -M` will fail with `Unable to create local directories`.
- **`[sync] source` and the unit's `BindReadOnlyPaths=` must name the same path.** `/home` is an empty tmpfs inside the unit apart from read-only bind mounts of the sync source, so a `source` that is not bound in is invisible to the broker no matter what the config says. `install/20-install-broker.sh` writes both from the worktree it was given, and warns when an existing `config.toml` disagrees. Editing `source` by hand afterwards means adding the bind mount by hand too, or every sync fails with `source ... does not exist`.
- **Children do not inherit the broker's environment.** The child gets exactly `[exec.base_env]` plus its injected secrets. If a tool works for you but not through the broker, an environment variable is usually the reason. Add it to `base_env` rather than widening anything else.
- **Interactive prompts fail, they do not hang.** The child owns a PTY for output, but its stdin is `/dev/null`, so a command that waits for input gets EOF immediately. Pass the non-interactive flags.
- **Output is truncated** at `max_output_bytes` (1 MiB default). The full, unredacted stream is always in the raw log.
- **The raw log grows without bound.** Add a logrotate rule; keep the mode at 0600 and the owner as `faramir-broker`.
- **Do not bind-mount or symlink the operator's `~/.claude` into the agent account.** A session that can write agent config paths can persist hooks or MCP servers that run with different privileges on the next launch.
- **SSH keys belong in `[ssh] keys`, not in the executor's home.** Listed there, the broker loads them into an agent it owns and passes the child only `SSH_AUTH_SOCK`, so a brokered command can authenticate without being able to copy a key that opens the whole fleet. Left empty, the keys must sit in `~faramir-exec/.ssh`, where every brokered command can read them.
- **The `bash` allowlist rule is the widest thing that ships.** Removing it is the single biggest available tightening; the cost is losing pipelines (and [verification](#verification) tests 4, 5, 10 and 11).

## Limits worth stating plainly

- Redaction is best-effort against *accidents*, not against intent. See [What it protects against](#what-it-protects-against).
- A secret shorter than 8 characters, or with very low entropy, is refused at load: the broker will not inject it. It is also absent from the redactor, so if it reaches the output some other way it arrives in plaintext. The broker tells you which ones; fix them at the source.
- A brokered command still receives the values it asked for, in its environment, because that is the point. What it does with them afterwards is the adversarial-exfiltration row in [What it protects against](#what-it-protects-against).
- The SSH agent lends authentication, not keys, and only while the broker runs. A command can still use it to reach any host those keys open, for as long as it is running. Bound that at the far end with `command=` in `authorized_keys` if it matters.
- With `[ssh] keys` left empty there is no agent, and the keys have to live where the executor's uid can read them. That is a working setup, not a recommended one.
- Git history still contains your old plaintext. See [Migrating from ansible-vault](#migrating-from-ansible-vault).

## Developing

```bash
make test            # the whole suite (needs sops + age)
make test-unit       # everything that needs neither sops, age, nor privileges
make test-e2e        # end-to-end against a real broker in a temp dir
make check           # byte-compile + config validation + unit hardening score
make install         # install the broker (root)
make verify          # the verification matrix, against the live deployment (root)
```

The end-to-end suites skip unless `sops` and `age` are installed; `make test-unit` needs neither.

```text
src/faramir/       broker, keeper, redaction, PTY execution, allowlist, protocol
bin/               faramir (CLI), faramir-broker, faramir-keeper, faramir-mcp
systemd/           socket + hardened service units, one pair per daemon
etc/config.toml    starter policy and allowlist
agent/             PreToolUse hook, deny patterns, agent settings, CLAUDE.md snippet
install/           provisioning scripts, one per phase
tests/             unit + end-to-end suites, and the verification matrix (verify.sh)
docs/              how the redactor works; the wire protocol; wiring Ansible to sops
```

- [docs/redaction.md](docs/redaction.md) - what the redactor covers, and what it cannot
- [docs/protocol.md](docs/protocol.md) - the request and response shapes on the socket
- [docs/ansible-sops.md](docs/ansible-sops.md) - pointing `group_vars` at the environment
