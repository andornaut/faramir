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

**There is no command allowlist**, and the invariant above does not need one. There used to be. It was removed rather than widened, because any rule permitting an interpreter — `bash`, `python`, `env` — reached past every constraint it expressed, so what it actually delivered was a rule to write per program and a denial per mistake. See [Architecture](#architecture).

## Installation

Requires systemd and [sops](https://github.com/getsops/sops) on the host, and Go to
build. Nothing else at runtime: the binaries are static, so the host needs no
interpreter and no libc of a particular vintage.

```bash
make build
sudo install/10-accounts.sh        # accounts, group, shared tree, umask 002
sudo install/30-sops-init.sh       # age keypair -> /etc/faramir/age.key, .sops.yaml
sudo install/20-install-broker.sh  # code, config, systemd units
sudo install/40-agent-config.sh    # MCP registration, hook, CLAUDE.md
```

Set `CONFIG` to install the configuration for a real workload instead of the
starter:

```bash
sudo CONFIG=etc/examples/ansible-fleet.toml \
     WORKTREE=/home/agent/work/ansible-ctrl install/20-install-broker.sh
```

`WORKTREE` names the working tree — the one the agent edits and the broker runs
in. The installer rewrites every mention of it in the config (`[exec]
default_cwd` and `[secrets] files`) and binds that one path into all three
units, so they cannot disagree.

`20-install-broker.sh` refuses to run without built binaries and needs no
toolchain on the target, so building on one machine and copying `bin/` to
another works. Point it elsewhere with `FARAMIR_BIN`.

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
    status      show broker status

options:
  -h, --help    show this help message and exit

Secrets are injected as environment variables only; they are never substituted
into the command line.
```

```bash
faramir list-secrets
faramir run --env ROUTER_PW=secret://home/router/admin -- printenv ROUTER_PW
```

A bare command name is looked up on `[exec.base_env] PATH`, which is the PATH
the child itself gets — so a tool in a venv or a pipx install is reached by
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
`[exec] max_output_bytes` | Ceiling on what comes back; the full stream is still in the raw log
`[secrets] min_length` and friends | A value too short or too low-entropy to redact is refused at load, so it cannot be injected at all
the executor's uid | The real one. See [Architecture](#architecture).

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

### Rules that are not negotiable

- **Nothing receives the age key.** There is no flag that grants it and the broker does not hold it to grant. Programs that want to decrypt sops themselves, Ansible included, cannot; they get named values instead.
- **Secrets are injected as environment variables only.** There is no way to ask for a value to be substituted into `argv`: argv is visible in `ps`, in `/proc/<pid>/cmdline`, and in the child's own error messages.
- **`cmd` is an array.** The broker never hands a string to `sh -c`. A pipeline is requested explicitly as `["bash", "-lc", "…"]`.
- **`{{SECRET:ref}}` inside an argument is readability sugar.** It is rewritten to `${VAR}` (a shell *variable reference*) and the variable is injected. It never expands to a value on the broker side.
- **The broker runs the working tree as it is on disk.** There is no promotion step: edit, then run. This used to be mediated by a commit-then-`faramir_sync` gate into a separate `/srv` checkout, which was removed — see [Architecture](#architecture) for why it did not buy what it claimed to.
- **`redactions` reports counts, not values**, so the caller can confirm a secret reached the right place without seeing it. `log_id` points into the operator-only raw log.

## Architecture

These decisions were made deliberately; the rationale is recorded so they are not re-litigated by accident.

Decision | Choice | Rationale
--- | --- | ---
Isolation | Unix uid separation + systemd hardening. No Docker, Podman or bubblewrap. | Network isolation was the main thing containers made easy, and it is a non-goal. Everything else comes straight from the kernel and systemd. A sandbox confines what a child *sees*; it cannot make a directory its owner can rewrite from outside hold still, and it is not a substitute for a uid that holds nothing.
Where commands run | The agent's own working tree, directly. | There used to be a `/srv` checkout, promoted into by a commit-then-`faramir_sync` gate. It was justified as stopping the agent from getting `debug: var=<secret>` executed — which it never did: the agent could commit that and sync it, and verification test 7 shows exactly that content running. What it actually bought was an immutable snapshot (against an agent editing a file mid-run) and a commit sha in the audit log. Both are properties against a *deliberate* agent, which is out of scope, and the cost was a commit per iteration plus a bind-mount/config pair that had to be kept in sync by hand.
Who executes | The broker, as its own uid. Never the agent. | If the client execs, plaintext lives in a process owned by the agent uid, which the agent can read.
Who holds the key | A separate `faramir-keeper` uid that executes nothing. | A systemd credential is readable by the unit's uid, and every brokered command runs as a broker-adjacent uid. A key the broker can load is a key any command can read.
Who forks the child | A third `faramir-exec` uid, given the PTY slave over `SCM_RIGHTS`. | Anything the forking uid can reach, the child can reach. Forking from the broker would hand every command the audit log and the SSH keys that open the whole fleet.
Command allowlist | None. | It never carried a security property. `allowed_bin_dirs` bounded `argv[0]` and the per-rule `args_allow`/`cwd_allow` bounded that rule's arguments — but one rule permitting `bash` made all of it reachable in a single step, and the shipped policies had to permit `bash` for pipelines. What it reliably did instead was refuse every venv, pipx, shim and working-tree script, and cost a rule per program. Removed rather than widened; the config carrying either setting is now a hard error rather than a silently ignored key.
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
/etc/faramir/age.key          0400 faramir-keeper:faramir-keeper
/etc/faramir/config.toml      0644 root:root, read by all three
/home/agent/work/repo         the working tree: agent edits it, commands run in it
/var/log/faramir/raw.log      unredacted audit log, 0600 faramir-broker:faramir-broker
```

All three service accounts are in `devwork`, because all three need the working tree: the keeper decrypts the sops files in it, the broker stats them to notice edits, and brokered commands run in it. That is access to files the agent already owns — it is not a route to anything the agent could not reach itself.

Three uids, because anything a uid can reach, a command running as that uid can reach. What a brokered command cannot do, and why:

Cannot | Why not
--- | ---
read `/etc/faramir/age.key` | 0400 `faramir-keeper`; `devwork` does not appear in that mode
open the keeper socket | 0660 `root:faramir-broker`, and it is not in that group
ask the keeper for the key | there is no such request
read or truncate the raw log | 0600 `faramir-broker`
read the SSH keys for managed hosts | 0700 `faramir-broker`; it gets an agent socket instead
receive `SOPS_AGE_KEY` | nothing puts it there

It **can** write the working tree, which is the point — Ansible drops `.retry` files and fact caches, and a playbook that generates config has to put it somewhere. It can also reach `/run/faramir/broker.sock`, since that is `0660 root:devwork`: a brokered command can call the broker back. That buys it nothing. The response is redacted and audited exactly like the agent's own, and every ref it could name is already listed by `faramir_list_secrets`.

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
1e | `faramir run -- bash -lc 'echo $SOPS_AGE_KEY'` | empty | `internal/e2e`, `verify.sh`
1f | any keeper request other than `get_values` | refused, no key | `internal/keeper`
1g | `faramir run -- bash -lc 'id -un'` | `faramir-exec` | `verify.sh`
1h | `sudo -u faramir-exec cat /var/log/faramir/raw.log` | Permission denied | `verify.sh`
1i | `faramir run -- bash -lc 'touch <worktree>/x'` | succeeds; commands run where the agent edits | `verify.sh`
1i2 | `sudo -u faramir-exec cat /etc/faramir/age.key` | Permission denied — `devwork` must not grant this | `verify.sh`
1j | `sudo -u faramir-exec test -w /run/faramir/exec.sock` | not writable | `verify.sh`
1k | broker hangs up mid-command | child's process group is killed | `internal/execserver`
1l | `faramir run -- bash -lc 'ssh-add -l'` | lists keys it cannot read | `internal/sshagent`, `verify.sh`
1m | `sudo -u faramir-exec cat ~faramir-broker/.ssh/id_*` | Permission denied | `verify.sh`
2 | `sudo -u agent cat /proc/$(pgrep -u faramir-broker faramir-broker)/environ` | No such file | `verify.sh`
3 | `faramir run -- printenv ROUTER_PW` (env_ref set) | `«SECRET:home/router/admin»` | `internal/e2e`, `verify.sh`
4 | `faramir run -- bash -lc 'printenv ROUTER_PW \| base64'` | redacted | `internal/e2e`, `verify.sh`
5 | `faramir run -- bash -lc 'printenv ROUTER_PW \| base64 -w0'` | redacted | `internal/e2e`, `verify.sh`
6 | `faramir run -- ansible-playbook site.yml -vvv` | no plaintext anywhere | `internal/e2e`, `verify.sh`
7 | playbook containing `debug: var=<secret>` | redacted | `internal/e2e`, `verify.sh`
7b | playbook that tries to decrypt the sops file itself | fails, no key available | `internal/e2e`
8 | `faramir run -- <not-on-PATH>` | refused, and the error names `[exec.base_env] PATH` | `test_resolve`, `internal/e2e`, `verify.sh`
8b | `faramir run -- <worktree>/script.sh` | runs; a program outside the system directories is not special | `internal/resolve`, `verify.sh`
9 | grep the raw log for the value | plaintext present, agent cannot read it | `internal/e2e`, `verify.sh`
**10** | **`faramir run -- bash -lc 'printenv ROUTER_PW \| rev'`** | **LEAKS, expected** | asserted in `internal/e2e`
**11** | **`faramir run -- bash -lc 'printenv ROUTER_PW \| cut -c1-4'`** | **LEAKS, expected** | asserted in `internal/e2e`

> [!NOTE]
> **Tests 10 and 11 are not defects.** They are the boundary described in [What it protects against](#what-it-protects-against): an agent that deliberately transforms a value defeats output redaction, and with unrestricted egress that value is gone. They are asserted *to keep leaking* so that a future change which appears to fix them is caught and forces this document to be revisited rather than silently outgrown.

The permission checks in tests 1 through 2 and 9 only mean something on a real deployment. `make test` runs everything else in a temp directory, with the keeper and the broker as separate processes but a single uid: that exercises the protocol and the split, not the uid boundary itself.

## Operational notes

- **`systemctl reload faramir-broker`** after editing a sops file it manages; it also picks up mtime changes within `refresh_interval_sec`. The broker stats the files itself and asks the keeper to decrypt, so a reload needs both services running.
- **The keeper and the executor must both be up.** `faramir-broker.service` requires both sockets. With no executor every command fails with `exec_failed`; with no keeper, see below.
- **The keeper must be up before the broker is useful.** With no keeper the broker keeps whatever value set it already had and logs the failure; on a cold start that set is empty, which means nothing gets redacted. Check `systemctl status faramir-keeper` first when tokens stop appearing.
- **The keeper needs the sops files visible.** They live in the working tree, so its unit sets `ProtectHome=tmpfs` and the installer binds that one path in read-only. A `[secrets] files` entry outside the tree is visible as-is under `ProtectSystem=strict`; one somewhere else under `/home` needs its own `BindReadOnlyPaths=` drop-in.
- **The broker's home is `/var/lib/faramir-broker`, not `/home/faramir-broker`.** It needs a writable home, because it holds the SSH keys for managed hosts and `ansible-playbook` creates `~/.ansible/tmp` unconditionally, and the unit sets `ProtectHome=tmpfs`, which would hide a home under `/home` from the very process that needs it. `install/10-accounts.sh` sets this up; an account created by hand with `useradd -M` will fail with `Unable to create local directories`.
- **The working tree and the units' bind mounts must name the same path.** `/home` is an empty tmpfs inside all three units apart from a bind mount of that tree, so a tree that is not bound in is invisible no matter what the config says — the keeper reports every ref as missing and the executor fails with `cwd does not exist`. `install/20-install-broker.sh` writes all three drop-ins from the `WORKTREE` it was given and rewrites the config to match, and warns when an existing `config.toml` disagrees. Moving the tree by hand afterwards means editing `10-worktree.conf` in each of `faramir-broker.service.d`, `faramir-keeper.service.d` and `faramir-exec.service.d`, or re-running the installer.
- **Children do not inherit the broker's environment.** The child gets exactly `[exec.base_env]` plus its injected secrets. If a tool works for you but not through the broker, an environment variable is usually the reason. Add it to `base_env` rather than widening anything else.
- **Interactive prompts fail, they do not hang.** The child owns a PTY for output, but its stdin is `/dev/null`, so a command that waits for input gets EOF immediately. Pass the non-interactive flags.
- **Output is truncated** at `max_output_bytes` (1 MiB default). The full, unredacted stream is always in the raw log.
- **The raw log grows without bound.** Add a logrotate rule; keep the mode at 0600 and the owner as `faramir-broker`.
- **Do not bind-mount or symlink the operator's `~/.claude` into the agent account.** A session that can write agent config paths can persist hooks or MCP servers that run with different privileges on the next launch.
- **SSH keys belong in `[ssh] keys`, not in the executor's home.** Listed there, the broker loads them into an agent it owns and passes the child only `SSH_AUTH_SOCK`, so a brokered command can authenticate without being able to copy a key that opens the whole fleet. Left empty, the keys must sit in `~faramir-exec/.ssh`, where every brokered command can read them.
- **There is no blast-radius bound.** A brokered command runs anything the executor's uid can run. That uid holds no key, no audit log and no SSH key, which is the property the design rests on — but it does have write access to the working tree, so a destructive command is destructive. See [What it protects against](#what-it-protects-against).
- **Upgrading from a `[sync]` config fails loudly.** The broker refuses a config that still has the section, rather than ignoring it and leaving `[exec] default_cwd` pointing at a `/srv` checkout nothing populates any more. Delete `[sync]`, point `default_cwd` and `[secrets] files` at the working tree, and re-run `install/20-install-broker.sh`. `/srv/faramir` is then dead weight; remove it once you have confirmed nothing else reads it.

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

## Developing

```bash
make build           # static binaries into bin/
make test            # the whole suite; needs no sops installed
make test-unit       # everything that needs no PTY and no subprocesses
make test-e2e        # end-to-end against a real broker in a temp dir
make check           # go vet + gofmt
make install         # build, then run all four install phases (root)
make verify          # the verification matrix, against the live deployment (root)
make sizes           # per-binary size, package count, and sops linkage
```

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
systemd/               socket + hardened service units, one pair per daemon
etc/config.toml        starter configuration
agent/                 deny patterns, agent settings, CLAUDE.md snippet
install/               provisioning scripts, one per phase
tests/verify.sh        the verification matrix, against a live deployment
docs/                  how the redactor works; the wire protocol; wiring Ansible to sops
```

- [docs/redaction.md](docs/redaction.md) - what the redactor covers, and what it cannot
- [docs/protocol.md](docs/protocol.md) - the request and response shapes on the socket
- [docs/ansible-sops.md](docs/ansible-sops.md) - pointing `group_vars` at the environment
