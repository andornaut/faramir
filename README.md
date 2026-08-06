# faramir: a secret broker for local AI coding agents

Lets a local coding agent run commands that need credentials, without any
plaintext secret entering the agent's context, and therefore without it being
transmitted to a model provider.

```
$ faramir run --env ROUTER_PW=secret://home/router/admin -- printenv ROUTER_PW
«SECRET:home/router/admin»
[faramir] redacted «SECRET:home/router/admin»×1; log_id=2026-08-05T14:22:01Z-a91f
```

The command really ran, the credential really reached it, and the agent never
saw the value.

---

## 1. What this does and does not protect against

Read this before anything else. Several design choices only make sense against
this model, and the project is easy to over-trust.

**One-sentence security property: the broker keeps plaintext out of model
context; it does not contain a compromised agent.**

### In scope: prevented

| Failure | How it is prevented |
|---|---|
| Accidental disclosure: `ansible-vault view`, `cat group_vars/all/vault.yml`, `printenv`, `ansible-playbook -vvv`, a `debug: var=` task | The agent uid cannot read the key material at all; anything run through the broker has its output redacted before the agent sees it |
| Passive discovery: reading the vault password file, an age key, an SSH private key, or another process's `/proc/<pid>/environ` | Unix uid separation plus `ProtectProc=invisible` |
| Casual prompt injection: instructions telling the agent to print or exfiltrate credentials | The agent process never holds them; there is nothing to print |
| **Loss of the master key.** The age key decrypts every managed file, retroactively, including everything already in git history. | It lives in a third uid that executes nothing. No brokered command can read the file, connect to the keeper's socket, or receive the key in its environment. See section 3. |

### Out of scope: explicitly not designed around

| Not prevented | Why |
|---|---|
| **Adversarial exfiltration.** An agent that deliberately transforms a value (`\| rev`, `\| cut -c1-4` across several calls, `\| sha256sum`) defeats output redaction. | Accepted. Verification tests 10 and 11 below demonstrate this and are asserted in the test suite so nobody quietly "fixes" them and starts believing a stronger property. The matcher cannot be completed: the child chooses the encoding of its own output. |
| **Network egress control.** No iptables rules, no network namespaces, no proxy allowlist. | The operator decided unrestricted networking is required. Consequence: a secret that does escape redaction is unrecoverable. |
| **Filesystem blast radius.** The agent has legitimate write access to the repo; destructive edits are not addressed here. | Separate problem. |

**Acceptance invariant:** if `CLAUDE.md` were deleted, no secret could reach the
model provider. Every enforcement point is a uid boundary, a file mode, or a
hook, never the agent choosing to behave.

---

## 2. Architecture decisions

Made deliberately; the rationale is recorded so they are not re-litigated by
accident.

| Decision | Choice | Rationale |
|---|---|---|
| Isolation | Unix uid separation + systemd hardening. No Docker, Podman or bubblewrap. | Network isolation was the main thing containers made easy, and it is a non-goal. Everything else comes straight from the kernel and systemd. |
| Who executes | The broker, as its own uid. Never the agent. | If the client execs, plaintext lives in a process owned by the agent uid, which the agent can read. |
| Who holds the key | A separate `faramir-keeper` uid that executes nothing. | A systemd credential is readable by the unit's uid, and every brokered command runs as the broker's uid. A key the broker can load is a key any command can read, whatever the allowlist says. |
| How Ansible gets its vars | Through `env_refs` and `lookup('env', …)`, like any other program. | Letting Ansible resolve sops itself meant handing it the master key, and Ansible can run arbitrary tasks. Ansible is one consumer of the broker, not the shape of it. |
| Secret store | sops + age, replacing ansible-vault. | Encrypted YAML in the repo, per-key diffs, no network round trip. |
| Redaction | Custom. | `op run` and similar mask only the values *they* injected. A managed host can print a credential the broker never injected, so the redactor is built from the whole value set regardless of injection path. |
| Agent interface | Unix socket, exposed as an MCP tool (`faramir_run`) plus a thin CLI. | A distinct tool is far more discoverable to a model than a convention documented in prose. |
| Enforcement | PreToolUse hook + filesystem permissions. | Instructions in `CLAUDE.md` are ergonomics, not a security boundary. |

---

## 3. Layout

```
uid <operator>                normal user, holds nothing special
uid agent                     runs the coding agent; member of group devwork
uid faramir-keeper            holds the age key; execs nothing but sops
uid faramir-broker            holds the SSH keys; executes brokered commands
group devwork                 shared access to the repo working tree

/run/faramir/broker.sock      socket-activated, 0660 root:devwork
/run/faramir/keeper.sock      socket-activated, 0660 faramir-keeper:faramir-broker
/etc/faramir/age.key          0400 faramir-keeper:faramir-keeper
/etc/faramir/config.toml      0644 root:root, read by all three
/srv/ansible-ctrl             broker's own git checkout (execution source of truth)
/home/agent/work/ansible-ctrl agent's working tree (authoring only)
/var/log/faramir/raw.log      unredacted audit log, 0600 faramir-broker:faramir-broker
```

The keeper is the whole reason the master key survives an agent that runs
arbitrary commands. It answers exactly one question, "what are the current
values", and there is no request that returns the key. A brokered command
cannot read `/etc/faramir/age.key` (wrong uid), cannot open the keeper socket
(wrong uid), and never sees `SOPS_AGE_KEY` (nothing puts it there).

In this repo:

```
src/faramir/       broker, keeper, redaction, PTY execution, allowlist, protocol
bin/               faramir (CLI), faramir-broker, faramir-keeper, faramir-mcp
systemd/           socket + hardened service units, one pair per daemon
etc/config.toml    starter policy and allowlist
agent/             PreToolUse hook, deny patterns, agent settings, CLAUDE.md snippet
install/           provisioning scripts, one per phase
tests/             unit + end-to-end suites, and the verification matrix (verify.sh)
docs/              how the redactor works; wiring Ansible to sops
```

---

## 4. Installation

Requires Python ≥ 3.11 (for `tomllib`), systemd, `age`, and `sops`.

```bash
sudo install/10-accounts.sh        # accounts, group, shared tree, umask 002
sudo install/30-sops-init.sh       # age keypair -> /etc/faramir/age.key, .sops.yaml
sudo install/20-install-broker.sh  # code, config, systemd units
sudo install/40-agent-config.sh    # MCP registration, hook, CLAUDE.md
```

Then migrate each vault file, point `group_vars` at the environment as
described in [docs/ansible-sops.md](docs/ansible-sops.md), and verify before
deleting anything:

```bash
install/migrate-vault.sh group_vars/all/vault.yml group_vars/all/vault.sops.yml
sudo systemctl reload faramir-broker
faramir run --env ROUTER_PW=secret://home/router/admin -- \
    ansible-playbook site.yml --check     # prove it works end to end
```

### ⚠️ Rotate everything that was ever committed in plaintext

Moving to sops does not un-leak what is already in the repository. After
`git rm`-ing the old vault files, the plaintext-equivalent blobs remain in git
history, and anyone with the old vault password can still read them. **Rotate
every credential that was ever committed**, or rewrite history with
`git filter-repo` and force-push, and rotate anyway if the repo was ever
pushed anywhere. This is not optional cleanup; it is the difference between
having migrated and having added a second copy.

The same applies to the vault password file: delete it only after a real
playbook run succeeds through the broker, then treat the password as burned.

---

## 5. Using it

**From the agent (MCP tools):**

- `faramir_run(cmd=[…], env_refs={NAME: "secret://ref"}, cwd=…, timeout_sec=…)`
- `faramir_list_secrets()`: names only, never values
- `faramir_sync(ref=…)`: promote committed work into the execution checkout
- `faramir_status()`

**From a shell:**

```bash
faramir list-secrets
faramir run --env ROUTER_PW=secret://home/router/admin -- \
    ansible-playbook site.yml --limit routers
faramir sync
```

### Rules that are not negotiable

- **Nothing receives the age key.** There is no flag that grants it and the
  broker does not hold it to grant. Programs that want to decrypt sops
  themselves, Ansible included, cannot; they get named values instead.
- **Secrets are injected as environment variables only.** There is no way to
  ask for a value to be substituted into `argv`: argv is visible in `ps`, in
  `/proc/<pid>/cmdline`, and in the child's own error messages.
- **`cmd` is an array.** The broker never hands a string to `sh -c`. A pipeline
  is requested explicitly as `["bash", "-lc", "…"]`, and that must match the
  allowlist like anything else.
- **`{{SECRET:ref}}` inside an argument is readability sugar.** It is rewritten
  to `${VAR}` (a shell *variable reference*) and the variable is injected. It
  never expands to a value on the broker side.
- **The broker executes committed content.** `/srv/ansible-ctrl` is the
  broker's own checkout; the agent authors in its tree, commits, then calls
  `faramir_sync`. Without this the agent could write `debug: var=<secret>` and
  ask the broker to run it, an authorized action that no amount of isolation
  prevents.
- **`redactions` reports counts, not values**, so the caller can confirm a
  secret reached the right place without seeing it. `log_id` points into the
  operator-only raw log.

---

## 6. How redaction works

Full detail in [docs/redaction.md](docs/redaction.md). In short:

1. **The value set is every managed secret**, not just the injected ones,
   fetched from the keeper and refreshed on mtime change and on `SIGHUP`. A
   managed host can print a credential the broker never injected, which is the
   case off-the-shelf injectors cannot cover.
2. **Children run on a PTY**, not a pipe: programs behave normally, and writes
   straight to `/dev/tty` (which is how `ssh` and `sudo` prompt) are captured.
   Consequence: stdout and stderr arrive merged.
3. **ANSI escapes are stripped before matching**, so a colour code spliced into
   the middle of a value cannot defeat it.
4. **An expanded value set is matched**: raw, base64 (padded/unpadded,
   wrapped/unwrapped), URL-encoded, JSON-escaped, shell single- and
   double-quoted.
5. **Streaming uses an overlap buffer**, so a value split across two reads is
   still caught.
6. **Short or low-entropy values are not redacted**: an 8-character floor plus
   an entropy gate, because a short password would blank out unrelated output
   at random. The broker logs a warning naming each one, and
   `faramir_list_secrets` marks them `NOT REDACTABLE`. Lengthen them.
7. **Tokens are stable**: the same secret always renders as `«SECRET:ref»`, so
   the model can reason about it across turns.

The age key is *not* in the value set. It used to be, so that a child which
printed it got a token instead of the key. No child can obtain it now, so the
property holds by construction rather than by the matcher catching it on the
way out, which is the stronger arrangement: redaction is best-effort, and a uid
boundary is not.

---

## 7. Verification

```bash
make test          # unit + end-to-end, no privileges required
sudo make verify   # the matrix below, against the live deployment
```

| # | Test | Expected | Covered by |
|---|---|---|---|
| 1 | `sudo -u agent cat /etc/faramir/age.key` | Permission denied | `verify.sh` |
| 1b | `sudo -u faramir-broker cat /etc/faramir/age.key` | Permission denied | `verify.sh` |
| 1c | `sudo -u agent test -w /run/faramir/keeper.sock` | not writable | `verify.sh` |
| 1d | `faramir run -- bash -lc 'cat /run/credentials/*/age_key'` | no key | `verify.sh` |
| 1e | `faramir run -- bash -lc 'echo $SOPS_AGE_KEY'` | empty | `test_e2e`, `verify.sh` |
| 1f | any keeper request other than `get_values` | refused, no key | `test_keeper` |
| 2 | `sudo -u agent cat /proc/$(pgrep -u faramir-broker faramir-broker)/environ` | No such file | `verify.sh` |
| 3 | `faramir run -- printenv ROUTER_PW` (env_ref set) | `«SECRET:home/router/admin»` | `test_e2e`, `verify.sh` |
| 4 | `faramir run -- bash -lc 'printenv ROUTER_PW \| base64'` | redacted | `test_e2e`, `verify.sh` |
| 5 | `faramir run -- bash -lc 'printenv ROUTER_PW \| base64 -w0'` | redacted | `test_e2e`, `verify.sh` |
| 6 | `faramir run -- ansible-playbook site.yml -vvv` | no plaintext anywhere | `test_e2e`, `verify.sh` |
| 7 | playbook containing `debug: var=<secret>`, run from the `/srv` checkout | redacted | `test_e2e`, `verify.sh` |
| 7b | playbook that tries to decrypt the sops file itself | fails, no key available | `test_e2e` |
| 8 | `faramir run -- cat /etc/passwd` | denied by allowlist | `test_e2e`, `verify.sh` |
| 9 | grep the raw log for the value | plaintext present, agent cannot read it | `test_e2e`, `verify.sh` |
| **10** | **`faramir run -- bash -lc 'printenv ROUTER_PW \| rev'`** | **LEAKS, expected** | asserted in `test_e2e` |
| **11** | **`faramir run -- bash -lc 'printenv ROUTER_PW \| cut -c1-4'`** | **LEAKS, expected** | asserted in `test_e2e` |

**Tests 10 and 11 are not defects.** They are the boundary described in
section 1: an agent that deliberately transforms a value defeats output
redaction, and with unrestricted egress that value is gone. They are asserted
*to keep leaking* so that a future change which appears to fix them is caught
and forces this document to be revisited rather than silently outgrown.

The permission checks in tests 1 through 2 and 9 only mean something on a real
deployment. `make test` runs everything else in a temp directory, with the
keeper and the broker as separate processes but a single uid: that exercises
the protocol and the split, not the uid boundary itself.

---

## 8. Operational notes

- **`systemctl reload faramir-broker`** after editing a sops file it manages; it
  also picks up mtime changes within `refresh_interval_sec`. The broker stats
  the files itself and asks the keeper to decrypt, so a reload needs both
  services running.
- **The keeper must be up before the broker is useful.** With no keeper the
  broker keeps whatever value set it already had and logs the failure; on a
  cold start that set is empty, which means nothing gets redacted. Check
  `systemctl status faramir-keeper` first when tokens stop appearing.
- **The keeper needs the sops files visible.** Its unit sets
  `ProtectHome=true`, so a `[secrets] files` entry under `/home` needs a
  `BindReadOnlyPaths=` drop-in. Under `/srv`, as shipped, it works as is.
- **The broker's home is `/var/lib/faramir-broker`, not `/home/faramir-broker`.**
  It needs a writable home, because it holds the SSH keys for managed hosts and
  `ansible-playbook` creates `~/.ansible/tmp` unconditionally, and the unit sets
  `ProtectHome=tmpfs`, which would hide a home under `/home` from the very
  process that needs it. `install/10-accounts.sh` sets this up; an account
  created by hand with `useradd -M` will fail with
  `Unable to create local directories`.
- **`[sync] source` and the unit's `BindReadOnlyPaths=` must name the same
  path.** `/home` is an empty tmpfs inside the unit apart from read-only bind
  mounts of the sync source, so a `source` that is not bound in is invisible to
  the broker no matter what the config says. `install/20-install-broker.sh`
  writes both from the worktree it was given, and warns when an existing
  `config.toml` disagrees. Editing `source` by hand afterwards means adding the
  bind mount by hand too, or every sync fails with `source ... does not exist`.
- **Children do not inherit the broker's environment.** The child gets exactly
  `[exec.base_env]` plus its injected secrets. If a tool works for you but not
  through the broker, an environment variable is usually the reason. Add it
  to `base_env` rather than widening anything else.
- **Interactive prompts hang.** The child owns a PTY but nothing writes to it,
  so a command that waits for input runs until its timeout. Pass the
  non-interactive flags.
- **Output is truncated** at `max_output_bytes` (1 MiB default). The full,
  unredacted stream is always in the raw log.
- **The raw log grows without bound.** Add a logrotate rule; keep the mode at
  0600 and the owner as `faramir-broker`.
- **Do not bind-mount or symlink the operator's `~/.claude` into the agent
  account.** A session that can write agent config paths can persist hooks or
  MCP servers that run with different privileges on the next launch.
- **The `bash` allowlist rule is the widest thing in the shipped policy.**
  Removing it is the single biggest available tightening; the cost is losing
  pipelines (and verification tests 4, 5, 10 and 11).

---

## 9. Limits worth stating plainly

- Redaction is best-effort against *accidents*, not against intent. See
  section 1.
- A secret shorter than 8 characters, or with very low entropy, is not
  redacted at all. The broker tells you which ones; fix them at the source.
- The keeper protects the age key, not the individual values. A brokered
  command still shares a uid with the broker, so it can read the raw audit log
  and the SSH keys for managed hosts, and it can write `/srv/ansible-ctrl`
  directly rather than going through commit-then-sync. Splitting execution into
  a third uid is what closes those; it is not done yet.
- The broker runs commands as a uid that holds every managed *value*. An
  allowlisted command that writes one to a file where the agent can read it is
  a leak the broker will not catch. Keep the allowlist tight and the execution
  checkout separate.
- `git history still contains your old plaintext.` See section 4.
