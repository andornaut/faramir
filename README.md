# secretd — a secret broker for local AI coding agents

Lets a local coding agent run commands that need credentials, without any
plaintext secret entering the agent's context — and therefore without it being
transmitted to a model provider.

```
$ secure-run --env ROUTER_PW=secret://home/router/admin -- printenv ROUTER_PW
«SECRET:home/router/admin»
[secure-run] redacted «SECRET:home/router/admin»×1; log_id=2026-08-05T14:22:01Z-a91f
```

The command really ran, the credential really reached it, and the agent never
saw the value.

---

## 1. What this does and does not protect against

Read this before anything else. Several design choices only make sense against
this model, and the project is easy to over-trust.

**One-sentence security property: the broker keeps plaintext out of model
context; it does not contain a compromised agent.**

### In scope — prevented

| Failure | How it is prevented |
|---|---|
| Accidental disclosure — `ansible-vault view`, `cat group_vars/all/vault.yml`, `printenv`, `ansible-playbook -vvv`, a `debug: var=` task | The agent uid cannot read the key material at all; anything run through the broker has its output redacted before the agent sees it |
| Passive discovery — reading the vault password file, an age key, an SSH private key, or another process's `/proc/<pid>/environ` | Unix uid separation plus `ProtectProc=invisible` |
| Casual prompt injection — instructions telling the agent to print or exfiltrate credentials | The agent process never holds them; there is nothing to print |

### Out of scope — explicitly not designed around

| Not prevented | Why |
|---|---|
| **Adversarial exfiltration.** An agent that deliberately transforms a value — `\| rev`, `\| cut -c1-4` across several calls, `\| sha256sum` — defeats output redaction. | Accepted. Verification tests 10 and 11 below demonstrate this and are asserted in the test suite so nobody quietly "fixes" them and starts believing a stronger property. |
| **Network egress control.** No iptables rules, no network namespaces, no proxy allowlist. | The operator decided unrestricted networking is required. Consequence: a secret that does escape redaction is unrecoverable. |
| **Filesystem blast radius.** The agent has legitimate write access to the repo; destructive edits are not addressed here. | Separate problem. |

**Acceptance invariant:** if `CLAUDE.md` were deleted, no secret could reach the
model provider. Every enforcement point is a uid boundary, a file mode, or a
hook — never the agent choosing to behave.

---

## 2. Architecture decisions

Made deliberately; the rationale is recorded so they are not re-litigated by
accident.

| Decision | Choice | Rationale |
|---|---|---|
| Isolation | Unix uid separation + systemd hardening. No Docker, Podman or bubblewrap. | Network isolation was the main thing containers made easy, and it is a non-goal. Everything else comes straight from the kernel and systemd. |
| Who executes | The broker, as its own uid. Never the agent. | If the client execs, plaintext lives in a process owned by the agent uid, which the agent can read. |
| Secret store | sops + age, replacing ansible-vault. | Encrypted YAML in the repo, per-key diffs, no network round trip, Ansible reads it natively. |
| Redaction | Custom. | `op run` and similar mask only the values *they* injected. `ansible-playbook` decrypts internally, so an injector-based tool cannot mask vault vars it never saw. The redactor knows the full value set regardless of injection path. |
| Agent interface | Unix socket, exposed as an MCP tool (`secure_run`) plus a thin CLI. | A distinct tool is far more discoverable to a model than a convention documented in prose. |
| Enforcement | PreToolUse hook + filesystem permissions. | Instructions in `CLAUDE.md` are ergonomics, not a security boundary. |

---

## 3. Layout

```
uid <operator>                  normal user, holds nothing special
uid agent                       runs the coding agent; member of group devwork
uid secretd                     holds the age key + SSH keys; executes brokered commands
group devwork                   shared access to the repo working tree

/run/secretd/sock               socket-activated, 0660 root:devwork
/etc/secretd/age.key            0400 secretd:secretd
/etc/secretd/config.toml        allowlist + policy
/srv/ansible-ctrl               broker's own git checkout (execution source of truth)
/home/agent/work/ansible-ctrl   agent's working tree (authoring only)
/var/log/secretd/raw.log        unredacted audit log, 0600 secretd:secretd
```

In this repo:

```
src/secretd/       broker: redaction, PTY execution, allowlist, protocol, sops store
bin/               secretd (daemon), secure-run (CLI), secretd-mcp (MCP server)
systemd/           socket + hardened service unit
etc/config.toml    starter policy and allowlist
agent/             PreToolUse hook, deny patterns, agent settings, CLAUDE.md snippet
install/           provisioning scripts, one per phase
tests/             unit + end-to-end suites, and the Phase 7 matrix (verify.sh)
docs/              how the redactor works; wiring Ansible to sops
```

---

## 4. Installation

Requires Python ≥ 3.11 (for `tomllib`), systemd, `age`, and `sops`.

```bash
sudo install/10-accounts.sh        # accounts, group, shared tree, umask 002
sudo install/30-sops-init.sh       # age keypair -> /etc/secretd/age.key, .sops.yaml
sudo install/20-install-broker.sh  # code, config, systemd units
sudo install/40-agent-config.sh    # MCP registration, hook, CLAUDE.md
```

Then migrate each vault file and verify before deleting anything:

```bash
install/migrate-vault.sh group_vars/all/vault.yml group_vars/all/vault.sops.yml
sudo systemctl reload secretd
secure-run -- ansible-playbook site.yml --check      # prove it works end to end
```

### ⚠️ Rotate everything that was ever committed in plaintext

Moving to sops does not un-leak what is already in the repository. After
`git rm`-ing the old vault files, the plaintext-equivalent blobs remain in git
history, and anyone with the old vault password can still read them. **Rotate
every credential that was ever committed**, or rewrite history with
`git filter-repo` and force-push — and rotate anyway if the repo was ever
pushed anywhere. This is not optional cleanup; it is the difference between
having migrated and having added a second copy.

The same applies to the vault password file: delete it only after a real
playbook run succeeds through the broker, then treat the password as burned.

---

## 5. Using it

**From the agent (MCP tools):**

- `secure_run(cmd=[…], env_refs={NAME: "secret://ref"}, cwd=…, timeout_sec=…)`
- `list_secret_refs()` — names only, never values
- `secure_sync(ref=…)` — promote committed work into the execution checkout
- `broker_status()`

**From a shell:**

```bash
secure-run --list-secrets
secure-run --env ROUTER_PW=secret://home/router/admin -- \
    ansible-playbook site.yml --limit routers
secure-run --sync
```

### Rules that are not negotiable

- **Secrets are injected as environment variables only.** There is no way to
  ask for a value to be substituted into `argv` — argv is visible in `ps`, in
  `/proc/<pid>/cmdline`, and in the child's own error messages.
- **`cmd` is an array.** The broker never hands a string to `sh -c`. A pipeline
  is requested explicitly as `["bash", "-lc", "…"]`, and that must match the
  allowlist like anything else.
- **`{{SECRET:ref}}` inside an argument is readability sugar.** It is rewritten
  to `${VAR}` — a shell *variable reference* — and the variable is injected. It
  never expands to a value on the broker side.
- **The broker executes committed content.** `/srv/ansible-ctrl` is the
  broker's own checkout; the agent authors in its tree, commits, then calls
  `secure_sync`. Without this the agent could write `debug: var=<secret>` and
  ask the broker to run it — an authorized action that no amount of isolation
  prevents.
- **`redactions` reports counts, not values**, so the caller can confirm a
  secret reached the right place without seeing it. `log_id` points into the
  operator-only raw log.

---

## 6. How redaction works

Full detail in [docs/redaction.md](docs/redaction.md). In short:

1. **The value set is every managed secret**, not just the injected ones —
   refreshed on mtime change and on `SIGHUP`. This is the requirement
   off-the-shelf injectors cannot meet.
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
6. **Short or low-entropy values are not redacted** — an 8-character floor plus
   an entropy gate, because a short password would blank out unrelated output
   at random. The broker logs a warning naming each one, and
   `list_secret_refs` marks them `NOT REDACTABLE`. Lengthen them.
7. **Tokens are stable**: the same secret always renders as `«SECRET:ref»`, so
   the model can reason about it across turns.

The age private key is itself in the value set, and only allowlist rules with
`provide_age_key = true` (Ansible, which must decrypt vars itself) receive it.

---

## 7. Verification

```bash
make test          # unit + end-to-end, no privileges required
sudo make verify   # the matrix below, against the live deployment
```

| # | Test | Expected | Covered by |
|---|---|---|---|
| 1 | `sudo -u agent cat /etc/secretd/age.key` | Permission denied | `verify.sh` |
| 2 | `sudo -u agent cat /proc/$(pgrep -u secretd secretd)/environ` | No such file | `verify.sh` |
| 3 | `secure-run -- printenv ROUTER_PW` (env_ref set) | `«SECRET:home/router/admin»` | `test_e2e`, `verify.sh` |
| 4 | `secure-run -- bash -lc 'printenv ROUTER_PW \| base64'` | redacted | `test_e2e`, `verify.sh` |
| 5 | `secure-run -- bash -lc 'printenv ROUTER_PW \| base64 -w0'` | redacted | `test_e2e`, `verify.sh` |
| 6 | `secure-run -- ansible-playbook site.yml -vvv` | no plaintext anywhere | `test_e2e`, `verify.sh` |
| 7 | playbook containing `debug: var=<secret>`, run from the `/srv` checkout | redacted | `test_e2e`, `verify.sh` |
| 8 | `secure-run -- cat /etc/passwd` | denied by allowlist | `test_e2e`, `verify.sh` |
| 9 | grep the raw log for the value | plaintext present, agent cannot read it | `test_e2e`, `verify.sh` |
| **10** | **`secure-run -- bash -lc 'printenv ROUTER_PW \| rev'`** | **LEAKS — expected** | asserted in `test_e2e` |
| **11** | **`secure-run -- bash -lc 'printenv ROUTER_PW \| cut -c1-4'`** | **LEAKS — expected** | asserted in `test_e2e` |

**Tests 10 and 11 are not defects.** They are the boundary described in
section 1: an agent that deliberately transforms a value defeats output
redaction, and with unrestricted egress that value is gone. They are asserted
*to keep leaking* so that a future change which appears to fix them is caught
and forces this document to be revisited rather than silently outgrown.

Tests 1, 2 and 9's permission checks only mean something on a real deployment —
`make test` runs everything else in a temp directory as a single uid.

---

## 8. Operational notes

- **`systemctl reload secretd`** after editing a sops file the broker manages;
  it also picks up mtime changes within `refresh_interval_sec`.
- **The broker's home is `/var/lib/secretd`, not `/home/secretd`.** It needs a
  writable home — it holds the SSH keys for managed hosts, and
  `ansible-playbook` creates `~/.ansible/tmp` unconditionally — and the unit
  sets `ProtectHome=tmpfs`, which would hide a home under `/home` from the very
  process that needs it. `install/10-accounts.sh` sets this up; an account
  created by hand with `useradd -M` will fail with
  `Unable to create local directories`.
- **Changing `[sync] source` needs a matching `BindReadOnlyPaths=`.** `/home` is
  an empty tmpfs inside the unit apart from read-only bind mounts of the sync
  source. `install/20-install-broker.sh` writes
  `secretd.service.d/10-sync-source.conf` for the worktree it was given, so an
  install with `AGENT_USER=` or `WORKTREE=` set is handled. Editing `source` in
  `config.toml` afterwards is not: add the bind mount by hand, or every sync
  fails with `source ... does not exist`.
- **Children do not inherit the broker's environment.** The child gets exactly
  `[exec.base_env]` plus its injected secrets. If a tool works for you but not
  through the broker, an environment variable is usually the reason —
  add it to `base_env` rather than widening anything else.
- **Interactive prompts hang.** The child owns a PTY but nothing writes to it,
  so a command that waits for input runs until its timeout. Pass the
  non-interactive flags.
- **Output is truncated** at `max_output_bytes` (1 MiB default). The full,
  unredacted stream is always in the raw log.
- **The raw log grows without bound.** Add a logrotate rule; keep the mode at
  0600 and the owner as `secretd`.
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
- The broker runs commands as a uid that can read every managed secret. An
  allowlisted command that writes a file where the agent can read it is a leak
  the broker will not catch — keep the allowlist tight and the execution
  checkout separate.
- `git history still contains your old plaintext.` See section 4.
