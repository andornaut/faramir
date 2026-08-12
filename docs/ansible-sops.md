# Wiring Ansible to sops

Playbooks get credentials the way every brokered program does: the caller names refs, the broker injects values as environment variables, and `group_vars` reads them.

Ansible does **not** decrypt sops and cannot. That needs the age private key, and no process the broker starts receives it: a playbook runs arbitrary tasks, so one holding the master key means anything that can reach Ansible obtains the key to every managed file, retroactively. A `community.sops` vars plugin or `lookup('pipe', 'sops -d …')` fails for the same reason; `internal/e2e` runs `sops --decrypt` as a brokered command and asserts it fails for want of key material.

Nothing here edits faramir's configuration: `[secrets] patterns` globs the secrets directory, so a file put there is managed by being there, and no drop-in is involved. One is needed only for encrypted files kept somewhere the glob does not reach, which then have to be named or none of their values reach the redactor, whether or not a playbook uses them. The other thing a drop-in is good for here is `[exec.base_env]`: a brokered command inherits nothing from the broker, so a variable `ansible-playbook` needs, `ANSIBLE_CONFIG` among them, has to be named there or it is absent.

## 1. Encrypt the right file, in the right place

The encrypted file belongs in the secrets directory: `secrets/` under the config directory, so `/etc/faramir/secrets` unless `--config-dir` moved it, `2750 root:faramir-keeper`. The operator is not in that group, so putting a file there and editing it afterwards both go through `sudo faramir edit`.

Not in a checkout, which is [absent at boot](design.md) if it sits in an encrypted home, and **never in `group_vars/` or `host_vars/`**. Ansible loads every `.yml` under those as a vars file: a sops file is valid YAML, so it binds each var to its `ENC[AES256_GCM,...]` ciphertext, and a name sorting after `vars.yml` also overwrites the mapping from section 2. Nothing errors; hosts get configured with ciphertext in place of the credential. `faramir init` refuses to finish when a file `[secrets] patterns` resolves to sits under either of those, naming it and where to move it.

`.sops.yaml` sits in the config directory above the secrets, `/etc/faramir/.sops.yaml`, written by `faramir init` and left alone thereafter; changing its recipients is [Adding a recipient](operating.md#adding-a-recipient).

```yaml
creation_rules:
  - path_regex: \.sops\.ya?ml$
    key_groups:
      - age:
          - age1... # the keeper's public key
```

The rule matches the suffix rather than a directory, so moving a file does not silently drop it out of encryption.

Creating the first one needs root and two flags. Which rule applies is matched against the file's path, but **which `.sops.yaml` sops reads is resolved from the current working directory upward**, so encrypting into the secrets directory from a checkout finds nothing and fails with `config file not found, or has no creation rules`:

```bash
sudo sops --config /etc/faramir/.sops.yaml \
    --encrypt --filename-override /etc/faramir/secrets/ansible-ctrl.sops.yml \
    plain.yml
```

Every edit after that is `sudo faramir edit /etc/faramir/secrets/ansible-ctrl.sops.yml`, which needs neither flag: it re-encrypts to the recipients the file already had. Decryption needs neither either, creation rules governing encryption only.

Key *names* stay readable, so diffs are per-key and the agent sees the file's shape without any value. Nesting maps to `/` in a ref:

```yaml
home:
  router:
    admin: …        # secret://home/router/admin
api_token: …        # secret://api_token
```

## 2. Resolution: read the environment

Add a committed, **unencrypted** vars file mapping each var to the environment variable the broker will inject. It holds no secrets:

```yaml
# group_vars/all/vars.yml
router_password: "{{ lookup('env', 'ROUTER_PW') }}"
api_token: "{{ lookup('env', 'API_TOKEN') }}"
```

The caller names the refs per run, or passes `--env-file` when there are many:

```bash
faramir run \
    --env ROUTER_PW=secret://home/router/admin \
    --env API_TOKEN=secret://api_token -- \
    ansible-playbook site.yml --limit routers
```

Verify once:

```bash
faramir run --env ROUTER_PW=secret://home/router/admin -- \
    ansible localhost -m debug -a 'var=router_password'
# -> «SECRET:home/router/admin»
```

That proves the var resolved *and* that printing it produces a token. `ENC[AES256_GCM,...]` instead means the encrypted file is somewhere Ansible auto-loads it, per section 1. A var whose ref was not injected resolves to an empty string, usually surfacing as a task failing further along: when a playbook behaves as though a credential were blank, check `env_refs` first.

## 3. SSH keys

Brokered commands run as `faramir-exec`, which must *use* the key that reaches managed hosts without being able to read it: a password can be rotated, a copied fleet key cannot be un-copied.

`faramir init` mints one, `0600 faramir-broker`, beside the age key:

```toml
[ssh]
key = "/etc/faramir/id_ed25519"
```

Nothing to write: `init` renders that line and refuses a drop-in that sets it. Put the public half `init` prints into `authorized_keys` on each managed host. `--ssh-key` moves the key, or adopts one you placed yourself.

The broker keeps both halves under its own uid, loads the private one into an `ssh-agent` it owns, and passes the child only `SSH_AUTH_SOCK`.

- A key the agent cannot load does not stop the broker: it is logged, `--check` and `doctor` fail on it, and commands that reach a host fail with ssh's own error rather than every command failing at once.
- The agent lives and dies with the broker, so nothing outlives the process holding the key in memory.

The executor's account cannot read the key, so `ssh` problems are debugged through `faramir run` or from the audit log via the reported `log_id`.

Keep `ANSIBLE_HOST_KEY_CHECKING=True` in `[exec.base_env]`. Turning it off to make a broken host work is how a broker with credentials hands them to whatever answers.

`faramir-exec` has its own `known_hosts` and it starts absent, so a play whose hosts are trusted only in the operator's `~/.ssh/known_hosts` fails verification before the key above is offered. `faramir init --known-hosts ~/.ssh/known_hosts` pins yours for it; `/etc/ssh/ssh_known_hosts` is the alternative, being the file every account on the host reads. `faramir doctor` reports how many host keys the executor can verify against.

## 4. Becoming root on the controller

`become` on a *managed* host is the operator's own arrangement: the account Ansible connects as has passwordless sudo there, and faramir has no part in it.

The controller, the host faramir itself runs on, is different, and by default it has to be left out:

```bash
faramir run --env-file faramir.env -- ansible-playbook msmtp.yml --limit '!controller'
```

because a brokered command runs as `faramir-exec`, which has no sudo. A playbook that touches every host including this one then splits in two: the fleet through the broker, the controller as root some other way, which is a secret-bearing run happening twice.

`sudo faramir init --allow-sudo` closes that. It grants `faramir-exec` a password-required sudoers entry here and points it at a PAM service of faramir's own, whose authentication step asks the broker whether a human approved the brokered command making the call. There is no password: what satisfies `sudo` is a decision, so nothing is minted, stored or handed out. The answer comes from `sudo faramir approve ID`, which the broker checks with `SO_PEERCRED` to be root, so the account the coding agent runs as cannot approve what the agent asked for. The full argument, including what an approval does *not* bound, is in [operating.md](operating.md#allowing-sudo-on-the-controller).

The Ansible side is one variable, on the controller host only:

```yaml
# host_vars/controller.yml
ansible_become_flags: '-H'
```

Dropping the default `-n` is the whole of it: `-n` tells `sudo` to fail rather than authenticate, and it does so before the PAM stack runs, so the question is never put and every task fails with `sudo: a password is required` even when a human is watching. Nothing here prompts, so there is no `SUDO_ASKPASS` and no `-A`. `-H` sets `HOME` to root's, which is what `become` normally does for you.

And you leave a watcher running, as root, in a terminal the coding agent cannot type into: a console, an ssh session from another machine, or a login as another account. Not a tmux pane on your own account, the agent running as you and `tmux send-keys` needing nothing more than that. The command warns when it can tell.

```bash
sudo faramir approvals --watch
```

Nothing else changes: no `--ask-become-pass`, no vault, and no become password in a var, there being no become password. The first task that runs sudo puts a question there naming the playbook; anything but `yes`, including no answer, fails that task with `sudo`'s own error.

- One approval per playbook run, not per task. Ansible calls `sudo` once per become'd task, and a question asked once a task is one nobody reads; a yes covers every `sudo` that `ansible-playbook` invocation makes. It is not a timed cache: the approval is scoped to that one brokered command and is gone when it exits, so a second `faramir run` is asked about separately however soon it follows.
- A *second* brokered command cannot ride the approval: the broker serialises approved runs, refusing to approve one while anything else runs as the executor and holding new `faramir run`s until it ends. Expect other brokered commands to return `busy` for the length of an approved playbook. What is *not* bounded is the approved command itself: it gets real root and can make it permanent (a setuid binary, a `systemd` unit, a line in `sudoers`), exactly as `sudo ansible-playbook` by hand can. So approve only a playbook you trust with permanent root, and keep it operator-owned and read-only to brokered commands so the agent cannot author what root runs. [operating.md](operating.md#allowing-sudo-on-the-controller) has the full argument, and [design.md](design.md#allowing-sudo-on-the-controller) the reasoning behind the mechanism.
- `faramir doctor` reports the arrangement, and reports a `NOPASSWD` entry for `faramir-exec` as a failure whether or not this host was installed with `--allow-sudo`.
