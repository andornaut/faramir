# Wiring Ansible to sops

Playbooks get credentials the way every brokered program does: the caller names refs, the broker injects values as environment variables, and `group_vars` reads them.

Ansible does **not** decrypt sops and cannot. That needs the age private key, and no process the broker starts receives it: a playbook runs arbitrary tasks, so one holding the master key means anything that can reach Ansible obtains the key to every managed file, retroactively. A `community.sops` vars plugin or `lookup('pipe', 'sops -d …')` fails for the same reason; the end-to-end suites assert it, `check-exec.sh` refusing a brokered command both the age key and an encrypted file.

Nothing here edits faramir's configuration: the managed store globs the secrets directory, so a file put there is managed by being there. What does need naming is the environment: a brokered command inherits nothing from the broker, so a variable `ansible-playbook` needs, `ANSIBLE_CONFIG` among them, has to be set with `faramir init --command-env NAME=VALUE` or it is absent.

## 1. Encrypt the right file, in the right place

The encrypted file belongs in the secrets directory, `/etc/faramir/secrets` unless `--config-dir` moved it. The operator is not in the group that owns it, so putting a file there and editing it afterwards both go through `sudo faramir sops edit`.

Not in a checkout, which is absent at boot if it sits in an encrypted home, and **never in `group_vars/` or `host_vars/`**. Ansible loads every `.yml` under those as a vars file: a sops file is valid YAML, so it binds each var to its `ENC[AES256_GCM,...]` ciphertext, and a name sorting after `vars.yml` also overwrites the mapping from section 2. Nothing errors; hosts get configured with ciphertext in place of the credential. `faramir init` refuses to finish when a managed file sits under either, naming it and where to move it.

`.sops.yaml` sits in the config directory above the secrets, written by `faramir init` and left alone thereafter; changing its recipients is [Adding a recipient](operating.md#adding-a-recipient).

```yaml
creation_rules:
  - path_regex: \.sops\.ya?ml$
    key_groups:
      - age:
          - age1... # the keeper's public key
```

The rule matches the suffix rather than a directory, so moving a file does not silently drop it out of encryption.

Creating the first one needs root and two flags. Which rule applies is matched against the file's path, but **which `.sops.yaml` sops reads is resolved from the working directory upward**, so encrypting into the secrets directory from a checkout finds nothing and fails with `config file not found, or has no creation rules`:

```bash
sudo sops --config /etc/faramir/.sops.yaml \
    --encrypt --filename-override /etc/faramir/secrets/ansible-ctrl.sops.yml \
    plain.yml
```

Every edit after that is `sudo faramir sops edit /etc/faramir/secrets/ansible-ctrl.sops.yml`, which needs neither flag, re-encrypting to the recipients the file already had.

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

Verify once, which proves the var resolved *and* that printing it produces a token:

```bash
faramir run --env ROUTER_PW=secret://home/router/admin -- \
    ansible localhost -m debug -a 'var=router_password'
# -> «SECRET:home/router/admin»
```

Symptom | Cause
--- | ---
`ENC[AES256_GCM,...]` | The encrypted file is somewhere Ansible auto-loads it, per section 1
An empty string, usually a task failing further along | The ref was not injected. Check `env_refs` first when a playbook behaves as though a credential were blank

## 3. SSH keys

Brokered commands run as `faramir-exec`, which must *use* the key that reaches managed hosts without being able to read it: a password can be rotated, a copied fleet key cannot be un-copied.

`faramir init` mints one, `0600 faramir-broker`, beside the age key, and renders `[ssh] key` itself. Put the public half `init` prints into `authorized_keys` on each managed host; `--ssh-key` moves the key, or adopts one you placed yourself.

The broker keeps both halves under its own uid, loads the private one into an `ssh-agent` it owns, and passes the child only `SSH_AUTH_SOCK`. A key the agent cannot load does not stop the broker: it is logged, `--check` and `doctor` fail on it, and only commands that reach a host fail, with ssh's own error. The agent lives and dies with the broker, so nothing outlives the process holding the key in memory. The executor's account cannot read the key, so `ssh` problems are debugged through `faramir run` or from the audit log via the reported `log_id`.

Add it with `faramir init --command-env ANSIBLE_HOST_KEY_CHECKING=True`. It is not in the shipped defaults. With it off, a broker holding credentials offers them to whatever answers on that address.

`faramir-exec` has its own `known_hosts` and it starts absent, so a play whose hosts are trusted only in the operator's `~/.ssh/known_hosts` fails verification before the key above is offered. `faramir init --known-hosts ~/.ssh/known_hosts` pins yours for it; `/etc/ssh/ssh_known_hosts` is the alternative, being the file every account reads. `faramir doctor` reports how many host keys the executor can verify against.

## 4. Becoming root on the controller

`become` on a *managed* host is the operator's own arrangement: the account Ansible connects as has passwordless sudo there, and faramir has no part in it.

The controller is different, and by default it has to be left out, a brokered command running as `faramir-exec`, which has no sudo:

```bash
faramir run --env-file faramir.env -- ansible-playbook msmtp.yml --limit '!controller'
```

A playbook that touches every host then splits in two: the fleet through the broker, the controller as root some other way. `sudo faramir init --allow-sudo` closes that: a brokered command's `sudo` puts a question to a human, answered per run by `sudo faramir approve ID`, with no password anywhere. How to run it is [operating.md](operating.md#allowing-sudo-on-the-controller); the reasoning is [design.md](design.md#allowing-sudo-on-the-controller).

The Ansible side is one variable, on the controller host only:

```yaml
# host_vars/controller.yml
ansible_become_flags: '-H'
```

Dropping the default `-n` is the whole of it: `-n` tells `sudo` to fail rather than authenticate, and it does so before the PAM stack runs, so the question is never put and every task fails with `sudo: a password is required` even when a human is watching. Nothing here prompts, so there is no `SUDO_ASKPASS` and no `-A`. `-H` sets `HOME` to root's, which is what `become` normally does for you.

Nothing else changes: no `--ask-become-pass`, no vault, and no become password in a var, there being no become password. Leave a watcher running as root, in a terminal the coding agent cannot type into, and the first task that runs sudo puts its question there naming the playbook:

```bash
sudo faramir approvals --watch
```

One approval covers the whole playbook run rather than one task. [What it does and does not bound](operating.md#one-question-per-run-and-what-to-expect), including which other commands are refused meanwhile.
