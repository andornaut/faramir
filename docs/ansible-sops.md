# Wiring Ansible to sops

Playbooks get credentials the way every brokered program does: the caller names refs, the broker injects values as environment variables, and `group_vars` reads them.

Ansible does **not** decrypt sops and cannot. That needs the age private key, and no process the broker starts receives it: a playbook runs arbitrary tasks, so one holding the master key means anything that can reach Ansible obtains the key to every managed file, retroactively. A `community.sops` vars plugin or `lookup('pipe', 'sops -d …')` fails for the same reason; `internal/e2e` runs `sops --decrypt` as a brokered command and asserts it fails for want of key material.

Nothing here edits faramir's configuration: `[secrets] files` globs the store, so a file put there is managed by being there. A store kept elsewhere needs a `/etc/faramir/config.d` drop-in naming it, or none of its values reach the redactor, whether or not a playbook uses them.

## 1. Encrypt the right file, in the right place

The encrypted file belongs in the store: `secrets/` under the config directory, so `/etc/faramir/secrets` unless `--config-dir` moved it, `2750 root:faramir-keeper`. The operator is not in that group, so putting a file there and editing it afterwards both go through `sudo faramir edit`.

Not in a checkout, which is [absent at boot](design.md) if it sits in an encrypted home, and **never in `group_vars/` or `host_vars/`**. Ansible loads every `.yml` under those as a vars file: a sops file is valid YAML, so it binds each var to its `ENC[AES256_GCM,...]` ciphertext, and a name sorting after `vars.yml` also overwrites the mapping from section 2. Nothing errors; hosts get configured with ciphertext in place of the credential. `faramir init` refuses to finish against a store under either directory, and `faramir doctor` reports one.

`.sops.yaml` sits in the config directory above the store, `/etc/faramir/.sops.yaml`, written by `faramir init` and left alone thereafter; changing its recipients is [Adding a recipient](../README.md#adding-a-recipient).

```yaml
creation_rules:
  - path_regex: \.sops\.ya?ml$
    key_groups:
      - age:
          - age1... # the keeper's public key
```

The rule matches the suffix rather than a directory, so moving a file does not silently drop it out of encryption.

Creating the first one needs root and two flags. Which rule applies is matched against the file's path, but **which `.sops.yaml` sops reads is resolved from the current working directory upward**, so encrypting into the store from a checkout finds nothing and fails with `config file not found, or has no creation rules`:

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

Brokered commands run as `faramir-exec`, which must *use* the keys that reach managed hosts without being able to read them: a password can be rotated, a copied fleet key cannot be un-copied.

```toml
[ssh]
keys = ["/var/lib/faramir-broker/.ssh/id_ed25519"]
```

The broker keeps the files under its own uid, loads them into an `ssh-agent` it owns, and passes the child only `SSH_AUTH_SOCK`.

- At runtime the broker logs a key it could not load and carries on, so one bad key does not stop the others.
- The agent lives and dies with the broker, so nothing outlives the process holding keys in memory.

The agent's own account cannot read the keys either way, so `ssh` problems are debugged through `faramir run` or from the audit log via the reported `log_id`.

Keep `ANSIBLE_HOST_KEY_CHECKING=True` in `[exec.base_env]`. Turning it off to make a broken host work is how a broker with credentials hands them to whatever answers.
