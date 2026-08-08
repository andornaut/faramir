# Wiring Ansible to sops

Playbooks get credentials the same way every brokered program does: the caller names refs, the broker injects values as environment variables, and `group_vars` reads them.

Ansible does **not** decrypt sops and cannot. That needs the age private key, and no process the broker starts receives it. A playbook can run arbitrary tasks, so a playbook holding the master key means anything that can reach Ansible obtains the key to every managed file, retroactively.

The variables and paths assumed here are set in a `/etc/faramir/config.d` drop-in rather than in the base config, so the broker's own configuration is not edited to name an Ansible checkout's secrets file.

## 1. Encrypt the right file, in the right place

The encrypted file belongs in the store, `/etc/faramir/secrets` unless `--secrets-dir` moved it, created `2770 root:dev` by `faramir init`. Not in a checkout, and never in `group_vars/` or `host_vars/`.

Ansible loads every `.yml` under those two directories as a vars file. A sops file is valid YAML, so it loads without error and binds each var to its `ENC[AES256_GCM,...]` ciphertext; a name sorting after `vars.yml` also overwrites the `lookup('env', …)` mapping from section 2. Nothing errors. Hosts get configured with ciphertext in place of the credential. `faramir init` refuses to finish against a store under either directory, and `faramir doctor` reports one.

Keeping it out of the checkout matters for a second reason: a checkout inside an encrypted home does not exist until its owner logs in, so at boot the broker finds the file absent. It treats that as a load failure and refuses rather than coming up with an empty value set, which turns a silent gap in redaction into an outage that names itself.

`.sops.yaml` sits in the same directory, written by `faramir init` and kept as it finds it thereafter: adding or dropping a recipient means re-encrypting every managed value, which is not something a re-run should do behind your back.

```yaml
creation_rules:
  - path_regex: \.sops\.ya?ml$
    key_groups:
      - age:
          - age1... # the keeper's public key
```

The rule matches on the `.sops.yml` suffix rather than a directory, so moving a file does not silently drop it out of encryption.

Which rule applies is matched against the file's path, but **which `.sops.yaml` sops reads is resolved from the current working directory upward**, not from the file being encrypted. Encrypting into the store from a checkout finds nothing and fails with `config file not found, or has no creation rules`. Name it:

```bash
sops --config /etc/faramir/secrets/.sops.yaml \
    --encrypt --filename-override /etc/faramir/secrets/ansible-ctrl.sops.yml \
    plain.yml
```

Decryption needs none of this: creation rules govern encryption only.

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

The caller names the refs per run:

```bash
faramir run \
    --env ROUTER_PW=secret://home/router/admin \
    --env API_TOKEN=secret://api_token -- \
    ansible-playbook site.yml --limit routers
```

A command needing many credentials takes `--env-file` instead, which holds refs and never values.

Verify once:

```bash
faramir run --env ROUTER_PW=secret://home/router/admin -- \
    ansible localhost -m debug -a 'var=router_password'
# -> «SECRET:home/router/admin»
```

That proves the var resolved *and* that printing it produces a token. `ENC[AES256_GCM,...]` instead means the encrypted file is somewhere Ansible auto-loads it, per section 1.

A var whose ref was not injected resolves to an empty string, which usually surfaces as a task failing further along. When a playbook behaves as though a credential were blank, check `env_refs` first.

A `community.sops` vars plugin or `lookup('pipe', 'sops -d …')` cannot work here: both need the age key in the playbook's environment. `internal/e2e` runs `sops --decrypt` as a brokered command and asserts it fails for want of key material.

Encrypted files still need listing in `[secrets] files` so their values land in the redaction set, whether or not any playbook names them.

## 3. SSH keys

Brokered commands run as `faramir-exec`, which must *use* the keys that reach managed hosts without being able to read them: a password can be rotated, a copied fleet key cannot be un-copied.

```toml
[ssh]
keys = ["/var/lib/faramir-broker/.ssh/id_ed25519"]
```

The broker keeps the files under its own uid, loads them into an `ssh-agent` it owns, and passes the child only `SSH_AUTH_SOCK`.

- Keys must have no passphrase, since nothing is there to type one.
- `faramir-broker --check`, run as the broker's own account, fails on a key `ssh-add` would refuse: a passphrase, or `keys` naming the `.pub` by mistake. Run as root it reads what the broker cannot, so a key left `root:root` passes a root check and then fails for the broker.
- At runtime the broker logs the error and carries on, so one bad key does not stop the others loading.
- The agent lives and dies with the broker, so nothing outlives the process holding keys in memory.
- Left empty, no agent runs and authentication is whatever `~faramir-exec/.ssh` allows, readable by every brokered command. It works; it is not the arrangement to choose.

Either way the *agent* account cannot read the keys, so `ssh` problems are debugged through `faramir run` or from the audit log via the reported `log_id`.

Keep `ANSIBLE_HOST_KEY_CHECKING=True` in `[exec.base_env]`. Turning it off to make a broken host work is how a broker with credentials hands them to whatever answers.
