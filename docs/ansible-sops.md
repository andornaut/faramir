# Wiring Ansible to sops

Playbooks get their credentials the same way every other brokered program
does: the caller names refs, the broker injects values as environment
variables, and `group_vars` reads them.

Ansible does **not** decrypt sops itself, and cannot. Doing so needs the age
private key, and no process the broker starts ever receives it: the keeper
holds it under its own uid and serves decrypted values only. A playbook can run
arbitrary tasks, so a playbook holding the master key would mean anything that
can reach Ansible can obtain the key that decrypts every managed file,
retroactively, including everything already in git history.

The `[exec.base_env]` variables and sops file paths this guide assumes are in
[etc/examples/ansible-fleet.toml](../etc/examples/ansible-fleet.toml). If
`ansible-playbook` is a pipx or venv install, put its directory on the `PATH`
in `[exec.base_env]`: that is the PATH the child gets, and where the broker
looks up a bare command name.

## 1. Encrypt the right file, in the right place

The encrypted file belongs in `/etc/faramir/secrets`, which phase 1 creates
`2770 root:dev`. Not in a checkout, and never in `group_vars/` or `host_vars/`.

Ansible loads every `.yml` under those two directories as a vars file, and a
sops file is valid YAML: it binds each var to its `ENC[AES256_GCM,...]`
ciphertext, and a name sorting after `vars.yml` also overwrites the
`lookup('env', …)` mapping from section 2. Nothing errors. Hosts get configured
with the ciphertext of a credential in place of the credential.
`install/migrate-vault.sh` refuses that destination.

Keeping it out of the checkout entirely matters for a different reason: a
checkout inside an encrypted home does not exist until its owner logs in, so
the broker would come up at boot with an empty value set and redact nothing,
and a cron job would find nothing at all.

`.sops.yaml` sits in the same directory, written by
`install/20-sops-init.sh`:

```yaml
creation_rules:
  - path_regex: \.sops\.ya?ml$
    key_groups:
      - age:
          - age1... # the keeper's public key
```

The rule matches on the `.sops.yml` suffix rather than on a directory, so
moving a file does not silently drop it out of encryption.

Which rule applies is matched against the file's path, but **which `.sops.yaml`
sops reads is resolved from the current working directory upward**, not from the
file being encrypted. Encrypting into the store from an Ansible checkout
therefore finds nothing and fails with `config file not found, or has no
creation rules`. Name it outright:

```bash
sops --config /etc/faramir/secrets/.sops.yaml \
    --encrypt --filename-override /etc/faramir/secrets/ansible-ctrl.sops.yml \
    plain.yml
```

`install/migrate-vault.sh` passes `--config` for you. Decryption needs none of
this: creation rules govern encryption only.

Key *names* stay readable, so diffs are per-key and reviewable and the agent
can see the shape of the file without seeing any value. `faramir_list_secrets`
shows the same names. Nesting maps to `/` in a ref:

```yaml
home:
  router:
    admin: …        # secret://home/router/admin
api_token: …        # secret://api_token
```

## 2. Resolution: read the environment

Add a committed, **unencrypted** vars file mapping each var to the environment
variable the broker will inject. It contains no secrets, so it is readable and
reviewable like any other file:

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

or, from the agent:

```
faramir_run(cmd=["ansible-playbook", "site.yml", "--limit", "routers"],
            env_refs={"ROUTER_PW": "secret://home/router/admin",
                      "API_TOKEN": "secret://api_token"})
```

A command needing many credentials takes `--env-file` instead, which holds refs
and never values and belongs beside the playbook it serves.

Verify:

```bash
faramir run --env ROUTER_PW=secret://home/router/admin -- \
    ansible localhost -m debug -a 'var=router_password'
# -> «SECRET:home/router/admin»
```

That is worth running once: it proves the var resolved *and* that printing it
produces a token rather than a value. Anything else is a fault.
`ENC[AES256_GCM,...]` in particular means the encrypted file is somewhere
Ansible auto-loads it, per section 1.

A var whose ref was not injected resolves to an empty string, which usually
surfaces as a task failing further along rather than as a clear error. When a
playbook behaves as though a credential were blank, check `env_refs` first.

A `community.sops` vars plugin or a `lookup('pipe', 'sops -d …')` cannot work
here: both need `SOPS_AGE_KEY` in the playbook's environment, and both fail
with a sops error about missing key material rather than anything naming
faramir. `internal/e2e` runs `sops --decrypt` as a brokered command and asserts
it fails for want of key material, so a change that quietly hands the key back
to a child is caught.

Encrypted files still need to be listed in `[secrets] files` so their values
land in the redaction set, whether or not any playbook names them.

## 3. SSH keys

Brokered commands run as `faramir-exec`, which must be able to *use* the keys
that reach managed hosts without being able to read them: a password can be
rotated, a fleet SSH key that has been copied cannot be un-copied.

List them in `[ssh] keys` and the broker keeps the files under its own uid,
loads them into an `ssh-agent` it owns, and passes the child only
`SSH_AUTH_SOCK`:

```toml
[ssh]
keys = ["/var/lib/faramir-broker/.ssh/id_ed25519"]
```

The keys must have no passphrase, since nothing is there to type one.
`faramir-broker --check`, run as the broker's own account, parses each
configured key and fails on one `ssh-add` would refuse, so a passphrase (or
`[ssh] keys` naming the `.pub` by mistake) is caught at install time rather
than as a fleet-wide authentication failure. It reads the file as the uid that
runs it, so a key left `root:root` passes a root-run check and then fails for
the broker. At runtime the broker logs the error and carries on, since one bad
key should not stop the others loading. The agent lives and dies with the
broker, so nothing outlives the process with keys in memory.

Leave `keys` empty and no agent runs. Authentication is then whatever the
executor's own uid can do, which in practice means keys in
`~faramir-exec/.ssh`, readable by every brokered command. It works; it is not
the arrangement to choose.

Either way the *agent* account cannot read the keys, which is the point, so
`ssh` connection problems have to be debugged through `faramir run` or from the
audit log, using the `log_id` the agent reports.

Keep `ANSIBLE_HOST_KEY_CHECKING=True` in `[exec.base_env]`. Turning it off to
make a broken host work is how a broker with credentials ends up handing them
to whatever answers.
