# Wiring Ansible to sops

Phase 2 of the migration: playbooks resolve their vars from sops at run time,
natively, with no decrypt step and no plaintext on disk.

## 1. Encrypt values, not keys

`.sops.yaml` in the repo root (written by `install/30-sops-init.sh`):

```yaml
creation_rules:
  - path_regex: (^|/)(group_vars|host_vars)/.*\.sops\.ya?ml$
    key_groups:
      - age:
          - age1... # the broker's public key
```

Keeping key *names* readable means diffs stay per-key and reviewable, and the
agent can see the shape of the file without seeing any value. The broker's
`faramir_list_secrets` shows the same names.

## 2. Keep var names unchanged

`install/migrate-vault.sh` preserves the YAML structure exactly, so a var that
was `vault_router_password` under ansible-vault stays `vault_router_password`.
Playbooks need no change beyond the lookup mechanism.

Reference them from the broker as `secret://` paths, where nesting maps to `/`:

```yaml
home:
  router:
    admin: …        # secret://home/router/admin
vault_router_password: …   # secret://vault_router_password
```

## 3. Native resolution: community.sops

Install the collection **on the broker host**, as the broker's uid can reach it:

```bash
ansible-galaxy collection install community.sops
```

`ansible.cfg` in `/srv/ansible-ctrl`:

```ini
[defaults]
vars_plugins_enabled = host_group_vars,community.sops.sops

[community.sops]
# sops finds the key through SOPS_AGE_KEY, which the broker injects for
# ansible and ansible-playbook only (provide_age_key = true).
```

Now `group_vars/all/vault.sops.yml` is loaded like any other group_vars file,
decrypted in memory by the vars plugin. Nothing changes in the playbooks.

Verify:

```bash
faramir run -- ansible-playbook site.yml --check
faramir run -- ansible localhost -m debug -a 'var=vault_router_password'
# -> «SECRET:vault_router_password»
```

That second command is worth running once: it proves the var resolved *and*
that printing it produces a token.

## 4. If you cannot install the collection

A `lookup('pipe', …)` works with no collection at all, at the cost of one
subprocess per lookup and a less pleasant syntax:

```yaml
vars:
  vault: "{{ lookup('pipe', 'sops --output-type json -d group_vars/all/vault.sops.yml') | from_json }}"
```

This is what `tests/harness.py` uses, so the end-to-end suite runs without
network access to Galaxy. Prefer the vars plugin in production.

## 5. Removing ansible-vault

In this order, and not before:

1. Point `[secrets] files` in `/etc/faramir/config.toml` at the new `.sops.yml`
   files, then `systemctl reload faramir-broker`.
2. Run a real playbook end to end through `faramir` — not `--check` — and
   confirm it works and prints no plaintext.
3. `git rm` the old vault files.
4. Delete the vault password file.
5. **Rotate every credential that was ever committed**, or rewrite history.
   See the warning in the README: the plaintext-equivalent blobs are still in
   git history and the old vault password still opens them.

## 6. SSH keys

The broker's uid owns the SSH keys used to reach managed hosts
(`~faramir-broker/.ssh/`). The agent uid cannot read them — that is the point — so
`ssh` connection problems have to be debugged through `faramir` or from the
raw log, using the `log_id` the agent reports.

Keep `ANSIBLE_HOST_KEY_CHECKING=True` in `[exec.base_env]`. Turning it off to
make a broken host work is how a broker with credentials ends up handing them
to whatever answers.
