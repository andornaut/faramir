# Wiring Ansible to sops

Playbooks get their credentials the same way every other brokered program
does: the caller names refs, the broker injects values as environment
variables, and `group_vars` reads them.

Ansible does **not** decrypt sops itself here, and cannot. Doing so needs the
age private key, and no process the broker starts ever receives it: the keeper
holds it under its own uid and serves decrypted values only. Since a playbook
can run arbitrary tasks, a playbook holding the master key would mean anything
that can reach Ansible can obtain the key that decrypts every managed file,
retroactively, including everything already in git history.

## 1. Encrypt values, not keys

`.sops.yaml` in the repo root (written by `install/30-sops-init.sh`):

```yaml
creation_rules:
  - path_regex: (^|/)(group_vars|host_vars)/.*\.sops\.ya?ml$
    key_groups:
      - age:
          - age1... # the keeper's public key
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

## 3. Resolution: read the environment

Add a committed, **unencrypted** vars file that maps each var to the
environment variable the broker will inject. It contains no secrets, so it is
readable and reviewable like any other file:

```yaml
# group_vars/all/vars.yml
vault_router_password: "{{ lookup('env', 'ROUTER_PW') }}"
vault_api_token: "{{ lookup('env', 'API_TOKEN') }}"
```

The caller names the refs per run:

```bash
faramir run \
    --env ROUTER_PW=secret://vault_router_password \
    --env API_TOKEN=secret://home/api/token -- \
    ansible-playbook site.yml --limit routers
```

or, from the agent:

```
faramir_run(cmd=["ansible-playbook", "site.yml", "--limit", "routers"],
            env_refs={"ROUTER_PW": "secret://vault_router_password",
                      "API_TOKEN": "secret://home/api/token"})
```

Verify:

```bash
faramir run --env ROUTER_PW=secret://vault_router_password -- \
    ansible localhost -m debug -a 'var=vault_router_password'
# -> «SECRET:vault_router_password»
```

That is worth running once: it proves the var resolved *and* that printing it
produces a token rather than a value.

A var whose ref was not injected resolves to an empty string, which usually
surfaces as a task failing further along rather than as a clear error. When a
playbook behaves as though a credential were blank, check `env_refs` first.

## 4. What this replaces

Earlier versions used the `community.sops` vars plugin, or a
`lookup('pipe', 'sops -d …')`. Both need `SOPS_AGE_KEY` in the playbook's
environment, so neither works now, and both fail with a sops error about
missing key material rather than anything about faramir.

`tests/harness.py` keeps a playbook that attempts the `lookup('pipe', …)` form
and asserts it **fails**, so a change that quietly hands the key back to a
child is caught.

Encrypted files still need to be listed in `[secrets] files` so their values
land in the redaction set, whether or not any playbook names them.

## 5. Removing ansible-vault

In this order, and not before:

1. Point `[secrets] files` in `/etc/faramir/config.toml` at the new `.sops.yml`
   files, then `systemctl reload faramir-broker`.
2. Add the `lookup('env', …)` vars file from section 3 and commit it.
3. Run a real playbook end to end through `faramir run`, not `--check`, with
   the refs it needs in `--env`, and confirm it works and prints no plaintext.
4. `git rm` the old vault files.
5. Delete the vault password file.
6. **Rotate every credential that was ever committed**, or rewrite history.
   See the warning in the README: the plaintext-equivalent blobs are still in
   git history and the old vault password still opens them.

## 6. SSH keys

The broker's uid owns the SSH keys used to reach managed hosts
(`~faramir-broker/.ssh/`). The agent uid cannot read them, which is the point, so
`ssh` connection problems have to be debugged through `faramir` or from the
raw log, using the `log_id` the agent reports.

Keep `ANSIBLE_HOST_KEY_CHECKING=True` in `[exec.base_env]`. Turning it off to
make a broken host work is how a broker with credentials ends up handing them
to whatever answers.
