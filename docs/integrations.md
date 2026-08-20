# Integrating a tool

Every program gets its credentials the same way: the caller names refs, the broker injects values as environment variables, and the program reads them. What differs between tools is only where the value comes from and how the program is told to look at the environment.

Two things hold for all of them:

- **Nothing decrypts sops but the keeper.** That needs the age private key, and no process the broker starts receives it: a brokered command runs arbitrary code, so one holding the master key means anything that can reach it obtains the key to every managed file, retroactively. A vars plugin, a `lookup('pipe', 'sops -d …')` or any tool's own sops support fails for this reason, and the end-to-end suites assert it.
- **A brokered command inherits nothing from the broker.** A variable the program needs, `ANSIBLE_CONFIG` and friends among them, has to be set with `faramir init --command-env NAME=VALUE` or it is absent.

## Where the value lives

Two places, and the choice is not about the tool:

Case | Where | Why
--- | --- | ---
You own the credential | The managed store, `sudo faramir vault add NAME` | faramir encrypts it and owns its rotation
Another tool already owns the file | A `[[secret.link]]` entry, `sudo faramir link add` | The file stays where that tool expects it, so rotating stays that tool's business and nothing here goes stale
No command needs the value; the agent must simply not read it | A `[[secret.refuse]]` entry, `sudo faramir refuse add` | A LUKS keyfile or an SSH identity. The path is refused and never opened, so it is also never redacted: [what that costs](configuration.md#refused-paths)
Neither, you only want output scrubbed | Nothing | `faramir redact -- ./script.sh`, or use it as a filter

## Onboarding, in three steps

1. **Put the value where the broker can reach it**, by the table above.
2. **Have the program read an environment variable** rather than a file or a vault of its own. Most tools already work this way.
3. **Name the refs per run**, or write them once into a file:

```bash
faramir run --env TOKEN=faramir://svc/token -- ./deploy.sh
faramir run --env-file faramir.env -- ansible-playbook site.yml
```

The file takes two forms per line, and they mix. A name on its own asks for the ref of that name, which is what a credential named after the variable that carries it needs; the mapping form is for the rest.

```text
# faramir.env
msmtp_password                          # -> faramir://msmtp_password
deploy_token                            # -> faramir://deploy_token
ROUTER_PW=faramir://home/router/admin   # a ref named something else
```

`#` starts a comment, at the start of a line or after whitespace. The space is what makes the cut safe: `faramir://api#token` is a ref written wrong, so it stays whole and is refused, rather than being cut to `faramir://api`, which may be a ref that exists and holds another credential.

Name a credential after its variable and the file is a list of what a run needs, said once. It holds refs and never values either way, and a bare line is held to the same rule as a mapped one, so anything that cannot be an environment variable name is refused with the file and the line rather than becoming a ref nothing serves.

Only step 2 really varies:

What you are running | Step 2
--- | ---
A deploy or release script | Already reads `$TOKEN`. Nothing to change
A cloud or infra CLI (`aws`, `terraform`, `flyctl`) | Name its documented environment variables; drop the credentials file
A database task | `PGPASSWORD`, `MYSQL_PWD`. The connection string goes in `argv`, the password never does
A registry push | `bash -lc 'printf %s "$TOKEN" \| docker login -u me --password-stdin'`
An HTTP call | `curl -H "Authorization: Bearer $TOKEN"` inside `bash -lc`, so the shell expands it
A tool needing a credentials *file* | Have the command write it, use it, remove it. Injection is environment-only
Ansible | `lookup('env', 'NAME')` in a committed vars file, or a vars plugin reading `faramir.env`. [Worked example below](#worked-example-ansible)
Something over SSH | Nothing for the value: `init` renders `[ssh] key` and the child gets `SSH_AUTH_SOCK`. [Below](#ssh-keys-and-host-verification)

- A pipeline is requested explicitly as `["bash", "-lc", "…"]`; the broker never hands a string to a shell.
- A bare command name is looked up on `[command.env] PATH`. Venv, pipx and shim directories belong there.
- A tool that decrypts sops itself does not onboard. It gets named values instead.
- `cd <project> && sudo faramir init-project` last, which shares the tree so a brokered command can run in it and configures whichever agents it already carries.

## Linking a credential another tool owns

`link add` reads the file as root to check that the type and the selector yield a value, then grants the broker read on it, then reads it again as the broker's own account to check that the grant landed, and only then writes the entry and reloads. The value joins the redactor, and the path is refused to the agent's file tools.

The two reads answer different questions and are in that order for a reason. Root can read what the broker cannot, so the first says the content is ingestible and the second says the broker can reach it. Asking the content first means a wrong `--type` or a `--key` naming nothing costs nothing: the file's mode and group, and the directories above it, are untouched. A selector that names nothing fails the command and lists the selectors the file does offer, names only.

```bash
sudo faramir link add gh/token ~/.config/gh/hosts.yml --type yaml --key github.com/oauth_token
```

Tool | File | `--type` | `--key`
--- | --- | --- | ---
`gh` | `~/.config/gh/hosts.yml` | `yaml` | `github.com/oauth_token`
npm | `~/.npmrc` | `ini` | `//registry.npmjs.org/:_authToken`
AWS | `~/.aws/credentials` | `ini` | `default/aws_secret_access_key`
kubeconfig | `~/.kube/config` | `yaml` | `users/0/user/token`
A container registry | `~/.docker/config.json` | `json` | `auths/ghcr.io/auth`
Cargo | `~/.cargo/credentials.toml` | `toml` | `registry/token`
A keyfile or single-line token | any | `text` | none
A file that is not text | any | `base64` | none

Each row is where that tool puts a credential it keeps in a file, and several of them no longer do. `gh` writes to the login keyring where one is available, leaving `hosts.yml` holding `git_protocol` and the account name; `docker login` writes to the keyring wherever `credsStore` is set, leaving `auths.<registry>` an empty object. A link reads files, so there is nothing to link in either case, and `link add` says so by listing what the file does offer. `gh auth status` names its store, and `jq -r '.credsStore' ~/.docker/config.json` names docker's.

`json`, `yaml` and `toml` walk the selector by `/` and index a list by number, which is what `users/0/user/token` is doing. `ini` matches the whole key, or `section/key` where the file has sections, which is why npm's sectionless `//registry...` key is given whole.

**A key that holds a slash is escaped**, `/` as `\/` and a literal backslash as `\\`. Docker Hub's own entry is keyed by URL, so it is named like this:

```bash
sudo faramir link add hub/auth ~/.docker/config.json --type json \
    --key 'auths/https:\/\/index.docker.io\/v1\//auth'
```

A selector that names nothing is refused by `link add` rather than at the next command, and the refusal lists what the file does offer, spelled the way a selector reads, so it can be copied back into `--key`.

**`ini` is the exception: it matches a key whole and escapes nothing**, which is what lets npm's key be given as it is written. The format has two levels, so there is no path to walk. The cost is that a slash in a section or a key can make two entries read alike:

```ini
a/b/c = one          # these three compose to the
[a]                  # same selector, "a/b/c"
b/c   = two
[a/b]
c     = three
```

That is refused, naming all of them, rather than answered with whichever came first: choosing would be choosing which credential to inject, and the ones not chosen are then absent from the redactor and come back in the clear if anything prints them. Rename a section, or link the file as `text`. A file holding the *same* key twice is a different thing and keeps INI's own answer, the first one.

The alternative, should this come up in practice, is to escape `ini` like the others and accept npm's key becoming `\/\/registry.npmjs.org\/:_authToken`.

**A linked file is bounded at 1 MiB.** A link pointed at something larger fails rather than reading it into the value set, a credential file being small.

**Link what the agent can already read.** Pointed at a file the agent cannot read, a link makes that value obtainable through `env_refs` and closes no disclosure path in exchange, so a root-owned keyfile belongs outside the store. [Why](design.md#linked-secrets-are-read-by-the-broker).

What an entry looks like and what a lost grant costs is in [configuration.md](configuration.md#linked-secrets).

## SSH keys and host verification

Brokered commands run as `faramir-exec`, which must *use* the key that reaches managed hosts without being able to read it: a password can be rotated, a copied fleet key cannot be un-copied.

`faramir init` mints one beside the age key and renders `[ssh] key` itself. Put the public half it prints into `authorized_keys` on each managed host. The broker keeps both halves under its own uid, loads the private one into an `ssh-agent` it owns, and passes the child only `SSH_AUTH_SOCK`.

- The `ssh-agent` lives and dies with the broker, so nothing outlives the process holding the key in memory.
- A key it cannot load is logged rather than fatal: `--check` and `doctor` name it, and only commands that reach a host fail, with ssh's own error.
- The executor's account cannot read the key, so `ssh` problems are debugged through `faramir run` or from the audit log via the reported `log_id`.

Two settings that are not defaults:

Setting | Why
--- | ---
`faramir init --command-env ANSIBLE_HOST_KEY_CHECKING=True` | Host key checking, for Ansible. Not in the shipped `[command.env]`, and with it off a broker holding credentials offers them to whatever answers on that address
`faramir init --known-hosts ~/.ssh/known_hosts` | `faramir-exec` has its own `known_hosts` and it starts absent, so a play whose hosts are trusted only in the operator's file fails verification before the key above is offered

`faramir doctor` reports how many host keys the executor can verify against. Both flags are in [installing.md](installing.md#what-each-flag-sets). Which login a bare `ssh host` asks for, which files it verifies against, and how to pin host keys across a fleet are in [operating.md](operating.md#rules-a-command-does-not-state).

## Worked example: Ansible

Ansible is the one integration that needs more than a variable name, because a playbook also configures the controller it runs on.

```text
/etc/faramir/secrets/ansible-ctrl.sops.yml   the values, outside every checkout
faramir.env                                  NAME=faramir://ref, one per line,
                                             or a bare NAME for the ref of that name
group_vars/all/vars.yml                      committed: var -> lookup('env', 'NAME'),
                                             or a vars plugin reading faramir.env instead
```

### Where the encrypted file goes

The secrets directory, `/etc/faramir/secrets` unless `--config-dir` moved it. The operator is not in the group that owns it, so writing and editing both go through `sudo faramir vault add` and `sudo faramir vault edit`.

Place | What happens
--- | ---
A checkout | Absent at boot if it sits in an encrypted home
`group_vars/` or `host_vars/` | Ansible loads every `.yml` under those as a vars file. A sops file is valid YAML, so each var binds to its `ENC[AES256_GCM,...]` ciphertext, and a name sorting after `vars.yml` also overwrites the mapping below. Nothing errors; hosts get configured with ciphertext in place of the credential. `faramir init` refuses to finish when a managed file sits under either, naming it and where to move it

Key *names* stay readable, so diffs are per-key and the agent sees the file's shape without any value. Nesting maps to `/` in a ref:

```yaml
home:
  router:
    admin: …        # faramir://home/router/admin
api_token: …        # faramir://api_token
```

**Do not encrypt one by hand.** It succeeds, and produces a file the broker never reads if the name is wrong, which nothing reports until somebody goes looking for the ref. `vault add` cannot make that mistake, and it passes sops `--config` and `--filename-override`, needed because **which `.sops.yaml` sops reads is resolved from the working directory upward**: encrypting into the secrets directory from a checkout otherwise fails with `config file not found, or has no creation rules`.

### Reading the environment

Two ways to turn an injected environment variable into an Ansible variable. Neither holds a secret; they differ in how many lists have to agree.

Approach | Costs | Buys
--- | --- | ---
A committed lookup file | Every credential named a second time, in a file that must agree with `faramir.env` | No code, and every credential visible in the repo
A vars plugin | About twenty lines of Python, and `faramir.env` becomes required for every route rather than only the brokered one | One list, and no mapping at all where a role already reads a variable of that name

#### A committed lookup file

A committed, **unencrypted** vars file maps each var to the environment variable the broker will inject. It holds no secrets:

```yaml
# group_vars/all/vars.yml
router_password: "{{ lookup('env', 'ROUTER_PW') }}"
api_token: "{{ lookup('env', 'API_TOKEN') }}"
```

#### A vars plugin

The plugin reads `faramir.env` for its names and exposes each as a variable of that name, so the lookup file above is not written at all:

```python
# vars_plugins/faramir_env.py, enabled by name in ansible.cfg
class VarsModule(BaseVarsPlugin):
    def get_vars(self, loader, path, entities, cache=True):
        super().get_vars(loader, path, entities)
        return {name: os.environ[name]
                for name in declared_names(loader.get_basedir())
                if os.environ.get(name)}
```

`declared_names` takes the left of each `NAME=faramir://ref` line, and the whole of a line that is only a name. Only the names: a ref is not a value, and the file holds none.

Name a credential after the variable that carries it and the file needs neither half twice:

```text
msmtp_password
deploy_token
```

Name a credential for what it is (`msmtp_password`), and where a role already reads a variable of that name it needs no mapping. Where the destination is named something else, or where one host draws two values from the same store, `host_vars/` keeps a line and that line is the routing:

```yaml
app_sensor_password: "{{ sensor_password_west }}"
```

Two things to know before choosing it. `vars_plugins_enabled` in `ansible.cfg` **replaces** the default list rather than adding to it, so it must keep naming `host_group_vars` or `host_vars/` stops loading. And a store key the env file does not name becomes invisible to Ansible, which is the same statement as one list saying what a run needs.

A missing or unreadable env file should yield no names rather than an error: every credential is then undefined and the first task to read one fails naming it, which is what a run nobody injected anything into should do, and what an ad-hoc command against a host needing no credential wants.

#### Running it, either way

```bash
faramir run \
    --env ROUTER_PW=faramir://home/router/admin \
    --env API_TOKEN=faramir://api_token -- \
    ansible-playbook site.yml --limit routers
```

Verify once, which proves the var resolved *and* that printing it produces a token. The variable is whatever the approach above named it: the lookup file's own name, or the ref's:

```bash
faramir run --env ROUTER_PW=faramir://home/router/admin -- \
    ansible localhost -m debug -a 'var=router_password'
# -> «SECRET:home/router/admin»
```

Symptom | Cause
--- | ---
`ENC[AES256_GCM,...]` | The encrypted file is somewhere Ansible auto-loads it, per the table above
An empty string, usually a task failing further along | The ref was not injected. Check `env_refs` first when a playbook behaves as though a credential were blank
`undefined variable`, with the name | Either approach, working as intended: nothing was injected, or the lookup file and `faramir.env` disagree, or the plugin's env file does not name that key

### Becoming root on the controller

`become` on a *managed* host is the operator's own arrangement: the account Ansible connects as has passwordless sudo there, and faramir has no part in it.

The controller is different, and by default it has to be left out, a brokered command running as `faramir-exec`, which has no sudo:

```bash
faramir run --env-file faramir.env -- ansible-playbook msmtp.yml --limit '!controller'
```

A playbook that touches every host then splits in two: the fleet through the broker, the controller as root some other way. `sudo faramir init --allow-sudo` closes that: a brokered command's `sudo` puts a question to a human, answered per run by `sudo faramir approve ID`, with no password anywhere. How to run it is [escalation.md](escalation.md); the reasoning is [design.md](design.md#allowing-sudo-on-the-controller).

The Ansible side is one variable, on the controller host only:

```yaml
# host_vars/controller.yml
ansible_become_flags: '-H'
```

Dropping the default `-n` is the whole of it: `-n` tells `sudo` to fail rather than authenticate, and it does so before the PAM stack runs, so the question is never put and every task fails with `sudo: a password is required` even when a human is watching. Nothing here prompts, so there is no `SUDO_ASKPASS` and no `-A`. `-H` sets `HOME` to root's, which is what `become` normally does for you.

Nothing else changes: no `--ask-become-pass`, no vault, and no become password in a var, there being no become password. Leave a watcher running as root, in a terminal the coding agent cannot type into, and the first task that runs sudo puts its question there naming the playbook:

```bash
sudo faramir escalations --watch
```

One approval covers the whole playbook run rather than one task. [What it does and does not bound](escalation.md#one-question-per-run-and-what-to-expect), including which other commands are refused meanwhile.
