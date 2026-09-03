# Integrating a tool

Every program gets its credentials the same way: the caller names refs, the broker injects the values as environment variables, and the program reads them. Tools differ only in where the value comes from and in how the program is told to read the environment.

Two rules apply to every tool:

- **Only the keeper decrypts sops.** Decrypting needs the age private key, and no process the broker starts receives it. A brokered command runs arbitrary code, so a command that held the master key could decrypt every managed file. A vars plugin, a `lookup('pipe', 'sops -d …')` or a tool's own sops support fails for this reason.
- **A brokered command inherits nothing from the broker's environment.** A variable the program needs, such as `ANSIBLE_CONFIG`, must be set with `sudo faramir init --command-env NAME=VALUE`. Otherwise it is absent.

## Where the value lives

The choice depends on who owns the credential, not on the tool:

Case | Where | Why
--- | --- | ---
You own the credential | The managed store: `sudo faramir vault add NAME` | faramir encrypts it and owns its rotation
Another tool already owns the file | A `[[secret.link]]` entry: `sudo faramir link add` | The file stays where that tool expects it, so that tool still rotates it and nothing goes stale
No command needs the value; the agent must only not read it | A `[[secret.block]]` entry: `sudo faramir block add` | For a LUKS keyfile or an SSH identity. The path is refused and never opened, so it is never redacted either: [what that costs](configuration.md#blocked-paths)
A credential inside a container | An entry naming the path the agent uses | The agent names the container's mount point, so declare that path. A rule naming the host path covers nothing the agent runs
Neither; you only want output scrubbed | Nothing | `faramir redact -- ./script.sh`, or use `faramir redact` as a filter

## Onboarding, in three steps

1. **Put the value where the broker can reach it**, per the table above.
2. **Have the program read an environment variable**, not a file or a vault of its own. Most tools already do.
3. **Name the refs on each run**, or write them once into a file:

```bash
faramir run --env TOKEN=faramir://svc/token -- ./deploy.sh
faramir run --env-file faramir.env -- ansible-playbook site.yml
```

A line in the file takes one of two forms, and the forms mix. A bare name asks for the ref of that name. The mapping form is for a ref named something else.

```text
# faramir.env
msmtp_password                          # -> faramir://msmtp_password
deploy_token                            # -> faramir://deploy_token
ROUTER_PW=faramir://home/router/admin   # a ref named something else
```

`#` starts a comment at the start of a line or after whitespace. The whitespace requirement matters: `faramir://api#token` is a malformed ref and stays whole so it is refused, rather than being cut to `faramir://api`, which may be a ref that exists and holds another credential.

Name a credential after its variable and the file is the list of what a run needs. The file holds refs and never values. A bare line follows the same rule as a mapped one: a name that cannot be an environment variable is refused, with the file and line, rather than becoming a ref nothing serves.

Only step 2 varies by tool:

What you are running | Step 2
--- | ---
A deploy or release script | Already reads `$TOKEN`. Nothing to change
A cloud or infra CLI (`aws`, `terraform`, `flyctl`) | Use its documented environment variables and drop the credentials file
A database task | `PGPASSWORD`, `MYSQL_PWD`. The connection string goes in `argv`; the password never does
A registry push | `bash -lc 'printf %s "$TOKEN" \| docker login -u me --password-stdin'`
An HTTP call | `bash -lc 'printf "header = \"Authorization: Bearer $TOKEN\"" \| curl -K - https://…'`. The header goes to curl on stdin: on the command line it would be in the process list
A tool that needs a credentials *file* | Have the command write the file, use it, and remove it. Injection is environment-only
Ansible | `lookup('env', 'NAME')` in a committed vars file, or a vars plugin that reads `faramir.env`. [Worked example below](#worked-example-ansible)
Something over SSH | Nothing for the value: `init` renders `[ssh] key` and the child gets `SSH_AUTH_SOCK`. [Below](#ssh-keys-and-host-verification)

- Request a pipeline explicitly as `["bash", "-lc", "…"]`. The broker never hands a string to a shell.
- A bare command name is looked up on `[command.env] PATH`. Add venv, pipx and shim directories there.
- A tool that decrypts sops itself cannot be onboarded. Give it named values instead.
- Finish with `cd <tree> && sudo faramir enrol`. It shares the tree so a brokered command can run in it, and configures the agents it detects (Codex from your home).

## Linking a credential another tool owns

`link add` checks everything before it writes anything, and changes nothing about the file to make a check pass: [the order of checks](configuration.md#link-add-asks-everything-before-it-writes). It leaves behind the entry, the value in the redactor, and a rule refusing the path to the agent's file tools.

Adding an entry the install already carries applies it again rather than refusing it, so a converge can name every link on every run: [what a re-add re-applies](configuration.md#linked-secrets).

**A dotfile that is a symlink is covered at both names.** Several of the files below are commonly symlinks into a dotfiles checkout. The entry has to name the target, that being the file whose group is changed and the file the broker is granted, so `link add` resolves the path and blocks the spelling you typed instead of refusing it. Both names are then refused, and `link rm` takes both unless another entry still names the target.

The file is read twice, and the order matters. The first read runs as root and confirms the content can be parsed: a wrong `--type` or a `--key` that names nothing fails here, before anyone is asked to change a file mode. The second read runs as the broker's own account and confirms that account can reach the value. A selector that names nothing fails the command and lists the selectors the file does offer, names only.

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

Each row is where that tool keeps a credential when it keeps one in a file. Some of these tools now use the login keyring instead. `gh` writes to the keyring where one is available, leaving `hosts.yml` with only `git_protocol` and the account name. `docker login` writes to the keyring wherever `credsStore` is set, leaving `auths.<registry>` an empty object. A link reads files, so in either case there is nothing to link, and `link add` says so by listing what the file does offer. `gh auth status` names its store; `jq -r '.credsStore' ~/.docker/config.json` names docker's.

`json`, `yaml` and `toml` walk the selector by `/` and index a list by number, as in `users/0/user/token`. `ini` matches the whole key, or `section/key` where the file has sections, so npm's sectionless `//registry...` key is given whole.

**A slash inside a key is escaped**: `/` as `\/` and a literal backslash as `\\`. Docker Hub's entry is keyed by URL, so it is named like this:

```bash
sudo faramir link add hub/auth ~/.docker/config.json --type json \
    --key 'auths/https:\/\/index.docker.io\/v1\//auth'
```

A selector that names nothing is refused by `link add`, not by a later command. The refusal lists what the file does offer, spelled the way a selector reads, so it can be copied back into `--key`.

**`ini` is the exception: it matches a key whole and escapes nothing.** That is what lets npm's key be given as written. The format has two levels, so there is no path to walk. The cost is that a slash in a section or key name can make two entries read alike:

```ini
a/b/c = one          # these three compose to the
[a]                  # same selector, "a/b/c"
b/c   = two
[a/b]
c     = three
```

That is refused, naming all of them. Picking one would pick which credential to inject, and the others would be absent from the redactor and printed in the clear. Rename a section, or link the file as `text`. A file holding the *same* key twice is a different case: INI's own rule applies, and the first one wins.

The alternative, if this comes up in practice, is to escape `ini` like the other types. npm's key would then become `\/\/registry.npmjs.org\/:_authToken`.

**A linked file is limited to 1 MiB.** A link to a larger file fails rather than reading it into the value set. Credential files are small.

**Link only what the agent can already read.** A link to a file the agent cannot read makes that value obtainable through `env_refs` and closes no disclosure path in return. A root-owned keyfile belongs outside the store. [Why](design.md#linked-secrets-are-read-by-the-broker).

What an entry looks like, and what a lost grant costs: [configuration.md](configuration.md#linked-secrets).

## SSH keys and host verification

Brokered commands run as `faramir-exec`. That account must be able to *use* the key that reaches managed hosts without being able to read it: a password can be rotated, but a copied fleet key cannot be un-copied.

`faramir init` mints a key beside the age key and renders `[ssh] key`. Put the public half it prints into `authorized_keys` on each managed host. The broker keeps both halves under its own uid, loads the private half into an `ssh-agent` it owns, and passes the child only `SSH_AUTH_SOCK`.

- The `ssh-agent` starts and stops with the broker, so nothing outlives the process holding the key in memory.
- A key the broker cannot load is logged, not fatal. `--check` and `doctor` report it, and only commands that reach a host fail, with ssh's own error.
- The executor's account cannot read the key, so debug `ssh` problems through `faramir run`, or from the audit log using the reported `log_id`.

Two settings that are off by default:

Setting | Why
--- | ---
`sudo faramir init --command-env ANSIBLE_HOST_KEY_CHECKING=True` | Host key checking for Ansible. Not in the shipped `[command.env]`. With it off, a broker holding credentials offers them to whatever answers on that address
`sudo faramir init --known-hosts ~/.ssh/known_hosts` | `faramir-exec` has its own `known_hosts`, and it starts empty. A play whose hosts are trusted only in the operator's file fails verification before the key is offered

`faramir doctor` reports how many host keys the executor can verify against. Both flags: [installing.md](installing.md#what-each-flag-sets). Which login a bare `ssh host` uses, which files it verifies against, and how to pin host keys across a fleet: [operating.md](operating.md#rules-a-command-does-not-state).

## Worked example: Ansible

Ansible needs more than a variable name, because a playbook also configures the controller it runs on. [ansible-ctrl](https://github.com/andornaut/ansible-ctrl) is a fleet run this way, with a working copy of each piece below: the [role that installs a host](https://github.com/andornaut/ansible-ctrl/tree/main/roles/faramir) and the [vars plugin](https://github.com/andornaut/ansible-ctrl/blob/main/vars_plugins/faramir_env.py).

```text
/etc/faramir/secrets/ansible.sops.yml        the values, outside every checkout
faramir.env                                  NAME=faramir://ref, one per line,
                                             or a bare NAME for the ref of that name
group_vars/all/vars.yml                      committed: var -> lookup('env', 'NAME'),
                                             or a vars plugin reading faramir.env instead
```

### Where the encrypted file goes

The secrets directory: `/etc/faramir/secrets`, unless `--config-dir` moved it. The operator is not in the group that owns it, so write and edit with `sudo faramir vault add` and `sudo faramir vault edit`.

Place | What happens
--- | ---
A checkout | Absent at boot if the checkout is in an encrypted home
`group_vars/` or `host_vars/` | Ansible loads every `.yml` under these as a vars file. A sops file is valid YAML, so each var binds to its `ENC[AES256_GCM,...]` ciphertext, and a file name that sorts after `vars.yml` also overrides the mapping below. Nothing errors: hosts are configured with ciphertext in place of the credential. `faramir init` refuses to finish when a managed file is under either directory, and names the file and where to move it

Key *names* stay readable, so diffs are per key and the agent sees the file's shape without any value. Nesting maps to `/` in a ref:

```yaml
home:
  router:
    admin: …        # faramir://home/router/admin
api_token: …        # faramir://api_token
```

**Do not encrypt a file by hand.** It succeeds, and if the name is wrong it produces a file the broker never reads, which nothing reports until someone looks for the ref. `vault add` cannot make that mistake. It also passes sops `--config` and `--filename-override`, which are needed because **sops resolves which `.sops.yaml` to read from the working directory upward**: encrypting into the secrets directory from a checkout otherwise fails with `config file not found, or has no creation rules`.

### Reading the environment

There are two ways to turn an injected environment variable into an Ansible variable. Neither holds a secret. They differ in how many lists have to agree.

Approach | Costs | Buys
--- | --- | ---
A committed lookup file | Every credential named a second time, in a file that must agree with `faramir.env` | No code, and every credential visible in the repo
A vars plugin | About twenty lines of Python, and `faramir.env` becomes required for every route, not only the brokered one | One list, and no mapping where a role already reads a variable of that name

#### A committed lookup file

A committed, **unencrypted** vars file maps each var to the environment variable the broker injects. It holds no secrets:

```yaml
# group_vars/all/vars.yml
router_password: "{{ lookup('env', 'ROUTER_PW') }}"
api_token: "{{ lookup('env', 'API_TOKEN') }}"
```

#### A vars plugin

The plugin reads the names in `faramir.env` and exposes each as a variable of that name, so the lookup file above is not needed. Abridged here; the full plugin, `declared_names` included, is [in ansible-ctrl](https://github.com/andornaut/ansible-ctrl/blob/main/vars_plugins/faramir_env.py):

```python
# vars_plugins/faramir_env.py, enabled by name in ansible.cfg
class VarsModule(BaseVarsPlugin):
    def get_vars(self, loader, path, entities, cache=True):
        super().get_vars(loader, path, entities)
        return {name: os.environ[name]
                for name in declared_names(loader.get_basedir())
                if os.environ.get(name)}
```

`declared_names` takes the left side of each `NAME=faramir://ref` line, and the whole of a bare-name line. Only the names: a ref is not a value, and the file holds none.

Name a credential for what it is (`msmtp_password`). Where a role already reads a variable of that name, no mapping is needed. Where the destination is named differently, or one host draws two values from the same store, `host_vars/` keeps one line per mapping:

```yaml
app_sensor_password: "{{ sensor_password_west }}"
```

Two things to know before choosing the plugin. `vars_plugins_enabled` in `ansible.cfg` **replaces** the default list rather than adding to it, so it must keep naming `host_group_vars` or `host_vars/` stops loading. And a store key that `faramir.env` does not name is invisible to Ansible. That is the cost of one list saying what a run needs.

Have a missing or unreadable env file yield no names rather than an error. Every credential is then undefined, and the first task to read one fails and names it. That is the right failure for a run nothing was injected into, and an ad-hoc command against a host that needs no credential keeps working.

#### Running it, either way

```bash
faramir run \
    --env ROUTER_PW=faramir://home/router/admin \
    --env API_TOKEN=faramir://api_token -- \
    ansible-playbook site.yml --limit routers
```

Verify once. This proves the var resolved *and* that printing it produces a token. The variable name is whatever the chosen approach named it: the lookup file's name, or the ref's:

```bash
faramir run --env ROUTER_PW=faramir://home/router/admin -- \
    ansible localhost -m debug -a 'var=router_password'
# -> «SECRET:home/router/admin»
```

Symptom | Cause
--- | ---
`ENC[AES256_GCM,...]` | The encrypted file is somewhere Ansible auto-loads it, per the table above
An empty string, usually a task failing further along | The ref was not injected. Check `env_refs` first when a playbook behaves as if a credential were blank
`undefined variable`, with the name | Working as intended under either approach: nothing was injected, or the lookup file and `faramir.env` disagree, or the plugin's env file does not name that key

### Becoming root on the controller

`become` on a *managed* host is the operator's own arrangement: the account Ansible connects as has passwordless sudo there, and faramir has no part in it.

The controller is different. A brokered command runs as `faramir-exec`, which has no sudo, so by default the controller has to be left out:

```bash
faramir run --env-file faramir.env -- ansible-playbook msmtp.yml --limit '!controller'
```

A playbook that touches every host then splits in two: the fleet through the broker, and the controller as root some other way. `sudo faramir init --allow-sudo` closes that gap. A brokered command's `sudo` puts a question to a human, answered per run by `sudo faramir sudo approve ID`, with no password anywhere. How to run it: [escalation.md](escalation.md). Why it is shaped this way: [design.md](design.md#allowing-sudo-on-the-controller).

The Ansible side needs nothing. `become` passes `-n` by default, which tells `sudo` to fail rather than authenticate. The grant sets `noninteractive_auth` for the executor alone, which lets the PAM stack run under `-n` and put the question. Nothing prompts, so there is no `SUDO_ASKPASS` and no `-A`.

Nothing else changes: no `--ask-become-pass`, no vault, and no become password in a var, because there is no become password. Leave a watcher running as root, in a terminal the coding agent cannot type into. The first task that runs sudo puts its question there, naming the playbook:

```bash
sudo faramir sudo watch
```

One approval covers the whole playbook run, not one task. [What it does and does not bound](escalation.md#one-question-per-run-and-what-to-expect), including which other commands are refused meanwhile.
