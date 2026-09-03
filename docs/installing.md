# Installing

`faramir init` creates the accounts and groups, creates the age key, installs the binary, the deny list and the docs, renders the config and the systemd units, and starts the sockets. It is idempotent, so re-running it is also how you upgrade. It does not migrate: it writes this version's layout and leaves an older version's files alone.

```bash
make build
sudo ./bin/faramir init
```

## A re-run keeps what the install already uses

A flag you leave out is read from the install, not from the compiled-in default:

Flag left out | Read from
--- | ---
`--broker-user`, `--keeper-user`, `--exec-user` | each unit's `User=`
`--client-group`, `--ssh-key` | the installed `config.toml`
`--secrets-group` | the group owning `<config-dir>/secrets`

`init` reports what it adopted before it writes. A flag you pass overrides the adopted value. If `config.toml` exists and does not parse, the run stops, regardless of the flags given.

## What each flag sets

`faramir init --help` describes each flag in full. The settings that `config.toml` records are in [configuration.md](configuration.md#what-a-flag-sets).

Flag | Default | Sets
--- | --- | ---
`--agent-user NAME` | `$FARAMIR_OPERATOR`, then `$SUDO_USER`, then the invoking user | The account the coding agent runs as (the agent account, `agent_user` in the config). It owns the checkouts brokered commands run in, so root and faramir's service accounts are refused. Only `init` takes this flag; every other command reads what `init` recorded
`--client-group NAME` | the install's, then `faramir-client` | The group admitted to the broker socket, and the group owning an enrolled tree. A member can ask the broker for any managed value, so choose the group accordingly. An existing group is adopted, and all its current members get that permission
`--secrets-group NAME` | the install's, then the keeper's own group | The group owning the ciphertext. `doctor` fails if the operator is in it
`--config-dir DIR` | the install's ([how it is found](operating.md#checking-an-install)), then `/etc/faramir` | The directory holding `config.toml`, the age key and the managed sops files. Only `init` takes this flag; every other command finds the install. Must be absolute, its parent must exist, and it may not be under `/tmp` or `/var/tmp`. A *different* directory than the install's needs `--repoint-config`
`--repoint-config` | off | Consent to point the daemons at a different directory. **Nothing is moved.** The daemons read the new directory instead of the old one. The refs the old directory served stop being redacted. Its age key and ciphertext stay on disk until you retire them. The old spelling `--move-config` is still accepted and prints a warning
`--broker-user`, `--exec-user`, `--keeper-user` | the install's, then `faramir-broker`, `faramir-exec`, `faramir-keeper` | The three service accounts, created if missing. No two may share a name
`--ssh-key PATH` | the install's, then `<config-dir>/id_ed25519` | The path of the keypair the broker lends. One is created either way: this flag sets where the key is, and does not enable it. An existing key is adopted and must be `0600`, owned by `faramir-broker`, with its `.pub` beside it at `0644`. The key is refused to the agent's tools and to brokered commands wherever it is, because the rule is rendered from the configured path
`--known-hosts PATH` | none | A `known_hosts` file copied to `<exec-home>/.ssh/known_hosts` and replaced whole on each run. A file that is not a `known_hosts` file is refused
`--agent NAME` | `auto` | Which agents get the deny rules and a credentials section in this home: a rule file, or the plugin, extension or hook the agent uses instead of one ([which file, per agent](layout.md)). If no agent is found, nothing is written and `init` reports it
`--allow-sudo` | off | Lets a brokered command *ask* to become root, through a password-required sudoers entry and faramir's own PAM service. Re-running without the flag removes the grant. [What it writes](escalation.md#the-decision-is-made-at-init-per-host)
`--notify-command ARG` | the install's, then none | Announces a waiting escalation. Needs `--allow-sudo`. Recorded in `config.toml`: [what it accepts](configuration.md#what-a-flag-sets)
`--dry-run` | off | Report what would change and write nothing. The only invocation that does not need root
`--json` | off | Print the report as JSON, one entry per step with a `changed` flag

## The config directory is not a free choice

The units are sandboxed, so the config directory must be a path systemd can pass to them:

- `init` refuses whitespace and `%` in the path. systemd splits and expands both in `Environment=`.
- A directory under `/tmp` or `/var/tmp` is refused before anything is written. `PrivateTmp=true` gives each unit its own temporary hierarchy, so no daemon would see what the install wrote: every step would report done and no daemon would start.

Every path an install creates, with its mode and owner, is in [layout.md](layout.md).

## Deny rules

The rules `--agent` installs cover **this install's own paths and nothing else**. They are rendered from the layout, so they name this host's real paths:

- `<config-dir>`, wherever `--config-dir` put it
- the secrets directory
- `/var/log/faramir`
- `/usr/local/libexec/faramir`
- the three service accounts' directories under `/var/lib`

Each rule covers everything under its path, so the age key, the broker's SSH key, the managed sops files, the audit log and the executor's `known_hosts` are all refused. `faramir block ls` prints the list this host uses.

Which file each agent reads the rules from is in [layout.md](layout.md). How the rules affect each agent is in [coding-agents.md](coding-agents.md).

No rule is compiled in. A compiled-in rule would have to name a file faramir does not write and cannot locate. faramir creates one age key, in its own directory. A second identity exists only if the operator made one, and `reader add` takes a public key without learning where the private half is. A rule for `~/.config/sops/age` would usually guard a file that does not exist, and would make the default look more protective than it is.

Every secret an install writes is also protected by its mode. The rules are the second of two mechanisms.

File | Mode and owner
--- | ---
`age.key` | `0400 faramir-keeper`
the broker's SSH key | `0600 faramir-broker`
the secrets directory | `2750 root:<secrets-group>`
the audit log | `0600 faramir-broker`

> [!IMPORTANT]
> **You must declare any credential faramir neither writes nor reads.** An SSH private key, a `.pem`, a `.env` or `~/.aws/credentials` is not refused by an install that declares nothing, so an agent's file tools can open it. `faramir block add --path` declares one, and a directory covers everything under it ([blocked paths](configuration.md#blocked-paths)). `--strict` also refuses a brokered command that names it. `faramir block ls` shows both halves. A fleet declares them once, with whatever tool manages its hosts' configuration.

The rules cover what faramir installs, not credentials in general. What faramir writes, it refuses; what it never touches, the operator declares. This keeps the rules from growing into a list that is wrong on every host.

## Checking it worked

```bash
sudo faramir doctor
```

Without root it still runs, and reports the checks it could not make as unasked, not as passing. [What it checks](operating.md#checking-an-install).
