# Installing

`faramir init` creates the accounts and groups, mints the age key, installs the binary, the deny list and the docs, renders the config and the systemd units, and starts the sockets. It is idempotent, so it is also the upgrade, and it never migrates: it writes this version's layout and leaves an older one's leftovers alone.

```bash
make build
sudo ./bin/faramir init
```

## A re-run keeps what the install already uses

A flag left out is taken from the install rather than from the compiled-in default:

Flag left out | Taken from
--- | ---
`--broker-user`, `--keeper-user`, `--exec-user` | each unit's `User=`
`--client-group`, `--ssh-key` | the installed `config.toml`
`--secrets-group` | the group owning `<config-dir>/secrets`

`init` reports what it adopted before writing with it, and a flag still outranks it. A `config.toml` that is there and will not parse stops the run whatever flags it was given.

## What each flag sets

`faramir init --help` carries each flag in full. The settings `config.toml` records, rather than the install itself, are in [configuration.md](configuration.md#what-a-flag-sets).

Flag | Default | Sets
--- | --- | ---
`--agent-user NAME` | `$SUDO_USER`, then you | The account the coding agent runs as. It owns the checkouts brokered commands run in, so root is refused
`--client-group NAME` | the install's, then `dev` | The group admitted to the broker socket and group-owning an enrolled tree
`--secrets-group NAME` | the install's, then the keeper's own group | The group owning the ciphertext. `doctor` fails if the operator is in it
`--config-dir DIR` | [found the usual way](operating.md#checking-an-install) | Where `config.toml`, the age key and the managed sops files live. Absolute, parent must exist, and a *different* one needs `--move-config`
`--move-config` | off | Consent to that move. The refs the old directory served leave the value set
`--broker-user`, `--exec-user`, `--keeper-user` | the install's, then `faramir-broker`, `faramir-exec`, `faramir-keeper` | The three service accounts, created if missing. No two may share a name
`--recipient KEY` | none | A **public** age or ssh key that may also decrypt the store, repeatable. An identity is refused, `.sops.yaml` being world-readable. Read only at the install that creates that file; later changes are [`faramir recipient add`](operating.md#adding-a-recipient)
`--ssh-key PATH` | the install's, then `<config-dir>/id_ed25519` | Where the keypair the broker lends lives. One is minted either way, so this relocates rather than enables. An existing key is adopted, and must be `faramir-broker`-owned `0600` with its `.pub` beside it at `0644`
`--known-hosts PATH` | none | A `known_hosts` file copied to `<exec-home>/.ssh/known_hosts` and replaced whole each run. One that is not a `known_hosts` file is refused
`--agent NAME` | `auto` | Which agents get deny rules and a credentials section in this home ([which file, per agent](layout.md)). Finding no agent writes nothing and says so
`--allow-sudo` | off | Lets a brokered command *ask* to become root, through a password-required sudoers entry and a PAM service of faramir's own. Not passing the flag takes it back. [What it writes](escalation.md#the-decision-is-made-at-init-per-host)
`--notify-command ARG` | none | Announces a waiting escalation, one argument per flag. Must name `{prompt}` or `{id}`; needs `--allow-sudo`
`--dry-run` | off | Report what would change and write nothing. The one form that does not need root
`--json` | off | The report as JSON, one entry per step with a `changed` flag

## The config directory is not a free choice

The units are sandboxed, so where the config sits is bounded by what systemd will carry:

- `init` refuses whitespace and `%`, which systemd splits and expands in `Environment=`.
- A directory under `/tmp` or `/var/tmp` installs and then finds nothing, `PrivateTmp=true` giving each unit its own. Nothing refuses it at install time; the daemons fail to load when they start.

Every path an install creates, with its mode and owner, is in [layout.md](layout.md).

## Deny rules

The rules `--agent` installs refuse the agent's file tools against key material by name and suffix (`id_ed25519`, `.pem`, `.env*`, credentials and sops files) and against the sops, age and faramir config directories. Which file each agent reads them from is in [layout.md](layout.md); what they cost that agent is in [agents.md](agents.md).

## Checking it worked

```bash
sudo faramir doctor
```

Reports whether the install is doing its job, and as root what each account can reach. Without root it still runs, reporting what it could not ask as unasked. [What it checks](operating.md#checking-an-install).
