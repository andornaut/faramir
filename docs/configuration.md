# Configuration

There is one config file, `<config-dir>/config.toml`, and faramir owns it. It is rendered from [etc/config.toml.tmpl](../etc/config.toml.tmpl) on every `faramir init` run, so an edit there is replaced without warning. There are no drop-ins and no merge: every value is either derived from the install or set by a flag the file records, and a re-run keeps what it finds.

There is no command allowlist. What bounds a brokered command:

Setting | Effect
--- | ---
`[command.env] PATH` | Where a bare name is looked up, and the only `PATH` the child gets.
`[command] max_timeout_sec` | How long a command may run.
`[secret] min_length` | A value too short to redact is refused at load, so nothing can inject it.
the executor's uid | The real bound.

## What a flag sets

Seven values, each rendered into the file and read back out of it on the next run, so a flag left out keeps the install rather than reverting it. Naming one again changes it.

Flag | Key | Default | Bounds
--- | --- | --- | ---
`--command-env NAME=VALUE` | `[command.env] NAME` | `PATH`, `TERM`, `LANG`, `LC_ALL`, `DEBIAN_FRONTEND` | repeatable, and it **adds**: naming one variable keeps the rest. `PATH` may not be emptied, and every component must be absolute
`--command-timeout-sec` | `[command] timeout_sec` | 600 | at least 1
`--command-max-timeout-sec` | `[command] max_timeout_sec` | 3600 | at least 1, and not below `timeout_sec`, which it would otherwise silently replace for every command
`--command-concurrency` | `[command] concurrency` | 10 | at least 1: zero refuses every request as busy
`--escalation-timeout-sec` | `[escalation] timeout_sec` | 120 | 1 to 600
`--secret-min-length` | `[secret] min_length` | 8 | at least 6
`--secret-min-refresh-sec` | `[secret] min_refresh_sec` | 10 | at least 1. A minimum, not a schedule: the check runs when a command arrives and nothing polls in the background, so an idle host costs nothing. It bounds the keeper round trip only; linked files are stat'ed on every request

`[[secret.link]]` is the eighth thing the file carries and is `faramir link`'s, [below](#linked-secrets).

**`--secret-min-length` has a floor of 6 and a reason for being low.** The two failures are not symmetric: a value refused for being too short is absent from the redactor and reaches output in the clear, while one matched too eagerly only mangles the operator's own text. Length is a crude proxy either way. The dictionary peaks at eight characters, so the default is not the safe point it looks like; `password` is eight and is a word.

## What is derived

Everything else, from the install rather than from a flag. `faramir init` computes it and rewrites it every run.

Key | Derived from
--- | ---
`socket_path` on `[server]`, `[keeper]`, `[executor]` | rendered with the `.socket` units
`[server] allowed_group` | `--client-group`
`[keeper] allowed_user`, `[executor] allowed_user` | `--broker-user`
`[keeper] age_key_file` | `--config-dir`
`[keeper] age_key_credential` | rendered with the keeper unit's `LoadCredential=`
`[ssh] key` | `--ssh-key`
`[ssh] exec_group` | `--exec-user`, resolved to that account's own group
`[ssh] ssh_agent`, `[ssh] ssh_add` | resolved on `PATH` at install time; the broker execs them as its own uid
`[ssh] agent_socket`, `[audit] log_path` | no flag: `/run/faramir` and `/var/log/faramir`, fixed at build time
`[escalation] exec_user`, `pam_service`, `helper` | `--allow-sudo`
`[escalation] notify_command` | `--notify-command`, repeatable, one argument each

## What is not a key at all

Eight values are constants in the binary. None was ever set by an install, and each says what the thing is rather than offering a preference:

Value | Why not a key
--- | ---
`max_output_bytes` (256 KiB) | It bounds how much text reaches the model, which belongs to the conversation rather than to the host. Roughly 64k tokens: a megabyte was more than the window it exists to protect, so it could not bind. The only use for a larger one is putting more in front of the model, and truncation is reported rather than silent
`max_request_bytes` (256 KiB) | A guard against a malformed request
`max_record_bytes` (256 KiB) | Matched to the output cap, which is what fills it: the record keeps the head and the tail of the same output and cuts every other field to fit
`term_cols`, `term_rows` (120x40) | Where a program folds its own output, on a stream a model reads
`kill_grace_sec` (5) | A window that opens only once a command has overrun its timeout
the managed store | `<config-dir>/secrets/` matching `*.sops.yml`, `*.sops.yaml` and `*.sops.json`: the three the agent deny rules already refuse, so what the broker reads and what the agent cannot open cannot disagree. Derived from where the config sits, so the store cannot be pointed at a checkout
the decrypt command | A second way to invoke sops is a second thing that could be pointed elsewhere, by the account holding the age key

## Linked secrets

A `[[secret.link]]` entry reads one secret out of a file another tool maintains, rather than copying it into the managed store. The file stays where that tool expects it, so rotating the credential is that tool's business and nothing here goes stale.

```sh
sudo faramir link add gh/token ~/.config/gh/hosts.yml \
    --type yaml --key github.com/oauth_token
```

That is the whole of it. The command grants the broker read on the file, reads it once as the broker's own account to check the selector, writes the entry, refuses the path to the agent's file tools, and leaves `faramir reload` to pick it up. `faramir link ls` lists what is declared; `faramir link rm REF` drops one.

**The order matters and is the command's own.** The grant comes first, because the question is whether the *broker* can read the file and it cannot until it has been granted. The probe comes before the entry is written, because a selector that names nothing would otherwise leave the broker refusing every command until somebody noticed. A probe that fails puts the grant back.

Entries live in `config.toml` beside everything else, and `init` reads them back before rewriting the file, so each grant and each deny rule is re-asserted on every run. That is what heals one a tool took away.

The entry it writes:

```toml
[[secret.link]]
ref  = "gh/token"
path = "/home/operator/.config/gh/hosts.yml"
type = "yaml"
key  = "github.com/oauth_token"
```

Key | Rule
--- | ---
`ref` | The name a caller asks by, in the same namespace the sops store uses. Nothing marks a ref as linked: where a secret is kept is not part of its name, or moving one into the store later would rename it, and every `faramir.env` naming it with it. A link claiming a ref the store already defines is refused too.
`path` | Absolute. No `~`, which nothing expands here: the broker runs as its own account, so a home would be the wrong one.
`type` | `text` or `base64` for the whole file, `json`, `yaml` or `ini` to select out of it.
`key` | Required for the three that select, refused for the two that do not. `a/b/c` walks a tree the way a sops ref does, a number indexing a list; for `ini` it is the whole key, or `section/key`.

Why it is shaped this way -- one ref per entry rather than a whole-file flatten, the broker reading these rather than the keeper, and modes rather than an ACL -- is in [design.md](design.md#linked-secrets-are-read-by-the-broker). What follows is what it costs you day to day.

**Link what the agent can already read.** Linking turns plaintext the agent could print into a value the redactor covers, and takes away the direct read. Pointed at something the agent *cannot* reach it does the opposite, since every managed value is reachable through `env_refs` by any brokered command.

**Every linked path is refused to the agent's file tools.** `link add` and `init` both render them into the account-wide deny rules, and `faramir doctor` fails on a linked file that is not refused. Pi is the exception, having no account-wide rule file.

**faramir grants the broker read**, so there is nothing to arrange by hand:

Path | Becomes
--- | ---
the linked file | the broker's own group and group-readable, its owner and owner bits left alone. That group holds one account, which is what keeps the executor out
every directory above it, down from the home | the client group, execute only, the same grant an enrolled tree gets. Traversal is not read

**A tool that replaces its own file rather than rewriting it takes the grant with it.** A temp file renamed over the original is created fresh, and `0600` on creation leaves nothing for a group to read. `faramir doctor` asks the broker's own account whether it can still read each file; `faramir init` grants it again.

**A link that is there and will not read stops the host.** It is a value the redactor is missing while the plaintext is still on disk, so `exec` and `redact` refuse until it is fixed, and `broker --check` and `doctor` name the ref. A link whose *path* is gone is the other case and is not fatal: the credential has left the machine, so there is nothing to redact.

## The sockets belong to their units

- Under socket activation the daemons are handed a listening descriptor and never reach the bind path, so `ListenStream=` and `SocketMode=` are what a socket is.
- No config key is a file mode. `--check` and `doctor` stat the bound socket rather than reading one.
- `socket_path` stays in the file, because the broker *dials* the keeper and the executor at it, and a daemon run outside systemd binds it itself. `init` rewrites both sides together, so the two cannot drift.
- The broker binds its own ssh-agent socket. Its mode is a constant beside the code that sets it rather than a value anything could widen past the group `exec_group` names.
- `allowed_group` exists on `[server]` alone. `[keeper]` and `[executor]` have one legitimate client each, the broker, named in `allowed_user`; the group form is not a key there and setting it is a hard error naming the alternatives, because the only group in play is the client group, which holds the agent's own uid.

## The install gate, and the same gate at startup

`faramir broker --check` exits non-zero on anything that leaves the broker protecting less than it appears to. Run it as the broker's own account, `sudo -u faramir-broker faramir broker --check`, which needs no `-c`: sudo clears `FARAMIR_CONFIG`, and the unit is the next step. Run as root it reads what the broker cannot, and the `allowed_user` check is skipped, every name comparing unequal from root.

Fails on | Because
--- | ---
An unknown key or `[section]`, or a value out of range | A config that reads as though it took effect. Reported by the loader, which exits 2
A ref too short to redact | Refused at load, so covered by nothing. When this is the *only* finding, `init` warns and carries on and `doctor` reports a warning: an install cannot lengthen a secret, and a refused value is never injected
A store that matched no file at all | Those values are absent from the redactor, and a store the broker cannot see is one it cannot redact against
A `[[secret.link]]` entry whose file is not there, or is there and did not read | The same two meanings, reported with the ref in front. The second is what an ACL dropped by a tool rewriting its own file looks like
A store holding zero refs | Stricter than the daemon's own gate, which asks only that every matched file loaded
An `[ssh] key` the agent cannot load | `ssh-add` refuses it, leaving every host unreachable. Passphrase-protected, unreadable, or pointed at the `.pub`
An `[escalation] helper` or PAM service file that is not there, or a `notify_command` that is not installed | Escalation is configured and either every request fails with `sudo` reporting an authentication error, or nothing announces the questions waiting
`[keeper]` or `[executor] allowed_user` naming an account that is not the broker | Each socket has one legitimate client. The keeper's is the age key by another route; the executor's runs a command with no policy, no redaction and no audit record
The bound broker socket having world bits | Every account on the host reaches the broker, whatever `allowed_group` says. Stat'ed rather than read from the config. Unbound is reported as unchecked
An audit log that cannot be written | A command that cannot be recorded is not run

**The daemon holds itself to the same rules, and on every request rather than at boot.** `--check` is run by `init` and by `doctor`, and neither runs at boot, so on its own it only ever described the host as it was at install time.

For the secrets it is one rule, and `exec` is held to it because a brokered command's output is redacted against the same set: **the broker serves `exec` and `redact` only while no managed file went unread.** At least one managed file or one link read, and everything that was there loaded.

- What those files held does not enter into it. An install whose operator has not written a secret yet serves, and a ref no file defines is answered by `unknown_secret`.
- Otherwise the broker refuses with `no_secrets`, naming why. It comes up either way, and `status` and `list_secrets` answer regardless.
- A keeper that could not be reached is the exception once a set has loaded, what is kept then being the last thing known to be true. A cold start has nothing to keep and refuses.

Secrets on a filesystem that is not mounted yet look exactly like ones never written, and both leave the broker redacting nothing. `--check` and `doctor` tell the two apart.

An `[ssh] key` the agent does not load is logged and not fatal: it breaks only commands that reach a managed host, and those fail at the point of use with `ssh`'s own error, while stopping the daemon over it would stop the commands that never touch SSH. An unset key is not a failure, being the host that authenticates some other way.

## What no setting changes

- **Nothing the broker starts receives the age key.** No flag grants it; the broker does not hold it to grant.
- **Secrets are injected as environment variables only.** Never into `argv`, which is visible in `ps` and `/proc/<pid>/cmdline`.
- **`cmd` is an array.** Never a string handed to `sh -c`.
- **The broker runs the working tree as it is on disk.** No promotion step.
- **No config names where a command runs.** A brokered command runs where its caller was; a request naming no cwd is refused.
- **Nothing runs sudo without a human, and no setting widens what one approval covers.** Whether a host may sudo at all is the `--allow-sudo` install-time decision, not a config key.
- **Every run is confined to a cgroup and reaped there**, or refused. Not a setting: `init` renders `Delegate=` on the executor unit for every install.
- **`redactions` reports counts, not values.**
