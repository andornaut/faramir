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
`--command-env NAME=VALUE` | `[command.env] NAME` | `PATH`, `TERM`, `LANG`, `LC_ALL`, `DEBIAN_FRONTEND` | repeatable, and it **adds**: naming one variable keeps the rest. `PATH` may not be emptied, and every component must be absolute. On a host that grants sudo they are written to `/usr/local/libexec/faramir/sudo-env` too, so a command keeps them across `sudo`: `env_reset` discards what the caller held, and this is put back from a file the caller cannot write. Not all of them: `HOME`, `PATH` and `SUDO_*` stay sudo's own, and a reserved name or a value holding a newline or a `#` is [left out with a warning](escalation.md#what-a-brokered-command-keeps-across-sudo)
`--command-timeout-sec` | `[command] timeout_sec` | 600 | at least 1
`--command-max-timeout-sec` | `[command] max_timeout_sec` | 3600 | at least 1, and not below `timeout_sec`, which it would otherwise silently replace for every command
`--command-concurrency` | `[command] concurrency` | 10 | at least 1: zero refuses every request as busy
`--escalation-timeout-sec` | `[escalation] timeout_sec` | 120 | 1 to 600
`--secret-min-length` | `[secret] min_length` | 8 | at least 6
`--secret-min-refresh-sec` | `[secret] min_refresh_sec` | 10 | at least 1. A minimum, not a schedule: the check runs when a command arrives and nothing polls in the background, so an idle host costs nothing. It bounds the keeper round trip only; linked files are stat'ed on every request

`[[secret.link]]` is the eighth thing the file carries and is `faramir link`'s, [below](#linked-secrets). `[[secret.refuse]]` is the ninth and is `faramir refuse`'s, [below that](#refused-paths).

**`--secret-min-length` has a floor of 6, and a reason for being low.** The two failures are not symmetric: a value refused for being too short is absent from the redactor and reaches output in the clear, while one matched too eagerly only mangles the operator's own text. `password` is eight characters, so the default is not the safe point it looks like. [What the gate is for](redaction.md#the-pipeline-in-order).

## What is derived

Everything else, from the install rather than from a flag. `faramir init` computes it and rewrites it every run.

Key | Derived from
--- | ---
`socket_path` on `[server]`, `[keeper]`, `[executor]` | rendered with the `.socket` units
`[server] allowed_group` | `--client-group`
`[server] agent_user` | `--agent-user`, defaulting to `$SUDO_USER` and then to you. Given to every brokered command as `FARAMIR_OPERATOR`, and to its `sudo` through the environment file its PAM service reads
`[keeper] allowed_user`, `[executor] allowed_user` | `--broker-user`
`[keeper] age_key_file` | `--config-dir`
`[keeper] age_key_credential` | rendered with the keeper unit's `LoadCredential=`
`[ssh] key` | `--ssh-key`
`[ssh] exec_group` | `--exec-user`, resolved to that account's own group
`[ssh] ssh_agent`, `[ssh] ssh_add` | resolved on `PATH` at install time; the broker execs them as its own uid
`[ssh] agent_socket`, `[audit] log_path` | no flag: `/run/faramir` and `/var/log/faramir`, fixed at build time
`[escalation] exec_user`, `pam_service`, `pam_stack`, `helper` | `--allow-sudo`. `pam_stack` is the file that carries faramir's PAM stack on this host, which is not always what `pam_service` names: see [the two sudos](escalation.md#the-two-sudos)
`[escalation] notify_command` | `--notify-command`, repeatable, one argument each

## What is not a key at all

Eight values are constants in the binary, none of them ever set by an install:

Value | Is
--- | ---
`max_output_bytes` | 256 KiB, roughly 64k tokens. It bounds how much text reaches the model, so it belongs to the conversation rather than to the host; truncation is reported rather than silent
`max_request_bytes` | 256 KiB
`max_record_bytes` | 256 KiB, matched to the output cap: a record keeps the head and the tail of the same output and cuts every other field to fit
`term_cols`, `term_rows` | 120x40, where a program folds its own output
`kill_grace_sec` | 5 seconds, opening only once a command has overrun its timeout
the managed store | `<config-dir>/secrets/` matching `*.sops.yml`. Derived from where the config sits, so the store cannot be pointed at a checkout. What the agent cannot open is the directory, which the deny rules name by path
the decrypt command | sops, invoked one way. A second way is a second thing that could be pointed elsewhere, by the account holding the age key

## Linked secrets

A `[[secret.link]]` entry reads one secret out of a file another tool maintains, rather than copying it into the managed store. [When to reach for one](integrations.md#where-the-value-lives).

```sh
sudo faramir link add gh/token ~/.config/gh/hosts.yml \
    --type yaml --key github.com/oauth_token
```

That is the whole of it; the [three link commands](operating.md#operator-commands) are the only way these entries are written.

**Each of the three is idempotent**, so a configuration manager may run them on every converge. Adding the entry this install already carries re-applies it: the grant, the deny rules and the config are rendered again, `--json` reports `changed: false`, and the daemons are reloaded only where something did change. Removing a ref it does not carry writes nothing. The one thing refused is the same ref against a different file, type or key, naming both definitions: a ref has one, and answering by replacing the entry would change which credential every caller of that name receives while the file that lost it keeps its grant and leaves the redactor.

**The order is the command's own and it matters.** The grant comes first, because the question is whether the *broker* can read the file and it cannot until it has been granted. The probe comes before the entry is written, because a selector that names nothing would otherwise leave the broker refusing every command until somebody noticed. A probe that fails puts the grant back.

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
`type` | `text` or `base64` for the whole file, `json`, `yaml`, `toml` or `ini` to select out of it.
`key` | Required for the four that select, refused for the two that do not. `a/b/c` walks a tree the way a sops ref does, a number indexing a list; `ini` matches the whole key instead. [Selectors, escaping and the per-tool recipes](integrations.md#linking-a-credential-another-tool-owns).

faramir grants the broker read, so there is nothing to arrange by hand:

Path | Becomes
--- | ---
the linked file | the broker's own group and group-readable, its owner and owner bits left alone. That group holds one account, which is what keeps the executor out
every directory above it, down from the home | the client group, execute only, the same grant an enrolled tree gets. Traversal is not read

Why it is shaped this way (one ref per entry rather than a whole-file flatten, the broker reading these rather than the keeper, and modes rather than an ACL) is in [design.md](design.md#linked-secrets-are-read-by-the-broker). What follows is what it costs you day to day.

- **Every linked path is refused to the agent's file tools.** `link add` and `init` both render them into the account-wide deny rules, and `faramir doctor` fails on a linked file that is not refused. Pi refuses them from its extension instead, having no account-wide rule file for one to be rendered into.
- **A tool that replaces its own file rather than rewriting it takes the grant with it.** A temp file renamed over the original is created fresh, and `0600` on creation leaves nothing for a group to read. `faramir doctor` asks the broker's own account whether it can still read each file; `faramir init` grants it again, and so does adding the same entry a second time. That repair needs the reload it gets: the broker fingerprints a linked file by mtime and size, which a `chgrp` leaves alone, so a store already refusing over that file would go on refusing.
- **A link that is there and will not read stops the host**, being a value the redactor is missing while the plaintext is still on disk: `run` and `redact` refuse until it is fixed. A link whose *path* is gone is the other case and is not fatal, the credential having left the machine.

## Refused paths

A `[[secret.refuse]]` entry refuses one thing to the agent's file tools, for a credential faramir has no use for the value of: a LUKS keyfile, an SSH identity. [When to reach for one](integrations.md#where-the-value-lives).

```sh
sudo faramir refuse add /etc/luks/volume.key          # this file, on this host
sudo faramir refuse add --name '*.htpasswd'           # any file of that name, anywhere
```

**A path and a name are not the same rule, and one entry is one of them.** A path refuses the file at that path. A name is matched against the path the agent names rather than against this host's filesystem, which is what reaches a path the host does not have: a container mounts `/srv/ha/config` as `/config`, the agent names the second, and a rule carrying the first covers nothing it runs. Naming both in one entry is refused rather than answered by picking one.

Name | Matches
--- | ---
`auth` | any file called `auth`, in any directory
`*.htpasswd` | any file whose name ends that way
`.env*` | any file whose name starts that way
`secrets*.yml` | any file whose name matches, the wildcard not crossing a directory
`.storage/` | everything under any directory of that name

Which of the five a pattern is comes from its shape, and `refuse add` prints what it read before writing it. That inference is safe where inferring path-from-name would not be: the shapes differ in breadth, and reading one as another refuses more or fewer files of the same kind, while an inferred path could turn a typo into a rule that silently matches nothing.

**The two forms fail in opposite directions.** A mistyped path refuses one file, and the file stays readable until somebody notices. A pattern that matches more than it was meant to refuses a class of files at once, and nothing announces it: the agent meets it as file tools failing on files nobody discussed. So a pattern that matches everything is refused at load the way `/` is as a path, and what a pattern will match is printed as it is written rather than left to be discovered.

**It is the weaker of the two entries.** A link reads the file, so it does three things this one cannot:

What happens to the file | `[[secret.link]]` | `[[secret.refuse]]`
--- | --- | ---
refused to the agent's file tools | yes | yes
regrouped to the broker's group, so a brokered command is refused it too | yes | no, the mode is left alone
the value in the redactor, tokenised wherever it appears | yes | no, faramir never reads it
injectable by ref | yes | no

So a command the broker runs may still open a refused path, and print it in the clear.

Key | Rule
--- | ---
`path` | Absolute, and in its shortest form: a rule matches the path as written, so `/etc/./k` and `/etc/k` are two rules of which one matches nothing. No `~`, which nothing expands here. `/` is refused, being every file on the host
`name` | A name, suffix, prefix, wildcard name or directory, per the table above. Not absolute, which is a path; no `~` and no `..`, nothing resolving either here; no `**`, a name matching in any directory already. A pattern with nothing left once the wildcards and separators are taken out is refused, being every file on the host

- **A path that is not there is still recorded**, and you are told. The rule costs nothing while the file is absent and holds once the volume mounts, which is the case these exist for. A path spelled wrong looks the same, so the message says both.
- **A name is not asked of the filesystem at all**, having nothing on this host to be asked about. What it will match is printed instead.
- **`faramir refuse ls` lists the built-in rules beside the declared ones**, under a `SOURCE` column, because there is otherwise no way to ask what faramir already refuses: the agent meets a built-in as a file tool refusing a path, and the refusal names the rule that matched rather than the set. `--declared` narrows the listing to the entries the config carries, which is the list a configuration manager converges.
- **A directory refuses what is under it.** Which it is, is asked of the filesystem as the rules are rendered, and a path that is not there renders as a file: the narrower of the two.
- **Nothing is reloaded.** No daemon reads these entries, so `refuse add` does not restart the broker under a running command.
- **Both commands are idempotent.** A path already refused is not an error: the entry stands, the rules are rendered again and `--json` reports `changed: false`. Removing a path this install does not refuse writes nothing.
- **Pi is the exception**, as it is for linked paths: its rules are compiled into the extension, so there is no account-wide file to render one into.

`init` reads the entries back before rewriting `config.toml`, so every rule is re-asserted on each run. That is what restores one an agent's settings dropped.

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

For the secrets it is one rule, and `run` is held to it because a brokered command's output is redacted against the same set: **the broker serves `run` and `redact` only while no managed file went unread.** At least one managed file or one link read, and everything that was there loaded.

- What those files held does not enter into it. An install whose operator has not written a secret yet serves, and a ref no file defines is answered by `unknown_secret`.
- Otherwise the broker refuses with `no_secrets`, naming why. It comes up either way, and `status` and `refs` answer regardless.
- A keeper that could not be reached is the exception once a set has loaded, what is kept then being the last thing known to be true. A cold start has nothing to keep and refuses.

- Secrets on a filesystem that is not mounted yet look exactly like ones never written, and both leave the broker redacting nothing. `--check` and `doctor` tell the two apart.
- An `[ssh] key` the agent does not load is logged and not fatal, breaking only commands that reach a managed host, which fail at the point of use with `ssh`'s own error. Stopping the daemon over it would stop the commands that never touch SSH. An unset key does not stop the daemon either, for the same reason, but `faramir doctor` fails on one: `init` mints a key on every run whether or not the host turns out to need it, so an empty `key` is an edit to the file rather than a host that authenticates some other way.

## What no setting changes

- **Nothing the broker starts receives the age key.** No flag grants it; the broker does not hold it to grant.
- **Secrets are injected as environment variables only.** Never into `argv`, which is visible in `ps` and `/proc/<pid>/cmdline`.
- **`cmd` is an array.** Never a string handed to `sh -c`.
- **The broker runs the working tree as it is on disk.** No promotion step.
- **No config names where a command runs.** A brokered command runs where its caller was; a request naming no cwd is refused.
- **Nothing runs sudo without a human, and no setting widens what one approval covers.** Whether a host may sudo at all is the `--allow-sudo` install-time decision, not a config key.
- **Every run is confined to a cgroup and reaped there**, or refused. Not a setting: `init` renders `Delegate=` on the executor unit for every install.
- **`redactions` reports counts, not values.**
