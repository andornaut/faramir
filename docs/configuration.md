# Configuration

`<config-dir>/config.toml` is rendered from [etc/config.toml.tmpl](../etc/config.toml.tmpl) on every `faramir init` run, so an edit there is replaced without warning. Settings go in `<config-dir>/config.d/*.toml`, which `init` never touches.

One section of that file is an exception, and only because `init` reads it back before rewriting it: the `[[secrets.link]]` entries [below](#linked-secrets), which `faramir link` writes and `init` re-asserts.

There is no command allowlist. What bounds a brokered command:

Setting | Effect
--- | ---
`[exec.base_env] PATH` | Where a bare name is looked up, and the only `PATH` the child gets.
`[exec] max_timeout_sec` | How long a command may run.
`[exec] max_output_bytes` | What comes back. The audit record keeps the head and the tail of the same output, sized so its line fits `[audit] max_record_bytes`.
`[secrets] min_length` | A value too short to redact is refused at load, so nothing can inject it.
the executor's uid | The real bound.

## Drop-ins

- `config.d/*.toml` merge over the base in lexical order. Tables merge key by key, so one `[secrets] patterns` does not discard `min_length`. Scalars replace.
- Dotfiles, subdirectories and non-`.toml` files are skipped, so an editor's `.#name.toml` lock does not stop the daemons. A missing `config.d` is fine; one that exists and cannot be read is a hard error.
- Validation runs after merging, so a drop-in is held to every rule the base file is. `faramir status` and `faramir broker --check` report `configs`: the base file and every drop-in that contributed, in merge order.

Two lists differ from the scalar rule:

List | Rule | Why
--- | --- | ---
`[secrets] patterns` | **accumulates**, duplicates collapsed | An inventory with one entry per owner. Replacing would leave the broker holding fewer files than its operator believes, injecting and redacting nothing for the loser. Entries are globs, deduplicated again after expansion.
`[[secrets.link]]` | **accumulates**, two entries claiming one `ref` refused, naming both | The same inventory rule. Deduplicated by `ref` rather than by equality: two definitions of one name are not a duplicate to collapse but a question of which file wins, and that would come down to filename order.
`[secrets] decrypt_command` | **refused** when two sources set it, naming both | Accumulating would hand the keeper a second way to invoke sops; taking the last would make it depend on filename order.

## What a drop-in may set

Everything `init` does not derive. `[keeper]`, `[executor]` and `[ssh]` have nothing settable.

Section | Keys | Bounds
--- | --- | ---
`[exec]` | `default_timeout_sec`, `max_timeout_sec`, `max_output_bytes`, `term_cols`, `term_rows`, `kill_grace_sec` | timeouts and bytes at least 1, `term_*` 1 to 65535, `kill_grace_sec` at least 0. `max_timeout_sec` may not be below `default_timeout_sec`
`[exec.base_env]` | all of them, and the one you reach for most: the child inherits nothing else | must define `PATH`, absolute components only
`[secrets]` | `patterns`, `link`, `refresh_interval_sec`, `min_length` | `refresh_interval_sec` at least 0, `min_length` at least 1, each pattern a parseable glob. `link` is an array of tables, [below](#linked-secrets)
`[server]` | `max_concurrency`, `max_request_bytes` | at least 1
`[audit]` | `max_record_bytes` | at least 4096, counted in encoded bytes
`[sudo]` | `timeout_sec` | 1 to 600

`[sudo] timeout_sec` is how long a question waits for a human. The 600 ceiling is load-bearing: the PAM helper cannot read this config (PAM gives it no environment and its argv is fixed at install time), so it derives its own deadline from the same constant and the two cannot drift. While a question is open every other brokered command on the host is refused, so past ten minutes a refusal and a second run is the better answer. On a host with no sudo grant the key still loads and does nothing.

## Linked secrets

A `[[secrets.link]]` entry reads one secret out of a file another tool maintains, rather than copying it into the managed store. The file stays where that tool expects it, so rotating the credential is that tool's business and nothing here goes stale.

```sh
sudo faramir link add gh/token ~/.config/gh/hosts.yml \
    --type yaml --key github.com/oauth_token
```

That is the whole of it. The command grants the broker read on the file, reads it once as the broker's own account to check the selector, writes the entry, refuses the path to the agent's file tools, and leaves `faramir reload` to pick it up. `faramir link ls` lists what is declared; `faramir link rm REF` drops one.

**The order matters and is the command's own.** The grant comes first, because the question is whether the *broker* can read the file and it cannot until it has been granted. The probe comes before the entry is written, because a selector that names nothing would otherwise leave the broker refusing every command until somebody noticed. A probe that fails puts the grant back.

Entries live in `config.toml`, which `init` rewrites every run and reads its links back out of, so they are install state rather than a drop-in's: `init` re-asserts each grant and each deny rule on every run, which is what heals one a tool took away. A `[[secrets.link]]` written by hand in a `config.d` drop-in still works and accumulates; `faramir link rm` will not touch it, that file being yours.

The entry it writes:

```toml
[[secrets.link]]
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

**One ref per entry, with a selector.** There is no whole-file flatten for the structured types, because a config file is mostly not secret: `https://registry.npmjs.org/` clears `min_length` and would turn unrelated output into tokens.

**The broker reads these, not the keeper.** A linked file needs no key, and the keeper exists to hold the one thing that decrypts everything, so it runs with the homes taken away entirely. The broker already holds every plaintext value and already sees the homes, having to stat a request's cwd.

**Link what the agent can already read.** Linking turns plaintext the agent could print into a value the redactor covers, and takes away the direct read. Pointed at something the agent *cannot* reach, it does the opposite: every managed value is reachable through `env_refs` by any brokered command, so a root-owned keyfile would become agent-obtainable and there would be no disclosure to close in exchange.

**Every linked path is refused to the agent's file tools.** `link add` and `init` both render them into the account-wide deny rules, beside the install's own directories. A link written by hand into a drop-in is the one case the two can part company, and is not covered until `init` runs again; `faramir doctor` fails until it does. Pi is the exception either way, having no account-wide rule file: its rules are compiled into each project's extension and do not carry these.

**faramir grants the broker read on each linked file**, so there is nothing to arrange by hand. `link add` does it when the link is added and `init` re-asserts it on every run. Two grants:

Path | Becomes
--- | ---
the linked file | the broker's own group and group-readable, its owner and owner bits left alone. That group holds one account, which is what keeps the executor out: naming a value is not permission to read the file it came from
every directory above it, down from the home | the client group, execute only, the same grant an enrolled tree gets. Traversal is not read, and the file's own mode still refuses every account but the broker's

Modes and ownership rather than an ACL, and not as a preference: a stacked filesystem does not carry one. An eCryptfs home takes `setfacl` without error and reads the entry back from its own cache, so a grant made that way looks applied, cannot be removed, and is not what decides the read.

**A tool that replaces its own file rather than rewriting it takes the grant with it.** A temp file renamed over the original is created fresh, and `0600` on creation leaves nothing for a group to read. An ACL is lost the same way, its inherited entry masked to nothing by that same mode, so this is not a cost of choosing modes. `faramir doctor` asks the broker's own account whether it can still read each file, and whether the executor can, which nothing derived from the mode would answer as reliably. `faramir init` grants it again.

**A link that is there and will not read stops the host.** It is a value the redactor is missing while the plaintext is still on disk, so it is the same failure as a managed file that did not decrypt: `exec` and `redact` refuse until it is fixed, and `broker --check` and `doctor` name the ref. A link whose *path* is gone is the other case and is not fatal, the credential having left the machine with nothing to redact; it is reported the way a pattern that matched nothing is.

## What init derives, a drop-in may not set

The rule is the value's provenance, not its section: a value `init` computes from a flag or from the install is refused outright; a value it writes as a plain default is yours.

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
`[sudo] exec_user`, `pam_service`, `helper` | `--allow-sudo`
`[sudo] notify_command` | `--notify-command`, repeatable, one argument each

Four of these are refused for what a drop-in could reach, not for tidiness:

- `exec_group` is the group the agent relay's `SO_PEERCRED` check admits, so a drop-in naming the client group there hands the broker's SSH identity to the account the relay exists to keep it from.
- `ssh_agent`, `ssh_add` and `notify_command` are programs the broker execs as the uid holding every plaintext value.
- `log_path` is rendered into `logrotate.conf` alongside, so moving one leaves rotation pointed at a file nothing writes, which `doctor` fails on. The audit log does not follow `--config-dir`, `{{.LogDir}}` being the broker unit's `ReadWritePaths`.
- The whole of `[sudo]` but `timeout_sec` is the approval boundary itself. `pam_service` names the file `sudo` authenticates through, so a drop-in pointing it at a service the operator wrote would choose what decides every approval; `helper` is the program PAM execs as root to make that decision. Re-run `init` with or without `--allow-sudo` to change the arrangement.

`notify_command` has a flag, `init` resolving the program on `PATH` as it does `ssh_agent` and `ssh_add`:

```sh
faramir init --allow-sudo \
    --notify-command /usr/bin/wall \
    --notify-command '{prompt}'
```

One argument per flag, so nothing has to be word-split. It must name `{prompt}` or `{id}`, and `init` refuses it otherwise rather than leaving the broker unable to load its config. Keep `{id}` off anything that broadcasts: `wall` reaches every terminal on the host, and the coding agent has one.

## The sockets belong to their units

- Under socket activation the daemons are handed a listening descriptor and never reach the bind path, so `ListenStream=` and `SocketMode=` are what a socket is.
- No config key is a file mode. `--check` and `doctor` stat the bound socket rather than reading one.
- `socket_path` stays, because the broker *dials* the keeper and the executor at it, and a daemon run outside systemd binds it itself. A drop-in setting it is refused, moving it otherwise disconnecting the broker from a daemon still listening where it always was.
- The broker binds its own ssh-agent socket. Its mode is a constant beside the code that sets it rather than a value a drop-in could widen past the group `exec_group` names.
- `allowed_group` exists on `[server]` alone. `[keeper]` and `[executor]` have one legitimate client each, the broker, named in `allowed_user`; the group form is not a key there and setting it is a hard error naming the alternatives, because the only group in play is the client group, which holds the agent's own uid.

## The install gate, and the same gate at startup

`faramir broker --check` exits non-zero on anything that leaves the broker protecting less than it appears to. Run it as the broker's own account, `sudo -u faramir-broker faramir broker --check`, which needs no `-c`: sudo clears `FARAMIR_CONFIG`, and the unit is the next step. Run as root it reads what the broker cannot, and the `allowed_user` check is skipped, every name comparing unequal from root.

Fails on | Because
--- | ---
An unknown key or `[section]`, or a value out of range | A config that reads as though it took effect. Reported by the loader, which exits 2
A ref too short to redact | Refused at load, so covered by nothing. When this is the *only* finding, `init` warns and carries on and `doctor` reports a warning: an install cannot lengthen a secret, and a refused value is never injected
A `[secrets] patterns` entry that named nothing, or a file it named that did not load | Those values are absent from the redactor. A pattern that matches no file is the same failure as a literal path that is not there
A `[[secrets.link]]` entry whose file is not there, or is there and did not read | The same two meanings, reported with the ref in front. The second is what an ACL dropped by a tool rewriting its own file looks like
A store holding zero refs | Stricter than the daemon's own gate, which asks only that every matched file loaded
An `[ssh] key` the agent cannot load | `ssh-add` refuses it, leaving every host unreachable. Passphrase-protected, unreadable, or pointed at the `.pub`
A `[sudo] helper` or PAM service file that is not there, or a `notify_command` that is not installed | Approval is configured and either every request fails with `sudo` reporting an authentication error, or nothing announces the questions waiting
`[keeper]` or `[executor] allowed_user` naming an account that is not the broker | Each socket has one legitimate client. The keeper's is the age key by another route; the executor's runs a command with no policy, no redaction and no audit record
The bound broker socket having world bits | Every account on the host reaches the broker, whatever `allowed_group` says. Stat'ed rather than read from the config. Unbound is reported as unchecked
An audit log that cannot be written | A command that cannot be recorded is not run

**The daemon holds itself to the same rules, and on every request rather than at boot.** `--check` is run by `init` and by `doctor`, and neither runs at boot, so on its own it only ever described the host as it was at install time.

For the secrets it is one rule, and `exec` is held to it because a brokered command's output is redacted against the same set: **the broker serves `exec` and `redact` only while no managed file went unread.** At least one `[secrets] patterns` entry matched a file or one `[[secrets.link]]` entry read, and everything that was there loaded.

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
