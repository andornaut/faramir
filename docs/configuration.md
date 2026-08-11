# Configuration

[etc/config.toml.tmpl](../etc/config.toml.tmpl) is what `init` renders, on every run. There is no command allowlist. What bounds a brokered command:

Setting | Effect
--- | ---
`[exec.base_env] PATH` | Where a bare name is looked up, and the only `PATH` the child gets.
`[exec] max_timeout_sec` | How long a command may run.
`[exec] max_output_bytes` | What comes back; the audit log keeps up to `[audit] max_record_bytes`.
`[secrets] min_length` | A value too short to redact is refused at load, so nothing can inject it.
the executor's uid | The real bound.

- `allowed_group` admits every member of one group including supplementary membership, and exists on `[server]` alone. `[keeper]` and `[executor]` have one legitimate client each, the broker, named in `allowed_user`; the group form is not a key there and setting it is a hard error naming the alternatives, because the only group in play is the client group, which holds the agent's own uid.
- No config names where a command runs. A brokered command runs where its caller was; a request naming no cwd is refused.
- A mistyped key or `[section]` is a hard error naming the alternatives. Values are range-checked. Zero stays legal where it means something (`kill_grace_sec = 0`, `refresh_interval_sec = 0`).

## The sockets belong to their units

- Under socket activation the daemons are handed a listening descriptor and never reach the bind path, so `ListenStream=` and `SocketMode=` are what a socket is.
- No config key is a file mode. `--check` and `doctor` stat the bound socket for its mode rather than reading one.
- `socket_path` stays, because the broker *dials* the keeper and the executor at it, and because a daemon run outside systemd binds it itself. `init` renders it alongside the unit and a drop-in setting it is refused, moving it otherwise disconnecting the broker from a daemon still listening where it always was.
- The broker binds its own ssh-agent socket. Its mode is a constant beside the code that sets it rather than a value a drop-in could widen past the group `exec_group` names.

## Drop-ins

`/etc/faramir/config.d/*.toml` merge over the base in lexical order. `config.toml` is faramir's own and `init` rewrites it every run, so an edit there is replaced without warning; `init` never touches a drop-in. Tables merge key by key, so one `[secrets] files` does not discard `min_length` and one `[exec.base_env]` variable does not mean restating `PATH`. Scalars replace.

What a drop-in may set is the defaults `init` does not derive:

Section | Keys
--- | ---
`[exec]` | all of them, `default_timeout_sec` being the one to reach for when a command outruns ten minutes
`[exec.base_env]` | all of them, and the one you reach for most: the child inherits nothing else
`[secrets]` | `files`, `refresh_interval_sec`, `min_length`. Not `decrypt_command`, which the base file sets and a second source is refused for
`[server]` | `max_concurrency`, `max_request_bytes`
`[audit]` | `max_record_bytes`
`[sudo]` | `timeout_sec` alone, and only on a host installed with `--allow-sudo`. The rest of the section is the approval boundary itself, below

## What init derives, a drop-in may not set

The rule is the value's provenance, not its section: a value `init` computes from a flag or from the install is `init`'s and is refused outright; a value it writes as a plain default is a starting point, and yours.

Key | Flag it derives from
--- | ---
`[server] socket_path`, and the same on `[keeper]` and `[executor]` | rendered with the `.socket` units
`[server] allowed_group` | `--client-group`
`[keeper] allowed_user`, `[executor] allowed_user` | `--broker-user`
`[keeper] age_key_file` | `--config-dir`
`[keeper] age_key_credential` | rendered with the keeper unit's `LoadCredential=`
`[ssh] ssh_agent`, `[ssh] ssh_add` | resolved on `PATH` at install time; the broker execs them as its own uid
`[ssh] key` | `--ssh-key`
`[ssh] exec_group` | `--exec-user`, resolved to that account's own group at install time
`[ssh] agent_socket`, `[audit] log_path` | no flag: `/run/faramir` and `/var/log/faramir`, fixed at build time. The audit log does not follow `--config-dir`, `{{.LogDir}}` being the broker unit's `ReadWritePaths`
`[sudo] exec_user`, `pam_service`, `helper` | `--allow-sudo` (see below)

Each is one value, matching the one flag behind it. Two cost something rather than being tidiness: `exec_group` is the group the agent relay's `SO_PEERCRED` check admits, so a drop-in naming the client group there hands the broker's SSH identity to the account the relay exists to keep it from; `ssh_agent` and `ssh_add` are binaries the broker execs as the uid holding every plaintext value. `log_path` is rendered into `logrotate.conf` alongside, so moving one leaves rotation pointed at a file nothing writes.

**The whole of `[sudo]` but `timeout_sec` is `init`'s, because it is the approval boundary itself, decided per host at install time.** Whether the section is rendered at all is the `--allow-sudo` flag ([operating.md](operating.md#the-decision-is-made-at-init-per-host) has the decision): unset, there is no `[sudo]` section, no sudoers entry and no PAM service, and a brokered command's `sudo` fails as on any host that granted nothing. Set, `exec_user` is the account the grant is written for, `pam_service` names the file `sudo` authenticates it through (so a drop-in pointing it at a service the operator wrote would choose what decides every approval), and `helper` is the program PAM execs, as root, to make that decision. A drop-in setting any of them is refused; re-run `init --allow-sudo` to change the arrangement, or re-run without it to take the grant away. `timeout_sec` is a plain default and yours: how long a question waits for a human before it is refused. `notify_command` is unset by default and is `init`'s only because the broker execs it; it announces a pending question and carries no answer.

Everything else is a default. Lists among them split by what they are:

What | Rule | Why
--- | --- | ---
`[secrets] files` | **accumulates**, duplicates collapsed | An inventory with one entry per owner. Replacing would leave the broker holding fewer files than its operator believes, injecting and redacting nothing for the loser. Entries are glob patterns, deduplicated again after expansion, so a drop-in naming a file the base already globs adds nothing.
`[secrets] decrypt_command` | **refused** when two sources set it, naming both | Policy, and the only list left that is. Accumulating would hand the keeper a second way to invoke sops by writing a file that never said so; taking the last would make it depend on filename order.

- Validation runs after merging, so a drop-in is held to every rule the base file is. `faramir status` and `faramir broker --check` report `configs`: the base file and every drop-in that contributed, in merge order.
- Dotfiles are skipped, so an editor's `.#name.toml` lock does not stop the daemons starting.

## The install gate, and the same gate at startup

`faramir broker --check` exits non-zero on anything that leaves the broker protecting less than it appears to.

Fails on | Because
--- | ---
An unknown key or `[section]` | A config that reads as though it took effect.
A value out of range | Same.
A ref too short to redact | Refused at load, so covered by nothing.
A `[secrets] files` entry that named nothing, or a file it named that did not load | Those values are absent from the redactor. A pattern that matches no file is the same failure as a literal path that is not there.
An `[ssh] key` the agent cannot load, passphrase-protected or not on disk | `ssh-add` refuses it, leaving every host unreachable. `init` catches one missing, unreadable by the broker, or without its `.pub`.
A `[sudo] helper` or PAM service file that is not there, or a `notify_command` that is not installed | The same weighting as the key: approval is configured and either every request fails with `sudo` reporting an authentication error, or nothing announces the questions that are waiting.
`[keeper]` or `[executor] allowed_user` naming an account that is not the broker | Each socket has one legitimate client. The keeper's is the age key by another route, and the executor's runs a command with no policy, no redaction and no audit record. The socket modes still stand in the way, so this is the second of two locks, and a gate that waits for both to be open reports the problem afterwards.
The bound broker socket having world bits | Every account on the host reaches the broker, whatever `allowed_group` says. Stat'ed, not read from the config, so it reflects what the `.socket` unit actually did. Unbound is reported as unchecked.

Secrets on a filesystem that is not mounted yet look exactly like ones never written, and both leave the broker redacting nothing. `--check` and `doctor` tell the two apart.

Run it as the broker's own account, `sudo -u faramir-broker faramir broker --check`, which needs no `-c`: sudo clears `FARAMIR_CONFIG`, and the unit is the next step. Run as root it reads what the broker cannot, and a key left `root:root` then passes a gate the broker fails on; the `allowed_user` check is skipped there too, since from root every name compares unequal. `faramir doctor` makes the same check knowing the account names.

**The daemon holds itself to the same rules, and on every request rather than at boot.** `--check` is run by `init` and by `doctor`, and neither runs at boot, so on its own it only ever described the host as it was at install time.

For the secrets it is one rule, and `exec` is held to it because a brokered command's output is redacted against the same set: **the broker serves `exec` and `redact` only while no managed file went unread.** At least one `[secrets] files` entry matched a file, and every matched file loaded.

- What those files held does not enter into it. An install whose operator has not written a secret yet serves, and a ref no file defines is answered by `unknown_secret`.
- Otherwise the broker refuses with `no_secrets`, naming why. It comes up either way, and `status` and `list_secrets` answer regardless, neither depending on the value set.
- Checked per request, so a reload that loses a file later is caught too.
- A keeper that could not be reached is the exception once a set has loaded, what is kept then being the last thing known to be true. A cold start has nothing to keep and refuses.

An `[ssh] key` the agent does not load is logged and not fatal. A value set the broker does not fully hold endangers the output of every command, so those are refused; a key the agent does not hold breaks only commands that reach a managed host, and those fail at the point of use with `ssh`'s own error. Stopping the daemon over it would stop the commands that never touch SSH and remove the process `status` and `doctor` ask. `--check` and `doctor` fail on it, which is where you find out without waiting for a playbook to.

An unset `[ssh] key` is not a failure, being the host that authenticates some other way.

## What no setting changes

- **Nothing the broker starts receives the age key.** No flag grants it; the broker does not hold it to grant. This bounds brokered commands and the agent, not root.
- **Secrets are injected as environment variables only.** Never into `argv`, which is visible in `ps` and `/proc/<pid>/cmdline`.
- **`cmd` is an array.** Never a string handed to `sh -c`.
- **The broker runs the working tree as it is on disk.** No promotion step.
- **Nothing runs sudo without a human, and no setting widens what one approval covers.** An approval is scoped to the brokered command it was shown for and dies with it; whether a host may sudo at all is the `--allow-sudo` install-time decision, not a config key. A `notify_command` that cannot announce is a refusal waiting to be seen, not a pass.
- **Every run is confined to a cgroup and reaped there.** Not a setting: `init` renders `Delegate=` on the executor unit so a real host confines. With no delegated cgroup (needs cgroup v2 and `cgroup.kill`, kernel 5.14 or newer) the executor refuses to run rather than degrade, on every host, a sudo grant or not, and `faramir doctor` fails such a host. [design.md](design.md#allowing-sudo-on-the-controller) has why there is no fallback.
- **`redactions` reports counts, not values.** `log_id` names the audit record, which holds the same tokens.
