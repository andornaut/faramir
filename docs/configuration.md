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
`--command-max-memory-percent` | `[command] max_memory_percent` | 50 | 10 to 100, rendered as `MemoryMax=` on the executor unit. A percentage because nothing here knows how much memory the host has, and a default has to mean the same thing on a laptop and on a build host. The kernel enforces it and chooses a victim inside the executor's cgroup, so a command that runs away is a failed command rather than a host that fell over; one ceiling for every brokered command at once, not one per child. 100 is the whole machine, which is the same as no bound. A cgroup counts page cache toward this, so a command that reads or writes a lot reaches the limit without holding anything: cache is reclaimable and the kernel reclaims it before it kills, so a source build meets this as reclaim and a process that has actually allocated the memory meets it as the OOM killer. Size it against what a command allocates rather than against a cgroup's `memory.peak`, which totals every process in it and is mostly cache. Read by `init`, so a change to the key alone does not reach the unit until the next `sudo faramir init`
`--escalation-timeout-sec` | `[escalation] timeout_sec` | 120 | 1 to 600
`--secret-min-length` | `[secret] min_length` | 8 | at least 6
`--secret-min-refresh-sec` | `[secret] min_refresh_sec` | 1 | at least 1. A minimum, not a schedule: the check runs when a command arrives and nothing polls in the background, so an idle host costs nothing. It bounds the keeper round trip only; linked files are stat'ed on every request

`[[secret.link]]` is the eighth thing the file carries and is `faramir link`'s, [below](#linked-secrets). `[[secret.block]]` is the ninth and is `faramir block`'s, [below that](#blocked-paths).

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

**Each of the three is idempotent**, so a configuration manager may run them on every converge. Adding the entry this install already carries re-applies it: the deny rules and the config are rendered again, the file's access is checked again, `--json` reports `changed: false`, and the daemons are reloaded only where something did change. Removing a ref it does not carry writes nothing. The one thing refused is the same ref against a different file, type or key, naming both definitions: a ref has one, and answering by replacing the entry would change which credential every caller of that name receives.

**The order is the command's own and it matters.** Every question is asked before the entry is written, and nothing about the file is altered to make an answer come out right: `link add` asks the running broker whether it already serves that ref, checks that the file is arranged the way a link needs, then reads it as the broker's own account to check the selector yields a value, and only then writes the entry. The first of those needs a broker that answers, and `link add` refuses rather than skipping it where none does: an entry claiming a name the store already answers refuses every brokered command on the host, and one written while nothing could check arrives at a moment nobody chose. `refs` answers on a host with no secrets yet, so this locks out no first install. A file that is not arranged that way is reported with the commands that fix it, and no entry is written.

Entries live in `config.toml` beside everything else, and `init` reads them back before rewriting the file, so each deny rule is re-asserted and each file re-checked on every run. That is what catches an arrangement a tool took away.

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
`ref` | The name a caller asks by, in the same namespace the sops store uses. Nothing marks a ref as linked: where a secret is kept is not part of its name, or moving one into the store later would rename it, and every `faramir.env` naming it with it. A link claiming a ref the store already defines is refused by `link add`, before an entry is written. One that reaches the config another way is refused the way a managed file that did not load is, and for the same reason: the managed value is what callers get, and the linked file then holds a second value for that name which nothing reads and nothing redacts.
`path` | Absolute. No `~`, which nothing expands here: the broker runs as its own account, so a home would be the wrong one. No control character either: the path is rendered into the deny rules, one rule to a line, and a newline in it splits the rule into halves that will not compile and are skipped.
`type` | `text` or `base64` for the whole file, `json`, `yaml`, `toml` or `ini` to select out of it.
`key` | Required for the four that select, refused for the two that do not. Held to the same bytes as `path`, `faramir link ls` printing it back to a terminal. `a/b/c` walks a tree the way a sops ref does, a number indexing a list; `ini` matches the whole key instead. [Selectors, escaping and the per-tool recipes](integrations.md#linking-a-credential-another-tool-owns).

**faramir checks this arrangement and does not apply it.** The file and every directory above it are the operator's, and faramir does not change the ownership or mode of a path it does not own; whoever manages the host's permissions sets them, and `link add`, `init` and `doctor` each report what is wrong with the command that fixes it.

Path | Has to be
--- | ---
the linked file | the broker's own group and group-readable, and readable by nobody else. The owner and the owner bits are the operator's business. That group holds one account, which is what keeps the executor out
every directory above it, down from the home | enterable by the client group. Traversal is not read, and never `chmod o+x`, which grants the same to every account on the machine

Why it is shaped this way (one ref per entry rather than a whole-file flatten, the broker reading these rather than the keeper, and modes rather than an ACL) is in [design.md](design.md#linked-secrets-are-read-by-the-broker). What follows is what it costs you day to day.

- **Every linked path is refused to the agent's file tools.** `link add` and `init` both render them into the account-wide deny rules, and `faramir doctor` fails on a linked file that is not refused. Pi refuses them from its extension instead, having no account-wide rule file for one to be rendered into.
- **A tool that replaces its own file rather than rewriting it takes the group with it.** A temp file renamed over the original is created fresh, and `0600` on creation leaves nothing for a group to read. `faramir doctor` asks the broker's own account whether it can still read each file, and `init` and `link add` check it again on every converge.
- **A repair needs a restart, and nothing performs one for you.** The broker fingerprints a linked file by mtime and size, and a `chgrp` changes neither, so its view of a file it gave up on stands until it is restarted: `sudo systemctl restart faramir-broker` after fixing one. `init` and `link add` do not do it either, both restarting the daemons only when they changed something and neither of them changing a file it does not own.
- **A link that does not load refuses that ref and nothing else.** The broker goes on serving every other ref, and a command that asks for this one is refused by name. Both cases reach it: a file that is gone, and one that is there and will not read. `faramir status` names the ref and exits non-zero, and `faramir doctor` fails, which is what tells you before a command does.
- **The unreadable case is the one that costs something.** The plaintext is still on disk while the redactor does not hold it, so that value can print in the clear through anything that touches the file. The broker cannot cover a value it does not have, and withholding every command's output over it takes out commands with no relationship to the credential, so it says which ref is missing instead of stopping. A file that is *gone* costs nothing: there is no plaintext left to cover.

## Blocked paths

A `[[secret.block]]` entry blocks one thing from the agent, for a credential faramir has no use for the value of: a LUKS keyfile, an SSH identity. A `path` or a `name` is kept from its file tools and its shell alike; a `command` is kept from the shell alone, a command being nothing a file tool can name. [When to reach for one](integrations.md#where-the-value-lives).

```sh
sudo faramir block add --path /etc/luks/volume.key   # this file, on this host
sudo faramir block add --name '*.htpasswd'           # any file of that name, anywhere

# Each argument and each --name is one entry, and one command writes them all
sudo faramir block add --name id_rsa --name '*.pem' --name '.env*'

# A command, for what a tool does rather than for a file it names
sudo faramir block add --command 'op read' --command 'pass show'
```

**Each form is named by its own flag, and one entry is one form.** A bare argument is refused rather than read as a path: the three block different things, and an operator who means every file of a name would otherwise get a rule about one file on this host.

**A path and a name are not the same rule.** A path refuses the file at that path. A name is matched against the path the agent names rather than against this host's filesystem, which is what reaches a path the host does not have: a container mounts `/srv/ha/config` as `/config`, the agent names the second, and a rule carrying the first covers nothing it runs. Naming both in one entry is refused rather than answered by picking one.

Name | Matches
--- | ---
`auth` | any file called `auth`, in any directory
`.storage/auth` | that file inside any directory called `.storage`, and no sibling of it
`*.htpasswd` | any file whose name ends that way
`.env*` | any file whose name starts that way
`secrets*.yml` | any file whose name matches, the wildcard not crossing a directory
`.storage/` | everything under any directory of that name

Which of the five a pattern is comes from its shape, and `block add` prints what it read before writing it. That inference is safe where inferring path-from-name would not be: the shapes differ in breadth, and reading one as another refuses more or fewer files of the same kind, while an inferred path could turn a typo into a rule that silently matches nothing.

**The two forms fail in opposite directions.** A mistyped path refuses one file, and the file stays readable until somebody notices. A pattern that matches more than it was meant to refuses a class of files at once, and nothing announces it: the agent meets it as file tools failing on files nobody discussed. So a pattern that matches everything is refused at load the way `/` is as a path, and what a pattern will match is printed as it is written rather than left to be discovered.

**A path or a name covers both entry points.** The agents' deny rules and the command guard's patterns are rendered from one set, so a declared path or name refuses a file tool and `cat` alike, and `faramir init` re-asserts both. A command covers the shell alone, being nothing a file tool can name.

**A rule matches the command as it was written.** The guard reads the text of a command and has no working directory to resolve a relative path against, so `cat /srv/keys/luks.key` is refused and `cd /srv/keys && cat luks.key` is not, and neither is a path the shell assembles from a variable. A managed or a linked value is covered whichever route reads it, an enrolled tree rewriting the command so its output is redacted on the way back; a blocked path holds no value faramir has read, so the refusal is the whole of what it adds. Where a file has to be beyond reach whatever is typed, the mode on it is what holds: this rule refuses a name, not an `open(2)`.

**It is the weaker of the two entries.** A link reads the file, so it does three things this one cannot:

What happens to the file | `[[secret.link]]` | `[[secret.block]]`
--- | --- | ---
refused to the agent's file tools | yes | yes
held to the broker's group, so a brokered command is refused it too | yes, checked and reported | no, the mode is nobody's business here
the value in the redactor, tokenised wherever it appears | yes | no, faramir never reads it
injectable by ref | yes | no

So a command the broker runs may still open a blocked path, and print it in the clear. The deny rules stop the agent's own shell and its file tools; a brokered command is a different uid running with the operator's consent, and nothing of the refused file is in the redactor to cover its output.

Key | Rule
--- | ---
`command` | A command the agent's shell may not run, written as it would be typed: `op read`, `sops -d`. The words are literal and the space between them matches any run of whitespace, so there is no pattern to get wrong. It reaches the command guard and no agent's file-tool rules, a command not being a path. A single-character word is refused, matching nearly every command line.

**Matched where a command starts**, not wherever the words appear: after a separator, a pipe, a subshell, an assignment, `sudo` and its kin, or a shell's `-c` string. So `pass` is safe to declare on its own, where matching anywhere would have refused every `ansible-playbook --ask-become-pass`, and a `grep` naming a declared command is left alone. The cost is the other way round: a command reached through a wrapper the anchor does not know is missed. That is the better error for a list [the design says is not the boundary](design.md#three-layers), which is there to catch an accident, and an accident is typed rather than wrapped
`path` | Absolute, and in its shortest form: a rule matches the path as written, so `/etc/./k` and `/etc/k` are two rules of which one matches nothing. A path under a home is refused in the spellings a shell expands to it as well: `~/`, `$HOME/` and `${HOME}/`, which is how a person and a model both write one. No `~`, which nothing expands here. `/` is refused, being every file on the host
`name` | A name, suffix, prefix, wildcard name or directory, per the table above. Not absolute, which is a path; no `~` and no `..`, nothing resolving either here; no `**`, a name matching in any directory already. A pattern with nothing left once the wildcards and separators are taken out is refused, being every file on the host

- **An entry carrying a control character is refused**, in all three forms. A rule is one line of a generated file and the entry is written into it, so a newline ends that rule early and starts a second line with the rest: neither half is the rule that was asked for, both are unbalanced expressions the guard cannot compile, and a rule that will not compile is skipped. The entry meant to refuse one more file would take the rules protecting the install with it. The rest of the controls are refused because a listing prints an entry back to a terminal, which obeys what it is sent. `faramir doctor` fails on any rendered rule that will not compile, whatever wrote it.
- **A path that is not there is still recorded**, and you are told. The rule costs nothing while the file is absent and holds once the volume mounts, which is the case these exist for. A path spelled wrong looks the same, so the message says both.
- **A name is not asked of the filesystem at all**, having nothing on this host to be asked about. What it will match is printed instead.
- **`faramir block ls` is the answer to "what is blocked here".** The declared entries in a table of kind and entry, and under it the rules faramir carries itself: this install's own directories, and the command rules about its binary, the files an enrolment installs, and the commands that act on the install rather than through it. The kind is one of three, `name`, `path` or `command`, and where a rule is enforced follows from it rather than being printed beside it. The table and each built-in section are sorted by kind and then by entry; `link ls`, `reader ls` and `vault ls` by ref, key and name. Neither half can be asked any other way, a refusal naming the rule that matched rather than the set. `--declared` narrows it to the entries the config carries, which is the list a configuration manager converges, and `--built-in` to the half faramir renders from its own layout, which no entry names.
- **An entry covers the path and everything under it**, whether or not it is a directory today. The filesystem is not asked: these rules are a function of the config alone, or a key on an unmounted volume would render no subtree rule and gain one when it mounts. The subject is bounded, so `~/.sshrc` is not part of `~/.ssh`.
- **A path this install occupies cannot be unblocked, and asking fails.** `block rm /etc/faramir/age.key` names a rule the layout renders on every run rather than an entry this install carries, so there is nothing to remove and the host goes on blocking it; reporting that as "nothing removed" would read as the file becoming readable. Where an install declared the same path as well, its entry is removed and the directory is named as what still blocks it. Nothing else is unremovable: no rule is compiled in.
- **Nothing is reloaded.** No daemon reads these entries, so `block add` does not restart the broker under a running command.
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
A ref too short to redact | Refused at load, so covered by nothing. `init` warns and carries on, an install being unable to lengthen a secret; `doctor` fails on it, a refused value being injected by nothing and covered by nothing
A `[[secret.link]]` entry whose file is not there, or is there and did not read | The same two meanings, reported with the ref in front. The second is what an ACL dropped by a tool rewriting its own file looks like
An `[ssh] key` the agent cannot load | `ssh-add` refuses it, leaving every host unreachable. Passphrase-protected, unreadable, or pointed at the `.pub`
An `[escalation] helper` or PAM service file that is not there, or a `notify_command` that is not installed | Escalation is configured and either every request fails with `sudo` reporting an authentication error, or nothing announces the questions waiting
`[keeper]` or `[executor] allowed_user` naming an account that is not the broker | Each socket has one legitimate client. The keeper's is the age key by another route; the executor's runs a command with no policy, no redaction and no audit record
The bound broker socket having world bits | Every account on the host reaches the broker, whatever `allowed_group` says. Stat'ed rather than read from the config. Unbound is reported as unchecked
An audit log that cannot be written | A command that cannot be recorded is not run

**The daemon holds itself to the same rules, and on every request rather than at boot.** `--check` is run by `init` and by `doctor`, and neither runs at boot, so on its own it only ever described the host as it was at install time.

For the managed store it is one rule, and `run` is held to it because a brokered command's output is redacted against the same set: **the broker serves `run` and `redact` only while no managed file went unread.** Every managed file that was there loaded. Matching none is not this: a value set that is empty holds nothing for output to carry, so the broker serves and says so.

**A `[[secret.link]]` entry is scoped to its own ref instead**, and that is the whole of the difference between them: a managed file holds any number of refs and names none of them until it decrypts, so one that did not load leaves the broker knowing values are missing and not which. A link is one ref by construction, so the broker refuses that ref and serves the rest. The exception is a link claiming a ref the managed store already defines, which is refused the way a managed file is: that ref is answered by the store, and what is missing is the second value the linked file holds for the same name.

- What those files held does not enter into it. A ref no file defines is answered by `unknown_secret`.
- **An empty value set serves.** Nothing configured, a store not written yet, a store that matched no file, and an install whose links have all gone: none of them holds a value output could carry, so all of them run commands. The broker logs it at startup, `status` reports `count: 0` beside the pattern that named nothing, and `doctor` warns.
- Otherwise the broker refuses with `no_secrets`, naming why. It comes up either way, and `status` and `refs` answer regardless.
- A keeper that could not be reached is the exception once a set has loaded, what is kept then being the last thing known to be true. A cold start has nothing to keep and refuses, that being a broker that cannot ask rather than one with nothing to hold.

- Secrets on a filesystem that is not mounted yet look exactly like ones never written, and both leave the broker redacting nothing. Both now serve, so this is the case the warning is for: nothing inside the broker can tell them apart, and `status` and `doctor` are where an operator sees it.
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
