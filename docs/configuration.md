# Configuration

There is one config file, `<config-dir>/config.toml`, and faramir owns it. `faramir init` renders it from [etc/config.toml.tmpl](../etc/config.toml.tmpl) on every run. There are no drop-in files and no merging: every value is either set by a flag or derived from the install.

## What bounds a brokered command

There is no command allowlist. Four things limit what a brokered command can do:

Setting | Effect
--- | ---
`[command.env] PATH` | Where a bare program name is looked up, and the only `PATH` the child gets.
`[command] max_timeout_sec` | How long a command may run.
`[secret] min_length` | A value too short to redact is refused at load, so nothing can inject it. There is no matching maximum setting: a value of 16 KiB or more is always refused, being more than the broker will hold.
the executor's uid | The real bound.

## The file is rewritten on every `init`

`init` renders the whole file each run. Before it writes, it reads the old file and takes some values from it. Those values survive; everything else is rendered fresh.

Edited by hand | Survives an `init`? | Why
--- | --- | ---
Any setting under [what a flag sets](#what-a-flag-sets) | **Yes**, unless you name the matching flag on that run | `init` reads these back so a bare re-run keeps the install instead of reverting it. A flag beats what the file says.
`[[secret.link]]` and `[[secret.block]]` entries | **Yes** | No flag reaches them: `faramir link` and `faramir block` write them. Reading them back is what stops a plain `init` from erasing every deny rule they added.
A **new** `[command.env]` variable | **Yes** | The environment merges: the file first, then anything a flag names on top.
A **deleted** `[command.env]` variable | **No**, it comes back | The built-in table sits under that merge. There is no way to unset a built-in variable.
Comments, ordering, whitespace | **No** | The whole file is rendered, so you get the template's.
Anything under [what is derived](#what-is-derived) | **No** | Re-derived from the install every run. The account names come from the units' own `User=` rather than from the file, so editing `allowed_user` changes nothing.

Two things follow:

- **Use the flag, not the edit.** A flag is written into the file and read back next run. An edit to a derived value is discarded on the next `init` without a word, and until then the daemons are using what you typed.
- **A file that does not parse stops the run.** `init` reads the old config before writing, so a hand edit that will not load is refused rather than replaced. No daemon can load it either, and overwriting it would destroy the evidence. Fix the file, or delete it to install fresh.

**One value is not read back: `[sudo] notify_command`.** A bare `init` drops whatever `--notify-command` set on the previous run, so name the flag again on every run.

## What a flag sets

Each of these is written into the file and read back on the next run.

Flag | Key | Default | Bounds
--- | --- | --- | ---
`--command-env NAME=VALUE` | `[command.env] NAME` | `PATH`, `TERM`, `LANG`, `LC_ALL`, `DEBIAN_FRONTEND` | Repeatable, and it **adds**: naming one variable keeps the rest. `PATH` may not be empty, and every component must be absolute.
`--command-timeout-sec` | `[command] timeout_sec` | 600 | At least 1. Zero would kill every command as it started.
`--command-max-timeout-sec` | `[command] max_timeout_sec` | 3600 | At least 1, and not below `timeout_sec`. A lower value would silently replace `timeout_sec` for every command.
`--command-concurrency` | `[command] concurrency` | 10 | 1 to 16, the most the executor forks at once. `init` refuses a negative value and anything above 16, where the surplus is refused by the executor *after* the run was recorded as started. Zero is the unset signal, so `--command-concurrency 0` installs the default.
`--command-max-memory-percent` | `[command] max_memory_percent` | 25 | 10 to 100. Rendered as `MemoryMax=` on the executor unit.
`--command-max-process-memory-mb` | `[command] max_process_memory_mb` | 4096 | 256 to 1048576. Rendered as `LimitDATA=` on the executor unit and inherited by every child.
`--sudo-timeout-sec` | `[sudo] timeout_sec` | 120 | 1 to 600. How long a sudo question waits for a human.
`--secret-min-length` | `[secret] min_length` | 8 | At least 6. Counted in characters, not bytes.

On a host that grants sudo, the `[command.env]` variables are also written to `/usr/local/libexec/faramir/sudo-env`, so a command keeps them across `sudo`: `env_reset` discards what the caller held, and this file puts them back from somewhere the caller cannot write. Not all of them survive. `HOME`, `PATH` and `SUDO_*` stay sudo's own, because sudo sets those itself and this file only adds what sudo did not. A name that is not a valid variable name, or a value holding a newline or a `#`, is [left out with a warning](escalation.md#what-a-brokered-command-keeps-across-sudo).

### The two memory settings

They do different jobs, and both are read by `init`: changing either key alone does not reach the systemd unit until the next `sudo faramir init`.

- `max_memory_percent` is the **backstop**. It is a cgroup total for every brokered command at once, so it cannot tell one process holding everything from twenty holding a fair share each, and it counts page cache. What it catches is fan-out, which no per-process limit sees. It is a percentage because nothing here knows how much memory the host has. Cache is reclaimed before anything is killed, so a source build meets this as reclaim while a process that really allocated the memory meets the OOM killer. 100 means the whole machine, which is the same as no bound.
- `max_process_memory_mb` is the **bound**. A runaway command is usually one process asking for far more than a real one, and this refuses it. Anonymous memory only, so a command is never charged for page cache. A process that reaches the limit gets an allocation failure it can report, rather than being picked by the OOM killer.

### Why `--secret-min-length` has a floor of 6

The two failure directions are not equal. A value refused for being too short is absent from the redactor and reaches output in the clear. A value matched too eagerly only mangles the operator's own text. The first direction leaks, so the floor is low. Note that `password` is eight characters, so the default of 8 is not as safe as it looks. See [what the gate is for](redaction.md#the-pipeline-in-order).

The file carries two more things, and no flag writes either: [`[[secret.link]]`](#linked-secrets) entries, written by `faramir link`, and [`[[secret.block]]`](#blocked-paths) entries, written by `faramir block`.

## What is derived

Everything else. `init` computes these from the install and rewrites them every run.

Key | Derived from
--- | ---
`socket_path` on `[server]`, `[keeper]`, `[executor]` | Rendered alongside the `.socket` units
`[server] allowed_group` | `--client-group`
`[server] agent_user` | `faramir init --agent-user`, then `$FARAMIR_OPERATOR`, then `$SUDO_USER`, then you. No other command takes this flag: they all read this key instead, so adding an entry cannot rename the host's owner. Passed to every brokered command as `FARAMIR_OPERATOR`, and to its `sudo` through the environment file its PAM service reads
`[keeper] allowed_user`, `[executor] allowed_user` | `--broker-user`
`[keeper] age_key_file` | `--config-dir`
`[keeper] age_key_credential` | Rendered alongside the keeper unit's `LoadCredential=`
`[ssh] key` | `--ssh-key`
`[ssh] exec_group` | `--exec-user`, resolved to that account's own group
`[ssh] ssh_agent`, `[ssh] ssh_add` | Resolved on `PATH` at install time. The broker runs them as its own uid
`[ssh] agent_socket`, `[audit] log_path` | No flag: `/run/faramir` and `/var/log/faramir`, fixed in the binary
`[sudo] exec_user`, `pam_service`, `pam_stack`, `helper` | `--allow-sudo`. `pam_stack` is the file carrying faramir's PAM stack on this host, which is not always what `pam_service` names: see [the two sudos](escalation.md#the-two-sudos)
`[sudo] notify_command` | `--notify-command`, repeatable, one argument per flag. Must contain `{prompt}` or `{id}`, or it would announce that something is waiting without saying what

## What is not a key at all

Nine values are constants in the binary. No install ever sets them.

Value | Is
--- | ---
`max_output_bytes` | 256 KiB, roughly 64k tokens. It limits how much text reaches the model, so it belongs to the conversation rather than to the host. Truncation is reported, not silent
`max_request_bytes` | 256 KiB. The largest request line the broker socket will read, a guard against a malformed request rather than a size anyone chooses
`max_record_bytes` | 256 KiB. The largest one audit record's line may be, counted in encoded bytes. A record keeps the head and tail of the output and cuts every other field to fit, so a long command degrades its record rather than failing to write one
`term_cols`, `term_rows` | 120x40. The PTY size every child gets, which decides where a program wraps its own output
`kill_grace_sec` | 5 seconds between SIGTERM and SIGKILL. This window only opens once a command has already overrun its timeout
`min_refresh_sec` | 1 second. The soonest the broker asks the keeper again whether a managed file changed, checked when a command arrives rather than on a timer, so an idle host makes no round trip. Not a setting because every larger value is worse: the check costs one stat per managed file, and what a longer interval buys with that is a wider window in which a value rotated outside faramir is still missing from the redactor. Linked files are not on this clock at all; they are stat'ed on every request
the managed store | `<config-dir>/secrets/` matching `*.sops.yml`. Derived from where the config sits, so the store cannot be pointed at a checkout. What the agent cannot open is the directory, which the deny rules name by path
the decrypt command | sops, invoked one way. A second way would be a second thing that could be pointed elsewhere by the account holding the age key

## Linked secrets

A `[[secret.link]]` entry reads one secret out of a file that another tool maintains, instead of copying it into the managed store. See [when to reach for one](integrations.md#where-the-value-lives).

```sh
sudo faramir link add gh/token ~/.config/gh/hosts.yml \
    --type yaml --key github.com/oauth_token
```

That is the whole interface. The [three link commands](operating.md#operator-commands) are the only way these entries get written. The entry looks like this:

```toml
[[secret.link]]
ref  = "gh/token"
path = "/home/operator/.config/gh/hosts.yml"
type = "yaml"
key  = "github.com/oauth_token"
```

Field | Rule
--- | ---
`ref` | The name a caller asks by, in the same namespace the sops store uses. Nothing marks a ref as linked: where a secret is kept is not part of its name. If it were, moving one into the store later would rename it, and every `faramir.env` that names it would have to change too. A link claiming a ref the store already defines is refused by `link add` before any entry is written.
`path` | Absolute. No `~`: nothing expands it here, and the broker runs as its own account, so a home directory would be the wrong one. No control characters either, because the path is rendered into the deny rules one rule per line, and a newline would split the rule into two halves that will not compile.
`type` | `text` or `base64` for the whole file. `json`, `yaml`, `toml` or `ini` to select a value out of it.
`key` | Required for the four types that select, refused for the two that do not. Held to the same character rules as `path`, because `faramir link ls` prints it to a terminal. `a/b/c` walks a tree the way a sops ref does, and a number indexes a list; `ini` matches the whole key instead. See [selectors, escaping and the per-tool recipes](integrations.md#linking-a-credential-another-tool-owns).

### The three commands are idempotent

A configuration manager can run them on every converge. Adding an entry the install already has re-applies it: the deny rules and the config are rendered again, the file's access is checked again, `--json` reports `changed: false`, and the daemons reload only where something actually changed. Removing a ref that is not there writes nothing.

The one thing refused is the same ref pointing at a different file, type or key. The error names both definitions. A ref has one definition, and answering by replacing the entry would change which credential every caller of that name receives.

### `link add` asks everything before it writes

Nothing about the file is altered to make an answer come out right. In order, `link add`:

1. Refuses a ref this install already defines against a different file, type or key.
2. Requires the file to be there.
3. Reads it as root, to confirm the type and the key yield a value.
4. Asks the running broker whether it already serves that ref.
5. Checks that the file is arranged the way a link needs.
6. Reads it again as the broker's own account, to confirm that account can reach the value.
7. Writes the entry.

[Why there are two reads, and in that order](integrations.md#linking-a-credential-another-tool-owns).

Step 4 needs a broker that answers, and `link add` refuses rather than skipping it. An entry claiming a name the store already answers would refuse every brokered command on the host, and one written while nothing could check arrives at a moment nobody chose. `refs` answers on a host with no secrets yet, so this locks out no first install. A file that is not arranged correctly is reported along with the commands that fix it, and no entry is written.

`init` reads these entries back before rewriting the file, so every deny rule is re-asserted and every file re-checked on each run. That is what catches an arrangement some other tool took away.

### The permissions a link needs

**faramir checks these and does not apply them.** The file and every directory above it belong to the operator, and faramir does not change the ownership or mode of a path it does not own. Whoever manages the host's permissions sets them; `link add`, `init` and `doctor` each report what is wrong along with the command that fixes it.

Path | Has to be
--- | ---
The linked file | Owned by the broker's group and group-readable, and readable by nobody else. The owner and the owner bits are the operator's business. That group holds one account, which is what keeps the executor out
Every directory above it, down from the home | Enterable by the client group. Traversal is not read access. Never `chmod o+x`, which grants the same to every account on the machine

Why it is shaped this way, with one ref per entry rather than a whole-file flatten, the broker reading these rather than the keeper, and modes rather than an ACL, is in [design.md](design.md#linked-secrets-are-read-by-the-broker).

### Keeping a link working

- **Every linked path is refused to the agent's file tools.** `link add` and `init` both render them into the account-wide deny rules, and `faramir doctor` fails on a linked file that is not refused. Pi refuses them from its extension instead, having no account-wide rule file to render into.
- **A tool that replaces its own file rather than rewriting it takes the group with it.** A temp file renamed over the original is created fresh, and mode `0600` on creation leaves nothing for a group to read. `faramir doctor` asks the broker's own account whether it can still read each file, and `init` and `link add` check again on every converge.
- **A repair needs a restart, and nothing does it for you.** The broker fingerprints a linked file by mtime and size, and `chgrp` changes neither, so its view of a file it gave up on stands until you run `sudo systemctl restart faramir-broker`. `init` and `link add` restart the daemons only when they changed something, and neither of them changes a file it does not own.

### When a link breaks

**A link that does not load costs that one ref.** The broker refuses that ref by name and goes on serving every other one. Both failures reach this: a file that is gone, and a file that is there and will not read.

This is the whole difference between a link and a managed file. A managed file holds any number of refs and names none of them until it decrypts, so one that did not load leaves the broker knowing values are missing but not which, and it stops serving. A link is one ref by construction, so the broker can name it and keep going.

What reports it:

- `faramir status` names the ref and exits non-zero.
- `faramir doctor` fails, which is what tells you before a command does.
- `faramir init` reports it and finishes. The fault is in one credential, the config for this run is already written, and the file belongs to a tool that `init` cannot write, so stopping would leave you without the install and no closer to the repair.

**The unreadable case costs something; the missing case does not.** If the file is there and will not read, the plaintext is still on disk while the redactor does not hold it, so that value can print in the clear through anything that touches the file. The broker cannot cover a value it does not have. Withholding every command's output over it would take out commands with no relationship to the credential, so it names the missing ref instead of stopping. A file that is *gone* leaves no plaintext to cover.

**One link is refused the way a managed file is**: a link claiming a ref the managed store already defines. That ref is answered by the store, so what is missing is the *second* value the linked file holds for the same name, a value nothing reads and nothing redacts, which will eventually be rotated with nothing watching. Rename the link or remove the managed value.

## Blocked paths

A `[[secret.block]]` entry keeps one thing away from the agent, for a credential faramir has no use for the value of: a LUKS keyfile, an SSH identity. See [when to reach for one](integrations.md#where-the-value-lives).

```sh
sudo faramir block add --path /etc/luks/volume.key   # this file, on this host
sudo faramir block add --name '*.htpasswd'           # any file of that name, anywhere

# Each flag given is one entry, and one command writes them all
sudo faramir block add --name id_rsa --name '*.pem' --name '.env*'

# A command, for what a tool does rather than for a file it names
sudo faramir block add --command 'op read' --command 'pass show'
```

**Each form has its own flag, and one entry is one form.** A bare argument is refused rather than read as a path. The three forms block different things, and an operator who meant "every file of this name" would otherwise get a rule about one file on this host.

Form | Covers | Blocks
--- | --- | ---
`--path` | The file at that exact path on this host | File tools and the shell
`--name` | A pattern matched against the path the agent names | File tools and the shell
`--command` | Command text | The shell only, a command being nothing a file tool can name

The deny rules and the command guard's patterns are rendered from one set, so a declared path or name refuses a file tool and `cat` alike, and `faramir init` re-asserts both.

### A path and a name are different rules

A path refuses the file at that path. A name is matched against the path the agent *names*, not against this host's filesystem, which is how it reaches a path the host does not have. A container mounts `/srv/ha/config` as `/config`, the agent names the second, and a rule carrying the first covers nothing it runs. Naming both in one entry is refused rather than answered by picking one.

There are five kinds of name pattern, and which one you get is inferred from the shape:

Name | Matches
--- | ---
`auth` | Any file called `auth`, in any directory
`.storage/auth` | That file inside any directory called `.storage`, and no sibling of it
`*.htpasswd` | Any file whose name ends that way
`.env*` | Any file whose name starts that way
`secrets*.yml` | Any file whose name matches, with the wildcard not crossing a directory
`.storage/` | Everything under any directory of that name

`block add` prints what it read before writing it. Inferring the kind is safe where inferring path-from-name would not be: these shapes differ only in breadth, so reading one as another refuses more or fewer files of the same kind, while an inferred path could turn a typo into a rule that silently matches nothing.

**The two forms fail in opposite directions.** A mistyped path refuses one file, and the file stays readable until somebody notices. A pattern that matches more than intended refuses a whole class of files at once, and nothing announces it: the agent just meets file tools failing on files nobody discussed. So a pattern that matches everything is refused at load, the way `/` is as a path, and what a pattern will match is printed as it is written.

### What each form accepts

Form | Rule
--- | ---
`path` | Absolute, and in its shortest form. A rule matches the path as written, so `/etc/./k` and `/etc/k` are two rules of which one matches nothing. A path under a home is also refused in the spellings a shell expands to it: `~/`, `$HOME/` and `${HOME}/`, which is how a person and a model both write one. No bare `~`, which nothing expands here. `/` is refused, being every file on the host.
`name` | A name, suffix, prefix, wildcard name or directory, per the table above. Not absolute, which would be a path. No `~` and no `..`, since nothing resolves either here, and no `**`, since a name already matches in any directory. A pattern with nothing left once the wildcards and separators are removed is refused, being every file on the host.
`command` | A command the agent's shell may not run, written as it would be typed: `op read`, `sops -d`. The words are literal and the space between them matches any run of whitespace, so there is no pattern to get wrong. It reaches the command guard and no file-tool rules, a command not being a path. A single-character word is refused, since it would match nearly every command line.

**A command rule matches where a command starts**, not wherever the words appear: after a separator, a pipe, a subshell, an assignment, `sudo` and its kin, or a shell's `-c` string. So `pass` is safe to declare on its own, where matching anywhere would have refused every `ansible-playbook --ask-become-pass`, and a `grep` that merely names a declared command is left alone. The cost runs the other way: a command reached through a wrapper the anchor does not know is missed. That is the better error for a list [the design says is not the boundary](design.md#three-layers): it is there to catch an accident, and an accident is typed rather than wrapped.

### How the entries behave

- **An entry carrying a control character is refused, in all three forms.** A rule is one line of a generated file, so a newline would end that rule early and start a second line with the rest. Neither half is the rule that was asked for, both are unbalanced expressions the guard cannot compile, and a rule that will not compile is skipped, so an entry meant to refuse one more file would take the rules protecting the install with it. Other control characters are refused because a listing prints an entry back to a terminal, which obeys what it is sent. `faramir doctor` fails on any rendered rule that will not compile, whatever wrote it.
- **A path that is not there is still recorded, and you are told.** The rule costs nothing while the file is absent and takes hold once the volume mounts, which is the case these exist for. A path spelled wrong looks the same, so the message says both.
- **A name is never asked of the filesystem**, having nothing on this host to be asked about. What it will match is printed instead.
- **An entry covers the path and everything under it**, whether or not it is a directory today. The filesystem is not consulted: these rules are a function of the config alone, or a key on an unmounted volume would render no subtree rule and gain one when it mounted. The subject is bounded, so `~/.sshrc` is not part of `~/.ssh`.
- **A path this install occupies cannot be unblocked, and asking fails.** `block rm /etc/faramir/age.key` names a rule the layout renders on every run, not an entry this install carries, so there is nothing to remove and the host goes on blocking it. Reporting that as "nothing removed" would read as the file becoming readable. If an install declared the same path as well, its entry is removed and the directory is named as what still blocks it. Nothing else is unremovable: no rule is compiled in.
- **Nothing is reloaded.** No daemon reads these entries, so `block add` does not restart the broker under a running command.
- **Both commands are idempotent.** A path already refused is not an error: the entry stands, the rules are rendered again, and `--json` reports `changed: false`. Removing a path this install does not refuse writes nothing.
- **Pi is the exception**, as it is for linked paths: its rules are compiled into the extension, so there is no account-wide file to render one into.
- **`faramir block ls` answers "what is blocked here".** It prints the declared entries in a table of kind and entry, and under it the rules faramir carries itself: this install's own directories, and the command rules covering its binary, the files an enrolment installs, and the commands that act on the install rather than through it. The kind is `name`, `path` or `command`, and where a rule is enforced follows from the kind. `--declared` narrows it to the entries the config carries, which is the list a configuration manager converges; `--built-in` narrows it to the half faramir renders from its own layout, which no entry names. Neither half can be asked any other way: a refusal names the rule that matched, not the set.

`init` reads these entries back before rewriting `config.toml`, so every rule is re-asserted on each run. That is what restores one an agent's settings dropped.

### What a block does not cover

**A rule matches the command as it was written.** The guard reads the text of a command and has no working directory to resolve a relative path against. So `cat /srv/keys/luks.key` is refused, `cd /srv/keys && cat luks.key` is not, and neither is a path the shell assembles from a variable. Where a file must be beyond reach whatever is typed, the file mode is what holds: this rule refuses a name, not an `open(2)`.

A managed or linked value is covered whichever route reads it, because an enrolled tree rewrites the command so its output is redacted on the way back. A blocked path holds no value faramir has read, so the refusal is all it adds.

**A brokered command can still read a blocked path.** The deny rules stop the agent's own shell and file tools. A brokered command is a different uid running with the operator's consent, and nothing of the blocked file is in the redactor to cover its output.

This is why a block is the weaker of the two entries. A link reads the file, so it does three things a block cannot:

What happens to the file | `[[secret.link]]` | `[[secret.block]]`
--- | --- | ---
Refused to the agent's file tools | Yes | Yes
Held to the broker's group, so a brokered command is refused it too | Yes, checked and reported | No, the mode is nobody's business here
The value is in the redactor, tokenised wherever it appears | Yes | No, faramir never reads it
Injectable by ref | Yes | No

## The sockets belong to their units

- Under socket activation the daemons are handed a listening descriptor and never reach the bind path, so `ListenStream=` and `SocketMode=` are what define a socket.
- No config key is a file mode. `--check` and `doctor` stat the bound socket rather than reading a setting.
- `socket_path` stays in the file because the broker *dials* the keeper and the executor at it, and a daemon run outside systemd binds it itself. `init` rewrites both sides together, so they cannot drift apart.
- The broker binds its own ssh-agent socket. Its mode is a constant next to the code that sets it, rather than a value anything could widen past the group `exec_group` names.
- `allowed_group` exists on `[server]` alone. `[keeper]` and `[executor]` have one legitimate client each, the broker, named in `allowed_user`. The group form is not a key there, and setting it is a hard error that names the alternative, because the only group in play is the client group, which holds the agent's own uid.

## The install gate, and the same gate at startup

`faramir broker --check` exits non-zero on anything that leaves the broker protecting less than it appears to. Run it as the broker's own account:

```sh
sudo -u faramir-broker faramir broker --check
```

No `-c` is needed: sudo clears `FARAMIR_CONFIG`, and the unit is the next step. Run as root it reads what the broker cannot, and the `allowed_user` check is skipped, since every name compares unequal from root.

Fails on | Because
--- | ---
An unknown key or `[section]`, or a value out of range | A config that reads as though it took effect. Reported by the loader, which exits 2
A ref too short to redact | Refused at load, so nothing covers it. `init` warns and carries on, since an install cannot lengthen a secret. `doctor` fails on it
A `[[secret.link]]` entry whose file is missing or will not read | See [when a link breaks](#when-a-link-breaks). The exit code says a credential is missing; it does not mean the broker stopped
An `[ssh] key` the agent cannot load | `ssh-add` refuses it, leaving every managed host unreachable. Passphrase-protected, unreadable, or pointed at the `.pub`
An `[sudo] helper` or PAM service file that is missing, or a `notify_command` that is not installed | Either every escalation fails with `sudo` reporting an authentication error, or nothing announces the questions waiting
`[keeper]` or `[executor] allowed_user` naming an account that is not the broker | Each socket has one legitimate client. The keeper's alternative is the age key by another route; the executor's runs a command with no policy, no redaction and no audit record
The bound broker socket having world bits | Every account on the host reaches the broker, whatever `allowed_group` says. Stat'ed rather than read from the config. An unbound socket is reported as unchecked
An audit log that cannot be written | A command that cannot be recorded is not run

**The daemon holds itself to the same rules, on every request rather than at boot.** `--check` is run by `init` and by `doctor`, and neither runs at boot, so on its own it only ever described the host as it was at install time.

### When the broker refuses to run anything

The rule is: **the broker serves `run` and `redact` only while no managed file went unread.** Every managed file that was found must have loaded. `run` is held to this too, because a brokered command's output is redacted against the same value set.

Matching no files is not this. So:

- **An empty value set serves.** Nothing configured, a store not written yet, a store that matched no file, and an install whose links have all gone: none of them holds a value that output could carry, so all of them run commands. The broker logs it at startup, `status` reports `count: 0` beside the pattern that matched nothing, and `doctor` warns.
- **Otherwise the broker refuses with `no_secrets`**, naming why. It starts either way, and `status` and `refs` answer regardless.
- **A ref no file defines** is answered with `unknown_secret`. What the files held does not enter into the serving decision.
- **A keeper that could not be reached is the exception, once a set has loaded.** What the broker keeps then is the last thing known to be true, marked unconfirmed, and it loads again on the next request past the refresh interval. A cold start has nothing to keep and refuses: that is a broker that cannot ask, rather than one with nothing to hold.

Two cases deserve a warning rather than a refusal:

- **Secrets on a filesystem that is not mounted yet look exactly like secrets never written.** Both leave the broker redacting nothing, and both serve. Nothing inside the broker can tell them apart, so `status` and `doctor` are where an operator sees it.
- **An `[ssh] key` the agent does not load is logged and not fatal.** It breaks only commands that reach a managed host, which fail at the point of use with `ssh`'s own error. Stopping the daemon over it would stop the commands that never touch SSH. An unset key does not stop the daemon either, but `faramir doctor` fails on one: `init` mints a key on every run whether or not the host needs it, so an empty `key` is a hand edit rather than a host that authenticates some other way.

## What no setting changes

- **Nothing the broker starts receives the age key.** No flag grants it, and the broker does not hold it to grant.
- **Secrets are injected as environment variables only.** Never into `argv`, which is visible in `ps` and `/proc/<pid>/cmdline`.
- **`cmd` is an array.** Never a string handed to `sh -c`.
- **The broker runs the working tree as it is on disk.** There is no promotion step.
- **No config names where a command runs.** A brokered command runs where its caller was, and a request naming no cwd is refused.
- **Nothing runs sudo without a human, and no setting widens what one approval covers.** Whether a host may sudo at all is the `--allow-sudo` install-time decision, not a config key.
- **Every run is confined to a cgroup and reaped there**, or refused. `init` renders `Delegate=` on the executor unit for every install.
- **`redactions` reports counts, not values.**
