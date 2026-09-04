# Configuration

There is one config file, `<config-dir>/config.toml`, and faramir owns it. `faramir init` renders it from [etc/config.toml.tmpl](../etc/config.toml.tmpl) on every run. There are no drop-in files and no merging: every value is either set by a flag or derived from the install.

## What bounds a brokered command

There is no command allowlist. Four things limit what a brokered command can do:

Setting | Effect
--- | ---
`[command.env] PATH` | Where a bare program name is looked up, and the only `PATH` the child gets.
`[command] max_timeout_sec` | How long a command may run.
`[secret] min_length` | A value too short to redact is refused at load, so nothing can inject it. There is no maximum setting: a value of 16 KiB or more is always refused, because the broker will not hold it.
the executor's uid | The real bound.

## The file is rewritten on every `init`

`init` renders the whole file on each run. Before writing, it reads the old file and keeps some values from it. Everything else is rendered fresh.

Edited by hand | Survives an `init`? | Why
--- | --- | ---
Any setting under [what a flag sets](#what-a-flag-sets) | **Yes**, unless you name the matching flag on that run | `init` reads these back, so a bare re-run keeps the install instead of reverting it. A flag overrides the file.
`[[secret.link]]` and `[[secret.block]]` entries | **Yes** | No flag sets them: `faramir link` and `faramir block` write them. Reading them back keeps a plain `init` from erasing the deny rules they added.
A **new** `[command.env]` variable | **Yes** | The environment merges: the file first, then any flag on top.
A **deleted** `[command.env]` variable | **No**, it comes back | The built-in table is the base of that merge. A built-in variable cannot be unset.
Comments, ordering, whitespace | **No** | The whole file is rendered, so you get the template's.
Anything under [what is derived](#what-is-derived) | **No** | Re-derived from the install on every run. The account names come from the units' `User=` lines, not from the file, so editing `allowed_user` changes nothing.

Two consequences:

- **Use the flag, not the edit.** A flag is written into the file and read back on the next run. An edit to a derived value is discarded on the next `init` without notice, and until then the daemons use what you typed.
- **A file that does not parse stops the run.** `init` reads the old config before writing, so a hand edit that will not load is refused rather than replaced. No daemon can load it either, and overwriting it would discard the edit that needs fixing. Fix the file, or delete it to install fresh.

## What a flag sets

Each of these is written into the file and read back on the next run.

Flag | Key | Default | Bounds
--- | --- | --- | ---
`--command-env NAME=VALUE` | `[command.env] NAME` | `PATH`, `TERM`, `LANG`, `LC_ALL`, `DEBIAN_FRONTEND` | Repeatable, and it **adds**: naming one variable keeps the rest. `PATH` may not be empty, and every component must be absolute.
`--command-timeout` | `[command] timeout_sec` | 600 | A duration (`10m`) or a bare number of seconds, in whole seconds. At least 1. Zero would kill every command as it started.
`--command-max-timeout` | `[command] max_timeout_sec` | 3600 | A duration or a bare number of seconds. At least 1, and not below `timeout_sec`. A lower value would silently replace `timeout_sec` for every command.
`--command-concurrency` | `[command] concurrency` | 10 | 1 to 16, the most the executor forks at once. `init` refuses a negative value and anything above 16; above 16, the executor refuses the surplus *after* the run was recorded as started. Zero means unset: it keeps what the install already has, and takes the default only where the file holds none.
`--command-max-memory-percent` | `[command] max_memory_percent` | 25 | 1 to 100. Rendered as `MemoryMax=` on the executor unit.
`--command-max-process-memory-mb` | `[command] max_process_memory_mb` | 4096 | 256 to 1048576. Rendered as `LimitDATA=` on the executor unit and inherited by every child.
`--sudo-timeout` | `[sudo] timeout_sec` | 120 | A duration or a bare number of seconds. 1 to 3600, and never more than `[command] max_timeout_sec`: a longer value is read as that one. How long a sudo question waits for a human. While a question is open every other brokered command is refused, so a long timeout blocks every brokered command on the host for that long.
`--secret-min-length` | `[secret] min_length` | 8 | At least 6. Counted in characters, not bytes.
`--notify-command ARG` | `[sudo] notify_command` | none | Repeatable, one argument per flag, and it **replaces**: naming the flag at all discards the installed list. Must contain `{prompt}` or `{id}`, or it would announce a question without saying which. Needs `--allow-sudo`, which writes the `[sudo]` section: a re-run without that flag removes the grant and the notifier with it. The program must be installed: a kept notifier whose program has been removed refuses the run.

On a host that grants sudo, the `[command.env]` variables are also written to `/usr/local/libexec/faramir/sudo-env`, so a command keeps them across `sudo`: `env_reset` discards the caller's environment, and this file restores these variables from a location the caller cannot write. `HOME`, `PATH` and `SUDO_*` are not restored, because sudo sets those itself. A name that is not a valid variable name, or a value holding a newline or a `#`, is [left out with a warning](escalation.md#what-a-brokered-command-keeps-across-sudo).

### The two memory settings

They do different jobs. Both are read by `init`: changing either key by hand does not reach the systemd unit until the next `sudo faramir init`.

- `max_memory_percent` is the **backstop**. It is a cgroup total for every brokered command at once, so it cannot tell one process holding everything from twenty holding a fair share each, and it counts page cache. It catches fan-out, which no per-process limit sees. It is a percentage because faramir does not know how much memory the host has. Cache is reclaimed before anything is killed, so a source build that reaches this limit loses cache, and a process that allocated the memory itself is killed by the OOM killer. 100 is the whole machine, so it is no bound.
- `max_process_memory_mb` is the **bound**. A runaway command is usually one process allocating far more than a real one does, and this limit refuses that allocation. Anonymous memory only, so a command is never charged for page cache. A process that reaches the limit gets an allocation failure it can report, instead of the OOM killer.

### Why `--secret-min-length` has a floor of 6

The two failure directions are not equal. A value refused for being too short is absent from the redactor and reaches output in the clear. A value matched too eagerly only mangles the operator's own text. The first direction leaks, so the floor is low. Note that `password` is eight characters, so the default of 8 is not as safe as it looks. See [what the gate is for](redaction.md#the-pipeline-in-order).

The file carries two more things, and no flag writes either: [`[[secret.link]]`](#linked-secrets) entries, written by `faramir link`, and [`[[secret.block]]`](#blocked-paths) entries, written by `faramir block`.

## What is derived

Everything else. `init` computes these from the install and rewrites them on every run.

Key | Derived from
--- | ---
`socket_path` on `[server]`, `[keeper]`, `[executor]` | Rendered alongside the `.socket` units
`[server] allowed_group` | `--client-group`
`[server] agent_user` | `faramir init --agent-user`, then `$FARAMIR_OPERATOR`, then `$SUDO_USER`, then you. No other command takes this flag: they all read this key, so adding an entry cannot rename the host's owner. Passed to every brokered command as `FARAMIR_OPERATOR`, and to its `sudo` through the environment file its PAM service reads
`[keeper] allowed_user`, `[executor] allowed_user` | `--broker-user`
`[keeper] age_key_file` | `--config-dir`
`[keeper] age_key_credential` | Rendered alongside the keeper unit's `LoadCredential=`
`[ssh] key` | `--ssh-key`
`[ssh] exec_group` | `--exec-user`, resolved to that account's own group
`[ssh] ssh_agent`, `[ssh] ssh_add` | Resolved on `PATH` at install time. The broker runs them as its own uid
`[ssh] agent_socket`, `[audit] log_path` | No flag: `/run/faramir` and `/var/log/faramir`, fixed in the binary
`[sudo] exec_user`, `pam_service`, `pam_stack`, `helper` | `--allow-sudo`. `pam_stack` is the file carrying faramir's PAM stack on this host, which is not always what `pam_service` names: see [the two sudos](escalation.md#the-two-sudos)

## What is not a key at all

Eleven values are constants in the binary. No install sets them.

Value | Is
--- | ---
`max_output_bytes` | 256 KiB, roughly 64k tokens. It limits how much text reaches the model, which is a property of the conversation rather than of the host. Truncation is reported, never silent
`max_request_bytes` | 256 KiB. The largest request line the broker socket reads. A guard against a malformed request, not a size anyone chooses
`max_stdin_bytes` | 128 KiB. The most a caller may pipe into a brokered command. The bytes travel inside the request, base64 encoded, so this leaves room under `max_request_bytes` for the command, the cwd and the refs beside them. More is refused rather than truncated: a command that read half its input has done something nobody asked for
`max_record_bytes` | 256 KiB. The largest one audit record's line may be, in encoded bytes. A record keeps the head and tail of the output and cuts every other field to fit, so a long command degrades its record rather than losing it
`min_record_bytes` | 4 KiB. The smallest record limit the audit log is built to survive, not a value anybody sets. A record keeps its identity (the `log_id`, the op and the caller) when everything else has been cut away, and the reducer is held to producing one at this size, which is what makes it safe at any larger one
`term_cols`, `term_rows` | 120x40. The PTY size every child gets, which decides where a program wraps its output
`kill_grace_sec` | 5 seconds between SIGTERM and SIGKILL. This window opens only after a command has overrun its timeout
`min_refresh_sec` | 1 second. The soonest the broker asks the keeper again whether a managed file changed. Checked when a command arrives, not on a timer, so an idle host makes no round trip. Not a setting because every larger value is worse: the check costs one stat per managed file, and a longer interval only widens the window in which a value rotated outside faramir is missing from the redactor. This interval does not apply to linked files: they are stat'ed on every request
the managed store | `<config-dir>/secrets/` matching `*.sops.yml`. Derived from where the config sits, so the store cannot be pointed at a checkout. The deny rules name the directory by path, so the agent cannot open it
the decrypt command | sops, invoked one way. A second invocation would be a second thing the account holding the age key could redirect

## Linked secrets

A `[[secret.link]]` entry (a link) reads one secret out of a file that another tool maintains, instead of copying it into the managed store. See [when to use one](integrations.md#where-the-value-lives).

```sh
sudo faramir link add gh/token ~/.config/gh/hosts.yml \
    --type yaml --key github.com/oauth_token
```

That is the whole interface. The [three link commands](operating.md#operator-commands) are the only way these entries are written. The entry looks like this:

```toml
[[secret.link]]
ref  = "gh/token"
path = "/home/operator/.config/gh/hosts.yml"
type = "yaml"
key  = "github.com/oauth_token"
```

Field | Rule
--- | ---
`ref` | The name a caller asks by, in the same namespace as the sops store. Nothing marks a ref as linked: where a secret is kept is not part of its name, so moving one into the store later does not rename it or change any `faramir.env` that names it. A link claiming a ref the store already defines is refused by `link add` before any entry is written.
`path` | Absolute, and in its shortest form: the file is opened as written and the deny rule matches the path as written, so `/etc/./k` and `/etc/k` are one file and two rules, one of which matches nothing. No `~`: nothing expands it here, and the broker runs as its own account, so the home would be the wrong one. No control characters: the path is rendered into the deny rules one rule per line, and a newline would split the rule into two halves that do not compile. No wildcard, and not `/`: a link opens the file it names on every load, so the trailing-`*` form a blocked path may carry would render a rule and never resolve a value, leaving the ref permanently degraded. Otherwise held to [the same rules as a blocked path](#what-each-form-accepts): the two render the same rule over the file and differ only in which entry a refusal names.
`type` | `text` or `base64` for the whole file. `json`, `yaml`, `toml` or `ini` to select a value out of it.
`key` | Required for the four types that select, refused for the two that do not. Held to the same character rules as `path`, because `faramir link ls` prints it to a terminal. `a/b/c` walks a tree the way a sops ref does, and a number indexes a list; `ini` matches the whole key instead. See [selectors, escaping and the per-tool recipes](integrations.md#linking-a-credential-another-tool-owns).
`strict` | Optional, written by `link add --strict`. Makes the broker refuse every command naming the file, not only the ones that would print it. The ref still answers either way. See [refusing every mention of an entry](#refusing-every-mention-of-an-entry).

### The three commands are idempotent

A configuration manager can run them on every converge. Adding an entry the install already has re-applies it: the deny rules and the config are rendered again, the file's access is checked again, `--json` reports `changed: false`, and the daemons reload only where something changed. Removing a ref that is not there writes nothing.

The one refusal is the same ref pointing at a different file, type or key. The error names both definitions. A ref has one definition; replacing the entry would change which credential every caller of that name receives.

### `link add` asks everything before it writes

Nothing about the file is altered to make a check pass. In order, `link add`:

0. Resolves the path. A symlink is resolved to its target: the grant and the group apply to the target, and every check below reads the target's mode. The spelling you typed is written as a `[[secret.block]]` entry carrying `derived_from`, so the rules cover both names: a rule matches the path a command names, and the name your agent has is the one you typed. `link rm` removes that entry with the link, unless another link or a `[[secret.block]]` entry still names the target, in which case the entry stays. A typed spelling that is, or holds, an enrolled tree is not blocked, because a rule there would refuse the agent the directory it works in. The report says so. Nothing is derived where the path named the file directly.
1. Refuses a ref this install already defines against a different file, type or key.
2. Requires the file to exist.
3. Reads it as root, to confirm the type and the key yield a value.
4. Asks the running broker whether it already serves that ref.
5. Checks that the file's ownership and mode are what a link needs.
6. Reads it again as the broker's own account, to confirm that account can reach the value.
7. Writes the entry.

[Why there are two reads, and in that order](integrations.md#linking-a-credential-another-tool-owns).

Step 4 needs a running broker, and `link add` refuses rather than skipping it. An entry claiming a name the store already answers would refuse every brokered command on the host. `refs` answers on a host with no secrets yet, so this does not block a first install. A file with the wrong ownership or mode is reported along with the commands that fix it, and no entry is written.

`init` reads these entries back before rewriting the file, so every deny rule is re-asserted and every file re-checked on each run. That catches a mode or group some other tool changed.

### The permissions a link needs

**faramir checks these and does not apply them.** The file and every directory above it belong to the operator, and faramir does not change the ownership or mode of a path it does not own. Whoever manages the host's permissions sets them; `link add`, `init` and `doctor` each report what is wrong along with the command that fixes it.

Path | Has to be
--- | ---
The linked file | Owned by the broker's group and group-readable, and readable by nobody else. The owner and the owner bits are the operator's choice. That group holds one account, which keeps the executor out. Never a symlink: `link add` resolves one before it writes the entry, and an entry that names one anyway, written by hand or pointed at a file that became a link afterwards, is refused with the target named
Every directory above it, down from the home | Enterable by the client group. Traversal is not read access. Never `chmod o+x`, which grants the same to every account on the machine

Why it is designed this way (one ref per entry rather than a whole-file flatten, the broker reading these rather than the keeper, and modes rather than an ACL) is in [design.md](design.md#linked-secrets-are-read-by-the-broker).

### Keeping a link working

- **Every linked path is refused to the agent's file tools.** `link add` and `init` both render them into the account-wide deny rules, and `faramir doctor` fails on a linked file that is not refused. The agents with no rule file of their own get the same list by asking `faramir guard`.
- **A tool that replaces its file instead of rewriting it drops the group.** A temp file renamed over the original is created fresh, and mode `0600` on creation leaves nothing for a group to read. `faramir doctor` asks the broker's own account whether it can still read each file, and `init` and `link add` check again on every converge.
- **A repair needs a restart, and nothing restarts automatically.** The broker fingerprints a linked file by mtime and size, and `chgrp` changes neither, so the broker keeps treating a file it failed to read as broken until you run `sudo systemctl restart faramir-broker`. `init` and `link add` restart the daemons only when they changed something, and neither changes a file it does not own.

### When a link breaks

**A link that does not load disables that one ref and nothing else.** The broker refuses that ref by name and goes on serving every other one. This covers both failures: a file that is gone, and a file that is there and cannot be read.

This is the difference between a link and a managed file. A managed file holds any number of refs and names none of them until it decrypts, so one that did not load leaves the broker with values missing and no way to know which, and it stops serving. A link is one ref, so the broker can name it and keep serving.

What reports it:

- `faramir status` names the ref and exits non-zero.
- `faramir doctor` fails, so you learn before a command does.
- `faramir init` reports it and finishes. The fault is in one credential, the config for this run is already written, and the file belongs to a tool that `init` cannot write, so stopping would leave the install unfinished without repairing the link.

**The unreadable case leaves a value exposed; the missing case does not.** If the file is there and cannot be read, the plaintext is still on disk while the redactor does not hold it, so that value can print in the clear through anything that reads the file. Withholding every command's output over it would break commands unrelated to the credential, so the broker names the missing ref instead of stopping. A file that is *gone* leaves no plaintext to cover.

**One link is refused the way a managed file is**: a link claiming a ref the managed store already defines. The store answers that ref, so the *second* value the linked file holds for the same name is one nothing reads and nothing redacts. Rename the link or remove the managed value.

## Blocked paths

A `[[secret.block]]` entry (a block) refuses the agent one path or one command. Use it for a credential faramir never needs the value of: a LUKS keyfile, an SSH identity. See [when to use one](integrations.md#where-the-value-lives).

```sh
sudo faramir block add --path /etc/luks/volume.key   # this file, on this host
sudo faramir block add --path ~/.ssh                 # and everything under it

# Each flag given is one entry, and one command writes them all
sudo faramir block add --path ~/.gnupg --path ~/.config/sops/age --path ~/.netrc

# A command, for what a tool does rather than for a file it names
sudo faramir block add --command 'op read' --command 'pass show'
```

**Each form has its own flag, and one entry is one form.** A bare argument is refused rather than read as a path. The two forms block different things, and neither is the default.

Form | Covers | Blocks
--- | --- | ---
`--path` | That path on this host, and everything under it | File tools, the shell, and a brokered command that would print it
`--command` | Command text | The shell and a brokered command. A file tool cannot name a command, so the rule does not reach it

`--path` also takes [`--strict`](#refusing-every-mention-of-an-entry), which narrows what a **brokered** command may do to the entry. It changes nothing for the agent's own shell or file tools, which refuse any command naming a declared path either way.

The deny rules, the guard's patterns and the broker's own check are built from one set, so a declared path refuses a file tool, `cat` and `faramir run` alike, and `faramir init` re-asserts all of them.

**A path covers the directory, so name the directory rather than the files in it.** `--path ~/.ssh` refuses every key under it, including `identity` and whatever an `IdentityFile` line points at. Listing `id_rsa`, `id_ecdsa` and `id_ed25519` covers those three and nothing else.

### What each form accepts

Form | Rule
--- | ---
`path` | Absolute, and in its shortest form. A rule matches the path as written, so `/etc/./k` and `/etc/k` are two rules, one of which matches nothing. A path under a home is also refused in the spellings a shell expands to it: `~/`, `$HOME/` and `${HOME}/`. No bare `~`, which nothing expands here. The tail of the path is refused on its own where the tail is a path rather than a word, meaning it holds a `/` or starts with a dot: a rule has no working directory to follow, so `cd $HOME && cat .ssh/id_rsa` is refused, and so is the same tail under another root. On a host with several homes, `/home/other/.ssh/id_rsa` is refused by this account's entry, and the refusal names that entry rather than the file the command touched. This is deliberate: the same looseness catches a path built from a variable such as `$PWD/.ssh/id_rsa`, and narrowing it to the account's own tree would drop both. A tail that is a plain word, such as `~/notes`, is refused only in the four spellings above: a rule for the word itself would refuse every command using that word. `/` is refused: it is every file on the host. **A wildcard is refused in every position but one.** A path is matched as written, not expanded, so `/srv/keys/*.key` would refuse a command typing that pattern and leave `/srv/keys/server.key` readable. Name the directory, which covers everything under it. The exception is a **trailing `*` on the last component, after at least one literal character**: `/srv/keys/server*` refuses `/srv/keys/server-2026.key` and every other name starting with `server`, up to the end of that component. Use it for a file whose name this config cannot write in full, such as a sentry or a session file carrying a per-account number; the literal parent bounds it. `/srv/keys/*`, `/srv/*/key` and `/srv/keys/*.key` stay refused: the first is the directory under another name, and the other two reach a directory or a file set this config cannot know. So is a top-level prefix such as `/h*`: a rule is not anchored on the left, so that one reaches `/home` and `/etc` alike, and there is no literal parent to bound it. The form is for `[[secret.block]]` only: a link opens the file it names, so a wildcard there names nothing. An entry whose rule would reach an enrolled tree is refused, as a literal entry is. The comparison uses the literal part rather than the whole entry, so `~/pro*` is refused where `~/project` is enrolled.
`command` | A command the agent's shell may not run, written as it would be typed: `op read`, `sops -d`. The words are literal and the space between them matches any run of whitespace, so there is no pattern to get wrong. It reaches the guard and no file-tool rules, because a command is not a path. A single-character word is refused: it would match nearly every command line.

**A command rule matches where a command starts**, not wherever the words appear: after a separator, a pipe, a subshell, an assignment, `sudo` and its equivalents, or a shell's `-c` string. So `pass` is safe to declare on its own, where matching anywhere would have refused every `ansible-playbook --ask-become-pass`, and a `grep` that merely names a declared command is left alone. The cost is that a command reached through a wrapper the anchor does not know is not matched. That is the better error for a list [the design says is not the boundary](design.md#three-layers): it exists to catch an accident, and an accident is typed rather than wrapped.

**A heredoc body is read as commands**, whichever way its delimiter is spelled. `<<'EOF'` makes every line up to the terminator literal, and literal is what an interpreter runs: `bash <<'EOF'` executes every line of its body, as do `sh`, `python3`, and a body piped into any of them. Nothing in the redirection separates that from `cat <<'EOF' > doc`, so a script body and a document body are the same bytes. Both are read as commands, which refuses the script. The cost is that writing a document quoting an operator command is refused: use your editing tool rather than a shell heredoc for that.

### How the entries behave

- **An entry carrying a control character is refused, in both forms.** A rule is one line of a generated file, so a newline would end that rule early and start a second line with the rest. Neither half is the rule that was asked for, both are unbalanced expressions the guard cannot compile, and a rule that does not compile is skipped, so an entry meant to refuse one more file would remove the rules protecting the install. Other control characters are refused because a listing prints an entry back to a terminal, and a terminal acts on the control characters it receives. `faramir doctor` fails on any rendered rule that does not compile, whatever wrote it.
- **A path that is not there is still recorded, and you are told.** The rule has no effect while the file is absent and takes effect once the volume mounts. A path spelled wrong looks the same, so the message says both.
- **An entry covers the path and everything under it**, whether or not it is a directory today. The filesystem is not consulted: these rules are a function of the config alone, so a key on an unmounted volume gets its subtree rule before the volume mounts. The match is bounded at a path component, so `~/.sshrc` is not part of `~/.ssh`.
- **A shell pattern that could reach the entry is refused too.** The rules are matched against the text of a command, and a shell expands `*` after the guard has answered, so a rule carrying a file name can never match a pattern: declaring `~/.ssh/id_rsa` alone would leave `cat ~/.ssh/*` printing it. So each entry also refuses the patterns that could produce its last component. `~/.ssh/*`, `~/.ssh/id_r*` and `~/.ssh/id_rs?` are refused; `~/.ssh/known_*` is not, because `known_` is no prefix of `id_rsa`, and neither is a pattern anywhere else. This does not reach a wildcard higher up the path (`~/.s*/id_rsa`), a character class standing in for a literal (`~/.ssh/id_[r]sa`), or any path a command builds while it runs. An entry that is itself a trailing-`*` prefix cannot constrain the end of the name, so it refuses any pattern whose literal opening is a prefix of the declared one: for `~/.ssh/id_*`, that is `~/.ssh/*`, `~/.ssh/i*` and `~/.ssh/id_*` but not `~/.ssh/known_*`.
- **A path this install occupies cannot be unblocked, and asking fails.** `block rm --path /etc/faramir/age.key` names a rule the layout renders on every run, not an entry this install carries, so there is nothing to remove and the host goes on blocking it. Reporting "nothing removed" would suggest the file had become readable. If an install declared the same path as well, its entry is removed and the directory is named as what still blocks it. Nothing else is unremovable: no rule is compiled in.
- **A change reloads the daemons.** The broker holds these entries itself and compiles them once, at start, so an entry added to a running install is not refused until it reloads, and one removed goes on being refused. `block add` and `block rm` reload where they changed something, and not where a converge found the host already correct.
- **A symlink is blocked at both names.** A rule matches the path a command names, and a link and its target are two names for one file, so an entry for the link alone leaves the file readable under the target's name. `block add` resolves the path it is given and records the target as a second entry, carrying `derived_from` and the strictness of the entry it came from. Both are written into `config.toml`, so the rules are a function of the config alone and `block ls` shows what is in force. A derived entry is an entry like any other, so a symlink to a directory derives a whole-directory rule on its target: file-by-file entries under that target are subsumed by it, and everything else under it is refused. Derivation reads the declared path's own last component and nothing above it, so a file named under a symlinked directory derives nothing and its entry refuses the spelling it names alone. Where a target has to stay partly readable, name each file at both the symlink's spelling and the canonical one: neither entry derives anything, and the target's other files stay readable. `block rm` on the declared path removes the derived entry with it, unless another declared symlink still resolves to the target, in which case the entry stays and `derived_from` names that one. An entry that cannot be read is assumed to resolve to the target: a rule kept unnecessarily costs a listing row, and a rule dropped wrongly exposes the file. The resolution happens when the entry is declared, not when a command is matched: a symlink created *after* the entry was written is not covered until the next `block add`. A target that is, or holds, an enrolled tree is left underived and reported, because a rule there would refuse the agent the directory it works in. A symlink repointed since it was declared keeps its entry for the old target until the next `block add` naming the link, which replaces it, and `faramir doctor` reports the drift as `derived paths` until then. An operator who declares the target on its own account takes over that entry, and it then survives a removal of the link. A `[[secret.link]]` entry derives one too, in the other direction: `link add` resolves a symlink to the file that holds the value and blocks the spelling that was typed, with `derived_from` naming the link's own path, and `link rm` removes it under the same rule. Removing an entry also removes it as a source, so what was derived from it goes or stays by the same rule. A derived entry is removed only by the entry that wrote it, so a `block rm` naming a path this config does not block removes nothing and leaves the derived entry in place.
- **A path that is, or holds, an enrolled tree is refused**, in a `[[secret.link]]` entry as well as a blocked one. The rules hold wherever the agent works, so such an entry would refuse it every file in that tree.
- **Removing an entry takes its rule out of the agent files too.** `block rm` and `link rm` re-render the same steps `add` does, and the merge is given the record of what faramir last wrote into each file: a rule in that record and no longer backed by an entry comes out, and a rule nobody recorded is the operator's and stays, whatever it looks like. Removal does not take back the grant; `link rm` prints the `chmod` that narrows it.
- **The form is part of what identifies an entry.** `block rm --command` removes a command entry, so a command is not removed by giving the same string to `--path`.
- **Both commands are idempotent.** A path already refused is not an error: the entry stands, the rules are rendered again, and `--json` reports `changed: false`. Removing a path this install does not refuse writes nothing.
- **`faramir block ls` answers "what is blocked here".** It prints the declared entries in a table of kind and entry, and under it the rules faramir carries itself: this install's own directories, and the command rules covering its binary, the files an enrolment installs, and the commands that act on the install rather than through it. The kind is `path` or `command`, and where a rule is enforced follows from the kind. A strict path reads `path (strict)`, so a reader can tell an expected refusal from an unexpected one. `--declared` narrows the output to the entries the config carries, which is the list a configuration manager converges. `--built-in` narrows it to the half faramir renders from its own layout, which no entry names. Neither half can be listed any other way: a refusal names the rule that matched, not the set. Naming both flags is the default and is refused. The table and each section are sorted and not merged into each other: the table by kind and then by entry, and a section by the line it prints. Those are the same thing for a path rule, which prints its entry, and not for a built-in command rule, whose entry is a regular expression. That one prints what the rule refuses instead, the pattern being the one thing in the listing nobody can read; `--json` carries the pattern as `entry`, so a configuration manager asserts on the rule and a reader is given the sentence. `--json` adds fields that are not columns. `state` is whether a declared path exists today. `strict` is the same flag the kind cell marks; the install's own directories also carry it, because the broker refuses any command naming one. `source` is which half a row came from: `declared` for an entry the config names, `built-in` for one faramir renders from its own layout, and `derived` for the target of a declared symlink, which the table marks `path (derived)` and which carries `derived_from` naming the entry it is removed with. A configuration manager converging its own list filters to `declared`, or it reads a derived entry as one it did not declare and removes it every run.

`init` reads these entries back before rewriting `config.toml`, so every rule is re-asserted on each run. That restores a rule an agent's settings dropped.

### Where an entry is enforced

**On the host where the command is typed, not the host holding the file.** Both enforcement points are local to the machine the agent is working on: the guard is a hook in that agent's session, and the broker is the daemon that machine's `faramir run` talks to. Neither consults another host, and neither is consulted by one.

So an entry for a path on another machine belongs on the machine the agent works from. Declaring `/home/other/.ssh/id_rsa` there is what refuses `ssh other-host sudo cat /home/other/.ssh/id_rsa`; the same entry on the host that holds the file refuses nothing, because nothing there is reading the command. Where an agent runs is the question, not where the credential lives, and an entry placed by the second reading is an entry with no evaluator.

A strict entry arms both points on that host: the guard refuses the command the agent runs itself, and the broker refuses the same command under `faramir run`. An entry that is not strict is refused by the guard and read by the broker under [the looser vocabulary](#the-brokered-route).

**Writing about a blocked path is refused too.** A rule is matched against the text of a command and cannot tell a name being written from one being used, so a path cannot appear in a shell command at all: not in an `echo`, not in a heredoc, not in a comment on the same line. Use an editing tool to write a file that quotes one. This is a consequence of the matching, not a separate rule, and it is what a person documenting an entry meets first.

### What a block does not cover

**A rule matches the command as it was written.** The guard reads the text of a command and has no working directory to resolve a relative path against. So in the agent's own shell `cat /srv/keys/luks.key` is refused and `cd /srv/keys && cat luks.key` is not, and neither is a path the shell assembles from a variable. Where a file must be unreachable whatever is typed, the file mode is what holds: this rule refuses a name, not an `open(2)`.

The broker is handed the working directory along with the command, so the same relative spelling is refused there. That is the one reading the guard cannot make.

The same limit bounds what an entry can do about another host. It refuses a command that names the path, so a reach that never puts the path in the text typed locally is not covered: an interactive `ssh other-host` session, where what follows is typed on the far side, and a remote shell that assembles the path once it is running. What holds against those is the far side's own file modes and the scope of the credential the agent authenticates with, not an entry here.

A managed or linked value is covered whichever route reads it, because the command is rewritten so its output is redacted on return. A blocked path holds no value faramir has read, so the refusal is all it adds.

### The brokered route

**A brokered command may not read a declared file either.** The agent's deny rules and the guard cover its own file tools and its own shell. A brokered command is neither: it runs as another uid on the far side of the broker. So the broker holds the same entries itself and refuses the command before it runs, with the [`blocked`](protocol.md) code. The refusal names the entry that matched and the list it is in.

Both tiers are built from one catalogue and read it the same way, case included, so an entry cannot reach one and miss the other. What each tier does with a rule differs, on purpose: the guard packs the paths into one pattern per kind, because a file of patterns has nowhere to keep a message, and the broker keeps a rule per entry so it can name that entry. The rules about faramir's own commands are in it too, which is why `faramir run -- faramir vault ls` is refused here as the bare spelling is refused to a shell: the account on the far side of the broker is not the operator either.

`[[secret.link]]` entries are held to the same rule, for their own reason. A linked ref comes back tokenised wherever it appears, but a file holds more than the one key a link selects, and the rest of it is in no redactor. The mode that keeps the executor's uid out of a linked file is checked at install time and by `doctor`; this is the same bound at the moment the command runs.

**On this side, and only this side, what is refused is a vocabulary rather than a direction: the commands that put a file's contents in the output, wherever the declared path sits in the line. Everything else is left alone, moving the file and writing over it included.** The agent's own shell is answered differently: there, naming a declared path is refused whatever the command would do with it. A brokered command has to be able to *use* a credential file and an agent's shell does not. A complete list of every program that reads a secret without printing it cannot be written, so the side that needs one keeps a vocabulary and the side that does not has none.

Through the broker | Example
--- | ---
Refused | `cat`, `head`, `python3`, `jq`, `cp`, `tar`, `scp`, `sops -d`, `< file`, and `p=/srv/keys/luks.key`
Refused | `sed -n p`, `awk`, `rev`, `zcat`: readers under other names, which the vocabulary carries by name rather than by what the line looks like
Left alone | `chmod`, `chown`, `setfacl`, `rm`, `shred`, `truncate`, `echo x > file`, `mv`, `ln`, `gzip`, `cryptsetup --key-file`, `stat`, `test -f`, `ls -l`

This is not the read/write split the agent's own rules use, and the difference is deliberate. What the agent types was not asked for by an operator, so it is refused in both directions: a value it cannot read is one it can still destroy, and an age key replaced makes every managed file unreadable retroactively. A brokered command runs as an account of its own, so managing a declared file is ordinary work: fixing its mode, changing its owner, moving one into place, removing one that is finished. None of that puts a byte of the file into the conversation. Reading it is refused because nothing else can cover it: a declared file is one faramir either never reads or reads a single ref out of, so the redactor holds nothing to replace the output with.

To read the file, run the command outside faramir, or remove the entry with `faramir block rm` or `faramir link rm`.

**What that leaves open.** A brokered `mv` or `ln -s` may put a declared file under a name no rule was written for, and the agent may then read that name with its own file tools. The agent invokes `faramir run` itself: only an escalation is approved per command, so no one is asked before this happens. It takes two deliberate steps rather than one accident, and that is the trade-off: a rule against it would also refuse the converge that rotates a keyfile by moving one into place. `--strict` is the per-entry answer for a file that should have the refusal rather than the converge.

**Faramir's own directories are held to the stricter rule on this side, and no brokered command may name one.** The looser reading exists so a brokered command can still manage a credential file, and nothing brokered has an install to manage. This is also the one route where a file mode does not protect the file. The agent's uid cannot read the age key whatever the rules say, but a brokered command runs as an account of its own, and as root wherever an escalation was approved, so the rule is what refuses it. The refusal offers no removal command: these rules are rendered from the layout on every run.

The rules match the text of a command rather than what it does once running, so a converge that sets the install up is untouched: `sudo ansible-playbook site.yml` goes through and `sudo cat <config-dir>/age.key` does not.

### Refusing every mention of an entry

The default above keeps a host working: most declared files still have to be managed, and a keyfile nothing may `chmod` is a keyfile nothing may rotate. It is the wrong default for a file no brokered command should name.

`--strict` says so, per entry, on `block add` and on `link add`:

```sh
sudo faramir block add --path ~/.private --strict
sudo faramir link add --strict gh/token ~/.config/gh/hosts.yml --type yaml --key github.com/oauth_token
```

It changes what a **brokered** command may do, and nothing else. The agent's shell and its file tools already refuse any command naming a declared path, strict or not, so there the flag changes only the wording of the refusal: a strict entry is refused on both tiers, so the message drops the paragraph offering the brokered route and names the ref instead.

It removes the looser reading the broker uses. Without it a brokered command may do anything to the file that does not put its contents in the output: `chmod`, `chown`, `rm`, `truncate`, a redirect over it, and `mv`, `ln` or `gzip` as well. This route runs what the operator asked for as an account of their own, so it does not defend against a file being moved out from under a rule. What stays refused is anything that prints the contents, whatever program does it: `sed -n p` is a read under another name. With `--strict`, no brokered command may name the path for any reason.

The cost is exactly that. **Nothing converges a path declared this way**, so it is for a file whose own tool is the only thing that should ever touch it, and not for a key something has to rotate. `faramir block ls` shows which entries carry it.

It is not for `--command`, which is already matched wherever a command starts: an entry naming both is refused at load rather than accepted and ignored.

On a link it is about the file, not the value. The ref still answers, so `faramir run --env NAME=faramir://gh/token` injects the token either way: that is what the link is for, and it names no path. What the flag removes is the brokered command that would name `~/.config/gh/hosts.yml` in order to manage it.

A link is still the stronger of the two entries, because it reads the file:

What happens to the file | `[[secret.link]]` | `[[secret.block]]`
--- | --- | ---
Refused to the agent's file tools | Yes | Yes
A brokered command cannot print it | Yes | Yes
Held away from the executor's uid by the mode | Yes, checked and reported | No, the mode is not checked
The value is in the redactor, tokenised wherever it appears | Yes | No, faramir never reads it
Injectable by ref | Yes | No

**A path may carry both, and the link is the entry that stays.** The rule is the same either way and only the message differs, so one path renders one rule, and a refusal names the removal that lifts it rather than one that leaves the other entry refusing. The dropped entry still contributes `--strict`: the two are two readings of one path and the stricter reading applies, so a block written strict keeps that reading when the link beside it was not. Both are still listed, `faramir block ls` and `faramir link ls` each showing their own.

## The sockets belong to their units

- Under socket activation the daemons are handed a listening descriptor and never reach the bind path, so `ListenStream=` and `SocketMode=` define a socket.
- No config key is a file mode. `--check` and `doctor` stat the bound socket rather than reading a setting.
- `socket_path` stays in the file because the broker *dials* the keeper and the executor at it, and a daemon run outside systemd binds it itself. `init` rewrites both sides together, so they cannot drift apart.
- The broker binds its own ssh-agent socket. Its mode is a constant next to the code that sets it, not a value anything could widen past the group `exec_group` names.
- `allowed_group` exists on `[server]` alone. `[keeper]` and `[executor]` have one legitimate client each, the broker, named in `allowed_user`. The group form is not a key there, and setting it is a hard error; the unknown-key refusal lists the keys that do exist. The only group in play is the client group, which holds the agent's own uid.

## The install gate, and the same gate at startup

`faramir broker --check` exits non-zero on anything that leaves the broker protecting less than it appears to. Run it as the broker's own account:

```sh
sudo -u faramir-broker faramir broker --check
```

The broker takes no config flag. It reads `$FARAMIR_CONFIG`, and the default path when that is unset, which it is here because sudo clears the environment. For a config elsewhere, put the variable after sudo: `sudo -u faramir-broker env FARAMIR_CONFIG=FILE faramir broker --check`. Run as root it reads what the broker cannot, and the `allowed_user` check is skipped, since every name compares unequal from root.

Fails on | Because
--- | ---
An unknown key or `[section]`, or a value out of range | A config that reads as though it took effect. Reported by the loader, which exits 2
A ref too short to redact | Refused at load, so nothing covers it. `init` warns and carries on, since an install cannot lengthen a secret. `doctor` fails on it
A `[[secret.link]]` entry whose file is missing or cannot be read | See [when a link breaks](#when-a-link-breaks). The exit code says a credential is missing; it does not mean the broker stopped
An `[ssh] key` the agent cannot load | `ssh-add` refuses it, leaving every managed host unreachable. Passphrase-protected, unreadable, or pointed at the `.pub`
An `[sudo] helper` or PAM service file that is missing, or a `notify_command` that is not installed | Either every escalation fails with `sudo` reporting an authentication error, or nothing announces the questions waiting
`[keeper]` or `[executor] allowed_user` naming an account that is not the broker | Each socket has one legitimate client. The keeper's alternative is the age key by another route; the executor's runs a command with no policy, no redaction and no audit record
The bound broker socket having world bits | Every account on the host reaches the broker, whatever `allowed_group` says. Stat'ed rather than read from the config. An unbound socket is reported as unchecked
An audit log that cannot be written | A command that cannot be recorded is not run

**The daemon holds itself to the same rules, on every request rather than at boot.** `--check` is run by `init` and by `doctor`, and neither runs at boot, so on its own it only describes the host as it was at install time.

### When the broker refuses to run anything

The rule: **the broker serves `run` and `redact` only while no managed file went unread.** Every managed file that was found must have loaded. `run` is held to this too, because a brokered command's output is redacted against the same value set.

Matching no files is not a failure. So:

- **An empty value set serves.** Nothing configured, a store not written yet, a store that matched no file, and an install whose links have all gone: none of them holds a value that output could carry, so all of them run commands. The broker logs it at startup, `status` reports `count: 0` beside the pattern that matched nothing, and `doctor` warns.
- **Otherwise the broker refuses with `no_secrets`**, naming why. It starts either way, and `status` and `refs` answer regardless.
- **A ref no file defines** is answered with `unknown_secret`. What the files held does not enter into the serving decision.
- **A keeper that could not be reached is the exception, once a set has loaded.** The broker keeps the last set it loaded, marked unconfirmed, and loads again on the next request past the refresh interval. A cold start has nothing to keep and refuses: that is a broker that cannot ask, not one with nothing to hold.

Two cases get a warning rather than a refusal:

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
