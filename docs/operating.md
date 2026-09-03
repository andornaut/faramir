# Operating an install

How to check an install, run it, and change who can decrypt the store.

## Checking an install

```bash
sudo faramir doctor
```

`doctor` asks questions only a real host can answer: whether the accounts exist, what each can reach, and whether the daemons serve what the config says. A broker serving zero refs, or a client group with unknown members, passes every other check. The checks, by the name each reports under:

Group | Checks | What they answer
--- | --- | ---
Install identity | `config`, `identities`, `client group`, `secrets group`, `secrets` | Is there an install; do the accounts and groups exist; does any account hold a group grant this install does not use; is the secrets directory the keeper's alone. The first two are hard failures that stop the run. `secrets group` is reported only when that group differs from the client group
Daemons | `sockets`, `unit drop-ins`, `broker`, `version`, `protectproc`, `managed store` | Are the socket units listening and enabled; does a drop-in override a unit; does `--check` pass; do the CLI and the running broker report the same build; do the units keep `ProtectProc=invisible`; what the store the broker read holds. A store with no managed file is a warning, not a failure: a `[[secret.link]]` entry can fill the value set by itself. A file that is present and did not load is a failure
Store health | `refused refs`, `shadowed refs`, `linked refs` | Refs the redactor refused (never injected, never redacted); a ref two managed files define differently (one of the values is in no redactor); linked files that did not load (their refs answer nothing)
Memory | `memory bounds`, `broker memory` | Whether the executor's per-process bound fits inside its cgroup total, and what the broker holds against its limit. Both are read from systemd, because the limits resolve against the cgroup's own numbers
Key material | `age key`, `agent keys`, `audit log`, `ssh key` | The age key is readable only by the keeper; the executor can traverse the agent account's home and no more, and cannot read or list its `~/.ssh`, `~/.config/sops` and `~/.gnupg`; the log and the SSH keys are equally closed to it, while it can still authenticate
Files | `config ownership`, `config reach`, `installed files`, `deny patterns` | The config, `.sops.yaml`, the binary, `wrap.sh` and the PAM helper are not writable by the operator; the broker's account can read the config (a reload needs this); the guard's pattern file matches what this install renders. `deny patterns` re-renders the file and compares: a rule missing from the host refuses less than the config asks and fails; a spare rule warns. Every rule is compiled first, because the hook skips a rule it cannot compile and a re-render would not notice. Comments are not compared
Sockets | `keeper socket`, `executor socket`, `broker socket`, and a `policy` check for each of the first two | The internal sockets are closed to the accounts that must not open them; the broker's is open to the operator; each `allowed_user` names the broker
Linked secrets | `linked file access`, `linked files` | Each linked file is readable by the broker's account and not by the executor, asked as those accounts rather than read off the mode; every linked path is refused by the agent's deny rules
Blocked paths | `blocked paths`, `derived paths` | Every `[[secret.block]]` path is refused by the agent's deny rules. The broker's own refusal of such a path is daemon behaviour and is not checked here. Whether the path exists is not asked: an entry for a key on an unmounted volume is still correct. Every entry carrying `derived_from` still names what its symlink resolves to; one whose symlink was repointed since it was declared fails, and `block add` naming the symlink again replaces it. A path that is not there is not judged
Behaviour | `brokered command`, `ssh agent`, `redaction`, `known hosts` | A managed value injected into a real command comes back as its token; the SSH relay answers; how many host keys a brokered `ssh` can verify against
sops | `sops config`, `rule coverage`, `recipient drift` | `.sops.yaml` names the keeper's current recipient and contains nothing sops would refuse; its rule covers every file in the managed store; every encrypted file is sealed to the recipients the rule names now
Agents | `agent rules`, `hook reach`, `agent code`, `agent rule drift`, `install rules`, `tree config`, `tree modes`, `agent file ownership`, `codex hook trust` | Each agent's deny rules are present, absent, or carried in an extension; each registration of the guard answers for every tool (one that matches fewer leaves the agent's file tools unguarded); the plugin and hook files still hold what `init` writes; rules an earlier version wrote and this one does not; the account-wide rules still name the paths this install writes (re-run `init` to restore them); enrolled trees still hold their agent files, credentials sections and rules frontmatter, at the right modes, in sticky directories; files an install would now refuse to write; whether Codex trusts the hooks written for it
Sudo and kernel | `sudo credential`, `sudo grant`, `cgroup delegation`, `ptrace scope`, `user namespaces` | [What escalation costs](escalation.md#what-escalation-costs-beyond-the-grant)
Rotation | `log rotation` | logrotate is installed, its rule names the log the broker writes, and the rule has been applied

Statuses are `ok`, `warn`, `failed` and `n/a`. `n/a` is a check whose subject this install does not have, counted in its own total so that it never reads as a pass. A run that stops early (no config, or an account that does not resolve) counts the remaining checks under `examination` as unasked, so one failure never reads as a host where everything else passed. Every probe runs on a deadline: a hung `systemctl` or broker is reported as unasked instead of hanging the run.

- **Version skew fails.** If a new binary is installed and the daemons were never restarted, every other finding describes a build that is not running. Re-run `init`. The daemons also refuse a request from another version ([version](protocol.md#version)). A broker that does not answer at all is a warning: `doctor` is for a stopped install too. Two builds with the same version string are told apart by `build`, which is what makes the check work between two `dev` builds.
- **`agent rules` reads `<config-dir>/enrolled.json`.** A tree depends on rules kept elsewhere, and the agent it was enrolled for may leave no trace in the home. An entry keeps every agent the tree carries, so enrolling one agent by name does not drop the others. An entry naming a tree that is not there is a warning, not a deletion: the tree may be unmounted.
- **`codex hook trust` fails on a hook Codex will not run.** Codex skips a hook it has not been told to trust and says nothing about it, so a guarded and an unguarded Codex look the same until this is asked. The check reads `~/.codex/config.toml` and compares what Codex recorded against the identity Codex computes for each hook on disk, so a hook trusted before a release rewrote it reads as untrusted. Only Codex's own prompt grants the trust: start Codex once where the hook is.
- **`agent rule drift` names rather than deletes.** An entry in those files is a bare string or a key, so a rule faramir left behind and a rule you wrote for the same path look identical. Extra refusals are untidy, not unsafe.
- **Three checks run a brokered command** instead of reading a mode: `ssh agent`, `brokered command` and `redaction`. The last seals a synthetic value into the store, expects exactly its token back, and removes it. The first two skip against a broker known to hold no values. `brokered command` and `redaction` need root; `ssh agent` runs as the caller. A refusal from a broker whose `--check` read every managed file is a failure, not a skip: the daemon came up before those files were written.

**Without sudo**, checks that need another uid report as unchecked, grouped at the end, with a line under the totals counting them. The checks that ask what an account can reach report under `boundaries` as one line with a count, because no account can answer that question for another.

**Without the agent's account**, most boundary checks cannot run: `access(2)` answers "no" for an account that cannot be named, which is the same answer a holding boundary gives. From a root shell or cron, `doctor` takes the account from `$FARAMIR_OPERATOR`, then `SUDO_USER`, then the calling account, then `[server] agent_user`, refusing root and faramir's own accounts at each step. Those checks report as unasked only when none of the four names an account, which means `init` has not finished: `faramir init --agent-user` records it, and `doctor` has no such flag.

**Finding the install.** `doctor`, `enrol`, `uninstall`, `link`, `block`, `vault add`, `vault edit`, `vault ls`, `vault rm`, `reader` and `logs` all act on an existing install. None of them takes the path as a flag. They find it in this order, whether they need the directory or the file:

Order | Source
--- | ---
1 | `$FARAMIR_CONFIG`, which skips the rest
2 | the running broker's own answer, asked at `$FARAMIR_SOCKET`, else `/run/faramir/broker.sock`
3 | the `FARAMIR_CONFIG=` line in the broker's unit, which covers a host whose config moved and whose broker is down

If nothing answers, the command fails and names both places it asked. It does not fall back to the compiled-in default: acting on the wrong install is worse than an error. A config file the ladder named but did not find is the same error. `$FARAMIR_CONFIG` is the way out, and the only thing an operator needs to say. It names the config **file**, not its directory; a directory value is refused.

`init` is the exception and takes `--config-dir`: a host with no install has no broker to ask and no unit to read, and `init`'s caller decides where the config goes. It asks the broker and reads the unit like the other commands, then falls back to `/etc/faramir`, and prints its choice before writing. `init` ignores `$FARAMIR_CONFIG`: it is a shell variable that `sudo -E` carries through, and a leftover from an earlier command must not decide where a host is provisioned.

`enrol --dry-run` is the other exception. It runs without an install: it writes nothing, so it has no wrong install to act on, and reporting on a tree from an unprovisioned host is what it is for.

`$FARAMIR_CONFIG` selects the install and nothing else. It does not stop a command from asking the broker. `doctor` asks whichever broker it points at, because a check that needs the broker's version must ask before it can report that the broker did not answer. Asking activates a stopped socket, so `doctor` samples the socket states before the round trip and reports the host as it found it.

The daemons skip step 2: each may be about to bind that socket, and connecting would activate the installed daemon and leave the two contending for the path. Under systemd this never happens, because the units set `FARAMIR_CONFIG` themselves. It matters for `faramir broker --check` run from a shell on an install away from the default path.

## The files an install writes into your agent's config

There are two kinds, and the kind decides what a run may do to the file.

**Faramir's own** are replaced whole and owned by faramir: the plugins and Pi's extension. Nothing else is.

**Yours** are edited and left yours. An agent's settings file gets only faramir's keys merged in.

- In an enrolled tree, Claude Code's file is `.claude/settings.local.json`, not `.claude/settings.json`. Everything written there names a path on this machine, and `settings.json` is the file Claude Code shares with your team. The account-wide rules go to `~/.claude/settings.json`.
- Codex's tree hook is `.codex/hooks.json`. Its account-wide hook has the same name under the home.
- Neither tree file is git-ignored by default. The enrolment says so when nothing ignores it.
- Your agent instructions file gets only the block between `<!-- BEGIN faramir: credentials -->` and `<!-- END faramir: credentials -->`.
- An existing file keeps its owner and mode. It keeps its group too, except in a tree, where the client group must be able to read the file the hook is written into. Only a file a run creates takes an owner from the run, and only one created in a rules directory gets the frontmatter that agent needs to load it.

A run stops rather than write a file it should not, and leaves it as it was:

- **Not yours.** These commands run as root on paths in directories your agent's account can write. Root must not edit somebody else's file, and must not chown it to make it yours.
- **A symlink it will not follow.** A symlink is followed and its target is written, so a dotfiles-managed `CLAUDE.md` or `settings.json` is updated in place. The target must be a regular file you own, and in a tree it must be inside the tree; otherwise the tree's group and mode would land on a dotfiles copy outside it.
- **Markers it cannot delimit.** One marker without the other, or a credentials section that is outside markers and differs from what would be written now. Either would leave two contradicting sets of instructions. Restore the markers or delete the section, then run again.
- **One file twice.** Two paths in one run that a symlink makes the same file, such as `~/.gemini/GEMINI.md` pointing at `~/.claude/CLAUDE.md`. Each path is written for the agent that reads it, so one file standing in for two would keep only the last write. Point one at a file of its own. Two cases are fine: two agents that read the same file *by name* get one file with a section that claims only what holds for both; and a tree's instructions files all carry the same section, so a `CLAUDE.md` linked to the tree's `AGENTS.md` is written once.

Every check runs before anything is written, so a refusal changes nothing: `init` stops before it hands a file to any account, and `enrol` before it shares the tree. `init` names every file it refused, not only the first. `doctor` asks the same questions under `agent file ownership`.

The section tells the agent to wait for an escalation only where one can be raised. `enrol` reads `[sudo] exec_user` from the config to decide.

A brokered command cannot delete these files: each agent's directory in a tree is sticky ([modes](layout.md#what-the-modes-decide)). The tree root is not sticky on purpose, so a tool can rewrite a lock file by rename, and a brokered command can move an agent's directory aside from above.

## Operator commands

**Every command that changes the install or needs root is refused to the coding agent's shell**, with sudo and without. The agent may run:

- `run`, `redact`, `status` and `refs`
- `version`, `help` and `completion`, which do not reach the broker
- `doctor`, `block ls`, `link ls` and `reader ls`, which describe the install without changing it and work without root

`logs` is refused even though it only reads the audit log: it needs root, and needs it through the broker as well, so allowing it would answer with a permission error pointing at a `sudo` that is also refused.

- All need root except `doctor`, which degrades without it, and the three that only read: `reader ls`, `link ls` and `block ls`.
- Five take a subcommand: `faramir vault` (the encrypted secret files), `faramir link` (a secret another tool owns), `faramir block` (a path refused to the agent and never read), `faramir reader` (which keys can decrypt the files) and `faramir sudo` (a brokered command's request to run `sudo`). `vault` and `link` share one ref namespace and nothing else: a ref is not marked as linked, and moving a secret between them does not rename it.

Command | Does
--- | ---
`sudo faramir enrol [DIR]` | Enrols one working tree, `DIR` defaulting to the current working directory: [shares the tree](layout.md), writes the credentials section into the tree's agent instructions file and into the separate file Claude Code, Codex and Antigravity read ([which name](layout.md)), and registers the routing hook for the two agents whose hook approves as well as rewrites: Claude Code's in `.claude/settings.local.json` and Codex's in `.codex/hooks.json`. The deny rules are `init`'s and hold account-wide. `--agent` picks the agents ([the names](../README.md#supported-agents)); `--client-group` shares the tree with another group than the installed config's; `--dry-run` writes nothing. The installed `config.toml` must be readable, because the linked and blocked paths are only there. Refused, after resolving symlinks: a home directory, `/`, anything above a home, the system directories (`/etc`, `/usr`, `/var` and their kind) and faramir's own directories
`sudo faramir doctor` | Reports whether the install works, and as root what each account can reach. [What it checks](#checking-an-install)
`sudo faramir vault add NAME` | Writes a new managed file, `NAME` relative to the secrets directory, with `.sops.yml` added for you. Opens an editor on a `0600` file in a tmpfs, so no plaintext reaches a disk. The editor runs as root over the decrypted value, so it must be a program only root can write or replace: `--editor`, `$VISUAL` and `$EDITOR` each name one by absolute path with no arguments, and each is checked. [How the editor is chosen](#choosing-the-editor) `--from FILE` encrypts a file you already have. `NAME` may not contain a byte a terminal acts on: every command that touches the file prints it and passes it to a shell
`sudo faramir vault ls` | The managed files by name, how many refs each holds, who can read it, and whether it agrees with the rule. Reads the directory rather than asking the broker, so a file the broker refused to load is listed with the reason. Decrypts nothing. `--json`
`sudo faramir vault rm NAME` | Removes a file from the store. Names the refs it will destroy and asks `[y/n]`; `--force` answers yes for a script. The audit record keeps the refs it held
`sudo faramir vault edit FILE` | Opens a managed sops file, decrypted to a `0600` file in a root-owned tmpfs, and re-encrypts it on save. `FILE` is any managed file, by name, base name or path. `--editor`, `$VISUAL` and `$EDITOR` name the editor. [How the editor is chosen](#choosing-the-editor)
`sudo faramir reader add KEY` | Lets one more key decrypt the store: validates it, adds it to `<config-dir>/.sops.yaml`, and re-encrypts every managed file to it, so the rule and the ciphertext agree. `--dry-run` writes neither. [What it refuses](#adding-a-reader)
`sudo faramir reader rm KEY` | The reverse. Does not reach a copy of the ciphertext somebody already holds
`faramir reader ls` | Who the store is sealed to. Needs no root: `.sops.yaml` holds public keys and no value. As root it also marks this host's own keeper. `--json`
`sudo faramir reader reseal [FILE...]` | Re-encrypts to the recipients `<config-dir>/.sops.yaml` names now: every managed file, or only the ones named. The repair for a pass that reached only some files. `--dry-run` writes nothing
`sudo faramir link add REF FILE` | Reads a secret from a file another tool maintains instead of copying it in; `--type` and `--key` say how. `REF` is the name a caller asks by, with or without the `faramir://` prefix `faramir refs` prints. Grants the broker read, refuses the file to the agent's file tools, writes the entry and reloads. `--json`. [Detail](configuration.md#linked-secrets)
`sudo faramir link rm REF` | Removes the entry, so the value leaves the redactor, and removes the deny rule it wrote. Does not undo the grant, and prints the `chmod` that does. `--json`. [Detail](configuration.md#linked-secrets)
`faramir link ls` | The linked secrets this install declares, and whether each file exists. `--json` prints the entries as the config holds them, without the state column. [Detail](configuration.md#linked-secrets)
`sudo faramir block add --path PATH` | Refuses one path to the agent's file tools, to its shell, and to a brokered command that would print it, without opening it. Writes the entry, re-renders the rules and reloads. No grant, no mode change, no value in the redactor. `--json`. [Detail](configuration.md#blocked-paths)
`sudo faramir block add --command COMMAND` | Blocks a command, written as it would be typed (`op read`). Reaches the guard and the broker; a file tool cannot name a command. [Detail](configuration.md#what-each-form-accepts)
`sudo faramir block add --strict` | Applies to every `--path` in the same command. Narrows the **brokered** route to refusing every command that *names* the path, not only the ones that would print it. Changes nothing for the agent's own shell, which refuses a declared path whenever it is named. Not for `--command`, which already matches wherever a command starts; the key is refused on a hand-written command entry. `faramir link add` takes the same flag. [Detail](configuration.md#refusing-every-mention-of-an-entry)
`sudo faramir block rm --path PATH` | Removes the entry, so `init` stops rendering the rule. `--command` removes a command entry; the form is part of the entry's identity. Repeatable, like `add`. `--json`. [Detail](configuration.md#how-the-entries-behave)
`faramir block ls` | Everything blocked here: the declared entries in a table of kind and entry, and under it the rules faramir carries itself. `--declared` and `--built-in` show one half. `--json`. [Detail](configuration.md#blocked-paths)
`sudo faramir logs [LOG-ID]` | Recent audit records, one row each: log id, local time, op, outcome, values replaced, and the command. With an id, one record in full. `--count`/`-n` bounds what is parsed as well as printed; `--json` prints records instead of rows; `--watch` follows the log across a rotation. Reads the log `[audit] log_path` names and takes no path of its own. Rotated files are not searched
`sudo faramir sudo ls` | Lists the escalation a brokered command is waiting on, and exits. Exit status is `0` if something was waiting, `1` if nothing was, `69` if the broker could not answer
`sudo faramir sudo watch` | Waits for questions, answers them from that terminal, and reports how each approved run ended. A separate command rather than a flag on `ls`: it holds the terminal and keeps reporting after the question is settled. [How to run a watcher](escalation.md#what-happens-when-a-command-runs-sudo)
`sudo faramir sudo approve ID` | Approves. The id is required, so that nobody approves a command they have not seen
`sudo faramir sudo reject [ID]` | Refuses. The id is optional, because only one question is outstanding at a time. Without one it prints the question it refused
`sudo faramir reload` | Stops the daemons. The next brokered command starts them on the changed config. All three are socket activated, so stopping them is enough. [When you need it](#when-a-reload-is-needed)
`sudo faramir uninstall` | Removes the broker from the install it finds. Leaves the accounts, the config, the secrets, the key and the audit log, and says so: deleting the age key would make every managed sops file unreadable. Running it again is not an error: the removal is at fixed paths whether or not an install answers

At the broker these four `sudo` commands are two ops: `ls` and `watch` both ask `escalations`, and `approve` and `reject` both send `answer` with a different verdict. `escalations`, `answer` and `escalate` are root-only there too, checked with `SO_PEERCRED`, so the account the coding agent runs as cannot answer what the agent asked for. `escalate` is the op sudo's PAM helper asks, and the one that decides whether a brokered command becomes root.

**`init` refuses to run inside a brokered command.** It asks the broker what the agent holds before it finishes, and a brokered command already holds the escalation that got it to root, so no second one can run while it is held: nested, `init` would do every step and then fail its own verification. `doctor` reports the same nesting as a check it could not ask, not as a broken install. So `faramir run -- sudo make <playbook>` works for every playbook except the one that installs faramir; run that one from your own shell.

**Colour** is on when stdout is a terminal, off under `$NO_COLOR` whatever its value, and forced either way by `--color=always|never`. Every listing and report takes the flag: `block ls`, `link ls`, `vault ls`, `reader ls`, `logs`, `doctor`, `sudo ls`, `sudo watch` and `sudo reject`. `sudo approve` does not: it names an id and prints no report. Only faramir's own words are painted: column headings, kinds and states. A path, a ref or a filename is never painted, so a value cannot pass as one of faramir's words. Those are escaped too, along with every path a report prints: a terminal obeys what it is sent, and a carriage return in a filename could make a row read as a different entry. `--json` is never painted.

## When a reload is needed

The daemons read `config.toml` once, at start. The commands that change it reload for you. `reload` is for the changes nothing else covers:

- **You edited `config.toml` by hand.** Nothing watches the file.
- **A `block` or `link` command wrote its entry and then failed to reload**, and said so. Until the reload, an added block is not refused, a removed one still is, and an added link is a ref the broker does not serve.
- **You repaired a linked file's group or mode yourself.** [Why that needs a restart](configuration.md#keeping-a-link-working).
- **The config moved out of reach of the broker's account.** An install in that state keeps answering from what it already holds, so the reload is the first thing that fails. `doctor` checks it ahead of time.

A reload is not needed for a new or edited managed sops file, which the next refresh picks up ([why](redaction.md#the-value-set-is-everything-the-keeper-manages)), nor after a converge that found the host already correct: that would restart the daemons under a running brokered command.

## Rules a command does not state

- **Adding or editing a managed sops file needs no config change**, but both daemons must be running for the new values to be picked up.
- **Changing `config.toml` needs both daemons restarted, keeper first.** Neither re-reads it while running. [`faramir reload`](#when-a-reload-is-needed) does this.
- **The keeper must be up before the broker.** On a cold start there is no previous value set, so a broker that cannot reach the keeper has nothing to redact with and refuses `run` and `redact`. Its unit `Requires=` the keeper socket. A keeper lost *later* does not stop a running broker: it keeps its current set and retries.
- **Run `init` before enrolling a tree with opencode, Kilo Code or pi.** Their plugins fail closed, so a binary too old to know the agent refuses every command in that tree instead of running it unredacted. [What those plugins ask the guard](coding-agents.md#opencode-kilo-code-and-pi).
- **Children do not inherit the broker's environment.** They get `[command.env]` plus the injected secrets. Add what a tool needs there.
- **Interactive prompts fail rather than hang.** Stdin is `/dev/null` unless the caller piped something in with `faramir run -i`, and the child gets no controlling terminal either way. A prompt falls back to stderr, which is redacted and recorded; one written only to `/dev/tty` is lost ([why](redaction.md#why-a-pty-and-not-a-pipe)). A prompt that reads piped input gets the caller's first line, not a typed passphrase. Pass non-interactive flags.
- **Output is truncated** at the output cap. The audit record keeps the head and the tail and says how many bytes it dropped.
- **The audit log rotates weekly**, 8 kept, compressed, early at 16MB. The record cap bounds one record, not the file. `doctor` fails when logrotate is not installed, when `/etc/logrotate.d/faramir` is absent or unreadable, or when the rule names a log the broker does not write. It warns when logrotate's state shows the rule has never been applied. Rotating some other way makes `doctor` fail on that host.
- **A command that cannot be recorded does not run.** Before anything starts, the broker checks that the log can be opened and its filesystem has room for one record. A host that fails either refuses every brokered command with `no_audit`. This can happen without anyone at fault: a record carries the command's output, so an agent that prints enough fills the filesystem itself.
- **The audit log holds no value.** Output is recorded after redaction, and `argv` is redacted on the way in.
- **A brokered command is two records sharing one `log_id`.** `run_started` when the child runs, naming the command, the cwd and the refs; `run` when it ends, adding the exit code, the duration and the output. A run whose status was lost carries `status_unknown` and a stand-in code. So `faramir logs --watch` shows a playbook while it runs, and a run that never returns still leaves a row. `faramir logs <id>` shows the ending if there is one and the start if not. A reader selecting `op == "run"` still gets one record per command.
- **There is one SSH key and `init` owns it.** It mints both halves into `<config-dir>`, so the key follows the config wherever `--config-dir` puts it, like the age key. `--ssh-key` moves or adopts one.
- **A brokered `ssh` logs in as the executor.** `ssh host` with no user asks for `faramir-exec`, which is nobody's account on a managed host. Give the login (`ssh deploy@host.example.com`), or write one `User` per host into `/var/lib/faramir-exec/.ssh/config` as root; that directory is the child's `HOME`. Ansible needs neither: `ansible_user` is in the inventory.
- **A brokered `ssh` verifies against `/etc/ssh/ssh_known_hosts` and the executor's own file**; either is enough. The executor's file starts empty and nothing can prompt you to add to it, so a host trusted only in your `~/.ssh/known_hosts` is refused before the broker's key is offered. `init --known-hosts PATH` pins a file for the executor, replaced whole on each run. The system-wide file is the alternative and covers every account. An entry is filed under the name ssh dials, with the port in brackets when it is not 22 (`[host.example.com]:2222`).

  ```bash
  sudo ssh-keygen -R host.example.com -f /etc/ssh/ssh_known_hosts
  ssh host.example.com 'cat /etc/ssh/ssh_host_*_key.pub' \
    | awk '{print "host.example.com", $1, $2}' \
    | sudo tee -a /etc/ssh/ssh_known_hosts
  ```

  The removal first makes this re-runnable. Take every key type the host offers, because the algorithm is negotiated per connection. [ansible-ctrl's faramir role](https://github.com/andornaut/ansible-ctrl/blob/main/roles/faramir/tasks/ssh.yml) does this across a fleet.
- **Encrypt the disk.** LUKS on the root filesystem covers the age key, the secrets, the audit log and swap at once.

## What a record is

A record's content comes from the account being recorded: the command, the cwd and the output are all the agent's. So every bound below is applied where the record is built, not left to whatever reads it.

- One record is one line within the record cap, counted in encoded bytes: `<`, `>`, `&` and every control character cost six bytes each as JSON.
- An append is exclusive and all-or-nothing. A short write is rolled back, so a torn line cannot swallow the record after it.
- Every `log_id` is distinct: the second it was minted in, the writer's nonce, and a counter that only advances. Fourteen characters, with no readable time; every record says when it happened in a field of its own.

## Choosing the editor

`vault add` and `vault edit` run an editor as root over the decrypted value, so the editor must be a program only root can change. Four sources, in order, each checked:

Source | Is
--- | ---
`--editor PATH` | Given on the command line, for one run
`$VISUAL` | The invoking shell's, if it survived `sudo`
`$EDITOR` | The same, consulted after `$VISUAL`
the built-in list | `/usr/bin/vim`, `/usr/bin/vi`, `/bin/vi`, `/usr/bin/nano`, `/bin/nano`, first that passes

A named source that fails the check is refused, not skipped: you asked for it, and falling through would silently open the store in an editor you did not choose.

The check:

- **An absolute path with no arguments.** `vim -u /somewhere/vimrc` is a common `$EDITOR`, and `-u` names a file of commands vim runs at startup, so an argument is a way to hand root a script no ownership check would see. A path containing a space is refused.
- **Symlinks are resolved first, and the resolved path is what runs.** `/usr/bin/vi` is an alternatives symlink on Debian, and an ownership check of the link says nothing about its target.
- **The binary and every directory above it, up to `/`, belong to root and are writable by nobody else.** Write on a directory is permission to replace what it holds, and write on the parent is permission to replace the directory, so checking one level is not enough.
- **The editor's environment is fixed**: `PATH`, `TERM`, `LANG`, and `HOME` pointed at the `0700` tmpfs holding the plaintext. This stops a root-owned editor from reading somebody else's `.vimrc`.

**`sudo` drops `$VISUAL` and `$EDITOR` unless the sudoers keep them.** Neither is in the default `env_keep`, and sudo reads them itself only for `sudoedit`. So under a stock `sudo faramir vault edit` both are empty and the built-in list decides. They take effect where you are already root, or where `env_keep` has been set.

## Adding a reader

A reader is an age recipient named in `.sops.yaml`: a key that can decrypt the managed store. `init` seals the store to one: the keeper's own, minted on the host. It writes `.sops.yaml` once and keeps it on every later run, reading it back and reporting its readers as `age_recipients`. Re-running the installer never changes a reader. `faramir vault edit` does not apply a changed rule either: it re-encrypts to the readers the file already carries, so an edit cannot drop one.

Granting a second key is one command, as root, at any point:

```bash
sudo faramir reader add age1hwvv...    # the rule and the ciphertext together
```

Where the key comes from is up to you: another operator's key, one a second host's `init` minted, or one a plugin holds. Mint a new one with `age-keygen -o FILE` on the machine that will hold it.

A second reader and a backup cover different losses. Another reader keeps the *values* readable if this host's key is gone; the [archive below](#backing-up-and-restoring) rebuilds *this host*. Neither replaces the other.

`reader add` validates the key, edits the rule, checks the keeper is still a reader, writes the file, and re-encrypts every managed value to the new list, keeping each file's ownership and mode. `--dry-run` reports the rule change and which files would be rewritten, and writes neither.

- **The rule and the ciphertext are changed together.** That is why this is one command. A rule naming a reader the existing files are not sealed to fails nothing by itself: new files get the new list, old ones keep the old, and the mismatch only shows when somebody tries a key they were told they had.
- **The key is checked before anything is written.** An identity (private key) given where a recipient belongs is refused by name. `.sops.yaml` is `0644`, so an identity written there is readable by every account on the host: treat it as disclosed and rotate. `sudo faramir doctor` asks the same question of the file under `sops config`.
- **A rule that drops the keeper's own key is refused** before anything is decrypted. It would leave secrets nothing on the host can open.
- **Dropping a reader does not reach a copy already held elsewhere.** Treat what that key could read as read.
- **`reader reseal` is for a `.sops.yaml` changed some other way.** Root can write a root-owned file however it likes. `reseal` takes the rule as it stands and brings the store to it.
- **`doctor` reports the mismatch** under `recipient drift`, so a drifted store is found before a value fails to decrypt.
- **A `.sops.yaml` with more than one creation rule is refused**, because the recipients would then depend on which `path_regex` a file matches. The count holds however the rules are written: keys in any order, flow style, `age:` as a string or a list. Use `sops updatekeys` per file: only sops can say which rule governs which file.
- **A rule that splits the data key is refused too.** `shamir_threshold` means N key groups together, and re-encrypting to one list would make it any one of them.
- **The rule is `<config-dir>/.sops.yaml`, and no flag names another.** Both commands hand sops that file and judge it against the managed file's real path, not the tmpfs copy the plaintext passes through. Left to search, sops walks up from the current working directory, which may be a tree the coding agent writes, and an `unencrypted_regex` in a rule found there would write managed values in the clear. `$FARAMIR_CONFIG` moves the whole install, which is how to act on another one. If the file is removed, `edit` falls back to sops' defaults and `reseal` stops, because that file is where its recipients come from.
- **A file no creation rule covers cannot be written back.** `edit` checks before opening the editor, so it costs a refusal rather than what you typed. `doctor` checks every managed file under `rule coverage`. This only happens when the rule was narrowed, or the managed store contains a file the shipped `*.sops.yml` rule does not match.

## Backing up and restoring

Back up the config directory as a unit. `/etc/faramir` holds the age key, the creation rule and the ciphertext, and none of the three is useful without the others.

```bash
sudo tar czf faramir-backup.tgz -C / etc/faramir
```

To restore a host that no longer exists, you need that archive, the binary, and `init`:

```bash
sudo tar xzf faramir-backup.tgz -C /
sudo faramir init --agent-user <account>
```

`init` adopts what it finds. An existing `age.key` is reported `ok` rather than `changed` and is never overwritten, and an existing `.sops.yaml` is kept and read back. The accounts, units, modes and group are rebuilt around the key and the ciphertext, and nothing is re-encrypted. The same run imports a store from elsewhere: put the files in place first.

- **The archive is the secret.** Everything under `secrets/` opens with the key beside it, so the archive is worth exactly what the store is.
- **Nothing exports the identity.** `tar` and `cp` already do, and a command for it would be one more thing an agent could be talked into running.
- **No command decrypts with a key other than the install's own.** The check that keeps this host a reader reads the key it is handed, so a run pointed at a second identity could take the host's own key out of the rule and reseal the store without it.
