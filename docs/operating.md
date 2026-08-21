# Operating an install

Check it, run it, and change who can decrypt.

## Checking an install

```bash
sudo faramir doctor
```

A broker serving zero refs and a client group with members nobody recognises both look healthy otherwise. `doctor` asks what only a real host can answer. The checks, by the name each reports under:

Group | Checks | What they answer
--- | --- | ---
Install identity | `config`, `identities`, `client group`, `secrets group`, `secrets` | Is there an install, do the accounts and groups exist, does anything hold a group's grant that this install does not use, is the secrets directory the keeper's alone. The first two are hard failures that stop the run; `secrets group` is reported only where that group is not the client group
Daemons | `sockets`, `broker`, `version`, `protectproc`, `secrets store` | Are the units listening, does `--check` pass, do the CLI and the running broker report the same build, is the broker's environment hidden, and what the store the broker read holds. Keeping no managed file is a warning rather than a failure: a `[[secret.link]]` entry fills the value set on its own, and a host that has not written its first secret is every install on its first day. A file that is there and did not load stays a failure
Key material | `age key`, `agent keys`, `audit log`, `ssh key` | The age key readable only by the keeper; the agent account's `~/.ssh`, `~/.config/sops` and `~/.gnupg` unreadable and unlistable by the executor; the log and SSH keys likewise, the executor still able to authenticate
Files | `config ownership`, `installed files`, `deny patterns` | The config, `.sops.yaml`, the binary, `wrap.sh` and the PAM helper not writable by the operator, and the deny list rendered for *this* config directory
Sockets | `keeper socket`, `executor socket`, `broker socket`, and a `policy` check for each of the first two | The internal sockets closed to the accounts that must not open them, the broker's open to the operator, and each `allowed_user` naming the broker
Linked secrets | `linked file access`, `linked files` | Each linked file readable by the broker's own account and not by the executor, asked as those accounts rather than read off the mode; and every linked path refused by the agent's deny rules
Refused paths | `refused paths` | Every `[[secret.refuse]]` path refused by the agent's deny rules, which is the whole of what one of those entries does. Whether the path is there is not asked: an entry for a key on an unmounted volume is doing its job
Behaviour | `brokered command`, `ssh agent`, `redaction`, `known hosts` | A managed value injected into a real command comes back as its token, the relay answers, and how many host keys a brokered `ssh` can verify against
sops | `sops config`, `rule coverage`, `recipient drift` | `.sops.yaml` names the keeper's own recipient rather than one it used to have, and nothing sops would refuse; its rule reaches every file the managed store names; and every encrypted file is sealed to what that rule says rather than to a set it used to name
Agents | `agent rules`, `agent rule drift`, `tree config`, `agent file ownership` | Each agent's deny rules present, absent, or carried in an extension; rules an earlier version wrote that this one does not; enrolled trees whose agent files no longer carry what the enrolment wrote; and files an install would now refuse to write
Sudo and kernel | `sudo credential`, `sudo grant`, `cgroup delegation`, `ptrace scope`, `user namespaces` | [What escalation costs](escalation.md#what-escalation-costs-beyond-the-grant)
Rotation | `log rotation` | logrotate installed, naming the log the broker writes, and having applied the rule

Four statuses: `ok`, `warn`, `failed`, and `n/a` for a check whose subject this install does not have, a separate total because a pass would claim a stack that is not there.

- **Version skew fails.** A new binary installed and the daemons never restarted onto it makes every other finding a report on the build that is not running. Re-run `init`. The daemons refuse a request naming another version outright ([version](protocol.md#version)), so this is met as a refused command as well as reported here. A broker that does not answer at all is a warning instead, `doctor` being for a stopped install as much as a running one.
- **`agent rules` reads `<config-dir>/enrolled.json`**, because a tree relies on rules kept elsewhere and the agent it was enrolled for may leave no trace in that home. An entry keeps every agent the tree still carries, so enrolling one by name does not drop the others; one naming a tree that is no longer there is warned about rather than forgotten, an unmounted tree not being a deleted one.
- **`agent rule drift` names rather than deletes.** An entry in those files is a bare string or a key, so one of ours left behind and one of yours refusing the same path look identical. Extra refusals, so untidy rather than unguarded.
- **Two checks run a brokered command** rather than reading a mode: `ssh agent` and `brokered command`. Both skip against a broker known to hold no values. `brokered command` needs root; the `ssh agent` probe runs as the caller. A refusal from a broker whose `--check` read every managed file fails rather than skips: a daemon refusing what those files cover came up before they were written.

**Without sudo**, checks needing another uid report as unchecked rather than passing, grouped at the end, with a line under the totals counting them: the totals alone would read the same on a host examined in full and on one where most questions were never put. The ones that ask what an account can reach report under `boundaries`, one line carrying the count rather than a name each, no account being able to answer that question for another.

**Without the agent's account**, most boundary checks cannot be put at all: `access(2)` answers "no" for an account that cannot be named, which is the same answer a boundary that holds gives. Run from a root shell or cron, `doctor` takes that account from `SUDO_USER`, finds none, and reports those as unasked. Pass `--agent-user` for the whole thing.

**Finding the install.** `doctor`, `init-project`, `uninstall`, `edit`, `reseal` and `logs` all act on an install they did not perform:

Order | Source
--- | ---
1 | `--config-dir`, or `--config` on `edit`, `reseal` and `logs`
2 | `$FARAMIR_CONFIG`, on `edit`, `reseal` and `logs` only, short-circuiting the rest
3 | the running broker's own answer, asked at `$FARAMIR_SOCKET`, else `/run/faramir/broker.sock`
4 | the `FARAMIR_CONFIG=` its unit names, which covers a host whose config moved and whose broker is down
5 | the compiled-in default

`init` follows the same chain and prints what it settled on before writing; naming `--config-dir` is still what puts an install somewhere new. The daemons skip step 3: each may be about to bind that socket, and connecting would activate the installed daemon and leave the two contending for the path. Under systemd none of this is reached, the units setting `FARAMIR_CONFIG` themselves; it is what makes `faramir broker --check` work from a shell on an install away from the default path.

## The files an install writes into your agent's config

Two kinds, and which one a file is decides what a run may do to it.

**Faramir's own** are replaced whole and owned outright: the plugins, and Pi's extension. Nothing else is, the MCP registrations included: those are yours, and a re-enrolment merges into them.

**Yours** are edited and left yours. Each agent's settings get only faramir's keys merged in. In an enrolled tree Claude Code's are `.claude/settings.local.json` rather than `.claude/settings.json`: everything written there names a path this machine decided, and the second file is the one Claude Code shares with your team. The account-wide rules go to `~/.claude/settings.json`, which is no tree's. It is not git-ignored unless something ignores it, so an enrolment says so when nothing does; your agent instructions file gets only the block between `<!-- BEGIN faramir: credentials -->` and `<!-- END faramir: credentials -->`. A file already there keeps its owner and mode, and its group except in a tree, where the client group has to read what the hook is written into. Only a file a run creates takes an owner from it, and only one created in a rules directory gets the frontmatter that agent needs to load it.

A run stops rather than write one it should not, leaving it exactly as it is:

- **Not yours.** These commands run as root on paths in directories the account your agent runs as can write. Editing somebody else's file would be root writing what it was never asked to, and chowning it to make that true would take it from them.
- **A link this will not follow.** A link is followed and what it points at written, so a dotfiles-managed `CLAUDE.md` or `settings.json` is updated in place rather than replaced by a regular file. Only to a regular file you own, and in a tree only inside the tree: otherwise the tree's group and mode would land on a dotfiles copy outside it.
- **Markers it cannot delimit.** One marker without the other, or a credentials section that is not between markers and is not what is written now, which would leave two sets of instructions contradicting each other. Restore the markers or delete the section, then run again.
- **One file twice.** Two paths in the same run that a link makes one file, such as `~/.gemini/GEMINI.md` pointing at `~/.claude/CLAUDE.md`. Each is written for the agent that reads it, so one file standing in for two would keep only the last write and report success. Point one at a file of its own. Two agents that read the same file *by name* are not this: that is one file written once, and the section it gets claims only what holds for both.

Each is asked before anything is written, so a refusal costs nothing: `init` stops before it has handed a file to any account, `init-project` before it has shared the tree. `init` names every file it refused rather than the first. `doctor` asks the same questions under `agent file ownership`.

The section tells an agent to wait for an escalation only where one can be raised, `init-project` reading `[escalation] exec_user` from the config.

A brokered command cannot delete these files, each agent's own directory in a tree being sticky ([modes](layout.md#what-the-modes-decide)). The tree root is deliberately not sticky, which keeps a tool rewriting a lock file by rename working and leaves a brokered command able to move an agent's directory aside from above.

## Operator commands

**Every one of these is refused to the coding agent's shell**, with sudo and without. An agent may run `run`, `redact`, `status` and `refs`, plus `version`, `help` and `completion`, which reach no broker; the rest act on the install rather than through it.

- All need root except `doctor`, which degrades, and the three that only read: `recipient ls`, `link ls` and `refuse ls`.
- Four group: `faramir vault` acts on the managed store, `faramir link` on a secret another tool owns, `faramir refuse` on a path refused to the agent and never read, and `faramir recipient` on who can decrypt the store. The first two share one ref namespace and nothing else, so nothing marks a ref as linked and moving a secret between them does not rename it.

Command | Does
--- | ---
`sudo faramir init-project [DIR]` | Enrols one working tree, `DIR` defaulting to the current working directory: [shares the tree](layout.md), registers the hook, the deny rules and the MCP server in each enrolled agent's settings, and writes the credentials section into the tree's agent instructions file. The installed `config.toml` has to be readable, the linked and refused paths among those rules being only there. A home directory, `/`, anything above a home, the system directories (`/etc`, `/usr`, `/var` and their kind) and faramir's own directories are refused, symlinks resolved first
`sudo faramir doctor` | Reports whether the install is doing its job, and as root what each account can reach. [What it checks](#checking-an-install)
`sudo faramir vault add NAME` | Writes a new managed file, `NAME` relative to the secrets directory with `.sops.yml` added for you. `$EDITOR` on a `0600` file in a tmpfs, so no plaintext reaches a disk; `--from FILE` encrypts one you already hold
`sudo faramir vault ls` | The managed files by name, how many refs each names, who can read it, and whether it agrees with the rule. Reads the directory rather than asking the broker, so a file the broker refused to load is listed with the reason. Decrypts nothing. `--json`
`sudo faramir vault rm NAME` | Takes a file out of the store, naming the refs it will destroy and asking for the file's name back; `--force` answers for a script. The audit record keeps the refs it held
`sudo faramir vault edit FILE` | Opens a managed sops file, decrypting to a `0600` file in a root-owned tmpfs and re-encrypting on the way out. `FILE` is any managed file, by name, base name or path. `--editor` names the editor
`sudo faramir recipient add KEY` | Lets one more key decrypt the store: validates it, adds it to `<config-dir>/.sops.yaml`, and re-encrypts every managed file to it, so the rule and the ciphertext never disagree. `--dry-run` writes neither. [What it refuses](#adding-a-recipient)
`sudo faramir recipient rm KEY` | The same in reverse. Reaches no copy of the ciphertext somebody already holds
`faramir recipient ls` | Who the store is sealed to. Needs no root, `.sops.yaml` holding public keys and no value; as root it also marks this host's own keeper. `--json`
`sudo faramir recipient reseal [FILE...]` | Re-encrypts to the recipients `<config-dir>/.sops.yaml` names now: every managed file unless some are named. The repair path for a pass that reached only some of them. `--dry-run` writes nothing
`sudo faramir link add REF FILE` | Reads a secret out of a file another tool maintains, instead of copying it in; `--type` and `--key` say how. Grants the broker read, refuses the file to the agent's file tools, writes the entry and reloads. Read as root first, so a selector naming nothing fails here rather than in every later command, and again as the broker's own account to check the grant landed. The entry this install already carries is re-applied rather than refused, which is the repair; the same ref against a different file, type or key is refused. `--json`. [Detail](configuration.md#linked-secrets)
`sudo faramir link rm REF` | Drops the entry, so the value leaves the redactor. It undoes neither the grant nor the deny rule, a merged rule file only being addable to, and prints both with what would narrow them. A ref this install does not carry is not an error. `--json`
`faramir link ls` | The linked secrets this install declares, and whether each file is there. `--json` prints the entries as the config carries them, without the state column, for a caller that wants the ref, path, type and key exactly
`sudo faramir refuse add PATH` | Refuses one path to the agent's file tools, without opening it. Writes the entry and re-renders the rules, and nothing else: no grant, no mode change, no value in the redactor. A path that is not there is recorded and reported, an unmounted volume being the case it is for. A path this install already refuses is re-rendered rather than refused. `--json`. [Detail](configuration.md#refused-paths)
`sudo faramir refuse add --name PATTERN` | The same, against a name rather than a path: a file name, a suffix (`*.pem`), a prefix (`.env*`), a name with a wildcard (`secrets*.yml`) or a directory (`.storage/`). Matched against what the agent names rather than against this host, which is what reaches a path the host does not have, a container's mount point being the case it is for. The wider form, so what a pattern will match is printed as it is written
`sudo faramir refuse rm PATH` | Drops the entry, so `init` stops rendering the rule. A rule compiled into faramir is refused rather than removed, whether it is named as a pattern or as a file it covers: it is not an entry, and the host goes on refusing it. It does not take the rule out of an agent's file, a merged rule file only being addable to, and says so. A path this install does not refuse is not an error. `--name` removes a name entry; the form is part of what identifies one, so a name is not removed by giving the same string as a path. `--json`
`faramir refuse ls` | What the agent's file tools are refused, in two parts under a `SOURCE` column: the rules compiled into faramir, and the entries this install declares, with whether each declared path is there. The built-ins are listed because nothing else can be asked what they cover, a refusal naming the rule that matched rather than the set. `--declared` narrows it to the entries the config carries, which is the list a configuration manager converges and the one that prints `[]` when there are none. `--json`
`sudo faramir logs [LOG-ID]` | Recent audit records, one row each: log id, local time, op, outcome, values stood in for, and the command. With an id, one record in full. `--count`/`-n` bounds what is parsed as well as printed, `--json` prints records rather than rows, `--watch` follows the log across a rotation, and `--color` is `auto`, `always` or `never`. Reads the log `[audit] log_path` names and takes no path of its own. Rotated files are not searched
`sudo faramir escalations [--watch]` | Lists the escalation a brokered command is waiting on. `--watch` waits for questions, answers them from that terminal, and reports how each approved run ended. [How to run a watcher](escalation.md#what-happens-when-a-command-runs-sudo)
`sudo faramir approve ID` | Say yes. The id is required: an escalation that names no command is one nobody judged
`sudo faramir deny [ID]` | Say no. The id is optional, one question being outstanding at a time
`sudo faramir reload` | Stops the daemons, so the next brokered command starts them on a changed config. All three are socket activated
`sudo faramir uninstall` | Removes the broker from the install it finds. Leaves the accounts, the config, the secrets, the key and the audit log, and says so: deleting the age key would make every managed sops file unreadable, retroactively

At the broker these are three ops rather than four, `deny` being `approve` with a no: `escalations`, `approve` and `escalate` are root-only there too, checked with `SO_PEERCRED`, so the account the coding agent runs as cannot answer what the agent asked for. `escalate` is the one sudo's PAM helper asks, and so the one that decides whether a brokered command becomes root.

## Rules a command does not state

- **Adding or editing a managed sops file needs no config change**, but both daemons must be running for the new values to be picked up.
- **Changing `config.toml` needs both daemons restarted, keeper first.** Neither re-reads it while running.
- **The keeper must be up before the broker is.** On a cold start there is no previous value set, so a keeper it cannot reach means nothing to redact with, and the broker refuses `run` and `redact`. Its unit `Requires=` the keeper socket. A keeper lost *later* does not stop a running broker: it keeps the set it has and retries.
- **Run `init` before enrolling a project with opencode or Kilo Code.** Their plugins fail closed, so a binary too old to know the agent refuses every command in that project rather than running it unredacted. [What those plugins ask the guard](coding-agents.md#opencode-and-kilo-code).
- **Children do not inherit the broker's environment.** They get `[command.env]` plus injected secrets. Add what a tool needs there.
- **Interactive prompts fail rather than hang.** Stdin is `/dev/null` and the child gets no controlling terminal, so a prompt falls back to stderr, which is redacted and recorded; one written only to `/dev/tty` is lost ([why](redaction.md#why-a-pty-and-not-a-pipe)). Pass non-interactive flags.
- **Output is truncated** at the output cap. The audit record keeps the head and the tail and says how many bytes it dropped.
- **The audit log rotates weekly**, 8 kept, compressed, early at 16MB. The record cap bounds one record, not the file. `doctor` fails when logrotate is not installed, when `/etc/logrotate.d/faramir` is absent or unreadable, and when the rule names a log the broker does not write; it warns when logrotate's state shows the rule has never been applied. Rotating some other way means `doctor` failing on that host.
- **A command that cannot be recorded does not run.** Before anything starts the broker checks the log can be opened and its filesystem has room for one record; a host failing either refuses every brokered command with `no_audit`. Reachable without anyone being at fault: a record carries the command's output, so an agent that prints enough fills that filesystem itself.
- **The audit log holds no value.** Output is recorded after redaction and `argv` is redacted on the way in.
- **A brokered command is two records sharing one `log_id`.** `run_started` when the child runs, naming the command, the cwd and the refs; `run` when it ends, adding the exit code, the duration and the output. So `faramir logs --watch` shows a playbook while it runs rather than only once it is over, and a run that never returns still leaves a row. `faramir logs <id>` shows the ending where there is one and the start where there is not. A reader selecting `op == "run"` still gets one record per command, the one that says how it went.
- **There is one SSH key and `init` owns it.** It mints both halves into `<config-dir>`, so the key follows the config wherever `--config-dir` puts it, the way the age key does. `--ssh-key` moves or adopts one.
- **A brokered `ssh` logs in as the executor.** `ssh host` naming no user asks for `faramir-exec`, which is nobody's account on a managed host. Give the login (`ssh deploy@host.example.com`), or write one `User` per host into `/var/lib/faramir-exec/.ssh/config` as root, that being the child's `HOME`. Ansible needs neither, `ansible_user` being in the inventory.
- **A brokered `ssh` verifies against `/etc/ssh/ssh_known_hosts` and the executor's own**, either sufficing. The executor's starts absent and nothing can prompt you to add to it, so a host trusted only in your `~/.ssh/known_hosts` is refused before the broker's key is offered. `init --known-hosts PATH` pins a file for the executor, replaced whole each run; the system-wide file is the alternative, covering every account at once. An entry is filed under the name ssh dials, port-bracketed where that is not 22 (`[host.example.com]:2222`).

  ```bash
  sudo ssh-keygen -R host.example.com -f /etc/ssh/ssh_known_hosts
  ssh host.example.com 'cat /etc/ssh/ssh_host_*_key.pub' \
    | awk '{print "host.example.com", $1, $2}' \
    | sudo tee -a /etc/ssh/ssh_known_hosts
  ```

  The removal first makes it re-runnable. Take every type the host offers, the algorithm being negotiated per connection. [ansible-ctrl's faramir role](https://github.com/andornaut/ansible-ctrl/blob/main/roles/faramir/tasks/ssh.yml) does this across a fleet.
- **Encrypt the disk.** LUKS on the root filesystem covers the age key, the secrets, the audit log and swap in one move.

## What a record is

A record's content comes from the account being recorded: the command, the cwd and the output are all the agent's, so every bound below is applied where the record is built rather than trusted to whatever reads it.

- One record is one line within the record cap, counted in encoded bytes: `<`, `>`, `&` and every control character cost six apiece as JSON.
- An append is exclusive and all-or-nothing. A write that lands short is taken back, so a torn line cannot swallow the record after it.
- Every `log_id` is distinct: the second it was minted in, the writer's nonce, and a counter that only advances. Fourteen characters, carrying no readable time, every record saying when it happened in a field of its own.

## Adding a recipient

`init` seals the store to one key: the keeper's own, minted on the host. It writes `.sops.yaml` once and keeps it on every later run, reading it back and reporting the recipients it lists as `age_recipients`, so nothing about a recipient is decided by re-running the installer. `faramir vault edit` does not apply a changed rule either, re-encrypting to the recipients a file already carries, so an edit cannot drop a reader mid-edit.

Granting a second key is one command, as root, at any point in a host's life:

```bash
sudo faramir recipient add age1hwvv...    # the rule and the ciphertext together
```

Where the key comes from is not faramir's business: another operator hands you theirs, a second host's `init` minted its own, or a plugin holds one. One nobody has yet is minted with `age-keygen -o FILE`, on the machine that will hold it.

A second recipient and a backup answer different losses. Another reader keeps the *values* readable if this host's key is gone; the [archive below](#backing-up-and-restoring) is what rebuilds *this host*. Neither substitutes for the other.

It validates the key, edits the rule, checks the keeper is still a reader, writes the file, and re-encrypts every managed value to what it now says, keeping each file's ownership and mode. `--dry-run` reports the rule change and which files would be rewritten, and writes neither.

- **The rule and the ciphertext are changed together**, which is what makes this one command rather than two. A rule naming a reader the existing files are not sealed to fails nothing: new files get the new list, old ones keep the old, and the divergence surfaces whenever somebody reaches for a value with a key they were told they had.
- **The key is checked before anything is written.** An identity where a recipient belongs is refused by name, `.sops.yaml` being `0644`: one that lands there is the key to the store readable by every account on the host, so treat it as disclosed and rotate. `sudo faramir doctor` asks the same question of a file however it was written, under `sops config`.
- **A rule that drops the keeper's own key is refused**, before anything is decrypted, that leaving secrets nothing on the host can open.
- **Dropping a recipient reaches no copy already held elsewhere.** Treat what that key could read as read.
- **`recipient reseal` is for a `.sops.yaml` changed some other way**, root being able to write a root-owned file whatever this page says. It takes the rule as it stands and brings the store to it.
- **`doctor` reports the disagreement** under `recipient drift`, so a drifted store is reported rather than met when a value will not decrypt.
- **A `.sops.yaml` with more than one creation rule is refused**, the recipients then depending on which `path_regex` a file matches. The count holds however the rules are written: keys in any order, flow style, `age:` as a string or a list. Use `sops updatekeys` per file, the only thing that can answer which rule governs which.
- **A rule that splits the data key is refused too.** `shamir_threshold` means N key groups together, and re-encrypting to one list makes it any one of them.
- **The rule is `<config-dir>/.sops.yaml`, and no flag names another.** Both commands hand sops that file and judge it against the managed file's real path, not the tmpfs copy the plaintext passes through. Left to search, sops walks up from the current working directory, which may be a tree the coding agent writes, and an `unencrypted_regex` in a rule found there writes managed values in the clear. `--config` moves the whole install, which is how to act on another one. Remove the file and `edit` falls back to sops' defaults, while `reseal` stops: that file is where its recipients come from.
- **A file no creation rule covers cannot be written back.** `edit` asks before opening the editor, so it costs a refusal rather than what you typed; `doctor` asks it of every managed file under `rule coverage`. Reachable only where the rule was narrowed, or the managed store names something the shipped `*.sops.yml` rule does not match.

## Backing up and restoring

The unit is the config directory. `/etc/faramir` holds the age key, the creation rule and the ciphertext, and none of the three is worth restoring without the others.

```bash
sudo tar czf faramir-backup.tgz -C / etc/faramir
```

Restoring a host that no longer exists is that archive, the binary, and `init`:

```bash
sudo tar xzf faramir-backup.tgz -C /
sudo faramir init --agent-user <account>
```

`init` adopts what it finds rather than replacing it. An `age.key` already in place is reported `ok` rather than `changed` and is never overwritten, and an existing `.sops.yaml` is kept and read back, so the accounts, units, modes and group are rebuilt around the key and the ciphertext and nothing is re-encrypted. The same run imports a store from elsewhere: put the files where they belong first.

- **The archive is the secret.** Everything under `secrets/` opens with the key beside it, so the two travel together and the archive is worth exactly what the store is.
- **Nothing exports the identity**, because `tar` and `cp` already do. A command for it would be a second name for the same act and a second thing an agent could be talked into running.
- **No command decrypts with a key other than the install's own.** The check that keeps this host a reader reads the key it is handed, so a run pointed at a second identity could take the host's own key out of the rule and reseal the store without it.
