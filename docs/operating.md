# Operating an install

Check it, run it, and change who can decrypt.

## Checking an install

```bash
sudo faramir doctor
```

A broker serving zero refs and a client group with members nobody recognises both look healthy otherwise. `doctor` asks what only a real host can answer. The checks, by the name each reports under:

Group | Checks | What they answer
--- | --- | ---
Install identity | `config`, `identities`, `group`, `secrets group` | Is there an install, do the accounts and groups exist, is the secrets group the keeper's alone. The first two are hard failures that stop the run
Daemons | `sockets`, `broker`, `version`, `protectproc` | Are the units listening, does `--check` pass, do the CLI and the running broker report the same build, is the broker's environment hidden
Key material | `age key`, `agent keys`, `audit log`, `ssh key` | The age key readable only by the keeper; the agent account's `~/.ssh`, `~/.config/sops` and `~/.gnupg` unreadable and unlistable by the executor; the log and SSH keys likewise, the executor still able to authenticate
Files | `config ownership`, `installed files`, `deny patterns` | The config, `.sops.yaml`, the binary, `wrap.sh` and the PAM helper not writable by the operator, and the deny list rendered for *this* config directory
Sockets | `keeper socket`, `executor socket`, `broker socket`, and a `policy` check for each of the first two | The internal sockets closed to the accounts that must not open them, the broker's open to the operator, and each `allowed_user` naming the broker
Behaviour | `brokered command`, `ssh agent`, `redaction`, `known hosts` | A managed value injected into a real command comes back as its token, the relay answers, and how many host keys a brokered `ssh` can verify against
sops | `sops config` | `.sops.yaml` lists the keeper's own recipient rather than one it used to have
Agents | `agent rules`, `agent rule drift`, `tree config`, `agent file ownership` | Each agent's deny rules present, absent, or carried in an extension; rules an earlier version wrote that this one does not; enrolled trees whose agent files no longer carry what the enrolment wrote; and files an install would now refuse to write
Sudo and kernel | `sudo credential`, `sudo grant`, `cgroup delegation`, `ptrace scope`, `user namespaces` | [Below](#what-approval-costs-beyond-the-grant)
Rotation | `log rotation` | logrotate installed, naming the log the broker writes, and having applied the rule

Four statuses: `ok`, `warn`, `failed`, and `n/a` for a check whose subject this install does not have, a separate total because a pass would claim a stack that is not there.

- **Version skew fails.** A new binary installed and the daemons never restarted onto it makes every other finding a report on the build that is not running. Re-run `init`. A broker that does not answer at all is a warning instead, `doctor` being for a stopped install as much as a running one.
- **`agent rules` reads `<config-dir>/enrolled.json`**, because a tree relies on rules kept elsewhere and the agent it was enrolled for may leave no trace in that home. An entry keeps every agent the tree still carries, so enrolling one by name does not drop the others; one naming a tree that is no longer there is warned about rather than forgotten, an unmounted tree not being a deleted one.
- **`agent rule drift` names rather than deletes.** An entry in those files is a bare string or a key, so one of ours left behind and one of yours refusing the same path look identical. Extra refusals, so untidy rather than unguarded.
- **Two checks run a brokered command** rather than reading a mode: `ssh agent` and `brokered command`. Both skip against a broker known to hold no values. `brokered command` needs root; the `ssh agent` probe runs as the caller. A refusal from a broker whose `--check` read every managed file fails rather than skips: a daemon refusing what those files cover came up before they were written.

**Without sudo**, checks needing another uid report as unchecked rather than passing, grouped at the end, with a line under the totals counting them: the totals alone would read the same on a host examined in full and on one where most questions were never put.

**Without the agent's account**, most boundary checks cannot be put at all: `access(2)` answers "no" for an account that cannot be named, which is the same answer a boundary that holds gives. Run from a root shell or cron, `doctor` takes that account from `SUDO_USER`, finds none, and reports those as unasked. Pass `--agent-user` for the whole thing.

**Finding the install.** `doctor`, `init-project`, `uninstall`, `edit`, `rekey` and `logs` all act on an install they did not perform:

Order | Source
--- | ---
1 | `--config-dir`, or `--config` on `edit`, `rekey` and `logs`
2 | `$FARAMIR_CONFIG`, on `edit`, `rekey` and `logs` only, short-circuiting the rest
3 | the running broker's own answer
4 | the `FARAMIR_CONFIG=` its unit names, which covers a host whose config moved and whose broker is down
5 | the compiled-in default

`init` follows the same chain and prints what it settled on before writing; naming `--config-dir` is still what puts an install somewhere new. The daemons skip step 3: each may be about to bind that socket, and connecting would socket-activate the installed daemon and leave the two contending for the path. Under systemd none of this is reached, the units setting `FARAMIR_CONFIG` themselves; it is what makes `faramir broker --check` work from a shell on an install that is not at the default path.

## The files an install writes into your agent's config

Two kinds, and which one a file is decides what a run may do to it.

**Faramir's own** are replaced whole and owned outright: the plugins, and Pi's extension. Nothing else is, the MCP registrations included: those are yours, and a re-enrolment merges into them.

**Yours** are edited and left yours. Each agent's settings get only faramir's keys merged in; your agent instructions file gets only the block between `<!-- BEGIN faramir: credentials -->` and `<!-- END faramir: credentials -->`. A file already there keeps its owner and its mode, and its group except in a tree, where the client group has to read what the hook is written into. Only a file a run creates takes an owner from it, and only one it creates in a rules directory is given the frontmatter that agent needs to load it.

A run stops rather than write one it should not, leaving it exactly as it is:

- **Not yours.** These commands run as root on paths in directories the account your agent runs as can write. Editing somebody else's file would be root writing what it was never asked to, and chowning it to make that true would take it from them.
- **A link this will not follow.** A link is followed and what it points at written, so a dotfiles-managed `CLAUDE.md` or `settings.json` is updated in place rather than replaced by a regular file. Only to a regular file you own, and in a tree only inside the tree: otherwise the tree's group and mode would land on a dotfiles copy outside it.
- **Markers it cannot delimit.** One marker without the other, or a credentials section that is not between markers and is not what is written now, which would leave two sets of instructions contradicting each other. Restore the markers or delete the section, then run again.
- **One file twice.** Two paths in the same run that a link makes one file, such as `~/.gemini/GEMINI.md` pointing at `~/.claude/CLAUDE.md`. Each of these files is written for the agent that reads it, so one file standing in for two would hold what was written for the other and keep only the last write, and the run would report success. Point one at a file of its own. Two agents that read the same file *by name* are not this: that is one file written once, and the section it gets claims only what holds for both.

Each is asked before anything is written, so a refusal costs nothing: `init` stops before it has handed a file to any account, `init-project` before it has shared the tree. `init` names every file it refused rather than the first. `doctor` asks the same questions under `agent file ownership`.

The section tells an agent to wait for an approval only where one can be raised, `init-project` reading `[sudo] exec_user` from the config.

A brokered command cannot delete these files: each agent's own directory in a tree is sticky, so unlink and rename there belong to the file's owner, which the settings' own `0640` would not have decided. The tree root is deliberately not sticky, which keeps a tool rewriting a lock file by rename working and leaves a brokered command able to move an agent's directory aside from above. `doctor` reports a tree whose agent files stopped carrying what the enrolment wrote.

## Rules a command does not state

- **Adding or editing a managed sops file needs no config change**, but both daemons must be running for the new values to be picked up.
- **Changing `config.toml` needs both daemons restarted, keeper first.** Neither re-reads it while running.
- **The keeper must be up before the broker is.** On a cold start there is no previous value set, so a keeper it cannot reach means nothing to redact with, and the broker refuses `exec` and `redact`. Its unit `Requires=` the keeper socket. A keeper lost *later* does not stop a running broker: it keeps the set it has and retries.
- **Run `init` before enrolling a project with opencode or Kilo Code.** Their plugins fail closed, so a binary too old to know the agent refuses every command in that project rather than running it unredacted.
- **Children do not inherit the broker's environment.** They get `[exec.base_env]` plus injected secrets. Add what a tool needs there.
- **Interactive prompts fail rather than hang.** Stdin is `/dev/null` and the child gets no controlling terminal, so `/dev/tty` will not open either: that is the one every credential prompt reads so a pipe cannot answer it. A program that prompts falls back to stderr, which is on the PTY and is redacted and recorded; one that writes only to `/dev/tty` loses that text. Pass non-interactive flags.
- **Output is truncated** at `[exec] max_output_bytes`. The audit record keeps the head and the tail and says how many bytes it dropped.
- **The audit log rotates weekly**, 8 kept, compressed, early at 16MB. `[audit] max_record_bytes` bounds one record, not the file. `doctor` fails when logrotate is not installed, when `/etc/logrotate.d/faramir` is absent or unreadable, and when the rule names a log the broker does not write; it warns when logrotate's state shows the rule has never been applied. Rotating some other way means `doctor` failing on that host.
- **A command that cannot be recorded does not run.** Before anything starts the broker checks the log can be opened and its filesystem has room for one record; a host failing either refuses every brokered command with `no_audit`. Reachable without anyone being at fault: a brokered command's output is what a record carries, so an agent that prints enough fills that filesystem itself.
- **The audit log holds no value.** Output is recorded after redaction and `argv` is redacted on the way in.
- **There is one SSH key and `init` owns it.** It mints both halves into `<config-dir>`, so the key follows the config into an encrypted home the way the age key does. A drop-in setting `[ssh] key` is refused; `--ssh-key` moves or adopts one.
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

## Adding a recipient

`--age-recipient` is read once, at the install that creates `.sops.yaml`. `init` keeps that file afterwards, so passing the flag to an installed host adds nothing: applying a changed rule means re-encrypting every managed value, which a re-run of the installer should not do unasked. A run that keeps the file reads it back, reports the recipients it lists as `age_recipients`, and warns naming any key you asked for that is not there. `faramir edit` does not apply a changed rule either, re-encrypting to the recipients a file already carries, so an edit cannot drop a reader mid-edit.

Applying one is two steps, both as root:

```bash
sudoedit /etc/faramir/.sops.yaml   # add the key under `- age:`
sudo faramir rekey                 # re-encrypt the secrets to what it now says
```

The first decides who can read files sops creates from then on. The second brings existing files into line. Name files to do only some; `--dry-run` writes nothing.

- **Ownership and mode are preserved.** This is why `rekey` exists rather than a loop over `sops updatekeys`, which rewrites in place with no regard for either: a managed file that stops being readable by the secrets group is one the keeper cannot open.
- **A rule that drops the keeper's own key is refused**, before anything is decrypted, that leaving secrets nothing on the host can open.
- **Files already sealed to the rule are skipped.** Re-encrypting rewrites the data key even when the recipients are identical, so a rekey that did not compare first would make every file look changed.
- **Dropping a recipient is the same two steps**, and reaches no copy of the ciphertext somebody already holds. Treat what that key could read as read.
- **A `.sops.yaml` with more than one creation rule is refused**, the recipients then depending on which `path_regex` a file matches. Use `sops updatekeys` per file, or `--sops-config` to name a single-rule file.
- **The keeper's key as the only recipient means losing it loses every managed value**, retroactively. A second recipient is the backup that avoids it.

## Allowing sudo on the controller

A brokered command runs as `faramir-exec`, which has no sudo, so a playbook that also configures the controller has to leave it out with `--limit '!controller'`. `faramir init --allow-sudo` closes that split without moving the boundary. Why it is shaped this way is in [design.md](design.md#allowing-sudo-on-the-controller); this is how you run it.

### The decision is made at `init`, per host

Not a runtime toggle and not a config key, because saying yes writes files only root may place and changes how the executor is sandboxed:

- a **password-required sudoers entry** for `faramir-exec` in `/etc/sudoers.d/faramir`
- a **PAM service of faramir's own**, `/etc/pam.d/faramir-sudo`, that the entry points sudo at
- the executor account **locked** (`usermod -L`), so a password is never a second way in
- `faramir-exec.service` **rendered without the sandbox that bounds root** ([what that costs](#what-approval-costs-beyond-the-grant))

Off by default, an install grants nothing. **Re-running without `--allow-sudo` takes it back.** `faramir doctor` reports which arrangement a host is in.

### What happens when a command runs `sudo`

Leave a watcher running, as root, somewhere the coding agent cannot type:

```bash
sudo faramir approvals --watch
```

1. `sudo` reaches the `auth` step of `faramir-sudo` and `pam_exec` runs the helper as **root**. The helper walks up its own process ancestry to the brokered command whose environment carries `FARAMIR_APPROVAL_TOKEN` and sends that to the broker. A token naming no running command is refused without asking anybody.
2. The broker files the question and holds the helper's connection open, which is the wait an authentication step is from `sudo`'s point of view.
3. Your watcher prints it and reads your answer from **its** terminal:

   ```text
   faramir: Approve this command to run as root? `ansible-playbook msmtp.yml`
     id       9f2a1c
     cmd      ansible-playbook msmtp.yml
     host     controller
     cwd      /srv/ansible-ctrl
     log_id   2026-08-10T12:04:11Z-3b7e000119
     expires  118s, after which it is refused
     waiting  2s
     approve? [yes/no]
   ```

   The command is the caller's, so it is rendered rather than printed: an argument holding a control character, a quote or a space is shown quoted. A `program` line appears when what argv[0] resolved to is not what argv[0] says, a relative program resolving against a tree the agent writes. The question is per run rather than per `sudo`: a yes is spent on every `sudo` that command makes until it exits.

4. Anything but `yes` is a refusal (the whole word, not `y`), and so is silence: the question expires after `[sudo] timeout_sec`, 120s by default and at most 600. The clock starts when the question is raised, which is what `waiting` counts.
5. On approval the helper exits `0` and PAM's `auth` stack falls through to `pam_permit`; on anything else `requisite` makes the non-zero exit fatal at once, and `sudo` reports its own authentication failure.
6. Approved or refused, every request is a record in the audit log naming the command, who answered, and the `exec` record it belongs to.

There is no password anywhere: what satisfies `sudo` is a decision, so nothing is minted, stored, injected or typed, and nothing a command approved once can keep and pass to a later one. The answer must come from root, checked with `SO_PEERCRED`.

**Where you watch from is part of it.** The socket check makes the answer come from root; it cannot make root the one typing. The agent runs as *your* account, and a terminal your account owns is one it can reach: `tmux send-keys` and screen's `stuff` take input from any process running as the user who started the session. `--watch` warns when it detects a multiplexer or a terminal not owned by root, but detection is not prevention, so watch from a console, an ssh session on another machine, or a login as another account. The deny rules refuse `sudo faramir approvals`, `approve` and `deny` from the agent's own shell, which raises the cost rather than removing it.

**Without `--watch`.** `sudo faramir approvals` lists what is waiting and exits. Answering is a second command: `sudo faramir approve 9f2a1c`, or `sudo faramir deny 9f2a1c`. Exit status is `0` when something was waiting, `1` when nothing was, `69` when the broker could not be reached. `--json` prints the questions as an array and carries the same status, an empty array being nothing waiting; a broker it could not reach prints nothing, an empty array there reporting a host as quiet when nothing was asked. Read `expires` and mean it: you are typing against what is left of it. If it expires, the `sudo` fails and a re-run asks afresh.

`deny` needs no id, only one question ever being outstanding, so a bare `sudo faramir deny` refuses the one waiting and prints what it refused. `approve` requires one: an approval that names no command is one nobody judged.

Approving from your own shell is the last resort rather than the first: reaching root that way leaves a warm sudo timestamp in a shell the agent can use. Consider `Defaults:<you> timestamp_timeout=0`.

`[sudo] notify_command` optionally announces a pending question. It carries no answer and nothing waits on it. Set it at install time, one argument per flag:

```sh
faramir init --allow-sudo \
    --notify-command /usr/bin/wall \
    --notify-command '{prompt}'
```

**Keep `{id}` off a broadcast channel.** `wall` writes to every terminal on the host including the agent's: the id is not a credential, but publishing it is the difference between an agent that would have to guess what to type into your watcher and one that knows. `{prompt}` says what is waiting without saying what to type.

**It runs as the broker, which reaches less than you do.** The environment is a fixed `PATH` and nothing else, and the uid is the broker's own, so anything needing your session is out: a desktop notifier wants `DBUS_SESSION_BUS_ADDRESS` and a path through `/run/user/<uid>`, which is `0700` and yours. What works from there is what needs neither, `wall` (setgid `tty`) or a request to something on the network. For a notification on your desktop, run a watcher on your own side instead: `sudo faramir approvals --watch` reads the same questions and is already in your session.

### One question per run, and what to expect

`ansible-playbook` calls `sudo` once per become'd task, and a question asked twenty times is one nobody reads by the tenth, so a yes covers every `sudo` that *one* run makes and is gone when the run exits. A second `faramir run` gets its own question.

What that looks like while a question is open, and why, is [design.md](design.md#what-the-approval-does-not-reach):

- **Other brokered commands fail** with `approval_in_progress` from the moment a question is put until the approved run ends. That pause is the protection. The refusal is terminal, the command having been neither run nor queued, so run it again afterwards.
- **A yes can still come back refused** (`not_quiescent`) when the broker finds a process of the executor's uid alive outside the run being approved. The `sudo` fails and the command is run again once the host is quiet. If it keeps happening, the executor's journal names the processes.
- **The approved command is trusted with permanent root.** Keep the code an approved run executes operator-owned and read-only to brokered commands, or the agent can author what root runs.

### What approval costs, beyond the grant

`faramir-exec.service` is rendered differently on a host that grants an approval, because the sandbox that bounds a uid holding nothing also bounds the root a human just approved:

Dropped | Why it had to go
--- | ---
`NoNewPrivileges=` | Makes every setuid binary inert, so `sudo` fails whatever sudoers says
`CapabilityBoundingSet=` (empty) | Hands back a root that cannot chown or mount
`ProtectSystem=strict` | Turns "configure this host" into `EROFS`
`SystemCallFilter=@system-service` | Excludes `@mount`, `@swap`, `@module`, `@reboot`
the `Protect*` family | Names the things root configures

Not dropped is anything bounding the uid below the approval: `ProtectProc=invisible`, the supplementary groups, the umask, `AmbientCapabilities=`. Re-running `init` without `--allow-sudo` restores all of them.

`faramir doctor` re-checks the arrangement on a host that has it and on one that does not:

Check | Asserts | No grant
--- | --- | ---
`sudo credential` | `faramir-exec` holds no `NOPASSWD` entry and no password of its own, the two ways it could sudo with the broker out of the way | still checked
`sudo grant` | The PAM service gates rather than falls open (`requisite`, `seteuid`, faramir's own helper), the helper is unwritable by the executor and by you, and `/etc/pam.d/other` is not a free pass | `n/a`
`cgroup delegation` | The executor unit is delegated a cgroup, so a run is confined and a `setsid` child cannot outlive it | still checked, and a failure
`ptrace scope` | `/proc/sys/kernel/yama/ptrace_scope` is not `0`. A warning: `sysctl -w kernel.yama.ptrace_scope=1`, plus a line in `/etc/sysctl.d`. The daemons mark themselves undumpable, so this is about brokered commands with respect to each other | `n/a`, `@system-service` excluding `@ptrace`
`user namespaces` | Unprivileged user namespaces are restricted. A warning: the uid boundaries hold either way, the namespace mapping only the executor's own uid. The unit cannot refuse one, `RestrictNamespaces=` being a seccomp rule on `clone()`'s flags, which `clone3()` carries behind a pointer seccomp cannot read | `n/a`, `@system-service` excluding `@mount`

`init` sets neither sysctl for you: every container runtime and browser sandbox on the host depends on the same switch.
