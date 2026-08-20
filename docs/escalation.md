# Allowing sudo on the controller

A brokered command runs as `faramir-exec`, which has no sudo, so a playbook that also configures the controller has to leave it out with `--limit '!controller'`. `faramir init --allow-sudo` closes that split without moving the boundary. Why it is shaped this way is in [design.md](design.md#allowing-sudo-on-the-controller); this is how you run it, and the commands that answer a question are in [operating.md](operating.md#operator-commands).

## The decision is made at `init`, per host

Not a runtime toggle and not a config key, because saying yes writes files only root may place and changes how the executor is sandboxed:

- a **password-required sudoers entry** for `faramir-exec` in `/etc/sudoers.d/faramir`
- a **PAM service of faramir's own**, `/etc/pam.d/faramir-sudo`, that the entry points sudo at
- an **environment file**, `/usr/local/libexec/faramir/sudo-env`, that the entry names as `env_file`
- the executor account **locked** (`usermod -L`), so a password is never a second way in
- `faramir-exec.service` **rendered without the sandbox that bounds root** ([what that costs](#what-escalation-costs-beyond-the-grant))

Off by default, an install grants nothing. **Re-running without `--allow-sudo` takes it back.** `faramir doctor` reports which arrangement a host is in.

**It needs classic sudo.** Ubuntu 26.04 ships sudo-rs, which has no `pam_service` setting and rejects the whole entry over it, so the grant cannot be installed there. `init` refuses before writing anything and names sudo-rs as the cause; the rest of the install is unaffected, and a host without the flag is the default arrangement.

## What happens when a command runs `sudo`

Leave a watcher running, as root, somewhere the coding agent cannot type:

```bash
sudo faramir escalations --watch
```

1. `sudo` reaches the `auth` step of `faramir-sudo` and `pam_exec` runs the helper as **root**. The helper walks up its own process ancestry and sends the pids it finds. The broker asks the executor which of its runs forked one of them, that being the only party that knows: it did the fork, and holds a pidfd taken at the time, so a number the kernel has since handed on answers for nothing. An ancestry no live run owns is refused without asking anybody, and nothing is carried in the command's environment for a caller to copy or hand on.
2. The broker files the question and holds the helper's connection open, which is the wait an authentication step is from `sudo`'s point of view.
3. Your watcher prints it and reads your answer from **its** terminal:

   ```text
   faramir: Approve this command to run as root?
     id       9f2a1c
     cmd      ansible-playbook msmtp.yml
     cwd      /srv/ansible-ctrl
     caller   you (uid 1000)
     host     controller
     log_id   w5vq7dbf000119
     expires  120s
     approve? [y/n]
   ```

   Field | What it says
   --- | ---
   `cmd` | The command, on its own line so a long one does not push the fields off the screen. It is the caller's, so it is rendered rather than printed: an argument holding a control character, a quote or a space is shown quoted
   `caller` | The account that asked, never the account the command would run as. That is the executor on every question, so this is the uid worth judging, and more than one account can be in the client group
   `expires` | Counts down to the refusal. It gains a `(waited 40s)` wherever the command's block, from the moment `sudo` asked, rounds to a second or more. That is the command's wait, not a report on whoever is answering: a watcher running the whole time still shows a second or two for its own start, the password it was run under, or the poll round trip. Read it at the sizes that mean something
   `program` | Present only where what argv[0] resolved to is not what argv[0] says, a relative program resolving against a tree the agent writes

   The question is per run rather than per `sudo`: a yes is spent on every `sudo` that command makes until it exits. `[escalation] notify_command` gets the whole sentence, having no second line to put the command on.

4. Anything but `y` is a refusal, `yes` included, and so is silence: the question expires after `[escalation] timeout_sec`, 120s by default and at most 600, counted from when it was raised. A blank line is asked again rather than counted as a no, and the prompt gives up on the same clock the broker does:

   ```text
     approve? [y/n]
     w9h4d78d000016 expired
   ```

   A watcher blocked on a read is not polling, so it has to give up, or the next question would wait for a keystroke before it was shown.
5. On approval the helper exits `0` and PAM's `auth` stack falls through to `pam_permit`; on anything else `requisite` makes the non-zero exit fatal at once, and `sudo` reports its own authentication failure. That report is the same whichever no it was, so `faramir run` names it on the way out and the `run` record keeps it:

   ```text
   faramir run: escalation denied: refused by root (pid 1000); log_id=w9yj6dda000005
   faramir run: escalation expired: nobody answered within 120s; log_id=w9z1ec21000003
   ```

   Which one it was decides whether running the command again is worth anything, so `--quiet` does not suppress it.
6. Approved or refused, every request is a record in the audit log naming the command, who answered, and the `run` record it belongs to. `outcome_code` says which ending it was in one word so a log can be read for `expired` apart from `denied` without matching English; `outcome` says it in a sentence. `faramir logs` renders the two as `timed out` and `refused`. The full set is in [protocol.md](protocol.md#escalations).
7. `--watch` prints how an approved run ended, when it does:

   ```text
     w5vq7dbf000119 started
     w5vq7dbf000119 exited 0 after 41.0s, waited 40s of it
   ```

   Every line names its run, the ending arriving after the terminal has moved on. The duration is wall time and the command sits inside `sudo` for the whole question, so the part spent waiting is named rather than subtracted; under a second it is left off, every approved run waiting a little. `exited 2 after 3.1s, timed out` when `[command] max_timeout_sec` ended it, `failed: <reason>` where the broker got no exit status, `ended, no exit status` where it got neither. The line arrives when the run ends, not when the poll runs out.

   A refusal prints `<log_id> refused` with the line it read, quoted, and nothing further: a refused run holds nothing once answered, so another command may start and raise the next question. Its `run` record lands when it ends like any other command's.

There is no password anywhere: what satisfies `sudo` is a decision, so nothing is minted, stored, injected or typed. The answer must come from root, checked with `SO_PEERCRED`.

**Where you watch from is part of it.** The socket check makes the answer come from root; it cannot make root the one typing. The agent runs as *your* account, and a terminal your account owns is one it can reach: `tmux send-keys` and screen's `stuff` take input from any process running as the user who started the session. `--watch` warns when it detects a multiplexer or a terminal not owned by root, but detection is not prevention, so watch from a console, an ssh session on another machine, or a login as another account. The deny rules refuse every faramir subcommand from the agent's own shell except the ones it needs, `escalations`, `approve` and `deny` among them, which raises the cost rather than removing it.

**Without `--watch`.** `sudo faramir escalations` lists what is waiting and exits. Answering is a second command: `sudo faramir approve 9f2a1c`, or `sudo faramir deny`, which takes an id but does not need one, only one question ever being outstanding. Exit status is `0` when something was waiting, `1` when nothing was, `69` when the broker could not be reached. `--json` prints the questions as an array and carries the same status; a broker it could not reach prints nothing rather than an empty array, which would report a host as quiet when nothing was asked. `expires` is what is left of the question, and you are typing against it. If it expires, the `sudo` fails and a re-run asks afresh.

Approving from your own shell is the last resort: reaching root that way leaves a warm sudo timestamp in a shell the agent can use. Consider `Defaults:<you> timestamp_timeout=0`.

`[escalation] notify_command` optionally announces a pending question. It carries no answer and nothing waits on it. Set it at install time, one argument per flag:

```sh
faramir init --allow-sudo \
    --notify-command /usr/bin/wall \
    --notify-command '{prompt}'
```

**Keep `{id}` off a broadcast channel.** `wall` writes to every terminal on the host including the agent's: the id is not a credential, but publishing it is the difference between an agent that would have to guess what to type into your watcher and one that knows. `{prompt}` says what is waiting without saying what to type.

**It runs as the broker, which reaches less than you do.** The environment is a fixed `PATH` and nothing else, and the uid is the broker's own, so anything needing your session is out: a desktop notifier wants `DBUS_SESSION_BUS_ADDRESS` and a path through `/run/user/<uid>`, which is `0700` and yours. What works is what needs neither, `wall` (setgid `tty`) or a request to something on the network. For a notification on your desktop, run `sudo faramir escalations --watch` on your own side instead: it reads the same questions and is already in your session.

## One question per run, and what to expect

`ansible-playbook` calls `sudo` once per become'd task, and a question asked twenty times is one nobody reads by the tenth, so a yes covers every `sudo` that *one* run makes and is gone when the run exits. A second `faramir run` gets its own question.

What that looks like while a question is open, and why, is [design.md](design.md#what-the-escalation-does-not-reach):

- **Other brokered commands fail** with `escalation_in_progress` from the moment a question is put until the approved run ends. That pause is the protection. The refusal is terminal, the command having been neither run nor queued, so run it again afterwards.
- **A yes can still come back refused** (`not_quiescent`) when the broker finds a process of the executor's uid alive outside the run being approved. The `sudo` fails and the command is run again once the host is quiet. If it keeps happening, the executor's journal names the processes.
- **The approved command is trusted with permanent root.** Keep the code an approved run executes operator-owned and read-only to brokered commands, or the agent can author what root runs.

## What a brokered command keeps across `sudo`

`sudo` discards the caller's environment, and should: the executor's uid is shared by every brokered command, so anything it was holding is a value one of them chose. What a command gets instead is named by the grant, `env_file=/usr/local/libexec/faramir/sudo-env`, which is root's and which the executor cannot write. Not `env_keep`, which would put the caller's own value back under the same name.

The file holds two things:

- **`[command.env]`**, so a command keeps its `TERM`, `LANG` and the rest across `sudo` rather than losing them at it. Set with `--command-env`; see [configuration.md](configuration.md#what-a-flag-sets).
- **`FARAMIR_OPERATOR`**, the account the coding agent runs as, which is whose host it is. The run already has it, the broker setting it on every brokered command, and `env_reset` is what drops it. `SUDO_USER` cannot stand in: `sudo` sets that from the account that invoked it, which here is the executor, whose home holds none of your configuration.

Not all of `[command.env]` reaches it. A variable is added only where `sudo` did not already set one, so `HOME`, `PATH` and `SUDO_*` stay `sudo`'s own. Three more are left out with a warning: a name that is not a variable name, a name [an injected value may not carry either](protocol.md#run), sudoers reading this file without `env_keep` or `env_check`, and a value holding a newline or a `#`. `sudo` treats a `#` as a comment anywhere on the line, not only at the start, so it keeps what precedes one and drops the rest; quoting does not rescue it. A value that differs between a command and its `sudo` is worse than one that is absent.

`faramir init` rewrites the file whenever it grants sudo, and an install without `--allow-sudo` removes it with the rest of the grant.

## What escalation costs, beyond the grant

`faramir-exec.service` is rendered differently on a host that grants an escalation, because the sandbox that bounds a uid holding nothing also bounds the root a human just approved:

Dropped | Why it had to go
--- | ---
`NoNewPrivileges=` | Makes every setuid binary inert, so `sudo` fails whatever sudoers says
`CapabilityBoundingSet=` (empty) | Hands back a root that cannot chown or mount
`ProtectSystem=strict` | Turns "configure this host" into `EROFS`
`SystemCallFilter=@system-service` | Excludes `@mount`, `@swap`, `@module`, `@reboot`
the `Protect*` family | Names the things root configures

Not dropped is anything bounding the uid below the escalation: `ProtectProc=invisible`, the supplementary groups, the umask, `AmbientCapabilities=`. Re-running `init` without `--allow-sudo` restores all of them.

`faramir doctor` re-checks the arrangement on a host that has it and on one that does not:

Check | Asserts | No grant
--- | --- | ---
`sudo credential` | `faramir-exec` holds no `NOPASSWD` entry and no password of its own, the two ways it could sudo with the broker out of the way | still checked
`sudo grant` | The PAM service gates rather than falls open (`requisite`, `seteuid`, faramir's own helper), the helper and the `env_file` are unwritable by the executor and by you, and `/etc/pam.d/other` is not a free pass | `n/a`
`cgroup delegation` | The executor unit is delegated a cgroup, so a run is confined and a `setsid` child cannot outlive it | still checked, and a failure
`ptrace scope` | `/proc/sys/kernel/yama/ptrace_scope` is not `0`. A warning: `sysctl -w kernel.yama.ptrace_scope=1`, plus a line in `/etc/sysctl.d`. The daemons mark themselves undumpable, so this is about brokered commands with respect to each other | `n/a`, `@system-service` excluding `@ptrace`
`user namespaces` | Unprivileged user namespaces are restricted. A warning: the uid boundaries hold either way, the namespace mapping only the executor's own uid. The unit cannot refuse one, `RestrictNamespaces=` being a seccomp rule on `clone()`'s flags, which `clone3()` carries behind a pointer seccomp cannot read | `n/a`, `@system-service` excluding `@mount`

`init` sets neither sysctl for you: every container runtime and browser sandbox on the host depends on the same switch.
