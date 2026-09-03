# Allowing sudo on the controller

A brokered command runs as `faramir-exec`, which has no sudo. A playbook that also configures the controller has to skip it with `--limit '!controller'`. `sudo faramir init --allow-sudo` removes that limitation without moving the uid boundary. The reasoning is in [design.md](design.md#allowing-sudo-on-the-controller). This page is about running it. The commands that answer a question are in [operating.md](operating.md#operator-commands).

## The decision is made at `init`, per host

The grant is not a runtime toggle or a config key. Granting it writes files only root may place and changes how the executor is sandboxed:

- a **password-required sudoers entry** for `faramir-exec` in `/etc/sudoers.d/faramir`
- a **PAM stack of faramir's own**, whose auth step asks the broker. Its location depends on the host's sudo ([why](#the-two-sudos)): `/etc/pam.d/faramir-sudo` on the original sudo, and a delimited block in `/etc/pam.d/sudo` and `/etc/pam.d/sudo-i` on sudo-rs, which has no service file
- an **environment file**, `/usr/local/libexec/faramir/sudo-env`, holding what a command keeps across its sudo
- the executor account **locked** (`usermod -L`), so no password can authenticate it
- `faramir-exec.service` **rendered without the sandbox that would also bound root** ([what that costs](#what-escalation-costs-beyond-the-grant))

The grant is off by default. **Re-running `init` without `--allow-sudo` removes it.** `faramir doctor` reports which arrangement a host has.

### The two sudos

Ubuntu ships two sudo implementations from 25.10 on. Both read `/etc/sudoers.d`. The `sudo` alternatives group decides which one is `/usr/bin/sudo`: sudo-rs at priority 50, the original at 40 as `sudo.ws`. `init` reads the version banner of the binary `sudo` resolves to, not the packaging, and writes the arrangement that sudo can read. The flag works on either.

They differ in one thing: where the PAM stack that decides an escalation is, and so how a brokered command's sudo reaches it.

| | The original sudo | sudo-rs |
| --- | --- | --- |
| Where the stack is | `/etc/pam.d/faramir-sudo`, selected by `pam_service` and `pam_login_service` in the grant | a `# BEGIN faramir` block in `/etc/pam.d/sudo` and `/etc/pam.d/sudo-i` |
| Files every account's sudo reads | none touched | two, each gaining four auth lines: a branch on the account, and the three lines it skips |

On both, the environment a brokered command keeps across `sudo` is read by a `pam_env` line in the file that carries the stack. sudoers has an `env_file` setting that would do the same, but sudo-rs has none, so faramir uses the one mechanism that works on both.

sudo-rs has neither `pam_service` nor `env_file`, and its service names `sudo` and `sudo-i` are compiled in. There is no separate stack to point it at, so no service file is written. The block is faramir's stack on such a host: a branch on the account, then the three modules that decide, load the environment and end the stack. Every other account skips all three and continues with the rest of the file. A missing module or an unparseable line sends `faramir-exec` to the stock stack, where its locked password fails it.

**The branch's jump count must be exact.** `default=3` skips the three modules after the branch. The branch and the modules come from one template, so the count cannot drift from the lines it counts. If the jump were one short, an account that is *not* the executor would enter the block at faramir's own `sufficient pam_permit` and be authenticated with no password. This is why the block carries the whole stack instead of an `auth include` of a separate file: a jump is only reliable over lines in its own file. `faramir doctor` re-counts it on the host, and `init` refuses to leave a block it did not render.

**On a sudo-rs host, run `faramir doctor` after a package upgrade.** `/etc/pam.d/sudo` is a dpkg conffile. An upgrade that installs the maintainer's version drops the block, and every escalation fails after it. The `sudo grant` check reports this, and re-running `init --allow-sudo` restores the block. The check also reports a host whose alternatives group was switched after the install, because the written arrangement then no longer matches the sudo in use.

**Version floor.** The grant sets `noninteractive_auth`, which needs sudo 1.9.11 or sudo-rs 0.2.9. `init` validates with `visudo` before writing anything and names the floor if the host is older.

**No mail on a refusal.** Every answer but `y` fails the auth step, and so does a question that expires. The stock `mail_badpass` in `/etc/sudoers` would mail the `mailto` address on each one. The grant sets `!mail_badpass` for the executor, so a refusal is silent. Failed authentications by every other account still mail.

## What happens when a command runs `sudo`

Leave a watcher running as root, in a terminal the coding agent cannot type into:

```bash
sudo faramir sudo watch
```

1. `sudo` reaches the `auth` step of faramir's stack (`/etc/pam.d/faramir-sudo` or the block in `/etc/pam.d/sudo`, depending on [which sudo the host has](#the-two-sudos)), and `pam_exec` runs the helper as **root**. The helper collects its own process ancestry and sends those pids to the broker. The broker asks the executor which of its runs forked one of them. The executor is the only party that can answer: it did the fork and holds a pidfd from that moment, so a pid the kernel has since reused does not match. An ancestry no live run owns is refused without asking anyone. Nothing in the command's environment identifies the run, so there is nothing for a caller to copy or pass on.
2. The broker records the question and holds the helper's connection open. To `sudo`, this is an authentication step that is still waiting.
3. Your watcher prints the question and reads your answer from **its** terminal:

   ```text
   faramir: Approve this command to run as root?
     id       9f2a1c
     log_id   w5vq7dbf000119
     cmd      ansible-playbook msmtp.yml
     cwd      /srv/ansible
     caller   you (uid 1000)
     host     controller
     received 2026-08-20 20:21:44 EDT (expires 120s, waited 23s)
     Approve? [y/n]
   ```

   Field | Meaning
   --- | ---
   `id` | What an answer is typed against. It means nothing once the question is answered
   `log_id` | What the audit log and the `run` record keep. Use it to look the run up afterwards
   `cmd` | The command, on its own line so a long one does not push the other fields off the screen. It comes from the caller, so it is rendered rather than printed as is: an argument holding a control character, a quote or a space is shown quoted
   `program` | Present only when the program argv[0] resolved to is not what argv[0] says, for example a relative program resolved against a tree the agent writes
   `caller` | The account that asked, never the account the command would run as. The command always runs as the executor, so this is the uid to judge. More than one account can be in the client group
   `received` | The wall clock time `sudo` asked at, so the question can be compared with other timestamps in this terminal. It carries the day and zone of the day heading in `faramir logs` with the time of its rows between them
   `expires` | Time left before the question is refused. This is the clock an answer is typed against
   `waited` | How long the command has been blocked, counted from the moment `sudo` asked. Shown only when it rounds to a second or more. The line is printed once and never updated, so this is the wait at the moment of printing. It measures the command's wait, not the watcher's, so a watcher that was running the whole time still shows a second or two of startup, password entry or poll round trip

   **Colour**, when stdout is a terminal. The first sentence is bold, the labels are coloured, and the two ids are dimmed. The values are never coloured: everything right of a label came from the account that asked, and colour stops where faramir's own words stop, so a value cannot look like part of the prompt. The endings the watcher prints use the green and red of the `faramir logs` outcome column. `--color=never` or [`NO_COLOR`](https://no-color.org) turns colour off; `--color=always` keeps it through a pipe.

   The question is per run, not per `sudo`: a yes covers every `sudo` that command makes until it exits. `[sudo] notify_command` gets the sentence with the command after it in backquotes, because it has no second line for the command.

4. Anything but `y` is a refusal, `yes` included. So is silence: the question expires after `[sudo] timeout_sec`, counted from when it was raised. The default is 120s and the maximum 3600, and it is never more than `[command] max_timeout_sec`: the command waits inside `sudo` for the whole question, so a longer timeout could answer a run the broker had already killed. A blank line repeats the prompt rather than counting as a no. The prompt expires on the same clock as the broker:

   ```text
     Approve? [y/n]
     w9h4d78d000016 expired
   ```

   A watcher blocked on a read cannot poll, so it must stop waiting. Otherwise the next question would not be shown until a key was pressed.
5. On approval the helper exits `0` and PAM's `auth` stack falls through to `pam_permit`. On anything else, `requisite` makes the non-zero exit fatal at once, and `sudo` reports its own authentication failure. That report is the same for every kind of no, so `faramir run` names the reason when it exits and the `run` record keeps it:

   ```text
   faramir run: escalation rejected: rejected by root (pid 1000)
   faramir run: escalation expired: nobody answered within 120s
   ```

   The reason decides whether re-running the command is useful, so `--quiet` does not suppress it.
6. Every request, approved or refused, is a record in the audit log naming the command, who answered, and the `run` record it belongs to. `outcome_code` names the ending in one word, so a log can be filtered for `expired` apart from `rejected` without matching English; `outcome` says it in a sentence. `faramir logs` prints `approved` and `rejected` as the code itself and the rest as short labels (`expired` shows as `timed out`), so select on the record's `outcome_code` rather than the row's wording. The full set is in [protocol.md](protocol.md#escalations).
7. `sudo watch` prints how an approved run ended:

   ```text
     w5vq7dbf000119 started
     w5vq7dbf000119 exited 0 in 1.0s (40.0s waiting to be approved, 41.0s total)
   ```

   Every line names its run, because the ending arrives after other output. The line starts with the time the command ran, excluding the wait, then the wait and the wall-time total. The total is shown because `[command] max_timeout_sec` is enforced against it. A wait under a second is left off. Other endings: `exited 2 in 3.1s, timed out` when that timeout ended the run, `failed: <reason>` when the broker got no exit status, and `ended, no exit status` when it got neither. The line arrives when the run ends, not when the poll runs out.

   A refusal prints `<log_id> rejected:` with the line it read, quoted, and nothing further. Once answered, a refused run blocks nothing, so another command may start and raise the next question. Its `run` record is written when it ends, like any other command's.

There is no password anywhere. What satisfies `sudo` is a decision, so nothing is created, stored, injected or typed. The answer must come from root, checked with `SO_PEERCRED`.

**Where you watch from matters.** The socket check makes the answer come from root; it cannot make root the one typing. The agent runs as *your* account, and it can reach any terminal your account owns: `tmux send-keys` and screen's `stuff` take input from any process running as the user who started the session. `sudo watch` warns when it detects a multiplexer or a terminal not owned by root, but detection is not prevention. Watch from a console, an ssh session on another machine, or a login as another account. The deny rules refuse every faramir subcommand from the agent's own shell except the ones it needs, the whole `sudo` group included, which makes an attack harder without preventing it.

**Without a watcher.** `sudo faramir sudo ls` lists what is waiting and exits. Answering is a second command: `sudo faramir sudo approve 9f2a1c`, or `sudo faramir sudo reject`, which accepts an id but does not need one, because only one question is ever outstanding. Exit status is `0` when something was waiting, `1` when nothing was, `69` when the broker could not be reached. `--json` prints the questions as an array with the same exit status. A broker it could not reach prints nothing rather than an empty array, which would report the host as quiet when nothing was asked. `expires` is the time left on the question. If it expires, the `sudo` fails and a re-run asks again.

Approving from your own shell is the last resort: it leaves a valid sudo timestamp in a shell the agent can use. Consider `Defaults:<you> timestamp_timeout=0`.

`[sudo] notify_command` optionally announces a pending question. It carries no answer and nothing waits on it. Set it at install time, one argument per flag:

```sh
sudo faramir init --allow-sudo \
    --notify-command /usr/bin/wall \
    --notify-command '{prompt}'
```

A later `init` [reads it back](configuration.md#what-a-flag-sets), so a bare re-run keeps the notifier. Naming the flag again replaces the whole list, and re-running without `--allow-sudo` drops it with the rest of the grant.

**Keep `{id}` off a broadcast channel.** `wall` writes to every terminal on the host, the agent's included. The id is not a credential, but publishing it tells the agent what to type into your watcher instead of leaving it to guess. `{prompt}` says what is waiting without saying what to type.

**The notifier runs as the broker, which has less access than your account.** Its environment is a fixed `PATH` and nothing else, and its uid is the broker's, so anything that needs your session cannot work: a desktop notifier needs `DBUS_SESSION_BUS_ADDRESS` and a path through `/run/user/<uid>`, which is `0700` and yours. It also runs inside the broker unit's sandbox: `PrivateTmp=` gives it its own `/tmp`, so a file written there is not in the `/tmp` you see, and `ProtectSystem=strict` leaves it nowhere else to write but the broker's own directories. What works is `wall` (setgid `tty`) or a request to something on the network. For a notification on your desktop, run `sudo faramir sudo watch` in your own session instead: it reads the same questions.

## One question per run, and what to expect

`ansible-playbook` calls `sudo` once per become'd task. Nobody reads a question asked twenty times, so a yes covers every `sudo` that *one* run makes and ends when the run exits. A second `faramir run` gets its own question.

While a question is open ([why, in design.md](design.md#what-the-escalation-does-not-reach)):

- **Other brokered commands fail** with `escalation_in_progress` from the moment a question is raised until the approved run ends. That pause is the protection. The refusal is final: the command was neither run nor queued, so run it again afterwards.
- **A yes can still come back refused** (`not_quiescent`) when the broker finds a process of the executor's uid alive outside the run being approved. The `sudo` fails; run the command again once the host is quiet. If it keeps happening, the executor's journal names the processes.
- **The approved command is trusted with permanent root.** Keep the code an approved run executes owned by the operator and read-only to brokered commands. Otherwise the agent can author what root runs.

## What a brokered command keeps across `sudo`

`sudo` discards the caller's environment, and it should: the executor's uid is shared by every brokered command, so anything in that environment is a value one of them chose. What a command gets instead comes from `/usr/local/libexec/faramir/sudo-env`, which root owns and the executor cannot write. `env_keep` is not used, because it would put the caller's own value back under the same name.

A `pam_env` line in the file that carries faramir's stack reads it ([which file, and why `pam_env` rather than sudoers' `env_file`](#the-two-sudos)). What PAM puts in the environment is what the command gets.

The file holds two things:

- **`[command.env]`**, so a command keeps its `TERM`, `LANG` and the rest across `sudo`. Set with `--command-env`; see [configuration.md](configuration.md#what-a-flag-sets).
- **`FARAMIR_OPERATOR`**, the account the coding agent runs as, which is the account the host belongs to. The broker sets it on every brokered command, and `env_reset` would drop it. `SUDO_USER` cannot replace it: `sudo` sets that to the account that invoked it, which here is the executor, whose home holds none of your configuration.

Not all of `[command.env]` reaches the file. A variable is added only where `sudo` did not already set one, so `HOME`, `PATH` and `SUDO_*` stay `sudo`'s own. Three kinds of entry are left out with a warning (`PATH` and `HOME` are left out silently, since sudo sets those itself):

- **A name that is not a variable name.** `--command-env` splits on the first `=`, so any other character in the name would be read as a second variable.
- **A name [an injected value may not carry either](protocol.md#run)**, because sudoers reads this file without `env_keep` or `env_check`.
- **A value holding a newline, a carriage return or a `#`.** `sudo` treats `#` as a comment anywhere on the line, not only at the start: it keeps what precedes one and drops the rest, and quoting does not help. A value that differs between a command and its `sudo` is worse than one that is absent.

`faramir init` rewrites the file whenever it grants sudo. An install without `--allow-sudo` removes it with the rest of the grant.

## What escalation costs, beyond the grant

`faramir-exec.service` is rendered differently on a host that grants an escalation. The sandbox that bounds a uid holding nothing would also bound the root a human just approved:

Dropped | Why
--- | ---
`NoNewPrivileges=` | Makes every setuid binary inert, so `sudo` fails whatever sudoers says
`CapabilityBoundingSet=` (empty) | Leaves a root that cannot chown or mount
`ProtectSystem=strict` | Makes the filesystem read-only, so configuring the host fails with `EROFS`
`SystemCallFilter=@system-service` | Excludes `@mount`, `@swap`, `@module`, `@reboot`
the `Protect*` family | Covers the things root configures

Still kept: `ProtectProc=invisible`, the supplementary groups, the umask, `AmbientCapabilities=`. Re-running `init` without `--allow-sudo` restores everything dropped.

**The broker's own rules stay.** They are decided before the command runs rather than enforced by the unit, so a brokered command naming a declared path or one of faramir's own directories is refused whether or not the host grants an escalation. This matters because root ignores file modes and can read the age key.

`faramir doctor` checks the arrangement on a host with the grant and on one without:

Check | Asserts | Without the grant
--- | --- | ---
`sudo credential` | `faramir-exec` holds no passwordless sudoers grant, in either spelling (`NOPASSWD` or `Defaults !authenticate`), and no password of its own. These are the two ways it could sudo without the broker. A `sudo -l` that fails to answer is reported as unchecked rather than as no entry, because a sudoers file this sudo cannot parse would otherwise look the same as an empty one | still checked
`sudo grant` | The PAM stack refuses rather than permits by default: `requisite`, `seteuid` and faramir's own helper, matched as fields rather than substrings, with nothing ahead of the helper that could answer before the broker is asked (only the sudo-rs branch may). The helper and the environment file are unwritable by the executor and by you, `/etc/pam.d/other` does not grant access, and the arrangement matches the sudo this host has: on sudo-rs the branch is in both shared stacks, and on the original no branch is left over | `n/a`
`cgroup delegation` | The executor unit is delegated a cgroup, so a run is confined and a `setsid` child cannot outlive it | still checked, and a failure
`ptrace scope` | `/proc/sys/kernel/yama/ptrace_scope` is not `0`. A warning: `sysctl -w kernel.yama.ptrace_scope=1`, plus a line in `/etc/sysctl.d`. The daemons mark themselves undumpable, so this concerns brokered commands with respect to each other | `n/a`, since `@system-service` excludes `@ptrace`
`user namespaces` | Unprivileged user namespaces are restricted. A warning: the uid boundaries hold either way, because the namespace maps only the executor's own uid. The unit cannot refuse one: `RestrictNamespaces=` is a seccomp rule on `clone()`'s flags, and `clone3()` passes them behind a pointer seccomp cannot read | `n/a`, since `@system-service` excludes `@mount`

`init` sets neither sysctl: every container runtime and browser sandbox on the host depends on the same setting.
