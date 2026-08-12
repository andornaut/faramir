# Operating an install

What to do with an install once it is on a host: check it, run it, and change who can decrypt.

## Checking an install

```bash
sudo faramir doctor
```

A broker serving zero refs and a client group with members nobody recognises both look healthy otherwise. `doctor` checks what exists only once the install is on a host:

- the age key unreadable by every account but the keeper
- the operator's own `~/.ssh` and `~/.config/sops` unreadable by the executor
- the secrets group the keeper's alone
- the config `[exec.base_env]` comes from, the binary and the deny list, none of them writable by the operator
- the keeper and executor sockets closed to the accounts that must not open them, the broker's open to the operator
- the audit log and the SSH keys unreadable by the executor, which can still authenticate
- how many host keys a brokered `ssh` can verify a host against
- `ProtectProc` hiding the broker's environment
- the `.sops.yaml` creation rule listing the keeper's own recipient rather than one it used to have
- a managed value injected into a real command coming back as its token
- each agent's deny rules: present, absent from a home that runs that agent or that a tree was enrolled for, or carried in the extension an enrolment installs. `init-project` records the enrolment in `<config-dir>/enrolled.json`, because a tree relies on rules kept somewhere else and the agent it was enrolled for may leave no trace in that home at all. An entry naming a tree that is no longer there is warned about rather than forgotten, an unmounted tree not being a deleted one
- rules an earlier version wrote and this one does not, which are named rather than deleted: an entry in those files is a bare string or a key, so one of ours left behind and one of yours refusing the same path look identical. Extra refusals, so untidy rather than unguarded

It also compares the version the broker reports against its own. They differ when a new binary was installed and the daemons were never restarted onto it, which makes every other finding a report on the build that is not running, so this fails rather than warns and the fix is to re-run `init`. A broker that does not answer at all is a warning instead, `doctor` being for a stopped install as much as a running one.

Most of the examination needs another uid: the broker's own `--check`, the comparison of the `.sops.yaml` recipients against the keeper's `0400` age key, and the checks that ask what each account can reach. Each is asked as the account it is about, root bypassing file modes so the same question from root answers itself.

Without sudo those report as unchecked rather than as passing, grouped at the end, and a line under the totals counts them: the totals alone would read the same on a host examined in full and on one where most of the questions were never put. A check whose subject this install does not have, the sudo arrangement on a host with no grant, reports `n/a`, a separate total from `ok`, since a pass would claim a stack that gates where there is no stack at all.

Two checks run a brokered command rather than reading a mode: the SSH agent probe and the brokered command check. Both skip against a broker known to hold no values, and against one that answered nothing when the install was looked up. They differ on a broker that was never asked: the brokered command check needs root, while the SSH agent probe runs as the caller's own account, so it is answered without sudo and a refusal is recognised as one. A refusal from a broker whose `--check` read every managed file fails rather than skips: a daemon refusing what those files cover came up before they were written.

**Finding the install.** `doctor`, `init-project`, `uninstall`, `edit`, `rekey` and `logs` all act on an install they did not perform, and each finds it the same way: `--config-dir` (or `--config`) if you name one, then the running broker's own answer, then the `FARAMIR_CONFIG=` its unit names, then the compiled-in default. The unit is what covers a host whose config moved and whose broker is down. `init` finds it the same way and prints what it settled on before writing anything; naming `--config-dir` is still what puts an install somewhere new.

The three daemon entry points, `broker`, `keeper` and `exec`, follow the same chain without asking a running broker: each is a process that may be about to bind that socket, and connecting would socket-activate the installed daemon and leave the two contending for the path. Under systemd none of this is reached, the units setting `FARAMIR_CONFIG` themselves; it is what makes `faramir broker --check` work from a shell on an install that is not at the default path.

## Rules a command does not state

- **Adding or editing a managed sops file needs no config change**, but both daemons must be running for the new values to be picked up.
- **Changing `config.toml` needs both daemons restarted, keeper first.** Neither re-reads it while running.
- **The keeper must be up before the broker is.** On a cold start there is no previous value set, so a keeper it cannot reach means nothing to redact with, and the broker refuses `exec` and `redact` rather than serving that. Its unit `Requires=` the keeper socket, so activation normally supplies this. A keeper lost *later* does not stop a running broker: it keeps the set it already has and retries.
- **Run `init` before enrolling a project with opencode or Kilo Code.** Their plugins fail closed, so an installed binary too old to know the agent refuses every command in that project rather than running it unredacted.
- **The credentials section is written once and never edited.** `init-project` adds it to `AGENTS.md` or `CLAUDE.md` when the file shows no sign of faramir, and leaves the file alone otherwise: word for word what is written now means there is nothing to do, and anything else is named in a warning. A file that mentions faramir and does not carry the current section may hold one an earlier version wrote, the same one reworded by whatever last tidied the file, or your own notes, and none of those is this command's to rewrite. Delete the section and re-run to get the current one.
- **Children do not inherit the broker's environment.** They get `[exec.base_env]` plus injected secrets. Add what a tool needs there.
- **Interactive prompts fail rather than hang.** Stdin is `/dev/null`, and the child gets no controlling terminal, so `/dev/tty` will not open either: that is the one every credential prompt reads so a pipe cannot answer it. A program that prompts falls back to stderr, which is on the PTY and is redacted and recorded; one that writes only to `/dev/tty` loses that text. Pass non-interactive flags.
- **Output is truncated** at `[exec] max_output_bytes`. The audit record keeps the head and the tail of a run and says how many bytes it dropped between them, sized so the whole record's line fits `[audit] max_record_bytes`, counted in encoded bytes, or the command would choose what the cap means.
- **The audit log rotates weekly**, 8 kept, compressed, and early at 16MB. `[audit] max_record_bytes` bounds one record, not the file: rotation is logrotate's, so `doctor` fails when logrotate is not installed and when the rule names a log the broker does not write, and warns when logrotate's own state shows it has never applied the rule. Delete `/etc/logrotate.d/faramir` to manage it some other way.
- **A command that cannot be recorded does not run.** Before anything is started the broker checks the audit log can be opened and that its filesystem has room for one record; a host that fails either refuses every brokered command with `no_audit`. Reachable without anyone being at fault: a brokered command's output is what a record carries, so an agent that prints enough fills that filesystem itself.
- **The audit log holds no value.** Output is recorded after redaction and `argv` is redacted on the way in.
- **There is one SSH key and `init` owns it.** It mints both halves into `<config-dir>`, so the key follows the config into an encrypted home the way the age key does. A drop-in setting `[ssh] key` is refused; `--ssh-key` is what moves or adopts one.
- **A brokered `ssh` logs in as the executor.** `ssh host` naming no user asks for `faramir-exec`, which is nobody's account on a managed host. Give the login (`ssh deploy@host.example.com`), or write one `User` per host into `/var/lib/faramir-exec/.ssh/config` as root, that being the child's `HOME`. Ansible needs neither, `ansible_user` being in the inventory.
- **A brokered `ssh` verifies against `/etc/ssh/ssh_known_hosts` and the executor's own.** The executor's starts absent and nothing can prompt you to add to it, so a host trusted only in your `~/.ssh/known_hosts` is refused before the broker's key is offered. `init --known-hosts PATH` pins a file for the executor; the system-wide file is the alternative, covering every account at once. Either way an entry is filed under the name ssh dials, port-bracketed where that is not 22 (`[host.example.com]:2222`), and is never consulted under another name. Seed the system-wide file from a connection you have already verified, taking every type the host offers, the algorithm being negotiated per connection:

  ```bash
  sudo ssh-keygen -R host.example.com -f /etc/ssh/ssh_known_hosts
  ssh host.example.com 'cat /etc/ssh/ssh_host_*_key.pub' \
    | awk '{print "host.example.com", $1, $2}' \
    | sudo tee -a /etc/ssh/ssh_known_hosts
  ```

  The removal first makes it re-runnable. [ansible-ctrl's faramir role](https://github.com/andornaut/ansible-ctrl/blob/main/roles/faramir/tasks/ssh.yml) does this across a fleet.
- **The broker's home is `/var/lib/faramir-broker`**, granted by `StateDirectory=`.
- **Encrypt the disk.** LUKS on the root filesystem covers the age key, the secrets, the audit log and swap in one move.

## Adding a recipient

`--age-recipient` is read once, at the install that creates `.sops.yaml`. `init` keeps that file afterwards, so passing the flag to an installed host adds nothing: applying a changed rule means re-encrypting every managed value, which is not something a re-run of the installer should do unasked. A run that keeps the file reads it back, reports the recipients it actually lists as `age_recipients`, and warns naming any key you asked for that is not in there; `doctor` answers the same question about a host nobody is installing.

`faramir edit` does not apply a changed rule either, and for the same reason: it re-encrypts to the recipients a file already carries, so an edit cannot drop a reader mid-edit.

Applying one is two steps, both as root:

```bash
sudoedit /etc/faramir/.sops.yaml   # add the key under `- age:`
sudo faramir rekey                 # re-encrypt the secrets to what it now says
```

The first decides who can read files sops creates from then on. The second brings the files that already exist into line, decrypting each with the keeper's key and re-sealing it to the rule. Name files to do only some; `--dry-run` reports what would change and writes nothing.

- **The ownership and mode are preserved.** This is why `rekey` exists rather than a loop over `sops updatekeys`, which rewrites in place with no regard for either: a managed file that stops being readable by the secrets group is one the keeper cannot open.
- **A rule that drops the keeper's own key is refused**, before anything is decrypted. Re-encrypting to it would leave secrets nothing on the host can open. This is the same drift `init` and `doctor` warn about: replace `age.key` and the rule still names the old recipient, so every value encrypted from then on is one the keeper cannot read.
- **Files already sealed to the rule are skipped.** Re-encrypting rewrites the data key even when the recipients are identical, so a rekey that did not compare first would make every file look changed.
- **Dropping a recipient is the same two steps**, and reaches no copy of the ciphertext that somebody already holds. Treat what that key could read as read.
- **A hand-written `.sops.yaml` with more than one creation rule is refused**, the recipients then depending on which `path_regex` a file matches. Use `sops updatekeys` per file, or `--sops-config` to name a single-rule file.
- **With the keeper's key as the only recipient there is nothing to keep in step.** `edit` and `rekey` always use `<config-dir>/age.key`. The cost is that the key is the only way in: losing it loses every managed value, retroactively, and a second recipient is the backup that avoids it.

## Allowing sudo on the controller

A brokered command runs as `faramir-exec`, which has no sudo, so a playbook that also configures the machine faramir runs on has to leave it out with `--limit '!controller'` and be applied some other way, as root, splitting one secret-bearing run in two. `faramir init --allow-sudo` closes that split without moving the boundary. Why the mechanism is shaped the way it is, with no credential, a PAM callback and per-run serialisation, is in [design.md](design.md#allowing-sudo-on-the-controller); this is how you run it.

### The decision is made at `init`, per host

Whether a host's brokered commands may sudo at all is chosen when you install it, by passing `--allow-sudo` to `faramir init` or not. It is not a runtime toggle and not a config key, because saying yes writes files only root may place and changes how the executor is sandboxed:

- a **password-required sudoers entry** for `faramir-exec` in `/etc/sudoers.d/faramir`;
- a **PAM service of faramir's own**, `/etc/pam.d/faramir-sudo`, that the entry points sudo at;
- the executor account **locked** (`usermod -L`), so a password is never a second way in;
- and `faramir-exec.service` **rendered without the sandbox that bounds root** (see [what it costs](#what-approval-costs-beyond-the-grant)).

**Off** (the default), an install grants nothing: no sudoers entry, no PAM service, the full seccomp sandbox. **On**, this host's executor is sandboxed as a uid that *can* become root, once, per human-approved command. That is a larger thing to be true of a host than "holds no secret", so choose it only for the controller you meant to. The choice is re-made every `init`: **re-running without `--allow-sudo` takes it back**, removing the entry and the service and restoring the tighter sandbox. `faramir doctor` reports which arrangement a host is in.

### What happens when a command runs `sudo`

Leave a watcher running, as root, somewhere the coding agent cannot type:

```bash
sudo faramir approvals --watch
```

1. `sudo` reaches the `auth` step of `faramir-sudo` and `pam_exec` runs the helper as **root**. The helper finds the token by walking up its own process ancestry to the brokered command whose environment carries `FARAMIR_APPROVAL_TOKEN`, and sends that to the broker. A token that names no running command is refused without asking anybody.
2. The broker files the question and holds the helper's connection open, which is the wait an authentication step is from `sudo`'s point of view.
3. Your watcher prints it and reads your answer from **its** terminal:

   ```text
   faramir: run as root on controller: ansible-playbook msmtp.yml in /srv/ansible-ctrl -- approve every sudo this command makes until it ends? Type yes
     id       9f2a1c
     cmd      ansible-playbook msmtp.yml
     cwd      /srv/ansible-ctrl
     log_id   2026-08-10T12:04:11Z-3b7e000119
     waiting  2s (expires in 118s, then refused)
     approve? [yes/no]
   ```

   The command is the caller's, so it is rendered rather than printed: an argument holding a control character, a quote or a space is shown quoted, which is how you tell an argument that means to be read from one that means to redraw your terminal. A `program` line appears when what argv[0] resolved to is not what argv[0] says: a relative program resolves against the cwd, and that is a tree the agent writes.

4. Anything but `yes` is a refusal (the whole word, not `y`), and so is silence: the question expires after `[sudo] timeout_sec` (120s by default, at most 600). The clock starts when the question is raised rather than when you see it, which is what the `waiting` line is counting.
5. On approval the helper exits `0` and PAM's `auth` stack falls through to `pam_permit`; on anything else `requisite` makes the non-zero exit fatal at once, and `sudo` reports its own authentication failure.
6. Approved or refused, every request is a record in the audit log naming the command, who answered, and the `exec` record it belongs to.

There is no password anywhere: what satisfies `sudo` is a decision, not a credential, so nothing is minted, stored, injected or typed, and nothing a command approved once can keep and pass to a later one. The answer must come from root, checked with `SO_PEERCRED` on the broker's own socket, so the account the coding agent runs as cannot answer for it ([design.md](design.md#allowing-sudo-on-the-controller) has why `systemd-ask-password` was not used).

**Where you watch from is part of it.** The socket check makes the answer come from root; it cannot make root the one doing the typing. The agent runs as *your* account, and a terminal your account owns is one it can reach: `tmux send-keys` and screen's `stuff` take input from any process running as the user who started the session. `faramir approvals --watch` warns when it detects a multiplexer or a terminal not owned by root, but detection is not prevention, so watch from a console, an ssh session on another machine, or a login as another account. An operator with `NOPASSWD` sudo, or a warm sudo timestamp in a shell the agent can use, has already handed it that account; the deny rules refuse `sudo faramir approvals`, `approve` and `deny` from the agent's own shell for that reason, which raises the cost rather than removing it.

**Without `--watch`.** `sudo faramir approvals` lists what is waiting and exits, a look rather than a vigil. Answering is a second command: `sudo faramir approve 9f2a1c`, or `sudo faramir deny 9f2a1c`. Exit status is `0` when something was waiting, `1` when nothing was, `69` when the broker could not be reached; `--json` gives the same in machine form. Read the "expires in" and mean it: the clock started when the question was raised, and you are typing a second command against what is left of it. If it expires, nothing is lost but time: the `sudo` fails and a re-run asks afresh.

`deny` needs no id: only one question is ever outstanding, so a bare `sudo faramir deny` refuses the one that is waiting, printing what it refused first. `approve` requires one, so there is deliberately no form that approves whatever is there: refusing something unseen is safe, and an approval that names no command is one nobody judged.

Approving from your own shell is the last resort rather than the first: reaching root that way leaves a warm sudo timestamp in a shell the agent can use. On a host installed with `--allow-sudo`, consider `Defaults:<you> timestamp_timeout=0` for the same reason.

`[sudo] notify_command` optionally announces a pending question (`wall`, a desktop notifier, a push). It carries no answer and nothing waits on it. **Keep `{id}` off a broadcast channel.** `wall` writes to every terminal on the host including the agent's: the id is not a credential (answering still requires uid 0), but publishing it is the difference between an agent that would have to guess what to type into your watcher and one that knows. `{prompt}` says what is waiting without saying what to type.

### One question per run, and what an approval does not bound

`ansible-playbook` calls `sudo` once per become'd task, and a question asked twenty times is one nobody reads by the tenth, so a yes covers every `sudo` that *one* run makes. That is not sudo's timestamp by another name (which is why `timestamp_timeout=0` stays): a timestamp is a stretch of time that anything starting inside rides, while this is scoped to the command the human was shown, gone the moment the run exits. A second `faramir run` gets its own token and its own question.

An approval could leak past the one command it was shown for in two ways. One is closed; the other cannot be:

- *A second, unapproved command riding the approval: closed.* The broker serialises ([design.md](design.md#allowing-sudo-on-the-controller) has the mechanism): **an approval is approved only when its run is the sole brokered command in flight, and while a question is waiting or an approval is held every other brokered command is refused `approval_in_progress`.** So expect other `faramir run`s to fail from the moment a question is put until the approved playbook ends. That pause is the protection. The refusal is terminal: the command was neither run nor queued, so run it again once the approved command has finished. A `sudo` that arrives while another brokered command is registered is likewise refused without a question being put, one that could only ever be answered no, which `sudo` reports as a failed authentication; there is never a queue of questions, and the same run's later `sudo`s join its own. The whole arrangement is **checked rather than assumed**: before an approval takes, the broker asks the executor whether anything of its uid is alive outside the run being approved, and a no turns your yes into a refusal there and then: the `sudo` fails and the command has to be run again. If that keeps happening, the executor's journal names the processes.
- *The approved command itself persisting root: not closed, ever.* An approved command gets real root and can make it permanent, with a setuid-root binary, a `systemd` unit, a `cron` entry or a line in `sudoers`, none of which involves faramir again. Approving is trusting **that command** with permanent root, identical to typing `sudo ansible-playbook` yourself. So keep the code an approved run executes operator-owned and read-only to brokered commands, or the agent can author what root runs. The audit log shows the approval; it does not show the persistence a hostile command installs, unless you look.

### What approval costs, beyond the grant

`faramir-exec.service` is rendered differently on a host that grants an approval, because the sandbox that bounds a uid holding nothing also bounds the root a human just approved. `NoNewPrivileges=` makes every setuid binary inert, so with it set `sudo` fails whatever the sudoers file says; an empty `CapabilityBoundingSet=` hands back a root that cannot chown or mount; `ProtectSystem=strict` turns "configure this host" into `EROFS`; and `SystemCallFilter=@system-service` excludes `@mount`, `@swap`, `@module` and `@reboot`. All of those are dropped, along with the `Protect*` family that names things root configures. What is *not* dropped is anything that bounds the uid below the approval: `ProtectProc=invisible`, the supplementary groups, the umask, `AmbientCapabilities=`. The unit states each one and why. Re-running `init` without `--allow-sudo` restores all of them.

`faramir doctor` re-checks the arrangement, on a host that has it and on one that does not:

- `sudo credential`: `faramir-exec` must hold no `NOPASSWD` entry from any source and no password of its own, which are the two ways it could sudo with the broker out of the way. Checked on every host, a grant or not, and a warning rather than a pass where the sudoers listing or `/etc/shadow` could not be read.
- `sudo grant`: the PAM service must gate rather than fall open (`requisite`, `seteuid`, faramir's own helper), the helper must be unwritable by the executor and by you, and `/etc/pam.d/other` must not be a free pass, for the case where the service file is ever removed. All three exist only where one was granted, so a host without a grant reports `n/a`. The two names are separate because a credential and a broken gate are different faults, and a host that holds one is still examined for the other.
- the executor unit must be delegated a cgroup, so a run is confined and a `setsid` child cannot outlive it. A hard failure on any host, a sudo grant or not.
- `/proc/sys/kernel/yama/ptrace_scope` must not be `0`, which lets any process of the executor's uid attach to any other of that uid. A warning rather than a failure: `sysctl -w kernel.yama.ptrace_scope=1`, and a line in `/etc/sysctl.d` to keep it. The daemons mark themselves undumpable, so this is about brokered commands with respect to each other. `n/a` without a grant: that host's executor unit carries `SystemCallFilter=@system-service`, which excludes `@ptrace`, so the syscall is refused whatever the sysctl says.
- whether unprivileged user namespaces are open (`kernel.apparmor_restrict_unprivileged_userns`, or `kernel.unprivileged_userns_clone` where that is what the distribution has). The executor unit cannot refuse one: `RestrictNamespaces=` is a seccomp rule on `clone()`'s flags, which `clone3()` carries behind a pointer seccomp cannot read, so systemd setting it would deny `clone3()` outright, the call every brokered command is spawned into its cgroup with. A warning rather than a failure: the uid boundaries hold either way, the namespace mapping only the executor's own uid. `n/a` without a grant, `@system-service` excluding `@mount`, so the capabilities the namespace confers have nothing to act on. `init` does not set the sysctl for you: every container runtime and browser sandbox on the host depends on the same switch.

**`doctor` without an operator.** Most of these ask what a *named* account can reach, and `access(2)` answers "no" for an account that cannot be named at all, which is the same answer a boundary that holds gives. Run from a root shell, a cron entry or a configuration manager, `doctor` takes the operator from `SUDO_USER` and finds none, so it reports those checks as unasked rather than claiming them. The rest of the examination is unaffected and still fails on a real fault. Pass `--operator-user` to get the whole thing.
