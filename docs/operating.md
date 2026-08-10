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

It also compares the version the broker reports against its own. They differ when a new binary was installed and the daemons were never restarted onto it, which makes every other finding a report on the build that is not running, so this fails rather than warns and the fix is to re-run `init`. A broker that does not answer at all is a warning instead, `doctor` being for a stopped install as much as a running one.

Most of the examination needs another uid: the broker's own `--check`, the comparison of the `.sops.yaml` recipients against the keeper's `0400` age key, and the checks that ask what each account can reach. Each is asked as the account it is about, root bypassing file modes so the same question from root answers itself.

Without sudo those report as unchecked rather than as passing, grouped at the end. A skipped check is one warn line whatever it stood for, so a line under the totals counts them: the totals alone would read the same on a host examined in full and on one where most of the questions were never put.

Two checks run a brokered command rather than reading a mode: the SSH agent probe and the brokered command check.

- Both skip against a broker known to hold no values, and against one that answered nothing when the install was looked up: neither will run the command, and the refusal and the outage are reported by the secrets and socket checks instead.
- They differ on a broker that was never asked. The brokered command check needs root, so an unestablished value set there is `--check` not having reported. The SSH agent probe runs as the caller's own account, so it is answered without sudo and a refusal is recognised as one.
- A refusal from a broker whose `--check` read every managed file fails rather than skips: `--check` reads those files itself, so a daemon refusing what they cover came up before they were written.

**Finding the install.** `doctor`, `init-project`, `uninstall`, `edit`, `rekey` and `logs` all act on an install they did not perform, and each finds it the same way: `--config-dir` (or `--config`) if you name one, then the running broker's own answer, then the `FARAMIR_CONFIG=` its unit names, then the compiled-in default. The unit is what covers a host whose config moved and whose broker is down. `init` finds it the same way and prints what it settled on before writing anything. Naming `--config-dir` is still what puts an install somewhere new.

The three daemon entry points, `broker`, `keeper` and `exec`, follow the same chain without asking a running broker: each is a process that may be about to bind that socket, and connecting to it would socket-activate the installed daemon and leave the two contending for the path. The unit answers the same question, being where a running broker's config came from. Under systemd none of this is reached, the units setting `FARAMIR_CONFIG` themselves; it is what makes `faramir broker --check` work from a shell on an install that is not at the default path.

## Rules a command does not state

- **Adding or editing a managed sops file needs no config change**, but both daemons must be running for the new values to be picked up.
- **Changing `config.toml` needs both daemons restarted, keeper first.** Neither re-reads it while running.
- **The keeper must be up before the broker is.** On a cold start there is no previous value set, so a keeper it cannot reach means nothing to redact with, and the broker refuses `exec` and `redact` rather than serving that. Its unit `Requires=` the keeper socket and restarts on failure, so activation normally supplies this. A keeper lost *later* does not stop a running broker: it keeps the set it already has and retries.
- **Run `init` before enrolling a project with opencode or Kilo Code.** Their plugins fail closed, so an installed binary too old to know the agent refuses every command in that project rather than running it unredacted.
- **Children do not inherit the broker's environment.** They get `[exec.base_env]` plus injected secrets. Add what a tool needs there.
- **Interactive prompts fail rather than hang.** Stdin is `/dev/null`. Pass non-interactive flags.
- **Output is truncated** at `[exec] max_output_bytes`; the audit log keeps up to `[audit] max_record_bytes`.
- **The audit log rotates weekly**, 8 kept, compressed, and early at 16MB. `[audit] max_record_bytes` bounds one record, not the file. Delete `/etc/logrotate.d/faramir` to manage it some other way.
- **The audit log holds no value.** Output is recorded after redaction and `argv` is redacted on the way in.
- **There is one SSH key and `init` owns it.** It mints both halves into `<config-dir>`, so the key follows the config into an encrypted home the way the age key does, and `ProtectSystem=strict` leaves that directory read-only to the broker that uses it. A drop-in setting `[ssh] key` is refused; `--ssh-key` is what moves or adopts one.
- **A brokered `ssh` logs in as the executor.** `ssh host` naming no user asks for `faramir-exec`, which is nobody's account on a managed host, and the key is refused however well it is installed. Give the login (`ssh deploy@host.example.com`), or write one `User` per host into `/var/lib/faramir-exec/.ssh/config` as root, that being the child's `HOME`. Ansible needs neither, `ansible_user` being in the inventory.
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

`--age-recipient` is read once, at the install that creates `.sops.yaml`. `init` keeps that file afterwards, so passing the flag to an installed host adds nothing: applying a changed rule means re-encrypting every managed value, which is not something a re-run of the installer should do behind your back.

A run that keeps the file reads it back, reports the recipients it actually lists as `age_recipients`, and warns naming any key you asked for that is not in there. `doctor` answers the same question about a host nobody is installing.

`faramir edit` does not apply a changed rule either, and for the same reason: it re-encrypts to the recipients a file already carries, so an edit cannot drop a reader mid-edit.

Applying one is two steps, both as root:

```bash
sudoedit /etc/faramir/.sops.yaml   # add the key under `- age:`
sudo faramir rekey                 # re-encrypt the secrets to what it now says
```

The first decides who can read files sops creates from then on. The second brings the files that already exist into line, decrypting each with the keeper's key and re-sealing it to the rule. Name files to do only some; `--dry-run` reports what would change and writes nothing.

- **The ownership and mode are preserved.** This is why `rekey` exists rather than a loop over `sops updatekeys`, which rewrites in place with no regard for either: a managed file that stops being readable by the secrets group is one the keeper cannot open.
- **A rule that drops the keeper's own key is refused**, before anything is decrypted. Re-encrypting to it would leave secrets nothing on the host can open, and re-running cannot undo that. This is the same drift `init` and `doctor` warn about: replace `age.key` (restored from a backup, or re-minted after the file was unlinked) and the rule still names the old recipient, so every value encrypted from then on is one the keeper cannot read.
- **Files already sealed to the rule are skipped.** Re-encrypting rewrites the data key even when the recipients are identical, so a rekey that did not compare first would make every file look changed.
- **Dropping a recipient is the same two steps**, and reaches no copy of the ciphertext that somebody already holds. Treat what that key could read as read.
- **A hand-written `.sops.yaml` with more than one creation rule is refused**, the recipients then depending on which `path_regex` a file matches. Use `sops updatekeys` per file, or `--sops-config` to name a single-rule file.
- **With the keeper's key as the only recipient there is nothing to keep in step.** `edit` decrypts and re-encrypts with `<config-dir>/age.key` every time, and `rekey` never needs running. The cost is that the key is the only way in: losing it loses every managed value, retroactively, and a second recipient is the backup that avoids it.

## Elevating on the controller

A brokered command runs as `faramir-exec`, which has no sudo. That is the boundary, and on most hosts it is the end of it: a playbook that also configures the machine faramir runs on has to leave it out with `--limit '!controller'` and be applied some other way, as root, splitting one secret-bearing run in two. `faramir init --elevate` closes that split without moving the boundary. The full argument for why the mechanism is shaped the way it is — no credential, a PAM callback, per-run serialisation — is in [design.md](design.md#elevating-on-the-controller); this is how you run it.

### The decision is made at `init`, per host

Whether a host's brokered commands may elevate at all is chosen when you install it, by passing `--elevate` to `faramir init` or not. It is not a runtime toggle and not a config key a drop-in can set, because saying yes writes files only root may place and changes how the executor is sandboxed:

- a **password-required sudoers entry** for `faramir-exec` in `/etc/sudoers.d/faramir`;
- a **PAM service of faramir's own**, `/etc/pam.d/faramir-sudo`, that the entry points sudo at;
- the executor account **locked** (`usermod -L`), so a password is never a second way in;
- and `faramir-exec.service` **rendered without the sandbox that bounds root** (see [what it costs](#what-elevation-costs-beyond-the-grant)).

So it is a deliberate, host-level choice with two honest positions:

- **Off (the default).** An install that never passed `--elevate` grants nothing. `faramir-exec` has no sudo, the PAM service and sudoers entry do not exist, and the executor keeps the full seccomp sandbox. This is every host but the one controller you mean to configure through faramir.
- **On.** This host's executor is sandboxed as a uid that *can* become root, once, per human-approved command. That is a larger thing to be true of a host than "holds no secret", so choose it only for the controller you meant to, and nowhere else.

The choice is re-made every `init`: **re-running `init` without `--elevate` takes it back** — it removes the sudoers entry and the PAM service, and restores the tighter sandbox. Re-running *with* it keeps the grant. There is nothing to toggle between installs; the flag you pass is the state you get. `faramir doctor` reports which arrangement a host is in.

### What happens when a command runs `sudo`

Leave a watcher running, as root, somewhere the coding agent cannot type:

```bash
sudo faramir approve --watch
```

1. `sudo` reaches the `auth` step of `faramir-sudo` and `pam_exec` runs the helper as **root**. The helper finds the token by walking up its own process ancestry to the brokered command whose environment carries `FARAMIR_ELEVATE_TOKEN`, and sends that to the broker. A token that names no running command is refused without asking anybody.
2. The broker files the question and holds the helper's connection open — which is exactly the wait an authentication step is, from `sudo`'s point of view.
3. Your watcher prints it and reads your answer from **its** terminal:

   ```text
   faramir: run as root on tron: ansible-playbook msmtp.yml in /srv/ansible-ctrl -- approve every sudo this command makes until it ends? Type yes
     id       9f2a1c
     log_id   2026-08-10T12:04:11Z-3b7e
     waiting  2s
     approve? [yes/no]
   ```

4. Anything but `yes` is a refusal, and so is silence: the question expires after `[elevate] timeout_sec`.
5. On approval the helper exits `0` and PAM's `auth` stack falls through to `pam_permit`; on anything else it exits non-zero, `requisite` makes that fatal at once, and `sudo` reports its own authentication failure. Nothing is written to the helper's stdout, because there is nothing to hand over.
6. Approved or refused, every request is a record in the audit log naming the command, who answered, and the `exec` record it belongs to.

There is no password anywhere: what satisfies `sudo` is a decision, not a credential, so nothing is minted, stored, injected or typed, and nothing a command approved once can keep and pass to a later one.

**Why the answer comes back over the broker socket.** `systemd-ask-password` is the tool this looks like it should use, and it cannot be: asking through it means creating a file in `/run/systemd/ask-password`, which is `0755 root:root`, so a broker running as its own uid is refused and every request would be denied for want of anyone to ask. What that channel offers is a reply socket only root can write to; `faramir approve` replaces it with the same guarantee made by the broker itself — `SO_PEERCRED` on its own socket, uid 0 or nothing. So the account that answers is one the coding agent cannot become.

**Where you watch from is part of it.** The socket check makes the answer come from root; it cannot make root the one doing the typing. The agent runs as *your* account, and a terminal your account owns is one it can reach — `tmux send-keys` and screen's `stuff` take input from any process running as the user who started the session. `faramir approve --watch` warns when it detects a multiplexer or a terminal not owned by root, but detection is not prevention: watch from a console, an ssh session on another machine, or a login as another account. And an operator with `NOPASSWD` sudo, or a warm sudo timestamp in a shell the agent can use, has already handed it that account.

`[elevate] notify_command` optionally announces a pending question (`wall`, a desktop notifier, a push). It carries no answer and nothing waits on it.

### One question per run, and what an approval does not bound

`ansible-playbook` calls `sudo` once per become'd task, so a question asked per request would be a prompt a task, and a question asked twenty times is one nobody reads by the tenth. A yes therefore covers every `sudo` that *one* run makes. That is not sudo's timestamp by another name (which is why `timestamp_timeout=0` stays): a timestamp is a stretch of time that anything starting inside rides, while this is scoped to the command the human was shown, gone the moment the run exits, and a second `faramir run` gets its own token and its own question.

An approval could leak past the one command it was shown for in two ways. One is closed; the other cannot be:

- *A second, unapproved command riding the approval — closed.* Two brokered commands share the `faramir-exec` uid, and `/proc/<pid>/environ` is readable within a uid, so a concurrent command could read the approved run's token and `sudo` on it. The broker shuts that window: **an elevation is approved only when its run is the sole brokered command in flight, and while it holds the approval every other brokered command is refused `busy`.** So expect other `faramir run`s to return `busy` for the length of an approved playbook — that pause is the protection. It rests on no `faramir-exec` process outliving its run, which is what the per-run cgroup guarantees ([design.md](design.md#elevating-on-the-controller) has the mechanism).
- *The approved command itself persisting root — not closed, ever.* An approved command gets real root and can make it permanent — a setuid-root binary, a `systemd` unit, a `cron` entry, a line in `sudoers` — none of which involves faramir again or expires when the token does. Approving is trusting **that command** with permanent root, identical to typing `sudo ansible-playbook` yourself. So keep the code an approved run executes operator-owned and read-only to brokered commands, or the agent can author what root runs. The audit log shows the elevation; it does not show the persistence a hostile command installs, unless you look.

### What elevation costs, beyond the grant

`faramir-exec.service` is rendered differently on a host that grants an elevation, because the sandbox that bounds a uid holding nothing also bounds the root a human just approved. `NoNewPrivileges=` makes every setuid binary inert, so with it set `sudo` fails on every task whatever the sudoers file says; an empty `CapabilityBoundingSet=` hands back a root that cannot chown or mount; `ProtectSystem=strict` turns "configure this host" into `EROFS`; and `SystemCallFilter=@system-service` excludes `@mount`, `@swap`, `@module` and `@reboot`. All of those are dropped, along with the `Protect*` family that names things root configures. What is *not* dropped is anything that bounds the uid below the approval: `ProtectProc=invisible`, the supplementary groups, the umask, `AmbientCapabilities=`. The unit states each one and why. Re-running `init` without `--elevate` restores all of them.

`faramir doctor` re-checks the arrangement, on a host that has it and on one that does not: the PAM service must gate rather than fall open (`requisite`, `seteuid`, faramir's own helper), the helper must be unwritable by the executor and by you, `/etc/pam.d/other` must not be a free pass for the case where the service file is ever removed, `faramir-exec` must hold no `NOPASSWD` entry from any source and no password of its own, and the executor unit must be delegated a cgroup so a run is confined and a `setsid` child cannot outlive it — a hard failure on an elevating host, where an unconfined run is refused, and a warning elsewhere, where the process-group kill reaps the rest.
