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
