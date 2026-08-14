# Layout

Every path the install creates, what owns it, and what each account can reach through it. `faramir init` writes all of it except the last two rows, which are `faramir init-project`'s.

```text
/usr/local/bin/faramir          0755 root:root, the only binary; every role is a subcommand
/usr/local/libexec/faramir/     0755 root:root
  deny-patterns.txt             0644 root:root, rendered per install
  wrap.sh                       0644 root:root, copied verbatim
  pam-approve                   0755 root:root, rendered; installed on every host, grant or not
/usr/local/share/doc/faramir/   0755 root:root, README, LICENSE and docs/, embedded and written out

/etc/systemd/system/faramir-*   0644 root:root, three .service and three .socket units
/etc/tmpfiles.d/faramir.conf    0644 root:root, creates /run/faramir
/run/faramir/                   0755 faramir-broker:faramir-broker
/run/faramir/broker.sock        socket-activated, 0660 root:<client-group>
/run/faramir/keeper.sock        socket-activated, 0660 root:<broker's group>
/run/faramir/exec.sock          socket-activated, 0660 root:<broker's group>
/run/faramir/ssh-agent.sock     0660 faramir-broker:<exec group>, only when [ssh] exec_group is set
/etc/sudoers.d/faramir          0440 root:root, password-required; --allow-sudo only
/etc/pam.d/faramir-sudo         0644 root:root, how sudo authenticates faramir-exec and nobody else; --allow-sudo only

<config-dir>/age.key            0400 faramir-keeper:faramir-keeper
<config-dir>/id_ed25519         0600 faramir-broker:faramir-broker, the key it lends; .pub 0644
<config-dir>/secrets/           2750 root:<secrets-group>, the managed sops files, each 0640
<config-dir>/.sops.yaml         0644 root:root, the creation rule; above the secrets directory, not in it
<config-dir>/config.toml        0644 root:root, faramir's own, rewritten every run
<config-dir>/config.d/          0755 root:root, yours; each *.toml re-owned 0644 root:root every run

/var/lib/faramir-broker/        the broker's home, a StateDirectory=; .ssh/ 0700
/var/lib/faramir-keeper/        the keeper's home, likewise
/var/lib/faramir-exec/          the child's HOME; .ssh/ 0700
  .ssh/known_hosts              0644 faramir-exec:faramir-exec, only with --known-hosts
/var/log/faramir/               0750 faramir-broker:faramir-broker, LogsDirectoryMode=
/var/log/faramir/audit.log      0600 faramir-broker:faramir-broker; faramir logs reads it
/etc/logrotate.d/faramir        0644 root:root, weekly, 8 kept, early at 16MB

<config-dir>/enrolled.json      0600 root:root, which trees were enrolled and for what; advisory, and doctor's
<any tree you enrol>            2770 <operator>:<client-group>, setgid
```

`init` also writes into the operator's home, each `0640 <operator>:<operator group>`, with any missing parent created `0700`:

Agent | Deny rules | Credentials section
--- | --- | ---
Claude Code | `~/.claude/settings.json` | `~/.claude/CLAUDE.md`
Gemini CLI | `~/.gemini/policies/faramir.toml` | `~/.gemini/GEMINI.md`
opencode | `~/.config/opencode/opencode.json` | `~/.config/opencode/AGENTS.md`
Kilo Code | `~/.config/kilo/kilo.json` | `~/.kilocode/rules/faramir.md`
Pi | none | `~/.pi/agent/AGENTS.md`

Pi gets no rule file: it has nowhere to put account-wide rules, so the same paths are compiled into the extension `init-project` installs. It gets the section like the rest.

The section goes between `<!-- BEGIN faramir: credentials -->` and `<!-- END faramir: credentials -->`, and only what is between them is faramir's: a later `init` replaces that and nothing else. These are the operator's own files, so the rest is theirs. It says what the deny rules refuse and why, which the rules themselves cannot: a refusal that reaches the model with no reason is the one that gets a second attempt through an interpreter. Kilo Code has no single home instructions file, so it gets one of faramir's own in its global rules directory, every `.md` in which is loaded for every project.

`~/.bashrc` gets a `umask 002` line, so a file the operator creates in a shared tree stays group-writable.

Each agent's own directory under the tree is `3770` rather than `2770`: sticky as well as setgid, so unlink and rename inside it are the file's owner's. That is what keeps a brokered command from deleting the settings that name the hook and writing its own, the file's `0640` saying nothing about being unlinked.

The tree's own root is not sticky, deliberately. Sticky there would stop a brokered command renaming over or deleting any operator-owned file at the top level, which is what a tool rewriting a lock file or `go.mod` by rename does. The cost of leaving it open is most of what the sticky bit below it buys: renaming a directory needs write on its parent, and the root is group-writable, so a brokered command can move `.claude` aside and put its own there. `faramir doctor` reports a tree whose agent files stopped carrying what the enrolment wrote.

`--config-dir` moves the config, `config.d/`, the secrets directory and the age key off `/etc` together, so the key cannot sit on an unencrypted disk while the secrets it opens live in an encrypted home. The audit log and the two sudo files do not follow: the log is the broker unit's `ReadWritePaths`, and the sudo files are the paths `sudo` and PAM read. `faramir status` reports the paths in use.

The `--allow-sudo` files are `root:root` because they decide who becomes root, so the account they govern must not be able to write them. Re-running `init` without the flag removes both. Every install renders the executor unit with `Delegate=yes` so each run gets its own cgroup and is reaped there.

A brokered command can write the working tree and reach the broker socket, its output redacted and audited like any other. It cannot reach the age key by any route: the modes above refuse the key file, the secrets directory, the keeper socket, the audit log and the SSH keys, no request returns the key, and nothing puts `SOPS_AGE_KEY` in its environment.

`0400 faramir-keeper` keeps the operator out of the key wherever it sits: owning the directory is permission to unlink the file, not to read it, so replacing the key yields denial of service rather than disclosure, secrets encrypted to the replaced key decrypting for nobody. Nothing starts the keeper at boot either; only the three `.socket` units are enabled.

## Sharing a working tree

A tree inside a 0700 home needs traversal for `faramir-exec`, which `faramir init-project` grants by group:

- Every directory from the home down becomes the client group and group-executable, execute only, so those uids pass through without listing what they pass.
- Never `chmod o+x`, which grants the same to every account on the machine.
- Everyone in the group gets that traversal, so keep membership to the accounts that need it.
- A directory already traversable by `other` is left alone. One whose group is something else is taken over, costing that group whatever the group bits gave it, and `init-project` says so.
- Membership is a permission, not a mount, so an encrypted home still unmounts at logout, though a brokered command running at the time holds it open.
- The tree itself gets `2770`, group-readable and group-writable, because a brokered command runs in it and writes to it. A whole tree, so a `.env` or a `.pem` sitting in the checkout is shared along with the code. The agent settings files faramir manages are regrouped but deliberately left not group-writable, and each agent's own directory is sticky, so a brokered command cannot get at those files by unlinking one and writing its own.
