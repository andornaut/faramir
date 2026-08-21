# Layout

Every path the install creates, what owns it, and what each account can reach through it. `faramir init` writes all of it except the last two rows, which are `faramir init-project`'s.

```text
/usr/local/bin/faramir          0755 root:root, the only binary; every role is a subcommand
/usr/local/libexec/faramir/     0755 root:root
  deny-patterns.txt             0644 root:root, rendered per install
  wrap.sh                       0644 root:root, copied verbatim
  pam-approve                   0755 root:root, rendered; installed on every host, grant or not
  sudo-env                      0644 root:root, what a brokered command's sudo is given; --allow-sudo only
/usr/local/share/doc/faramir/   0755 root:root, README, LICENSE and docs/, embedded and written out

/etc/systemd/system/faramir-*   0644 root:root, three .service and three .socket units
/etc/tmpfiles.d/faramir.conf    0644 root:root, creates /run/faramir
/run/faramir/                   0755 faramir-broker:faramir-broker
/run/faramir/broker.sock        socket-activated, 0660 root:<client-group>
/run/faramir/keeper.sock        socket-activated, 0660 root:<broker's group>
/run/faramir/exec.sock          socket-activated, 0660 root:<broker's group>
/run/faramir/ssh-agent.sock     0660 faramir-broker:<exec group>, only when [ssh] exec_group is set
/etc/sudoers.d/faramir          0440 root:root, password-required; --allow-sudo only
/etc/pam.d/faramir-sudo         0644 root:root, how sudo authenticates faramir-exec and nobody else; --allow-sudo only, and only where the host's sudo can be sent to a service by name
/etc/pam.d/sudo, sudo-i         the distribution's, gaining a `# BEGIN faramir` block on a sudo-rs host, which has no faramir-sudo at all; --allow-sudo only

<config-dir>/age.key            0400 faramir-keeper:faramir-keeper
<config-dir>/id_ed25519         0600 faramir-broker:faramir-broker, the key it lends; .pub 0644
<config-dir>/secrets/           2750 root:<secrets-group>, the managed sops files, each 0640
<config-dir>/.sops.yaml         0644 root:root, the creation rule; above the secrets directory, not in it
<config-dir>/config.toml        0644 root:root, faramir's own, rewritten every run

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

`sudo-env` is the one file here sudo reads as policy, so it stays out of `<config-dir>`: the grant names one path wherever `--config-dir` points, and an uninstall keeps the config directory and so must never remove it whole. Root-owned and never writable by the executor, or that uid would be choosing root's environment.

`init` also grants access to any file a `[[secret.link]]` entry names, which is a file it does not own and does not create:

```text
<any file you link>             group-readable by <broker's group>, owner and owner bits kept
<the directories above it>      <client-group> and execute only, down from the home
```

`init` also writes into the operator's home. A file it creates is `0640 <operator>:<operator group>` and a missing parent `0700`; one already there keeps its own owner, group and mode. What a run refuses to write, and why, is in [operating.md](operating.md#the-files-an-install-writes-into-your-agents-config):

Agent | Deny rules | Credentials section
--- | --- | ---
Claude Code | `~/.claude/settings.json` | `~/.claude/CLAUDE.md`
opencode | `~/.config/opencode/opencode.json` | `~/.config/opencode/AGENTS.md`
Kilo Code | `~/.config/kilo/kilo.json` | `~/.kilocode/rules/faramir.md`
Pi | none | `~/.pi/agent/AGENTS.md`
Antigravity | none | `~/.gemini/GEMINI.md`, under the directory the whole Antigravity family keeps its own things in

Pi gets no rule file, having nowhere to put account-wide rules: the same paths are compiled into the extension `init-project` installs. It gets the section like the rest. Antigravity gets no rule file either, its permission lists being the IDE's own state. Kilo Code has no single home instructions file, so its section is a file of faramir's own in the global rules directory, every `.md` in which is loaded for every project. Why each agent gets what it gets is in [coding-agents.md](coding-agents.md).

Every agent but one reads the enrolled tree's own `AGENTS.md`, or its `CLAUDE.md` where that is what the tree has. Antigravity reads no documented file at a tree's root, so it gets `.agents/rules/faramir.md` there instead, headed with the frontmatter that makes a rule always-on where this creates it.

The section is what the deny rules cannot say: why they refuse, and what to do instead.

`~/.bashrc` gets a `umask 002` line, so a file the operator creates in a shared tree stays group-writable.

## What the modes decide

- **A brokered command** can write the working tree and reach the broker socket, its output redacted and audited like any other. It cannot reach the age key by any route: the modes above refuse the key file, the secrets directory, the keeper socket, the audit log and the SSH keys, no request returns the key, and nothing puts `SOPS_AGE_KEY` in its environment.
- **`0400 faramir-keeper` keeps the operator out of the key wherever it sits.** Owning the directory is permission to unlink the file, not to read it, so replacing the key yields denial of service rather than disclosure, secrets encrypted to the replaced key decrypting for nobody. Nothing starts the keeper at boot either; only the three `.socket` units are enabled.
- **The `--allow-sudo` files are `root:root`** because they decide who becomes root, so the account they govern must not be able to write them. Re-running `init` without the flag removes both.
- **Each agent's own directory in an enrolled tree is `3770` rather than `2770`:** sticky as well as setgid, so unlink and rename inside it belong to the file's owner. The tree root is `2770` deliberately, and what that costs is in [operating.md](operating.md#the-files-an-install-writes-into-your-agents-config).
- **Every install renders the executor unit with `Delegate=yes`**, so each run gets its own cgroup and is reaped there.

`--config-dir` moves the config, the secrets directory and the age key together, and the reason is in [design.md](design.md#the-secrets-live-in-a-directory-not-a-tree). What does not follow: the audit log, which is the broker unit's `ReadWritePaths`, and the two sudo files, which are the paths `sudo` and PAM read. `faramir status` reports the paths in use.

## Sharing a working tree

A tree inside a 0700 home needs traversal for `faramir-exec`, which `faramir init-project` grants by group:

- Every directory from the home down becomes the client group and group-executable, execute only, so those uids pass through without listing what they pass.
- Never `chmod o+x`, which grants the same to every account on the machine.
- Everyone in the group gets that traversal, so keep membership to the accounts that need it.
- A directory already traversable by `other` is left alone. One whose group is something else is taken over, costing that group whatever the group bits gave it, and `init-project` says so.
- Membership is a permission, not a mount, so an encrypted home still unmounts at logout, though a brokered command running at the time holds it open.
- The tree itself gets `2770`, group-readable and group-writable, because a brokered command runs in it and writes to it. A whole tree, so a `.env` or a `.pem` sitting in the checkout is shared along with the code. The agent settings faramir manages are regrouped and deliberately not group-writable.
