# Layout

Every path the install creates, what owns it, and what each account can reach through it. `faramir init` writes all of it except the last two rows, which are `faramir enrol`'s.

```text
/usr/local/bin/faramir          0755 root:root, the only binary; every role is a subcommand
/usr/local/libexec/faramir/     0755 root:root
  deny-patterns.txt             0644 root:root, rendered per install
  wrap.sh                       0644 root:root, copied verbatim
  pam-escalate                  0755 root:root, rendered; installed on every host, grant or not
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
/var/lib/faramir-keeper/        the keeper's home, a StateDirectory= as well
/var/lib/faramir-exec/          the child's HOME; .ssh/ 0700
  .ssh/known_hosts              0644 faramir-exec:faramir-exec, only with --known-hosts
/var/log/faramir/               0750 faramir-broker:faramir-broker, LogsDirectoryMode=
/var/log/faramir/audit.log      0600 faramir-broker:faramir-broker; faramir logs reads it
/etc/logrotate.d/faramir        0644 root:root, weekly, 8 kept, early at 16MB

<config-dir>/enrolled.json      0600 root:root, which trees were enrolled and for what; advisory, and doctor's
<any tree you enrol>            2770 <operator>:<client-group>, setgid
```

`sudo-env` sits in `/usr/local/libexec/faramir`, beside the other files this install renders for its own use, rather than in either place it might otherwise go. Not `/etc/sudoers.d`, which sudo parses in its entirety. Not `<config-dir>`, which an uninstall keeps and so must never remove wholesale. It is root-owned and nowhere the executor's uid can write, because PAM reads it as root: a file that uid could rewrite would be that uid choosing root's environment.

`init` also checks any file a `[[secret.link]]` entry names, which is a file it does not own and does not create. It reports what is wrong and the command that fixes it, and changes nothing:

```text
<any file you link>             group-readable by <broker's group>, and by nobody else
<the directories above it>      enterable by <client-group>, down from the home
```

`init` also writes into the operator's home. A file it creates is `0640 <operator>:<operator group>` and a missing parent `0700`; one already there keeps its own owner, group and mode. What a run refuses to write, and why, is in [operating.md](operating.md#the-files-an-install-writes-into-your-agents-config):

Agent | Rule file | What faramir installs beside it | Credentials section | Notes
--- | --- | --- | --- | ---
Antigravity CLI (`agy`) | `~/.gemini/antigravity-cli/settings.json` | the hook in `~/.gemini/config/hooks.json` | `~/.gemini/GEMINI.md` | `~/.gemini` is where the whole Antigravity family keeps its own things, so the section and the hook are shared with the IDE and the deny rules are not
Antigravity IDE | none | the same hook | `~/.gemini/GEMINI.md` | It keeps its permission lists as its own state rather than in a file an install may write, so that hook is what refuses its file tools
Claude Code | `~/.claude/settings.json` | a deny-only hook, in that same file | `~/.claude/CLAUDE.md` | The ordinary case: a rule file and a section
Codex | none | a deny-only hook in `~/.codex/hooks.json` | `~/.codex/AGENTS.md` | Its own `.rules` files are an exec policy: they decide commands and name no path, so there is no rule file to write and the hook is what refuses its file tools
Kilo Code | `~/.config/kilo/kilo.json` | `~/.config/kilo/plugin/faramir.js` | `~/.kilocode/rules/faramir.md` | Its rule file is a prompt rather than a refusal, so the plugin is what refuses. It has no single home instructions file either, so the section goes in a file of faramir's own in the global rules directory, where every `.md` is loaded for every project
opencode | `~/.config/opencode/opencode.json` | `~/.config/opencode/plugin/faramir.js` | `~/.config/opencode/AGENTS.md` | The same rule file, a prompt rather than a refusal, so the plugin is what refuses here too
Pi | none | `~/.pi/agent/extensions/faramir.ts` | `~/.pi/agent/AGENTS.md` | No rule file an install can write, so the extension is the whole of it. Pi loads a home's extensions for every project without the project being trusted

Every one of these refuses a path by asking `faramir guard`, and every one but Claude Code's and Codex's also routes a command through the broker. Those two return a permission decision, so the hook that rewrites a command must also approve it, and their account-wide hooks are `--deny-only`: each refuses what the list names and nothing else, and routing is what an enrolment buys.

Why each agent gets what it gets is in [coding-agents.md](coding-agents.md).

In an enrolled tree, every agent reads the tree's own `AGENTS.md`, or its `CLAUDE.md` where that is what the tree has. Three agents read a name of their own as well, and get a file there:

Agent | File in the tree | Why
--- | --- | ---
Antigravity | `.agents/rules/faramir.md` | It reads `.agents/rules/*.md` as well as the tree's own file, so a tree whose own file is a `CLAUDE.md` would leave it nothing, that being a name it does not read
Claude Code | `CLAUDE.md` | It reads `CLAUDE.md` and not `AGENTS.md`, so a tree whose own file is an `AGENTS.md` would leave it nothing
Codex | `AGENTS.md` | The mirror image of Claude Code: it reads `AGENTS.md` and not `CLAUDE.md`. Where the tree's own file has that name the two are one file and the section is written once

Two agents also get a hook in the tree, which is what routing costs them: Claude Code a `.claude/settings.local.json` and Codex a `.codex/hooks.json`. Both name paths this machine decided, so both belong in git's ignores, and an enrolment says so when they are not there.

Every instructions file in a tree carries the same section, so linking one at another is supported and writes it once: an operator who keeps a single file for every agent points `CLAUDE.md` at `AGENTS.md`, and the section goes into the file both names.

The section says what the deny rules cannot: why they refuse, and what to do instead.

`~/.bashrc` gets a `umask 002` line, so a file the operator creates in a shared tree stays group-writable.

## What the modes decide

- **A brokered command** can write the working tree and reach the broker socket, its output redacted and audited like any other. It cannot reach the age key by any route: the modes above refuse the key file, the secrets directory, the keeper socket, the audit log and the SSH keys, no request returns the key, and nothing puts `SOPS_AGE_KEY` in its environment.
- **`0400 faramir-keeper` keeps the operator out of the key wherever it sits.** Owning the directory is permission to unlink the file, not to read it, so replacing the key yields denial of service rather than disclosure, secrets encrypted to the replaced key decrypting for nobody. Nothing starts the keeper at boot either; only the three `.socket` units are enabled.
- **The `--allow-sudo` files are `root:root`** because they decide who becomes root, so the account they govern must not be able to write them. Re-running `init` without the flag removes both.
- **The directory directly holding a file the enrolment wrote is sticky as well as setgid**, so unlink and rename inside it belong to the file's owner. The tree root deliberately is not, and what that costs is in [operating.md](operating.md#the-files-an-install-writes-into-your-agents-config).
- **Every install renders the executor unit with `Delegate=yes`**, so each run gets its own cgroup and is reaped there.

`--config-dir` moves the config, the secrets directory and the age key together, and the reason is in [design.md](design.md#the-secrets-live-in-a-directory-not-a-tree). What does not follow: the audit log, which is the broker unit's `ReadWritePaths`, and the two sudo files, which are the paths `sudo` and PAM read. `faramir status` reports the paths in use.

## Sharing a working tree

**The enrolled tree is the one place faramir changes ownership and modes.** Everywhere else it checks and reports. The directories above the tree are not part of it, so the traversal `faramir-exec` needs through a 0700 home is the operator's to grant:

- Every directory from the home down has to be enterable by the client group, execute only, so those uids pass through without listing what they pass. `enrol` refuses to share a tree it cannot reach, naming each directory and the `chgrp` and `chmod` that open it.
- Never `chmod o+x`, which grants the same to every account on the machine.
- Everyone in the group gets that traversal, so keep membership to the accounts that need it.
- A directory already traversable by `other` is accepted as it is: tightening one the operator left open is not this command's business.
- Membership is a permission, not a mount, so an encrypted home still unmounts at logout, though a brokered command running at the time holds it open.
- The tree itself gets `2770`, group-readable and group-writable, because a brokered command runs in it and writes to it. That is the whole tree, so a `.env` or a `.pem` sitting in the checkout is shared along with the code. The agent settings faramir manages are regrouped but deliberately left not group-writable. `enrol` reports how many paths it altered, how many it left at their own mode, and how many directories it closed to unlink by anyone but their owner.
