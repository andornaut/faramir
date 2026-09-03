# Layout

Every path the install creates, what owns it, and what each account can reach through it. `faramir init` writes all of it except the last two rows, which `faramir enrol` writes.

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

`sudo-env` is in `/usr/local/libexec/faramir` with the other files the install renders for its own use. It is not in `/etc/sudoers.d`, because sudo parses every file there, and not in `<config-dir>`, because an uninstall keeps that directory. It is owned by root, in a directory the executor's uid cannot write, because PAM reads it as root: if that uid could rewrite the file, it could set root's environment.

`init` also checks any file a `[[secret.link]]` entry names. It does not own or create that file, so it changes nothing. It reports what is wrong and the command that fixes it:

```text
<any file you link>             group-readable by <broker's group>, and by nobody else
<the directories above it>      enterable by <client-group>, down from the home
```

`init` also writes into the operator's home. A file it creates is `0640 <operator>:<operator group>`, and a missing parent is `0700`. A file that already exists keeps its owner and group; a rule file, hook or plugin is set to `0640` whatever mode it had, and an instructions file keeps its mode. What a run refuses to write, and why, is in [operating.md](operating.md#the-files-an-install-writes-into-your-agents-config):

Agent | Rule file | What faramir installs beside it | Credentials section | Notes
--- | --- | --- | --- | ---
Antigravity CLI (`agy`) | `~/.gemini/antigravity-cli/settings.json` | the hook in `~/.gemini/config/hooks.json` | `~/.gemini/GEMINI.md` | The whole Antigravity family keeps its files under `~/.gemini`, so the section and the hook are shared with the IDE. The deny rules are not
Antigravity IDE | none | the same hook | `~/.gemini/GEMINI.md` | It keeps its permission lists as internal state, not in a file an install can write, so the hook refuses its file tools
Claude Code | `~/.claude/settings.json` | a deny-only hook, in that same file | `~/.claude/CLAUDE.md` | A rule file and a section
Codex | none | a deny-only hook in `~/.codex/hooks.json` | `~/.codex/AGENTS.md` | Its own `.rules` files are an exec policy: they decide commands and name no path. There is no rule file to write, so the hook refuses its file tools
Kilo Code | `~/.config/kilo/kilo.json` | `~/.config/kilo/plugin/faramir.js` | `~/.kilocode/rules/faramir.md` | Its rule file is a prompt, not a refusal, so the plugin refuses. It has no single home instructions file, so the section goes in a file of faramir's own in the global rules directory, where every `.md` is loaded for every project
opencode | `~/.config/opencode/opencode.json` | `~/.config/opencode/plugin/faramir.js` | `~/.config/opencode/AGENTS.md` | Its rule file is also a prompt, not a refusal, so the plugin refuses
Pi | none | `~/.pi/agent/extensions/faramir.ts` | `~/.pi/agent/AGENTS.md` | No rule file an install can write, so the extension does everything. Pi loads a home's extensions for every project without the project being trusted

Every one of these refuses a path by asking `faramir guard`. Every one except Claude Code's and Codex's also routes commands through the broker. Those two return a permission decision, so a hook that rewrites a command must also approve it. Their account-wide hooks are `--deny-only`: each refuses what the list names and nothing else. An enrolment adds the routing.

The reasons behind each agent's files are in [coding-agents.md](coding-agents.md).

In an enrolled tree, every agent reads the tree's own `AGENTS.md`, or its `CLAUDE.md` if that is what the tree has. Three agents also read a file under their own name, and the enrolment writes one:

Agent | File in the tree | Why
--- | --- | ---
Antigravity | `.agents/rules/faramir.md` | It reads `.agents/rules/*.md` as well as the tree's own file. It does not read `CLAUDE.md`, so a tree whose own file is `CLAUDE.md` would give it nothing
Claude Code | `CLAUDE.md` | It reads `CLAUDE.md` and not `AGENTS.md`, so a tree whose own file is `AGENTS.md` would give it nothing
Codex | `AGENTS.md` | It reads `AGENTS.md` and not `CLAUDE.md`. If the tree's own file has that name, the two are one file and the section is written once

Two agents also need a hook in the tree for routing: Claude Code gets `.claude/settings.local.json` and Codex gets `.codex/hooks.json`. Both name paths chosen on this machine, so both belong in git's ignores. An enrolment reports when they are not ignored.

Every instructions file in a tree gets the same section, so you can symlink one to another and the section is written once. An operator who keeps a single file for every agent points `CLAUDE.md` at `AGENTS.md`, and the section goes into the file both names reach.

The section says what the deny rules cannot: why they refuse, and what to do instead.

`~/.bashrc` gets a `umask 002` line, so a file the operator creates in a shared tree stays group-writable.

## What the modes decide

- **A brokered command** can write the working tree and reach the broker socket. Its output is redacted and audited like any other. It cannot reach the age key by any route. The modes above refuse it the key file, the secrets directory, the keeper socket, the audit log and the SSH keys. No request returns the key, and nothing puts `SOPS_AGE_KEY` in its environment.
- **`0400 faramir-keeper` denies the operator the key wherever it is.** Owning the directory is permission to unlink the file, not to read it. Replacing the key causes denial of service, not disclosure: secrets encrypted to the old key decrypt for nobody. Nothing starts the keeper at boot; only the three `.socket` units are enabled.
- **The `--allow-sudo` files are `root:root`** because they decide who becomes root, so the account they govern must not be able to write them. Re-running `init` without the flag removes all of them, the `# BEGIN faramir` block included.
- **The directory directly holding a file the enrolment wrote is sticky as well as setgid**, so only the file's owner can unlink or rename inside it. The tree root is deliberately not sticky. The consequences are in [operating.md](operating.md#the-files-an-install-writes-into-your-agents-config).
- **Every install renders the executor unit with `Delegate=yes`**, so each run gets its own cgroup and is reaped there.

`--config-dir` moves the config, the secrets directory and the age key together. The reason is in [design.md](design.md#the-secrets-live-in-a-directory-not-a-tree). Three things do not follow it: the audit log, which is the broker unit's `ReadWritePaths`, the two sudo files, which are at the paths `sudo` and PAM read, and `sudo-env`, which stays in `/usr/local/libexec/faramir`. `faramir status` reports the config file and the secrets files the broker loaded.

## Sharing a working tree

**The enrolled tree is the only place faramir changes ownership and modes.** Everywhere else it checks and reports. The directories above the tree are not part of it, so the operator grants the traversal `faramir-exec` needs through a `0700` home:

- Every directory from the home down must be enterable by the client group (execute only), so those uids can pass through without listing what they pass. `enrol` refuses to share a tree it cannot reach, and names each directory and the `chgrp` and `chmod` that open it.
- Never `chmod o+x`. That grants the same to every account on the machine.
- Everyone in the group gets that traversal, so keep membership to the accounts that need it.
- A directory already traversable by `other` is accepted as it is. `enrol` does not tighten a directory the operator left open.
- Membership is a permission, not a mount, so an encrypted home still unmounts at logout. A brokered command running at the time holds it open.
- The tree itself gets `2770`, group-readable and group-writable, because a brokered command runs in it and writes to it. That covers the whole tree, so a `.env` or `.pem` in the checkout is shared along with the code. The agent settings faramir manages are regrouped but deliberately not made group-writable. `enrol` reports how many paths it changed, how many it left at their own mode, and how many directories it closed to unlink by anyone but their owner.
