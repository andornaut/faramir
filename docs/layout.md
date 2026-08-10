# Layout

Every path `faramir init` creates, what owns it, and what each account can reach through it.

```text
/usr/local/bin/faramir        the only binary; every role is a subcommand
/usr/local/libexec/faramir/   the deny list, wrap.sh and (with --elevate) the PAM helper, rendered per install

/run/faramir/broker.sock      socket-activated, 0660 root:<client-group>
/run/faramir/keeper.sock      socket-activated, 0660 root:faramir-broker
/run/faramir/exec.sock        socket-activated, 0660 root:faramir-broker
/run/faramir/ssh-agent.sock   optional, 0660 faramir-broker:faramir-exec
/etc/sudoers.d/faramir        0440 root:root, the grant; --elevate only, password-required
/etc/pam.d/faramir-sudo       0644 root:root, how sudo authenticates faramir-exec and nobody else; --elevate only
<config-dir>/age.key          0400 faramir-keeper:faramir-keeper
<config-dir>/id_ed25519       0600 faramir-broker:faramir-broker, the key it lends; .pub 0644
<config-dir>/secrets/         2750 root:faramir-keeper, the managed sops files
<config-dir>/.sops.yaml       0644 root:root, the creation rule; above the secrets directory, not in it
<config-dir>/config.toml      0644 root:root, faramir's own, rewritten every run
<config-dir>/config.d/        0755 root:root, yours and each consumer's, merged over it
<any tree you enrol>          2770 <operator>:<client-group>, setgid; faramir init-project
~faramir-broker/.ssh/         0700 faramir-broker, the keys it lends through the agent
/var/log/faramir/             0750 faramir-broker:faramir-broker, LogsDirectoryMode=
/var/log/faramir/audit.log    0600 faramir-broker:faramir-broker; faramir logs reads it
/etc/logrotate.d/faramir      0644 root:root, weekly, 8 kept, early at 16MB
```

`--config-dir` moves the config, the secrets directory and the age key off `/etc` together; the audit log stays where it is. `faramir status` reports the paths in use.

The two `--elevate` files (and the PAM helper beside `wrap.sh`) are `root:root` on purpose: they decide who becomes root, so the account they govern must not be able to write them, and `faramir doctor` checks that. They stay at `/etc`, unmoved by `--config-dir`, being the paths `sudo` and PAM read. Re-running `init` without `--elevate` removes both; see [operating.md](operating.md#elevating-on-the-controller). Every install, elevation or not, also renders the executor unit with `Delegate=yes` so each run gets its own cgroup and is reaped there — a brokered command leaves no process behind, which is what the serialisation an elevation relies on rests on. Where a cgroup cannot be made (a container without delegation, say), an elevating host refuses to run and a plain one reaps by process group instead.

A brokered command can write the working tree and reach the broker socket, its output redacted and audited like any other. It cannot reach the age key by any route: the modes above are what refuse the key file, the secrets directory, the keeper socket, the audit log and the SSH keys, no request returns the key, and nothing puts `SOPS_AGE_KEY` in its environment.

`0400 faramir-keeper` keeps the operator out of the key wherever it sits: owning the directory is permission to unlink the file, not to read it, so replacing the key buys denial of service rather than disclosure, secrets encrypted to the replaced key decrypting for nobody. Nothing starts the keeper at boot either; its unit is triggered only by its socket.

## Sharing a working tree

A tree inside a 0700 home needs traversal for `faramir-exec`, which `faramir init-project` grants by group:

- Every directory from the home down becomes the client group and group-executable, execute only, so those uids pass through without listing what they pass.
- Never `chmod o+x`, which grants the same to every account on the machine.
- Everyone in the group gets that traversal, so keep membership to the accounts that need it.
- A directory already traversable by `other` is left alone. One whose group is something else is taken over, costing that group whatever the group bits gave it, and `init-project` says so.
- Membership is a permission, not a mount, so an encrypted home still unmounts at logout, though a brokered command running at the time holds it open.
- The tree itself gets more than traversal: `2770`, group-readable and group-writable throughout, because a brokered command runs in it and writes to it. A whole tree, so a `.env` or a `.pem` sitting in the checkout is shared along with the code.
