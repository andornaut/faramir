# Scope

## What this defends

**Keeping sops-managed values out of the model's context, in the projects enrolled to do it.** That is the whole of it.

Enrolment is per project because coverage is not free: the hook rewrites every Bash command so output can be redacted, and a rewritten command matches no permission rule, so Bash is auto-approved wherever the hook runs.

The value set is global. The broker holds every managed secret regardless of which project asked, so a command in an unenrolled project can print a managed value uncaught. **Treat unenrolled as "no redaction", not "safe".**

Not defended | Why
--- | ---
The agent's reach | Confining it is a means, and only where free. Not the goal.
The fleet | The account Ansible connects as has passwordless sudo on every managed host. That is the operator's arrangement.
Personal credentials at rest | `.env`, `~/.npmrc` and the like are read directly by the tools that need them. Scope and rotation are the mitigations.

**Accidental disclosure over deliberate exfiltration.** An agent that is trying to leak a credential cannot be stopped: it runs a playbook, reads the value on a managed host, and encodes it however it likes. What can be stopped is a credential landing in a transcript because a command printed it.

## One mode

The agent runs as the operator, with no account of its own and no boundary around the agent process. An agent maintaining the operator's repositories needs their checkouts, their `gh` credential and their commit identity; every route to granting a separate uid that access hands over the same files by another name.

The boundaries are around the secrets, not the agent:

Held by | What | Reachable by the operator
--- | --- | ---
`faramir-keeper` | the age key | no
`faramir-broker` | decrypted values, SSH keys, the audit log | no, except through the broker
`faramir-exec` | nothing; brokered commands run here | it cannot read the operator's home

Bounding what an unattended run may change is a credential-scope problem: a `gh` token limited to the repositories it maintains, plus branch protection. Filesystem blast radius is out of scope.

## Secrets in their own directory, not in a tree

Managed sops files live in `/etc/faramir/secrets`, `2770 root:dev`, and never in a checkout: a store a clone or a branch can move is not a store. The operator edits them in place with `sops`, through the group, without sudo. `.sops.yaml` sits in the same directory, but note that sops resolves it from the **current working directory** upward, not from the file being encrypted: encrypting into the store from elsewhere has to name it with `--config`.

`CONFIG_DIR` and `SECRETS_DIR` move both off `/etc`. What the units can see decides where, not the modes:

Placement | Result
--- | ---
`/etc/faramir` | the default. Present at boot, readable by three uids, owned by none of them
`/tmp`, `/var/tmp` | refused. `PrivateTmp=true` gives each unit its own, so nothing there is the file that was installed
inside a home | works, with the costs below. The installer relaxes the keeper's `ProtectHome=` to `tmpfs` and binds back that one directory

A home costs two things, and both are the operator's to accept:

- **It is not mounted until its owner logs in**, so the store is absent at boot and to anything running from cron. A value set that depends on one is empty exactly when nobody is watching.
- **Absent has to be fatal, then.** The broker treats any configured file it cannot load, including one that is simply not there, as a load failure: `--check` fails and the daemon says so. The alternative is a broker that comes up holding nothing and reports itself healthy, which is a security failure disguised as a working install. An outage that names itself is the cheaper of the two.

The installer also refuses to write into an encrypted home that is not currently mounted, because that lands in the unencrypted backing directory and is shadowed the moment the home mounts.

## Where brokered commands run

A brokered command runs where its caller was, so `faramir-exec` must reach that directory: it forks the command there. The broker stats it too, but only to fail early with a clear message, and treats its own permission error as the executor's business. The keeper needs nothing either way: its unit sets `ProtectHome=true`, so `/home` is empty in its namespace except for a store the installer bound back into it.

A tree outside the homes needs nothing. Inside a `0700` home the executor needs traversal, which `faramir share-tree` grants by making every directory from the home down group `dev` and group-executable. Execute only, so those uids pass through without listing what they pass, and never `chmod o+x`, which grants the same to every account on the machine: with `umask 002` in force the files below are `0664`, so that opens the home rather than a path through it.

The group slot is the one going spare on a home its owner holds outright, and it costs nothing to use: `chgrp` is ordinary inode metadata, so it passes through an encrypted home unchanged and needs no tooling beyond coreutils. What it costs is that membership of the group is also a grant to traverse the operator's home, so keep it to the accounts that need it. That is an argument for a group of its own rather than one that already means other things.

Group membership is a permission, not a mount: it holds nothing open, so an encrypted home still unmounts at logout. A brokered command running at the time does hold one open.

## Three layers

1. **No plaintext where the agent will trip over it.** Values are sops ciphertext; the age key is `0400` under a uid that executes nothing but sops.
2. **Leak-prone commands are refused.** [agent/hooks/deny-patterns.txt](../agent/hooks/deny-patterns.txt) names direct decryption, wholesale environment dumps, and readers or encoders pointed at key material. The refusal states the alternative, because a denial the agent cannot act on gets worked around. Ergonomics with teeth, not the boundary: the agent's uid cannot read the key material either way.
3. **Redact what still gets through.** The `redact` op returns text with every known value replaced by its token. The caller never receives the value set.

## How the rewrite works

A `PreToolUse` hook cannot rewrite a tool's result, but it can rewrite its input. The guard replaces `<command>` with:

```bash
source /usr/local/libexec/faramir/wrap.sh '<command>'
```

[wrap.sh](../agent/hooks/wrap.sh) creates a `0600` file on tmpfs, runs the command with both streams redirected into it, reads it back through `faramir redact`, removes it, and restores the exit status.

One constraint decides the shape: **the agent's shell persists between tool calls**, so a `cd` or `export` must survive.

Wrapper | State | Output | Allow-listable
--- | --- | --- | ---
`faramir redact -- bash -lc '<cmd>'` | lost, runs in a grandchild | fine | yes
`{ <cmd>; } 2>&1 \| faramir redact` | lost, pipeline elements are subshells | fine | no
`{ <cmd>; } > >(faramir redact) 2>&1` | kept | races the redactor | no
inline `{ <cmd>; } >"$f" 2>&1` | kept | complete | no
`source wrap.sh '<cmd>'` | kept | complete | no

Sourcing runs the command in the caller's own shell, so everything it sets stays set. Redacting the file afterwards rather than through a live pipe removes the race at no observable cost.

Failure modes all fall back to running the command and showing its output, never to running nothing or showing nothing. A temp file that cannot be created falls back to stdout; a `faramir` that cannot redact falls back to `cat`. When the broker is unreachable the wrapper warns and passes output through unredacted, because a wrapper that breaks every command gets removed, and a removed wrapper redacts nothing.

Left alone rather than rewritten, because buffering would change what they do:

- one already running under the redactor, so the wrapper is idempotent
- a `BashOutput` read
- a backgrounded command, whose output is wanted while it runs
- one whose last line ends in `\`, `&&`, `||` or `|`
- a denied command, which is refused instead

## What this gives up

**No kernel boundary around the agent process.** Hooks and the deny list, which is the trade for an agent that can do the operator's work.

**For Bash, the deny list replaces the permission prompt.** Permission matching runs against the rewritten command, so a rule keyed on the program name no longer matches, and the wrapper cannot be allow-listed either. Returning `allow` is not what removes those rules: the rewrite already stopped them matching, and the decision only makes that explicit rather than leaving rules that appear active and never fire.

**The shipped deny list names credential disclosure and nothing destructive.** Enrolling drops whatever Bash prompting stood between the agent and `rm -rf` and puts nothing in its place. Prompts on `Write` and `Edit` do not cover it, since Bash can write and delete without them.

There is no setting that returns `ask` instead. It would prompt on every command including `ls`, show the rewritten text rather than what was typed, offer no rule that could pre-approve any of it, and strand an unattended run on the first command with nobody to answer.

### Cost by permission mode

Hook decisions are evaluated independently of the session's permission mode, and the hook's decision applies. Measured with a hook that denies one pattern and rewrites everything else:

Session mode | Hook fires | A `deny` is enforced | The rewrite applies
--- | --- | --- | ---
`default` | yes | yes | yes
`acceptEdits` | yes | yes | yes
`bypassPermissions` | yes | yes | yes
`--dangerously-skip-permissions` | yes | yes | yes

Bypassing permissions skips neither hooks nor a hook-issued refusal. So enrolment does not cost the same everywhere:

Mode | Cost
--- | ---
`default` | Bash would have prompted and now does not. This is what the warning is about.
`acceptEdits` | Auto-accepts `Write` and `Edit`, leaves Bash prompting. Same cost as default. The mode that looks like it should exempt a project and does not.
`bypassPermissions` | Bash never prompted, so approving it removes nothing. Redaction and the deny list still apply, making enrolment purely additive.

Rewriting rather than denying is the point: a deny list only covers what somebody thought to name, and the command that leaks a credential is usually one nobody would have named.

**A `redact` op is an oracle.** Ask about a guessed value and the answer says whether the guess was right. No rate limit, no concurrency slot, not visible. Acceptable only on weighting: an accident does not guess, and an agent that is guessing has the fleet anyway. If that weighting changes, fix this first.

**A killed command loses its output.** Output is redacted after the command finishes, so a timeout or interrupt yields nothing where an unwrapped command would have shown partial output. The cost of buffering, which the persistent shell forces.

**The invariant:** no sops-managed value reaches the model except as a token, and nothing a session can read decrypts one.
