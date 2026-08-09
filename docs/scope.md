# Scope

## What this defends

**Keeping sops-managed values out of the model's context, in the projects enrolled to do it.** That is the whole of it.

The value set is global, so a command in an unenrolled project can print a managed value uncaught. **Treat unenrolled as "no redaction", not "safe".**

**Accidental disclosure over deliberate exfiltration.** An agent that is trying to leak a credential reads it on a managed host and encodes it however it likes. What can be stopped is a credential landing in a transcript because a command printed it.

Not defended | Why
--- | ---
The agent's reach | Confining it is a means, and only where free. Not the goal.
The fleet | The account Ansible connects as has passwordless sudo on every managed host. The operator's arrangement.
Personal credentials at rest | `.env`, `~/.npmrc` and the like are read by the tools that need them. Scope and rotation are the mitigations.

## One mode

The agent runs as the operator. An agent maintaining the operator's repositories needs their checkouts, their `gh` credential and their commit identity, and every route to giving a separate uid that access hands over the same files by another name. Bounding an unattended run is then a credential-scope problem: a `gh` token limited to the repositories it maintains, plus branch protection. Filesystem blast radius is out of scope.

The boundaries are around the secrets, not the agent:

Held by | What | Reachable by the operator
--- | --- | ---
`faramir-keeper` | the age key | no
`faramir-broker` | decrypted values, SSH keys, the audit log | no, except through the broker
`faramir-exec` | nothing; brokered commands run here | it cannot read the operator's home

## The store is a directory, not a tree

`/etc/faramir/secrets`, `2750 root:faramir-keeper`, never in a checkout: a store a clone or a branch can move is not a store. The keeper is the only account in that group and the only one that opens a managed file, so editing a value is `sudo faramir edit`. The broker socket admits a different group, because asking for a value by name is not permission to read the file it came from.

The broker is outside the store group deliberately: it holds every decrypted value already, so read on the ciphertext buys it nothing and would reach files no `[secrets]` list names. It asks the keeper when a file changed instead, over `get_state`, which touches neither the key nor sops.

`.sops.yaml` lives there too, but sops resolves it from the current working directory upward rather than from the file being encrypted, so encrypting into the store from elsewhere must pass `--config`.

`--config-dir` moves the store off `/etc`, along with the config and the age key: one path rather than three, so the key cannot be left on an unencrypted disk while the store it opens sits in an encrypted home. What the units can see decides where, not the modes:

Placement | Result
--- | ---
`/etc/faramir` | the default. Present at boot, readable by three uids, owned by none of them
`/tmp`, `/var/tmp` | installs, then finds nothing: `PrivateTmp=true` gives each unit its own, so the daemons open an empty one and fail to load
inside a home | works, at the cost below. `init` drops the keeper's `ProtectHome=` to `tmpfs` and binds that one directory back

A home is not mounted until its owner logs in, so the store is absent at boot and to cron. Absent is therefore fatal: a configured file the broker cannot load fails `--check` and stops the daemon, a broker holding nothing and reporting itself healthy being a security failure disguised as a working install. `init` also refuses to write into an unmounted encrypted home, which lands in the backing directory and is shadowed the moment the home mounts.

## Where brokered commands run

Where the caller was; `faramir-exec` forks the command there. A tree outside the homes needs nothing. Inside a `0700` home it needs traversal, which `faramir init-project` grants by making every directory from the home down group `dev` and group-executable: execute only, so those uids pass through without listing what they pass. Never `chmod o+x`, which with `umask 002` in force opens the `0664` files below rather than a path through them.

Membership is a permission, not a mount, so the home still unmounts at logout, though a brokered command running at the time holds it open. It is also a grant to traverse the operator's home: keep it to the accounts that need it, in a group that means nothing else.

## Three layers

1. **No plaintext where the agent will trip over it.** Values are sops ciphertext; the age key is `0400` under a uid that executes nothing but sops.
2. **Leak-prone commands are refused.** [deny-patterns.txt](../agent/hooks/deny-patterns.txt) names direct decryption, environment dumps, and readers or encoders pointed at key material. The refusal states the alternative, because a denial the agent cannot act on gets worked around. Ergonomics with teeth, not the boundary.
3. **Redact what still gets through.** The `redact` op returns text with every known value replaced by its token. The caller never receives the value set.

## How the rewrite works

A pre-execution check cannot rewrite a tool's result, but it can rewrite its input:

```bash
source /usr/local/libexec/faramir/wrap.sh '<command>'
```

[wrap.sh](../agent/hooks/wrap.sh) creates a `0600` file on tmpfs, runs the command with both streams redirected into it, reads it back through `faramir redact`, removes it, and restores the exit status.

**The agent's shell persists between tool calls**, so a `cd` or `export` must survive. That constraint decides the shape:

Wrapper | State | Output | Allow-listable
--- | --- | --- | ---
`faramir redact -- bash -lc '<cmd>'` | lost, runs in a grandchild | fine | yes
`{ <cmd>; } 2>&1 \| faramir redact` | lost, pipeline elements are subshells | fine | no
`{ <cmd>; } > >(faramir redact) 2>&1` | kept | races the redactor | no
inline `{ <cmd>; } >"$f" 2>&1` | kept | complete | no
`source wrap.sh '<cmd>'` | kept | complete | no

Every failure fails closed. No temp file and the command does not run, there being nowhere to capture what it would print; output captured but not redacted is withheld. Both say so on stderr and return non-zero, so a withheld output cannot read as a command that printed nothing. `faramir redact -- <cmd>` does the opposite and passes output through when the broker is gone: it wraps a command its caller is running rather than one an agent will read.

Left alone rather than rewritten, because buffering would change what they do:

- one already running under the redactor, so the wrapper is idempotent
- a read of a running command's output, such as Claude Code's `BashOutput`
- a backgrounded command, whose output is wanted while it runs
- one whose last line ends in `\`, `&&`, `||` or `|`
- a denied command, which is refused instead

## Agents

The guard is one program speaking each agent's contract. What varies is the tool that runs a command, the shape of the reply and where it is registered; what does not is that the command is rewritten to redact its own output. Which agents, and what enrolling each costs, is the table in the [README](../README.md). They are named with `--agent`, never detected.

opencode and Kilo Code have no hook that runs a program. A plugin in the agent's own process blocks a call by throwing and changes one by mutating its arguments, so it asks the guard and applies the answer:

```json
{"decision": "deny", "reason": "<what the model is told>"}
{"decision": "rewrite", "tool_input": {"command": "source .../wrap.sh '<command>'"}}
```

Nothing written is a call left alone, per the list above. Every other answer fails closed: a guard that cannot be run, a non-zero exit, an answer that is not JSON, a decision the plugin does not know. That covers version skew, so run `faramir init` before enrolling one of these: a binary too old to know `--host opencode` refuses every command in that project rather than running it unredacted.

Antigravity is declined rather than pending. A deny list without redaction is the weaker half of this, and shipping it under the same name would say a project is covered when the thing that covers it is absent.

## What this gives up

**No kernel boundary around the agent process.** Hooks and the deny list, which is the trade for an agent that can do the operator's work.

**For Bash on Claude Code, the deny list replaces the permission prompt.** Matching runs against the rewritten command, so a rule keyed on the program name no longer fires, and the wrapper cannot be allow-listed either. Returning `allow` is not what removes those rules; the rewrite already stopped them matching. There is no `ask` to return instead: it would prompt on every command including `ls`, show the rewritten text rather than what was typed, and strand an unattended run on the first command.

**The shipped deny list names credential disclosure and nothing destructive.** Enrolling drops whatever Bash prompting stood between the agent and `rm -rf` and puts nothing in its place. Prompts on `Write` and `Edit` do not cover it, Bash writing and deleting without them.

Hooks fire in every Claude Code permission mode and a `deny` is enforced in each, `--dangerously-skip-permissions` included, so what enrolment costs depends on the mode:

Mode | Cost
--- | ---
`default` | Bash would have prompted and now does not. This is what the warning is about.
`acceptEdits` | Auto-accepts `Write` and `Edit`, leaves Bash prompting. Same cost as default, and the mode that looks like it should exempt a project and does not.
`bypassPermissions` | Bash never prompted, so approving it removes nothing. Enrolment is purely additive.

Rewriting rather than denying is the point: a deny list covers what somebody thought to name, and the command that leaks a credential is usually one nobody would have.

**A `redact` op is an oracle.** A guessed value comes back confirmed or not, unmetered and invisible. Acceptable only on weighting: an accident does not guess, and an agent that is guessing has the fleet anyway. If that weighting changes, fix this first.

**A killed command loses its output.** Redaction happens after the command finishes, so a timeout or interrupt yields nothing where an unwrapped command would have shown partial output. The cost of buffering, which the persistent shell forces.

**The invariant:** no sops-managed value reaches the model except as a token, and nothing a session can read decrypts one.
