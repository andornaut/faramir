# Design decisions and their costs

## What this defends

The [Prevented](../README.md#prevented) and [Not prevented](../README.md#not-prevented) tables are the boundary, including that the agent's own reach is not part of it. Two more things nobody should expect this to cover:

Not defended | Why
--- | ---
The fleet | The account Ansible connects as has passwordless sudo on every managed host. The operator's arrangement.
Personal credentials at rest | `.env`, `~/.npmrc` and the like are read by the tools that need them. Scope and rotation are the mitigations.

## One mode

The agent runs as the operator. An agent maintaining the operator's repositories needs their checkouts, their `gh` credential and their commit identity, and every route to giving a separate uid that access hands over the same files by another name. Bounding an unattended run is then a credential-scope problem: a `gh` token limited to the repositories it maintains, plus branch protection. Filesystem blast radius is out of scope.

The boundaries are around the secrets, not the agent. Of the three uids in the [README's table](../README.md#how-it-works), the operator reaches the keeper's age key not at all, the broker's decrypted values, SSH keys and audit log only through the broker, and `faramir-exec`, where brokered commands run, cannot read the operator's home.

## The secrets live in a directory, not a tree

`/etc/faramir/secrets`, `2750 root:faramir-keeper`, never in a checkout, which a clone or a branch could move. The keeper is the only account in that group and the only one that opens a managed file, so editing a value is `sudo faramir edit`. The broker socket admits a different group, because asking for a value by name is not permission to read the file it came from.

The broker is outside the secrets group deliberately: it holds every decrypted value already, so read on the ciphertext buys it nothing and would reach files no `[secrets]` list names. It asks the keeper when a file changed instead, over `get_state`, which touches neither the key nor sops.

`.sops.yaml` sits in the config directory above the secrets directory rather than in it. sops resolves that file from the current working directory upward rather than from the file being encrypted, so the parent is found from the secrets directory as well as from itself, while the secrets directory would be found only from itself; encrypting from anywhere else still has to pass `--config`. And it is a drop zone that `[secrets] files` globs, where Go's `filepath.Glob` matches dotfiles: a rule file among the ciphertext is one glob spelling away from being loaded as a managed file that does not decrypt, which fails `--check` and leaves the broker redacting nothing.

`--config-dir` moves the secrets off `/etc`, along with the config and the age key: one path rather than three, so the key cannot be left on an unencrypted disk while the secrets it opens sit in an encrypted home. What the units can see decides where, not the modes:

Placement | Result
--- | ---
`/etc/faramir` | the default. Present at boot, readable by three uids, owned by none of them
`/tmp`, `/var/tmp` | installs, then finds nothing: `PrivateTmp=true` gives each unit its own, so the daemons open an empty one and fail to load
inside a home | works, at the cost below. `init` drops the keeper's `ProtectHome=` to `tmpfs` and binds that one directory back

A home is not mounted until its owner logs in, so the secrets are absent at boot and to cron. Absent is therefore never quietly tolerated: a file may be missing because it was never written or because the filesystem holding it is not mounted, and only the second is dangerous, so both are refused. `exec` is held to the same rule as `redact`, a brokered command's output being redacted against the same value set. The cost is a fresh install refusing every wrapped command until it has one file, loudly and with the reason; the rule and its one exception are stated with [the gate](../README.md#the-install-gate-and-the-same-gate-at-startup).

Checked per request rather than once at startup, which is what makes this placement survivable: `--check` runs from `init` and `doctor`, neither of which is around at boot, which is exactly when an unmounted home is absent. `init` also refuses to write into an unmounted encrypted home, which lands in the backing directory and is shadowed the moment the home mounts.

## Three layers

1. **No plaintext where the agent will trip over it.** Values are sops ciphertext; the age key is `0400` under a uid that executes nothing but sops.
2. **Leak-prone commands are refused.** [deny-patterns.txt](../agent/hooks/deny-patterns.txt) names direct decryption, environment dumps, and readers or encoders pointed at key material. The refusal states the alternative, because a denial the agent cannot act on gets worked around.
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

Every failure fails closed. No temp file and the command does not run, there being nowhere to capture what it would print; output captured but not redacted is withheld. Both say so on stderr and return non-zero, so a withheld output cannot read as a command that printed nothing.

`faramir redact` does the same, in both its shapes and for the same reason. A chunk it cannot redact is never written, nothing after it is written, and the exit status is non-zero, which is what the wrapper above is reading when it withholds. The command form keeps the child's own status when the child failed and turns a success into a failure otherwise, because the command still ran and only its output is missing.

What is *not* withheld is the part of a stream that was already redacted, on a broker that dies part way through. Those chunks came back covered, so holding them protects nothing, and buffering the whole stream to be able to hold them would cost an unbounded buffer and every byte of incremental output for a guarantee that is already met: no unredacted byte is written. A failure therefore truncates the output rather than emptying it, and on the usual failure (a broker that is not running, which fails on the first chunk) those are the same thing.

Left alone rather than rewritten, because buffering would change what they do:

- one this rewrite already produced, so the wrapper is idempotent
- a read of a running command's output, such as Claude Code's `BashOutput`
- a backgrounded command, whose output is wanted while it runs
- one whose last line ends in `\`, `&&`, `||` or `|`
- a denied command, which is refused instead

The first is a prefix test against the whole command, and it is the only thing that counts as already covered. Two forms that look covered and are not:

- **A command that merely names the wrap script.** The path is in this project's documentation and in the wrapper itself, so a match anywhere in the line would leave `echo /usr/local/libexec/faramir/wrap.sh; cat secrets` unrewritten.
- **A command piping into the redactor.** A pipe carries stdout, so whatever the upstream program wrote to stderr reaches the transcript unredacted while the tool reports both streams as one blob. Chaining past it with `;`, `&&` or `||` runs the rest of the line uncovered as well. Wrapping one of these costs a second redaction pass, which changes nothing because a token is not a value, and captures both streams.

## Agents

The guard is one program speaking each agent's contract. What varies is the tool that runs a command, the shape of the reply and where it is registered; what does not is that the command is rewritten to redact its own output. Which agents, and what enrolling each costs, is the table in the [README](../README.md). They are named with `--agent`, never detected.

opencode and Kilo Code have no hook that runs a program. A plugin in the agent's own process blocks a call by throwing and changes one by mutating its arguments, so it asks the guard and applies the answer:

```json
{"decision": "deny", "reason": "<what the model is told>"}
{"decision": "rewrite", "tool_input": {"command": "source .../wrap.sh '<command>'"}}
```

Nothing written is a call left alone, per the list above. Every other answer fails closed: a guard that cannot be run, a non-zero exit, an answer that is not JSON, a decision the plugin does not know. That covers version skew, so run `faramir init` before enrolling one of these: a binary too old to know `--host opencode` refuses every command in that project rather than running it unredacted.

Antigravity is declined, not pending. A deny list without redaction is the weaker half of this, and shipping it under the same name would say a project is covered when the thing that covers it is absent.

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

**A `redact` op is an oracle.** A guessed value comes back confirmed or not. Acceptable only on weighting: an accident does not guess, and an agent that is guessing has the fleet anyway. If that weighting changes, fix this first.

It is not rate-limited. Nothing short of removing the op closes the oracle, and a throttle bounds only a guessing attack the same caller need never mount: `list_secrets` and `run` are ops on this socket behind the same `allowed_group` check, so every managed value can be had by naming it. Bounding the slower path buys nothing while the faster one is open by design, and costs a lock on the path the wrapper takes once per Bash command. Every call is recorded, refused or not, so the visibility a limit would add comes from the audit log instead. A guess shorter than `[secrets] min_length` is not an oracle at all, every value below that length being refused at load and absent from the matcher.

Bring a limit back if `redact` ever becomes reachable by a caller that cannot reach `run`. There is no such caller today.

**A killed command loses its output.** Redaction happens after the command finishes, so a timeout or interrupt yields nothing where an unwrapped command would have shown partial output. The cost of buffering, which the persistent shell forces.
