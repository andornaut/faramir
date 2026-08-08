# Scope

## What this defends

**Keeping sops-managed values out of the model's context, in the projects
enrolled to do it.** That is the whole of it.

Enrolment is per project, because the coverage is not free: the hook rewrites
every Bash command so the output can be redacted, and a rewritten command
matches no permission rule, so Bash is auto-approved wherever the hook runs.
That is worth paying where managed credentials are in play and is not worth
paying everywhere.

The value set, though, is global: the broker holds every managed secret
regardless of which project asked. So a command in a project that was never
enrolled can still print a managed value, and nothing will catch it. Enrol
anything that touches these credentials, and treat an unenrolled project as
having no redaction rather than as being safe.

Three further things it does not defend:

- **The agent's reach.** Confining what a coding agent can touch is a means, and
  only where it is free. It is not the goal.
- **The fleet.** The account Ansible connects as has passwordless sudo on every
  managed host, so anything that can run a brokered playbook can read anything
  on those hosts. That is the operator's arrangement, and no design here
  changes it.
- **Personal credentials at rest.** `.env` files, `~/.npmrc` and the like are
  read directly by the tools that need them, and encrypting them breaks those
  tools. Scope and rotation are the mitigations there, not access control.

**Accidental disclosure over deliberate exfiltration.** Because the fleet is
already reachable, an agent that is *trying* to leak a credential cannot be
stopped: it runs a playbook, reads the value on a managed host, and encodes it
however it likes. What can be stopped is a credential landing in a transcript
because a command printed it. Machinery whose only benefit is against a
determined agent is not worth its cost.

## One mode

The coding agent runs as the operator. There is no account of its own, and no
boundary around the agent process.

That is what the work requires. An agent maintaining the operator's
repositories needs their checkouts, their `gh` credential and their commit
identity, and a separate uid can reach none of those. Every route to granting
it access hands over the operator's files by another name: relocating the
trees, punching group traversal through a home, or copying credentials into a
second account, which turns one credential into two. Unattended runs are no
different: an unattended maintainer still has to push commits and call GitHub
as the operator.

The boundaries that matter are around the secrets, not around the agent:

| Held by | What | Reachable by the operator |
| --- | --- | --- |
| `faramir-keeper` | the age key | no |
| `faramir-broker` | decrypted values, the fleet SSH key, the audit log | no, except through the broker |
| `faramir-exec` | nothing; brokered commands run here | it cannot read the operator's home |

What is given up is a boundary around the agent *process*: it can read the
operator's own files, and an unattended run with permissions skipped can
rewrite their repositories. Bounding that is a credential-scope problem, not a
uid problem: a `gh` token limited to the repositories it maintains, and branch
protection so it cannot force-push. Filesystem blast radius is out of scope.

## Secrets under /etc, not in a tree

The managed sops files live in `/etc/faramir/secrets`, `2770 root:dev`. They are
configuration an operator authors and the daemons read at startup, which is what
`/etc` is for, and the location decides more than convention:

- **A home is not mounted until its owner logs in.** A value set that depends on
  one is empty at boot, so the broker comes up redacting nothing. That is a
  security failure rather than an outage, and it is silent.
- **Unattended jobs do not have a session.** Anything running from cron as root
  cannot reach a path inside an encrypted home, whatever its mode says.
- **The keeper stops needing a home at all**, so its unit sets
  `ProtectHome=true`. The uid holding the age key is the one worth taking `/home`
  away from outright.

The operator still edits them in place with `sops`, through the group, without
sudo. `.sops.yaml` sits in the same directory because sops resolves creation
rules by walking up from the file it is encrypting, so a rule that is not an
ancestor is a rule it never finds.

## Where brokered commands run

A brokered command runs where its caller was, so `faramir-exec` is the only
service uid that needs to reach a working tree. A home is `0700`, so a tree
inside one is unreachable until that uid is granted traversal; a tree outside
the homes needs nothing.

Both work. Phase 1 grants the inside-a-home case with an ACL naming that one
uid on every component from the home down. Not `chmod o+x`, which would hand
traversal to every account on the machine; the ACL leaves `other` at nothing.

An ACL is a permission, not a mount: it holds nothing open, so an encrypted home
still unmounts at logout. What holds one open is a brokered command running at
the time, which is the one remaining cost of working inside an encrypted home.

## Three layers

**1. No plaintext where the agent will trip over it.** The defended values are
sops ciphertext in the tree, and the age key is `0400` under a uid that
executes nothing but sops. This layer does not extend to personal credentials,
per the scope above.

**2. Leak-prone commands are refused outright.** The commands that put a
credential in the context window are a short, predictable list, and
[agent/hooks/deny-patterns.txt](../agent/hooks/deny-patterns.txt) is it:
direct decryption (`ansible-vault view`, `sops -d`, `age -d`), wholesale
environment dumps (`printenv`, `env`, `/proc/<pid>/environ`), reading key
material or encrypted blobs (`cat` and friends against a vault, a `.env`, an
age key or an SSH key), and reaching the broker's own state (`/var/log/faramir`,
`journalctl`, `sudo` as a service account). The `PreToolUse` hook denies those
and names `faramir run` instead. A denial the agent cannot act on gets worked
around, so the refusal states the alternative.

This is ergonomics with teeth rather than the boundary: the agent's uid cannot
read the key material either way.

**3. Redact what still gets through.** The `redact` op takes text and returns
it with every known value replaced by its token. The caller never receives the
value set; the broker holds it and answers questions about it, the same shape
as `list_secrets` returning names and never values. This is what covers
everything the agent runs itself, rather than only what it routed through the
broker.

## How the rewrite works

A `PreToolUse` hook cannot rewrite a tool's *result*, but it can rewrite the
tool's *input*, and for a shell command that is enough. The guard replaces
`<command>` with:

```bash
source /usr/local/libexec/faramir/wrap.sh '<command>'
```

[agent/hooks/wrap.sh](../agent/hooks/wrap.sh) creates a `0600` file on a tmpfs,
runs the command with both streams redirected into it, reads it back through
`faramir redact`, removes it, and restores the command's own exit status.

The shape is decided by one constraint: **the agent's shell persists between
tool calls.** A `cd` or an `export` in one command has to still be in effect
for the next, which rules out the obvious wrappers:

| Wrapper | State | Output | Allow-listable |
| --- | --- | --- | --- |
| `faramir redact -- bash -lc '<cmd>'` | lost, runs in a grandchild | fine | yes |
| `{ <cmd>; } 2>&1 \| faramir redact` | lost, a pipeline element is a subshell | fine | no |
| `{ <cmd>; } > >(faramir redact) 2>&1` | kept | races: the shell moves on while the redactor is still writing | no |
| an inline `{ <cmd>; } >"$f" 2>&1; …` | kept | complete | no |
| `source wrap.sh '<cmd>'` | kept | complete | no |

Sourcing runs the command in the caller's own shell and `eval` re-parses it
there, so everything it sets stays set. Redacting the file afterwards rather
than through a live pipe removes the race at no observable cost, since the tool
returns a command's output in one piece anyway. Of the two forms that keep
state, the sourced script is short, testable on its own, and handles an
incomplete command by failing inside `eval` rather than taking the wrapper's
syntax down with it.

The temp file is `0600` from `mktemp`, preferring `$XDG_RUNTIME_DIR` and then
`/dev/shm` so the unredacted text stays in memory rather than on a disk, and
falling back to `mktemp`'s own default. It is removed as soon as it is read. The
leading `:;` keeps a comment-only command from forming an empty group, and the
newline before the closing brace keeps a trailing `# comment` from swallowing
the redirection.

Every failure falls back to running the command and showing its output, never
to running nothing or showing nothing: a temp file that could not be created
falls back to stdout, and a `faramir` that cannot redact falls back to `cat`.
Without the second, a client one version behind turns every command into silent
success. When the broker cannot be reached the wrapper warns and passes output
through unredacted, because a wrapper that breaks every command whenever the
broker is down gets removed, and a removed wrapper redacts nothing.

Commands left alone rather than rewritten, because buffering or appending would
change what they do:

- one already running under the redactor, so the wrapper is idempotent
- a `BashOutput` read, which reads a running command's buffer
- a backgrounded or `run_in_background` command, whose output is wanted while
  it runs
- one whose last line ends in `\`, `&&`, `||` or `|`, where the appended
  newline would be swallowed and the group left unterminated
- a denied command, which is refused instead

## What this gives up

**There is no kernel boundary around the agent process.** It is hooks and the
deny list, which is the trade for an agent that can do the operator's work.

**For Bash, the deny list replaces the permission prompt.** That is forced, not
chosen: permission matching runs against the rewritten command, so a rule keyed
on the program name (`Bash(rm:*)`) no longer matches, and the wrapper itself
cannot be allow-listed either. The hook therefore approves everything the deny
list did not refuse. Granular Bash permissions are lost in the enrolled
project; every other tool's permissions are untouched, there and everywhere.

Returning `allow` is not what removes those rules. The rewrite already stopped
them matching; the decision only makes that explicit rather than leaving rules
that appear active and silently never fire.

Note what the shipped deny list is for. It names credential disclosure -- vault
readers, environment dumps, decryptors, and encoders pointed at key material --
and nothing destructive. Enrolling a project therefore drops whatever Bash
prompting stood between the agent and `rm -rf`, and puts nothing in its place on
that axis. Prompts on `Write` and `Edit` do not cover it, since Bash can write
and delete without them.

`FARAMIR_WRAP_DECISION=ask` restores the prompt, on every command including
`ls`: each rewritten command is a distinct string that no rule can pre-approve.
It is an escape hatch, not a mode.

Rewriting rather than denying is the point. A deny list only covers what
somebody thought to name, and the command that leaks a credential is usually
one nobody would have named. The list stays for what must not run at all;
everything else runs under the redactor.

**A `redact` op is an oracle.** Ask it about a guessed value and the answer
says whether the guess was right. Nothing bounds that: the op takes no
concurrency slot and the broker has no rate limit, so guessing is neither
slowed nor visible. What makes it acceptable is the weighting rather than a
mitigation: an accident does not guess, and an agent that is guessing has the
fleet anyway. If that weighting changes, this is the first thing to fix.

**A command that is killed loses its output.** Output is redacted after the
command finishes, so a command stopped by a timeout or an interrupt never
reaches the redactor: the caller gets nothing where an unwrapped command would
have shown what it had printed so far, and the temp file holding the
unredacted text is left until the tmpfs is cleared. That is the cost of
buffering, and buffering is what the persistent shell forces.

**The invariant:** no sops-managed value reaches the model except as a token,
and nothing a session can read decrypts one.
