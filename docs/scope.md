# Scope

> Implemented.

## What this defends

**Keeping sops-managed values out of the model's context, wherever the agent
runs.** That is the whole of it. Three things it explicitly does not defend:

- **The agent's reach.** Confining what a coding agent can touch is a means, and
  only where it is free. It is not the goal.
- **The fleet.** The account Ansible connects as has passwordless sudo on every
  managed host, so anything that can run a brokered playbook can read anything
  on those hosts. That is not a gap to close; it is the operator's arrangement,
  and no design here changes it.
- **Personal credentials at rest.** `.env` files, `~/.npmrc` and the like are
  read directly by the tools that need them. Encrypting them breaks those tools.
  Scope and rotation are the mitigations there, not access control.

**Accidental disclosure over deliberate exfiltration.** Because the fleet is
already reachable, an agent that is *trying* to leak a credential cannot be
stopped: it runs a playbook, reads the value on a managed host, and encodes it
however it likes. What can be stopped is a credential landing in a transcript
because a command printed it. Every decision below is weighed that way, and
machinery whose only benefit is against a determined agent is not worth its
cost.

## One mode

The coding agent runs as the operator. There is no account of its own, and no
boundary around the agent process.

That is not a concession made for convenience; it is what the work requires. An
agent that maintains the operator's repositories needs their checkouts, their
`gh` credential and their commit identity, and a separate uid can reach none of
those. Every route to giving it access ends up handing over the operator's files
by another name: relocating the trees, punching group traversal through a home,
copying credentials into a second account. The last is the worst, because it
turns one credential into two.

The same holds for unattended runs, which is the case a separate uid looked most
justified for. An unattended maintainer with permissions skipped still has to
push commits and call GitHub as the operator, so confining it means copying
exactly the credentials that make it dangerous.

What the uid boundary was protecting is not lost, because it was never what
protected the secrets:

| | Held by | Reachable by the operator |
| --- | --- | --- |
| The age key | `faramir-keeper`, `0400` | no |
| Decrypted values | `faramir-broker`, in memory | no, except through the broker |
| The fleet SSH key | `faramir-broker`, `0600` | no |
| The audit log | `faramir-broker`, `0600` | no |
| Brokered command execution | `faramir-exec` | it cannot read the operator's home |

What is given up is a boundary around the agent *process*: it can read the
operator's own files, and an unattended run with permissions skipped can rewrite
their repositories. Bounding that is a credential-scope problem, not a uid
problem: a `gh` token limited to the repositories the maintainer maintains, and
branch protection so it cannot force-push. The README has always listed
filesystem blast radius as out of scope, and it still is.

**The working tree has to be reachable by two uids that are not the
operator's.** The keeper decrypts the sops files there and the executor runs
brokered commands there. A home is `0700`, so a tree inside one is unreachable
until those uids are given traversal; a tree outside the homes needs nothing.

Both work. Outside (`/srv/faramir/worktree`, the default) is the simpler one.
Inside the operator's own checkout is the one that means nothing moves, and
phase 1 grants it with an ACL naming exactly `faramir-keeper` and `faramir-exec`
on every component from the home down. Not `chmod o+x`, which would hand
traversal to every account on the machine; the ACL leaves `other` at nothing.

An ACL is a permission, not a mount: it holds nothing open, so an encrypted home
still unmounts at logout. What does hold one open is a brokered command that
happens to be running at the time. Two costs come with the inside-the-home
choice, both from the mount's lifecycle rather than from permissions: between
boot and the operator's first login the tree does not exist, so the broker comes
up with an empty value set and brokered commands fail until a request after
login reloads it; and a logout during a brokered run cannot unmount.

## Three layers

**1. No plaintext where the agent will trip over it.** Already true for the
values this defends: they are sops ciphertext in the tree, and the age key is
`0400` under a uid that executes nothing but sops. This layer is not extended to
personal credentials, per the scope above.

**2. Leak-prone commands go through the broker.** The commands that print
credentials by accident are a short, predictable list: `ansible-playbook -vvv`,
a `debug: var=` task, `sops -d`, `env`, `journalctl -u`, `docker inspect`. The
`PreToolUse` hook denies those directly and names `faramir run` instead, which
injects values without putting them in `argv`, runs the child on a PTY, redacts
the whole value set out of its output, and writes the audit record. The
mechanism exists; what changes is the deny list, and that the hook is installed
into the account the agent actually runs as.

A denial the agent cannot act on gets worked around, so every entry states the
alternative rather than only refusing.

**3. Redact what still gets through.** A `redact` op on the broker socket: send
text, receive it back with every known value replaced by its `«SECRET:ref»`
token. The caller never receives the value set. The broker holds it and answers
questions about it, which is the same shape as `list_secrets` returning names
and never values.

That is what covers everything the agent runs itself, rather than only what it
routed through the broker.

## What it took

- **`redact` on the broker socket.** The redactor already existed and was
  already built from the whole value set ([docs/redaction.md](redaction.md));
  this exposes it to a caller that holds no values. `faramir redact` is the
  client, as a filter over stdin or as a wrapper around a command.
- **A guard that rewrites rather than only refuses**, installed by phase 4 into
  the account the agent runs as.

The installer role that provisions the agent account lives in a separate
repository. The parts of it that exist to give that account access to the
operator's checkouts are deleted by this design rather than fixed: operator mode
covers that work, and the account does not need them.

## What this gives up

**There is no kernel boundary around the agent process.** It is hooks and the
deny list. That is the trade for an agent that can do the operator's work, and
the boundaries that remain are the ones around the secrets rather than around
the agent: the age key, the decrypted values, the fleet SSH key and the audit
log are all held by uids the operator cannot read.

**A `redact` op is an oracle.** Ask it about a guessed value and the answer says
whether the guess was right. There is nothing bounding that: the op takes no
concurrency slot, writes no audit record, and the broker has no rate limit, so
guessing is neither slowed nor visible. What makes it acceptable is the
weighting, not a mitigation: an accident does not guess, and an agent that is
guessing has the fleet anyway. If that weighting ever changes, this is the first
thing to fix.

**A command that is killed loses its output.** Output is redacted after the
command finishes, so a command stopped by the tool's timeout or by an interrupt
never reaches the redactor: the caller gets nothing, where an unwrapped command
would have shown what it had printed so far, and the temporary file holding the
unredacted text is left behind until the tmpfs is cleared. That is the cost of
buffering, and buffering is what the persistent shell forces.

**The invariant changes.** It is no longer that a session can reach no secret.
It is: *no sops-managed value reaches the model except as a token, in either
mode, and nothing a session can read decrypts one.* That is still testable, and
the verification matrix should be rewritten around it.

## How the rewrite works

A `PreToolUse` hook cannot rewrite a tool's *result*, but it can rewrite the
tool's *input*, and for a shell command that is enough. The guard replaces
`<command>` with one simple command:

```bash
source /usr/local/libexec/faramir/wrap.sh '<command>'
```

[agent/hooks/wrap.sh](../agent/hooks/wrap.sh) creates a `0600` file on a tmpfs,
runs the command with both streams redirected into it, reads it back through
`faramir redact`, removes it, and restores the command's own exit status.

The shape is decided entirely by one constraint: **the agent's shell persists
between tool calls.** A `cd` or an `export` in one command has to still be in
effect for the next one, and that rules out the two obvious wrappers.

| Wrapper | State | Output | Allow-listable |
| --- | --- | --- | --- |
| `faramir redact -- bash -lc '<cmd>'` | lost, runs in a grandchild | fine | yes |
| `{ <cmd>; } 2>&1 \| faramir redact` | lost, a pipeline element is a subshell | fine | no |
| `{ <cmd>; } > >(faramir redact) 2>&1` | kept | races: the shell moves on while the redactor is still writing, and the rest is lost | no |
| an inline `{ <cmd>; } >"$f" 2>&1; …` | kept | complete | no |
| `source wrap.sh '<cmd>'` | kept | complete | no |

Sourcing runs the command in the caller's own shell, and `eval` re-parses it
there, so everything it sets stays set. Redacting the file afterwards rather
than through a live pipe is what removes the race, and it costs nothing the
agent can observe: the tool returns a command's output in one piece anyway.

The last column is why the shape is a sourced script rather than the inline
form: neither can be allow-listed, so the hook has to decide (below), and given
that, the sourced version is the one that is short, testable on its own, and
handles an incomplete command by failing inside `eval` rather than taking the
wrapper's syntax down with it.

The file is `0600` from `mktemp`, and `/dev/shm` is tried before falling back to
`mktemp`'s own default, so the unredacted text is in memory rather than on a
disk wherever a tmpfs is available. It is removed as soon as it has been read.
The leading `:;` keeps a comment-only command from forming an empty group, and
the newline before the closing brace keeps a trailing `# comment` from
swallowing the redirection.

Every failure falls back to running the command and showing its output, never to
running nothing or showing nothing: `${__frf:-/dev/stdout}` covers a temp file
that could not be created, and `|| cat` covers a `faramir` that cannot redact,
which is what an install one version behind looks like. Without the second one,
an out-of-date client turns every command into silent success.

Four kinds of command are left alone rather than rewritten, because buffering or
appending would change what they do: one already under the redactor; a
`BashOutput` read; a backgrounded or `run_in_background` command, whose output
is wanted while it runs; and a command whose last line ends in `\`, `&&`, `||`
or `|`, where the appended newline would be swallowed and the group left
unterminated.

**For Bash, the deny list replaces the permission prompt.** That is forced, not
chosen: a rewritten command cannot be allow-listed by any rule. The matcher
refuses an allow rule against a compound statement (`Contains
compound_statement`) and refuses one naming `source` or `eval` (`'source'
evaluates arguments as shell code`), and a wrapper that redacts output has to be
one of those. A rewrite that claims nothing therefore makes every command
prompt, with no rule an operator can write to stop it.

So the hook decides, after the deny list has run: a forbidden command is still
refused, and everything else is approved here rather than by a rule the operator
wrote. What this gives up is granular Bash permissions; what it keeps is the
deny list, and every other tool's permissions are untouched.
`FARAMIR_WRAP_DECISION=ask` restores the prompt for an operator who would rather
answer one per command.

Rewriting rather than denying is the point. A deny list only covers what
somebody thought to name, and the command that leaks a credential is usually one
nobody would have named. The list stays for what must not run at all; everything
else runs under the redactor.

Three cases the rewrite leaves alone: a command already under `faramir redact`,
so the wrapper is idempotent; `BashOutput`, which reads a running command's
buffer rather than starting one; and a denied command, which is refused instead.

When the broker cannot be reached, the wrapper prints a warning and passes the
output through unredacted rather than failing. A wrapper that breaks every
command whenever the broker is down is a wrapper that gets removed, and a
removed wrapper redacts nothing at all.
