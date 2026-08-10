# Design decisions and their costs

## What this defends

The [Prevented](../README.md#prevented) and [Not prevented](../README.md#not-prevented) tables are the boundary, including that the agent's own reach is not part of it. Two more things nobody should expect this to cover:

Not defended | Why
--- | ---
The fleet | The account Ansible connects as has passwordless sudo on every managed host. The operator's arrangement.
Personal credentials at rest | `.env`, `~/.npmrc` and the like are read by the tools that need them. Scope and rotation are the mitigations.

## The decisions

What was chosen, and what it cost. The sections after this one take up the choices that cost the most.

Decision | Choice | Rationale
--- | --- | ---
Isolation | Uid separation plus systemd hardening. No containers. | Network isolation is a non-goal, and it was the main thing containers made easy. A sandbox confines what a child sees; it is not a substitute for a uid that holds nothing.
How the roles are separated | `User=` in three units, all starting one binary. | The uid is what the kernel checks against `0400 faramir-keeper` and against a socket's group. Separate executables check nothing extra.
Filesystem isolation | None beyond file modes and `ProtectSystem=strict`. | A home the executor may not read is one the mode already refuses; one it may read, the agent can read directly.
Where commands run | The agent's working tree, directly. | A promotion gate buys an immutable snapshot and a commit sha, both properties against a deliberate agent, which is out of scope.
Who executes | The broker, as its own uid. | If the client execs, plaintext lives in a process the agent owns.
Who holds the key | A separate uid that executes nothing. | A key the broker can load is a key any brokered command can read.
Who forks the child | A third uid, given the PTY slave over `SCM_RIGHTS`. | Anything the forking uid can reach, the child can reach.
Command allowlist | None. | Any rule permitting an interpreter is reachable in one step through `bash`, which a usable policy must permit.
How a program gets values | `env_refs`, read from the environment. | The alternative is handing the program the master key.
Secrets at rest | sops plus age. | Encrypted YAML in the repo, per-key diffs, no network round trip.
Redaction | Custom, over the whole value set. | Off-the-shelf injectors mask only what they injected; a managed host can print a credential the broker never injected.
Agent interface | Unix socket exposed as MCP tools plus a CLI. | A distinct tool is more discoverable to a model than a documented convention.
Enforcement | Hook plus filesystem permissions. | Instructions to the agent are ergonomics, not a boundary.

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

A home is not mounted until its owner logs in, so the secrets are absent at boot and to cron. Absent is therefore never quietly tolerated: a file may be missing because it was never written or because the filesystem holding it is not mounted, and only the second is dangerous, so both are refused. `exec` is held to the same rule as `redact`, a brokered command's output being redacted against the same value set. The cost is a fresh install refusing every wrapped command until it has one file, loudly and with the reason; the rule and its one exception are stated with [the gate](configuration.md#the-install-gate-and-the-same-gate-at-startup).

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

**The wrapper needs a private `XDG_RUNTIME_DIR`, and refuses to run a command without one.** It captures a command's output before redacting it, so that file holds plaintext and belongs in a directory no other account can enter. `XDG_RUNTIME_DIR` is the only one a session is given; the alternative, `/dev/shm`, is 1777, where a name nothing has created yet is one another account can create first. A session that does not set it, which includes `sudo` and `cron`, gets a refusal on every Bash command rather than a capture whose contents nothing can answer for.

**The wrapper takes the caller's `EXIT` trap.** A command that runs `exit` ends the sourced shell at the `eval`, before the cleanup, leaving a capture file nothing has redacted yet; an `EXIT` trap is what bash still runs there, and on SIGINT, SIGTERM and SIGHUP with it. Being sourced, that trap is the caller's shell's, so the one it had is saved and put back after the files are removed. On the `exit` path ours runs and the caller's does not, bash keeping one handler per signal rather than chaining them. The trade is a handler that only matters to a shell exiting anyway, against unredacted output surviving in the runtime directory.

Two ways past it, both leaving a 0600 capture file in a directory only the operator can enter: `SIGKILL`, which runs no trap at all, and a command that installs an `EXIT` trap of its own, which replaces this one in the shell they share. Neither is reachable by accident, which is what the capture file is guarded against; a command that writes its own trap has chosen to.

**A `redact` op is an oracle.** A guessed value comes back confirmed or not. Acceptable only on weighting: an accident does not guess, and an agent that is guessing has the fleet anyway. If that weighting changes, fix this first.

It is not rate-limited. Nothing short of removing the op closes the oracle, and a throttle bounds only a guessing attack the same caller need never mount: `list_secrets` and `run` are ops on this socket behind the same `allowed_group` check, so every managed value can be had by naming it. Bounding the slower path buys nothing while the faster one is open by design, and costs a lock on the path the wrapper takes once per Bash command. Every call is recorded, refused or not, so the visibility a limit would add comes from the audit log instead. A guess shorter than `[secrets] min_length` is not an oracle at all, every value below that length being refused at load and absent from the matcher.

Bring a limit back if `redact` ever becomes reachable by a caller that cannot reach `run`. There is no such caller today.

## Elevating on the controller

How to install and run this is in [operating.md](operating.md#elevating-on-the-controller); this is why it is shaped the way it is. `--elevate` is a per-host, install-time decision (that section explains the choice); everything below is the reasoning behind the mechanism it installs.

**An approval is the same kind of oracle as `redact`, weighted the other way.** `--elevate` puts a question to a human, and a question a human can answer wrongly is a boundary made of attention. It survives the same weighting the `redact` op is held to, and for a different reason: this one is deny-by-default. Silence is a refusal, an unreachable answer channel is a refusal, and anything that is not `yes` is a refusal, so an oracle that is not answered grants nothing.

What makes the answer worth anything is that the prompt names the command. A human who approves an elevation they did not initiate has already lost — so the broker writes the question itself, from the argv it started, and refuses a request it cannot attribute to a running command rather than asking about "something". The prompt string `sudo` passes to the helper is dropped on the floor: it comes from the child, which is the side being asked about.

Three things follow from that, and each is the reason an easier design was not taken:

- **No time window.** `timestamp_timeout=0`, so sudo's own credential cache never decides this. A window in which approval is assumed is a window an agent can start a brokered command inside, riding an approval a human gave for something else. What an approval does cover is the brokered command it was shown for: one question per `faramir run`, spent on that run's sudos and gone when it exits. The scope is a named command rather than a stretch of time, which is the difference between the two, and the prompt says which one it is asking for.
- **Not the caller's terminal.** Passing stdin through so `--ask-become-pass` prompts where `faramir run` was typed is the fix that suggests itself first and the worst one available: the agent owns that process tree, so a password typed into it is a password the agent can read.
- **Not systemd-ask-password either**, which is the tool this looks like it should use. Asking through it means creating a file in `/run/systemd/ask-password`, `0755 root:root`, so a broker running as its own uid is refused and every request would be denied for want of anybody to ask. What that channel offers is a reply socket only root can write to, and `faramir approve` makes the same guarantee directly: `SO_PEERCRED` on the broker's own socket, uid 0 or nothing. A `notify_command` may still announce a question; it carries no answer.
- **Not a managed secret.** `--client-group` documents that the executor can request the same injection the agent can. Anything injectable is therefore agent-reachable, and a sudo password in the store is root for the asking.
- **Not a password at all**, which is what the other four were working around. A password is a bearer credential, so wherever it is kept, a command approved once can read it, keep it, and leave it for a later command that was not approved: same uid, shared `PrivateTmp`, shared working tree, `sudo -S`, root. Keeping it on tmpfs and minting it per boot narrows the window and does not close the class. So `sudo` is pointed at a PAM service of faramir's own, whose `auth` step execs a helper that asks the broker and whose exit status is the whole authentication. What satisfies `sudo` is a decision, and a decision cannot be carried because there is nothing to carry.

**How that stack fails matters more than how it works**, because two words decide whether it gates anything, and both were checked against a live host rather than argued from the manual:

- `requisite`, never `sufficient`. With `sufficient`, a helper that *refuses* is not fatal: the stack falls through to the `pam_permit` beneath it and every elevation is granted without asking anybody. Demonstrated -- one word, and the gate is gone. `faramir doctor` reads the file and fails on it.
- `seteuid`, because `pam_exec` otherwise runs the helper with the real uid, which under setuid `sudo` is the executor's own. The broker answers the `elevate` op to root alone, so the helper would be refused and nothing on the host could elevate: off rather than loose, but off. It also keeps the deciding process out of reach of the uid being decided about instead of resting on the kernel marking a setuid child non-dumpable, which it does today and is not a thing to build a boundary on.

Everything else fails closed by construction: an unreachable broker, an unknown token, a refusal and a timeout all exit non-zero, and nothing in the file authenticates except by reaching `pam_permit` past a `requisite` that succeeded. The service is faramir's own -- named by `pam_service=` in the sudoers entry -- so everyone else's `sudo` reads the stock `/etc/pam.d/sudo` and a mistake here can neither lock this host's operators out nor hand another account a free root. Removing the file falls back to `/etc/pam.d/other`, which on a stock host is a real password check; `doctor` fails if that fallback is a free pass.

**What the approval does not reach.** There are two ways an approval could reach past the one command it named, and they have different answers. The token not being *carriable* turns out to matter less than either.

The first is a *second, unapproved command* riding the approval. Every brokered command runs as `faramir-exec`; `/proc/<pid>/environ` is readable within a uid, so a concurrent run could read the approved run's token and `sudo` on it. Demonstrated on a live host before it was closed. The broker closes it by serialising: an elevation is approved only when its run is the sole brokered command in flight, and while the approval is live every other brokered command is refused `busy`. The two enforcement points are symmetric under one lock — registering a run blocks a new approval, a live approval blocks a new registration — so a live approval and any other registered run never coexist, and the window has no second process to do the stealing. It rests on no `faramir-exec` process outliving its run, and that is what the per-run cgroup buys: a brokered command is spawned into a cgroup of its own (clone3's `CLONE_INTO_CGROUP`, the unit granted `Delegate=`), and the whole cgroup is killed and drained when the run ends, so a `setsid` child that breaks out of the process group is reaped with it.

**The cgroup is the one reaper, and there is no fallback.** A process group is a strictly weaker grouping the same `setsid` escapes, so a run that cannot be confined is *refused* rather than reaped by process group — on every host, elevation or not. On an elevating host a straggler through the approval window is exactly the failure this closes; without elevation an unreaped `setsid` child is still a process outliving the run that spawned it, holding the working tree or a concurrency slot past its life. Neither is worth a silent degrade to the weaker mechanism, and supporting one would mean carrying the escapable path in production so a test or an old kernel could use it — the weaker-posture-that-still-looks-fine this whole exercise is against. So confinement needs cgroup v2, the unit granted `Delegate=`, and `cgroup.kill` (kernel ≥ 5.14); `init` renders `Delegate=` on the executor unit for every install, so a real host always confines, and a host that cannot (an old kernel, a container without delegation) refuses every brokered command until it is fixed rather than running one it cannot reap. `faramir doctor` fails a host whose executor unit lost the delegation, so the difference is never a mystery. (Older kernels and cgroup v1 are simply unsupported; the tests run under the same delegated cgroup a real install grants — see [the test workflow](../.github/workflows/test.yml).)

The second cannot be closed: the *approved command itself* persisting root. It spends its legitimate root once and installs a setuid-root binary, a `systemd` unit, a `cron` entry, a line in `sudoers` — none of which involves faramir again or expires when the token does. Demonstrated end to end: an approved run planted a setuid-root `bash` that returned root after the run had ended. Configuring a host and backdooring it are the same primitives, so no sandbox distinguishes them without an allowlist of exactly which files, which is not "run a playbook". This is not the token's failure — it is root's nature, and it would defeat a password, a PAM callback, or any other credential equally.

So the honest scope is "the command a human approves is trusted with permanent root on this host" — serialisation keeps every *other* command out of that trust, and nothing walls the approved command itself in. `--elevate` belongs where that command is operator-owned and read-only to brokered commands (so the agent cannot author what root runs), on a host where the occasional `busy` a serialised approval imposes is acceptable. The audit log shows the elevation; it does not show the persistence a hostile approved command installs, unless someone looks. Detection, not prevention. The class serialisation ends is the bystander's; the class that remains is the trusted command's own supply chain, the same risk as running it under `sudo` by hand — which is the boundary of the whole project, the next paragraph.

The uid stays the bound. `faramir-exec` gains the ability to *ask*, not the ability to elevate, and the ask is answered by an account the agent cannot become. What that leaves, and it is worth being plain about: an agent that can already reach root can answer, and can also read the age key, so elevation adds nothing to its reach; an operator with `NOPASSWD` sudo or a warm sudo timestamp has already handed it that account; and a watcher left in a terminal the agent can type into is a prompt the agent can answer. The first is the boundary of this whole project, and the other two are operational. A `NOPASSWD` entry would remove all of that in one line, so `faramir doctor` checks for one whether or not this host was installed with `--elevate`.

**A killed command loses its output.** Redaction happens after the command finishes, so a timeout or interrupt yields nothing where an unwrapped command would have shown partial output. The cost of buffering, which the persistent shell forces.
