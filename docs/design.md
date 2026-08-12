# Design decisions and their costs

## What this defends

The [Prevented](../README.md#prevented) and [Not prevented](../README.md#not-prevented) tables are the boundary, including that the agent's own reach is not part of it. Two more things this does not cover:

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
Where commands run | The agent's working tree, directly. | A promotion gate provides an immutable snapshot and a commit sha, both properties against a deliberate agent, which is out of scope.
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

The broker is outside the secrets group deliberately: it holds every decrypted value already, so read on the ciphertext gains it nothing. It asks the keeper when a file changed instead, over `get_state`, which touches neither the key nor sops.

`.sops.yaml` sits in the config directory above the secrets directory rather than in it, for two reasons: sops resolves that file from the current working directory upward, and a parent is found from the secrets directory as well as from itself; and the secrets directory is a drop zone that `[secrets] patterns` globs, `filepath.Glob` matches dotfiles, so a rule file among the ciphertext is one glob spelling away from being loaded as a managed file that does not decrypt.

`--config-dir` moves the secrets off `/etc`, along with the config and the age key: one path rather than three, so the key cannot be left on an unencrypted disk while the secrets it opens sit in an encrypted home. What the units can see decides where, not the modes:

Placement | Result
--- | ---
`/etc/faramir` | The default. Present at boot, readable by three uids, owned by none of them.
`/tmp`, `/var/tmp` | Installs, then finds nothing: `PrivateTmp=true` gives each unit its own, so the daemons open an empty one and fail to load.
inside a home | Works, at the cost below. `init` drops the keeper's `ProtectHome=` to `tmpfs` and binds that one directory back.

A home is not mounted until its owner logs in, so the secrets are absent at boot and to cron. Absent is therefore never quietly tolerated: a file may be missing because it was never written or because the filesystem holding it is not mounted, and only the second is dangerous, so both are refused — `exec` held to the same rule as `redact`, a brokered command's output being redacted against the same value set. The cost is a fresh install refusing every wrapped command until it has one file, loudly and with the reason; the rule and its one exception are stated with [the gate](configuration.md#the-install-gate-and-the-same-gate-at-startup). Checked per request rather than once at startup, which is what makes this placement survivable: `--check` runs from `init` and `doctor`, neither of which is around at boot. `init` also refuses to write into an unmounted encrypted home, which lands in the backing directory and is shadowed the moment the home mounts.

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

`faramir redact` does the same, in both its shapes and for the same reason: a chunk it cannot redact is never written, nothing after it is written, and the exit status is non-zero, which is what the wrapper reads when it withholds. What is *not* withheld is the part of a stream that was already redacted, on a broker that dies part way through: those chunks came back covered, so holding them protects nothing, and buffering the whole stream to be able to would cost an unbounded buffer for a guarantee already met. A failure therefore truncates the output rather than emptying it, and on the usual failure — a broker that is not running, which fails on the first chunk — those are the same thing.

Left alone rather than rewritten, because buffering would change what they do:

- one this rewrite already produced, so the wrapper is idempotent
- a read of a running command's output, such as Claude Code's `BashOutput`, and every tool that is not the shell
- a backgrounded command, whose output is wanted while it runs: a trailing `&`, or the tool's own background flag
- an empty command
- a denied command, which is refused instead

An incomplete command is *not* on that list. One ending in `\`, `&&`, `||` or `;` is wrapped like any other and fails inside the wrapper's `eval`, which re-parses it in isolation, so it fails the way it would have failed unwrapped rather than breaking the wrapper's own syntax.

The first is a prefix test against the whole command, and it is the only thing that counts as already covered. Two forms that look covered and are not:

- **A command that merely names the wrap script.** The path is in this project's documentation and in the wrapper itself, so a match anywhere in the line would leave `echo /usr/local/libexec/faramir/wrap.sh; cat secrets` unrewritten.
- **A command piping into the redactor.** A pipe carries stdout, so whatever the upstream program wrote to stderr reaches the transcript unredacted, and chaining past it with `;`, `&&` or `||` runs the rest of the line uncovered as well. Wrapping one of these costs a second redaction pass, which changes nothing because a token is not a value, and captures both streams.

## Agents

The guard is one program speaking each agent's contract. What varies is the tool that runs a command, the shape of the reply and where it is registered; what does not is that the command is rewritten to redact its own output. Which agents, and what enrolling each costs, is the table in the [README](../README.md).

`--agent` defaults to `auto`, which configures the agents already there and nothing else: `init` asks that of the operator's home, `init-project` of the tree, and they are not the same paths — opencode keeps `opencode.json` beside a project and `.config/opencode` under a home. Naming one configures it regardless, which is how a tree is set up for an agent before it is installed. Detection only ever adds, so the two need no rule about which wins.

The paths those rules refuse are written once, in [internal/install/protectedpaths.go](../internal/install/protectedpaths.go), and rendered into each agent's own spelling. Four agents held a copy before, in four spellings, and they had already drifted: one refused writing an SSH private key while the others refused only reading one, and a fifth arrived with no list at all. A rule that covers nothing looks exactly like a rule that covers everything, so the drift is silent — one of Gemini's did cover nothing, for want of a backslash. pi has no rule file to write, so its rules are compiled into the extension and applied by shape, a file tool whose name it does not know still carrying a path.

opencode and Kilo Code have no hook that runs a program. A plugin in the agent's own process blocks a call by throwing and changes one by mutating its arguments, so it asks the guard and applies the answer:

```json
{"decision": "deny", "reason": "<what the model is told>"}
{"decision": "rewrite", "tool_input": {"command": "source .../wrap.sh '<command>'"}}
```

Nothing written is a call left alone, per the list above. Every other answer fails closed: a guard that cannot be run, a non-zero exit, an answer that is not JSON, a decision the plugin does not know. That covers version skew, so run `faramir init` before enrolling one of these: a binary too old to know the agent refuses every command in that project rather than running it unredacted.

Antigravity is declined, not pending. A deny list without redaction is the weaker half of this, and shipping it under the same name would say a project is covered when the thing that covers it is absent.

## What this gives up

**No kernel boundary around the agent process.** Hooks and the deny list, which is the trade for an agent that can do the operator's work.

**For Bash on Claude Code, the deny list replaces the permission prompt.** Matching runs against the rewritten command, so a rule keyed on the program name no longer fires, and the wrapper cannot be allow-listed either. There is no `ask` to return instead: it would prompt on every command including `ls`, show the rewritten text rather than what was typed, and strand an unattended run on the first command.

**The shipped deny list names credential disclosure and nothing destructive.** Enrolling drops whatever Bash prompting stood between the agent and `rm -rf` and puts nothing in its place. Prompts on `Write` and `Edit` do not cover it, Bash writing and deleting without them.

Hooks fire in every Claude Code permission mode and a `deny` is enforced in each, `--dangerously-skip-permissions` included, so what enrolment costs depends on the mode:

Mode | Cost
--- | ---
`default` | Bash would have prompted and now does not. This is what the warning is about.
`acceptEdits` | Auto-accepts `Write` and `Edit`, leaves Bash prompting. Same cost as default, and the mode that looks like it should exempt a project and does not.
`bypassPermissions` | Bash never prompted, so approving it removes nothing. Enrolment is purely additive.

Rewriting rather than denying is the point: a deny list covers what somebody thought to name, and the command that leaks a credential is usually one nobody would have.

**The wrapper needs a private `XDG_RUNTIME_DIR`, and refuses to run a command without one.** It captures a command's output before redacting it, so that file holds plaintext and belongs in a directory no other account can enter. `XDG_RUNTIME_DIR` is the only one a session is given; the alternative, `/dev/shm`, is 1777, where a name nothing has created yet is one another account can create first. A session that does not set it, which includes `sudo` and `cron`, gets a refusal on every Bash command.

**The wrapper takes the caller's `EXIT` trap.** A command that runs `exit` ends the sourced shell at the `eval`, before the cleanup, leaving a capture file nothing has redacted yet; an `EXIT` trap is what bash still runs there. Being sourced, that trap is the caller's shell's, so the one it had is saved and put back after the files are removed; on the `exit` path ours runs and the caller's does not, bash keeping one handler per signal rather than chaining them. Two ways past it, both leaving a `0600` capture file in a directory only the operator can enter: `SIGKILL`, which runs no trap at all, and a command that installs an `EXIT` trap of its own. Neither is reachable by accident, which is what the capture file is guarded against.

**A `redact` op is an oracle.** A guessed value comes back confirmed or not. Acceptable only on weighting: an accident does not guess, and an agent that is guessing has the fleet anyway. If that weighting changes, fix this first.

It is not rate-limited. Nothing short of removing the op closes the oracle, and a throttle bounds only a guessing attack the same caller need never mount: `list_secrets` and `run` are ops on this socket behind the same `allowed_group` check, so every managed value can be had by naming it. Every call is recorded, refused or not, so the visibility a limit would add comes from the audit log instead. A guess shorter than `[secrets] min_length` is not an oracle at all, every value below that length being absent from the matcher. Bring a limit back if `redact` ever becomes reachable by a caller that cannot reach `run`; there is no such caller today.

## Allowing sudo on the controller

How to install and run this is in [operating.md](operating.md#allowing-sudo-on-the-controller); this is the reasoning behind the mechanism it installs.

**An approval is the same kind of oracle as `redact`, weighted the other way.** `--allow-sudo` puts a question to a human, and a question a human can answer wrongly is a boundary made of attention. It survives that weighting because it is deny-by-default: silence is a refusal, an unreachable answer channel is a refusal, and anything that is not `yes` is a refusal, so an oracle that is not answered grants nothing.

What makes the answer worth anything is that the prompt names the command. An approval a human cannot attribute to a command they initiated is worthless, so the broker writes the question itself, from the argv it started, and refuses a request it cannot attribute to a running command. The prompt string `sudo` passes to the helper is ignored: it comes from the child, which is the side being asked about.

**Naming the command means rendering it, not printing it.** The argv is the caller's and the question is printed to a terminal, which obeys what it is sent. Most of that is already gone through the redactor, which strips CSI (colour included), OSC and the C0 controls. Two things survive it, and either is enough: a bare `\r` returns the cursor, so the rest of the line overwrites what came before it, and `ESC` followed by a byte outside `@-Z` and `\-_` matches no pattern there — including `ESC c`, a full terminal reset that on many emulators takes the scrollback with it. So every caller-chosen part of a question is quoted the moment it holds anything but printable text, ordinary arguments are left bare (a prompt full of quotation marks is one that is read less carefully), and the command is bounded, the audit record keeping the whole of it.

The same rendering covers `faramir logs`, the other place this text reaches a root terminal; [internal/termsafe](../internal/termsafe/termsafe.go) holds the rule for both. Recorded output is escaped rather than quoted and is never bounded, being the text an operator came to read. The prompt also names what argv[0] *resolved to* when that is not what argv[0] says: a relative program resolves against the request's cwd, which is the agent's working tree, so `bin/ansible-playbook` can be a file the agent wrote.

Five things follow, and each is the reason an easier design was not taken:

- **No time window.** `timestamp_timeout=0`, so sudo's own credential cache never decides this. A window in which approval is assumed is a window an agent can start a brokered command inside, riding an approval a human gave for something else. An approval covers the brokered command it was shown for: one question per `faramir run`, spent on that run's sudos and gone when it exits.
- **Not the caller's terminal.** Passing stdin through so `--ask-become-pass` prompts where `faramir run` was typed is the fix that suggests itself first and the worst one available: the agent owns that process tree, so a password typed into it is a password the agent can read.
- **Not systemd-ask-password either**, which is the tool this looks like it should use. Asking through it means creating a file in `/run/systemd/ask-password`, `0755 root:root`, so a broker running as its own uid is refused and every request would be denied for want of anybody to ask. What that channel offers is a reply socket only root can write to, and the approval commands make the same guarantee directly: `SO_PEERCRED` on the broker's own socket, uid 0 or nothing.
- **Not a managed secret.** `--client-group` documents that the executor can request the same injection the agent can. Anything injectable is therefore agent-reachable, and a sudo password in the store is root for the asking.
- **Not a password at all**, which is what the other four were working around. A password is a bearer credential, so wherever it is kept, a command approved once can read it, keep it, and leave it for a later command that was not approved: same uid, shared `PrivateTmp`, shared working tree, `sudo -S`, root. So `sudo` is pointed at a PAM service of faramir's own, whose `auth` step execs a helper that asks the broker and whose exit status is the whole authentication. What satisfies `sudo` is a decision, and a decision cannot be carried because there is nothing to carry.

**How that stack fails matters more than how it works**, because two words decide whether it gates anything:

- `requisite`, never `sufficient`. With `sufficient`, a helper that *refuses* is not fatal: the stack falls through to the `pam_permit` beneath it and every approval is granted without asking anybody. `faramir doctor` reads the file and fails on it.
- `seteuid`, because `pam_exec` otherwise runs the helper with the real uid, which under setuid `sudo` is the executor's own. The broker answers `ask_approval` to root alone, so the helper would be refused and nothing on the host could sudo: off rather than loose, but off. It also keeps the deciding process out of reach of the uid being decided about.

Everything else fails closed by construction: an unreachable broker, an unknown token, a refusal and a timeout all exit non-zero, and nothing in the file authenticates except by reaching `pam_permit` past a `requisite` that succeeded. The service is faramir's own, named by `pam_service=` in the sudoers entry, so everyone else's `sudo` reads the stock `/etc/pam.d/sudo` and a mistake here can neither lock this host's operators out nor hand another account a free root. Removing the file falls back to `/etc/pam.d/other`, which on a stock host is a real password check; `doctor` fails if that fallback is a free pass.

**What the approval does not reach.** There are two ways an approval could reach past the one command it named, and they have different answers.

The first is a *second, unapproved command* riding the approval. Every brokered command runs as `faramir-exec`, and `/proc/<pid>/environ` is readable within a uid, so a concurrent run could read the approved run's token and `sudo` on it — the token is uid-scoped rather than secret, and a process that reads it forges nothing. **Any live `faramir-exec` process during an approved window is root.**

The broker closes it by serialising: an approval is approved only when its run is the sole brokered command in flight, and while the approval is live every other brokered command is refused `approval_in_progress`. That is a terminal refusal rather than a `busy` to retry, because a caller retrying against a live approval is one polling the exact interval the serialisation exists to protect. The two enforcement points are symmetric under one lock — registering a run blocks a new approval, a live approval blocks a new registration — so a live approval and any other registered run never coexist. A question merely *pending* holds a new command too: without that, a caller free to keep starting commands decides whether the host is ever quiet enough for a yes to take. The cost is that one unanswered question stalls unrelated brokered work for up to `[sudo] timeout_sec`, which is the cost an approved run already imposes for its whole length.

**No question that could only be refused.** A run whose `sudo` arrives while another run is registered is refused there and then, naming the command in the way, rather than filing a question: approving requires sole occupancy, so that question could only ever be answered no, and attention is the scarce thing this design spends. One question at a time and never a queue follows from that rather than being a second rule. Requests from the *same* run still join that run's own question, which is what makes one approval cover a playbook's twenty become'd tasks.

It rests on no `faramir-exec` process outliving its run, which the per-run cgroup provides: a brokered command is spawned into a cgroup of its own (clone3's `CLONE_INTO_CGROUP`, the unit granted `Delegate=`), and the whole cgroup is killed and drained when the run ends, so a `setsid` child that breaks out of the process group is reaped with it.

**Serialisation is checked against the kernel, not believed.** The bookkeeping above can part from the process table: a drain that does not finish, a run aborted from the broker's side, the broker restarting while the executor is still killing a run. So before an approval takes, the broker asks the executor whether any process of its uid is alive outside that daemon and outside the runs it is confining — asked of the executor because the broker's own unit sets `ProtectProc=invisible` — and a no turns the operator's yes into a refusal there and then: the `sudo` fails, the question closes, and the command is run again rather than the question being held open for a second answer, which would make a human poll the one interval in which the host has to be quiet. Every failure is a no.

**The executor daemon is the one exception to that sentence, and it is closed differently.** It runs as the uid every brokered command runs as, sits in no run's cgroup, and receives each run's whole environment over its socket, so it is the single process from which every run's token could be read. What refuses a brokered command reaching *into* it is `PR_SET_DUMPABLE=0`, set by both daemons at startup: it refuses same-uid `ptrace` whatever `/proc/sys/kernel/yama/ptrace_scope` says (`0` on RHEL, Fedora and Arch), and a host installed with `--allow-sudo` has no seccomp filter to refuse the syscall — it cannot, a filter forcing `NoNewPrivileges=` on and that making `sudo` inert. `faramir doctor` warns on `ptrace_scope=0` for what it still governs, which is two brokered commands with respect to each other.

**The cgroup is the one reaper, and there is no fallback.** A process group is a strictly weaker grouping the same `setsid` escapes, so a run that cannot be confined is *refused* rather than reaped by process group, on every host, a sudo grant or not: a straggler through the approval window is exactly the failure this closes, and without a grant an unreaped child still holds the working tree or a concurrency slot past its life. Neither is worth a silent degrade. So confinement needs cgroup v2, the unit granted `Delegate=`, and `cgroup.kill` (kernel 5.14 or newer); `init` renders `Delegate=` on the executor unit for every install, a host that cannot confine refuses every brokered command until it is fixed, and `faramir doctor` fails one whose executor unit lost the delegation. The tests run under the same delegated cgroup (see [the test workflow](../.github/workflows/test.yml)).

The second way cannot be closed: the *approved command itself* persisting root. It spends its legitimate root once and installs a setuid-root binary, a `systemd` unit, a `cron` entry, a line in `sudoers`, none of which involves faramir again or expires when the token does. Configuring a host and backdooring it are the same primitives, so no sandbox distinguishes them without an allowlist of exactly which files, which is not "run a playbook". A password, a PAM callback, or any other credential would be defeated equally.

So the scope is "the command a human approves is trusted with permanent root on this host": serialisation keeps every *other* command out of that trust, and nothing walls the approved command itself in. `--allow-sudo` belongs where that command is operator-owned and read-only to brokered commands, so the agent cannot author what root runs. The audit log shows the approval; it does not show the persistence a hostile approved command installs, unless someone looks. The class that remains is the trusted command's own supply chain, the same risk as running it under `sudo` by hand, which is the boundary of the whole project.

The uid stays the bound. `faramir-exec` gains the ability to *ask*, not the ability to sudo, and the ask is answered by an account the agent cannot become. What that leaves is operational: an operator with `NOPASSWD` sudo or a warm sudo timestamp has already handed the agent that account, and a watcher left in a terminal the agent can type into is a prompt the agent can answer. A `NOPASSWD` entry would remove all of this in one line, so `faramir doctor` checks for one whether or not this host was installed with `--allow-sudo`.

**A killed command loses its output.** Redaction happens after the command finishes, so a timeout or interrupt yields nothing where an unwrapped command would have shown partial output. The cost of buffering, which the persistent shell forces.
