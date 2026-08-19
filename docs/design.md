# Design decisions and their costs

The [Prevented](../README.md#prevented) and [Not prevented](../README.md#not-prevented) tables are the boundary, including that the agent's own reach is not part of it. What follows is why the pieces inside it are shaped the way they are.

## The decisions

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
Secrets at rest | sops plus age. | Encrypted YAML, per-key diffs, no network round trip.
Credentials another tool owns | Linked by path, not copied in. | A copy is a second thing to rotate. The tool keeps its own file; the broker reads one value out of it. See [below](#linked-secrets-are-read-by-the-broker).
Redaction | Custom, over the whole value set. | Off-the-shelf injectors mask only what they injected; a managed host can print a credential the broker never injected.
Agent interface | Unix socket exposed as MCP tools plus a CLI. | A distinct tool is more discoverable to a model than a documented convention.
Enforcement | Hook plus filesystem permissions. | Instructions to the agent are ergonomics, not a boundary.

## One mode

The agent runs as the operator. An agent maintaining the operator's repositories needs their checkouts, their `gh` credential and their commit identity, and every route to giving a separate uid that access hands over the same files by another name. Bounding an unattended run is then a credential-scope problem: a `gh` token limited to the repositories it maintains, plus branch protection.

The boundaries are around the secrets, not the agent. The operator reaches the keeper's age key not at all, the broker's values, SSH keys and audit log only through the broker, and `faramir-exec` cannot read the operator's home.

## The secrets live in a directory, not a tree

`/etc/faramir/secrets`, `2750 root:<secrets-group>`, never in a checkout, which a clone or a branch could move. The keeper is the only account in that group and the only one that opens a managed file, so editing a value is `sudo faramir vault edit`. The broker socket admits a different group: asking for a value by name is not permission to read the file it came from. The broker holds every decrypted value already, so it stays outside the secrets group and asks the keeper when a file changed over `get_state`, which touches neither the key nor sops.

`.sops.yaml` sits in the config directory above the secrets directory for two reasons:

- sops resolves that file from the working directory upward, so a parent is found from the secrets directory as well as from itself.
- the managed store globs the secrets directory and `filepath.Glob` matches dotfiles, so a rule file among the ciphertext is one glob spelling away from being loaded as a managed file that does not decrypt.

`--config-dir` moves the secrets, the config and the age key together: the key and the ciphertext it opens are one placement decision rather than three, so no part of an install stays behind at a path the rest has left. What the units can see decides where, not the modes:

Placement | Result
--- | ---
`/etc/faramir` | The default. Present at boot, readable by three uids, owned by none of them.
`/tmp`, `/var/tmp` | Installs, then finds nothing: `PrivateTmp=true` gives each unit its own. Nothing refuses this at install time; it surfaces when a daemon starts.
inside a home | Works. `init` drops the keeper's `ProtectHome=` to `tmpfs` and binds that directory back. An *unmounted encrypted* home is refused, the write landing in the backing directory and being shadowed the moment the home mounts.

An encrypted home is not mounted until its owner logs in, so an install inside one has its secrets absent at boot and to cron. A file may be missing because it was never written or because the filesystem holding it is not mounted, and only the second is dangerous, so both are refused, per request rather than at startup. The rule and its one exception are with [the gate](configuration.md#the-install-gate-and-the-same-gate-at-startup).

## Linked secrets are read by the broker

An `~/.npmrc` token and a `gh` OAuth token are the tools' own files, and copying them into the store would mean re-encrypting on every rotation. A `[[secret.link]]` entry names one instead. How to write one is in [configuration.md](configuration.md#linked-secrets); this is why it is shaped that way.

**The broker reads them, not the keeper.** The keeper holds the age key, which decrypts every managed file retroactively, so it runs with the homes taken away entirely and one `BindReadOnlyPaths` at most. A linked file needs no key, so putting these behind it would widen the one account worth keeping narrow, and would make every link change a unit re-render. The broker already holds every plaintext value, already reads key material at rest for `[ssh] key`, and deliberately has no `ProtectHome=`, having to stat a request's cwd. What bounds it is the file's own mode.

**The grant is modes and ownership, and `init` makes it.** The file becomes the broker's own group and group-readable; the directories above it become the client group, execute only, which is what `sharetree` already grants an enrolled tree. Not an ACL, and the reason is not taste:

Rejected | Why
--- | ---
An ACL | A stacked filesystem does not carry one. An eCryptfs home takes `setfacl` without error and reads the entry back from its own cache, so the grant looks applied, cannot be removed, and is not what decides the read.
A default ACL, for durability | It does not survive the case it was reached for. A tool that renames a temp file over the original creates it fresh, and the `0600` creation mode masks the inherited entry to nothing. Neither mechanism survives a rename, and both survive an in-place rewrite, so durability does not choose between them.
The client group on the file | The executor is in it, so every brokered command could read the file directly rather than asking for the ref.
Leaving it to the operator | A grant nobody re-applies is one a tool silently takes away.

What catches a lost grant is `faramir doctor`, which asks the broker's own account whether it can still read each file, and the executor's whether it can. Asking rather than reading the mode is what makes it answer correctly whatever the filesystem is.

**What linking buys is redaction, and it only applies to values the agent could already reach.** The agent runs as the operator, so `~/.npmrc` is one `Read` away; linking puts that value in the redactor and renders the path into the deny rules, closing both halves. Pointed at a file the agent *cannot* read, it inverts: every managed value is reachable through `env_refs` by any brokered command, so the value becomes agent-obtainable and no disclosure path is closed in exchange. A root-owned LUKS keyfile belongs outside the store for that reason.

**One ref per entry, with an explicit selector.** There is no whole-file flatten. A config file is mostly not secret, and a value in the set is a value the redactor searches output for: `https://registry.npmjs.org/` clears `min_length` and would tokenize unrelated output. `min_length` is a bound on what can be searched for safely, not a filter for what is secret.

**faramir puts no source in a ref.** One flat namespace, and a cross-source collision refused at load naming both sides. Tagging the source into the name (`faramir://sops/...`) would make moving a secret between the store and a link a rename, breaking every `faramir.env` and playbook naming it, which is the drift linking exists to avoid.

**A link that is there and will not read is held to the same gate as a managed file that did not decrypt**, because it is the same state: a value on disk that the redactor does not have. What that costs day to day is in [configuration.md](configuration.md#linked-secrets).

**A link is install state**, re-asserted by every `init` run rather than applied once, which is why `faramir link add` applies those same steps rather than a private copy of them.

Rendering linked paths into the per-project assets instead would change every enrolled tree's files whenever a link was added, and report drift in all of them until each was enrolled again. Pi's extension is the only file it gets, so covering its links would mean exactly that, and only in the trees it has been trusted in. It carries none, which is the gap it already has.

## Three layers

1. **No plaintext where the agent will trip over it.** Values are sops ciphertext; the age key is `0400` under a uid that executes nothing but sops.
2. **Leak-prone commands are refused.** [deny-patterns.txt](../agent/hooks/deny-patterns.txt) names direct decryption, environment dumps, and readers or encoders pointed at key material. The refusal states the alternative, because a denial the agent cannot act on gets worked around.
3. **Redact what still gets through.** The `redact` op returns text with every known value replaced by its token. The caller never receives the value set.

## How the rewrite works

A pre-execution check cannot rewrite a tool's result, but it can rewrite its input:

```bash
source /usr/local/libexec/faramir/wrap.sh '<command>'
```

[wrap.sh](../agent/hooks/wrap.sh) creates two `0600` files on tmpfs, one for the captured output and one for the redacted result, runs the command with both streams redirected into the first, reads it back through `faramir redact`, removes both, and restores the exit status.

**The agent's shell persists between tool calls**, so a `cd` or `export` must survive. That constraint decides the shape:

Wrapper | State | Output | Allow-listable
--- | --- | --- | ---
`faramir redact -- bash -lc '<cmd>'` | lost, runs in a grandchild | fine | yes
`{ <cmd>; } 2>&1 \| faramir redact` | lost, pipeline elements are subshells | fine | no
`{ <cmd>; } > >(faramir redact) 2>&1` | kept | races the redactor | no
inline `{ <cmd>; } >"$f" 2>&1` | kept | complete | no
`source wrap.sh '<cmd>'` | kept | complete | no

Every failure fails closed. No `XDG_RUNTIME_DIR` and the command does not run, there being nowhere private to capture what it would print; output captured but not redacted is withheld. Both say so on stderr and return non-zero, so a withheld output cannot read as a command that printed nothing.

`faramir redact` fails the same way in both its shapes. What is *not* withheld is the part of a stream already redacted when the broker died part way through: those chunks came back covered, and buffering the whole stream to withhold them would cost an unbounded buffer for a guarantee already met.

Left alone rather than rewritten:

Case | Why
--- | ---
One this rewrite already produced | Idempotence. Matched as a prefix of the whole command, in either spelling, `source` or `.`, each followed by a space
A read of a running command's output, such as Claude Code's `BashOutput` | It starts nothing. What it reads was redacted when the command filling the buffer was started
An empty command | Nothing to cover
A denied command | Refused instead

A **backgrounded** command takes a third path: `source wrap.sh --stream '<cmd>'`, which streams through the redactor rather than capturing, the capture path otherwise holding a dev server unshown until it exited. The wrapper runs `{ eval "$cmd"; } 2>&1 | faramir redact` under `set -o pipefail`, carrying the command's exit status out past the redactor. A trailing `&` is moved outside the rewrite; a tool's own background flag gets no `&` appended, the host backgrounding it. This is also what makes `BashOutput` read redacted.

An incomplete command is *not* left alone. One ending in `\`, `&&`, `||` or `;` is wrapped like any other and fails inside the wrapper's `eval`, which re-parses it in isolation, so it fails the way it would have failed unwrapped rather than breaking the wrapper's syntax.

The already-covered test is a prefix rather than a match anywhere, because two forms look covered and are not:

- **A command that merely names the wrap script.** The path is in this project's documentation and in the wrapper itself, so a match anywhere would leave `echo /usr/local/libexec/faramir/wrap.sh; cat secrets` unrewritten.
- **A command piping into the redactor.** A pipe carries stdout, so whatever the upstream wrote to stderr reaches the transcript unredacted, and chaining past it with `;`, `&&` or `||` runs the rest of the line uncovered. Wrapping one captures both streams and costs a second redaction pass, which changes nothing because a token is not a value.

## Agents

The guard is one program speaking each agent's contract. What varies is the tool that runs a command, the shape of the reply and where it is registered; what does not is that the command is rewritten to redact its own output. Which agents, and what enrolling each costs, is the table in the [README](../README.md#supported-agents).

`--agent` defaults to `auto`, which configures the agents already there and nothing else: `init` asks that of the operator's home, `init-project` of the tree, and they are not the same paths, opencode keeping `opencode.json` beside a project and `.config/opencode` under a home. Naming one configures it regardless, which is how a tree is set up for an agent before it is installed. Detection only ever adds, so the two need no rule about which wins.

Beside the rules goes prose saying what they refuse and why, in the file each agent reads for every project. A model given a refusal and no explanation tries the next route: another tool, an interpreter, a base64 pipe. The section is also the only thing faramir says in a tree `init-project` has never been run in, where the deny rules still hold and there is no broker to name. The tree's own section is the longer one, there being a route there to point at.

The paths those rules refuse are written once, in [internal/install/protectedpaths.go](../internal/install/protectedpaths.go), and rendered into each agent's own spelling. A copy per agent drifts silently: a rule that covers nothing looks exactly like a rule that covers everything, and one character is the difference. Pi has no rule file to write, so its rules are compiled into the extension and applied by shape, a file tool whose name it does not know still carrying a path.

opencode and Kilo Code have no hook that runs a program. A plugin in the agent's own process blocks a call by throwing and changes one by mutating its arguments, so it asks the guard and applies the answer:

```json
{"decision": "deny", "reason": "<what the model is told>"}
{"decision": "rewrite", "tool_input": {"command": "source .../wrap.sh '<command>'"}}
```

The rewrite carries back every field of the original tool input with only `command` replaced. Nothing written is a call left alone. Every other answer fails closed: a guard that cannot be run, a non-zero exit, an answer that is not JSON, a decision the plugin does not know. That covers version skew, so run `faramir init` before enrolling one of these: a binary too old to know the agent refuses every command in that project rather than running it unredacted.

Antigravity gets one half of this ([which half](../README.md#supported-agents)) and is told so: shipping prose silently would say a project is covered when the thing that covers it is absent, so the enrolment warns.

A file two agents read is written once, and claims only what holds for both: a file that told one of them its file tools are refused everywhere would be telling the other something false. No two share one today, and the rule stays because the failure it prevents is silent. A rules file faramir creates carries the frontmatter that makes it always-on, that being what decides whether the model is shown it at all.

## What this gives up

Cost | Detail
--- | ---
No kernel boundary around the agent process | Hooks and the deny list, which is the trade for an agent that can do the operator's work.
For Bash on Claude Code, the deny list replaces the permission prompt | Matching runs against the rewritten command, so a rule keyed on the program name no longer fires, and the wrapper cannot be allow-listed. There is no `ask` to return instead: it would prompt on every command including `ls`, show the rewritten text rather than what was typed, and strand an unattended run on the first command.
The shipped deny list names credential disclosure and nothing destructive | Enrolling drops whatever Bash prompting stood between the agent and `rm -rf` and puts nothing in its place. Prompts on `Write` and `Edit` do not cover it, Bash writing and deleting without them.
A killed command loses its output | Redaction happens after the command finishes, so a timeout or interrupt yields nothing where an unwrapped command would have shown partial output. The cost of the buffering the persistent shell forces.
The wrapper needs a private `XDG_RUNTIME_DIR` | It captures output before redacting it, so that file holds plaintext and belongs where no other account can enter. `/dev/shm` is 1777, where a name nothing has created yet is one another account can create first. A session without one, which includes `sudo` and `cron`, gets a refusal on every Bash command.
The wrapper takes the caller's `EXIT` trap | A command that runs `exit` ends the sourced shell at the `eval`, before the cleanup, and an `EXIT` trap is what bash still runs there. The caller's is saved and put back afterwards. Two ways past it, both leaving a `0600` capture file only the operator can reach: `SIGKILL`, which runs no trap, and a command that installs an `EXIT` trap of its own.

Hooks fire in every Claude Code permission mode and a `deny` is enforced in each, `--dangerously-skip-permissions` included, so what enrolment costs depends on the mode:

Mode | Cost
--- | ---
`default` | Bash would have prompted and now does not. This is what the warning is about.
`acceptEdits` | Auto-accepts `Write` and `Edit`, leaves Bash prompting. Same cost as default.
`bypassPermissions` | Bash never prompted, so approving it removes nothing. Enrolment is purely additive.

Rewriting rather than denying is the point: a deny list covers what somebody thought to name, and the command that leaks a credential is usually one nobody would have.

**A `redact` op is an oracle.** A guessed value comes back confirmed or not. Acceptable only on weighting: an accident does not guess. It is not rate-limited, because a throttle bounds only a guessing attack the same caller need never mount: `refs` and `run` sit on the same socket behind the same `allowed_group` check, so every managed value can be had by naming it. Every call is recorded, and a guess shorter than `[secret] min_length` is not an oracle at all. Bring a limit back if `redact` ever becomes reachable by a caller that cannot reach `run`; there is no such caller today.

## Allowing sudo on the controller

How to install and run this is in [escalation.md](escalation.md); this is the reasoning.

**An escalation is the same kind of oracle as `redact`, weighted the other way.** A human can answer wrongly, so it survives that weighting by being deny-by-default: silence is a refusal, an unreachable answer channel is a refusal, and anything that is not `yes` is a refusal.

What makes the answer worth anything is that the prompt names the command. The broker writes the question itself, from the argv it started, and refuses a request it cannot attribute to a running command; the prompt string `sudo` passes to the helper is ignored, coming from the child, which is the side being asked about.

**Naming the command means rendering it, not printing it.** The argv is the caller's and the question goes to a terminal, which obeys what it is sent. Most of it has been through the redactor. Two things survive that, and either is enough: a bare `\r`, which returns the cursor so the rest of the line overwrites what came before it, and `ESC` followed by a byte outside `@-Z` and `\-_`, including `ESC c`, a terminal reset that on many emulators takes the scrollback with it. So every caller-chosen part of a question is quoted the moment it holds anything but printable text, ordinary arguments are left bare, and the command is bounded, the audit record keeping the whole of it. [internal/termsafe](../internal/termsafe/termsafe.go) holds the same rule for `faramir logs`, where recorded output is escaped rather than quoted and never bounded, being the text an operator came to read.

Five easier designs, and why each was not taken:

Rejected | Why
--- | ---
A time window | `timestamp_timeout=0`, so sudo's own credential cache never decides this. A window in which escalation is assumed is one an agent can start a brokered command inside, riding an approval a human gave for something else.
The caller's terminal | The agent owns that process tree, so a password typed into it is one the agent can read.
`systemd-ask-password` | Asking through it means creating a file in `/run/systemd/ask-password`, `0755 root:root`, so a broker running as its own uid is refused and every request is denied for want of anybody to ask. What that channel offers is a reply socket only root can write to, which `SO_PEERCRED` provides directly.
A managed secret | The executor can request the same injection the agent can, so anything injectable is agent-reachable, and a sudo password in the store is root for the asking.
A password at all | A bearer credential, so wherever it is kept, a command approved once can read it, keep it, and leave it for a later command that was not approved: same uid, shared `PrivateTmp`, shared working tree, `sudo -S`, root. What satisfies `sudo` here is a decision, and a decision cannot be carried.

**How the PAM stack fails matters more than how it works.** Two settings decide whether it gates anything:

- `requisite`, never `sufficient`. With `sufficient`, a helper that *refuses* is not fatal: the stack falls through to the `pam_permit` beneath it and every escalation is granted without asking anybody.
- `seteuid`, because `pam_exec` otherwise runs the helper with the real uid, which under setuid `sudo` is the executor's own. The broker answers `escalate` to root alone, so the helper would be refused and nothing on the host could sudo. It also keeps the deciding process out of reach of the uid being decided about.

`faramir doctor` fails on either. Everything else fails closed by construction: an unreachable broker, an unknown token, a refusal and a timeout all exit non-zero, and nothing authenticates except by reaching `pam_permit` past a `requisite` that succeeded. The service is faramir's own, named by `pam_service=` in the sudoers entry, so everyone else's `sudo` reads the stock `/etc/pam.d/sudo` and a mistake here can neither lock this host's operators out nor hand another account a free root. Removing the file falls back to `/etc/pam.d/other`; `doctor` fails if that fallback is a free pass.

### What the escalation does not reach

Two ways it could go past the one command it named, with different answers.

**A second, unapproved command riding it: closed.** Every brokered command runs as `faramir-exec`, and `/proc/<pid>/environ` is readable within a uid, so a concurrent run could read the approved run's token and `sudo` on it. **Any live `faramir-exec` process during an approved window is root.** The broker closes this by serialising: an escalation takes only when its run is the sole brokered command in flight, and while it is live every other brokered command is refused `escalation_in_progress`, terminal rather than a `busy` to retry, a caller retrying against a live escalation being one polling the exact interval the serialisation protects. Registering a run blocks a new escalation and a live escalation blocks a new registration, under one lock. A merely *pending* question holds a new command too, or a caller free to keep starting commands decides whether the host is ever quiet enough for a yes to take. The cost is that one unanswered question stalls unrelated brokered work for up to `[escalation] timeout_sec`.

Three things follow:

- **No question that could only be refused.** A `sudo` arriving while another run is registered is refused there and then rather than filing a question that could only be answered no. One question at a time and never a queue follows from that. Requests from the *same* run join that run's question, which is what makes one approval cover a playbook's twenty become'd tasks.
- **Serialisation is checked against the kernel, not believed.** The bookkeeping can part from the process table: a drain that does not finish, a run aborted from the broker's side, the broker restarting while the executor is still killing a run. So before an escalation takes, the broker asks the executor whether any process of its uid is alive outside that daemon and outside the runs it is confining, asked of the executor because the broker's own unit sets `ProtectProc=invisible`. Every failure is a no.
- **The cgroup is the one reaper, with no fallback.** A brokered command is spawned into a cgroup of its own (clone3's `CLONE_INTO_CGROUP`, the unit granted `Delegate=`), killed and drained when the run ends, so a `setsid` child that broke out of the process group is reaped with it. A process group is a strictly weaker grouping the same `setsid` escapes, so a run that cannot be confined is *refused*, on every host, grant or not. Needs cgroup v2 and `cgroup.kill`, kernel 5.14 or newer.

**The executor daemon is the one exception, closed differently.** It runs as the uid every brokered command runs as, sits in no run's cgroup, and receives each run's whole environment over its socket, so it is the single process from which every run's token could be read. What refuses a brokered command reaching *into* it is `PR_SET_DUMPABLE=0`, set by both daemons at startup: it refuses same-uid `ptrace` whatever `ptrace_scope` says (`0` on RHEL, Fedora and Arch), and a host installed with `--allow-sudo` has no seccomp filter to refuse the syscall and cannot have one, such a filter forcing `NoNewPrivileges=` on and that making `sudo` inert.

**The approved command itself persisting root: not closable.** It spends its legitimate root once and installs a setuid-root binary, a `systemd` unit, a `cron` entry or a line in `sudoers`, none of which involves faramir again or expires when the token does. Configuring a host and backdooring it are the same primitives, so no sandbox distinguishes them without an allowlist of exactly which files, which is not "run a playbook". Any credential would be defeated equally.

So the scope is "the command a human approves is trusted with permanent root on this host". Serialisation keeps every *other* command out of that trust; nothing walls the approved command itself in. `--allow-sudo` belongs where that command is operator-owned and read-only to brokered commands.

The uid stays the bound. `faramir-exec` gains the ability to *ask*, not the ability to sudo, and the ask is answered by an account the agent cannot become. What remains is operational: an operator with `NOPASSWD` sudo or a warm sudo timestamp has already handed the agent that account, and a watcher left in a terminal the agent can type into is a prompt the agent can answer. A `NOPASSWD` entry would remove all of this in one line, so `faramir doctor` checks for one whether or not this host was installed with `--allow-sudo`.
