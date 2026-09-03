# Design decisions and their costs

The [Prevented](../README.md#prevented) and [Not prevented](../README.md#not-prevented) tables in the README define the boundary. The agent's own reach is outside it. This page explains why the pieces inside that boundary are built the way they are.

## The decisions

Decision | Choice | Rationale
--- | --- | ---
Isolation | Uid separation plus systemd hardening. No containers. | Network isolation is a non-goal, and that is the main thing containers make easy. A sandbox limits what a child can see. It is not a substitute for a uid that holds nothing.
How the roles are separated | `User=` in three units, all starting one binary. | The kernel checks the uid against `0400 faramir-keeper` and against a socket's group. Separate executables would add no check.
Filesystem isolation | None beyond file modes and `ProtectSystem=strict`, which `--allow-sudo` drops. | A home the executor may not read is already refused by its mode. A home it may read, the agent can read directly. Faramir's own directories are refused by rule, not by mode, because an approved escalation runs as root and root ignores modes.
Where commands run | The agent's working tree, directly. | A promotion gate gives an immutable snapshot and a commit sha. Both defend against a deliberate agent, which is out of scope.
Who executes | The broker, as its own uid. | If the client execs, plaintext is in a process the agent owns.
Who holds the key | A separate uid that executes nothing but sops. | A key the broker can load is a key any brokered command can read.
Who forks the child | A third uid, given the PTY slave over `SCM_RIGHTS`. | The child can reach anything the forking uid can reach.
Command allowlist | None. | Any rule that permits an interpreter is reachable in one step through `bash`, and a usable policy must permit `bash`.
How a program gets values | `env_refs`, read from the environment. | The alternative is handing the program the master key.
Secrets at rest | sops plus age. | Encrypted YAML, per-key diffs, no network round trip.
Credentials another tool owns | Linked by path, not copied in. | A copy is a second thing to rotate. The tool keeps its own file; the broker reads one value out of it. See [below](#linked-secrets-are-read-by-the-broker).
Redaction | Custom, over the whole value set. | Off-the-shelf injectors mask only what they injected. A managed host can print a credential the broker never injected.
Agent interface | A Unix socket, reached through the CLI. | The binary is installed for the account, so the route is the same in every directory and needs no registration. A registered tool is easier for a model to discover, but it needs a config surface per agent, a second path to the broker and a tool slot in every session. The prose that names the route is installed account-wide either way.
Enforcement | Hook plus filesystem permissions. | Instructions to the agent are ergonomics, not a boundary.

## One mode

The agent runs as the operator. An agent that maintains the operator's repositories needs their checkouts, their `gh` credential and their commit identity. Giving a separate uid that access would expose the same files under another name. Bounding an unattended run is therefore a credential-scope problem: a `gh` token limited to the repositories it maintains, plus branch protection.

The boundaries are around the secrets, not around the agent:

- The operator cannot reach the keeper's age key at all.
- The operator reaches the broker's values, SSH keys and audit log only through the broker.
- `faramir-exec` cannot read the operator's home.

## The secrets live in a directory, not a tree

The secrets directory is `/etc/faramir/secrets`, `2750 root:<secrets-group>`. It is never in a checkout, because a clone or a branch could move it. The keeper is the only account in that group and the only one that opens a managed file, so editing a value is `sudo faramir vault edit`. The broker socket admits a different group: permission to ask for a value by name is not permission to read the file it came from. The broker already holds every decrypted value, so it stays outside the secrets group. It asks the keeper whether a file changed over `get_state`, which uses neither the key nor sops.

`.sops.yaml` sits in the config directory, above the secrets directory, for two reasons:

- sops looks for that file from the working directory upward, so a parent directory works for the secrets directory and for itself.
- The managed store globs the secrets directory, and `filepath.Glob` matches dotfiles. A rule file among the ciphertext could be loaded as a managed file that does not decrypt.

`--config-dir` moves the secrets, the config and the age key together. The key and the ciphertext it opens are one placement decision, so no part of an install is left behind at the old path. Where the directory may go is decided by what the units can see, not by the file modes:

Placement | Result
--- | ---
`/etc/faramir` | The default. Present at boot, readable by three uids, owned by none of them.
`/tmp`, `/var/tmp` | Refused at install time: `PrivateTmp=true` gives each unit its own, so a daemon started there would find nothing.
inside a home | Works. `init` sets the keeper's `ProtectHome=` to `tmpfs` and binds that directory back. An *unmounted encrypted* home is refused: the write would land in the backing directory and be hidden when the home mounts.

An encrypted home is not mounted until its owner logs in, so an install inside one has no secrets at boot or under cron. A file can be missing because it was never written or because its filesystem is not mounted. Only the second is dangerous, and nothing inside the broker can tell them apart, so both serve with a warning rather than a refusal, and `status` and `doctor` are where an operator sees it. The rule and its exceptions are described with [the gate](configuration.md#the-install-gate-and-the-same-gate-at-startup).

## Linked secrets are read by the broker

An `~/.npmrc` token and a `gh` OAuth token belong to their tools. Copying them into the store would mean re-encrypting on every rotation. A `[[secret.link]]` entry names the file instead. [configuration.md](configuration.md#linked-secrets) shows how to write one; this section explains the design.

**The broker reads them, not the keeper.** The keeper holds the age key, which decrypts every managed file retroactively, so it runs with the homes removed and at most one `BindReadOnlyPaths`. A linked file needs no key. Putting links behind the keeper would widen the reach of the account that should stay narrowest, and would make every link change a unit re-render. The broker already holds every plaintext value, already reads key material at rest for `[ssh] key`, and has no `ProtectHome=` because it has to stat a request's cwd. The file's own mode bounds it.

**The arrangement is modes and ownership. Faramir checks it and does not apply it.** The file must belong to the broker's group, be group-readable and no more. The directories above it must be enterable by the client group. Both are the operator's paths, and faramir changes no path it does not own: `link add`, `init` and `doctor` report what is wrong and the command that fixes it, and whoever manages the host's permissions applies it. Why modes rather than an ACL:

Rejected | Why
--- | ---
An ACL | A stacked filesystem does not carry one. An eCryptfs home accepts `setfacl` without error and reads the entry back from its own cache. The entry looks applied, cannot be removed, and does not decide the read.
A default ACL, for durability | It does not survive the case it exists for. A tool that renames a temp file over the original creates the file fresh, and the `0600` creation mode masks the inherited entry to nothing. Neither an ACL nor a group survives a rename, and both survive an in-place rewrite, so durability does not choose between them.
The client group on the file | The executor is in it, so every brokered command could read the file directly instead of asking for the ref.
faramir applying it | A tool that regroups a file it does not own moves a permission change out of the place where the host's permissions are decided. A later revert would go unnoticed until something unrelated breaks.

`faramir doctor` detects a lost arrangement. It asks the broker's own account whether it can still read each file, and the executor's account whether it can. Asking, rather than reading the mode, gives the correct answer on any filesystem. `init` and `link add` check the file's ownership and mode instead, because their report has to name the `chgrp` and `chmod` that fix it.

**Linking buys redaction, and only for values the agent could already reach.** The agent runs as the operator, so it can read `~/.npmrc` with one `Read`. Linking puts that value in the redactor and renders the path into the deny rules, closing both disclosure paths. Pointed at a file the agent *cannot* read, linking makes things worse: every managed value is reachable through `env_refs` by any brokered command, so the agent can obtain the value, and no disclosure path is closed in return. A root-owned LUKS keyfile belongs outside the store for that reason. A [blocked path](configuration.md#blocked-paths) covers such a file: the refusal without the value. The refusal covers both routes an agent has, its own tools and the broker.

**One ref per entry, with an explicit selector.** There is no whole-file flatten. A config file is mostly not secret, and every value in the set is a value the redactor searches output for: `https://registry.npmjs.org/` is longer than `min_length` and would tokenize unrelated output. `min_length` bounds what can be searched for safely. It does not decide what is secret.

**A ref carries no source.** There is one flat namespace, and a collision between sources is refused at load, naming both sides. Tagging the source into the name (`faramir://sops/...`) would make moving a secret between the store and a link a rename, which would break every `faramir.env` and playbook that names it. Linking exists to avoid that drift.

**A link that exists but cannot be read disables that one ref and nothing else.** It is the same state as a managed file that did not decrypt, a value on disk that the redactor does not have, but a link is one ref the broker can name and refuse while serving the rest, where a managed file names none of its refs until it decrypts and so stops the broker serving.

**A link is install state.** Every `init` run re-asserts it, and `faramir link add` applies the same steps rather than a private copy of them.

A linked path is rendered into the rule files that agents enforce themselves, which `link add` and `init` rewrite in the operator's home. No other file carries a copy: the plugin, the extension and the hook ask `faramir guard`, which reads the rendered rules on each call, so adding a link covers those agents without rewriting anything they load.

## Three layers

1. **No plaintext where the agent can find it.** Values are sops ciphertext. The age key is `0400` under a uid that executes nothing but sops.
2. **Commands naming a declared path are refused.** [deny-patterns.txt](../agent/hooks/deny-patterns.txt) names the paths the install declares: the key material, meaning the age key, the SSH private key and whatever `faramir block` declares, plus the managed store and faramir's own files. A command naming one is refused whatever it would do with the path. There is no verb list to keep complete: every subject is an absolute path, and a path names itself. There is one rule per kind of entry, and every rule names its kind, so the refusal can say which kind it is and name the command that removes the entry. A `--strict` entry is a kind of its own. It is the one entry the two tiers treat differently: its refusal names the ref instead of offering a brokered route, because the broker will not give it one either. Faramir's own binary, units and plugin files keep verb rules, because an agent reads and runs those files and only replacing them is refused. The file is in kind order, which is the order the broker holds its own rules in. First match wins on both sides, so a command that is both an operator command and a named path gets the same answer either way.

   The second half of the file is generated from the same set as the agents' deny rules: one catalogue, three entry points. A declared path is refused to a file tool, to `cat` and to a brokered command together, not to only one of them. Each rule carries its subject, and each tier turns that into its own shape and its own message. The guard packs the subjects into one pattern per kind, because a file of patterns has nowhere to keep a message. The broker keeps a rule per entry so a refusal can name the entry and the command that removes it. A path under a home is named in every spelling a shell expands to it, `~/` and `$HOME/` among them, because that is how the file is usually written. It is also named by its tail alone where that tail is a path rather than a word, because a rule has no working directory and cannot follow a `cd`.

   The refusal states the alternative, because a denial the agent cannot act on gets worked around. Nothing is refused for being a decryption or an environment dump. What a command *does* is the operator's to declare, with `block add --command`. In an enrolled tree the command is rewritten before it runs, so `printenv` comes back with every managed value replaced by its token.

   What an operator declares under `[[secret.block]]` or `[[secret.link]]` is enforced twice, because the deny rules only reach the agent's own tools. The broker holds the same entries and refuses a brokered command that would print one. A brokered command runs as another uid on the other side of the broker, where no hook over shell tools reaches. Only the broker's rules apply there: a brokered command has to be able to use a credential file, so the broker refuses the commands that print its contents and leaves changing or moving the file alone. The broker also holds this install's own directories and the key it lends, wherever `--ssh-key` put it. It refuses those to any brokered command that names one, for any reason: on a host where an escalation was approved, that route runs as root, and root ignores file modes. The commands that act on the install rather than through it are refused the same way, `faramir vault edit` and `systemctl stop faramir-broker` among them. They are the operator's by either route, and the account on the other side of the broker is not the operator. See [the brokered route](configuration.md#the-brokered-route).
3. **Redact what still gets through.** The `redact` op returns text with every known value replaced by its token. The caller never receives the value set.

## How the rewrite works

A pre-execution check cannot rewrite a tool's result, but it can rewrite its input:

```bash
source /usr/local/libexec/faramir/wrap.sh '<command>'
```

[wrap.sh](../agent/hooks/wrap.sh) creates two `0600` files on tmpfs, one for the captured output and one for the redacted result. It runs the command with both streams redirected into the first, reads it back through `faramir redact`, removes both files, and restores the exit status.

**The agent's shell persists between tool calls**, so a `cd` or `export` must survive. That constraint decides the shape:

Wrapper | State | Output
--- | --- | ---
`faramir redact -- bash -lc '<cmd>'` | lost, runs in a grandchild | fine
`{ <cmd>; } 2>&1 \| faramir redact` | lost, pipeline elements are subshells | fine
`{ <cmd>; } > >(faramir redact) 2>&1` | kept | races the redactor
inline `{ <cmd>; } >"$f" 2>&1` | kept | complete
`source wrap.sh '<cmd>'` | kept | complete

Every failure fails closed. Without `XDG_RUNTIME_DIR` the command does not run, because there is nowhere private to capture its output. Output that was captured but not redacted is withheld. Both cases say so on stderr and return non-zero, so a withheld output cannot be mistaken for a command that printed nothing.

`faramir redact` fails the same way in both its forms. One thing is not withheld: the part of a stream that was already redacted when the broker died part way through. Those chunks were already redacted, and withholding them would need an unbounded buffer for a guarantee they already meet.

Commands left alone rather than rewritten:

Case | Why
--- | ---
One this rewrite already produced | Idempotence. The whole command must be a single wrap invocation, matched as a prefix in either spelling, `source` or `.`, each followed by a space. A command that begins with a wrap invocation and chains more (`source wrap.sh 'x' && cat log`) is re-wrapped, because the chained part would run unredacted
A read of a running command's output, such as Claude Code's `BashOutput` | It starts nothing. What it reads was redacted when the command filling the buffer was started
An empty command | Nothing to cover
A denied command | Refused instead

A **backgrounded** command takes a third path: `source wrap.sh --stream '<cmd>'`. It streams through the redactor instead of capturing, because the capture path would show nothing from a dev server until it exited. The wrapper runs `{ eval "$cmd"; } 2>&1 | faramir redact` under `set -o pipefail`, so the command's exit status survives the pipe. A trailing `&` is moved outside the rewrite. A tool's own background flag gets no `&` appended, because the host backgrounds it. This is also what makes `BashOutput` read redacted text.

Antigravity's `run_command` takes a fourth path, `--stream-state`: the same live redaction, with the eval kept in the caller's shell. That host's shell persists between calls and its runner polls a long command, so a capture would show nothing until exit and `--stream` would lose an `export` to its subshell. The redactor runs behind a process substitution set up with `exec`, so the shell can read its pid and status, and a failed redaction is not reported as success. SIGPIPE is ignored for the duration and the caller's disposition is restored afterwards. Without that, a builtin writing to a dead redactor would kill the persistent shell.

An incomplete command is *not* left alone. One ending in `\`, `&&`, `||` or `;` is wrapped like any other and fails inside the wrapper's `eval`, which parses it on its own. It fails the way it would have failed unwrapped, without breaking the wrapper's syntax.

The already-covered test matches a single-command prefix, not a wrap invocation anywhere in the line. Three forms look covered and are not:

- **A command that merely names the wrap script.** The path appears in this project's documentation and in the wrapper itself. A match anywhere would leave `echo /usr/local/libexec/faramir/wrap.sh; cat secrets` unrewritten.
- **A command chaining past a wrap invocation.** The prefix is there, but everything after the `&&` would run unredacted. That is why the test requires a single command and not only a prefix.
- **A command piping into the redactor.** A pipe carries stdout, so whatever the upstream wrote to stderr reaches the transcript unredacted, and chaining past it with `;`, `&&` or `||` runs the rest of the line uncovered. Wrapping such a command captures both streams and adds a second redaction pass, which changes nothing because a token is not a value.

What each agent does with the rewrite, how the rules reach it, and what enrolling one costs is in [coding-agents.md](coding-agents.md).

## What this gives up

Cost | Detail
--- | ---
No kernel boundary around the agent process | Hooks and the deny list instead. That is the price of an agent that can do the operator's work.
The shipped deny list names credential disclosure and nothing destructive | Enrolling removes whatever Bash prompting stood between the agent and `rm -rf` and puts nothing in its place. Prompts on `Write` and `Edit` do not cover it, because Bash writes and deletes without them.
A killed command loses its output | Redaction happens after the command finishes, so a timeout or interrupt yields nothing where an unwrapped command would have shown partial output. This is the cost of the buffering the persistent shell requires.
The wrapper needs a private `XDG_RUNTIME_DIR` | It captures output before redacting it, so that file holds plaintext and must be somewhere no other account can enter. `/dev/shm` is 1777, where another account can create a name first. A session without `XDG_RUNTIME_DIR`, which includes `sudo` and `cron`, gets a refusal on every Bash command.
The wrapper takes the caller's `EXIT` trap | A command that runs `exit` ends the sourced shell at the `eval`, before the cleanup, and an `EXIT` trap is what bash still runs there. The caller's trap is saved and restored afterwards. Two things get past it, each leaving a `0600` capture file only the operator can reach: `SIGKILL`, which runs no trap, and a command that installs an `EXIT` trap of its own.

What each agent gives up on top of this, including Claude Code's cost per permission mode, is in [coding-agents.md](coding-agents.md#claude-code).

Rewriting rather than denying is the design. A deny list covers what somebody thought to name, and the command that leaks a credential is usually one nobody thought to name.

**A `redact` op is an oracle.** A guessed value comes back confirmed or not. This is acceptable because an accident does not guess. It is not rate-limited, because a throttle would bound only a guessing attack the same caller never needs to mount: `refs` and `run` sit on the same socket behind the same `allowed_group` check, so every managed value can be obtained by naming it. Every call is recorded, and a guess shorter than `[secret] min_length` is not an oracle at all. Add a limit if `redact` ever becomes reachable by a caller that cannot reach `run`.

## Allowing sudo on the controller

How to install and run this is in [escalation.md](escalation.md). This section is the reasoning.

**An escalation is the same kind of oracle as `redact`, weighted the other way.** A human can answer wrongly, so the design is deny-by-default: silence is a refusal, an unreachable answer channel is a refusal, and anything that is not `y` is a refusal.

An answer is meaningful only if the question names the right command. The broker writes the question itself, from the argv of the command it started, and refuses any request it cannot match to a running command. The prompt string that `sudo` hands the helper is ignored, because that string comes from the child, which is the side being asked about.

**Naming the command means rendering it, not printing it.** The argv is the caller's, and the question goes to a terminal, which acts on any control sequence it receives. Most of the argv has been through the redactor. Two things survive that, and either is enough to do harm: a bare `\r`, which returns the cursor so the rest of the line overwrites what came before it, and `ESC` followed by a byte outside `@-Z` and `\-_`, including `ESC c`, a terminal reset that on many emulators clears the scrollback. So every caller-chosen part of a question is quoted as soon as it holds anything but printable text, ordinary arguments are left bare, and the command is bounded in length, with the audit record keeping the whole of it. [internal/termsafe](../internal/termsafe/termsafe.go) holds the same rule for `faramir logs`, where recorded output is escaped rather than quoted and never bounded, because that text is what the operator asked to read.

Five easier designs, and why each was rejected:

Rejected | Why
--- | ---
A time window | `timestamp_timeout=0`, so sudo's own credential cache never decides this. An agent can start a brokered command inside a window in which escalation is assumed, using an approval a human gave for something else.
The caller's terminal | The agent owns that process tree, so a password typed into it is one the agent can read.
`systemd-ask-password` | Asking through it means creating a file in `/run/systemd/ask-password`, `0755 root:root`. A broker running as its own uid is refused, so every request would be denied because there is nobody to ask. What that channel offers is a reply socket only root can write to, and `SO_PEERCRED` provides that directly.
A managed secret | The executor can request the same injection the agent can, so anything injectable is reachable by the agent. A sudo password in the store gives root to any brokered command that requests it.
A password at all | A bearer credential. Wherever it is kept, a command approved once can read it, keep it, and leave it for a later command that was not approved: same uid, shared `PrivateTmp`, shared working tree, `sudo -S`, root. What satisfies `sudo` here is a decision, and a decision cannot be carried.

**How the PAM stack fails matters more than how it works.** Two settings decide whether it gates anything:

- `requisite`, never `sufficient`. With `sufficient`, a helper that *refuses* is not fatal: the stack falls through to the `pam_permit` beneath it and every escalation is granted without asking anybody.
- `seteuid`, because `pam_exec` otherwise runs the helper with the real uid, which under setuid `sudo` is the executor's own. The broker answers `escalate` only to root, so the helper would be refused and nothing on the host could sudo. It also keeps the deciding process out of reach of the uid being decided about.

`faramir doctor` fails on either. Everything else fails closed by construction: an unreachable broker, a request no run owns, a refusal and a timeout all exit non-zero, and nothing authenticates except by reaching `pam_permit` past a `requisite` that succeeded.

The PAM service is faramir's own, so a mistake in it reaches the executor and no other account. Everyone else's `sudo` authenticates as it did before the install. What sends the executor to that service depends on the host ([the two sudos](escalation.md#the-two-sudos)). Under the original sudo it is `pam_service=` in the sudoers entry, which touches nothing shared. Under sudo-rs it is a delimited block in `/etc/pam.d/sudo`, a file the distribution owns. The block tests the account and falls through for everybody else, so the reach is the same but the exposure is not, and `doctor` re-checks that the block still says what it should.

Removing the service file falls back to `/etc/pam.d/other`, and `doctor` fails if that fallback authenticates unconditionally.

### What the escalation does not reach

There are two ways an escalation could go past the one command it named. They have different answers.

**A second, unapproved command using it: closed.** Every brokered command runs as `faramir-exec`, so whatever attributes a `sudo` to a run cannot be something the command holds. A value in an environment is readable within a uid, and one process of that uid can hand it to another. So nothing is held. A run is named by the process the executor forked, and a `sudo` is attributed by its own ancestry, which the kernel supplies and no process chooses for itself.

The approved run's own process tree is still reachable. A same-uid process that can `ptrace` into that tree is inside the run as far as an escalation is concerned. `ptrace_scope` and `PR_SET_DUMPABLE=0`, below, cover that.

**On top of that, the broker serialises.** An escalation takes only when its run is the sole brokered command in progress. While one is live, every other brokered command is refused with `escalation_in_progress`. That refusal is terminal rather than a `busy` to retry: a caller retrying against a live escalation would poll exactly the interval the serialisation protects. Registering a run blocks a new escalation, and a live escalation blocks a new registration, under one lock. A *pending* question also holds new commands, because a caller free to keep starting commands could decide whether the host is ever quiet enough for a yes to take. The cost is that one unanswered question stalls unrelated brokered work for up to `[sudo] timeout_sec`.

Four things follow:

- **A pid names a run only while its holder is alive.** Attribution is by ancestry, so the executor has to match a pid the helper walked against what it forked, and the kernel can reuse a pid once the process holding it is reaped. A pidfd taken before the exec resolves it: it names the process rather than the number ([owner](protocol.md#the-executor-socket)). A number that went to something else fails the check rather than passing it. A kernel without `CLONE_PIDFD` leaves the run unowned, so nothing inside it can sudo.
- **No question that could only be refused.** A `sudo` arriving while another run is registered is refused immediately rather than filing a question that could only be answered no. So there is one question at a time and never a queue. Requests from the *same* run join that run's question, which is why one approval covers a playbook's twenty become'd tasks.
- **Serialisation is checked against the kernel, not trusted.** The bookkeeping can drift from the process table: a drain that does not finish, a run aborted from the broker's side, the broker restarting while the executor is still killing a run. So before an escalation takes, the broker asks the executor whether the host is [quiescent](protocol.md#the-executor-socket) rather than reading its own bookkeeping. Every failure is a no.
- **The cgroup is the only reaper, with no fallback.** A brokered command is spawned into a cgroup of its own (clone3's `CLONE_INTO_CGROUP`, with the unit granted `Delegate=`), then killed and drained when the run ends, so a `setsid` child that left the process group is reaped with it. A process group is a weaker grouping that the same `setsid` escapes, so a run that cannot be confined is *refused*, on every host, grant or not. This needs cgroup v2 and `cgroup.kill`, kernel 5.14 or newer.

**The executor daemon is the one exception, closed differently.** It runs as the uid every brokered command runs as, sits in no run's cgroup, and receives each run's whole environment over its socket, so it is the single process from which every run's injected values could be read. `PR_SET_DUMPABLE=0`, set by both daemons at startup, refuses a brokered command reaching *into* it: it blocks same-uid `ptrace` whatever `ptrace_scope` says (`0` on RHEL, Fedora and Arch). A seccomp filter is not an option on a host installed with `--allow-sudo`: refusing the syscall that way forces `NoNewPrivileges=` on, which makes `sudo` inert.

**The approved command itself persisting root: not closable.** It spends its legitimate root once and installs a setuid-root binary, a `systemd` unit, a `cron` entry or a line in `sudoers`. None of that involves faramir again or ends when the run does. Configuring a host and backdooring it use the same primitives, so no sandbox tells them apart without an allowlist of exactly which files, which is not "run a playbook". Any credential would be defeated the same way.

So the scope is: the command a human approves is trusted with permanent root on this host. Serialisation keeps every *other* command out of that trust. Nothing confines the approved command itself. `--allow-sudo` belongs where that command is operator-owned and read-only to brokered commands.

The uid stays the bound. `faramir-exec` gains the ability to *ask*, not the ability to sudo, and the ask is answered by an account the agent cannot become. What remains is operational: an operator with `NOPASSWD` sudo or a valid sudo timestamp has already given the agent that account, and a watcher left in a terminal the agent can type into is a prompt the agent can answer. A passwordless sudoers grant for the executor's account, `NOPASSWD` or `Defaults !authenticate`, would remove all of this in one line, so `faramir doctor` checks that account for either spelling, whether or not this host was installed with `--allow-sudo`.
