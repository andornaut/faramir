# Coding agents

Every agent gets the same treatment: each command is rewritten so that its output is redacted. What differs per agent is the tool that runs a command, the reply format that tool expects, and where the configuration is registered. One program, `faramir guard`, answers in all of these formats.

The [README](../README.md#supported-agents) lists the supported agents and what enrolling each costs. [design.md](design.md#how-the-rewrite-works) explains how the rewrite works. [layout.md](layout.md) lists which file each agent reads.

## What each agent gets

**Yes** means faramir does it and it was verified against the agent. **No**
means the agent cannot do it. **N/A** means the agent does not need it.

Feature | agy | Antigravity IDE | Claude Code | Codex | Kilo Code | opencode | pi
--- | --- | --- | --- | --- | --- | --- | ---
Command routed through the broker | Yes | Yes | Enrolled trees | Enrolled trees | Yes | Yes | Yes
Its output redacted | Yes | Yes | Enrolled trees | Enrolled trees | Yes | Yes | Yes
Deny list refuses a command | Yes | Yes | Yes | Yes | Yes | Yes | Yes
A backgrounded command streams rather than buffering | Yes | Yes | Yes | Yes | Yes | Yes | Yes
File tools refused | Yes | Yes | Yes | Yes | Yes | Yes | Yes
&nbsp;&nbsp;by a rule file the agent enforces | Yes | No | Yes | No | No | No | No
&nbsp;&nbsp;by faramir itself | Yes | Yes | Yes | Yes | Yes | Yes | Yes
The route reaches the agent | Yes | Yes | Yes | Yes | Yes | Yes | Yes
Credentials section in the file it reads | Yes | Yes | Yes | Yes | Yes | Yes | Yes
Enrolment costs a permission prompt | N/A | N/A | Bash | Bash | N/A | N/A | N/A
Configuration written into a tree | None | None | The routing hook | The routing hook | None | None | None
Runs a hook only once told to trust it | No | No | No | Yes | N/A | N/A | N/A

Unless a cell says otherwise, everything in the table is account-wide:
`faramir init` installs the guard into a home, and it applies in every
directory the agent works in. An enrolment adds the credentials section and
shares the tree with the broker's account.

Four rows need explanation.

**Deny list refuses a command.** Applies everywhere, for every agent. This is
what a `[[secret.block]]` entry is for: it describes the host, and the agent
may work in any directory on it.

**Command routed, and its output redacted.** Applies everywhere except on
Claude Code and Codex, where it applies only in enrolled trees. Their hooks
return a permission decision, so a hook that rewrites a command must also
approve it, and that approval covers every command the deny list does not
name. Claude Code refuses the permission rule that would approve the rewrite
instead, with "'source' evaluates arguments as shell code". So on those two
agents routing suppresses the Bash permission prompt, and the operator accepts
that per tree, by enrolling it. Account-wide, they run `faramir guard
--deny-only`, which refuses what the list names and says nothing about any
other command, so the agent's own permission flow is unchanged.

**File tools refused.** Faramir refuses them for every agent, through a hook,
a plugin or an extension installed in a home. All of these ask `faramir
guard`, which checks the same list by the shape of the tool call, not by tool
name.

Where an agent has a rule file of its own, faramir writes the same paths there
as well. Which agents have one:

Agent | Rule file
--- | ---
Claude Code, Antigravity CLI | Yes, and it refuses the paths
Antigravity IDE, pi | None
Codex | None. Its `.rules` files are an exec policy: they decide commands and cannot name a path
opencode, Kilo Code | Yes, but a `deny` entry is a prompt to the operator, and an autonomous run approves it

Where both a rule file and the hook exist, both apply. The duplication is
deliberate. Claude Code enforces a deny rule in every permission mode,
`bypassPermissions` included, and so does the hook, but the two fail in
different ways: a hook that is turned off, unreadable or slow answers nothing,
and a rule refuses a path the hook never saw. The rule file also records in one
place what the operator asked for.

A Claude Code path rule takes two leading slashes. One anchors the pattern at
the settings source, so `Read(/home/op/.age)` in `~/.claude/settings.json` asks
about `~/.claude/home/op/.age` and refuses nothing.

For the same reason the hook is registered for every tool, not for the shell
alone. An empty reply leaves a call unchanged, so answering for a tool that
runs no command has no effect, and matching every tool is what makes the file
tools reach the deny list. `faramir doctor` reports a Claude Code registration
that matches less than every tool: an enrolment written by an older version
matches `Bash` only, so its file tools never reach the guard.

**Runs a hook only once told to trust it.** Codex only. It skips a hook it has
not been told to trust and does not say so, so what faramir writes does
nothing until you start Codex once and trust the hook. `faramir init` and
`faramir enrol` say so on every run.

## Which agents an install configures

`--agent` defaults to `auto`: configure the agents that are already present,
and nothing else. The two commands look in different places, because agents
keep project and account configuration apart. opencode, for example, keeps
`opencode.json` beside a project and `.config/opencode` under a home.

Command | Where `auto` looks
--- | ---
`faramir init` | the operator's home
`faramir enrol` | the tree, and the home for an agent that keeps nothing beside a project

Codex is that agent: the only thing a tree carries for it is the hook an
enrolment writes, so looking in the tree would only find Codex where it was
already enrolled. `auto` reads `~/.codex` instead. The enrolment record is
separate: it counts only what the tree carries, so a tree does not record an
agent it never had.

Naming an agent configures it whether or not it is installed, which is how a
tree is prepared for an agent before the agent is there. A name composes with
`auto`, so `--agent auto --agent pi` means "whatever is installed, plus pi".
Detection only ever adds. An unknown name is an error, not a skip.

## The rules, and the prose that explains them

Beside the rules, faramir writes a section of prose saying what they refuse
and why. A model given a refusal and no explanation tries another route:
another tool, an interpreter, a base64 pipe.

There are two such sections:

- **The account-wide one**, in the file each agent reads for every project. In
  a tree that has never been enrolled, this is the only thing faramir says: the
  deny rules still apply there, and there is no route to describe.
- **The tree's own**, written by `enrol`. It is longer, because in an enrolled
  tree there is a route to describe.

A tree's own file is whichever of `AGENTS.md` and `CLAUDE.md` it already has.
Three agents also read a file of their own beside it and get the section there
as well:

Agent | File
--- | ---
Claude Code | `CLAUDE.md`
Codex | `AGENTS.md`
Antigravity | `.agents/rules/faramir.md`

Every one of these carries the same section. An operator who keeps a single
file for every agent can symlink `CLAUDE.md` to `AGENTS.md`, and the section
is written once into the file both names reach. Two agents' *settings* files
linked that way are refused: they hold different content, and only the last
write would survive.

### One list, rendered per agent

What the rules name is written once, in
[internal/agentcfg/protectedpaths.go](../internal/agentcfg/protectedpaths.go),
and rendered into each agent's own syntax from there. A copy per agent would
drift, and the drift would be silent: a rule that covers nothing looks like a
rule that covers everything, one character apart.

No pattern is compiled in. The list is the directories this install occupies,
taken from the layout so they are this host's real paths, plus the file each
`[[secret.link]]` entry reads and every `[[secret.block]]` entry the operator
declared.

Five agents cannot rely on a rule file: pi, Codex and the Antigravity IDE have
none, and on opencode and Kilo Code a `deny` rule is a prompt that an
autonomous run approves. So faramir applies the same list for every agent
itself, by the shape of the tool call rather than by tool name: a call
carrying a path is checked whatever the tool is called. No agent carries a
copy of the list. The hook, the plugin and the extension all ask `faramir
guard`, which checks the path both as a read and as a write, so one
implementation answers for every agent.

### What a rule matches

A declared path covers itself and everything under it. It is refused in every
spelling a shell expands to it: `~/`, `$HOME/` and `${HOME}/`. A path under a
home whose tail contains a `/` or starts with a dot is also refused by that
tail alone, so `cd $HOME && cat .ssh/id_rsa` is refused like the absolute
form. The tail is matched wherever it appears, so the same tail under another
root is refused too: on a host with several homes, `/home/other/.ssh/id_rsa`
is refused by this account's entry, and the refusal names that entry rather
than the file the command touched. That is intended. The same looseness
catches a path built from a variable, such as `$PWD/.ssh/id_rsa`, because a
rule has no working directory to tell the two apart. A space in a path is
matched both quoted and backslash-escaped. See
[configuration.md](configuration.md#blocked-paths).

A path this install names is a literal, so the guard tries the spellings that
name the same file: as the tool gave it, with `~` expanded, and with dot
segments and doubled separators removed. A relative path is resolved against
the directory the payload names, where the host sends one, and otherwise
against the guard's own working directory. The plugin and the extension run
inside the agent's own process, so the guard's working directory is the one
the call meant. A hook host runs the guard as a separate program and does not
define its working directory, so a hook host that names no directory has a
relative path checked as written.

The path is checked both as a read and as a write. A file tool does both, and
the two are separate rules: the plugin, the extension and the hook an
enrolment installs are refused as the target of a write, and they are the only
thing that refuses those agents' file tools. Codex's hook file is also a
tree's own file, so one spelling covers `~/.codex/hooks.json` and a project's
`.codex/hooks.json`.

Where an agent has a rule file of its own, that agent does the matching. Which
spellings it catches is the agent's answer, not faramir's.

### A file two agents share

A file two agents both read is written once, and claims only what is true for
both. Telling one agent that its file tools are refused everywhere would tell
the other something false. Antigravity's two halves are the case:
`~/.gemini/GEMINI.md` and `~/.gemini/config/hooks.json` are each written once
for the family, whichever half `--agent` named.

A rules file faramir creates carries the frontmatter that makes it always-on.
That frontmatter decides whether the model is shown the file at all.

## opencode, Kilo Code and pi

These three have no hook that runs a program. Instead, a plugin inside the
agent's own process blocks a call or changes one by mutating its arguments. The
plugin asks the guard and applies the answer:

```json
{"decision": "deny", "reason": "<what the model is told>"}
{"decision": "rewrite", "tool_input": {"command": "source .../wrap.sh '<command>'"}}
```

A rewrite carries back every field of the original tool input with only
`command` replaced. No output means the call is left alone.

Every other answer fails closed: a guard that cannot be run, a non-zero exit,
an answer that is not JSON, a rewrite naming no command, or a decision the
plugin does not recognise. The last covers version skew, which is why
`faramir init` [comes before enrolling one of
these](operating.md#rules-a-command-does-not-state).

opencode and Kilo Code load a JavaScript plugin, which blocks by throwing. Pi
loads a TypeScript extension, which blocks by returning `{ block: true, reason
}`. All three are installed in a home and loaded for every project. Each
applies a decision the guard made; none decides anything itself.

## Claude Code

**The deny list replaces the Bash permission prompt.** Claude Code matches its
permission rules against the rewritten command, and the wrapper is sourced, so
three things follow:

- **A sourced command cannot be allow-listed.** Claude Code refuses one whatever
  rules exist, saying `'source' evaluates arguments as shell code`. Only the
  hook's own allow runs it.
- **A rule keyed on the program name no longer fires.** The list of wrappers
  Claude Code strips before matching (`timeout`, `nice`, `nohup` and a few
  more) is built in and not configurable, so `Bash(npm test *)` does not match
  a wrapped `npm test`. The one rule shape that could match a wrapper approves
  every command inside it, which is the blanket approval written out longer.
- **The built-in read-only set is lost with it.** A wrapped `ls` is not `ls`, so
  it needs approval like anything else.

Returning `ask` does reach a prompt, and an operator willing to answer one per
command could have it. What it cannot have is a way to stop: "don't ask again"
saves a rule that can never match, the prompt shows the rewritten text rather
than what was typed, and an unattended run stops at the first command.

Hooks fire in every Claude Code permission mode and a `deny` is enforced in
each, `--dangerously-skip-permissions` included. What enrolment removes from
the permission flow depends on the mode:

Mode | Cost
--- | ---
`default` | Bash would have prompted and now does not. This is what the warning is about.
`acceptEdits` | Auto-accepts `Write` and `Edit`, leaves Bash prompting. Same cost as default.
`auto` | Bash goes to a classifier rather than to a prompt, so no prompt is removed. See below.
`plan` | Edits stay blocked either way. Commands go to the classifier where auto mode is available.
`dontAsk` | Everything unlisted is denied, so the hook's allow is what runs a command at all.
`bypassPermissions` | Bash never prompted, so approving it removes nothing. Enrolment is purely additive.

`auto` is the mode a session starts in on most plans, and its cost is the one
line here that is not established. A classifier reviews each command instead of
prompting, and whether the hook's `allow` preempts that review is not
documented and was not settled by testing: every probe was an action the
operator had asked for, which the classifier permits with or without the hook.
Until it is settled, assume enrolment may remove the classifier's review of a
command as well as the prompt.

## Codex

Codex uses Claude Code's hook contract: the payload names the tool and puts
its input beside it, a decision goes back under `hookSpecificOutput`, and a
rewrite is `updatedInput`, which replaces the call's arguments. So the
enrolment has the same shape, for the same reason. The account gets a
deny-only hook in `~/.codex/hooks.json`, which Codex reads wherever it works;
an enrolled tree gets the routing hook in its own `.codex/hooks.json`. Both
files load and both hooks run, the account's first. The only overhead is a
second pass over the deny list.

Three things differ.

**There is no rule file.** Codex's `.rules` files are an exec policy: they
decide commands and cannot name a path, so nothing an install writes can say
"not this file". The hook is the only thing that refuses Codex a path, which
is why it matches every tool rather than `Bash`.

**Files are written through `apply_patch`, whose input is a patch rather than
a command.** The tool applies the patch itself, so there is nothing to route.
The files it writes are named in the envelope's `Add File`, `Update File`,
`Delete File` and `Move to` headers, and those are what the deny list is
checked against. The patch body is never scanned as a command line: otherwise
a patch that adds documentation quoting `rm /etc/faramir/config.toml` would be
refused for what the documentation says. It is never rewritten either: run
through the wrapper, the result would be a patch that no longer applies.

A patch the guard cannot parse is refused. This check is the only thing that
refuses Codex a path, so an envelope the guard cannot read would otherwise
leave every write unexamined.

The tool can also be invoked from a shell, and the documented form puts the
envelope in a heredoc. The body is split into commands like any other, and a
patch header is not a command: `*** Add File: <path>` names a path and nothing
else. Naming a declared path is what the rule refuses, so a header naming one
is refused wherever it appears in a command the guard reads. A command that
runs the patch tool has its headers read the same way the tool's own call
does.

Reads need none of this. Codex reads a file by running one of the shell's own
readers, so the guard covers every read it makes.

**A hook has to be trusted before it runs.** Codex skips a hook it has not
been told to trust and does not say so, so what `faramir init` and `faramir
enrol` write does nothing until you start Codex once and trust it. The trust
is a hash of the hook as Codex parses it, so you must grant it, and grant it
again after any change. Both commands say so on every run, and `faramir
doctor` fails on a hook that is still untrusted: it is the only
misconfiguration here that produces no refusal, no failed play and no degraded
ref, so nothing else would report it.

> [!IMPORTANT]
> **Codex must run without its own sandbox** (`codex --dangerously-bypass-approvals-and-sandbox`). Sandboxed, it cannot reach the broker socket: `read-only` and `workspace-write` both deny the `AF_UNIX` connect and deny writes to `XDG_RUNTIME_DIR`, and `network_access` governs `AF_INET` only and does not lift it. The wrapper fails closed, so every command's output is withheld rather than redacted.

Enrolling removes the same permission prompt it removes on Claude Code, and
only where Codex runs with approvals on: the hook that rewrites a command must
approve it, and that approval covers every command the deny list does not
name. With approvals bypassed there is no prompt, so enrolling removes
nothing.

## Antigravity

Two agents, one contract. The CLI (`agy`) and the IDE share one hook contract
and one permission syntax, so one tree enrolment serves both: the same
`PreToolUse` registration and the same prose. Naming either writes the same
files, so enrolling one does not report the other as unconfigured.

The hook returns `overwrite` beside its decision: a shallow merge into the
tool call's own arguments, and the merged form is what runs. So `run_command`
is rewritten to `source .../wrap.sh --stream-state '<command>'`, as Claude
Code's `Bash` is rewritten to `source .../wrap.sh '<command>'`, and the output
comes back redacted. No other tool carries a command, and the guard rewrites
no other tool.

Every `run_command` is rewritten to `--stream-state`, which redacts live while
the command runs in the host's persistent shell. `run_command` carries a wait
after which the host runs the command asynchronously and polls it, so a long
build shows its output as it runs, and an `export` still survives the call. A
trailing `&` streams as it does everywhere.

The registration matches every tool rather than naming `run_command`, so a
payload the guard cannot read is refused rather than passed, whatever tool it
arrived on.

The permission check runs before the hook. A command no rule permits is
refused before the guard is asked, so the guard's allow approves nothing that
was going to prompt. Unlike Claude Code, enrolling takes nothing away.

The two halves differ in the rule file; the
[README](../README.md#supported-agents) says which half gets one. The CLI
reads `~/.gemini/antigravity-cli/settings.json` and gets deny rules there as
well as the hook. The IDE keeps its permission lists as internal state, so it
gets no rule file, and the hook is its only protection.

The hook goes into `~/.gemini/config/hooks.json`, which both halves read for
every workspace, so the guard applies before any enrolment. What an enrolment
writes into a tree is the credentials section. Both halves load a tree's
customizations only once that tree is a project they have opened, and the
enrolment says so.

### What a rule can name

The CLI's rules are `read_file(<path>)` and `write_file(<path>)`. A path names
the hierarchy under it: a rule on a directory refuses every file below it, at
any depth.

A trailing wildcard does not. `read_file(<dir>/*)` matches nothing, not even
the files directly in that directory, so a rule written that way looks
protective and refuses nothing. What faramir renders is paths from the layout:
the install's own directories, and the file each `[[secret.link]]` and
`[[secret.block]]` entry names, each covering what is under it. A path entry
carrying a wildcard is passed through as written, and one whose wildcard is
not leading matches nothing here. So a prefix entry ending in `*` renders a
rule this syntax cannot read. That loses nothing: this family's file tools are
refused by the hook rather than by these rules, on both halves, and the hook
is asked the same question every other agent's is. The rule is written anyway
so the file records what the operator declared, and so a release that adds
trailing wildcards to the syntax needs no change here.
