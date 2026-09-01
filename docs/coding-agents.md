# Coding agents

Every agent gets the same thing: each command is rewritten so that its own output is redacted. What differs is the tool that runs a command, the shape of the reply that tool expects, and where the configuration is registered. One program, `faramir guard`, speaks all of these dialects.

Which agents are supported, and what enrolling each costs, is the table in the [README](../README.md#supported-agents). How the rewrite is shaped, and why, is in [design.md](design.md#how-the-rewrite-works). Which file each agent reads is in [layout.md](layout.md).

## What each agent gets

**Yes** means faramir does it and it was verified against the agent. **No**
means the agent cannot do it and nothing here pretends otherwise. **N/A** means
the agent needs no such thing.

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

Everything here is account-wide unless a cell says otherwise: `faramir init`
installs the guard into a home, and it holds in every directory the agent works
in. An enrolment adds the prose, and shares the tree so the broker's own account
can reach it.

Four rows need reading carefully.

**Deny list refuses a command.** Everywhere, for every agent. This is what a
`[[secret.block]]` entry is for: the entry describes the host, and an agent
wanders into directories nobody pointed faramir at.

**Command routed, and its output redacted.** Everywhere except Claude Code and
Codex, where it is what an enrolment buys. Their hooks return a permission
decision, so a hook that rewrote a command has to approve it, and the approval
covers every command the deny list does not name; Claude Code refuses the
permission rule that would approve the rewrite instead, saying "'source'
evaluates arguments as shell code". So routing costs a permission on those two
and nowhere else, and an operator takes that trade one tree at a time.
Account-wide they run `faramir guard --deny-only`, which refuses what the list
names and says nothing about anything else, leaving the host's own permission
flow as it was.

**File tools refused.** By faramir, for every agent, through a hook, a plugin or
an extension installed in a home, all asking the same `faramir guard` and
checking the same list by the shape of the tool call rather than by tool name.

A rule file in the agent's own settings is written as well where the agent has
one, and refuses the same paths. Claude Code and the Antigravity CLI have one.
The Antigravity IDE and pi have no such file at all; Codex has none either, its
own `.rules` files being an exec policy that decides commands and names no path.
opencode and Kilo Code have one and it is not a refusal: an entry of `deny` is
put to the operator as a prompt, and an autonomous run approves it.

Where both exist, both hold, and the duplication is the point. A rule file is
applied in some of the permission modes an agent runs in and not in others: a
Claude Code session started in `bypassPermissions` applies none of its deny
rules, so a rule there says what the operator asked for without being what
happens. A hook is run in every mode. The rules stay because they are what
refuses a read in a session that never reaches the hook, and because they say in
one file what the operator asked for.

This is why the hook is registered for every tool rather than for the shell
alone. An empty reply is a call left alone, so answering for a tool that runs
nothing costs nothing, and matching every tool is what puts the file tools in
front of the deny list at all. `faramir doctor` reports a registration that
matches less than that: an enrolment written by an older version matches `Bash`,
and its file tools reach the guard through nothing.

**Runs a hook only once told to trust it.** Codex alone. It skips a hook it has
not been trusted with and says nothing when it does, so what faramir writes is
inert until you start Codex once and trust it. Both commands say so on every
run, because nothing else would.

## Which agents an install configures

`--agent` defaults to `auto`: configure the agents that are already there, and nothing else. The two commands look in different places, because agents keep project and account configuration apart. opencode, for example, keeps `opencode.json` beside a project and `.config/opencode` under a home.

Command | Where `auto` looks
--- | ---
`faramir init` | the operator's home
`faramir init-project` | the tree, and the home for an agent that keeps nothing beside a project

Codex is that agent: the only thing a tree can carry for it is the hook an enrolment writes, so a tree asked on its own could only ever report Codex where Codex was already enrolled. `auto` reads `~/.codex` instead. The enrolment record is a separate question and still counts only what the tree carries, so a tree does not keep an agent it never had.

Naming an agent configures it whether or not it is installed, which is how a tree is prepared for an agent before the agent is there. A name composes with `auto`, so `--agent auto --agent pi` means "whatever is installed, plus pi". Detection only ever adds, so the two never have to be ranked. An unknown name is an error rather than a skip, which would leave you believing something is covered.

## The rules, and the prose that explains them

Beside the rules, faramir writes prose saying what they refuse and why. A model given a refusal and no explanation tries the next route: another tool, an interpreter, a base64 pipe.

There are two such sections:

- **The account-wide one**, in the file each agent reads for every project. In a tree `init-project` has never been run in, this is the only thing faramir says: the deny rules still hold there, and there is no broker to point at.
- **The tree's own**, written by `init-project`. It is the longer of the two, because in an enrolled tree there is a route to name.

A tree's own file is whichever of `AGENTS.md` and `CLAUDE.md` it already has. Three agents read a name of their own beside it and get one there as well: Claude Code a `CLAUDE.md`, which is the name it reads and `AGENTS.md` is not, Codex an `AGENTS.md`, which is the mirror image, and Antigravity a `.agents/rules/faramir.md`. Every one of these carries the same section, so an operator who keeps a single file for every agent links `CLAUDE.md` at `AGENTS.md` and the section is written once into the file both names. Two agents' settings files linked that way are refused instead: those are different bytes, and only the last write would survive.

### One list, rendered per agent

What the rules name is written once, in [internal/agentcfg/protectedpaths.go](../internal/agentcfg/protectedpaths.go), and rendered into each agent's own spelling from there. A copy per agent would drift, and the drift is silent: a rule that covers nothing looks exactly like a rule that covers everything, one character apart.

No pattern is compiled in. The list is the directories this install occupies, taken from the layout so they are this host's real paths, plus the file each `[[secret.link]]` entry reads and every `[[secret.block]]` entry the operator declared.

Five agents cannot rely on a rule file: pi, Codex and the Antigravity IDE have none to write, and on opencode and Kilo Code a rule of `deny` is a prompt an autonomous run approves. Faramir applies the same list for every agent, and applies it by shape rather than by tool name: a tool call carrying a path is checked whatever the tool is called. None of them carries a copy of the list. The hook, the plugin and the extension all ask `faramir guard`, which puts the question as a read of that path and as a write to it, so one implementation answers for every agent and cannot drift from another.

### What a rule matches

A declared path covers itself and everything under it, and is refused in the spellings a shell expands to it: `~/`, `$HOME/` and `${HOME}/`. A path under a home whose tail holds a `/` or opens on a dot is refused by that tail as well, so a `cd` first buys nothing: `cd $HOME && cat .ssh/id_rsa` is refused as the absolute form is. That tail is matched wherever it appears, so the same tail under another root is refused with it: on a host with several homes, `/home/other/.ssh/id_rsa` is refused by this account's entry, and the refusal names that entry rather than the file the command touched. It reads like a mismatch and is not one. The looseness is what also catches a path built from a variable, `$PWD/.ssh/id_rsa` among them, and a rule has no working directory to tell the two apart. A space in one is matched quoted and backslash-escaped alike, both reaching the same file. See [configuration.md](configuration.md#blocked-paths).

A path this install names is a literal, so the guard tries the spellings that mean the same file: as the tool gave it, with `~` expanded, and with dot segments and doubled separators removed. A relative path is resolved as well, against the directory the payload names where the host sends one and otherwise against the guard's own: the plugin and the extension run inside the agent's own process, so the guard's working directory is the one the call meant, and a hook host runs the guard as a program of its own and promises nothing about where. A hook host that names no directory has a relative path asked about as written.

The question is put both ways, as a read of the path and as a write to it. A file tool does both, and the two are separate rules: the plugin, the extension and the hook an enrolment installs are refused to a write, and they are the only thing refusing those agents' file tools. Codex's is the one that is also a tree's own file, so one spelling covers `~/.codex/hooks.json` and a project's `.codex/hooks.json`.

Where an agent has a rule file of its own, that agent does the matching. Which spellings are caught there is its answer, not faramir's.

### A file two agents share

A file two agents both read is written once, and claims only what holds for both. One telling one agent that its file tools are refused everywhere would be telling the other something false. The two halves of Antigravity are the case: `~/.gemini/GEMINI.md` and `~/.gemini/config/hooks.json` are each written once for the family, whichever half the enrolment named.

A rules file faramir creates carries the frontmatter that makes it always-on, which is what decides whether the model is shown it at all.

## opencode, Kilo Code and pi

These three have no hook that runs a program. A plugin inside the agent's own process blocks a call and changes one by mutating its arguments, so it asks the guard and applies the answer:

```json
{"decision": "deny", "reason": "<what the model is told>"}
{"decision": "rewrite", "tool_input": {"command": "source .../wrap.sh '<command>'"}}
```

A rewrite carries back every field of the original tool input with only `command` replaced. Writing nothing means the call is left alone.

Every other answer fails closed: a guard that cannot be run, a non-zero exit, an answer that is not JSON, a rewrite naming no command, a decision the plugin does not recognise. That last one covers version skew, which is why `faramir init` [comes before enrolling one of these](operating.md#rules-a-command-does-not-state).

opencode and Kilo Code load a JavaScript plugin, which blocks by throwing. Pi loads a TypeScript extension, which blocks by returning `{ block: true, reason }`. All three are installed in a home and loaded for every project; each translates a decision the guard made, and none of them decides anything.

## Claude Code

**The deny list replaces the Bash permission prompt.** Matching runs against the rewritten command, so a rule keyed on the program name no longer fires, and the wrapper cannot be allow-listed. There is no `ask` to return instead: it would prompt on every command including `ls`, show the rewritten text rather than what was typed, and strand an unattended run on the first command.

Hooks fire in every Claude Code permission mode and a `deny` is enforced in each, `--dangerously-skip-permissions` included, so what enrolment costs depends on the mode:

Mode | Cost
--- | ---
`default` | Bash would have prompted and now does not. This is what the warning is about.
`acceptEdits` | Auto-accepts `Write` and `Edit`, leaves Bash prompting. Same cost as default.
`bypassPermissions` | Bash never prompted, so approving it removes nothing. Enrolment is purely additive.

## Codex

Codex reads Claude Code's hook contract: the payload names the tool and flattens its input beside it, a decision goes back under `hookSpecificOutput`, and a rewrite is `updatedInput`, which replaces the call's arguments. So the enrolment is shaped the same way and for the same reason. The account gets a deny-only hook in `~/.codex/hooks.json`, which Codex reads wherever it is working; an enrolled tree gets the routing one in its own `.codex/hooks.json`. Both files load and both hooks run, the account's first, which costs a second pass over the deny list and nothing else.

Three things differ.

**There is no rule file.** Codex's `.rules` files are an exec policy: they decide commands and name no path, so nothing an install writes can say "not this file". The hook is the whole of what refuses Codex a path, which is why it matches every tool rather than `Bash`.

**Files are written through `apply_patch`, whose input is a patch rather than a command.** The tool applies it itself, so there is nothing to route, and the files it writes are named on the envelope's own `Add File`, `Update File`, `Delete File` and `Move to` headers. Those are what the deny list is asked about; the patch is never scanned as a command line, or a patch that adds documentation quoting `rm /etc/faramir/config.toml` would be refused for what the documentation says. It is never rewritten either: fed through the wrapper, what came back would be a patch that no longer applies.

A patch the guard cannot read is refused. This branch is the whole of what refuses Codex a path, so an envelope that is not where the guard reads it would otherwise leave every write unexamined and say nothing about it.

The tool is also invocable from a shell, and the documented spelling puts the envelope in a heredoc. The body is split into commands like any other, and a patch header is not a command: `*** Add File: <path>` names a path and nothing else. Naming a declared path is what the rule answers, so a header naming one is refused where it appears in a command the guard reads. A command that runs the patch tool has its headers read the same way the tool's own call does.

Reads need none of that. Codex reads a file by running one of the shell's own readers, so the command guard covers every read it makes.

**A hook has to be trusted before it runs.** Codex skips a hook it has not been told to trust and says nothing when it does, so what `faramir init` and `faramir init-project` write is inert until you start Codex once and trust it. The trust is a hash of the hook as Codex parses it, so it is yours to grant and it has to be granted again after a change. Both commands say so on every run, and `faramir doctor` fails on a hook that is still untrusted: it is the only misconfiguration here that produces no refusal, no failed play and no degraded ref, so nothing else would report it.

> [!IMPORTANT]
> **Codex must run without its own sandbox** (`codex --dangerously-bypass-approvals-and-sandbox`). Sandboxed, it is refused the broker socket: `read-only` and `workspace-write` both deny the `AF_UNIX` connect and deny writes to `XDG_RUNTIME_DIR`, and `network_access` governs `AF_INET` alone and does not lift it. The wrapper fails closed, so what that costs is every command's output withheld rather than redacted.

Enrolling costs the same permission it costs on Claude Code, and only where Codex is run with approvals on: the hook that rewrote a command has to approve it, and that approval covers every command the deny list does not name. Run with approvals bypassed, there is no prompt to give away and the trade is free.

## Antigravity

Two agents, one contract. The CLI (`agy`) and the IDE ship a single hook contract and a single permission syntax between them, so one tree enrolment serves both: the same `PreToolUse` registration and the same prose. Naming either writes the same bytes, which is why enrolling one does not report the other as an agent nothing covers.

The hook returns `overwrite` beside its decision, a shallow merge into the tool call's own arguments whose merged form is what runs. So `run_command` is rewritten to `source .../wrap.sh '<command>'` exactly as Claude Code's `Bash` is, and the output comes back redacted. Nothing else carries a command, and the guard answers for nothing else.

Every `run_command` is rewritten to `--stream-state`, which redacts live with the eval kept in the host's persistent shell: `run_command` carries a wait after which the host takes the command async and polls, so a long build shows its output as it runs, and an `export` still survives the call. A trailing `&` streams the way it does everywhere.

The registration matches every tool rather than naming `run_command`. An empty reply is a call left alone here, so answering for a tool that runs nothing costs nothing, and taking every tool is what makes a payload the guard cannot read refuse the call rather than pass it, whatever tool it arrived on.

The permission check runs before the hook. A command with no rule permitting it is refused before the guard is asked, so the guard's allow approves nothing that was going to prompt: enrolling takes nothing away, unlike Claude Code.

Where they differ is the rule file, which is [which half each gets](../README.md#supported-agents). The CLI reads `~/.gemini/antigravity-cli/settings.json` and gets deny rules there as well as the hook. The IDE keeps its permission lists as its own state, so it gets none, and for it the hook is not a second answer but the only one.

The hook goes into `~/.gemini/config/hooks.json`, which both halves read for every workspace, so nothing about guarding one waits on an enrolment. What an enrolment writes into a tree is the credentials section, and both load a tree's customizations only once that tree is a project they have opened, which the enrolment says.

### What a rule can name

The CLI's rules are `read_file(<path>)` and `write_file(<path>)`. A path names the hierarchy under it: a rule on a directory refuses every file below it, at any depth.

A trailing wildcard does not. `read_file(<dir>/*)` matches nothing, including the files directly in that directory, so a rule written that way is one that looks protective and refuses nothing. What this renders is paths out of the layout: the install's own directories, and the file each `[[secret.link]]` and `[[secret.block]]` entry names, each covering what is under it. A path entry carrying a wildcard is passed through as written, and one whose wildcard is not leading matches nothing here.
