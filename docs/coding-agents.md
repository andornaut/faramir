# Coding agents

Every agent gets the same thing: each command is rewritten so that its own output is redacted. What differs is the tool that runs a command, the shape of the reply that tool expects, and where the configuration is registered. One program, `faramir guard`, speaks all of these dialects.

Which agents are supported, and what enrolling each costs, is the table in the [README](../README.md#supported-agents). How the rewrite is shaped, and why, is in [design.md](design.md#how-the-rewrite-works). Which file each agent reads is in [layout.md](layout.md).

## What each agent gets

**Yes** means faramir does it and it was verified against the agent. **No**
means the agent cannot do it and nothing here pretends otherwise. **N/A** means
the agent needs no such thing.

Feature | Claude Code | agy | Antigravity IDE | opencode | Kilo Code | pi
--- | --- | --- | --- | --- | --- | ---
Command routed through the broker | Enrolled trees | Yes | Yes | Yes | Yes | Yes
Its output redacted | Enrolled trees | Yes | Yes | Yes | Yes | Yes
Deny list refuses a command | Yes | Yes | Yes | Yes | Yes | Yes
A backgrounded command streams rather than buffering | Yes | Yes | Yes | Yes | Yes | Yes
File tools refused | Yes | Yes | Yes | Yes | Yes | Yes
&nbsp;&nbsp;by a rule file the agent enforces | Yes | Yes | No | No | No | No
&nbsp;&nbsp;by faramir itself | N/A | Yes | Yes | Yes | Yes | Yes
The route reaches the agent | Yes | Yes | Yes | Yes | Yes | Yes
Credentials section in the file it reads | Yes | Yes | Yes | Yes | Yes | Yes
Enrolment costs a permission prompt | Bash | N/A | N/A | N/A | N/A | N/A
Configuration written into a tree | The routing hook | None | None | None | None | None

Everything here is account-wide unless a cell says otherwise: `faramir init`
installs the guard into a home, and it holds in every directory the agent works
in. An enrolment adds the prose, and shares the tree so the broker's own account
can reach it.

Three rows need reading carefully.

**Deny list refuses a command.** Everywhere, for every agent. This is what a
`[[secret.block]]` entry is for: the entry describes the host, and an agent
wanders into directories nobody pointed faramir at.

**Command routed, and its output redacted.** Everywhere except Claude Code,
where it is what an enrolment buys. Its hook has to approve the command it
rewrote, and the approval covers every command the deny list does not name;
Claude Code refuses the permission rule that would approve the rewrite instead,
saying "'source' evaluates arguments as shell code". So routing costs a
permission there and nowhere else, and an operator takes that trade one tree at
a time. Account-wide it runs `faramir guard --deny-only`, which refuses what the
list names and says nothing about anything else, leaving the host's own
permission flow as it was.

**File tools refused.** By a rule file where the agent enforces one, and by
faramir where it does not. Claude Code and the Antigravity CLI enforce a deny
rule in their own settings. The Antigravity IDE and pi have no such file at all.
opencode and Kilo Code have one and it is not a refusal: an entry of `deny` is
put to the operator as a prompt, and an autonomous run approves it. So every
agent but Claude Code is refused a path by faramir itself, through a hook, a
plugin or an extension installed in a home, all asking the same `faramir guard`
and checking the same list by the shape of the tool call rather than by tool
name. The Antigravity CLI is refused twice, its own rules holding as well.

## Which agents an install configures

`--agent` defaults to `auto`: configure the agents that are already there, and nothing else. The two commands look in different places, because agents keep project and account configuration apart. opencode, for example, keeps `opencode.json` beside a project and `.config/opencode` under a home.

Command | Where `auto` looks
--- | ---
`faramir init` | the operator's home
`faramir init-project` | the tree

Naming an agent configures it whether or not it is installed, which is how a tree is prepared for an agent before the agent is there. A name composes with `auto`, so `--agent auto --agent pi` means "whatever is installed, plus pi". Detection only ever adds, so the two never have to be ranked. An unknown name is an error rather than a skip, which would leave you believing something is covered.

## The rules, and the prose that explains them

Beside the rules, faramir writes prose saying what they refuse and why. A model given a refusal and no explanation tries the next route: another tool, an interpreter, a base64 pipe.

There are two such sections:

- **The account-wide one**, in the file each agent reads for every project. In a tree `init-project` has never been run in, this is the only thing faramir says: the deny rules still hold there, and there is no broker to point at.
- **The tree's own**, written by `init-project`. It is the longer of the two, because in an enrolled tree there is a route to name.

A tree's own file is whichever of `AGENTS.md` and `CLAUDE.md` it already has. Two agents read a name of their own beside it and get one there as well: Claude Code a `CLAUDE.md`, which is the name it reads and `AGENTS.md` is not, and Antigravity a `.agents/rules/faramir.md`. Every one of these carries the same section, so an operator who keeps a single file for every agent links `CLAUDE.md` at `AGENTS.md` and the section is written once into the file both names. Two agents' settings files linked that way are refused instead: those are different bytes, and only the last write would survive.

### One list, rendered per agent

What the rules name is written once, in [internal/install/protectedpaths.go](../internal/install/protectedpaths.go), and rendered into each agent's own spelling from there. A copy per agent would drift, and the drift is silent: a rule that covers nothing looks exactly like a rule that covers everything, one character apart.

No pattern is compiled in. The list is the directories this install occupies, taken from the layout so they are this host's real paths, plus the file each `[[secret.link]]` entry reads and every `[[secret.block]]` entry the operator declared.

Four agents cannot rely on a rule file: pi and the Antigravity IDE have none to write, and on opencode and Kilo Code a rule of `deny` is a prompt an autonomous run approves. All four get the same list applied by faramir instead, and applied by shape rather than by tool name: a tool call carrying a path is checked whatever the tool is called. None of them carries a copy of the list. The hook, the plugin and the extension all ask `faramir guard`, which puts the question as a read of that path, so one implementation answers for every agent and cannot drift from another.

### What a rule matches

A declared name matches as a name, a suffix, a prefix, a wildcard name or a directory, anywhere in a path, so `--name id_ed25519` covers `~/.ssh/id_ed25519` and `.ssh/id_ed25519` as readily as the absolute form. The five shapes are in [configuration.md](configuration.md#a-path-and-a-name-are-different-rules).

A path this install names is a literal, so the guard tries the spellings that mean the same file: as the tool gave it, with `~` expanded, and with dot segments and doubled separators removed. A relative path is asked about as written and never resolved, because resolving it would need the working directory the call meant rather than the guard's.

Where an agent has a rule file of its own, that agent does the matching. Which spellings are caught there is its answer, not faramir's.

### A file two agents share

A file two agents both read is written once, and claims only what holds for both. One telling one agent that its file tools are refused everywhere would be telling the other something false. The two halves of Antigravity are the case: `~/.gemini/GEMINI.md` and `~/.gemini/config/hooks.json` are each written once for the family, whichever half the enrolment named.

A rules file faramir creates carries the frontmatter that makes it always-on, which is what decides whether the model is shown it at all.

## opencode, Kilo Code and pi

These three have no hook that runs a program. A plugin inside the agent's own process blocks a call by throwing and changes one by mutating its arguments, so it asks the guard and applies the answer:

```json
{"decision": "deny", "reason": "<what the model is told>"}
{"decision": "rewrite", "tool_input": {"command": "source .../wrap.sh '<command>'"}}
```

A rewrite carries back every field of the original tool input with only `command` replaced. Writing nothing means the call is left alone.

Every other answer fails closed: a guard that cannot be run, a non-zero exit, an answer that is not JSON, a rewrite naming no command, a decision the plugin does not recognise. That last one covers version skew, which is why `faramir init` [comes before enrolling one of these](operating.md#rules-a-command-does-not-state).

opencode and Kilo Code load a JavaScript plugin. Pi loads a TypeScript extension. All three are installed in a home and loaded for every project; each translates a decision the guard made, and none of them decides anything.

## Claude Code

**The deny list replaces the Bash permission prompt.** Matching runs against the rewritten command, so a rule keyed on the program name no longer fires, and the wrapper cannot be allow-listed. There is no `ask` to return instead: it would prompt on every command including `ls`, show the rewritten text rather than what was typed, and strand an unattended run on the first command.

Hooks fire in every Claude Code permission mode and a `deny` is enforced in each, `--dangerously-skip-permissions` included, so what enrolment costs depends on the mode:

Mode | Cost
--- | ---
`default` | Bash would have prompted and now does not. This is what the warning is about.
`acceptEdits` | Auto-accepts `Write` and `Edit`, leaves Bash prompting. Same cost as default.
`bypassPermissions` | Bash never prompted, so approving it removes nothing. Enrolment is purely additive.

## Antigravity

Two agents, one contract. The CLI (`agy`) and the IDE ship a single hook contract and a single permission syntax between them, so one tree enrolment serves both: the same `PreToolUse` registration and the same prose. Naming either writes the same bytes, which is why enrolling one does not report the other as an agent nothing covers.

The hook returns `overwrite` beside its decision, a shallow merge into the tool call's own arguments whose merged form is what runs. So `run_command` is rewritten to `source .../wrap.sh '<command>'` exactly as Claude Code's `Bash` is, and the output comes back redacted. Nothing else carries a command, and the guard answers for nothing else.

The registration matches every tool rather than naming `run_command`. An empty reply is a call left alone here, so answering for a tool that runs nothing costs nothing, and taking every tool is what makes a payload the guard cannot read refuse the call rather than pass it, whatever tool it arrived on.

The permission check runs before the hook. A command with no rule permitting it is refused before the guard is asked, so the guard's allow approves nothing that was going to prompt: enrolling takes nothing away, unlike Claude Code.

Where they differ is the rule file, which is [which half each gets](../README.md#supported-agents). The CLI reads `~/.gemini/antigravity-cli/settings.json` and gets deny rules there as well as the hook. The IDE keeps its permission lists as its own state, so the hook is the whole of what refuses its file tools.

The hook goes into `~/.gemini/config/hooks.json`, which both halves read for every workspace, so nothing about guarding one waits on an enrolment. What an enrolment writes into a tree is the credentials section, and both load a tree's customizations only once that tree is a project they have opened, which the enrolment says.

### What a rule can name

The CLI's rules are `read_file(<path>)` and `write_file(<path>)`. A path names the hierarchy under it: a rule on a directory refuses every file below it, at any depth.

A trailing wildcard does not. `read_file(<dir>/*)` matches nothing, including the files directly in that directory, so a rule written that way is one that looks protective and refuses nothing. Only literal paths are rendered for this agent, and a `[[secret.block]]` entry naming a pattern rather than a path is reported as one this agent cannot be given.
