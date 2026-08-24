# Coding agents

Every agent gets the same thing: each command is rewritten so that its own output is redacted. What differs is the tool that runs a command, the shape of the reply that tool expects, and where the configuration is registered. One program, `faramir guard`, speaks all of these dialects.

Which agents are supported, and what enrolling each costs, is the table in the [README](../README.md#supported-agents). How the rewrite is shaped, and why, is in [design.md](design.md#how-the-rewrite-works). Which file each agent reads is in [layout.md](layout.md).

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

### One list, rendered per agent

What the rules name is written once, in [internal/install/protectedpaths.go](../internal/install/protectedpaths.go), and rendered into each agent's own spelling from there. A copy per agent would drift, and the drift is silent: a rule that covers nothing looks exactly like a rule that covers everything, one character apart.

No pattern is compiled in. The list is the directories this install occupies, taken from the layout so they are this host's real paths, plus the file each `[[secret.link]]` entry reads and every `[[secret.block]]` entry the operator declared.

Pi has no rule file to write, so its rules are compiled into the extension instead and applied by shape: a tool call carrying a path is checked whatever the tool is called.

### What a rule matches

A declared name matches as a name, a suffix, a prefix, a wildcard name or a directory, anywhere in a path, so `--name id_ed25519` covers `~/.ssh/id_ed25519` and `.ssh/id_ed25519` as readily as the absolute form. The five shapes are in [configuration.md](configuration.md#a-path-and-a-name-are-different-rules).

A path this install names is a literal. Pi tries the spellings that mean the same file: as the tool gave it, with `~` expanded, and with dot segments and doubled separators removed. A relative path is left alone, because resolving it would need the working directory the call meant rather than the extension host's.

Where an agent has a rule file of its own, that agent does the matching. Which spellings are caught there is its answer, not faramir's.

### A file two agents share

A file two agents both read is written once, and claims only what holds for both. One telling one agent that its file tools are refused everywhere would be telling the other something false. No two agents share a file today; the rule stands because the failure it prevents is silent.

A rules file faramir creates carries the frontmatter that makes it always-on, which is what decides whether the model is shown it at all.

## opencode, Kilo Code and pi

These three have no hook that runs a program. A plugin inside the agent's own process blocks a call by throwing and changes one by mutating its arguments, so it asks the guard and applies the answer:

```json
{"decision": "deny", "reason": "<what the model is told>"}
{"decision": "rewrite", "tool_input": {"command": "source .../wrap.sh '<command>'"}}
```

A rewrite carries back every field of the original tool input with only `command` replaced. Writing nothing means the call is left alone.

Every other answer fails closed: a guard that cannot be run, a non-zero exit, an answer that is not JSON, a decision the plugin does not recognise. That last one covers version skew, which is why `faramir init` [comes before enrolling one of these](operating.md#rules-a-command-does-not-state).

opencode and Kilo Code load a JavaScript plugin. Pi loads a TypeScript extension from the project, which also registers the tools the other agents reach through an MCP server.

## Claude Code

**The deny list replaces the Bash permission prompt.** Matching runs against the rewritten command, so a rule keyed on the program name no longer fires, and the wrapper cannot be allow-listed. There is no `ask` to return instead: it would prompt on every command including `ls`, show the rewritten text rather than what was typed, and strand an unattended run on the first command.

Hooks fire in every Claude Code permission mode and a `deny` is enforced in each, `--dangerously-skip-permissions` included, so what enrolment costs depends on the mode:

Mode | Cost
--- | ---
`default` | Bash would have prompted and now does not. This is what the warning is about.
`acceptEdits` | Auto-accepts `Write` and `Edit`, leaves Bash prompting. Same cost as default.
`bypassPermissions` | Bash never prompted, so approving it removes nothing. Enrolment is purely additive.

## Antigravity

Antigravity gets one half of this ([which half](../README.md#supported-agents)) and is told so: shipping the prose silently would tell a project it is covered when the thing that covers it is absent, so the enrolment warns.
