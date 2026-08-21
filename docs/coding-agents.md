# Agents

The guard is one program speaking each agent's contract. What varies is the tool that runs a command, the shape of the reply and where it is registered; what does not is that the command is rewritten to redact its own output. Which agents, and what enrolling each costs, is the table in the [README](../README.md#supported-agents). How that rewrite is shaped, and why, is in [design.md](design.md#how-the-rewrite-works); which file each agent reads is in [layout.md](layout.md).

## Which agents an install configures

`--agent` defaults to `auto`, which configures the agents already there and nothing else: `init` asks that of the operator's home, `init-project` of the tree, and they are not the same paths, opencode keeping `opencode.json` beside a project and `.config/opencode` under a home. Naming one configures it regardless, which is how a tree is set up for an agent before it is installed. Detection only ever adds, so the two need no rule about which wins.

## The rules, and the prose beside them

Beside the rules goes prose saying what they refuse and why, in the file each agent reads for every project. A model given a refusal and no explanation tries the next route: another tool, an interpreter, a base64 pipe. The section is also the only thing faramir says in a tree `init-project` has never been run in, where the deny rules still hold and there is no broker to name. The tree's own section is the longer one, there being a route there to point at.

The patterns those rules refuse are written once, in [internal/install/protectedpaths.go](../internal/install/protectedpaths.go), and rendered into each agent's own spelling. Beside them, in the account-wide files only, go the literal paths this install names: the file each `[[secret.link]]` entry reads, and each [refused path](configuration.md#refused-paths). A copy per agent drifts silently: a rule that covers nothing looks exactly like a rule that covers everything, and one character is the difference. Pi has no rule file to write, so its rules are compiled into the extension and applied by shape, a file tool whose name it does not know still carrying a path.

What a rule *matches* is a second question. The built-in patterns are read as a name or a suffix anywhere in a path, so `~/.ssh/id_ed25519` and `.ssh/id_ed25519` are refused as readily as the absolute form. A path this install names is a literal, and pi tries the spellings that mean the same file: as the tool gave it, with `~` expanded, and with dot segments and doubled separators taken out. A relative path is left as it is, resolving one needing the working directory the call meant rather than the extension host's. Where an agent has a rule file, its own host does the matching, so which spellings are caught there is the host's answer and not faramir's.

A file two agents read is written once, and claims only what holds for both: a file that told one of them its file tools are refused everywhere would be telling the other something false. No two share one today, and the rule stays because the failure it prevents is silent. A rules file faramir creates carries the frontmatter that makes it always-on, that being what decides whether the model is shown it at all.

## opencode and Kilo Code

These two have no hook that runs a program. A plugin in the agent's own process blocks a call by throwing and changes one by mutating its arguments, so it asks the guard and applies the answer:

```json
{"decision": "deny", "reason": "<what the model is told>"}
{"decision": "rewrite", "tool_input": {"command": "source .../wrap.sh '<command>'"}}
```

The rewrite carries back every field of the original tool input with only `command` replaced. Nothing written is a call left alone. Every other answer fails closed: a guard that cannot be run, a non-zero exit, an answer that is not JSON, a decision the plugin does not know. That covers version skew, which is why `faramir init` [comes before enrolling one of these](operating.md#rules-a-command-does-not-state).

## Claude Code

**The deny list replaces the Bash permission prompt.** Matching runs against the rewritten command, so a rule keyed on the program name no longer fires, and the wrapper cannot be allow-listed. There is no `ask` to return instead: it would prompt on every command including `ls`, show the rewritten text rather than what was typed, and strand an unattended run on the first command.

Hooks fire in every Claude Code permission mode and a `deny` is enforced in each, `--dangerously-skip-permissions` included, so what enrolment costs depends on the mode:

Mode | Cost
--- | ---
`default` | Bash would have prompted and now does not. This is what the warning is about.
`acceptEdits` | Auto-accepts `Write` and `Edit`, leaves Bash prompting. Same cost as default.
`bypassPermissions` | Bash never prompted, so approving it removes nothing. Enrolment is purely additive.

## Antigravity

Antigravity gets one half of this ([which half](../README.md#supported-agents)) and is told so: shipping prose silently would say a project is covered when the thing that covers it is absent, so the enrolment warns.
