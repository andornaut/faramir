// faramir: run every shell command under the redactor, and refuse the ones the
// deny list names.
//
// `faramir init-project --agent opencode` writes this into
// .opencode/plugins/faramir.js, which opencode loads at startup; there is no
// entry in opencode.json that registers it.
//
// It decides nothing.  The deny list, the rewrite and the rules about what is
// left alone are `faramir guard`, the one program every enrolled agent talks
// to, so a pattern added to the shipped list covers this agent as soon as it is
// installed rather than when a copy of it here is edited.  What is in this file
// is the translation: a payload out, a decision back, applied the way this host
// applies one.  opencode has no reply document -- a plugin blocks by throwing
// and rewrites by mutating the arguments in place -- so the decision is applied
// rather than returned.
//
// node:child_process rather than the Bun shell the plugin context hands in: the
// guard reads its payload on stdin, and building a command line out of the
// model's own text is the one thing this project does not do.  spawnSync,
// because the decision has to be applied before this hook returns and there is
// nothing to overlap the wait with; the guard is a static binary that answers
// in milliseconds.

import { spawnSync } from "node:child_process"

const CLI = process.env.FARAMIR_CLI || "/usr/local/bin/faramir"
const HOST = "opencode"

// The tool opencode runs shell commands through.  Every other tool is left
// alone, because only a command has output worth redacting.
const SHELL_TOOL = "bash"

export const faramir = async () => ({
  "tool.execute.before": async (input, output) => {
    if (input.tool !== SHELL_TOOL) return
    const args = output.args
    if (!args || !args.command) return

    const result = spawnSync(CLI, ["guard", "--host", HOST], {
      input: JSON.stringify({ tool_name: input.tool, tool_input: args }),
      encoding: "utf8",
      timeout: 10000,
    })

    // Fail closed.  Every way of not getting a decision ends here and the
    // command does not run: a guard that cannot be reached is an install that
    // is broken, absent or too old, and running the command anyway would print
    // whatever it found straight into the transcript.
    if (result.error || result.status !== 0) {
      throw new Error(
        `faramir: the guard did not answer, so this command was not run (${CLI} guard --host ${HOST})` +
          (result.stderr ? `: ${String(result.stderr).trim()}` : ""),
      )
    }

    // Nothing to say.  A backgrounded command and one already under the
    // redactor are left exactly as they are; see docs/scope.md for the list.
    const text = (result.stdout || "").trim()
    if (!text) return

    let decision
    try {
      decision = JSON.parse(text)
    } catch {
      throw new Error("faramir: the guard's answer was not JSON, so this command was not run")
    }

    switch (decision.decision) {
      case "deny":
        // The reason reaches the model rather than the operator, and it names
        // the tool to use instead, so it is the whole of what the agent can act
        // on.
        throw new Error(decision.reason)
      case "rewrite":
        // Assigned into the object the host handed in, because that is how this
        // hook changes a call.  Every field comes back, not only the command: a
        // description or a timeout dropped here is one the tool never sees.
        Object.assign(args, decision.tool_input)
        return
      default:
        throw new Error(
          "faramir: the guard returned a decision this plugin does not understand, " +
            "so this command was not run",
        )
    }
  },
})
