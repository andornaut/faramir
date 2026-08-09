// faramir: run every shell command under the redactor, and refuse the ones the
// deny list names.
//
// `faramir init-project --agent opencode` writes this into
// .opencode/plugins/faramir.js, which opencode loads at startup.
//
// It decides nothing: the deny list, the rewrite and what is left alone are
// `faramir guard`.  This is the translation -- a payload out, a decision back,
// applied rather than returned, opencode having no reply document.
//
// node:child_process rather than the Bun shell: the guard reads its payload on
// stdin, and this never builds a command line out of the model's text.
// spawnSync, the decision having to be applied before the hook returns.

import { spawnSync } from "node:child_process"

const CLI = process.env.FARAMIR_CLI || "/usr/local/bin/faramir"
const HOST = "opencode"

// Every other tool is left alone: only a command has output worth redacting.
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

    // Fail closed: running the command without a decision would print
    // whatever it found straight into the transcript.
    if (result.error || result.status !== 0) {
      throw new Error(
        `faramir: the guard did not answer, so this command was not run (${CLI} guard --host ${HOST})` +
          (result.stderr ? `: ${String(result.stderr).trim()}` : ""),
      )
    }

    // Nothing to say: a backgrounded command, or one already under the
    // redactor.  See docs/design.md.
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
        // Reaches the model, not the operator, and names the tool to use
        // instead.
        throw new Error(decision.reason)
      case "rewrite":
        // Assigned into the object the host handed in, which is how this hook
        // changes a call.  Every field, not only the command.
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
