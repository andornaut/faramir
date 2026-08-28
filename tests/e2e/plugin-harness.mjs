// Drives one enrolled plugin's tool.execute.before hook the way its host does.
//
// One case per process: the plugin reads FARAMIR_CLI once at module load, so a
// case that needs a different guard needs a different process.  That is also
// how the host loads it, which is the point.
//
// usage: node plugin-harness.mjs <plugin.js> <case>
// prints: PASS <case> <detail>  |  FAIL <case> <detail>

const [pluginPath, name] = process.argv.slice(2)

const mod = await import(pluginPath)
// opencode exports the factory by name; Kilo Code exports { id, server }.
const factory = mod.faramir ?? mod.default?.server
if (typeof factory !== "function") {
  console.log(`FAIL ${name} the plugin exports no hook factory`)
  process.exit(1)
}
const hooks = await factory()
const before = hooks["tool.execute.before"]
if (typeof before !== "function") {
  console.log(`FAIL ${name} the plugin registers no tool.execute.before`)
  process.exit(1)
}

const pass = (detail) => { console.log(`PASS ${name} ${detail}`); process.exit(0) }
const fail = (detail) => { console.log(`FAIL ${name} ${detail}`); process.exit(1) }

// call runs the hook and reports whether it threw, and with what.
async function call(input, output) {
  try {
    await before(input, output)
    return { threw: false }
  } catch (e) {
    return { threw: true, message: String(e && e.message ? e.message : e) }
  }
}

const shell = (command, extra = {}) => ({
  input: { tool: "bash" },
  output: { args: { command, ...extra } },
})

switch (name) {
  case "other-tool-untouched": {
    // An ordinary file: nothing here runs a command and nothing here is
    // protected, so the call goes through unchanged.
    const output = { args: { filePath: "/etc/hosts" } }
    const r = await call({ tool: "read" }, output)
    if (r.threw) fail(`a non-shell tool threw: ${r.message}`)
    if (output.args.filePath !== "/etc/hosts") fail("a non-shell tool's args were changed")
    pass("a tool that is not the shell is left alone")
    break
  }
  case "other-tool-refused-key-material": {
    // The host's own permission map is not a refusal on either of these agents:
    // an entry of "deny" is put to the operator as a prompt, and an autonomous
    // run approves it. So the plugin refuses the path itself.
    const r = await call({ tool: "read" }, { args: { filePath: "/etc/faramir/age.key" } })
    if (!r.threw) fail("a file tool opened the age key")
    if (!/faramir run/.test(r.message)) fail(`the refusal names no way through: ${r.message.slice(0, 80)}`)
    pass("a file tool naming key material is refused")
    break
  }
  case "other-tool-refused-by-shape": {
    // By shape rather than by tool name, and at any depth: a tool nobody listed,
    // taking a list rather than a path.
    const r = await call({ tool: "read_many" },
      { args: { paths: ["/srv/README.md", "/etc/faramir/age.key"] } })
    if (!r.threw) fail("a key named among several paths was opened")
    pass("a tool nobody listed is refused when a path it carries is protected")
    break
  }
  case "known-shell-without-command-throws": {
    // A tool known to run commands, arriving in a shape this cannot read: the
    // guard cannot be asked, so the call is not made.
    const r = await call({ tool: "bash" }, { args: {} })
    if (!r.threw) fail("a known shell tool with no command string was waved through")
    if (!/no command string/i.test(r.message)) fail(`unclear: ${r.message.slice(0, 80)}`)
    pass("a known shell tool with no command string is refused")
    break
  }
  case "unlisted-tool-with-command-guarded": {
    // Guarded by shape: a tool nobody listed still carries a command.
    const { output } = shell("cat /etc/faramir/age.key")
    const r = await call({ tool: "some-new-shell" }, output)
    if (!r.threw) fail(`a tool this list never named ran a command unguarded: ${output.args.command.slice(0, 50)}`)
    pass("a tool nobody listed is guarded when it carries a command")
    break
  }
  case "ordinary-rewritten": {
    const { input, output } = shell("echo hello")
    const r = await call(input, output)
    if (r.threw) fail(`an ordinary command was refused: ${r.message}`)
    if (output.args.command === "echo hello") fail("the command was not rewritten")
    if (!/faramir|wrap\.sh/.test(output.args.command)) {
      fail(`rewritten to something unexpected: ${output.args.command.slice(0, 70)}`)
    }
    pass("an ordinary command is rewritten through the wrapper")
    break
  }
  case "denied-throws": {
    const { input, output } = shell("cat /etc/faramir/age.key")
    const r = await call(input, output)
    if (!r.threw) fail(`reading the age key was allowed; command=${output.args.command.slice(0, 60)}`)
    if (!/faramir|secret|refus|deny|denied/i.test(r.message)) {
      fail(`threw without a usable reason: ${r.message.slice(0, 80)}`)
    }
    pass(`a denied command throws: ${r.message.slice(0, 44)}`)
    break
  }
  case "rewrite-assigns-every-field": {
    // The host hands one object in and reads it back; a rewrite that replaced
    // only .command would leave the rest of the call as the model wrote it.
    const { input, output } = shell("echo hello", { cwd: "/home/op/project", timeout: 1 })
    const r = await call(input, output)
    if (r.threw) fail(`threw: ${r.message}`)
    if (output.args.cwd !== "/home/op/project") fail("an unrelated field was dropped by the rewrite")
    pass("a rewrite assigns into the object the host handed in")
    break
  }
  case "guard-missing-throws": {
    const { input, output } = shell("echo hello")
    const r = await call(input, output)
    if (!r.threw) fail("a missing guard let the command through")
    if (!/did not answer|not run/i.test(r.message)) fail(`unclear: ${r.message.slice(0, 80)}`)
    pass(`a guard that cannot run fails closed: ${r.message.slice(0, 40)}`)
    break
  }
  case "guard-nonzero-throws": {
    const { input, output } = shell("echo hello")
    const r = await call(input, output)
    if (!r.threw) fail("a guard exiting non-zero let the command through")
    pass("a guard exiting non-zero fails closed")
    break
  }
  // A guard that answers and exits without reading its payload. The write to it
  // does not finish, and node reports that as an error on a child that ran and
  // exited 0: taking that for a guard that could not run would refuse a command
  // the guard decided on. Deterministic because the payload is larger than a
  // pipe buffer, so the write cannot have completed before the child exited.
  case "guard-answering-without-reading-is-obeyed": {
    const { input, output } = shell("echo " + "a".repeat(200000))
    const r = await call(input, output)
    if (!r.threw) fail("a deny from a guard that did not read its payload was ignored")
    if (/did not answer/i.test(r.message)) {
      fail(`a guard that answered was reported as silent: ${r.message.slice(0, 80)}`)
    }
    if (!/refused-by-the-stub/.test(r.message)) fail(`unclear: ${r.message.slice(0, 80)}`)
    pass("a guard that answers without draining its payload is obeyed")
    break
  }
  case "guard-garbage-throws": {
    const { input, output } = shell("echo hello")
    const r = await call(input, output)
    if (!r.threw) fail("a guard answering with non-JSON let the command through")
    if (!/JSON/i.test(r.message)) fail(`unclear: ${r.message.slice(0, 80)}`)
    pass("a guard answering with non-JSON fails closed")
    break
  }
  case "guard-silent-allows": {
    // No answer is the guard's way of saying it has nothing to change.
    const { input, output } = shell("echo hello")
    const r = await call(input, output)
    if (r.threw) fail(`a silent guard threw: ${r.message}`)
    if (output.args.command !== "echo hello") fail("a silent guard still changed the command")
    pass("a guard with nothing to say leaves the command alone")
    break
  }
  case "rewrite-without-command-throws": {
    // The one malformed answer that used to run: Object.assign ignores a null
    // source, so the hook returned having changed nothing and the command went
    // out as the model wrote it.
    const { input, output } = shell("echo hello")
    const r = await call(input, output)
    if (!r.threw) fail("a rewrite naming no command let the original through")
    if (output.args.command !== "echo hello") fail("it changed the command anyway")
    if (!/named no command|not run/i.test(r.message)) fail(`unclear: ${r.message.slice(0, 80)}`)
    pass("a rewrite naming no command fails closed")
    break
  }
  case "unknown-decision-throws": {
    const { input, output } = shell("echo hello")
    const r = await call(input, output)
    if (!r.threw) fail("a decision the plugin does not understand let the command through")
    if (!/does not understand|not run/i.test(r.message)) fail(`unclear: ${r.message.slice(0, 80)}`)
    pass("a decision it does not understand fails closed")
    break
  }
  default:
    fail(`no such case`)
}
