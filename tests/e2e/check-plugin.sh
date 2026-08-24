#!/bin/bash
# The opencode and Kilo Code plugins, executed.
#
# Two of the four supported agents do not use a hook that runs a program. They
# load JavaScript into their own process, and that file is the whole enforcement
# path: it calls `faramir guard`, applies what comes back, and refuses when it
# cannot. Nothing has ever run it. The project suite proved the file is
# written; this one proves it works.
#
# The failure it exists for is silent. A plugin that throws where it should
# rewrite stops the agent working, which somebody notices; a plugin that returns
# where it should throw runs the command unredacted in a project the operator
# believes is enrolled, and nobody notices at all.
#
# Every case drives the real hook with the real binary and a live broker behind
# it. The stub matrix is here too (a guard that exits non-zero, answers with
# something that is not JSON, or returns a decision it does not understand),
# driven through the enrolled file rather than a template rendered against a
# stand-in: what each host does with an answer it cannot use is the host's own
# contract, and only the installed plugin under a real agent shows it.
#
# Run as root in the e2e container.
set -u
HARNESS=/root/plugin-harness.mjs
SECRET='hunter2-correct-horse-battery'
PROJECT=/home/op/project
. "$(dirname "$0")/lib.sh" || { echo "e2e: lib.sh is missing beside $0" >&2; exit 2; }

command -v node >/dev/null || { echo "node is not in this image; suite J cannot run"; exit 1; }

# run drives one case against one plugin, with the guard the case needs.
# asModule is the plugin under test with the extension node needs. The hosts
# run Bun, which reads ESM out of a .js on sight; node decides from the nearest
# package.json and there is none in a project, so it would refuse the file the
# host loads happily. The bytes are unchanged: only the name tells node what it
# is already looking at.
asModule() {
  local copy
  copy=/tmp/under-test-$(basename "$(dirname "$1")").mjs
  cp "$1" "$copy"
  printf '%s' "$copy"
}

run() { # plugin-path, case
  local plugin; plugin=$(asModule "$1")
  local name=$2
  local out
  # stdout only, and the verdict line out of it: node warns on stderr that a .js
  # holding ESM is reparsed, which is its own business and not a verdict.
  out=$(cd "$PROJECT" && timeout 30 node "$HARNESS" "$plugin" "$name" 2>/dev/null \
        | grep -E '^(PASS|FAIL) ' | head -1)
  case "$out" in
    PASS*) ok "${out#PASS }" ;;
    FAIL*) bad "${out#FAIL }" ;;
    *)     bad "$name produced no verdict: $(head -c 110 <<<"$out")" ;;
  esac
}

# The plugin runs the installed path and reads no environment variable that could
# redirect it, which is the whole point of naming the path. So a guard that
# answers badly is that binary replaced for one case and put back.
REAL=/usr/local/bin/faramir
ASIDE=/usr/local/bin/faramir.aside

# On the way out as well as between cases: twelve suites run against this box
# after this one, and every one of them needs the binary where it was.
restore_binary() {
  local rc=$?
  [ -e "$ASIDE" ] && mv -f "$ASIDE" "$REAL"
  return "$rc"
}
trap restore_binary EXIT

# Every stub drains stdin before it answers, as the real guard does. A guard
# that exits without reading the payload leaves the plugin's write to it
# unfinished, and node reports that as an error on a child that ran and exited
# 0. The plugin decides on the exit status alone, so that no longer changes what
# it does, but a case about what the guard said is measured against a stub that
# received it. The one case that is about the unfinished write uses rawStub.
withStub() { # shell-body, plugin-path, case
  rawStub "cat >/dev/null
$1" "$2" "$3"
}

# rawStub is withStub without the drain, for the one case about a guard that
# answers before it has read its payload.
rawStub() { # shell-body, plugin-path, case
  local body=$1 plugin=$2 name=$3
  mv "$REAL" "$ASIDE"
  printf '#!/bin/sh\n%s\n' "$body" > "$REAL"
  chmod 0755 "$REAL"
  run "$plugin" "$name"
  rm -f "$REAL"
  mv "$ASIDE" "$REAL"
}

for agent in opencode kilocode; do
  case $agent in
    opencode) plugin=$PROJECT/.opencode/plugins/faramir.js ;;
    kilocode) plugin=$PROJECT/.kilo/plugin/faramir.js ;;
  esac

  head_ "$agent"
  if [ ! -f "$plugin" ]; then
    /usr/local/bin/faramir init-project --agent "$agent" "$PROJECT" >/dev/null 2>&1
  fi
  if [ ! -f "$plugin" ]; then
    bad "$agent: enrolment wrote no plugin at $plugin"
    continue
  fi
  ok "$agent: the enrolled plugin is at ${plugin#"$PROJECT"/}"

  # What it must leave alone.
  run "$plugin" other-tool-untouched
  run "$plugin" known-shell-without-command-throws
  run "$plugin" unlisted-tool-with-command-guarded

  # What it must change, and what it must refuse.
  run "$plugin" ordinary-rewritten
  run "$plugin" rewrite-assigns-every-field
  run "$plugin" denied-throws

  # The guard unable to run at all, which is the one fail-closed path the
  # installed path can still be made to take: move the binary aside.
  mv "$REAL" "$ASIDE"
  run "$plugin" guard-missing-throws
  mv "$ASIDE" "$REAL"

  # The guard running and answering badly. Every one of these must fail closed
  # but the silent one, which is how the guard says it has nothing to change.
  withStub 'exit 3' "$plugin" guard-nonzero-throws
  withStub 'printf %s "not json"' "$plugin" guard-garbage-throws
  # The one stub that deliberately does not drain stdin, which is the whole
  # case: it answers and exits while the payload is still being written.
  rawStub 'printf %s "{\"decision\":\"deny\",\"reason\":\"refused-by-the-stub\"}"' \
    "$plugin" guard-answering-without-reading-is-obeyed
  withStub 'printf %s ""' "$plugin" guard-silent-allows
  withStub 'printf %s "{\"decision\":\"maybe\"}"' "$plugin" unknown-decision-throws
  # A rewrite is the one answer that changes the call, so an incomplete one has
  # to stop it: assigning nothing would run the command as the model wrote it.
  withStub 'printf %s "{\"decision\":\"rewrite\"}"' "$plugin" rewrite-without-command-throws
done

# --------------------------------------------------------------------------
head_ "pi"
#
# pi's extension answers differently in both directions, so it gets a driver of
# its own. The matrix lives in the Go tests, which run in CI with a stand-in
# guard; what is checked here is the enrolled file against the real binary.

PI_EXT=$PROJECT/.pi/extensions/faramir.ts
[ -f "$PI_EXT" ] || /usr/local/bin/faramir init-project --agent pi "$PROJECT" >/dev/null 2>&1
if [ ! -f "$PI_EXT" ]; then
  bad "pi: enrolment wrote no extension at $PI_EXT"
else
  ok "pi: the enrolled extension is at ${PI_EXT#"$PROJECT"/}"
  # The shipped bytes: the extension is a .ts carrying no type annotations, so
  # node runs it as it is. 0644 because these probes run as the operator.
  cp "$PI_EXT" /tmp/pi-under-test.mjs; chmod 0644 /tmp/pi-under-test.mjs
  cat > /tmp/pi-drive.mjs <<'PIEOF'
const m = await import("/tmp/pi-under-test.mjs")
const handlers = {}
m.default({ on: (n, f) => { handlers[n] = f }, registerTool: () => {} })
const event = { toolName: process.env.TOOL, input: JSON.parse(process.env.INPUT) }
const verdict = await handlers["tool_call"](event, {})
console.log(JSON.stringify({ blocked: !!(verdict && verdict.block), reason: verdict && verdict.reason, input: event.input }))
PIEOF
  chmod 0644 /tmp/pi-drive.mjs
  pidrive() { TOOL="$1" INPUT="$2" node /tmp/pi-drive.mjs 2>/dev/null; }

  # pi ships no MCP, so the extension registers what the other hosts reach
  # through it. Without faramir_run the guard's own refusal names a tool that
  # would not exist on this host.
  cat > /tmp/pi-tools.mjs <<'TOOLEOF'
const m = await import("/tmp/pi-under-test.mjs")
const tools = []
m.default({ on: () => {}, registerTool: (t) => tools.push(t) })
const run = tools.find((t) => t.name === "faramir_run")
const r = await run.execute("id", {
  cmd: ["sh", "-c", "echo $PW"],
  cwd: process.env.PROJECT,
  env_refs: { PW: "faramir://db/password" },
})
console.log(JSON.stringify({ names: tools.map((t) => t.name), text: r.content[0].text, isError: r.isError }))
TOOLEOF
  chmod 0644 /tmp/pi-tools.mjs
  tools=$(runuser -u op -- env PROJECT="$PROJECT" node /tmp/pi-tools.mjs 2>/dev/null)
  # The two MCP exposes; there is no status tool on any host.
  for want in faramir_run faramir_refs; do
    grep -q "$want" <<<"$tools" && ok "pi: $want is registered" || bad "pi: $want was not registered"
  done
  grep -q 'faramir_status' <<<"$tools" && bad "pi registers a status tool no other host has" \
    || ok "pi: and no status tool, matching the other hosts"
  body=$(jq -r .text <<<"$tools" 2>/dev/null)
  grep -qF "$SECRET" <<<"$body" && bad "pi: faramir_run returned the value in plaintext" \
    || ok "pi: faramir_run returns no plaintext"
  grep -q '«SECRET:db/password»' <<<"$body" && ok "pi: it returns the token" \
    || bad "pi: no token: $(head -c 80 <<<"$body")"
  grep -q 'exit_code=0' <<<"$body" && ok "pi: in the shape the MCP server returns" \
    || bad "pi: unexpected result shape: $(head -c 80 <<<"$body")"

  out=$(pidrive bash '{"command":"cat /etc/faramir/age.key"}')
  [ "$(jq -r .blocked <<<"$out")" = true ] && ok "pi: reading the age key is blocked" \
    || bad "pi: the age key was not blocked: ${out:0:90}"
  jq -r .reason <<<"$out" | grep -qi 'faramir\|credential' && ok "pi: and the reason reaches the model" \
    || bad "pi: no usable reason: $(jq -r .reason <<<"$out" | head -c 70)"

  out=$(pidrive bash '{"command":"echo hello","description":"look"}')
  [ "$(jq -r .blocked <<<"$out")" = false ] && ok "pi: an ordinary command is not blocked" \
    || bad "pi: an ordinary command was blocked: ${out:0:90}"
  jq -r .input.command <<<"$out" | grep -q 'wrap.sh\|faramir' && ok "pi: and event.input was rewritten in place" \
    || bad "pi: not rewritten: $(jq -r .input.command <<<"$out" | head -c 70)"
  [ "$(jq -r .input.description <<<"$out")" = look ] && ok "pi: with every other field kept" \
    || bad "pi: the rewrite dropped a field"

  # And what it hands back runs, and redacts.
  cmd=$(pidrive bash '{"command":"echo hunter2-correct-horse-battery"}' | jq -r .input.command)
  out=$(runuser -u op -- env XDG_RUNTIME_DIR="/run/user/$(id -u op)" bash -c "cd $PROJECT && $cmd" 2>&1)
  grep -qF 'hunter2-correct-horse-battery' <<<"$out" && bad "pi: running the rewrite printed the value" \
    || ok "pi: running the rewrite does not print the value"
  grep -q '«SECRET:db/password»' <<<"$out" && ok "pi: it comes back as its token" \
    || bad "pi: no token: $(head -c 90 <<<"$out")"
fi

# --------------------------------------------------------------------------
head_ "what the rewrite actually runs"
#
# The plugin hands the host a command string and the host runs it. So the
# rewrite has to be something a shell can run, and running it has to redact:
# everything up to here has only checked what the plugin returned.
#
# `printenv PW` would be denied rather than rewritten, the deny list naming it,
# so the command here is one the guard passes through.

PLUGIN_UNDER_TEST=$(asModule $PROJECT/.opencode/plugins/faramir.js)
export PLUGIN_UNDER_TEST
rewritten=$(cd $PROJECT && FARAMIR_CLI=/usr/local/bin/faramir node --input-type=module -e '
const m = await import(process.env.PLUGIN_UNDER_TEST)
const hooks = await (m.faramir ?? m.default.server)()
const args = { command: "echo hunter2-correct-horse-battery" }
await hooks["tool.execute.before"]({ tool: "bash" }, { args })
process.stdout.write(args.command)
' 2>/dev/null)
[ -n "$rewritten" ] && ok "the plugin produced a command to run" || bad "no rewritten command"

# The command prints a managed value. What the host runs is the rewrite, so
# the redaction has to happen there rather than in anything faramir invoked.
# bash, not sh: the rewrite sources the wrapper, and the hosts run the shell
# tool through bash.
# XDG_RUNTIME_DIR because the wrapper captures output into a private directory
# of the caller's own, and runuser supplies no session environment.
out=$(runuser -u op -- env XDG_RUNTIME_DIR="/run/user/$(id -u op)" \
  bash -c "cd $PROJECT && $rewritten" 2>&1)
if grep -qF 'hunter2-correct-horse-battery' <<<"$out"; then
  bad "running the rewrite printed the value in plaintext"
else
  ok "running the rewrite does not print the value"
fi
grep -q '«SECRET:db/password»' <<<"$out" && ok "it comes back as its token" \
  || bad "no token in the rewritten command's output: $(head -c 100 <<<"$out")"

# --------------------------------------------------------------------------
summary
