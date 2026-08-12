#!/bin/bash
# Suite P: `faramir init-project`, the enrolment that makes a tree protected.
#
# The stakes are the reason this is a suite of its own.  Every other command
# fails loudly; this one fails silently.  If enrolment writes the wrong thing,
# the guard and the wrapper never run, and commands execute unredacted in a
# project the operator believes is covered.  So the assertions are about what
# lands on disk AND about whether the thing it lands works.
#
# Four agents, and until now the lab enrolled only claude.  The other three
# write different files in different places, so each is enrolled into a tree of
# its own here.
#
# Run as root in the lab container.
set -u
OP=op
HOME_OP=/home/op
SECRET='hunter2-correct-horse-battery'
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; }
head_() { printf '\n== %s\n' "$1"; }

# tree makes an empty working tree owned by the operator, as a checkout would be.
tree() {
  local d=$1
  rm -rf "$d"
  install -d -o $OP -g $OP -m 0755 "$d"
  printf '%s\n' "$d"
}
enrol() { # dir, then --agent flags
  local d=$1; shift
  /usr/local/bin/faramir init-project --operator-user $OP "$@" "$d" 2>&1
}
# owned asserts a path exists and belongs to the operator, not to root:
# init-project runs as root over somebody else's checkout.
owned() { # path, label
  if [ ! -e "$1" ]; then bad "$2 was not written ($1)"; return; fi
  local who; who=$(stat -c '%U' "$1")
  if [ "$who" = "$OP" ]; then ok "$2 ($(stat -c '%a' "$1") $who)"
  else bad "$2 is owned by $who, not $OP: $1"; fi
}
absent() { [ -e "$1" ] && bad "$2 was written and should not be: $1" || ok "$2 is absent"; }

echo "enrolling as $OP; agents: claude gemini opencode kilocode"

# --------------------------------------------------------------------------
head_ "P1. each agent's own file set"

D=$(tree /home/op/p-claude); enrol "$D" --agent claude >/tmp/p-claude.log 2>&1 \
  || bad "claude enrolment failed: $(tail -2 /tmp/p-claude.log)"
owned "$D/.claude/settings.json" "claude: project settings"
owned "$D/.mcp.json" "claude: MCP registration"


D=$(tree /home/op/p-gemini); enrol "$D" --agent gemini >/tmp/p-gemini.log 2>&1 \
  || bad "gemini enrolment failed: $(tail -2 /tmp/p-gemini.log)"
owned "$D/.gemini/settings.json" "gemini: project settings (hooks and mcpServers)"


D=$(tree /home/op/p-opencode); enrol "$D" --agent opencode >/tmp/p-opencode.log 2>&1 \
  || bad "opencode enrolment failed: $(tail -2 /tmp/p-opencode.log)"
owned "$D/.opencode/plugins/faramir.js" "opencode: plugin"
owned "$D/opencode.json" "opencode: MCP registration"


D=$(tree /home/op/p-kilo); enrol "$D" --agent kilocode >/tmp/p-kilo.log 2>&1 \
  || bad "kilocode enrolment failed: $(tail -2 /tmp/p-kilo.log)"
owned "$D/.kilo/plugin/faramir.js" "kilocode: plugin"
owned "$D/kilo.json" "kilocode: MCP registration"


# The account-wide files are `faramir init --agent`'s half of enrolment, not
# this command's: init-project writes the per-project hook, init writes the deny
# rules that hold wherever the agent works.
/usr/local/bin/faramir init --operator-user $OP --agent claude --agent gemini \
  --agent opencode --agent kilocode >/tmp/p-init.log 2>&1
owned "$HOME_OP/.claude/settings.json" "claude: account-wide settings (from init)"
owned "$HOME_OP/.gemini/policies/faramir.toml" "gemini: account-wide policy (from init)"
owned "$HOME_OP/.config/opencode/opencode.json" "opencode: account-wide deny rules (from init)"
owned "$HOME_OP/.config/kilo/kilo.json" "kilocode: account-wide deny rules (from init)"

# Nothing lands in root's home, which is where a command run under sudo would
# put an account-wide file if it took the caller's HOME rather than the
# operator's.
for stray in /root/.claude /root/.gemini /root/.config/opencode /root/.config/kilo; do
  absent "$stray" "$(basename "$stray") in root's home"
done

# --------------------------------------------------------------------------
head_ "P2. every file it writes is valid to the tool that reads it"

for f in /home/op/p-claude/.claude/settings.json /home/op/p-claude/.mcp.json \
         /home/op/p-gemini/.gemini/settings.json \
         /home/op/p-opencode/opencode.json /home/op/p-kilo/kilo.json \
         $HOME_OP/.claude/settings.json $HOME_OP/.config/opencode/opencode.json \
         $HOME_OP/.config/kilo/kilo.json; do
  if jq -e . "$f" >/dev/null 2>&1; then ok "valid JSON: ${f#/home/op/}"
  else bad "not JSON: $f"; fi
done
# The plugins are JavaScript the agent loads in-process; a syntax error there is
# an agent that starts with no guard at all.
for js in /home/op/p-opencode/.opencode/plugins/faramir.js /home/op/p-kilo/.kilo/plugin/faramir.js; do
  if ! command -v node >/dev/null 2>&1; then
    ok "(no node in the image; $(basename "$js") not parsed)"; continue
  fi
  # As a module: these are ESM in a .js, which the hosts' Bun runtime infers and
  # node decides from the nearest package.json, of which a project has none.
  cp "$js" /tmp/syntax-check.mjs
  if node --check /tmp/syntax-check.mjs >/dev/null 2>&1; then
    ok "parses as an ES module: ${js#/home/op/}"
  else
    bad "syntax error in $js: $(node --check /tmp/syntax-check.mjs 2>&1 | head -1)"
  fi
done
# And each names the binary that is actually installed.
for f in /home/op/p-claude/.claude/settings.json /home/op/p-gemini/.gemini/settings.json; do
  grep -q '/usr/local/bin/faramir' "$f" && ok "names the installed binary: ${f#/home/op/}" \
    || bad "does not name the binary: $f"
done

# --------------------------------------------------------------------------
head_ "P3. the hook it registers actually runs and denies"
#
# The point of enrolment.  A settings.json naming a hook that does not run is
# the silent failure this whole suite exists for, so the command in the file is
# extracted and executed.

hook=$(jq -r '.hooks.PreToolUse[0].hooks[0].command' /home/op/p-claude/.claude/settings.json 2>/dev/null)
if [ -n "$hook" ] && [ "$hook" != null ]; then
  ok "claude settings name a PreToolUse command: ${hook:0:48}"
  out=$(printf '{"tool_name":"Bash","tool_input":{"command":"cat /etc/faramir/age.key"}}' \
    | runuser -u $OP -- sh -c "cd /home/op/p-claude && $hook" 2>/dev/null)
  grep -q '"permissionDecision":"deny"' <<<"$out" \
    && ok "and running it denies reading the age key" \
    || bad "the registered hook did not deny: ${out:0:120}"
  out=$(printf '{"tool_name":"Bash","tool_input":{"command":"echo hello"}}' \
    | runuser -u $OP -- sh -c "cd /home/op/p-claude && $hook" 2>/dev/null)
  grep -q 'wrap.sh\|faramir' <<<"$out" \
    && ok "and rewrites an ordinary command through the wrapper" \
    || bad "an ordinary command was not rewritten: ${out:0:120}"
else
  bad "no PreToolUse command in the claude settings"
fi

# The MCP server it registers answers.
cmd=$(jq -r '.mcpServers.faramir.command' /home/op/p-claude/.mcp.json 2>/dev/null)
args=$(jq -r '.mcpServers.faramir.args // [] | join(" ")' /home/op/p-claude/.mcp.json 2>/dev/null)
if [ -n "$cmd" ] && [ "$cmd" != null ]; then
  ok "the MCP registration names $cmd $args"
  out=$(printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"p","version":"1"}}}' \
    | runuser -u $OP -- sh -c "cd /home/op/p-claude && timeout 10 $cmd $args" 2>/dev/null | head -1)
  grep -q '"serverInfo"' <<<"$out" && ok "and that server answers initialize" \
    || bad "the registered MCP server did not answer: ${out:0:120}"
else
  bad "no MCP server registered in .mcp.json"
fi

# --------------------------------------------------------------------------
head_ "P4. it merges into what the operator already had"
#
# Every shared file is merged rather than replaced.  An enrolment that discarded
# an operator's own settings would be found the hard way, in a project whose
# other tooling stopped working.

D=$(tree /home/op/p-merge)
runuser -u $OP -- mkdir -p "$D/.claude"
runuser -u $OP -- tee "$D/.claude/settings.json" >/dev/null <<'JSON'
{"model": "opus", "env": {"MY_OWN": "keep me"}, "hooks": {"PostToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/bin/true"}]}]}}
JSON
runuser -u $OP -- tee "$D/.mcp.json" >/dev/null <<'JSON'
{"mcpServers": {"mine": {"command": "/usr/bin/true"}}}
JSON
enrol "$D" --agent claude >/tmp/p-merge.log 2>&1 || bad "merge enrolment failed"

jq -e '.model == "opus"' "$D/.claude/settings.json" >/dev/null \
  && ok "the operator's own scalar survived the merge" || bad "settings.json lost .model"
jq -e '.env.MY_OWN == "keep me"' "$D/.claude/settings.json" >/dev/null \
  && ok "and their own env entry" || bad "settings.json lost .env.MY_OWN"
jq -e '.hooks.PostToolUse[0].hooks[0].command == "/usr/bin/true"' "$D/.claude/settings.json" >/dev/null \
  && ok "and their own unrelated hook" || bad "settings.json lost the operator's PostToolUse hook"
jq -e '.hooks.PreToolUse != null' "$D/.claude/settings.json" >/dev/null \
  && ok "while faramir's PreToolUse hook was added beside it" || bad "the faramir hook was not added"
jq -e '.mcpServers.mine.command == "/usr/bin/true"' "$D/.mcp.json" >/dev/null \
  && ok "the operator's own MCP server survived" || bad ".mcp.json lost the operator's server"
jq -e '.mcpServers.faramir != null' "$D/.mcp.json" >/dev/null \
  && ok "and faramir's was added beside it" || bad "faramir's MCP server was not added"

# A file the operator owns stays theirs after root has written to it.
owned "$D/.claude/settings.json" "the merged file is still the operator's"

# --------------------------------------------------------------------------
head_ "P5. enrolling twice changes nothing"

D=/home/op/p-claude
# Settled first: the first run writes the asset's key order and the second
# re-serialises it sorted, so the pair to compare is the second and the third.
enrol "$D" --agent claude >/dev/null 2>&1
before=$(find "$D" -type f -exec sha256sum {} \; | sort)
inodes=$(find "$D" -type f -exec stat -c '%n %i' {} \; | sort)
enrol "$D" --agent claude >/tmp/p-again.log 2>&1 || bad "re-enrolment failed"
after=$(find "$D" -type f -exec sha256sum {} \; | sort)
[ "$before" = "$after" ] && ok "a settled tree keeps every file byte-identical" \
  || bad "re-enrolment changed content: $(diff <(echo "$before") <(echo "$after") | head -2 | tr '\n' ' ')"

# Identical content is not the same as untouched.  writeFile documents an
# unchanged re-run as writing nothing, so the inode is what says whether it did.
now=$(find "$D" -type f -exec stat -c '%n %i' {} \; | sort)
[ "$inodes" = "$now" ] && ok "and rewrites none of them" \
  || bad "every file is rewritten on a no-op run (inodes move, bytes do not): $(diff <(echo "$inodes") <(echo "$now") | grep -c '^<') file(s)"
# Which is what the report tells the operator.
n=$(/usr/local/bin/faramir init-project --operator-user $OP --agent claude --json "$D" 2>/dev/null \
  | jq '[.steps[]|select(.changed)]|length')
[ "$n" -eq 0 ] && ok "and reports nothing changed" \
  || bad "a no-op enrolment reports $n step(s) changed, so an operator cannot tell a real run from this one"
# And the hook is registered once, not twice.
n=$(jq '[.hooks.PreToolUse[]?.hooks[]? | select(.command | test("faramir"))] | length' "$D/.claude/settings.json")
[ "$n" -eq 1 ] && ok "the faramir hook is registered once, not appended again" \
  || bad "$n faramir hooks after two enrolments"

# --------------------------------------------------------------------------
head_ "P6. several agents in one tree"

D=$(tree /home/op/p-multi)
enrol "$D" --agent claude --agent gemini --agent opencode --agent kilocode >/tmp/p-multi.log 2>&1 \
  || bad "multi-agent enrolment failed: $(tail -2 /tmp/p-multi.log)"
for f in .claude/settings.json .mcp.json .gemini/settings.json \
         .opencode/plugins/faramir.js opencode.json .kilo/plugin/faramir.js kilo.json; do
  [ -e "$D/$f" ] && ok "  $f" || bad "  $f was not written by the multi-agent enrolment"
done

# --------------------------------------------------------------------------
head_ "P7. the tree itself is shared with the executor"

D=/home/op/p-claude
mode=$(stat -c '%a %U:%G' "$D")
[ "$mode" = "2770 op:dev" ] && ok "the tree is $mode: setgid, group-shared" \
  || bad "the tree is $mode, want 2770 op:dev"
id -nG faramir-exec | grep -qw dev && ok "and the executor is in that group" \
  || bad "the executor is not in the tree's group"
# Which is what lets a brokered command run there at all.
out=$(runuser -u $OP -- /usr/local/bin/faramir run --quiet -t 20 -C "$D" -- /bin/pwd 2>&1)
[ "$(tail -1 <<<"$out")" = "$D" ] && ok "so a brokered command runs in it" \
  || bad "a brokered command cannot enter the enrolled tree: ${out:0:110}"
# What enrolment buys is reach into a tree the executor could not otherwise
# enter.  A 0755 checkout is world-traversable and needs no enrolment for that,
# so the claim is about a private one.
U=/home/op/p-private
rm -rf $U; install -d -o $OP -g $OP -m 0700 $U
out=$(runuser -u $OP -- /usr/local/bin/faramir run --quiet -t 20 -C "$U" -- /bin/pwd 2>&1)
grep -qiE 'permission denied|cannot|no such|refused|exec_failed|log_id' <<<"$out" \
  && ok "a private tree that was never enrolled is refused" \
  || bad "a brokered command entered an unenrolled private tree: ${out:0:110}"
enrol "$U" --agent claude >/dev/null 2>&1
out=$(runuser -u $OP -- /usr/local/bin/faramir run --quiet -t 20 -C "$U" -- /bin/pwd 2>&1)
[ "$(tail -1 <<<"$out")" = "$U" ] && ok "and enrolling it is what admits the executor" \
  || bad "enrolment did not open the private tree: ${out:0:110}"

# --------------------------------------------------------------------------
head_ "P8. --dry-run writes nothing"

D=$(tree /home/op/p-dry)
out=$(enrol "$D" --agent claude --dry-run)
n=$(find "$D" -mindepth 1 | wc -l)
[ "$n" -eq 0 ] && ok "a dry run left the tree empty" || bad "a dry run wrote $n path(s)"
grep -qiE 'would|dry' <<<"$out" && ok "and reported what it would do" \
  || bad "a dry run said nothing useful: ${out:0:110}"
mode=$(stat -c '%a %U:%G' "$D")
[ "$mode" = "755 op:op" ] && ok "and did not reshare the tree" || bad "a dry run changed the tree to $mode"

# --------------------------------------------------------------------------
head_ "P9. the values still do not leak from an enrolled tree"

out=$(runuser -u $OP -- /usr/local/bin/faramir run --quiet -t 20 -C /home/op/p-multi \
  --env PW=secret://db/password -- /bin/sh -c 'echo $PW' 2>&1)
grep -qF "$SECRET" <<<"$out" && bad "the value came back in plaintext from an enrolled tree" \
  || ok "a value injected in a freshly enrolled tree comes back redacted"
grep -q '«SECRET:db/password»' <<<"$out" && ok "as its token" || bad "no token: ${out:0:110}"
# Nothing enrolment wrote carries a value.
if grep -rqF "$SECRET" /home/op/p-multi /home/op/.claude /home/op/.gemini /home/op/.config 2>/dev/null; then
  bad "a value is written into the enrolled configuration"
else
  ok "and no file enrolment wrote carries a value"
fi

# --------------------------------------------------------------------------
printf '\n== suite P: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
