#!/bin/bash
# `faramir init-project`, the enrolment that makes a tree protected.
#
# The stakes are the reason this is a suite of its own. Every other command
# fails loudly; this one fails silently. If enrolment writes the wrong thing,
# the guard and the wrapper never run, and commands execute unredacted in a
# project the operator believes is covered. So the assertions are about what
# lands on disk AND about whether the thing it lands works.
#
# Four agents, and until now the suites enrolled only claude. The other three
# write different files in different places, so each is enrolled into a tree of
# its own here.
#
# Run as root in the e2e container.
set -u
OP=op
HOME_OP=/home/op
SECRET='hunter2-correct-horse-battery'
. "$(dirname "$0")/lib.sh" || { echo "e2e: lib.sh is missing beside $0" >&2; exit 2; }

# tree makes an empty working tree owned by the operator, as a checkout would be.
tree() {
  local d=$1
  rm -rf "$d"
  install -d -o $OP -g $OP -m 0755 "$d"
  printf '%s\n' "$d"
}
enrol() { # dir, then --agent flags
  local d=$1; shift
  /usr/local/bin/faramir init-project --agent-user $OP "$@" "$d" 2>&1
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

echo "enrolling as $OP; agents: claude antigravity opencode kilocode"

# --------------------------------------------------------------------------
head_ "1. each agent's own file set"

D=$(tree /home/op/p-claude); enrol "$D" --agent claude >/tmp/p-claude.log 2>&1 \
  || bad "claude enrolment failed: $(tail -2 /tmp/p-claude.log)"
owned "$D/.claude/settings.local.json" "claude: project settings"
owned "$D/.mcp.json" "claude: MCP registration"


# Antigravity gets no hook, there being none it could register: the MCP
# registration and a rules file of prose are the whole of its enrolment.
D=$(tree /home/op/p-antigravity); enrol "$D" --agent antigravity >/tmp/p-anti.log 2>&1 \
  || bad "antigravity enrolment failed: $(tail -2 /tmp/p-anti.log)"
owned "$D/.agents/mcp_config.json" "antigravity: MCP registration"
owned "$D/.agents/rules/faramir.md" "antigravity: rules file"
grep -q 'trigger: always_on' "$D/.agents/rules/faramir.md" \
  && ok "antigravity: the rules file is headed so the agent loads it" \
  || bad "the rules file carries no always-on frontmatter, so it may never be read"


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
/usr/local/bin/faramir init --agent-user $OP --agent claude --agent antigravity \
  --agent opencode --agent kilocode >/tmp/p-init.log 2>&1
owned "$HOME_OP/.claude/settings.json" "claude: account-wide settings (from init)"
owned "$HOME_OP/.gemini/GEMINI.md" "antigravity: credentials section (from init)"
owned "$HOME_OP/.config/opencode/opencode.json" "opencode: account-wide deny rules (from init)"
owned "$HOME_OP/.config/kilo/kilo.json" "kilocode: account-wide deny rules (from init)"

# Nothing lands in root's home, which is where a command run under sudo would
# put an account-wide file if it took the caller's HOME rather than the
# operator's.
for stray in /root/.claude /root/.gemini /root/.config/opencode /root/.config/kilo; do
  absent "$stray" "$(basename "$stray") in root's home"
done

# --------------------------------------------------------------------------
head_ "2. every file it writes is valid to the tool that reads it"

for f in /home/op/p-claude/.claude/settings.local.json /home/op/p-claude/.mcp.json \
         /home/op/p-antigravity/.agents/mcp_config.json \
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
    note "no node in the image, so $(basename "$js") went unparsed"; continue
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
for f in /home/op/p-claude/.claude/settings.local.json \
         /home/op/p-antigravity/.agents/mcp_config.json; do
  grep -q '/usr/local/bin/faramir' "$f" && ok "names the installed binary: ${f#/home/op/}" \
    || bad "does not name the binary: $f"
done

# --------------------------------------------------------------------------
head_ "3. the hook it registers actually runs and denies"
#
# The point of enrolment. A settings.local.json naming a hook that does not run is
# the silent failure this whole suite exists for, so the command in the file is
# extracted and executed.

hook=$(jq -r '.hooks.PreToolUse[0].hooks[0].command' /home/op/p-claude/.claude/settings.local.json 2>/dev/null)
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
  # The other tool the host runs commands through, in the shape it arrives in:
  # it names a running shell and carries no command. What filled that buffer
  # went through the redactor when it started, so the hook has nothing to say;
  # denying it would leave a backgrounded command's output unreadable.
  out=$(printf '{"tool_name":"BashOutput","tool_input":{"bash_id":"bash_1"}}' \
    | runuser -u $OP -- sh -c "cd /home/op/p-claude && $hook" 2>/dev/null)
  [ -z "$(tr -d '[:space:]' <<<"$out")" ] \
    && ok "and says nothing about a read of a running command's output" \
    || bad "BashOutput was answered rather than left alone: ${out:0:120}"
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
head_ "4. it merges into what the operator already had"
#
# Every shared file is merged rather than replaced. An enrolment that discarded
# an operator's own settings would be found the hard way, in a project whose
# other tooling stopped working.

D=$(tree /home/op/p-merge)
runuser -u $OP -- mkdir -p "$D/.claude"
runuser -u $OP -- tee "$D/.claude/settings.local.json" >/dev/null <<'JSON'
{"model": "opus", "env": {"MY_OWN": "keep me"}, "hooks": {"PostToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/bin/true"}]}]}}
JSON
runuser -u $OP -- tee "$D/.mcp.json" >/dev/null <<'JSON'
{"mcpServers": {"mine": {"command": "/usr/bin/true"}}}
JSON
enrol "$D" --agent claude >/tmp/p-merge.log 2>&1 || bad "merge enrolment failed"

jq -e '.model == "opus"' "$D/.claude/settings.local.json" >/dev/null \
  && ok "the operator's own scalar survived the merge" || bad "settings.local.json lost .model"
jq -e '.env.MY_OWN == "keep me"' "$D/.claude/settings.local.json" >/dev/null \
  && ok "and their own env entry" || bad "settings.local.json lost .env.MY_OWN"
jq -e '.hooks.PostToolUse[0].hooks[0].command == "/usr/bin/true"' "$D/.claude/settings.local.json" >/dev/null \
  && ok "and their own unrelated hook" || bad "settings.local.json lost the operator's PostToolUse hook"
jq -e '.hooks.PreToolUse != null' "$D/.claude/settings.local.json" >/dev/null \
  && ok "while faramir's PreToolUse hook was added beside it" || bad "the faramir hook was not added"
jq -e '.mcpServers.mine.command == "/usr/bin/true"' "$D/.mcp.json" >/dev/null \
  && ok "the operator's own MCP server survived" || bad ".mcp.json lost the operator's server"
jq -e '.mcpServers.faramir != null' "$D/.mcp.json" >/dev/null \
  && ok "and faramir's was added beside it" || bad "faramir's MCP server was not added"

# A file the operator owns stays theirs after root has written to it.
owned "$D/.claude/settings.local.json" "the merged file is still the operator's"

# A file the merge cannot read is refused, and refused before the share: that
# walk cannot be undone, so a refusal arriving at the write would leave the
# client group holding a tree with no hook registered in it.
B=/home/op/p-unparsable
rm -rf $B; install -d -o $OP -g $OP $B
runuser -u $OP -- mkdir -p "$B/.claude"
runuser -u $OP -- tee "$B/.claude/settings.local.json" >/dev/null <<'JSON'
{ not json
JSON
out=$(enrol "$B" --agent claude 2>&1)
grep -q 'parsing the file already there' <<<"$out" \
  && ok "an agent config that does not parse is refused" \
  || bad "an unparseable agent config was not named: ${out:0:120}"
mode=$(stat -c '%U:%G' "$B")
[ "$mode" = "$OP:$OP" ] && ok "and the tree was not shared on the way to refusing" \
  || bad "the tree is $mode after a refused enrolment: the share ran anyway"

# --------------------------------------------------------------------------
head_ "5. enrolling twice changes nothing"

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

# Identical content is not the same as untouched. writeFile documents an
# unchanged re-run as writing nothing, so the inode is what says whether it did.
now=$(find "$D" -type f -exec stat -c '%n %i' {} \; | sort)
[ "$inodes" = "$now" ] && ok "and rewrites none of them" \
  || bad "every file is rewritten on a no-op run (inodes move, bytes do not): $(diff <(echo "$inodes") <(echo "$now") | grep -c '^<') file(s)"
# Which is what the report tells the operator.
n=$(/usr/local/bin/faramir init-project --agent-user $OP --agent claude --json "$D" 2>/dev/null \
  | jq '[.steps[]|select(.changed)]|length')
[ "$n" -eq 0 ] && ok "and reports nothing changed" \
  || bad "a no-op enrolment reports $n step(s) changed, so an operator cannot tell a real run from this one"
# And the hook is registered once, not twice.
n=$(jq '[.hooks.PreToolUse[]?.hooks[]? | select(.command | test("faramir"))] | length' "$D/.claude/settings.local.json")
[ "$n" -eq 1 ] && ok "the faramir hook is registered once, not appended again" \
  || bad "$n faramir hooks after two enrolments"

# --------------------------------------------------------------------------
head_ "6. several agents in one tree"

D=$(tree /home/op/p-multi)
enrol "$D" --agent claude --agent antigravity --agent opencode --agent kilocode >/tmp/p-multi.log 2>&1 \
  || bad "multi-agent enrolment failed: $(tail -2 /tmp/p-multi.log)"
for f in .claude/settings.local.json .mcp.json .agents/mcp_config.json \
         .opencode/plugins/faramir.js opencode.json .kilo/plugin/faramir.js kilo.json; do
  [ -e "$D/$f" ] && ok "  $f" || bad "  $f was not written by the multi-agent enrolment"
done

# --------------------------------------------------------------------------
head_ "7. the tree itself is shared with the executor"

D=/home/op/p-claude
mode=$(stat -c '%a %U:%G' "$D")
[ "$mode" = "2770 op:faramir-client" ] && ok "the tree is $mode: setgid, group-shared" \
  || bad "the tree is $mode, want 2770 op:faramir-client"
# The agent's own directory is sticky as well, so unlink there is the file's
# owner's: the settings naming the hook are 0640, which says nothing about being
# unlinked. The root is deliberately not, so a tool rewriting a file there by
# rename still works.
mode=$(stat -c '%a' "$D/.claude")
[ "$mode" = "3770" ] && ok "and the agent's own directory is $mode: sticky" \
  || bad ".claude is $mode, want 3770: a brokered command can unlink the hook settings"
# What that buys, asked of the account it is meant to stop.
if runuser -u faramir-exec -- rm -f "$D/.claude/settings.local.json" 2>/dev/null; then
  bad "the executor deleted the settings naming the hook"
else
  ok "and the executor cannot delete the settings naming the hook"
fi
# On a tree enrolled once, which is the state an operator leaves one in. The
# walk that sets the sticky bit runs before the enrolment writes anything, so a
# directory the enrolment creates is the case the tree above cannot show: it has
# been enrolled twice, and the second walk found the directory there.
F=/home/op/p-once
rm -rf $F; install -d -o $OP -g $OP $F
enrol "$F" --agent claude >/dev/null 2>&1
mode=$(stat -c '%a' "$F/.claude")
[ "$mode" = "3770" ] && ok "one enrolment is enough to make it sticky" \
  || bad ".claude is $mode after a single enrolment, want 3770: until a second run it can be unlinked"
if runuser -u faramir-exec -- rm -f "$F/.claude/settings.local.json" 2>/dev/null; then
  bad "the executor deleted the hook settings in a tree enrolled once"
else
  ok "and the executor cannot delete the hook settings there either"
fi
id -nG faramir-exec | grep -qw faramir-client && ok "and the executor is in that group" \
  || bad "the executor is not in the tree's group"
# Which is what lets a brokered command run there at all.
out=$(runuser -u $OP -- /usr/local/bin/faramir run --quiet -t 20 -C "$D" -- /bin/pwd 2>&1)
[ "$(tail -1 <<<"$out")" = "$D" ] && ok "so a brokered command runs in it" \
  || bad "a brokered command cannot enter the enrolled tree: ${out:0:110}"
# What enrolment buys is reach into a tree the executor could not otherwise
# enter. A 0755 checkout is world-traversable and needs no enrolment for that,
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
head_ "8. --dry-run writes nothing"

D=$(tree /home/op/p-dry)
out=$(enrol "$D" --agent claude --dry-run)
n=$(find "$D" -mindepth 1 | wc -l)
[ "$n" -eq 0 ] && ok "a dry run left the tree empty" || bad "a dry run wrote $n path(s)"
grep -qiE 'would|dry' <<<"$out" && ok "and reported what it would do" \
  || bad "a dry run said nothing useful: ${out:0:110}"
mode=$(stat -c '%a %U:%G' "$D")
[ "$mode" = "755 op:op" ] && ok "and did not reshare the tree" || bad "a dry run changed the tree to $mode"

# --------------------------------------------------------------------------
head_ "9. the values still do not leak from an enrolled tree"

out=$(runuser -u $OP -- /usr/local/bin/faramir run --quiet -t 20 -C /home/op/p-multi \
  --env PW=faramir://db/password -- /bin/sh -c 'echo $PW' 2>&1)
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
head_ "10. the record of what was enrolled"
#
# An enrolment writes into the tree and into the operator's home, and neither
# half names the other: a tree carries an agent's settings without saying which
# account they were written for, and a home carries deny rules without saying
# which trees rely on them. This file is the only thing that can tell `doctor`
# a tree depends on rules the home it is looking at shows no sign of.

REC=/etc/faramir/enrolled.json
# agentsOf and agentUserOf read one tree's entry. Empty when there is none,
# which is itself an assertion below.
agentsOf()    { jq -r --arg d "$1" '[.[]|select(.dir==$d)|.agents[]]|join(",")' $REC 2>/dev/null; }
agentUserOf() { jq -r --arg d "$1" '[.[]|select(.dir==$d)|.agent_user]|join(",")' $REC 2>/dev/null; }
entriesFor() { jq -r --arg d "$1" '[.[]|select(.dir==$d)]|length' $REC 2>/dev/null; }

mode=$(stat -c '%a %U:%G' $REC 2>/dev/null)
[ "$mode" = "600 root:root" ] && ok "the record is $mode: init-project writes it and doctor reads it, both as root" \
  || bad "the record is [$mode], want 600 root:root"
jq -e . $REC >/dev/null 2>&1 && ok "and parses as JSON" \
  || bad "the record does not parse: $(head -c 120 $REC 2>/dev/null)"

D=$(tree /home/op/p-record)
enrol "$D" --agent claude --agent antigravity >/dev/null 2>&1
[ "$(agentsOf "$D")" = "antigravity,claude" ] && ok "an enrolment records the agents it was made for" \
  || bad "recorded [$(agentsOf "$D")], want antigravity,claude"
[ "$(agentUserOf "$D")" = "$OP" ] && ok "and the account it was made for" \
  || bad "recorded agent_user [$(agentUserOf "$D")], want $OP"

# Keyed by directory, so a tree has one entry however often it is enrolled. Its
# agents are the ones this run named plus the ones an earlier run did that the
# tree still carries: enrolling one by name does not say the others have gone,
# their hook and MCP registration still being there for doctor to check.
enrol "$D" --agent opencode >/dev/null 2>&1
[ "$(agentsOf "$D")" = "antigravity,claude,opencode" ] \
  && ok "re-enrolling keeps the agents the tree still carries, and adds the new one" \
  || bad "the entry is [$(agentsOf "$D")], want antigravity,claude,opencode"
[ "$(entriesFor "$D")" = 1 ] && ok "and the tree appears once" \
  || bad "the tree has $(entriesFor "$D") entries"

# Bounded by what is in the tree, because the entry is not only read: an
# enrolled agent whose rules are missing is a doctor failure, so a name that
# accumulated and could never leave would fail the command for ever on an agent
# the operator had removed. Evidence gone is configuration gone.
rm -rf "$D/.claude"
enrol "$D" --agent opencode >/dev/null 2>&1
[ "$(agentsOf "$D")" = "antigravity,opencode" ] \
  && ok "and an agent whose configuration has left the tree drops out of the entry" \
  || bad "the entry is [$(agentsOf "$D")], want antigravity,opencode"

[ "$(jq -r '[.[].dir] == ([.[].dir]|sort)' $REC)" = true ] \
  && ok "the entries are sorted by tree, so a second run does not churn the file" \
  || bad "the entries are not sorted: $(jq -c '[.[].dir]' $REC)"

# Nothing to tell doctor about, and an entry with no agents would report as
# though there were.
D=$(tree /home/op/p-noagent)
enrol "$D" >/dev/null 2>&1
[ -z "$(agentsOf "$D")" ] && ok "a tree enrolled for no agent leaves no entry" \
  || bad "an agentless enrolment was recorded as [$(agentsOf "$D")]"

# The half of it that matters: doctor asks this file, not the home.
D=$(tree /home/op/p-recorded); enrol "$D" --agent kilocode >/dev/null 2>&1
/usr/local/bin/faramir doctor --agent-user $OP --json >/tmp/p-doctor.json 2>/dev/null
rules() { jq -r '[.findings[]|select(.check=="agent rules")|.detail]|join(" | ")' /tmp/p-doctor.json; }
grep -q kilocode <<<"$(rules)" \
  && ok "doctor examines an agent because a tree was enrolled for it" \
  || bad "doctor says nothing about kilocode: $(rules | head -c 140)"

# Advisory and allowed to be stale: a tree can be moved or deleted with nothing
# to tell this file, so a reader reports the entry rather than treating it as a
# fault, and rather than dropping the record of it.
rm -rf "$D"
/usr/local/bin/faramir doctor --agent-user $OP --json >/tmp/p-doctor.json 2>/dev/null
grep -q "$D" <<<"$(rules)" && ok "a tree that has gone since is named rather than passed over" \
  || bad "doctor did not report the missing tree: $(rules | head -c 140)"
[ "$(entriesFor "$D")" = 1 ] && ok "and its entry survives, this file not being the authority on what exists" \
  || bad "the entry for a missing tree was removed"

# --------------------------------------------------------------------------
head_ "11. --agent auto, which the two commands ask of different places"
#
# The default on both. `init` asks the operator's home and `init-project` asks
# the tree, and naming an agent configures it whether or not it is there. So
# the two compose into the union, and there is no rule about which wins.

D=$(tree /home/op/p-auto-claude); install -d -o $OP -g $OP "$D/.claude"
enrol "$D" >/dev/null 2>&1
[ "$(agentsOf "$D")" = "claude" ] && ok "a tree carrying .claude enrols claude with no --agent given" \
  || bad "auto found [$(agentsOf "$D")] in a tree carrying .claude"

D=$(tree /home/op/p-auto-none)
out=$(enrol "$D")
[ -z "$(agentsOf "$D")" ] && ok "a tree carrying nothing enrols nothing" \
  || bad "auto found [$(agentsOf "$D")] in an empty tree"
grep -q 'no coding agent is configured' <<<"$out" \
  && ok "and says so rather than enrolling it silently" \
  || bad "an empty tree was enrolled with nothing said: ${out:0:120}"
grep -q 'antigravity, claude, kilocode, opencode, pi' <<<"$out" \
  && ok "  naming all five it could be told to write for" \
  || bad "  the message does not name the five: ${out:0:160}"

# Evidence, not proof: what is found is added to what was asked for.
D=$(tree /home/op/p-auto-plus); install -d -o $OP -g $OP "$D/.claude"
enrol "$D" --agent auto --agent pi >/dev/null 2>&1
[ "$(agentsOf "$D")" = "claude,pi" ] && ok "auto and a name compose: what was found, plus what was asked for" \
  || bad "--agent auto --agent pi gave [$(agentsOf "$D")], want claude,pi"

D=$(tree /home/op/p-named-absent)
enrol "$D" --agent pi >/dev/null 2>&1
[ "$(agentsOf "$D")" = "pi" ] && ok "and a name alone enrols an agent the tree shows no sign of" \
  || bad "naming pi in a bare tree gave [$(agentsOf "$D")]"

# Refused rather than skipped, which would leave an operator believing an agent
# is covered.
D=$(tree /home/op/p-unknown)
out=$(enrol "$D" --agent nosuch); rc=$?
[ "$rc" -ne 0 ] && ok "an unknown --agent fails (exit $rc) rather than being passed over" \
  || bad "an unknown --agent exited 0"
grep -q 'unknown --agent' <<<"$out" && ok "and names the ones it does know" \
  || bad "the refusal explains nothing: ${out:0:120}"
[ -z "$(agentsOf "$D")" ] && ok "and nothing was enrolled" \
  || bad "a failed enrolment recorded [$(agentsOf "$D")]"

# --------------------------------------------------------------------------
head_ "12. the credentials section in the tree's instructions file"
#
# Documentation rather than enforcement: deleting the section changes nothing
# about what is reachable. What matters is that it is never written over
# somebody else's words, the file being prose an operator edits and asks agents
# to rewrite.

D=$(tree /home/op/p-instr)
enrol "$D" >/dev/null 2>&1
owned "$D/AGENTS.md" "the instructions file"
grep -q '^# Credentials' "$D/AGENTS.md" && ok "  carrying the credentials section" \
  || bad "  without the credentials section"
grep -q 'faramir_run' "$D/AGENTS.md" && ok "  which names the tool to use instead" \
  || bad "  it does not name faramir_run"

sum=$(md5sum "$D/AGENTS.md" | cut -d' ' -f1)
enrol "$D" >/dev/null 2>&1
[ "$(md5sum "$D/AGENTS.md" | cut -d' ' -f1)" = "$sum" ] \
  && ok "a second enrolment leaves a section that is already current byte-identical" \
  || bad "the instructions file was rewritten on a second run"

D=$(tree /home/op/p-instr-own)
printf '# House rules\n\nAlways run the tests.\n' > "$D/AGENTS.md"
chown $OP:$OP "$D/AGENTS.md"
enrol "$D" >/dev/null 2>&1
grep -q 'Always run the tests' "$D/AGENTS.md" && ok "an existing file keeps what the operator wrote" \
  || bad "the operator's own instructions were replaced"
grep -q '^# Credentials' "$D/AGENTS.md" && ok "and gains the section after it" \
  || bad "the section was not added to an existing file"

# Naming faramir is not carrying its section. A tree whose instructions mention
# the tool for any other reason still receives one, and keeps what was there.
D=$(tree /home/op/p-instr-mentions)
printf '# My notes\n\nWe use faramir here somehow.\n' > "$D/AGENTS.md"
chown $OP:$OP "$D/AGENTS.md"
enrol "$D" >/dev/null 2>&1
grep -q 'We use faramir here somehow' "$D/AGENTS.md" \
  && ok "a file that only mentions faramir keeps what the operator wrote" \
  || bad "the operator's words were replaced: [$(head -c 140 "$D/AGENTS.md")]"
grep -q '<!-- BEGIN faramir: credentials -->' "$D/AGENTS.md" \
  && ok "  and still receives the section, between markers" \
  || bad "  a file naming faramir was passed over: [$(head -c 140 "$D/AGENTS.md")]"

# A credentials section of faramir's in words that are not these, with no
# markers around it: what a version whose snippet read differently wrote, or a
# copy something reworded. Which of those it is cannot be read off the file,
# appending would leave two sections contradicting each other, and neither is
# faramir's to rewrite. So it is named and left.
D=$(tree /home/op/p-instr-drift)
printf '# Credentials\n\nWe use faramir here somehow.\n' > "$D/AGENTS.md"
chown $OP:$OP "$D/AGENTS.md"
sum=$(md5sum "$D/AGENTS.md" | cut -d' ' -f1)
out=$(enrol "$D")
[ "$(md5sum "$D/AGENTS.md" | cut -d' ' -f1)" = "$sum" ] \
  && ok "a drifted section is left byte-identical" \
  || bad "a drifted instructions file was edited in place"
grep -q 'already carries a credentials section that is not between markers' <<<"$out" \
  && ok "and the drift is reported rather than reconciled" \
  || bad "the drift was not reported: ${out:0:140}"
grep -q 'not written; see the error' <<<"$out" \
  && ok "  with the step naming the file it did not write" \
  || bad "  the step does not name the file it left: ${out:0:140}"

# CLAUDE.md when that is the file the tree has: the first of the two that
# exists is the one written into, and a second is never created.
D=$(tree /home/op/p-instr-claude)
printf '# Notes\n' > "$D/CLAUDE.md"; chown $OP:$OP "$D/CLAUDE.md"
enrol "$D" >/dev/null 2>&1
grep -q '^# Credentials' "$D/CLAUDE.md" && ok "CLAUDE.md is written into when that is the file the tree has" \
  || bad "the section did not go into CLAUDE.md"
absent "$D/AGENTS.md" "a second instructions file"

# --------------------------------------------------------------------------
head_ "13. a tree nothing in the client group can enter"
#
# A home is 0700, so every directory between it and the tree has to let the
# client group through. Group execute on the tree grants nothing while a
# directory above it refuses the traversal, and an enrolment that finished
# anyway would leave a tree that says it is shared and is not.
#
# The directories above the tree are outside what enrolment owns, so this is a
# refusal that names them rather than a chmod. That is the whole of the case:
# what it must NOT do is open them.

B=/home/op/p-blocked
rm -rf $B
install -d -o $OP -g $OP -m 0700 $B
install -d -o $OP -g $OP -m 0755 $B/tree
out=$(enrol $B/tree); rc=$?
[ $rc -ne 0 ] && ok "enrolment is refused (exit $rc)" \
  || bad "a tree behind a 0700 directory was enrolled anyway"
grep -q 'cannot enter' <<<"$out" \
  && ok "and says the group cannot enter it" \
  || bad "the refusal does not say what blocks it: ${out:0:200}"
grep -q "$B (op, 0700)" <<<"$out" \
  && ok "naming the blocking directory and the mode it has" \
  || bad "the refusal does not name $B and its mode: ${out:0:200}"
grep -q "chgrp faramir-client $B" <<<"$out" \
  && ok "and printing the command that opens it" \
  || bad "the refusal prints no remedy: ${out:0:200}"
# The refusal is the whole of what happened: nothing above the tree moved.
[ "$(stat -c '%a %U:%G' $B)" = "700 op:op" ] \
  && ok "and the blocking directory is left exactly as it was" \
  || bad "the refusal altered $B: $(stat -c '%a %U:%G' $B)"
[ -e $B/tree/.claude ] \
  && bad "the tree was half-enrolled before the refusal" \
  || ok "and the tree was not half-enrolled"

# Opened as the refusal asked, which is the operator's job and not faramir's,
# the same command goes through.
chgrp faramir-client $B
chmod g=x $B
out=$(enrol $B/tree); rc=$?
[ $rc -eq 0 ] && ok "opened as instructed, the enrolment goes through" \
  || bad "the remedy did not work: ${out:0:200}"
[ "$(stat -c '%a %U:%G' $B/tree)" = "2770 op:faramir-client" ] \
  && ok "and the tree is shared" \
  || bad "the tree is $(stat -c '%a %U:%G' $B/tree), want 2770 op:faramir-client"
rm -rf $B

# --------------------------------------------------------------------------
summary
