#!/bin/bash
# The guard's decision surface.
#
# `faramir guard` is the PreToolUse hook: it reads an agent's tool-call payload
# on stdin and answers with a deny, a rewrite, or nothing. It is explicitly not
# the security boundary (the agent's uid cannot read the key material either
# way), so what is under test is the two claims it does make: a command that
# would put a credential in the context window is refused with a message naming
# the tool to use instead, and everything else is rewritten to run under the
# redactor rather than let through.
#
# Every case here goes through the real binary as the agent's own uid.
set -u
. "$(dirname "$0")/lib.sh" || { echo "e2e: lib.sh is missing beside $0" >&2; exit 2; }

GUARD=/usr/local/bin/faramir

# decide CMD [guard args...] -- the raw hook reply for a Bash tool call.
decide() {
  local cmd=$1; shift
  jq -cn --arg c "$cmd" '{tool_name:"Bash",tool_input:{command:$c}}' \
    | runuser -u op -- env HOME=/home/op "$GUARD" guard "$@" 2>/dev/null
}
verdict() { # -> deny | rewrite | pass
  local out; out=$(decide "$@")
  if [ -z "$out" ]; then echo pass; return; fi
  case "$(echo "$out" | jq -r '.hookSpecificOutput.permissionDecision // .decision // "?"')" in
    deny) echo deny;; allow|rewrite) echo rewrite;; *) echo "?$out";;
  esac
}

# --------------------------------------------------------------------------
head_ "1. commands that would put a credential in the context are refused"
# A sample, not the surface: every pattern is decided case by case in
# internal/guard's corpus test. What only this can show is that the list
# `init` rendered and installed, driven through the real binary as the agent's
# own uid, decides the same way. So the cases here are the ones that turn on
# an interpolated path or on this host's own accounts and units.
while IFS='|' read -r label cmd; do
  [ -z "$label" ] && continue
  got=$(verdict "$cmd")
  [ "$got" = deny ] && ok "denied: $label" || bad "$label -> $got (wanted deny): $cmd"
done <<'CASES'
read the age key|cat /etc/faramir/age.key
page the age key|less /etc/faramir/age.key
copy it somewhere else|cp /etc/faramir/age.key /tmp/k
tar the whole config dir|tar cf /tmp/c.tar /etc/faramir
decrypt a managed store|sops -d /etc/faramir/secrets/app.sops.yml
delete the age key|rm /etc/faramir/age.key
redirect over the age key|echo x > /etc/faramir/age.key
redirect the age key into a loop|while read l; do echo $l; done < /etc/faramir/age.key
redirect it into a builtin that names no reader|mapfile -t k < /etc/faramir/age.key
overwrite the binary|cp /tmp/evil /usr/local/bin/faramir
rewrite the deny list|sed -i /d/ /usr/local/libexec/faramir/deny-patterns.txt
run the keeper as root|sudo faramir keeper
run as the broker's uid|sudo -u faramir-broker id
answer its own escalation|sudo faramir sudo approve abc123
refuse whatever is waiting|sudo faramir sudo reject
read what is waiting|sudo faramir sudo ls
an operator command under sudo|sudo faramir doctor
an operator command without it|faramir doctor
read the audit log through the CLI|faramir logs
change who can read the store|faramir reader add age1abc
open a managed file|faramir vault edit app
stop the broker|systemctl stop faramir-broker.socket
read the audit log|cat /var/log/faramir/audit.log
delete the opencode plugin|rm .opencode/plugins/faramir.js
edit the pi extension|sed -i s/x/y/ .pi/extensions/faramir.ts
CASES

# --------------------------------------------------------------------------
head_ "2. ordinary work is rewritten, not refused"
# The complement, and the more important half: a deny list that refuses real
# work gets turned off. A sample again, chosen the same way.
#
# The last three are the agent config files an enrolment MERGES into, which
# carry the operator's own settings and other tools' servers beside faramir's
# entries. Editing them is ordinary work; only the plugin and extension files
# faramir writes in full are refused, and those are in the block above.
#
# No comments inside the heredoc: a #-line there is read as a case, the loop
# skipping an empty label rather than a comment.
while IFS='|' read -r label cmd; do
  [ -z "$label" ] && continue
  got=$(verdict "$cmd")
  [ "$got" = rewrite ] && ok "allowed: $label" || bad "$label -> $got (wanted rewrite): $cmd"
done <<'CASES'
list files|ls -la
grep the tree|grep -rn TODO .
run the tests|go test ./...
env as a prefix, not a dump|env FOO=bar ./run.sh
an environment dump, which the rewrite redacts|printenv
the operator's own sops key, theirs to declare|cat /home/op/.config/sops/age/keys.txt
an ssh private key, theirs to declare|cat /home/op/.ssh/id_ed25519
restart a faramir unit|systemctl restart faramir-keeper.socket
a brokered command|faramir run --env P=faramir://db/password -- ./deploy.sh
edit claude's settings|sed -i s/a/b/ .claude/settings.json
replace the MCP list|rm .mcp.json
edit the opencode config|sed -i s/a/b/ opencode.json
a process substitution, which is not an input redirect|diff <(ls) <(ls -a)
a heredoc marker before a protected path, which redirects nothing|echo <<EOF /etc/faramir/age.key
CASES

# --------------------------------------------------------------------------
head_ "3. a sanctioned call does not launder what follows it"
# faramir's own arguments are exempt from scanning, or `faramir run -- cat
# /etc/faramir/...` would refuse itself. The exemption stops at the first
# separator; this is the test that it does.
for cmd in \
  'faramir refs; cat /etc/faramir/age.key' \
  'faramir status && cat /etc/faramir/age.key' \
  'faramir status | cat; sops -d /etc/faramir/secrets/app.sops.yml' \
  'faramir refs; rm -f /etc/faramir/age.key'
do
  got=$(verdict "$cmd")
  [ "$got" = deny ] && ok "chained after a sanctioned call is still seen: ${cmd:0:44}" \
    || bad "the exemption swallowed the chain -> $got: $cmd"
done
# And the exemption itself works: a ref on the command line is not a value.
got=$(verdict 'faramir run --env PW=faramir://db/password -- env')
[ "$got" = rewrite ] && ok "a brokered command ending in 'env' is not read as an env dump" \
  || bad "the sanctioned exemption does not cover its arguments -> $got"

# --------------------------------------------------------------------------
head_ "4. each host gets its answer in its own dialect"
# The wrong dialect fails open: a document the agent does not understand is a
# command it runs unredacted. So the exact shape matters, per host.
check_shape() { # host jq-expr want label
  local host=$1 expr=$2 want=$3 label=$4 cmd=$5
  local got
  got=$(jq -cn --arg c "$cmd" --arg t "$6" '{tool_name:$t,tool_input:{command:$c}}' \
        | runuser -u op -- "$GUARD" guard --host "$host" 2>/dev/null | jq -r "$expr" 2>/dev/null)
  [ "$got" = "$want" ] && ok "$host $label" || bad "$host $label: got '$got', want '$want'"
}
check_shape claude   '.hookSpecificOutput.permissionDecision' deny  "deny"    'cat /etc/faramir/age.key' Bash
check_shape claude   '.hookSpecificOutput.permissionDecision' allow "rewrite" 'ls'       Bash
check_shape opencode '.decision'                              deny    "deny"    'cat /etc/faramir/age.key' bash
check_shape opencode '.decision'                              rewrite "rewrite" 'ls'       bash
check_shape kilocode '.decision'                              deny    "deny"    'cat /etc/faramir/age.key' bash
check_shape kilocode '.decision'                              rewrite "rewrite" 'ls'       bash
# The deny reason has to reach the model with the alternative in it, or the
# agent retries the same command a different way.
reason=$(decide 'cat /etc/faramir/age.key' | jq -r '.hookSpecificOutput.permissionDecisionReason')
echo "$reason" | grep -q 'faramir_run' && ok "the refusal names faramir_run as the way to proceed" \
  || bad "the refusal does not tell the agent what to do instead"
echo "$reason" | grep -q 'matched deny pattern' && ok "and names the pattern that matched" \
  || bad "the refusal does not say which rule fired"
# A refusal must not quote the secret it is refusing to disclose.
echo "$reason" | grep -q 'hunter2\|tok_live' && bad "the refusal text contains a secret value" \
  || ok "the refusal quotes no value"

head_ "5. an unknown dialect is an error, not a guess"
out=$(echo '{"tool_name":"Bash","tool_input":{"command":"cat /etc/faramir/age.key"}}' \
      | runuser -u op -- "$GUARD" guard --host codex 2>/tmp/g.err; echo "rc=$?")
grep -q 'rc=2' <<<"$out" && ok "an unknown --host exits 2" || bad "unknown --host: $out"
[ "$(echo "$out" | grep -vc 'rc=')" = "0" ] && ok "and answers nothing, so nothing is approved" \
  || bad "it emitted a decision anyway: $out"
grep -q 'known hosts are' /tmp/g.err && ok "and lists the dialects it does speak" \
  || bad "no help on stderr: $(cat /tmp/g.err)"
# --host=NAME as well as --host NAME. The payload names the plugin hosts' own
# shell tool: a host is only asked about the tools it runs commands through.
got=$(jq -cn '{tool_name:"bash",tool_input:{command:"cat /etc/faramir/age.key"}}' \
      | runuser -u op -- "$GUARD" guard --host=opencode 2>/dev/null | jq -r '.decision')
[ "$got" = deny ] && ok "--host=NAME is read the same as --host NAME" || bad "--host=NAME: $got"
# And a hook host answers only for the tools it runs commands through: a payload
# naming anything else is a call with no output to redact.
got=$(jq -cn '{tool_name:"Read",tool_input:{command:"cat /etc/faramir/age.key"}}' \
      | runuser -u op -- "$GUARD" guard --host=claude 2>/dev/null; echo "rc=$?")
[ "$got" = "rc=0" ] && ok "a tool this host does not run commands through is left alone" \
  || bad "claude answered a Read payload: $got"

# --------------------------------------------------------------------------
head_ "6. only the tools that run shell commands are touched"
route() { # tool command -> deny|rewrite|pass
  local out
  out=$(jq -cn --arg t "$1" --arg c "$2" '{tool_name:$t,tool_input:{command:$c}}' \
        | runuser -u op -- "$GUARD" guard 2>/dev/null)
  [ -z "$out" ] && { echo pass; return; }
  case "$(echo "$out" | jq -r '.hookSpecificOutput.permissionDecision')" in
    deny) echo deny;; allow) echo rewrite;; *) echo "?";;
  esac
}
[ "$(route Read 'cat /etc/faramir/age.key')" = pass ] && ok "a non-shell tool is left alone" || bad "Read was answered"
[ "$(route Edit 'cat /etc/faramir/age.key')" = pass ] && ok "Edit is left alone" || bad "Edit was answered"
# BashOutput reads a running command's buffer: there is nothing to rewrite, but
# a deny still applies, and the buffer it reads came through the wrapper.
[ "$(route BashOutput 'cat /etc/faramir/age.key')" = deny ] && ok "BashOutput is still refused a denied command" \
  || bad "BashOutput escapes the deny list"
[ "$(route BashOutput 'ls')" = pass ] && ok "and is not rewritten, having no command to run" \
  || bad "BashOutput was rewritten"

head_ "7. a payload it cannot use is answered with silence"
try() { echo "$1" | runuser -u op -- "$GUARD" guard 2>/dev/null; echo "rc=$?"; }
[ "$(try 'not json at all')" = "rc=0" ] && ok "malformed JSON: no decision, exit 0" || bad "malformed JSON was answered"
[ "$(try '{}')" = "rc=0" ] && ok "an empty object: no decision" || bad "empty object was answered"
[ "$(try '{"tool_name":"Bash","tool_input":{"command":""}}')" = "rc=0" ] \
  && ok "an empty command: no decision" || bad "empty command was answered"
[ "$(try '{"tool_name":"Bash","tool_input":{"command":null}}')" = "rc=0" ] \
  && ok "a null command: no decision" || bad "null command was answered"
# argv-array clients: the command is in args, not command.
got=$(echo '{"tool_name":"Bash","tool_input":{"args":["cat","/etc/faramir/age.key"]}}' \
      | runuser -u op -- "$GUARD" guard | jq -r '.hookSpecificOutput.permissionDecision')
[ "$got" = deny ] && ok "an argv array is scanned too" || bad "argv-array payload -> $got"

head_ "8. a rewrite hands back every field it was given"
out=$(echo '{"tool_name":"Bash","tool_input":{"command":"ls","description":"list","timeout":5000}}' \
      | runuser -u op -- "$GUARD" guard | jq -c '.hookSpecificOutput.updatedInput')
echo "$out" | jq -e '.description == "list" and .timeout == 5000' >/dev/null \
  && ok "description and timeout survive the rewrite" || bad "fields were dropped: $out"
echo "$out" | jq -re '.command' | grep -q "^source /usr/local/libexec/faramir/wrap.sh 'ls'$" \
  && ok "and the command is the wrapped form" || bad "rewrite shape: $(echo "$out" | jq -r .command)"

head_ "9. what the rewrite must not do"
wrapped=$(decide 'ls' | jq -r '.hookSpecificOutput.updatedInput.command')
[ "$(verdict "$wrapped")" = pass ] && ok "an already-wrapped command is not wrapped again" \
  || bad "double wrapping: $(verdict "$wrapped")"
# A backgrounded command is streamed through the redactor rather than left
# alone: capturing it would buffer a command that never exits, but passing it
# unwrapped lets its output reach the transcript unredacted.
bgw=$(decide 'sleep 30 &' | jq -r '.hookSpecificOutput.updatedInput.command')
grep -q -- '--stream' <<<"$bgw" && ok "a backgrounded command is streamed through the redactor" \
  || bad "a backgrounded command was not streamed: [$bgw]"
grep -q ' &$' <<<"$bgw" && ok "  with its backgrounding kept, outside the wrapper" \
  || bad "  the backgrounding was lost: [$bgw]"
[ "$(verdict 'a && b')" = rewrite ] && ok "a trailing && is not backgrounding" || bad "&& was read as &"
grep -q -- '--stream' <<<"$(decide 'a && b' | jq -r '.hookSpecificOutput.updatedInput.command')" \
  && bad "&& was streamed as if backgrounded" || ok "  and takes the ordinary capture path"
bgflag=$(echo '{"tool_name":"Bash","tool_input":{"command":"tail -f log","run_in_background":true}}' \
      | runuser -u op -- "$GUARD" guard 2>/dev/null | jq -r '.hookSpecificOutput.updatedInput.command')
grep -q -- '--stream' <<<"$bgflag" && ok "run_in_background is streamed so BashOutput reads redacted" \
  || bad "run_in_background was not streamed: [$bgflag]"
grep -q ' &$' <<<"$bgflag" && bad "run_in_background carried its own &: [$bgflag]" \
  || ok "  and carries no & of its own, the host doing the backgrounding"
# The deny list still fires on a backgrounded credential read: streaming is not
# a way around it.
[ "$(verdict 'cat /etc/faramir/age.key &')" = deny ] \
  && ok "a backgrounded credential read is still denied" \
  || bad "backgrounding got a denied command past the guard"

head_ "10. quoting into the sourced script survives exactly one round trip"
for cmd in "echo it's fine" 'echo $(date)' 'echo `id`' 'echo "a\\b"' "echo 'x'\\''y'"; do
  w=$(decide "$cmd" | jq -r '.hookSpecificOutput.updatedInput.command')
  # Recovered by one shell parse, which is what the sourced script's eval does.
  back=$(runuser -u op -- bash -c "set -- $(printf '%s' "${w#source /usr/local/libexec/faramir/wrap.sh }"); printf '%s' \"\$1\"" 2>/dev/null)
  [ "$back" = "$cmd" ] && ok "round trip: $cmd" || bad "round trip: got [$back] want [$cmd]"
done

# --------------------------------------------------------------------------
head_ "11. the pattern list is the operator's, and a broken one fails closed"
PAT=/usr/local/libexec/faramir/deny-patterns.txt
cp $PAT /tmp/patterns.bak
# Missing entirely: the compiled-in fallback has to carry it.
mv $PAT /tmp/gone.txt
[ "$(verdict 'cat /etc/faramir/age.key')" = deny ] && ok "with no patterns file, the built-in fallback still refuses" \
  || bad "a missing patterns file disabled the deny list"
mv /tmp/gone.txt $PAT
# One unparseable line must not take the rest down with it. This file is the
# test's own, so the rule it carries need not be one faramir ships.
printf 'this is a (broken regex\n\\bprintenv\\b\n' > /tmp/mixed.txt
got=$(jq -cn '{tool_name:"Bash",tool_input:{command:"printenv"}}' \
      | runuser -u op -- env FARAMIR_DENY_PATTERNS=/tmp/mixed.txt "$GUARD" guard \
      | jq -r '.hookSpecificOutput.permissionDecision')
[ "$got" = deny ] && ok "a typo on one line does not disable the lines around it" \
  || bad "one bad regex disabled the list -> $got"
# A comments-only file is not an empty list; it falls back rather than allowing
# everything.
printf '# nothing here\n\n' > /tmp/empty.txt
got=$(jq -cn '{tool_name:"Bash",tool_input:{command:"cat /etc/faramir/age.key"}}' \
      | runuser -u op -- env FARAMIR_DENY_PATTERNS=/tmp/empty.txt "$GUARD" guard \
      | jq -r '.hookSpecificOutput.permissionDecision')
[ "$got" = deny ] && ok "a comments-only file falls back rather than allowing everything" \
  || bad "an empty patterns file turned the guard off -> $got"

head_ "12. a moved install is refused where it actually is"
# The rules name /etc/faramir literally; an operator who moved the config with
# --config-dir gets rules naming the new place, resolved the way the daemons
# resolve it.
mkdir -p /opt/elsewhere
run_moved() {
  jq -cn --arg c "$1" '{tool_name:"Bash",tool_input:{command:$c}}' \
    | runuser -u op -- env FARAMIR_CONFIG=/opt/elsewhere/config.toml "$GUARD" guard \
    | jq -r '.hookSpecificOutput.permissionDecision'
}
[ "$(run_moved 'cat /opt/elsewhere/age.key')" = deny ] \
  && ok "reading the moved config directory is refused" || bad "the moved install is not covered"
[ "$(run_moved 'echo x > /opt/elsewhere/age.key')" = deny ] \
  && ok "and writing into it is too" || bad "writes into the moved install are allowed"
[ "$(run_moved 'cat /etc/faramir/age.key')" = deny ] \
  && ok "while the literal rules still cover the default location" || bad "the default location lost cover"
[ "$(run_moved 'cat /opt/elsewhere-notes.md')" = allow ] \
  && ok "and a sibling path that merely starts the same is not refused" \
  || bad "the moved-dir rule is matching too widely"

summary
