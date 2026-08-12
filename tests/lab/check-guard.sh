#!/bin/bash
# Suite A: the guard's decision surface.
#
# `faramir guard` is the PreToolUse hook: it reads an agent's tool-call payload
# on stdin and answers with a deny, a rewrite, or nothing.  It is explicitly not
# the security boundary (the agent's uid cannot read the key material either
# way), so what is under test is the two claims it does make: a command that
# would put a credential in the context window is refused with a message naming
# the tool to use instead, and everything else is rewritten to run under the
# redactor rather than let through.
#
# Every case here goes through the real binary as the agent's own uid.
set -u
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; }
head_() { printf '\n== %s\n' "$1"; }

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
head_ "A1. commands that would put a credential in the context are refused"
# One per disclosure route the deny list names.  Each is a real thing an agent
# would plausibly try while "just looking at the config".
while IFS='|' read -r label cmd; do
  [ -z "$label" ] && continue
  got=$(verdict "$cmd")
  [ "$got" = deny ] && ok "denied: $label" || bad "$label -> $got (wanted deny): $cmd"
done <<'CASES'
read the age key|cat /etc/faramir/age.key
page the age key|less /etc/faramir/age.key
hexdump the age key|xxd /etc/faramir/age.key
base64 the age key|base64 /etc/faramir/age.key
strings the age key|strings /etc/faramir/age.key
read it with python|python3 -c "print(open('/etc/faramir/age.key').read())"
copy it somewhere else|cp /etc/faramir/age.key /tmp/k
tar the whole config dir|tar cf /tmp/c.tar /etc/faramir
rsync the config dir|rsync -a /etc/faramir/ /tmp/c/
decrypt with sops|sops -d /etc/faramir/secrets/app.sops.yml
decrypt with sops (long)|sops --decrypt /etc/faramir/secrets/app.sops.yml
re-encrypt with sops|sops --encrypt /tmp/x.yml
decrypt with age|age -d -i /etc/faramir/age.key /tmp/x
mint and print a private key|age-keygen
ansible-vault view|ansible-vault view group_vars/all/vault.yml
1password read|op read op://vault/item/field
pass show|pass show personal/router
vault kv get|vault kv get secret/data/app
dump the environment|printenv
dump the environment (env)|env
dump the environment (set)|set
dump exported vars|declare -x
read a process environ|cat /proc/self/environ
read another process environ|cat /proc/1234/environ
read the operator's sops key|cat ~/.config/sops/age/keys.txt
read an ssh private key|cat ~/.ssh/id_ed25519
read an rsa key|head -20 /home/op/.ssh/id_rsa
read a .env file|cat .env
read a production .env|cat .env.production
read a secrets.yaml|head -5 config/secrets.yaml
read a credentials file|cat ~/.aws/credentials
read a pem|cat /etc/ssl/private/server.pem
find private keys|find / -name id_ed25519 2>/dev/null
find .env files|find . -name '*.env'
delete the age key|rm /etc/faramir/age.key
truncate the age key|truncate -s 0 /etc/faramir/age.key
chmod the config dir|chmod -R 777 /etc/faramir
redirect over the age key|echo x > /etc/faramir/age.key
overwrite the binary|cp /tmp/evil /usr/local/bin/faramir
rewrite the deny list|sed -i /d/ /usr/local/libexec/faramir/deny-patterns.txt
run the keeper as root|sudo faramir keeper
run as the broker's uid|sudo -u faramir-broker id
answer its own approval|sudo faramir approve abc123
list what is waiting|sudo faramir approvals
refuse its own approval|sudo faramir deny abc123
refuse whatever is waiting|sudo faramir deny
stop the broker|systemctl stop faramir-broker.socket
mask the units|systemctl mask faramir-exec.service
read the audit log|cat /var/log/faramir/audit.log
CASES

# --------------------------------------------------------------------------
head_ "A2. ordinary work is rewritten, not refused"
# The complement, and the more important half: a deny list that refuses real
# work gets turned off.  Each of these is a command an agent runs constantly,
# several of them deliberately near a rule's edge.
while IFS='|' read -r label cmd; do
  [ -z "$label" ] && continue
  got=$(verdict "$cmd")
  [ "$got" = rewrite ] && ok "allowed: $label" || bad "$label -> $got (wanted rewrite): $cmd"
done <<'CASES'
list files|ls -la
read a source file|cat internal/server/server.go
grep the tree|grep -rn TODO .
grep for a secret name|grep -rn ROUTER_PW .
run the tests|go test ./...
git status|git status
env as a prefix, not a dump|env FOO=bar ./run.sh
env piped into a filter|env | grep -c PATH
a file whose name ends in .env|cat faramir.env.example
keygen to a file, not to stdout|age-keygen -o /tmp/new.key
sed editing a source file|sed -i s/a/b/ README.md
restart a faramir unit|systemctl restart faramir-keeper.socket
check a faramir unit|systemctl status faramir-broker.service
the sanctioned CLI|faramir list-secrets
the sanctioned CLI under sudo|sudo faramir doctor
a brokered command|faramir run --env P=secret://db/password -- ./deploy.sh
answering an approval unprivileged|faramir approve abc123
CASES

# --------------------------------------------------------------------------
head_ "A3. a sanctioned call does not launder what follows it"
# faramir's own arguments are exempt from scanning, or `faramir run -- cat
# /etc/faramir/...` would refuse itself.  The exemption stops at the first
# separator; this is the test that it does.
for cmd in \
  'faramir list-secrets; cat /etc/faramir/age.key' \
  'faramir doctor && printenv' \
  'faramir status | cat; sops -d /etc/faramir/secrets/app.sops.yml' \
  'sudo faramir doctor; cat ~/.ssh/id_ed25519'
do
  got=$(verdict "$cmd")
  [ "$got" = deny ] && ok "chained after a sanctioned call is still seen: ${cmd:0:44}" \
    || bad "the exemption swallowed the chain -> $got: $cmd"
done
# And the exemption itself works: a ref on the command line is not a value.
got=$(verdict 'faramir run --env PW=secret://db/password -- env')
[ "$got" = rewrite ] && ok "a brokered command ending in 'env' is not read as an env dump" \
  || bad "the sanctioned exemption does not cover its arguments -> $got"

# --------------------------------------------------------------------------
head_ "A4. each host gets its answer in its own dialect"
# The wrong dialect fails open: a document the agent does not understand is a
# command it runs unredacted.  So the exact shape matters, per host.
check_shape() { # host jq-expr want label
  local host=$1 expr=$2 want=$3 label=$4 cmd=$5
  local got
  got=$(jq -cn --arg c "$cmd" --arg t "$6" '{tool_name:$t,tool_input:{command:$c}}' \
        | runuser -u op -- "$GUARD" guard --host "$host" 2>/dev/null | jq -r "$expr" 2>/dev/null)
  [ "$got" = "$want" ] && ok "$host $label" || bad "$host $label: got '$got', want '$want'"
}
check_shape claude   '.hookSpecificOutput.permissionDecision' deny  "deny"    'printenv' Bash
check_shape claude   '.hookSpecificOutput.permissionDecision' allow "rewrite" 'ls'       Bash
check_shape gemini   '.decision'                              deny  "deny"    'printenv' run_shell_command
check_shape gemini   '.hookSpecificOutput.tool_input.command|startswith("source ")' true "rewrite" 'ls' run_shell_command
check_shape opencode '.decision'                              deny    "deny"    'printenv' bash
check_shape opencode '.decision'                              rewrite "rewrite" 'ls'       bash
check_shape kilocode '.decision'                              deny    "deny"    'printenv' bash
check_shape kilocode '.decision'                              rewrite "rewrite" 'ls'       bash
# The deny reason has to reach the model with the alternative in it, or the
# agent retries the same command a different way.
reason=$(decide 'printenv' | jq -r '.hookSpecificOutput.permissionDecisionReason')
echo "$reason" | grep -q 'faramir_run' && ok "the refusal names faramir_run as the way to proceed" \
  || bad "the refusal does not tell the agent what to do instead"
echo "$reason" | grep -q 'matched deny pattern' && ok "and names the pattern that matched" \
  || bad "the refusal does not say which rule fired"
# A refusal must not quote the secret it is refusing to disclose.
echo "$reason" | grep -q 'hunter2\|tok_live' && bad "the refusal text contains a secret value" \
  || ok "the refusal quotes no value"

head_ "A5. an unknown dialect is an error, not a guess"
out=$(echo '{"tool_name":"Bash","tool_input":{"command":"printenv"}}' \
      | runuser -u op -- "$GUARD" guard --host codex 2>/tmp/g.err; echo "rc=$?")
grep -q 'rc=2' <<<"$out" && ok "an unknown --host exits 2" || bad "unknown --host: $out"
[ "$(echo "$out" | grep -vc 'rc=')" = "0" ] && ok "and answers nothing, so nothing is approved" \
  || bad "it emitted a decision anyway: $out"
grep -q 'known hosts are' /tmp/g.err && ok "and lists the dialects it does speak" \
  || bad "no help on stderr: $(cat /tmp/g.err)"
# --host=NAME as well as --host NAME.  The payload names gemini's own shell
# tool: a host is only asked about the tools it runs commands through.
got=$(jq -cn '{tool_name:"run_shell_command",tool_input:{command:"printenv"}}' \
      | runuser -u op -- "$GUARD" guard --host=gemini 2>/dev/null | jq -r '.decision')
[ "$got" = deny ] && ok "--host=NAME is read the same as --host NAME" || bad "--host=NAME: $got"
# And one host's tool name is not another's: Claude's Bash reaching a gemini
# registration is a misregistration, and answering it would be the wrong dialect.
got=$(jq -cn '{tool_name:"Bash",tool_input:{command:"printenv"}}' \
      | runuser -u op -- "$GUARD" guard --host=gemini 2>/dev/null; echo "rc=$?")
[ "$got" = "rc=0" ] && ok "a tool this host does not run commands through is left alone" \
  || bad "gemini answered a Bash payload: $got"

# --------------------------------------------------------------------------
head_ "A6. only the tools that run shell commands are touched"
route() { # tool command -> deny|rewrite|pass
  local out
  out=$(jq -cn --arg t "$1" --arg c "$2" '{tool_name:$t,tool_input:{command:$c}}' \
        | runuser -u op -- "$GUARD" guard 2>/dev/null)
  [ -z "$out" ] && { echo pass; return; }
  case "$(echo "$out" | jq -r '.hookSpecificOutput.permissionDecision')" in
    deny) echo deny;; allow) echo rewrite;; *) echo "?";;
  esac
}
[ "$(route Read 'printenv')" = pass ] && ok "a non-shell tool is left alone" || bad "Read was answered"
[ "$(route Edit 'cat /etc/faramir/age.key')" = pass ] && ok "Edit is left alone" || bad "Edit was answered"
# BashOutput reads a running command's buffer: there is nothing to rewrite, but
# a deny still applies, and the buffer it reads came through the wrapper.
[ "$(route BashOutput 'printenv')" = deny ] && ok "BashOutput is still refused a denied command" \
  || bad "BashOutput escapes the deny list"
[ "$(route BashOutput 'ls')" = pass ] && ok "and is not rewritten, having no command to run" \
  || bad "BashOutput was rewritten"

head_ "A7. a payload it cannot use is answered with silence"
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

head_ "A8. a rewrite hands back every field it was given"
out=$(echo '{"tool_name":"Bash","tool_input":{"command":"ls","description":"list","timeout":5000}}' \
      | runuser -u op -- "$GUARD" guard | jq -c '.hookSpecificOutput.updatedInput')
echo "$out" | jq -e '.description == "list" and .timeout == 5000' >/dev/null \
  && ok "description and timeout survive the rewrite" || bad "fields were dropped: $out"
echo "$out" | jq -re '.command' | grep -q "^source /usr/local/libexec/faramir/wrap.sh 'ls'$" \
  && ok "and the command is the wrapped form" || bad "rewrite shape: $(echo "$out" | jq -r .command)"

head_ "A9. what the rewrite must not do"
wrapped=$(decide 'ls' | jq -r '.hookSpecificOutput.updatedInput.command')
[ "$(verdict "$wrapped")" = pass ] && ok "an already-wrapped command is not wrapped again" \
  || bad "double wrapping: $(verdict "$wrapped")"
[ "$(verdict 'sleep 30 &')" = pass ] && ok "a backgrounded command is left alone (nothing to capture)" \
  || bad "a backgrounded command was wrapped"
[ "$(verdict 'a && b')" = rewrite ] && ok "a trailing && is not backgrounding" || bad "&& was read as &"
got=$(echo '{"tool_name":"Bash","tool_input":{"command":"tail -f log","run_in_background":true}}' \
      | runuser -u op -- "$GUARD" guard; echo "rc=$?")
[ "$got" = "rc=0" ] && ok "run_in_background is left alone" || bad "background flag ignored: $got"

head_ "A10. quoting into the sourced script survives exactly one round trip"
for cmd in "echo it's fine" 'echo $(date)' 'echo `id`' 'echo "a\\b"' "echo 'x'\\''y'"; do
  w=$(decide "$cmd" | jq -r '.hookSpecificOutput.updatedInput.command')
  # Recovered by one shell parse, which is what the sourced script's eval does.
  back=$(runuser -u op -- bash -c "set -- $(printf '%s' "${w#source /usr/local/libexec/faramir/wrap.sh }"); printf '%s' \"\$1\"" 2>/dev/null)
  [ "$back" = "$cmd" ] && ok "round trip: $cmd" || bad "round trip: got [$back] want [$cmd]"
done

# --------------------------------------------------------------------------
head_ "A11. the pattern list is the operator's, and a broken one fails closed"
PAT=/usr/local/libexec/faramir/deny-patterns.txt
cp $PAT /tmp/patterns.bak
# Missing entirely: the compiled-in fallback has to carry it.
mv $PAT /tmp/gone.txt
[ "$(verdict 'printenv')" = deny ] && ok "with no patterns file, the built-in fallback still refuses" \
  || bad "a missing patterns file disabled the deny list"
mv /tmp/gone.txt $PAT
# One unparseable line must not take the rest down with it.
printf 'this is a (broken regex\n\\bprintenv\\b\n' > /tmp/mixed.txt
got=$(jq -cn '{tool_name:"Bash",tool_input:{command:"printenv"}}' \
      | runuser -u op -- env FARAMIR_DENY_PATTERNS=/tmp/mixed.txt "$GUARD" guard \
      | jq -r '.hookSpecificOutput.permissionDecision')
[ "$got" = deny ] && ok "a typo on one line does not disable the lines around it" \
  || bad "one bad regex disabled the list -> $got"
# A comments-only file is not an empty list; it falls back rather than allowing
# everything.
printf '# nothing here\n\n' > /tmp/empty.txt
got=$(jq -cn '{tool_name:"Bash",tool_input:{command:"printenv"}}' \
      | runuser -u op -- env FARAMIR_DENY_PATTERNS=/tmp/empty.txt "$GUARD" guard \
      | jq -r '.hookSpecificOutput.permissionDecision')
[ "$got" = deny ] && ok "a comments-only file falls back rather than allowing everything" \
  || bad "an empty patterns file turned the guard off -> $got"

head_ "A12. a moved install is refused where it actually is"
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

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
