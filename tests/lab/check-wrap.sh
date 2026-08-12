#!/bin/bash
# Suite B: the rewrite, executed.
#
# Suite A stopped at the decision.  This one takes the exact string the guard
# hands back and runs it in a shell standing where the agent's shell stands,
# because everything the wrapper claims is about what happens when it runs: the
# output is redacted, the exit status is the command's, the shell keeps what the
# command set, and every failure withholds output rather than printing it.
#
# Run as root; each case drops to the agent's own uid.
set -u
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; }
head_() { printf '\n== %s\n' "$1"; }

SECRET='hunter2-correct-horse-battery'
TOKEN='«SECRET:db/password»'
UID_OP=$(id -u op)
RUNDIR=/run/user/$UID_OP

# asAgent runs a bash script as the agent would run it: its own uid, its own
# private runtime directory, in the enrolled tree.
asAgent() {
  runuser -u op -- env HOME=/home/op XDG_RUNTIME_DIR="$RUNDIR" \
    bash -c "cd /home/op/project; $1" 2>&1
}
# rewriteOf asks the real guard what this command becomes.
rewriteOf() {
  jq -cn --arg c "$1" '{tool_name:"Bash",tool_input:{command:$c}}' \
    | runuser -u op -- /usr/local/bin/faramir guard \
    | jq -r '.hookSpecificOutput.updatedInput.command'
}
# agentRun is one tool call, end to end: guard, then eval what it returned.
agentRun() {
  local w; w=$(rewriteOf "$1")
  asAgent "$(printf '%s' "$w")"
}

# A file in the tree holding a secret in the clear: an operator's mistake, and
# the case the wrapper exists for.  The guard has no rule against reading it,
# which is the point -- a deny list only covers what someone thought to name.
printf 'DB_PASSWORD=%s\nnote: the api token is %s\n' \
  "$SECRET" 'tok_live_0PENSESAME_9911' > /home/op/project/notes.txt
chown op:dev /home/op/project/notes.txt

# --------------------------------------------------------------------------
head_ "B1. the case the deny list does not cover"
[ "$(jq -cn '{tool_name:"Bash",tool_input:{command:"cat notes.txt"}}' \
     | runuser -u op -- /usr/local/bin/faramir guard \
     | jq -r '.hookSpecificOutput.permissionDecision')" = allow ] \
  && ok "reading a file the deny list does not name is allowed" \
  || bad "notes.txt was denied; this suite needs it allowed"
out=$(agentRun 'cat notes.txt')
grep -q "$SECRET" <<<"$out" && bad "THE SECRET REACHED THE TRANSCRIPT: $out" \
  || ok "the value does not appear in the output"
grep -q "$TOKEN" <<<"$out" && ok "it came back as its ref token instead" \
  || bad "no token in the output: $out"
grep -q '«SECRET:api/token»' <<<"$out" && ok "the second value in the same file too" \
  || bad "the api token was not redacted: $out"

head_ "B2. both streams, and the exit status the command returned"
out=$(agentRun "printf '%s\n' '$SECRET' >&2")
grep -q "$TOKEN" <<<"$out" && ok "a secret written to stderr is redacted too" \
  || bad "stderr escaped the redactor: $out"
# Merged into stdout, which docs/redaction.md names as the cost of capturing both.
out=$(runuser -u op -- env HOME=/home/op XDG_RUNTIME_DIR="$RUNDIR" bash -c \
  "cd /home/op/project; $(rewriteOf 'echo to-err >&2') 2>/dev/null")
[ "$out" = "to-err" ] && ok "and arrives on stdout: both streams come back as one" \
  || bad "stderr routing: [$out]"
for want in 0 1 7 42; do
  asAgent "$(rewriteOf "exit-with() { return $want; }; exit-with")" >/dev/null 2>&1
  got=$?
  [ "$got" = "$want" ] && ok "exit status $want is preserved" || bad "status: got $got want $want"
done
asAgent "$(rewriteOf 'ls /nonexistent-path')" >/dev/null 2>&1
code=$?
if [ "$code" -ne 0 ]; then
  ok "a failing command still fails"
else
  bad "a failure was reported as success"
fi

head_ "B3. the shell keeps what the command set"
# The whole reason the rewrite sources a script instead of piping into one: a
# child process would lose every cd, export and function the agent set up.
out=$(asAgent "$(rewriteOf 'cd /tmp'); pwd")
[ "$out" = "/tmp" ] && ok "cd persists past the wrapper" || bad "cd was lost: [$out]"
out=$(asAgent "$(rewriteOf 'export MARKER=kept'); echo \$MARKER")
[ "$out" = "kept" ] && ok "export persists" || bad "export was lost: [$out]"
out=$(asAgent "$(rewriteOf 'greet() { echo hello; }'); greet")
[ "$out" = "hello" ] && ok "a function defined by the command survives" || bad "function lost: [$out]"
out=$(asAgent "$(rewriteOf 'PLAIN=also-kept'); echo \$PLAIN")
[ "$out" = "also-kept" ] && ok "an unexported assignment survives" || bad "assignment lost: [$out]"
# And it leaves nothing of its own behind in the caller's namespace.
out=$(asAgent "$(rewriteOf 'true'); echo \"[\${__frf:-unset}][\${__fro:-unset}][\${__frc:-unset}]\"")
[ "$out" = "[unset][unset][unset]" ] && ok "and its own variables are unset afterwards" \
  || bad "the wrapper left variables in the shell: $out"

head_ "B4. nothing unredacted is left on disk"
before=$(find "$RUNDIR" -name 'faramir.*' 2>/dev/null | wc -l)
asAgent "$(rewriteOf 'cat notes.txt')" >/dev/null 2>&1
after=$(find "$RUNDIR" -name 'faramir.*' 2>/dev/null | wc -l)
[ "$before" = "$after" ] && ok "the capture files are removed after a normal run ($after left)" \
  || bad "capture files accumulated: $before -> $after"
# "exit" inside the command ends the shell before the rm; the EXIT trap is what
# still runs.
asAgent "$(rewriteOf "cat notes.txt; exit 3")" >/dev/null 2>&1
[ "$?" = 3 ] && ok "a command that exits the shell still returns its status" || bad "exit status through the trap"
leftover=$(find "$RUNDIR" -name 'faramir.*' 2>/dev/null | wc -l)
[ "$leftover" = "$after" ] && ok "and its capture files are removed by the EXIT trap" \
  || bad "an exiting command left $leftover capture files behind"
# Whatever the caller had on EXIT has to be there afterwards.
out=$(asAgent "trap 'echo MINE-RAN' EXIT; $(rewriteOf 'true'); trap -p EXIT")
grep -q "MINE-RAN" <<<"$out" && ok "the caller's own EXIT trap still runs" || bad "the caller's trap was eaten: $out"
grep -q "echo MINE-RAN" <<<"$out" && ok "and is still installed after the wrapper" || bad "trap not restored: $out"

head_ "B5. one eval, not two"
# The guard shell-quotes for exactly one round trip through the sourced script.
# A second expansion would run whatever the model put in a string.
rm -f /tmp/second-eval
out=$(agentRun "echo 'literal \$(touch /tmp/second-eval) end'")
[ -e /tmp/second-eval ] && bad "COMMAND INJECTION: the quoted text was evaluated twice" \
  || ok "a command substitution inside a quoted string is not run"
grep -q 'literal $(touch /tmp/second-eval) end' <<<"$out" && ok "and comes back literally" \
  || bad "literal text was mangled: $out"
out=$(agentRun 'echo "it'"'"'s fine"')
[ "$out" = "it's fine" ] && ok "a single quote in the command survives the round trip" || bad "quoting: [$out]"
# A command that is not valid shell has to fail the way it would have failed
# unwrapped, rather than becoming a different error or, worse, running.
wrapped=$(agentRun "echo it's fine" 2>&1)
bare=$(asAgent "echo it's fine" 2>&1)
grep -q 'unexpected EOF' <<<"$wrapped" && grep -q 'unexpected EOF' <<<"$bare" \
  && ok "an unterminated quote fails as a parse error, wrapped and unwrapped alike" \
  || bad "wrapped [$wrapped] vs bare [$bare]"
out=$(agentRun 'printf "%s\n" "a\\b" "c|d" "e;f" "g\$h"')
[ "$out" = 'a\b
c|d
e;f
g$h' ] && ok "backslashes, pipes, semicolons and dollars survive" || bad "metacharacters: [$out]"

# --------------------------------------------------------------------------
head_ "B6. every failure withholds output rather than printing it"
# Without a private directory to capture into, the command must not run at all:
# it would print whatever it found straight through.
rm -f /tmp/it-ran
out=$(runuser -u op -- env -u XDG_RUNTIME_DIR HOME=/home/op bash -c \
  "cd /home/op/project; $(rewriteOf 'touch /tmp/it-ran; cat notes.txt')" 2>&1; echo "rc=$?")
[ -e /tmp/it-ran ] && bad "the command RAN with nowhere private to capture its output" \
  || ok "with no XDG_RUNTIME_DIR the command is not run at all"
grep -q "$SECRET" <<<"$out" && bad "and it printed the secret" || ok "and nothing was printed"
grep -q 'rc=1' <<<"$out" && ok "and it returns non-zero" || bad "status on refusal: $out"
grep -q 'no private directory' <<<"$out" && ok "and says why, on stderr" || bad "no explanation: $out"

# A directory another account can enter is not private, whoever owns it.
chmod 0750 "$RUNDIR"
rm -f /tmp/it-ran
out=$(asAgent "$(rewriteOf 'touch /tmp/it-ran; cat notes.txt')"; echo "rc=$?")
[ -e /tmp/it-ran ] && bad "a group-readable runtime directory was accepted" \
  || ok "a group-readable XDG_RUNTIME_DIR is refused"
grep -q "$SECRET" <<<"$out" && bad "and the secret was printed" || ok "and nothing was printed"
chmod 0700 "$RUNDIR"

# Somebody else's directory, even at 0700.
mkdir -p /run/user/9999 && chown root:root /run/user/9999 && chmod 0700 /run/user/9999
rm -f /tmp/it-ran
out=$(runuser -u op -- env HOME=/home/op XDG_RUNTIME_DIR=/run/user/9999 bash -c \
  "cd /home/op/project; $(rewriteOf 'touch /tmp/it-ran; cat notes.txt')" 2>&1)
[ -e /tmp/it-ran ] && bad "a directory owned by another account was accepted" \
  || ok "an XDG_RUNTIME_DIR owned by somebody else is refused"

head_ "B7. a redactor that cannot answer withholds the output"
# The most important failure: the command has already run and its output is
# sitting in a file.  If the redactor cannot be reached, that output must not
# be printed.
rm -f /tmp/it-ran
out=$(runuser -u op -- env HOME=/home/op XDG_RUNTIME_DIR="$RUNDIR" FARAMIR_CLI=/nonexistent/faramir \
  bash -c "cd /home/op/project; $(rewriteOf 'touch /tmp/it-ran; cat notes.txt')" 2>&1; echo "rc=$?")
[ -e /tmp/it-ran ] && ok "the command itself ran" || bad "the command did not run"
grep -q "$SECRET" <<<"$out" && bad "OUTPUT LEAKED: no redactor, and it printed anyway" \
  || ok "with no redactor, the output it had already captured is withheld"
grep -q 'withheld' <<<"$out" && ok "and says so" || bad "no explanation: $out"
grep -q 'rc=1' <<<"$out" && ok "and does not read as a clean success" || bad "status: $out"
# A command that succeeded, whose output could not be redacted, must not
# report success either.
out=$(runuser -u op -- env HOME=/home/op XDG_RUNTIME_DIR="$RUNDIR" FARAMIR_CLI=/bin/false \
  bash -c "cd /home/op/project; $(rewriteOf 'true')" 2>/dev/null; echo "rc=$?")
grep -q 'rc=1' <<<"$out" && ok "a successful command with withheld output returns non-zero" \
  || bad "a withheld output read as success: $out"

head_ "B8. the same, with the broker actually stopped"
systemctl stop faramir-broker.socket faramir-broker.service >/dev/null 2>&1
sleep 1
rm -f /tmp/it-ran
out=$(asAgent "$(rewriteOf 'touch /tmp/it-ran; cat notes.txt')"; echo "rc=$?")
[ -e /tmp/it-ran ] && ok "with the broker down the command still runs" || bad "the command did not run"
grep -q "$SECRET" <<<"$out" && bad "SECRET LEAKED WITH THE BROKER DOWN" \
  || ok "and its output is withheld rather than printed"
grep -q 'rc=1' <<<"$out" && ok "and returns non-zero" || bad "status with the broker down: $out"
systemctl start faramir-broker.socket >/dev/null 2>&1
sleep 2
out=$(agentRun 'cat notes.txt')
grep -q "$TOKEN" <<<"$out" && ok "and it recovers once the broker is back" || bad "did not recover: $out"

head_ "B9. output the wrapper has to carry unchanged"
out=$(agentRun 'printf "no trailing newline"')
[ "$out" = "no trailing newline" ] && ok "output with no trailing newline" || bad "trailing newline: [$out]"
out=$(agentRun 'printf "a\n\n\nb\n"')
[ "$(printf '%s' "$out" | wc -l)" = "3" ] && ok "blank lines are kept" || bad "blank lines: [$out]"
out=$(agentRun 'true')
[ -z "$out" ] && ok "a command that prints nothing prints nothing" || bad "empty output: [$out]"
n=$(agentRun 'seq 1 200000' | wc -l)
[ "$n" = "200000" ] && ok "200k lines arrive complete" || bad "large output: $n lines"
out=$(agentRun 'printf "caf\xc3\xa9 \xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e \xf0\x9f\x94\x91\n"')
[ "$out" = "café 日本語 🔑" ] && ok "multi-byte characters survive" || bad "utf-8: [$out]"
# Binary is what `cat` on the wrong file produces; it must not hang or truncate.
out=$(agentRun 'head -c 4096 /dev/urandom | wc -c')
[ "$out" = "4096" ] && ok "binary output does not truncate the stream" || bad "binary: [$out]"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
