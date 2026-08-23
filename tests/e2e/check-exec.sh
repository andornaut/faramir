#!/bin/bash
# The executor boundary.
#
# Everything else in this project rests on one claim: a brokered command runs as
# a uid that holds no keys, in a cgroup of its own, with an environment the
# broker chose, and it ends when it is told to. A container with real cgroups
# is the only place that can be checked honestly, so this is where the kill path
# and the confinement get tested rather than reasoned about.
set -u
export SECRET='hunter2-correct-horse-battery'
TOKEN='«SECRET:db/password»'
. "$(dirname "$0")/lib.sh" || { echo "e2e: lib.sh is missing beside $0" >&2; exit 2; }

run() { runuser -u op -- /usr/local/bin/faramir run --quiet -t 30 "$@" 2>&1; }

# Every client sends the version of the binary it is, and a daemon refuses a
# request naming another one before it reads the op.
VERSION=$(faramir version | awk '{print $NF}')

EXECD=$(systemctl show faramir-exec.service -p MainPID --value)
CGBASE=$(systemctl show faramir-exec.service -p ControlGroup --value)
CGPATH="/sys/fs/cgroup${CGBASE}"

# strays counts processes owned by the executor's uid that are not the daemon
# itself. Named exactly, never by a pattern that could match the pgrep: a
# self-matching pattern is how this kind of check quietly always passes.
strays() {
  local out=""
  for pid in $(pgrep -u faramir-exec 2>/dev/null); do
    [ "$pid" = "$EXECD" ] && continue
    out="$out $pid:$(cat /proc/"$pid"/comm 2>/dev/null)"
  done
  printf '%s' "$out"
}
runCgroups() { find "$CGPATH" -maxdepth 1 -name 'run-*' -type d 2>/dev/null | wc -l; }

echo "executor daemon pid $EXECD, cgroup base $CGPATH"

# --------------------------------------------------------------------------
head_ "1. who the command is"
out=$(run -- /usr/bin/id -un)
[ "$out" = "faramir-exec" ] && ok "it runs as faramir-exec" || bad "id -un = [$out]"
out=$(run -- /usr/bin/id -u)
[ "$out" != "0" ] && ok "and not as root (uid $out)" || bad "the command ran as root"
[ "$out" != "$(id -u op)" ] && ok "and not as the caller" || bad "it ran as the caller's uid"

head_ "2. what that uid cannot reach"
refused() { # path label
  local out; out=$(run -- /bin/cat "$1")
  if grep -qiE "permission denied|no such file|cannot open|not found" <<<"$out"; then
    ok "cannot read $2"
  else
    bad "READ $2: $(head -c 90 <<<"$out")"
  fi
}
refused /etc/faramir/age.key "the age key"
refused /etc/faramir/secrets/app.sops.yml "the encrypted secrets"
refused /var/log/faramir/audit.log "the audit log"
refused /etc/faramir/id_ed25519 "the broker's ssh private key"
refused /home/op/.ssh/id_ed25519 "the operator's ssh key"
# The keeper socket is the age key by another name. python3, not nc: nc is not
# installed here, and "nc: not found" matches every "is it blocked" pattern
# there is, so that check was answering a question nobody asked.
out=$(run -- /usr/bin/python3 -c "
import socket
s = socket.socket(socket.AF_UNIX)
try:
    s.connect('/run/faramir/keeper.sock')
    s.sendall(b'{\"op\":\"get_values\"}\n')
    print('CONNECTED ' + repr(s.recv(200)[:80]))
except Exception as e:
    print('REFUSED %s' % e)")
grep -q "REFUSED" <<<"$out" && ok "cannot reach the keeper socket ($(grep -o 'Errno [0-9]*[^]]*' <<<"$out" | head -1))" \
  || bad "keeper socket reachable: $out"

# The broker socket it CAN reach: the executor is in the client group, because
# sharetree grants tree traversal to that group and the executor has to enter
# the tree. Recorded rather than asserted away -- what it means is in the
# README's blast-radius row, and this is the fact behind it.
out=$(run -- /usr/bin/python3 -c "
import socket
s = socket.socket(socket.AF_UNIX)
try:
    s.connect('/run/faramir/broker.sock'); print('CONNECTED')
except Exception as e:
    print('REFUSED %s' % e)")
grep -q "CONNECTED" <<<"$out" \
  && note "reaches the broker socket, being in the client group (see README, blast radius)" \
  || note "cannot reach the broker socket: $out"
# But the ops that decide an escalation stay root's, whoever asks.
out=$(run -- /usr/bin/python3 -c "
import socket, json
s = socket.socket(socket.AF_UNIX); s.connect('/run/faramir/broker.sock')
s.sendall(json.dumps({'op':'escalations','version':'$VERSION'}).encode()+b'\n')
print(s.recv(400).decode()[:120])")
grep -q "forbidden" <<<"$out" && ok "and is still refused the escalation ops, which are root's" \
  || bad "the executor was answered an escalation op: $out"

# --------------------------------------------------------------------------
head_ "2b. the check behind the socket mode"
# The modes above are the first answer, and they are the only one those probes
# can reach: a peer a mode turns away never gets far enough to be identified.
# Behind them each daemon reads SO_PEERCRED and refuses a caller that is not the
# account it serves, so a mode widened by a bad install, a umask or a drop-in is
# not the whole boundary. Reaching that check means getting past the mode, so
# this widens it, puts the question, and puts it back.
#
# Every one of these answers "forbidden": the daemon identified the caller and
# said no. Anything else is this check failing to ask rather than the boundary
# holding, and each way of failing to ask says so in its own words.
#
# peerprobe fills in the version every client sends, so what these measure is
# the peer check: a daemon refuses a request naming another version whoever
# sent it, and that refusal would read as a boundary that did not identify the
# caller.
peerprobe() { # account, socket, payload
  runuser -u "$1" -- /usr/bin/python3 -c "
import json, socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(10)
try:
    s.connect(sys.argv[1])
except Exception as e:
    print('UNREACHABLE %s' % e); raise SystemExit(0)
payload = json.loads(sys.argv[2])
payload.setdefault('version', sys.argv[3])
try:
    s.sendall(json.dumps(payload).encode() + b'\n')
except Exception:
    pass  # refused and closed before reading; the answer may be here already
try:
    reply = s.recv(400)
except Exception as e:
    print('NOANSWER %s' % e); raise SystemExit(0)
print(reply.decode('utf-8', 'replace') if reply else 'NOANSWER closed unread')" \
    "$2" "$3" "$VERSION" 2>&1
}

# refuses ACCOUNT SOCKET PAYLOAD LABEL. A daemon's answer is JSON, so anything
# that does not start with a brace is this suite failing to run the probe --
# no python3, no such account -- and is reported as that rather than as a
# boundary that gave way.
refuses() {
  local out; out=$(peerprobe "$1" "$2" "$3")
  case $out in
    *'"forbidden"'*) ok "$4" ;;
    UNREACHABLE*) bad "$4: the mode was not widened, so the peer check was never asked ($out)" ;;
    NOANSWER*)    bad "$4: the daemon answered nothing ($out)" ;;
    '{'*)         bad "$4: served a peer it does not admit: $out" ;;
    *)            bad "$4: the probe did not run ($out)" ;;
  esac
}

RUNDIR_MODE=$(stat -c '%a' /run/faramir)
MODE_KEEPER=$(stat -c '%a' /run/faramir/keeper.sock)
MODE_EXEC=$(stat -c '%a' /run/faramir/exec.sock)
MODE_BROKER=$(stat -c '%a' /run/faramir/broker.sock)

# On the way out as well as in line: this suite is the eleventh of seventeen
# against one install, so a socket left widened by a probe that hung or a
# harness that cut the run is a boundary the six suites after this one would
# measure and report as holding.
restore_socket_modes() {
  local rc=$?
  chmod "$MODE_KEEPER" /run/faramir/keeper.sock 2>/dev/null
  chmod "$MODE_EXEC" /run/faramir/exec.sock 2>/dev/null
  chmod "$MODE_BROKER" /run/faramir/broker.sock 2>/dev/null
  chmod "$RUNDIR_MODE" /run/faramir 2>/dev/null
  return "$rc"
}
trap restore_socket_modes EXIT

chmod o+x /run/faramir
chmod o+rw /run/faramir/keeper.sock /run/faramir/exec.sock /run/faramir/broker.sock

# The keeper and the executor each serve one account, the broker, and op is not
# it. op is the account the coding agent runs as, so this is the reach a
# compromised agent would have if the mode alone were the boundary.
refuses op /run/faramir/keeper.sock '{"op":"get_values"}' \
  "the keeper refuses op, whatever the socket mode says"
refuses op /run/faramir/exec.sock '{"op":"exec","cmd":["/bin/true"]}' \
  "the executor refuses op, whatever the socket mode says"
# The broker admits a group rather than one account, so the peer that tests it
# is one outside that group. nobody is in none.
refuses nobody /run/faramir/broker.sock '{"op":"status"}' \
  "the broker refuses an account outside the client group"

restore_socket_modes
trap - EXIT
# Every mode this widened, rather than the one that had to change: /run/faramir
# is 0755 already, so asserting on it alone would be an assertion that cannot
# fail, and the two sockets that did change would go unchecked.
got="$(stat -c '%a' /run/faramir) $(stat -c '%a' /run/faramir/keeper.sock)"
got="$got $(stat -c '%a' /run/faramir/exec.sock) $(stat -c '%a' /run/faramir/broker.sock)"
want="$RUNDIR_MODE $MODE_KEEPER $MODE_EXEC $MODE_BROKER"
[ "$got" = "$want" ] \
  && ok "every widened mode is back to what the install set ($got)" \
  || bad "modes left widened: $got, want $want"

head_ "3. the environment the broker chose"
env_out=$(run -- /usr/bin/printenv)
for want in PATH TERM LANG LC_ALL DEBIAN_FRONTEND; do
  grep -q "^$want=" <<<"$env_out" && ok "env carries $want" || bad "$want is missing"
done
# The caller's environment must not come with it.
out=$(runuser -u op -- env LEAKED_FROM_CALLER=yes /usr/local/bin/faramir run --quiet -t 20 -- /usr/bin/printenv 2>&1)
grep -q "LEAKED_FROM_CALLER" <<<"$out" && bad "the caller's environment reached the child" \
  || ok "a variable set by the caller does not reach the child"
# Nor anything of the daemon's own. FARAMIR_OPERATOR is set on purpose and is
# checked on its own below, so it is taken out here rather than widening the
# pattern: anything else wearing the prefix is still a leak.
deliberate=$(grep -v '^FARAMIR_OPERATOR=' <<<"$env_out")
grep -qE "^(FARAMIR_|LISTEN_|NOTIFY_|INVOCATION_ID|JOURNAL_)" <<<"$deliberate" \
  && bad "daemon environment leaked: $(grep -E '^(FARAMIR_|LISTEN_|NOTIFY_|INVOCATION_ID|JOURNAL_)' <<<"$deliberate" | head -2)" \
  || ok "and none of the daemon's own activation environment does either"
# The one it does set: who the host belongs to. Every brokered command runs as the
# executor, so without this nothing inside a run can name the operator.
grep -q '^FARAMIR_OPERATOR=op$' <<<"$env_out" \
  && ok "and the child is told which account is the operator" \
  || bad "FARAMIR_OPERATOR does not name the operator: $(grep '^FARAMIR_OPERATOR=' <<<"$env_out")"
# Nor the key that decrypts everything. Named apart from the daemon prefixes
# above because this is the one variable whose arrival would undo the whole
# arrangement: a child holding it needs no broker, and sops reads both spellings.
grep -qE "^(SOPS_AGE_KEY|SOPS_AGE_KEY_FILE)=|AGE-SECRET-KEY-" <<<"$env_out" \
  && bad "*** the age key reached the child's environment ***" \
  || ok "and no age key, in either spelling sops reads"

# An injected ref is there, and comes back as its token.
out=$(run --env PW=faramir://db/password -- /usr/bin/printenv PW)
[ "$out" = "$TOKEN" ] && ok "an injected ref is in the child's environment, redacted on the way out" \
  || bad "injected value = [$out]"
# The same by file, which is how a playbook names a fleet's credentials once
# rather than on every command line. Only here: the parsing and the precedence
# are unit tests, and what neither reaches is the ref in a file arriving in a
# child's environment.
runuser -u op -- tee /tmp/refs.env >/dev/null <<'ENV'
# the fleet's credentials
PW=faramir://db/password
ENV
out=$(runuser -u op -- /usr/local/bin/faramir run --quiet -t 20 \
  --env-file /tmp/refs.env -- /usr/bin/printenv PW 2>&1)
[ "$out" = "$TOKEN" ] && ok "a ref named in an --env-file reaches the child too" \
  || bad "the file's ref did not arrive: [$out]"
# A literal value in one is refused rather than passed through, the file being
# a list of names like every other way of asking.
runuser -u op -- tee /tmp/literal.env >/dev/null <<'ENV'
PW=hunter2-correct-horse-battery
ENV
out=$(runuser -u op -- /usr/local/bin/faramir run --quiet -t 20 \
  --env-file /tmp/literal.env -- /usr/bin/printenv PW 2>&1); code=$?
[ $code -eq 2 ] && ok "and a literal value in one is refused, exit 2" \
  || bad "a literal value in an --env-file: exit $code"
grep -q "$SECRET" <<<"$out" && bad "*** the refusal echoed the value ***" \
  || ok "and the refusal does not echo it back"
# The short form names the variable and the ref with one word, so it cannot
# serve a ref whose name is not also a name a variable may have -- which is
# every one with a "/" in it, and so most of them. `refs` prints
# faramir://db/password, and db/password is the obvious thing to type.
out=$(runuser -u op -- /usr/local/bin/faramir run --quiet -t 20 \
  --env db/password -- /bin/true 2>&1); code=$?
[ $code -eq 2 ] && ok "a bare ref that no variable could be named after is refused" \
  || bad "--env db/password exited $code: ${out:0:90}"
grep -q -- "--env NAME=faramir://db/password" <<<"$out" \
  && ok "  and the refusal carries the form that does serve it" \
  || bad "  the refusal offers no way to ask for it: ${out:0:120}"
rm -f /tmp/refs.env /tmp/literal.env

# And only the ones asked for. printenv on an unset name prints nothing and
# exits 1, so empty is the answer that says it was not injected.
out=$(run -- /usr/bin/printenv PW)
if [ -n "$out" ]; then
  bad "a ref nobody asked for was injected: [$out]"
else
  ok "and a ref that was not asked for is absent"
fi

head_ "4. the terminal it runs on"
out=$(run -- /bin/sh -c 'test -t 1 && echo TTY || echo PIPE')
[ "$out" = "TTY" ] && ok "stdout is a terminal, so programs format as they would for a person" \
  || bad "stdout is not a tty: $out"
# Constants now rather than keys: internal/config TermCols and TermRows.
cols=120
rows=40
# From stdout, not stdin: stty reads the terminal on its standard input by
# default, and stdin here is /dev/null by design. The PTY is on stdout.
out=$(run -- /bin/sh -c 'stty size <&1 2>/dev/null')
[ "$out" = "$rows $cols" ] && ok "sized from the config ($out)" || bad "stty size = [$out], want [$rows $cols]"

head_ "5. stdin"
# A command that reads stdin must not hang until the timeout holding a slot.
start=$(date +%s)
out=$(run -- /bin/cat)
elapsed=$(( $(date +%s) - start ))
[ "$elapsed" -lt 10 ] && ok "a command reading stdin gets EOF at once (${elapsed}s), not a timeout" \
  || bad "reading stdin took ${elapsed}s"
[ -z "$out" ] && ok "and reads nothing" || bad "cat returned [$out]"

head_ "6. where it runs"
out=$(cd /home/op/project && runuser -u op -- /usr/local/bin/faramir run --quiet -t 20 -- /bin/pwd 2>&1)
[ "$out" = "/home/op/project" ] && ok "a command runs where its caller was" || bad "pwd = [$out]"
out=$(run --cwd /root -- /bin/pwd)
grep -qiE "denied|no such|cannot|refus" <<<"$out" && ok "a directory it cannot enter is refused" \
  || bad "running in /root gave [$out]"
out=$(run --cwd relative/path -- /bin/pwd)
grep -qiE "absolute|invalid|refus" <<<"$out" && ok "a relative cwd is refused" || bad "relative cwd gave [$out]"

head_ "6b. a cmd[0] that is not a program"
# Three different things, and the caller has to be able to tell them apart: a
# path with nothing at it, a path holding something that is not a program, and
# a program this account may not run. All three came back as one sentence or as
# the raw fork/exec error, which reads as the caller's own permissions.
out=$(run -- /no/such/thing)
grep -q "no such program" <<<"$out" && ok "a path with nothing at it is named as missing" \
  || bad "a missing program gave [${out:0:110}]"
out=$(run -- /etc)
grep -q "not a program" <<<"$out" && grep -q "directory" <<<"$out" \
  && ok "a directory is named as what it is, not as missing" \
  || bad "a directory gave [${out:0:110}]"
out=$(run -- /etc/hostname)
grep -q "may not execute" <<<"$out" && grep -q "faramir-exec" <<<"$out" \
  && ok "a file this account may not execute names the account it runs as" \
  || bad "a non-executable file gave [${out:0:110}]"

# --------------------------------------------------------------------------
head_ "7. the kill path, which is the whole of the cgroup argument"
before_strays=$(strays); before_cgroups=$(runCgroups)
echo "  (before: cgroups=$before_cgroups strays=[${before_strays:-none}])"

# A command that times out, having forked a child that left the process group
# and a parent that ignores SIGTERM. Signalling the process group would miss
# the setsid one; this is what cgroup.kill is for.
# Backgrounded, and inspected on a clock of its own. Waiting for the call to
# return would mean checking for strays after the sleeps had ended by
# themselves, which is a check that passes whether or not anything killed them:
# the whole question is whether they are gone EARLY.
start=$(date +%s)
runuser -u op -- /usr/local/bin/faramir run --quiet -t 3 -- \
  /bin/bash -c 'trap "" TERM; setsid /bin/sleep 300 </dev/null >/dev/null 2>&1 & /bin/sleep 300' \
  > /tmp/kill.out 2>&1 &
caller=$!
# 3s timeout plus kill_grace_sec, and a margin: everything must be gone by then,
# and 300s short of the sleeps ending on their own.
sleep 15
after=$(strays)
if [ -z "$after" ]; then
  ok "15s in, nothing of the executor's is left, with 285s still on the sleeps"
else
  bad "processes were still running 15s in:$after"
fi
[ "$(runCgroups)" = "$before_cgroups" ] && ok "and the run's cgroup is already gone" \
  || bad "the cgroup is still there 15s in: $(runCgroups)"

wait $caller 2>/dev/null
elapsed=$(( $(date +%s) - start ))
out=$(cat /tmp/kill.out)
[ "$elapsed" -lt 25 ] && ok "and the caller was released after ${elapsed}s" \
  || bad "the caller waited ${elapsed}s"
grep -qiE "timed out|timeout" <<<"$out" && ok "and told it timed out" || bad "no timeout in [$out]"

sleep 2
after=$(strays)
if [ -z "$after" ]; then
  ok "the SIGTERM-ignoring parent and the setsid child both went"
else
  bad "processes survived the kill:$after"
fi
[ "$(pgrep -u faramir-exec -x sleep 2>/dev/null | wc -l)" = "0" ] \
  && ok "specifically, no stray sleep is left" || bad "$(pgrep -u faramir-exec -x sleep | wc -l) sleep(s) left"
after_cgroups=$(runCgroups)
[ "$after_cgroups" = "$before_cgroups" ] && ok "and the run's cgroup was removed ($after_cgroups left)" \
  || bad "cgroups went $before_cgroups -> $after_cgroups"

# The same for a command that ends normally: nothing accumulates.
for i in 1 2 3; do run -- /bin/true >/dev/null; done
[ "$(runCgroups)" = "$before_cgroups" ] && ok "three ordinary runs leave no cgroup behind" \
  || bad "cgroups accumulated: $(runCgroups)"
[ -z "$(strays)" ] && ok "and no processes" || bad "strays after ordinary runs: $(strays)"

# A killed command is still a command that happened.
sleep 1
grep -q '"timed_out":true' /var/log/faramir/audit.log 2>/dev/null \
  && ok "and the timed-out run is in the audit log" \
  || bad "no timed_out record: $(tail -1 /var/log/faramir/audit.log | head -c 120)"

head_ "8. output limits"
cap=262144
out=$(run -- /bin/sh -c "yes abcdefgh | head -c $(( cap * 2 ))")
[ "${#out}" -lt "$(( cap * 2 ))" ] && ok "output past max_output_bytes ($cap) is cut at ${#out} chars" \
  || bad "no truncation: got ${#out} for a cap of $cap"
grep -q "bytes of output dropped" <<<"$out" && ok "and the caller is told what was dropped" \
  || bad "truncation was silent: $(tail -c 200 <<<"$out")"
# What the cut keeps is the head and the tail. The end is the half a failing
# command is read for: keeping the head alone returned the first half of the
# noise and none of the reason, with the exit code the only sign of it.
ends=$(run -- /bin/sh -c "yes abcdefgh | head -c $(( cap * 2 )); echo THE-LAST-LINE")
grep -q "THE-LAST-LINE" <<<"$ends" \
  && ok "and the end of a long run survives the cut" \
  || bad "the end of the output was dropped: $(tail -c 200 <<<"$ends")"
[ "${ends:0:8}" = "abcdefgh" ] \
  && ok "as does the start of it" \
  || bad "the start of the output was dropped: $(head -c 80 <<<"$ends")"

# Output that is not text is altered rather than cut, and the caller is told the
# same way. On stderr, unlike the truncation marker: stdout is intact in this
# case except for the bytes themselves, so a line in it would corrupt what a
# caller is piping. Stdout is dropped below so that only the summary is read.
notice() { { runuser -u op -- /usr/local/bin/faramir run -t 30 "$@" >/dev/null; } 2>&1; }
out=$(notice -- /bin/sh -c 'head -c 4096 /dev/urandom')
grep -qE '[0-9]+ non-text byte\(s\) replaced' <<<"$out" \
  && ok "binary output is reported as non-text, with a count" \
  || bad "binary output was not reported: [$out]"
out=$(notice -- /bin/echo hello)
grep -q 'non-text' <<<"$out" && bad "ordinary text was counted as non-text: [$out]" \
  || ok "and ordinary text is not"
# The ordinary case, and the one that must stay quiet: colour is stripped rather
# than replaced, so a notice on it would fire on most commands an agent runs.
out=$(notice -- /bin/sh -c 'printf "\033[31mRED\033[0m\n"')
grep -q 'non-text' <<<"$out" && bad "stripped colour was counted as non-text: [$out]" \
  || ok "nor is colour, which is stripped rather than replaced"
out=$({ runuser -u op -- /usr/local/bin/faramir run --quiet -t 30 -- \
  /bin/sh -c 'head -c 4096 /dev/urandom' >/dev/null; } 2>&1)
[ -z "$out" ] && ok "and --quiet suppresses it with the rest of the summary" \
  || bad "--quiet still printed: [$out]"
runuser -u op -- /usr/local/bin/faramir run -t 30 -- /bin/echo hello >/tmp/notice.out 2>/dev/null
[ "$(cat /tmp/notice.out)" = hello ] && ok "while stdout carries the output and nothing else" \
  || bad "stdout carried more than the output: [$(cat /tmp/notice.out)]"

head_ "9. finding the program"
out=$(run -- /bin/echo absolute)
[ "$out" = "absolute" ] && ok "an absolute path runs" || bad "[$out]"
out=$(run -- echo "on the path")
[ "$out" = "on the path" ] && ok "a bare name resolves on the broker's PATH" || bad "[$out]"
out=$(run -- definitely-not-a-real-program)
grep -qiE "not found|no such" <<<"$out" && ok "an unknown program is a clear error" || bad "[$out]"
grep -qi "PATH" <<<"$out" && ok "which names the PATH it looked on" || bad "the error does not say where it looked"
# No shell is spawned: a pipeline as one argument is not interpreted.
out=$(run -- /bin/echo 'a | b > c')
[ "$out" = "a | b > c" ] && ok "no shell is spawned, so metacharacters are literal" || bad "[$out]"

head_ "10. exit status"
for want in 0 1 7 42; do
  runuser -u op -- /usr/local/bin/faramir run --quiet -t 20 -- /bin/sh -c "exit $want" >/dev/null 2>&1
  got=$?
  [ "$got" = "$want" ] && ok "exit $want is passed through" || bad "exit: got $got want $want"
done
# A command killed by a signal reports it as a shell would.
runuser -u op -- /usr/local/bin/faramir run --quiet -t 20 -- /bin/sh -c 'kill -9 $$' >/dev/null 2>&1
got=$?
[ "$got" = "137" ] && ok "a SIGKILLed command reports 137, as a shell does" || bad "signal exit = $got"

head_ "10b. a timeout larger than anything can wait for"
# The wait the caller holds the socket open for is built from the timeout it
# named. Multiplied unsaturated it wraps negative somewhere past 292 years, and
# the deadline is then already past: the request fails on the write and reports
# a broker that did not answer, having never sent one. Any value the broker
# takes is clamped to max_timeout_sec, so these all run.
for t in 3600 9223372036 92233720368; do
  out=$(runuser -u op -- /usr/local/bin/faramir run --quiet -t "$t" -- /bin/true 2>&1)
  rc=$?
  [ "$rc" = 0 ] && ok "  -t $t runs, clamped to what the broker allows" \
    || bad "  -t $t exited $rc: ${out:0:100}"
done
# And one no whole number of seconds can hold is refused as that, rather than as
# not being a positive integer, which it is.
out=$(runuser -u op -- /usr/local/bin/faramir run --quiet -t 9223372036854775807 -- /bin/true 2>&1)
grep -q "too large" <<<"$out" && ok "  and one too large to hold is named as that" \
  || bad "  -t 9223372036854775807 gave: ${out:0:110}"

head_ "11. more commands at once than the broker will take"
limit=$(grep -oP 'concurrency = \K[0-9]+' /etc/faramir/config.toml)
rm -f /tmp/conc.*; for i in $(seq $(( limit + 3 ))); do
  ( runuser -u op -- /usr/local/bin/faramir run --quiet -t 20 -- /bin/sleep 6 >/tmp/conc."$i" 2>&1 ) &
done
wait
busy=$(grep -lci "concurrency limit" /tmp/conc.* 2>/dev/null | wc -l)
[ "$busy" -ge 1 ] && ok "past the limit of $limit, $busy call(s) were refused rather than queued" \
  || bad "nothing was refused with $(( limit + 3 )) concurrent calls"
grep -hi "concurrency limit" /tmp/conc.* 2>/dev/null | head -1 | grep -qi "retry" \
  && ok "and the refusal says it is worth retrying" || bad "the refusal does not say what to do"
[ -z "$(strays)" ] && ok "and nothing was left running afterwards" || bad "strays: $(strays)"

head_ "12. what the operator can see and the agent cannot"
runuser -u op -- /bin/cat /var/log/faramir/audit.log >/dev/null 2>&1 \
  && bad "the caller's account can read the audit log" || ok "the agent's uid cannot read the audit log"
[ -r /var/log/faramir/audit.log ] && ok "and root can" || bad "root cannot read the audit log"
last=$(tail -1 /var/log/faramir/audit.log)
grep -qF "$SECRET" <<<"$last" && bad "THE AUDIT LOG HOLDS A VALUE" || ok "and it holds no value"
python3 -c "
import json,sys
r=json.loads(sys.stdin.read())
missing=[k for k in ('log_id','op','peer') if k not in r]
print('MISSING:'+','.join(missing) if missing else 'COMPLETE')" <<<"$last" | grep -q COMPLETE \
  && ok "every record names the op and the peer that asked" || bad "record is missing fields: $last"

summary
