#!/bin/bash
# The executor boundary.
#
# Everything else in this project rests on one claim: a brokered command runs as
# a uid that holds no keys, in a cgroup of its own, with an environment the
# broker chose, and it ends when it is told to.  A container with real cgroups
# is the only place that can be checked honestly, so this is where the kill path
# and the confinement get tested rather than reasoned about.
set -u
export SECRET='hunter2-correct-horse-battery'
TOKEN='«SECRET:db/password»'
. "$(dirname "$0")/lib.sh" || { echo "lab: lib.sh is missing beside $0" >&2; exit 2; }

run() { runuser -u op -- /usr/local/bin/faramir run --quiet -t 30 "$@" 2>&1; }

EXECD=$(systemctl show faramir-exec.service -p MainPID --value)
CGBASE=$(systemctl show faramir-exec.service -p ControlGroup --value)
CGPATH="/sys/fs/cgroup${CGBASE}"

# strays counts processes owned by the executor's uid that are not the daemon
# itself.  Named exactly, never by a pattern that could match the pgrep: a
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
# The keeper socket is the age key by another name.  python3, not nc: nc is not
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
# the tree.  Recorded rather than asserted away -- what it means is in the
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
# But the ops that decide an approval stay root's, whoever asks.
out=$(run -- /usr/bin/python3 -c "
import socket, json
s = socket.socket(socket.AF_UNIX); s.connect('/run/faramir/broker.sock')
s.sendall(json.dumps({'op':'approvals'}).encode()+b'\n')
print(s.recv(400).decode()[:120])")
grep -q "forbidden" <<<"$out" && ok "and is still refused the approval ops, which are root's" \
  || bad "the executor was answered an approval op: $out"

head_ "3. the environment the broker chose"
env_out=$(run -- /usr/bin/printenv)
for want in PATH TERM LANG LC_ALL DEBIAN_FRONTEND; do
  grep -q "^$want=" <<<"$env_out" && ok "base_env carries $want" || bad "$want is missing"
done
# The caller's environment must not come with it.
out=$(runuser -u op -- env LEAKED_FROM_CALLER=yes /usr/local/bin/faramir run --quiet -t 20 -- /usr/bin/printenv 2>&1)
grep -q "LEAKED_FROM_CALLER" <<<"$out" && bad "the caller's environment reached the child" \
  || ok "a variable set by the caller does not reach the child"
# Nor anything of the daemon's own.
grep -qE "^(FARAMIR_|LISTEN_|NOTIFY_|INVOCATION_ID|JOURNAL_)" <<<"$env_out" \
  && bad "daemon environment leaked: $(grep -E '^(FARAMIR_|LISTEN_|NOTIFY_|INVOCATION_ID|JOURNAL_)' <<<"$env_out" | head -2)" \
  || ok "and none of the daemon's own activation environment does either"
# An injected ref is there, and comes back as its token.
out=$(run --env PW=secret://db/password -- /usr/bin/printenv PW)
[ "$out" = "$TOKEN" ] && ok "an injected ref is in the child's environment, redacted on the way out" \
  || bad "injected value = [$out]"
# And only the ones asked for.  printenv on an unset name prints nothing and
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
cols=$(grep -oP 'term_cols = \K[0-9]+' /etc/faramir/config.toml)
rows=$(grep -oP 'term_rows = \K[0-9]+' /etc/faramir/config.toml)
# From stdout, not stdin: stty reads the terminal on its standard input by
# default, and stdin here is /dev/null by design.  The PTY is on stdout.
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

# --------------------------------------------------------------------------
head_ "7. the kill path, which is the whole of the cgroup argument"
before_strays=$(strays); before_cgroups=$(runCgroups)
echo "  (before: cgroups=$before_cgroups strays=[${before_strays:-none}])"

# A command that times out, having forked a child that left the process group
# and a parent that ignores SIGTERM.  Signalling the process group would miss
# the setsid one; this is what cgroup.kill is for.
# Backgrounded, and inspected on a clock of its own.  Waiting for the call to
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
cap=$(grep -oP 'max_output_bytes = \K[0-9]+' /etc/faramir/config.toml)
out=$(run -- /bin/sh -c "yes abcdefgh | head -c $(( cap * 2 ))")
[ "${#out}" -lt "$(( cap * 2 ))" ] && ok "output past max_output_bytes ($cap) is cut at ${#out} chars" \
  || bad "no truncation: got ${#out} for a cap of $cap"
grep -qi "truncat" <<<"$out" && ok "and the caller is told it was truncated" \
  || bad "truncation was silent"

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

head_ "11. more commands at once than the broker will take"
limit=$(grep -oP 'max_concurrency = \K[0-9]+' /etc/faramir/config.toml)
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
