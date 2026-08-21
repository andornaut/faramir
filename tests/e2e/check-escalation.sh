#!/bin/bash
# The --allow-sudo escalation channel, the one path that hands out root.
#
# Not "does sudo work" but the claims the design makes about it: root is handed
# out one command at a time, only a human at a root shell hands it out, a child
# cannot decide its own escalation, no second brokered command runs beside an
# escalation, and a yes that lands while the host is not quiet is refused rather
# than taken.
#
# Self-provisioning: it installs the grant itself, so it can run on a container
# brought up without one. Run as root in the container.
set -u
SECRET='hunter2-correct-horse-battery'
CFG=/etc/faramir/config.toml

# The escalation timeout, addressed by section. [command] has a key of the same
# name, and it comes first in the file, so a bare `sed -n 's/^timeout_sec/'`
# reads the wrong one and a bare `sed -i` rewrites both -- which puts a command
# timeout into a section whose ceiling is 600 and leaves the broker refusing to
# start at all.
escalation_timeout() { sed -n '/^\[escalation\]/,/^\[/{s/^timeout_sec *= *\([0-9]*\).*/\1/p}' "$CFG" | head -1; }
set_escalation_timeout() { sed -i "/^\[escalation\]/,/^\[/{s/^timeout_sec = .*/timeout_sec = $1/}" "$CFG"; }
LOG=/var/log/faramir/audit.log
. "$(dirname "$0")/lib.sh" || { echo "e2e: lib.sh is missing beside $0" >&2; exit 2; }

# The outstanding question's id, and a wait for one to appear.
q() { /usr/local/bin/faramir escalations --json 2>/dev/null | grep -oE '"id"[^,]*' | head -1 | cut -d'"' -f4; }
waitq() { local i; for _ in $(seq 100); do i=$(q); [ -n "$i" ] && { echo "$i"; return; }; sleep 0.1; done; echo ""; }
# quiesce leaves no question outstanding and no process of the executor's uid,
# which is the state every group below starts from: a leftover of either makes
# the next group measure the last one.
quiesce() {
  local id
  for id in $(/usr/local/bin/faramir escalations --json 2>/dev/null | grep -oE '"id"[^,]*' | cut -d'"' -f4); do
    /usr/local/bin/faramir deny "$id" >/dev/null 2>&1
  done
  pkill -u faramir-exec 2>/dev/null || true
  sleep 1
}
# sudoRun starts a brokered sudo in the background and leaves its pid in RUN.
sudoRun() { # outfile, then argv
  local out=$1; shift
  setsid runuser -u op -- /usr/local/bin/faramir run --quiet -t 45 -- "$@" >"$out" 2>&1 </dev/null &
  RUN=$!
}
# ask sends one request to the broker as an account, and prints the answer. The
# version every client sends is filled in, the broker refusing a request naming
# another before it reads the op.
VERSION=$(faramir version | awk '{print $NF}')
ask() { runuser -u "$1" -- /usr/bin/python3 -c "
import json,socket,sys
p=json.loads(sys.argv[1]); p.setdefault('version', sys.argv[2])
s=socket.socket(socket.AF_UNIX); s.connect('/run/faramir/broker.sock')
s.sendall(json.dumps(p).encode()+b'\n')
print(s.recv(65536).decode()[:160])" "$2" "$VERSION" 2>&1; }

# The notifier the grant is installed with. A script rather than wall, which
# writes to terminals a container has none of; what is being checked is that the
# broker runs the thing at all and what it hands it, not what wall does with it.
# It writes into the log directory because that is one of the two places the
# broker's own unit can write, PrivateTmp= putting its /tmp somewhere nothing
# else sees.
NOTIFY=/var/log/faramir/notify.log
cat >/usr/local/bin/e2e-notify <<'EOS'
#!/bin/sh
printf '%s\n' "$*" >>/var/log/faramir/notify.log
EOS
chmod 0755 /usr/local/bin/e2e-notify

# Re-installed when the grant is absent OR when it carries no notifier: the
# suites share one install, so this may run after another has already written a
# [escalation] section without one.
if ! grep -q '^notify_command' $CFG; then
  /usr/local/bin/faramir init --allow-sudo --agent-user op \
    --notify-command /usr/local/bin/e2e-notify --notify-command '{prompt}' \
    >/tmp/sudo-init.log 2>&1 \
    || { echo "could not install the grant"; tail -3 /tmp/sudo-init.log; exit 1; }
  systemctl restart faramir-keeper.socket faramir-exec.socket faramir-broker.socket >/dev/null 2>&1
  sleep 3
fi
rm -f "$NOTIFY"
echo "grant installed; [escalation] timeout_sec=$(escalation_timeout)"
pkill -u faramir-exec 2>/dev/null; sleep 1

# --------------------------------------------------------------------------
head_ "1. a yes makes one command root, a no does not"

sudoRun /tmp/ap.out /usr/bin/sudo /usr/bin/id
ID=$(waitq)
if [ -z "$ID" ]; then
  bad "no question was filed for a brokered sudo"
else
  ok "a question was filed ($ID)"
  /usr/local/bin/faramir approve "$ID" >/dev/null 2>&1
  wait $RUN 2>/dev/null
  grep -q 'uid=0(root)' /tmp/ap.out && ok "the approved command ran as root" \
    || bad "it did not become root: $(head -2 /tmp/ap.out | tr '\n' ' ')"
fi
quiesce

sudoRun /tmp/dn.out /usr/bin/sudo /usr/bin/id
ID=$(waitq)
/usr/local/bin/faramir deny "$ID" >/dev/null 2>&1
wait $RUN 2>/dev/null
grep -q 'uid=0(root)' /tmp/dn.out && bad "a REFUSED command became root anyway" \
  || ok "a refused command does not become root"
quiesce

# Which no it was, at the tool boundary. sudo reports the same authentication
# failure for a refusal and for a question nobody answered, and the two differ in
# whether running the command again is worth anything.
sudoRun /tmp/dnwhy.out /usr/bin/sudo /usr/bin/id
ID=$(waitq)
/usr/local/bin/faramir deny "$ID" >/dev/null 2>&1
wait $RUN 2>/dev/null
grep -q 'escalation denied' /tmp/dnwhy.out && ok "and the caller is told a human refused it" \
  || bad "the refusal reaches the caller unnamed: $(tr '\n' ' ' </tmp/dnwhy.out | cut -c1-150)"
quiesce

# --------------------------------------------------------------------------
head_ "2. only a human at a root shell answers"

sudoRun /tmp/who.out /usr/bin/sudo /usr/bin/id -un
ID=$(waitq)
[ -n "$ID" ] || bad "no question to answer"

out=$(ask op "{\"op\":\"approve\",\"id\":\"$ID\"}")
grep -q forbidden <<<"$out" && ok "the agent's uid cannot approve over the socket" \
  || bad "op approved: ${out:0:110}"
out=$(ask faramir-exec "{\"op\":\"approve\",\"id\":\"$ID\"}")
grep -q forbidden <<<"$out" && ok "nor can the executor's uid" || bad "faramir-exec approved: ${out:0:110}"
out=$(ask op '{"op":"escalations"}')
grep -q forbidden <<<"$out" && ok "and neither may even list what is waiting" \
  || bad "op listed the questions: ${out:0:110}"
out=$(runuser -u op -- /usr/local/bin/faramir approve "$ID" 2>&1)
grep -q 'must run as root' <<<"$out" && ok "faramir approve as the agent is refused by name" \
  || bad "faramir approve as op: ${out:0:110}"
# A brokered command cannot even reach the attempt: it is refused for the same
# serialisation that holds every other command while a question waits.
out=$(runuser -u op -- /usr/local/bin/faramir run --quiet -t 10 -- /bin/echo ran 2>&1)
grep -q escalation_in_progress <<<"$out" && ok "and a brokered command cannot run at all to try" \
  || bad "a brokered command ran beside a question: ${out:0:110}"
[ "$(q)" = "$ID" ] && ok "the question survived every attempt" || bad "the question is gone after those attempts"
/usr/local/bin/faramir deny "$ID" >/dev/null 2>&1
wait $RUN 2>/dev/null
quiesce

# --------------------------------------------------------------------------
head_ "3. a child asking about itself is refused, truthful claim and all"
#
# The child holds nothing to present, so what it sends is its own ancestry --
# which really is inside a live run. It is refused anyway, because `escalate` is
# root's. What protects the op is who may call it, not what a caller knows.

out=$(runuser -u op -- /usr/local/bin/faramir run --quiet -t 20 -- timeout 5 /usr/bin/python3 -c "
import json,os,socket
s = socket.socket(socket.AF_UNIX); s.connect('/run/faramir/broker.sock')
s.sendall((json.dumps({'op': 'escalate', 'version': '$VERSION', 'procs': [os.getpid()]}) + '\n').encode())
print(s.recv(65536).decode()[:200])" 2>&1)
grep -qi 'forbidden\|root' <<<"$out" && ok "a child asking about its own run is refused" \
  || bad "a child decided its own escalation: ${out:0:140}"
quiesce

# --------------------------------------------------------------------------
head_ "4. a yes that lands while the host is not quiet is refused"
#
# The window a yes opens is the executor's uid, which every brokered command
# shares. A process of that uid alive outside the run being approved could ride
# it, so the answer is refused rather than taken.

sudoRun /tmp/stray.out /usr/bin/sudo /usr/bin/id -un
ID=$(waitq)
setsid runuser -u faramir-exec -- /bin/sleep 60 >/dev/null 2>&1 </dev/null &
sleep 1
out=$(/usr/local/bin/faramir approve --json "$ID" 2>&1)
grep -q not_quiescent <<<"$out" && ok "the operator's yes was refused: not_quiescent" \
  || bad "a yes was taken with a stray process alive: ${out:0:130}"
grep -qE '[0-9]+ \(sleep\)' <<<"$out" && ok "and it names the process in the way" \
  || bad "it does not name what was running: ${out:0:130}"
wait $RUN 2>/dev/null
grep -q 'uid=0\|^root$' /tmp/stray.out && bad "*** it became root anyway ***" \
  || ok "and the command did not become root"
quiesce

sudoRun /tmp/quiet.out /usr/bin/sudo /usr/bin/id -un
ID=$(waitq)
out=$(/usr/local/bin/faramir approve --json "$ID" 2>&1)
grep -q 'approved' <<<"$out" && ok "the same yes on a quiet host is taken" \
  || bad "a yes on a quiet host was refused: ${out:0:130}"
wait $RUN 2>/dev/null
[ "$(tail -1 /tmp/quiet.out)" = root ] && ok "and the command became root" \
  || bad "it did not become root: $(tail -1 /tmp/quiet.out)"
quiesce

# --------------------------------------------------------------------------
head_ "5. what one approval covers, and what the question shows of it"
#
# One question per run, not per sudo: a playbook's twenty become'd tasks are one
# escalation. What the operator judges that by is the command, so the question has
# to carry the whole of it.

sudoRun /tmp/scope.out /bin/sh -c 'sudo /usr/bin/id -un; sudo /bin/cat /etc/shadow | head -1; sudo /usr/bin/whoami'
ID=$(waitq)
question=$(/usr/local/bin/faramir escalations 2>/dev/null)
grep -q 'cat /etc/shadow' <<<"$question" && ok "shows the whole argv, second sudo included" \
  || bad "the question hides part of the command: ${question:0:150}"
# The host is a field rather than part of the prompt, and an operator watching
# two of them has nothing else to place the question by.
grep -qE '^  host +[^ ]' <<<"$question" && ok "and names the host it would become root on" \
  || bad "the question names no host: ${question:0:150}"
# And who asked, which is not who would run it: every brokered command runs as
# the executor, so that uid says nothing about whose command this is.
grep -qE "^  caller +op \(uid $(id -u op)\)" <<<"$question" \
  && ok "and the account that asked, by name and uid" \
  || bad "the question does not name the caller: $(grep -E '^  caller' <<<"$question")"
grep -qE '^  caller +faramir-exec' <<<"$question" \
  && bad "the question names the executor as the caller" \
  || ok "and not the account it would run as"
/usr/local/bin/faramir approve "$ID" >/dev/null 2>&1
wait $RUN 2>/dev/null
covered=$(grep -c '^root' /tmp/scope.out)
[ "$covered" -ge 2 ] && ok "one yes covered all $covered sudos in that run" \
  || bad "only $covered sudo(s) ran: $(tr '\n' ' ' </tmp/scope.out | cut -c1-110)"
[ "$(q)" = "" ] && ok "and no further question was filed for the later ones" || bad "a second question was filed"
quiesce

# --------------------------------------------------------------------------
head_ "6. the question itself carries no value"

runuser -u op -- /usr/local/bin/faramir run --quiet -t 30 \
  --env PW=faramir://db/password -- /usr/bin/sudo /usr/bin/id -un >/tmp/val.out 2>&1 </dev/null &
RUN=$!
ID=$(waitq)
body=$(/usr/local/bin/faramir escalations --json 2>/dev/null)
# The listing answered, or the absence below is an op that failed rather than a
# question that holds no value.
grep -qF "$ID" <<<"$body" || bad "escalations --json did not name the waiting question"
grep -qF "$SECRET" <<<"$body" && bad "the question carries the plaintext value" \
  || ok "the question an operator reads carries no value"
/usr/local/bin/faramir deny "$ID" >/dev/null 2>&1
wait $RUN 2>/dev/null
grep -qF "$SECRET" $LOG && bad "the audit log carries the value" || ok "and neither does the record"
quiesce

# --------------------------------------------------------------------------
head_ "7. answering something that is not there"

out=$(/usr/local/bin/faramir approve deadbeef 2>&1); code=$?
[ $code -ne 0 ] && ok "an id naming no question is an error (exit $code)" \
  || bad "approving an unknown id succeeded"
grep -qi 'unknown\|no such\|not waiting' <<<"$out" && ok "and says so: $(head -1 <<<"$out" | cut -c1-70)" \
  || bad "unclear: ${out:0:110}"

sudoRun /tmp/twice.out /usr/bin/sudo /usr/bin/id -un
ID=$(waitq)
/usr/local/bin/faramir approve "$ID" >/dev/null 2>&1
out=$(/usr/local/bin/faramir approve "$ID" 2>&1); code=$?
[ $code -ne 0 ] && ok "answering the same question twice is an error" \
  || bad "the same question was answered twice: ${out:0:110}"
wait $RUN 2>/dev/null
quiesce

out=$(/usr/local/bin/faramir deny 2>&1); code=$?
[ $code -ne 0 ] && ok "a bare deny with nothing waiting is an error" || bad "deny with no question: exit $code"

# --------------------------------------------------------------------------
head_ "8. a question nobody answers"

before=$(escalation_timeout)
set_escalation_timeout 5
systemctl restart faramir-broker.socket faramir-broker.service >/dev/null 2>&1; sleep 3

start=$(date +%s)
runuser -u op -- /usr/local/bin/faramir run --quiet -t 40 -- /usr/bin/sudo /usr/bin/id -un >/tmp/to.out 2>&1
elapsed=$(( $(date +%s) - start ))
[ "$elapsed" -lt 25 ] && ok "an unanswered question ends in ${elapsed}s, near [escalation] timeout_sec=5" \
  || bad "it took ${elapsed}s to give up on an unanswered question"
grep -q 'uid=0\|^root$' /tmp/to.out && bad "*** an unanswered command became root ***" \
  || ok "and the command did not become root"
[ "$(q)" = "" ] && ok "and the question is not left outstanding" || bad "the question outlived its timeout"
# And the caller is told which of the two it was, the command having seen the
# same authentication failure either way.
runuser -u op -- /usr/local/bin/faramir run --quiet -t 40 -- /usr/bin/sudo /usr/bin/id -un >/tmp/towhy.out 2>&1
grep -q 'escalation expired' /tmp/towhy.out && ok "and told under --quiet, which is how an agent runs one" \
  || bad "an expiry is not told from a refusal: $(tr '\n' ' ' </tmp/towhy.out | cut -c1-150)"
grep -q 'escalation denied' /tmp/towhy.out && bad "an expiry was reported as a refusal" \
  || ok "and not as one somebody typed"
# The host is usable again straight after, the serialisation having ended with it.
out=$(runuser -u op -- /usr/local/bin/faramir run --quiet -t 10 -- /bin/echo after 2>&1)
[ "$(tail -1 <<<"$out")" = after ] && ok "and ordinary commands run again at once" \
  || bad "the host stayed held after the timeout: ${out:0:110}"
# Nobody watching and somebody saying no are different events, and the record
# says which without anyone parsing the sentence beside it.
[ "$(jq -r 'select(.op=="escalate") | .outcome_code' $LOG 2>/dev/null | tail -1)" = expired ] \
  && ok "the record calls it expired rather than refused" \
  || bad "an unanswered question is recorded as $(jq -r 'select(.op=="escalate") | .outcome_code' $LOG 2>/dev/null | tail -1)"
/usr/local/bin/faramir logs --color never -n 10 | grep -q 'timed out' \
  && ok "and the listing reads it as timed out" \
  || bad "the listing does not tell it from a refusal: $(/usr/local/bin/faramir logs --color never -n 3)"

set_escalation_timeout "${before:-120}"
systemctl restart faramir-broker.socket faramir-broker.service >/dev/null 2>&1; sleep 3
quiesce

# --------------------------------------------------------------------------
head_ "9. the PAM helper on its own"
#
# It is what sudo execs, as root, so what it does when invoked by hand is the
# question: it decides authentication for one account and one PAM type.

HELPER=/usr/local/libexec/faramir/pam-approve
for probe in "PAM_TYPE=account:PAM_USER=faramir-exec" "PAM_TYPE=session:PAM_USER=faramir-exec" \
             "PAM_TYPE=auth:PAM_USER=root" "PAM_TYPE=auth:PAM_USER=op"; do
  env_type=${probe%%:*}; env_user=${probe##*:}
  out=$(env "$env_type" "$env_user" "$HELPER" --account faramir-exec 2>&1); code=$?
  if [ $code -ne 0 ]; then
    ok "$env_type $env_user is refused: $(head -1 <<<"$out" | cut -c1-62)"
  else
    bad "$env_type $env_user was authenticated"
  fi
done
out=$(env PAM_TYPE=auth PAM_USER=faramir-exec "$HELPER" --account faramir-exec 2>&1); code=$?
[ $code -ne 0 ] && ok "and an auth for the right account with no brokered run behind it is refused" \
  || bad "the helper authenticated a caller that is not a brokered command"

# --------------------------------------------------------------------------
head_ "10. what became of the approved run"
#
# A yes is the last decision anybody makes about that command, so the terminal
# that gave root away is told how it ended. It comes back on the poll the
# question came in on, which is what `faramir escalations --watch` is sitting in:
# no second channel, and no read of the audit log.
#
# Only here, and not in the Go tests: filling the ending in is the exec path's,
# and reaching that path means a real sudo through PAM.

sudoRun /tmp/ended.out /usr/bin/sudo /bin/sh -c 'exit 3'
ID=$(waitq)
LOGID=$(/usr/local/bin/faramir escalations --json 2>/dev/null | grep -oE '"log_id"[^,]*' | head -1 | cut -d'"' -f4)
[ -n "$LOGID" ] && ok "the question names the exec record it belongs to ($LOGID)" \
  || bad "the question carries no log_id, so there is nothing to wait on"
# Answered after a pause, so the wait is a number worth reporting: the command's
# own duration is wall time and it is blocked inside sudo for all of it.
sleep 3
/usr/local/bin/faramir approve "$ID" >/dev/null 2>&1
wait $RUN 2>/dev/null

# The op as the watcher sends it: the run it approved, by name.
ending() { /usr/bin/python3 -c "
import socket,sys,json
s=socket.socket(socket.AF_UNIX); s.connect('/run/faramir/broker.sock')
request={'op':'escalations','version':'$VERSION'}
if sys.argv[1]: request['await_log_id']=sys.argv[1]
s.sendall(json.dumps(request).encode()+b'\n')
f=json.loads(s.recv(65536).decode()).get('finished')
print('none' if f is None else '%s %s' % (f.get('log_id'), f.get('exit_code')))" "$1"; }

# What of that duration was the question rather than the command. The answer
# was slept on above, so the number has something to report.
#
# w+0 forces the comparison numeric: a missing field reads back as the string
# "null", and awk compares two strings lexically, where "null" >= "2" is true.
# The field going missing is what this exists to catch, so it must not pass.
waited=$(jq -r --arg id "$LOGID" 'select(.log_id==$id and .op=="run") | .waited_sec' $LOG 2>/dev/null | tail -1)
awk -v w="${waited:-0}" 'BEGIN { exit !(w + 0 >= 2) }' \
  && ok "and the record says ${waited}s of it was waiting to be approved" \
  || bad "waited_sec is [$waited], want the seconds the answer took"
resp=$(runuser -u op -- /usr/local/bin/faramir run --json -t 20 -- /bin/true 2>/dev/null)
grep -q '"waited_sec"' <<<"$resp" \
  && bad "a command that asked nobody reports a wait: $(head -c 120 <<<"$resp")" \
  || ok "and a command that never asked carries no wait at all"

[ "$(ending "$LOGID")" = "$LOGID 3" ] \
  && ok "and its ending reached root: exit 3, the status the command left" \
  || bad "the ending did not reach root: $(ending "$LOGID")"
# The slot is not emptied when it is read, so naming the run is the whole of
# what keeps a stale ending off a terminal that approved nothing.
[ "$(ending "")" = none ] && ok "and a caller that approved nothing is told nothing" \
  || bad "an ending reached a caller that named no run: $(ending "")"
quiesce

# --------------------------------------------------------------------------
head_ "11. the record"

[ "$(grep -c '"approved":true' $LOG)" -ge 1 ] && ok "an escalation is recorded" || bad "no escalation recorded"
[ "$(grep -c '"approved":false' $LOG)" -ge 1 ] && ok "a refusal is recorded" || bad "no refusal recorded"
# Both answers read as answers in the listing, not as blank rows.
/usr/local/bin/faramir logs --color never -n 80 | grep -q approved && ok "an escalation reads as approved in faramir logs" \
  || bad "an escalation renders with no outcome"
/usr/local/bin/faramir logs --color never -n 80 | grep -q refused && ok "and a refusal reads as refused" \
  || bad "a refusal renders with no outcome"
# Which no it was, for each of the three this suite produced. A denial, an
# expiry and a yes read alike in prose and are acted on differently.
for want in approved denied expired; do
  [ "$(jq -r --arg c "$want" 'select(.op=="escalate" and .outcome_code==$c) | .outcome_code' $LOG 2>/dev/null | head -1)" = "$want" ] \
    && ok "a $want ending is recorded as one" || bad "no escalate record carries outcome_code=$want"
done
# The prose is kept beside it: it names the account that answered, which no code
# carries.
jq -r 'select(.op=="escalate" and .outcome_code=="denied") | .outcome' $LOG 2>/dev/null | grep -q 'refused by' \
  && ok "and the sentence beside it still names who answered" \
  || bad "the prose was dropped when the code arrived"

# The escalation points at the command it authorised.
id=$(jq -r 'select(.op=="escalate" and .approved==true) | .run_log_id' $LOG 2>/dev/null | tail -1)
[ -n "$id" ] && [ "$id" != null ] && ok "and names the command's own record ($id)" \
  || bad "an escalation does not point at the run it authorised"

# --------------------------------------------------------------------------
head_ "12. the notifier"
#
# [escalation] notify_command is what says a question is waiting, and it is init's:
# a drop-in setting it is refused, so `faramir init --notify-command` is the
# only way onto a host, and this is the check that the flag reaches the broker
# rather than only the file.

grep -q '^notify_command = \["/usr/local/bin/e2e-notify", "{prompt}"\]' $CFG \
  && ok "init wrote the notifier the flag named" \
  || bad "the config does not carry it: $(grep '^notify_command' $CFG || echo none)"
[ -s "$NOTIFY" ] && ok "the broker ran it, $(wc -l <"$NOTIFY") announcement(s)" \
  || bad "nothing was announced, though questions were raised"
grep -q 'Approve this command to run as root?' "$NOTIFY" && ok "and handed it the prompt, expanded" \
  || bad "the announcement is not the prompt: $(head -1 "$NOTIFY" | cut -c1-90)"
grep -q '{prompt}' "$NOTIFY" && bad "the placeholder was passed through unexpanded" \
  || ok "with the placeholder substituted rather than passed through"
# {prompt} was asked for and {id} was not, so the id must not be in there: it is
# what a reader types to approve, and this channel reaches whoever can see it.
if grep -qE '\b[0-9a-f]{6}\b' "$NOTIFY"; then
  bad "an announcement carries a question id, which {prompt} alone must not: $(grep -oE '\b[0-9a-f]{6}\b' "$NOTIFY" | head -1)"
else
  ok "and no question id, {id} not having been asked for"
fi
grep -q "$SECRET" "$NOTIFY" && bad "*** an announcement carries the plaintext value ***" \
  || ok "and no secret value"

# --------------------------------------------------------------------------
head_ "13. an Enter is not an answer"
#
# Two ways a keypress reaches a question it was not meant for, and neither may
# refuse it:
#
#   - typed before the question arrived, which sits in the terminal until one
#     does and is spent on it the instant it appears;
#   - typed after the prompt, which is somebody at the terminal saying nothing.
#
# Only here, and not in the Go tests: both are about the terminal's own input
# queue, so what they need is a pty and a real question raised through PAM.

# The driver: a watcher on a pty of its own, a brokered sudo to raise the
# question, and the keystrokes written in at the moment each case is about. It
# reports what the terminal saw rather than deciding anything, so the assertions
# stay in the shell with the rest of them.
cat >/tmp/watch-answer.py <<'EOS'
import os, pty, select, subprocess, sys, time

MODE = sys.argv[1]

pid, fd = pty.fork()
if pid == 0:
    os.execv("/usr/local/bin/faramir", ["faramir", "escalations", "--watch"])
    os._exit(127)

buf = ""


def pump(until, timeout):
    """Read the pty until until(buf), or the timeout runs out."""
    global buf
    end = time.time() + timeout
    while time.time() < end:
        if until(buf):
            return True
        r, _, _ = select.select([fd], [], [], 0.2)
        if not r:
            continue
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        buf += data.decode("utf-8", "replace")
    return until(buf)


def give_up(why):
    print("FAILED", why)
    print("PROMPTS", buf.count("approve? [y/n]"))
    os.kill(pid, 9)
    sys.exit(0)


if not pump(lambda b: "waiting for escalation requests" in b, 30):
    give_up("the watcher never started")

# Before the question exists, which is the whole of the first case: these have
# to be in the terminal's queue by the time one is raised.
if MODE == "before":
    os.write(fd, b"\n\n\n\n")
    time.sleep(1)

run = subprocess.Popen(
    ["runuser", "-u", "op", "--", "/usr/local/bin/faramir", "run", "--quiet",
     "-t", "45", "--", "/usr/bin/sudo", "/usr/bin/id", "-un"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if not pump(lambda b: "approve? [y/n]" in b, 60):
    give_up("no prompt appeared")

if MODE == "after":
    # One burst, the blank lines and the answer behind them: separate writes
    # would pass even where each re-ask throws away what is queued behind it.
    os.write(fd, b"\n\n\n\ny\n")
else:
    os.write(fd, b"y\n")

# "refused:" with the colon, which is the watcher's own line. Bare "refused"
# is in every question, the expires line saying what happens if nobody answers,
# so waiting on that returns before the answer has been read at all. The colon
# and no further: this is a pty, so the watcher paints, and what follows the
# word is the reset rather than the space it reads as.
pump(lambda b: " started" in b or "refused:" in b, 60)
try:
    run.wait(timeout=60)
except subprocess.TimeoutExpired:
    run.kill()
os.kill(pid, 15)

print("PROMPTS", buf.count("approve? [y/n]"))
print("REFUSED", "yes" if "refused:" in buf else "no")
print("STARTED", "yes" if " started" in buf else "no")
EOS

field() { sed -n "s/^$2 //p" <<<"$1" | head -1; }



quiesce
out=$(/usr/bin/python3 /tmp/watch-answer.py before 2>&1)
[ "$(field "$out" REFUSED)" = no ] \
  && ok "Enters typed before the question do not refuse it" \
  || bad "an Enter typed before the question refused it: ${out//$'\n'/ }"
[ "$(field "$out" STARTED)" = yes ] && ok "and the yes after them is taken" \
  || bad "the yes was not taken: ${out//$'\n'/ }"
# One prompt, not five: they were discarded rather than asked again, which is
# what keeps them from being spent on a question nobody had read.
[ "$(field "$out" PROMPTS)" = 1 ] && ok "and they were discarded rather than re-asked" \
  || bad "$(field "$out" PROMPTS) prompts, want 1: input predating the question reached it"
quiesce

out=$(/usr/bin/python3 /tmp/watch-answer.py after 2>&1)
[ "$(field "$out" REFUSED)" = no ] \
  && ok "Enters typed after the prompt do not refuse the question" \
  || bad "an Enter typed at the prompt refused the question: ${out//$'\n'/ }"
[ "$(field "$out" STARTED)" = yes ] && ok "and the yes behind them is taken" \
  || bad "the yes behind them was lost: ${out//$'\n'/ }"
# Five: the first prompt and one re-ask for each blank line. Fewer means a
# blank line was counted as an answer; the yes surviving the burst is what says
# a re-ask does not discard what is queued behind it.
[ "$(field "$out" PROMPTS)" = 5 ] && ok "and each was asked again rather than counted" \
  || bad "$(field "$out" PROMPTS) prompts, want 5"
quiesce

# --------------------------------------------------------------------------
head_ "14. a question nobody answers, and the one raised after it"
#
# The prompt has a clock of its own, and it is the question's. Without it the
# watcher sat inside the read until somebody typed, so the first question's
# clock ran out unnoticed and the second was not shown until a keystroke
# arrived: a watcher that has stopped watching while still saying it is.
cat >/tmp/watch-expire.py <<'EOS'
import os, pty, select, subprocess, sys, time

PROMPT = "approve? [y/n]"

pid, fd = pty.fork()
if pid == 0:
    os.execv("/usr/local/bin/faramir", ["faramir", "escalations", "--watch"])
    os._exit(127)

buf = ""


def pump(until, timeout):
    global buf
    end = time.time() + timeout
    while time.time() < end:
        if until(buf):
            return True
        r, _, _ = select.select([fd], [], [], 0.2)
        if not r:
            continue
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        buf += data.decode("utf-8", "replace")
    return until(buf)


def terminal():
    # What the watcher printed, on one line: the answer it refused and why is
    # printed there and nowhere else this driver can reach, so a failure that
    # does not carry it says only that something did not happen.
    return "TERMINAL " + repr(buf[-600:])


def give_up(why):
    print("FAILED", why)
    print(terminal())
    os.kill(pid, 9)
    sys.exit(0)


def raise_question(marker):
    return subprocess.Popen(
        ["runuser", "-u", "op", "--", "/usr/local/bin/faramir", "run", "--quiet",
         "-t", "60", "--", "/usr/bin/sudo", "/bin/echo", marker],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if not pump(lambda b: "waiting for escalation requests" in b, 30):
    give_up("the watcher never started")

first = raise_question("first")
if not pump(lambda b: PROMPT in b, 60):
    give_up("no prompt for the first question")

# Nothing typed: the question's own clock is what has to end the wait.
if not pump(lambda b: "expired" in b, 60):
    give_up("the watcher never said the question expired")
try:
    first.wait(timeout=120)
except subprocess.TimeoutExpired:
    first.kill()
    give_up("the first command never returned")

# The prompts printed so far, so what is waited for below is a new one rather
# than a count already reached: a yes typed at a prompt that has not been
# printed is discarded, the terminal dropping what predates the question.
asked = buf.count(PROMPT)
# And the host is left quiet first, which is the state every group here starts
# from. A yes that lands while a stray of the command just ended is still
# alive is refused for want of quiescence, which is section 4's subject rather
# than this one's.
subprocess.run(["pkill", "-u", "faramir-exec"], check=False)
time.sleep(1)

# And the next one is shown without a keystroke having been sent.
second = raise_question("second")
shown = pump(lambda b: b.count(PROMPT) > asked, 60)
if shown:
    os.write(fd, b"y\n")
    pump(lambda b: " started" in b, 60)
try:
    second.wait(timeout=60)
except subprocess.TimeoutExpired:
    second.kill()
os.kill(pid, 15)

print("EXPIRED", "yes" if "expired" in buf else "no")
print("SECOND_SHOWN", "yes" if shown else "no")
print("SECOND_ANSWERED", "yes" if " started" in buf else "no")
print(terminal())
EOS

quiesce
# Long enough that the second question can be raised, shown, answered and
# started inside it, and short enough that the first expires while the driver
# waits. Section 8's five seconds only has to reach an expiry, and this has to
# reach an answer after one.
before=$(escalation_timeout)
set_escalation_timeout 20
systemctl restart faramir-broker.socket faramir-broker.service >/dev/null 2>&1; sleep 3

out=$(/usr/bin/python3 /tmp/watch-expire.py 2>&1)
[ "$(field "$out" EXPIRED)" = yes ] \
  && ok "a question nobody answers ends the wait on its own clock" \
  || bad "the watcher sat on a dead prompt: ${out//$'\n'/ }"
[ "$(field "$out" SECOND_SHOWN)" = yes ] \
  && ok "and the question raised after it is shown without a keystroke" \
  || bad "the watcher stopped watching: ${out//$'\n'/ }"
[ "$(field "$out" SECOND_ANSWERED)" = yes ] && ok "and can still be answered" \
  || bad "the second question could not be answered: ${out//$'\n'/ }"

set_escalation_timeout "${before:-120}"
systemctl restart faramir-broker.socket faramir-broker.service >/dev/null 2>&1; sleep 3
quiesce

# --------------------------------------------------------------------------
head_ "15. what a brokered command's sudo is given"
#
# env_reset throws away what the caller was holding, which is right: the
# executor's uid is shared by every brokered command, so anything it carries is a
# value one of them chose. What root gets instead comes from the file the grant
# names, which that uid cannot write.

ENVFILE=/usr/local/libexec/faramir/sudo-env
[ -f "$ENVFILE" ] && ok "the environment file is there" \
  || bad "$ENVFILE was not written"
owner=$(stat -c '%U:%G %a' "$ENVFILE" 2>/dev/null)
[ "$owner" = "root:root 644" ] \
  && ok "and is root's at 0644, PAM reading it as root" \
  || bad "$ENVFILE is '$owner', not 'root:root 644'"
# Read by pam_env in whichever file carries faramir's stack, rather than named as
# the grant's env_file: sudo-rs has no such setting, so one mechanism is carried
# for both. Which file that is, the install recorded.
STACK=$(sed -n '/^\[escalation\]/,/^\[/{s/^pam_stack *= *"\(.*\)".*/\1/p}' $CFG | head -1)
[ -n "$STACK" ] \
  && ok "[escalation] pam_stack names $STACK" \
  || bad "the config records no pam_stack, so nothing says where the stack is"
[ -e "$STACK" ] \
  && ok "and that file is there" || bad "$STACK is recorded and absent"
grep -q "pam_env.so envfile=$ENVFILE" "$STACK" \
  && ok "and it reads the environment file with pam_env" \
  || bad "$STACK does not read $ENVFILE"
# Under libexec rather than the config directory, which an uninstall keeps and so
# must never remove whole. A file at the old path would pass every check above.
[ -e /etc/faramir/sudo-env ] \
  && bad "a sudo-env is in the config directory, which uninstall must not remove" \
  || ok "and it is not in the config directory"

# The claim itself: a value the file names reaches root, having been discarded on
# the way in. printenv rather than a shell, so what is asserted is the
# environment sudo built and not what a shell would add to it.
sudoRun /tmp/sudoenv.out /usr/bin/sudo /usr/bin/printenv
ID=$(waitq)
if [ -z "$ID" ]; then
  bad "no question was filed for a sudo that reads its own environment"
else
  /usr/local/bin/faramir approve "$ID" >/dev/null 2>&1
  wait $RUN 2>/dev/null
  grep -q '^FARAMIR_OPERATOR=op$' /tmp/sudoenv.out \
    && ok "root is told which account the host belongs to" \
    || bad "FARAMIR_OPERATOR did not survive the sudo: $(grep '^FARAMIR_OPERATOR=' /tmp/sudoenv.out || echo absent)"
  # Which SUDO_USER cannot say, and this is the check that shows why the variable
  # exists at all: sudo names the account that invoked it, and that is the
  # executor on every brokered command.
  grep -q '^SUDO_USER=faramir-exec$' /tmp/sudoenv.out \
    && ok "and SUDO_USER names the executor, which is why the operator is named apart" \
    || bad "SUDO_USER is $(grep '^SUDO_USER=' /tmp/sudoenv.out || echo absent)"
  grep -q '^DEBIAN_FRONTEND=noninteractive$' /tmp/sudoenv.out \
    && ok "and a [command] env value survives the sudo too" \
    || bad "DEBIAN_FRONTEND did not survive: $(grep '^DEBIAN_FRONTEND=' /tmp/sudoenv.out || echo absent)"
  # PATH is sudo's own on the far side whatever the file says, so what is checked
  # is that root has one rather than which one: a PATH from pam_env is overridden,
  # which is why the install leaves it out without a word.
  grep -q '^PATH=' /tmp/sudoenv.out && ok "and root has a PATH of sudo's own choosing" \
    || bad "root got no PATH at all"
fi
quiesce

# --------------------------------------------------------------------------
head_ "15b. sudo -n reaches the question"

# The grant sets noninteractive_auth, and integrations.md tells operators they
# can drop the `ansible_become_flags: '-H'` workaround because of it. Without the
# setting, sudo refuses before the PAM stack runs and no question is ever put, so
# the whole become path fails while a human watches for something that never
# arrives. `become` passes -n by default, so this is what most brokered sudo
# actually looks like.
grep -q 'noninteractive_auth' /etc/sudoers.d/faramir \
  && ok "the grant sets noninteractive_auth" \
  || bad "the grant does not set noninteractive_auth"
sudoRun /tmp/nonint.out /usr/bin/sudo -n /usr/bin/id
ID=$(waitq)
if [ -z "$ID" ]; then
  bad "sudo -n filed no question, so it refused before the PAM stack ran: $(head -2 /tmp/nonint.out)"
else
  ok "a question was filed for a sudo run with -n ($ID)"
  /usr/local/bin/faramir approve "$ID" >/dev/null 2>&1
  wait $RUN 2>/dev/null
  grep -q 'uid=0' /tmp/nonint.out \
    && ok "and the approved -n command reached root" \
    || bad "sudo -n did not end at root: $(head -2 /tmp/nonint.out)"
fi
quiesce
# And a refusal under -n is still a refusal rather than a fall-through.
sudoRun /tmp/nonint.deny /usr/bin/sudo -n /usr/bin/id
ID=$(waitq)
if [ -z "$ID" ]; then
  bad "no question was filed for the -n refusal check"
else
  /usr/local/bin/faramir deny "$ID" >/dev/null 2>&1
  wait $RUN 2>/dev/null
  grep -q 'uid=0' /tmp/nonint.deny \
    && bad "a refused sudo -n reached root" || ok "and a no still refuses under -n"
fi
quiesce

# --------------------------------------------------------------------------
head_ "16. the other sudo, and switching to it"

# Ubuntu ships two implementations behind one alternatives group, and they take
# different settings out of the same /etc/sudoers.d. Every group above ran under
# whichever this stack's host has; this one switches to the OTHER and checks that
# `init` writes what that sudo can read, that what it needs lands without
# changing what the shared stacks say for anybody else, and that a real
# escalation still ends at root.
#
# Last, and it puts the host back: leaving the box on the other implementation
# would hand the next suite an install this one rewrote.
SUDORS=/usr/lib/cargo/bin/sudo
SUDOWS=/usr/bin/sudo.ws
# Where this stack started, and where it is going. FARAMIR_E2E_SUDO is set by
# e2e.sh from its own SUDO.
case "${FARAMIR_E2E_SUDO:-classic}" in
  rs) HOME_SUDO=$SUDORS; OTHER_SUDO=$SUDOWS; OTHER_NAME="the original sudo"; OTHER_IS_RS=no ;;
  *)  HOME_SUDO=$SUDOWS; OTHER_SUDO=$SUDORS; OTHER_NAME="sudo-rs"; OTHER_IS_RS=yes ;;
esac
# The `sudo grant` check's status, or "missing". Defined here rather than inside
# the arrangement branch below: the restore at the end asks for it whichever way
# that branch went.
grant_status() {
  /usr/local/bin/faramir doctor --agent-user op --json 2>/dev/null \
    | jq -r '[.findings[]|select(.check=="sudo grant")|.status]|first // "missing"'
}
restore_sudo() {
  update-alternatives --set sudo "$HOME_SUDO" >/dev/null 2>&1
  /usr/local/bin/faramir init --allow-sudo --agent-user op \
    --notify-command /usr/local/bin/e2e-notify --notify-command '{prompt}' \
    >/tmp/sudo-restore.log 2>&1
  systemctl restart faramir-exec.socket >/dev/null 2>&1
}

if [ ! -x "$OTHER_SUDO" ]; then
  note "$OTHER_NAME is not installed here, so the second arrangement went untested"
else
  # What the stock stacks say before faramir touches them, so the claim that
  # everything outside the block survives is measured rather than asserted.
  cp /etc/pam.d/sudo /tmp/sudo.stack.before
  update-alternatives --set sudo "$OTHER_SUDO" >/dev/null 2>&1
  [ "$(readlink -f /etc/alternatives/sudo)" = "$OTHER_SUDO" ] \
    && ok "the host's sudo is now $OTHER_NAME" \
    || bad "switching the alternatives group did not change which sudo runs"

  if ! /usr/local/bin/faramir init --allow-sudo --agent-user op \
      --notify-command /usr/local/bin/e2e-notify --notify-command '{prompt}' \
      >/tmp/other-init.log 2>&1; then
    bad "init refused to write a grant for $OTHER_NAME: $(tail -2 /tmp/other-init.log)"
  else
    ok "init wrote a grant for it"
    systemctl restart faramir-exec.socket >/dev/null 2>&1
    sleep 2

    # The grant names only what this sudo parses, and visudo -- which follows the
    # same alternatives group -- takes the file.
    if [ "$OTHER_IS_RS" = yes ]; then
      grep -qE '^Defaults.*pam_(service|login_service)' /etc/sudoers.d/faramir \
        && bad "the grant still names a setting sudo-rs cannot parse" \
        || ok "and it names no pam_service"
    else
      grep -qE '^Defaults.*pam_service' /etc/sudoers.d/faramir \
        && ok "and it names pam_service, which this sudo does read" \
        || bad "the grant names no pam_service for a sudo that needs one"
    fi
    visudo -cf /etc/sudoers.d/faramir >/dev/null 2>&1 \
      && ok "and this host's visudo parses it" \
      || bad "visudo rejects the grant this host was given"

    if [ "$OTHER_IS_RS" = yes ]; then
      # The branch, in both stacks: the service name is the launch type, so a host
      # covered for `sudo` and not for `sudo -i` fails one of them.
      for stack in /etc/pam.d/sudo /etc/pam.d/sudo-i; do
        grep -q '^# BEGIN faramir' "$stack" \
          && ok "$stack carries the branch" \
          || bad "$stack has no faramir block, so nothing asks the broker there"
        # And the jump clears every faramir module below it. One short and it lands
        # on the block's own pam_permit, which authenticates everybody else.
        jump=$(sed -n '/^# BEGIN faramir/,/^# END faramir/p' "$stack" \
          | grep -m1 '^auth' | grep -oE 'default=[0-9]+' | cut -d= -f2)
        after=$(sed -n '/^# BEGIN faramir/,/^# END faramir/p' "$stack" \
          | grep -c '^auth')
        [ "$jump" = "$((after - 1))" ] \
          && ok "and its branch skips all $jump module(s) below it" \
          || bad "$stack: the branch skips $jump of $((after - 1)) modules in the block"
      done
      # No service file: sudo-rs reaches the service named `sudo` and nothing a
      # caller may name, so one beside the block would be a stack nothing reads.
      [ -e /etc/pam.d/faramir-sudo ] \
        && bad "/etc/pam.d/faramir-sudo is there on a sudo-rs host, where nothing reads it" \
        || ok "and no service file was left beside it"
    else
      [ -e /etc/pam.d/faramir-sudo ] \
        && ok "/etc/pam.d/faramir-sudo is there, which this sudo can be sent to" \
        || bad "no service file for a sudo that selects one by name"
      grep -q '^# BEGIN faramir' /etc/pam.d/sudo \
        && bad "a block is left in /etc/pam.d/sudo, which this sudo needs none of" \
        || ok "and no block was left in the shared stack"
    fi
    # And nothing the distribution put there was touched.
    grep -q 'common-auth' /etc/pam.d/sudo \
      && ok "and what the stack already said is still in it" \
      || bad "the shared stack lost the distribution's own lines"

    # THE ONE THAT MATTERS. An ordinary account with a PASSWD: entry must still
    # be asked for its password, and a wrong one must still be refused.
    #
    # NOPASSWD is no use here: it skips PAM entirely, so an arrangement that
    # authenticates every account for free passes a NOPASSWD check exactly as a
    # correct one does. What the branch can get wrong is landing such an account
    # on faramir's own pam_permit, and only a PASSWD: account can see it.
    useradd -m -s /bin/bash e2e-alice 2>/dev/null
    echo 'e2e-alice:correcthorse-e2e' | chpasswd
    echo 'e2e-alice ALL=(ALL:ALL) PASSWD: ALL' >/etc/sudoers.d/e2e-alice
    chmod 440 /etc/sudoers.d/e2e-alice
    echo wrongpassword | runuser -u e2e-alice -- /usr/bin/sudo -S /usr/bin/id \
      >/tmp/alice.wrong 2>&1
    grep -q 'uid=0' /tmp/alice.wrong \
      && bad "an ordinary account reached root with a WRONG password: whatever \
faramir wrote authenticates every account on this host" \
      || ok "an ordinary account is refused a wrong password"
    printf '\n' | runuser -u e2e-alice -- /usr/bin/sudo -S /usr/bin/id \
      >/tmp/alice.empty 2>&1
    grep -q 'uid=0' /tmp/alice.empty \
      && bad "an ordinary account reached root with an EMPTY password" \
      || ok "and refused an empty one"
    echo correcthorse-e2e | runuser -u e2e-alice -- /usr/bin/sudo -S /usr/bin/id \
      >/tmp/alice.right 2>&1
    grep -q 'uid=0' /tmp/alice.right \
      && ok "and still let through with the right one, so the branch fell through" \
      || bad "an ordinary account cannot sudo at all with the branch in place: \
$(tail -1 /tmp/alice.right)"
    userdel -r e2e-alice >/dev/null 2>&1
    rm -f /etc/sudoers.d/e2e-alice

    # The claim the whole arrangement exists for: a yes still ends at root, and
    # the environment still crosses the sudo.
    quiesce
    sudoRun /tmp/rs.out /usr/bin/sudo /usr/bin/printenv
    ID=$(waitq)
    if [ -z "$ID" ]; then
      bad "no question was filed for a brokered sudo under sudo-rs"
    else
      ok "a question was filed under sudo-rs ($ID)"
      /usr/local/bin/faramir approve "$ID" >/dev/null 2>&1
      wait $RUN 2>/dev/null
      grep -q '^FARAMIR_OPERATOR=op$' /tmp/rs.out \
        && ok "an approved command reached root, and was told whose host it is" \
        || bad "the escalation did not end at root under sudo-rs: $(head -2 /tmp/rs.out)"
      grep -q '^DEBIAN_FRONTEND=noninteractive$' /tmp/rs.out \
        && ok "and pam_env carried [command] env across the sudo" \
        || bad "a [command] env value did not survive: $(grep '^DEBIAN_FRONTEND=' /tmp/rs.out || echo absent)"
    fi
    quiesce

    # A refusal is still a refusal, which is the half that matters.
    sudoRun /tmp/rs.deny.out /usr/bin/sudo /usr/bin/id
    ID=$(waitq)
    if [ -z "$ID" ]; then
      bad "no question was filed for the refusal check under sudo-rs"
    else
      /usr/local/bin/faramir deny "$ID" >/dev/null 2>&1
      wait $RUN 2>/dev/null
      grep -q 'uid=0' /tmp/rs.deny.out \
        && bad "a refused escalation reached root under sudo-rs" \
        || ok "and a no still refuses"
    fi
    quiesce

    # doctor asks the same questions of this arrangement.
    [ "$(grant_status)" = ok ] \
      && ok "doctor passes the sudo-rs arrangement" \
      || bad "doctor says sudo grant is $(grant_status): $(/usr/local/bin/faramir doctor --agent-user op 2>&1 | grep -A1 'sudo grant' | head -2)"

    # Switching back without re-running init is the drift doctor has to catch:
    # the grant then names settings this sudo does not read, and whatever selects
    # faramir's stack is the other implementation's.
    update-alternatives --set sudo "$HOME_SUDO" >/dev/null 2>&1
    [ "$(grant_status)" = failed ] \
      && ok "and switching the alternatives group back without re-running init fails doctor" \
      || bad "doctor says sudo grant is $(grant_status) on a host whose sudo no longer matches its grant"
  fi

  # Back to where this stack started, with a grant written for it, so the next
  # suite gets the install it expects.
  restore_sudo
  if [ "$OTHER_IS_RS" = yes ]; then
    # Home is the original: the service file comes back and the block goes.
    [ -e /etc/pam.d/faramir-sudo ] \
      && ok "and the original sudo gets its service file back" \
      || bad "no /etc/pam.d/faramir-sudo after re-installing for the original sudo"
    grep -q '^# BEGIN faramir' /etc/pam.d/sudo \
      && bad "the branch outlived a re-install made for the original sudo" \
      || ok "and re-running init takes the branch out again"
    diff -q /tmp/sudo.stack.before /etc/pam.d/sudo >/dev/null 2>&1 \
      && ok "leaving /etc/pam.d/sudo byte for byte what it was" \
      || bad "the stack did not come back: $(diff /tmp/sudo.stack.before /etc/pam.d/sudo | head -4)"
  else
    # Home is sudo-rs: the block comes back and the service file goes.
    grep -q '^# BEGIN faramir' /etc/pam.d/sudo \
      && ok "and sudo-rs gets its branch back" \
      || bad "no faramir block after re-installing for sudo-rs"
    [ -e /etc/pam.d/faramir-sudo ] \
      && bad "the service file outlived a re-install made for sudo-rs" \
      || ok "and the service file nothing would read is gone again"
  fi
  [ "$(grant_status)" = ok ] \
    && ok "and doctor passes the arrangement this stack came back to" \
    || bad "doctor says sudo grant is $(grant_status) after restoring"
fi
quiesce

# --------------------------------------------------------------------------
summary
