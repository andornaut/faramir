#!/bin/bash
# The --allow-sudo approval channel, the one path that hands out root.
#
# Not "does sudo work" but the claims the design makes about it: root is handed
# out one command at a time, only a human at a root shell hands it out, the
# token a child holds cannot spend itself, no second brokered command runs
# beside an approval, and a yes that lands while the host is not quiet is
# refused rather than taken.
#
# Self-provisioning: it installs the grant itself, so it can run on a container
# brought up without one.  Run as root in the container.
set -u
SECRET='hunter2-correct-horse-battery'
CFG=/etc/faramir/config.toml
LOG=/var/log/faramir/audit.log
. "$(dirname "$0")/lib.sh" || { echo "e2e: lib.sh is missing beside $0" >&2; exit 2; }

# The outstanding question's id, and a wait for one to appear.
q() { /usr/local/bin/faramir approvals --json 2>/dev/null | grep -oE '"id"[^,]*' | head -1 | cut -d'"' -f4; }
waitq() { local i; for _ in $(seq 100); do i=$(q); [ -n "$i" ] && { echo "$i"; return; }; sleep 0.1; done; echo ""; }
# quiesce leaves no question outstanding and no process of the executor's uid,
# which is the state every group below starts from: a leftover of either makes
# the next group measure the last one.
quiesce() {
  local id
  for id in $(/usr/local/bin/faramir approvals --json 2>/dev/null | grep -oE '"id"[^,]*' | cut -d'"' -f4); do
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
# ask sends one request to the broker as an account, and prints the answer.
ask() { runuser -u "$1" -- /usr/bin/python3 -c "
import socket,sys
s=socket.socket(socket.AF_UNIX); s.connect('/run/faramir/broker.sock')
s.sendall(sys.argv[1].encode()+b'\n')
print(s.recv(65536).decode()[:160])" "$2" 2>&1; }

# The notifier the grant is installed with.  A script rather than wall, which
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
# [sudo] section without one.
if ! grep -q '^notify_command' $CFG; then
  /usr/local/bin/faramir init --allow-sudo --agent-user op \
    --notify-command /usr/local/bin/e2e-notify --notify-command '{prompt}' \
    >/tmp/sudo-init.log 2>&1 \
    || { echo "could not install the grant"; tail -3 /tmp/sudo-init.log; exit 1; }
  systemctl restart faramir-keeper.socket faramir-exec.socket faramir-broker.socket >/dev/null 2>&1
  sleep 3
fi
rm -f "$NOTIFY"
echo "grant installed; [sudo] timeout_sec=$(sed -n 's/^timeout_sec *= *\([0-9]*\).*/\1/p' $CFG | head -1)"
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
grep -q 'approval denied' /tmp/dnwhy.out && ok "and the caller is told a human refused it" \
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
out=$(ask op '{"op":"approvals"}')
grep -q forbidden <<<"$out" && ok "and neither may even list what is waiting" \
  || bad "op listed the questions: ${out:0:110}"
out=$(runuser -u op -- /usr/local/bin/faramir approve "$ID" 2>&1)
grep -q 'must run as root' <<<"$out" && ok "faramir approve as the agent is refused by name" \
  || bad "faramir approve as op: ${out:0:110}"
# A brokered command cannot even reach the attempt: it is refused for the same
# serialisation that holds every other command while a question waits.
out=$(runuser -u op -- /usr/local/bin/faramir run --quiet -t 10 -- /bin/echo ran 2>&1)
grep -q approval_in_progress <<<"$out" && ok "and a brokered command cannot run at all to try" \
  || bad "a brokered command ran beside a question: ${out:0:110}"
[ "$(q)" = "$ID" ] && ok "the question survived every attempt" || bad "the question is gone after those attempts"
/usr/local/bin/faramir deny "$ID" >/dev/null 2>&1
wait $RUN 2>/dev/null
quiesce

# --------------------------------------------------------------------------
head_ "3. the token a child holds is an identifier, not a credential"

out=$(runuser -u op -- /usr/local/bin/faramir run --quiet -t 20 -- /bin/sh -c '
  printf "{\"op\":\"ask_approval\",\"token\":\"$FARAMIR_APPROVAL_TOKEN\"}\n" |
  timeout 5 /usr/bin/python3 -c "
import socket,sys
s=socket.socket(socket.AF_UNIX); s.connect(\"/run/faramir/broker.sock\")
s.sendall(sys.stdin.buffer.read()); print(s.recv(65536).decode()[:200])"' 2>&1)
grep -qi 'forbidden\|root' <<<"$out" && ok "a child spending its own token is refused" \
  || bad "a child spent its own token: ${out:0:140}"
quiesce

# --------------------------------------------------------------------------
head_ "4. a yes that lands while the host is not quiet is refused"
#
# The window a yes opens is the executor's uid, which every brokered command
# shares.  A process of that uid alive outside the run being approved could ride
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
# approval.  What the operator judges that by is the command, so the question has
# to carry the whole of it.

sudoRun /tmp/scope.out /bin/sh -c 'sudo /usr/bin/id -un; sudo /bin/cat /etc/shadow | head -1; sudo /usr/bin/whoami'
ID=$(waitq)
question=$(/usr/local/bin/faramir approvals 2>/dev/null)
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
  --env PW=secret://db/password -- /usr/bin/sudo /usr/bin/id -un >/tmp/val.out 2>&1 </dev/null &
RUN=$!
ID=$(waitq)
body=$(/usr/local/bin/faramir approvals --json 2>/dev/null)
# The listing answered, or the absence below is an op that failed rather than a
# question that holds no value.
grep -qF "$ID" <<<"$body" || bad "approvals --json did not name the waiting question"
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

before=$(sed -n 's/^timeout_sec *= *\([0-9]*\).*/\1/p' $CFG | head -1)
sed -i 's/^timeout_sec = .*/timeout_sec = 5/' $CFG
systemctl restart faramir-broker.socket faramir-broker.service >/dev/null 2>&1; sleep 3

start=$(date +%s)
runuser -u op -- /usr/local/bin/faramir run --quiet -t 40 -- /usr/bin/sudo /usr/bin/id -un >/tmp/to.out 2>&1
elapsed=$(( $(date +%s) - start ))
[ "$elapsed" -lt 25 ] && ok "an unanswered question ends in ${elapsed}s, near [sudo] timeout_sec=5" \
  || bad "it took ${elapsed}s to give up on an unanswered question"
grep -q 'uid=0\|^root$' /tmp/to.out && bad "*** an unanswered command became root ***" \
  || ok "and the command did not become root"
[ "$(q)" = "" ] && ok "and the question is not left outstanding" || bad "the question outlived its timeout"
# And the caller is told which of the two it was, the command having seen the
# same authentication failure either way.
runuser -u op -- /usr/local/bin/faramir run --quiet -t 40 -- /usr/bin/sudo /usr/bin/id -un >/tmp/towhy.out 2>&1
grep -q 'approval expired' /tmp/towhy.out && ok "and told under --quiet, which is how an agent runs one" \
  || bad "an expiry is not told from a refusal: $(tr '\n' ' ' </tmp/towhy.out | cut -c1-150)"
grep -q 'approval denied' /tmp/towhy.out && bad "an expiry was reported as a refusal" \
  || ok "and not as one somebody typed"
# The host is usable again straight after, the serialisation having ended with it.
out=$(runuser -u op -- /usr/local/bin/faramir run --quiet -t 10 -- /bin/echo after 2>&1)
[ "$(tail -1 <<<"$out")" = after ] && ok "and ordinary commands run again at once" \
  || bad "the host stayed held after the timeout: ${out:0:110}"
# Nobody watching and somebody saying no are different events, and the record
# says which without anyone parsing the sentence beside it.
[ "$(jq -r 'select(.op=="ask_approval") | .outcome_code' $LOG 2>/dev/null | tail -1)" = expired ] \
  && ok "the record calls it expired rather than refused" \
  || bad "an unanswered question is recorded as $(jq -r 'select(.op=="ask_approval") | .outcome_code' $LOG 2>/dev/null | tail -1)"
/usr/local/bin/faramir logs --color never -n 10 | grep -q 'timed out' \
  && ok "and the listing reads it as timed out" \
  || bad "the listing does not tell it from a refusal: $(/usr/local/bin/faramir logs --color never -n 3)"

sed -i "s/^timeout_sec = .*/timeout_sec = ${before:-120}/" $CFG
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
# that gave root away is told how it ended.  It comes back on the poll the
# question came in on, which is what `faramir approvals --watch` is sitting in:
# no second channel, and no read of the audit log.
#
# Only here, and not in the Go tests: filling the ending in is the exec path's,
# and reaching that path means a real sudo through PAM.

sudoRun /tmp/ended.out /usr/bin/sudo /bin/sh -c 'exit 3'
ID=$(waitq)
LOGID=$(/usr/local/bin/faramir approvals --json 2>/dev/null | grep -oE '"log_id"[^,]*' | head -1 | cut -d'"' -f4)
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
request={'op':'approvals'}
if sys.argv[1]: request['await_log_id']=sys.argv[1]
s.sendall(json.dumps(request).encode()+b'\n')
f=json.loads(s.recv(65536).decode()).get('finished')
print('none' if f is None else '%s %s' % (f.get('log_id'), f.get('exit_code')))" "$1"; }

# What of that duration was the question rather than the command.  The answer
# was slept on above, so the number has something to report.
#
# w+0 forces the comparison numeric: a missing field reads back as the string
# "null", and awk compares two strings lexically, where "null" >= "2" is true.
# The field going missing is what this exists to catch, so it must not pass.
waited=$(jq -r --arg id "$LOGID" 'select(.log_id==$id and .op=="exec") | .waited_sec' $LOG 2>/dev/null | tail -1)
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

[ "$(grep -c '"approved":true' $LOG)" -ge 1 ] && ok "an approval is recorded" || bad "no approval recorded"
[ "$(grep -c '"approved":false' $LOG)" -ge 1 ] && ok "a refusal is recorded" || bad "no refusal recorded"
# Both answers read as answers in the listing, not as blank rows.
/usr/local/bin/faramir logs --color never -n 80 | grep -q approved && ok "an approval reads as approved in faramir logs" \
  || bad "an approval renders with no outcome"
/usr/local/bin/faramir logs --color never -n 80 | grep -q refused && ok "and a refusal reads as refused" \
  || bad "a refusal renders with no outcome"
# Which no it was, for each of the three this suite produced.  A denial, an
# expiry and a yes read alike in prose and are acted on differently.
for want in approved denied expired; do
  [ "$(jq -r --arg c "$want" 'select(.op=="ask_approval" and .outcome_code==$c) | .outcome_code' $LOG 2>/dev/null | head -1)" = "$want" ] \
    && ok "a $want ending is recorded as one" || bad "no ask_approval record carries outcome_code=$want"
done
# The prose is kept beside it: it names the account that answered, which no code
# carries.
jq -r 'select(.op=="ask_approval" and .outcome_code=="denied") | .outcome' $LOG 2>/dev/null | grep -q 'refused by' \
  && ok "and the sentence beside it still names who answered" \
  || bad "the prose was dropped when the code arrived"

# The approval points at the command it authorised.
id=$(jq -r 'select(.op=="ask_approval" and .approved==true) | .exec_log_id' $LOG 2>/dev/null | tail -1)
[ -n "$id" ] && [ "$id" != null ] && ok "and names the command's own record ($id)" \
  || bad "an approval does not point at the run it authorised"

# --------------------------------------------------------------------------
head_ "12. the notifier"
#
# [sudo] notify_command is what says a question is waiting, and it is init's:
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
# question, and the keystrokes written in at the moment each case is about.  It
# reports what the terminal saw rather than deciding anything, so the assertions
# stay in the shell with the rest of them.
cat >/tmp/watch-answer.py <<'EOS'
import os, pty, select, subprocess, sys, time

MODE = sys.argv[1]

pid, fd = pty.fork()
if pid == 0:
    os.execv("/usr/local/bin/faramir", ["faramir", "approvals", "--watch"])
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
    print("PROMPTS", buf.count("approve? [yes/no]"))
    os.kill(pid, 9)
    sys.exit(0)


if not pump(lambda b: "waiting for approval requests" in b, 30):
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

if not pump(lambda b: "approve? [yes/no]" in b, 60):
    give_up("no prompt appeared")

if MODE == "after":
    # One burst, the blank lines and the answer behind them: separate writes
    # would pass even where each re-ask throws away what is queued behind it.
    os.write(fd, b"\n\n\n\nyes\n")
else:
    os.write(fd, b"yes\n")

# "refused: " with the colon, which is the watcher's own line.  Bare "refused"
# is in every question, the expires line saying what happens if nobody answers,
# so waiting on that returns before the answer has been read at all.
pump(lambda b: " started" in b or "refused: " in b, 60)
try:
    run.wait(timeout=60)
except subprocess.TimeoutExpired:
    run.kill()
os.kill(pid, 15)

print("PROMPTS", buf.count("approve? [yes/no]"))
print("REFUSED", "yes" if "refused: " in buf else "no")
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
# Five: the first prompt and one re-ask for each blank line.  Fewer means a
# blank line was counted as an answer; the yes surviving the burst is what says
# a re-ask does not discard what is queued behind it.
[ "$(field "$out" PROMPTS)" = 5 ] && ok "and each was asked again rather than counted" \
  || bad "$(field "$out" PROMPTS) prompts, want 5"
quiesce

# --------------------------------------------------------------------------
head_ "14. a question nobody answers, and the one raised after it"
#
# The prompt has a clock of its own, and it is the question's.  Without it the
# watcher sat inside the read until somebody typed, so the first question's
# clock ran out unnoticed and the second was not shown until a keystroke
# arrived: a watcher that has stopped watching while still saying it is.
cat >/tmp/watch-expire.py <<'EOS'
import os, pty, select, subprocess, sys, time

pid, fd = pty.fork()
if pid == 0:
    os.execv("/usr/local/bin/faramir", ["faramir", "approvals", "--watch"])
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


def give_up(why):
    print("FAILED", why)
    os.kill(pid, 9)
    sys.exit(0)


def raise_question(marker):
    return subprocess.Popen(
        ["runuser", "-u", "op", "--", "/usr/local/bin/faramir", "run", "--quiet",
         "-t", "60", "--", "/usr/bin/sudo", "/bin/echo", marker],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if not pump(lambda b: "waiting for approval requests" in b, 30):
    give_up("the watcher never started")

first = raise_question("first")
if not pump(lambda b: "approve? [yes/no]" in b, 60):
    give_up("no prompt for the first question")

# Nothing typed: the question's own clock is what has to end the wait.
if not pump(lambda b: "expired" in b, 60):
    give_up("the watcher never said the question expired")
try:
    first.wait(timeout=120)
except subprocess.TimeoutExpired:
    first.kill()
    give_up("the first command never returned")

# And the next one is shown without a keystroke having been sent.
second = raise_question("second")
shown = pump(lambda b: b.count("approve? [yes/no]") >= 2, 60)
os.write(fd, b"yes\n")
pump(lambda b: " started" in b, 60)
try:
    second.wait(timeout=60)
except subprocess.TimeoutExpired:
    second.kill()
os.kill(pid, 15)

print("EXPIRED", "yes" if "expired" in buf else "no")
print("SECOND_SHOWN", "yes" if shown else "no")
print("SECOND_ANSWERED", "yes" if " started" in buf else "no")
EOS

quiesce
# Long enough that the second question can be raised, shown, answered and
# started inside it, and short enough that the first expires while the driver
# waits.  Section 8's five seconds only has to reach an expiry, and this has to
# reach an answer after one.
before=$(sed -n 's/^timeout_sec *= *\([0-9]*\).*/\1/p' $CFG | head -1)
sed -i 's/^timeout_sec = .*/timeout_sec = 20/' $CFG
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

sed -i "s/^timeout_sec = .*/timeout_sec = ${before:-120}/" $CFG
systemctl restart faramir-broker.socket faramir-broker.service >/dev/null 2>&1; sleep 3
quiesce

# --------------------------------------------------------------------------
summary
