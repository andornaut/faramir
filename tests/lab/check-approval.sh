#!/bin/bash
# The --allow-sudo approval channel, the one path that hands out root.
#
# Not "does sudo work" but the claims the design makes about it: root is handed
# out one command at a time, only a human at a root shell hands it out, the
# token a child holds cannot spend itself, no second brokered command runs
# beside an approval, and a yes that lands while the host is not quiet is
# refused rather than taken.
#
# Self-provisioning: it installs the grant itself, so it can run on a lab
# brought up without one.  Run as root in the container.
set -u
SECRET='hunter2-correct-horse-battery'
CFG=/etc/faramir/config.toml
LOG=/var/log/faramir/audit.log
. "$(dirname "$0")/lib.sh" || { echo "lab: lib.sh is missing beside $0" >&2; exit 2; }

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
cat >/usr/local/bin/lab-notify <<'EOS'
#!/bin/sh
printf '%s\n' "$*" >>/var/log/faramir/notify.log
EOS
chmod 0755 /usr/local/bin/lab-notify

# Re-installed when the grant is absent OR when it carries no notifier: the
# suites share one install, so this may run after another has already written a
# [sudo] section without one.
if ! grep -q '^notify_command' $CFG; then
  /usr/local/bin/faramir init --allow-sudo --agent-user op \
    --notify-command /usr/local/bin/lab-notify --notify-command '{prompt}' \
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
head_ "5. what one approval covers, and whether the prompt says so"
#
# One question per run, not per sudo: a playbook's twenty become'd tasks are one
# approval.  So the prompt has to say that is what a yes means.

sudoRun /tmp/scope.out /bin/sh -c 'sudo /usr/bin/id -un; sudo /bin/cat /etc/shadow | head -1; sudo /usr/bin/whoami'
ID=$(waitq)
prompt=$(/usr/local/bin/faramir approvals --json 2>/dev/null | grep -o '"prompt"[^,]*' | head -1)
grep -qi 'every sudo this command makes until it ends' <<<"$prompt" \
  && ok "the prompt says a yes covers every sudo the command makes" \
  || bad "the prompt does not say what a yes covers: ${prompt:0:150}"
grep -q 'cat /etc/shadow' <<<"$prompt" && ok "and shows the whole argv, second sudo included" \
  || bad "the prompt hides part of the command: ${prompt:0:150}"
/usr/local/bin/faramir approve "$ID" >/dev/null 2>&1
wait $RUN 2>/dev/null
covered=$(grep -c '^root' /tmp/scope.out)
[ "$covered" -ge 2 ] && ok "one yes covered all $covered sudos in that run, as the prompt said" \
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
# The host is usable again straight after, the serialisation having ended with it.
out=$(runuser -u op -- /usr/local/bin/faramir run --quiet -t 10 -- /bin/echo after 2>&1)
[ "$(tail -1 <<<"$out")" = after ] && ok "and ordinary commands run again at once" \
  || bad "the host stayed held after the timeout: ${out:0:110}"

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
head_ "10. the record"

[ "$(grep -c '"approved":true' $LOG)" -ge 1 ] && ok "an approval is recorded" || bad "no approval recorded"
[ "$(grep -c '"approved":false' $LOG)" -ge 1 ] && ok "a refusal is recorded" || bad "no refusal recorded"
# Both answers read as answers in the listing, not as blank rows.
/usr/local/bin/faramir logs --color never -n 80 | grep -q approved && ok "an approval reads as approved in faramir logs" \
  || bad "an approval renders with no outcome"
/usr/local/bin/faramir logs --color never -n 80 | grep -q refused && ok "and a refusal reads as refused" \
  || bad "a refusal renders with no outcome"
# The approval points at the command it authorised.
id=$(jq -r 'select(.op=="ask_approval" and .approved==true) | .exec_log_id' $LOG 2>/dev/null | tail -1)
[ -n "$id" ] && [ "$id" != null ] && ok "and names the command's own record ($id)" \
  || bad "an approval does not point at the run it authorised"

# --------------------------------------------------------------------------
head_ "11. the notifier"
#
# [sudo] notify_command is what says a question is waiting, and it is init's:
# a drop-in setting it is refused, so `faramir init --notify-command` is the
# only way onto a host, and this is the check that the flag reaches the broker
# rather than only the file.

grep -q '^notify_command = \["/usr/local/bin/lab-notify", "{prompt}"\]' $CFG \
  && ok "init wrote the notifier the flag named" \
  || bad "the config does not carry it: $(grep '^notify_command' $CFG || echo none)"
[ -s "$NOTIFY" ] && ok "the broker ran it, $(wc -l <"$NOTIFY") announcement(s)" \
  || bad "nothing was announced, though questions were raised"
grep -q 'approve every sudo' "$NOTIFY" && ok "and handed it the prompt, expanded" \
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
summary
