#!/bin/bash
# The SSH agent relay, against a real managed host.
#
# The promise: a brokered command authenticates to a managed host with a key it
# cannot read, and what it is handed is two agent operations rather than the
# agent protocol.  A stub cannot test that -- the interesting half is what a
# real sshd does with a real signature -- so the suite runs a second container
# with sshd and no passwords, reachable as managed-host, and the broker's key is
# the only way in.
#
# Run as root on the broker container, with managed-host on the same network.
set -u
SECRET='hunter2-correct-horse-battery'
KEY=/etc/faramir/id_ed25519
RELAY=/run/faramir/ssh-agent.sock
HOST=managed-host
LOG=/var/log/faramir/audit.log
. "$(dirname "$0")/lib.sh" || { echo "e2e: lib.sh is missing beside $0" >&2; exit 2; }

brokered() { runuser -u op -- /usr/local/bin/faramir run --quiet -t 25 -- "$@" 2>&1; }
# ssh with nothing interactive and nothing inherited from a user's config.
sshb() { brokered /usr/bin/ssh -o BatchMode=yes -o ConnectTimeout=8 "$@"; }

# --------------------------------------------------------------------------
head_ "1. a brokered command reaches the managed host"

out=$(sshb deploy@$HOST /usr/bin/id -un)
[ "$(tail -1 <<<"$out")" = deploy ] && ok "authenticated as deploy on the managed host" \
  || bad "the brokered ssh did not log in: ${out:0:140}"

# The whole point: the account that authenticated is not the account that holds
# the key, and neither is the one that asked.
# One string: ssh joins argv with spaces and the remote shell expands it, so
# separate words would leave $SSH_CONNECTION as the remote sh's $0.
out=$(sshb deploy@$HOST 'echo CONN=$SSH_CONNECTION')
grep -q 'CONN=[0-9]' <<<"$out" && ok "and the managed host sees a real connection" \
  || bad "no SSH_CONNECTION on the far side: ${out:0:100}"

# --------------------------------------------------------------------------
head_ "2. and it cannot read what it authenticated with"

runuser -u faramir-exec -- test -r $KEY 2>/dev/null \
  && bad "faramir-exec can read the private key it authenticates with" \
  || ok "faramir-exec cannot read $KEY"
out=$(brokered /bin/cat $KEY)
grep -q 'PRIVATE KEY' <<<"$out" && bad "a brokered command read the key" \
  || ok "and a brokered command reading it gets nothing"

# The agent's own socket is the whole protocol; the relay is the two operations.
runuser -u faramir-exec -- test -w "$RELAY.private" 2>/dev/null \
  && bad "faramir-exec can open $RELAY.private, which bypasses the relay" \
  || ok "faramir-exec cannot open $RELAY.private"
mode=$(stat -c '%a %U:%G' $RELAY)
[ "$mode" = "660 faramir-broker:faramir-exec" ] && ok "the relay is $mode" \
  || bad "the relay socket is $mode"
mode=$(stat -c '%a %U:%G' "$RELAY.private")
[ "$mode" = "600 faramir-broker:faramir-broker" ] && ok "and the agent's own socket is $mode" \
  || bad "the private socket is $mode"

# The agent's uid is not in the executor's group, so the relay is not its to use.
out=$(runuser -u op -- env SSH_AUTH_SOCK=$RELAY ssh-add -l 2>&1)
grep -qi 'permission denied' <<<"$out" && ok "the agent's own uid cannot open the relay" \
  || bad "op reached the relay: ${out:0:100}"

# --------------------------------------------------------------------------
head_ "3. two operations, and the rest refused"

out=$(brokered /usr/bin/ssh-add -l)
grep -q SHA256 <<<"$out" && ok "list identities is served: $(grep -o 'SHA256:[^ ]*' <<<"$out" | head -1 | cut -c1-26)..." \
  || bad "the agent listed nothing: ${out:0:120}"
# -L is the same request, rendered as public keys.  A public key is not a
# disclosure: it is in authorized_keys on every managed host already.
out=$(brokered /usr/bin/ssh-add -L)
grep -q '^ssh-ed25519 ' <<<"$(tail -1 <<<"$out")" && ok "and returns the public key, which is not a secret" \
  || bad "-L returned no public key: ${out:0:100}"
grep -q 'PRIVATE' <<<"$out" && bad "the private half came back" || ok "and never the private half"

# Everything below is a request the relay does not forward.  Each is checked for
# a refusal AND for the key surviving it: an agent a brokered command can empty
# or lock is one it can take away from every other command on the host.
refuses() { # label, then argv
  local label=$1; shift
  local out; out=$(brokered "$@")
  if grep -qiE 'fail|error|not |refus|denied' <<<"$out"; then
    ok "$label is refused: $(head -1 <<<"$out" | cut -c1-56)"
  else
    bad "$label was served: ${out:0:110}"
  fi
  if brokered /usr/bin/ssh-add -l | grep -q SHA256; then
    ok "  and the key is still there afterwards"
  else
    bad "  the agent lost its key to $label"
  fi
}
refuses "remove all identities" /usr/bin/ssh-add -D
refuses "remove one identity"   /usr/bin/ssh-add -d /etc/faramir/id_ed25519.pub
refuses "add an identity"       /usr/bin/ssh-add /etc/faramir/id_ed25519

# And the relay still serves the next command, a refusal not being a close.
out=$(sshb deploy@$HOST /usr/bin/id -un)
[ "$(tail -1 <<<"$out")" = deploy ] && ok "the relay still authenticates after three refusals" \
  || bad "the relay stopped working: ${out:0:110}"

# --------------------------------------------------------------------------
head_ "4. where that key can be used"
#
# The blast radius as documented: any host trusting the public key, for as long
# as the broker holds it.  What bounds it is which accounts trust it.

out=$(sshb nosuchuser@$HOST /usr/bin/id -un)
grep -qi 'permission denied\|denied' <<<"$out" && ok "an account that does not trust the key is refused" \
  || bad "logged in as an account that never trusted the key: ${out:0:110}"
# No user given asks for the executor's own name, which is nobody's account
# there.  Documented, and the first thing an agent gets wrong.
out=$(sshb $HOST /usr/bin/id -un)
grep -q 'faramir-exec@' <<<"$out" && ok "ssh with no user asks for faramir-exec, and is refused" \
  || bad "a userless ssh did something else: ${out:0:110}"

# --------------------------------------------------------------------------
head_ "5. the host has to be pinned before the key is offered"

# The same host under a name nothing pinned: the executor cannot be prompted to
# accept a key, so this fails before the broker's key is offered.
addr=$(getent hosts $HOST | awk '{print $1}')
out=$(sshb deploy@"$addr" /usr/bin/id -un)
grep -qi 'host key verification failed' <<<"$out" \
  && ok "an unpinned name for the same host is refused, not prompted" \
  || bad "an unpinned host: ${out:0:110}"
grep -qi 'are you sure you want to continue' <<<"$out" \
  && bad "it tried to prompt" || ok "and nothing waited for an answer"

# The operator's own known_hosts is not what the executor reads.  0700 and
# removed again afterwards: a ~/.ssh the executor can read is a finding of its
# own (doctor's "agent keys"), and a suite that leaves one behind hands the
# next suite a fault to report.
had_ssh_dir=$([ -d /home/op/.ssh ] && echo yes || echo no)
runuser -u op -- mkdir -p -m 0700 /home/op/.ssh
runuser -u op -- sh -c "ssh-keyscan -t ed25519 $addr 2>/dev/null > /home/op/.ssh/known_hosts"
out=$(sshb deploy@"$addr" /usr/bin/id -un)
grep -qi 'host key verification failed' <<<"$out" \
  && ok "and trusting it in the operator's ~/.ssh/known_hosts changes nothing" \
  || bad "the operator's known_hosts was consulted: ${out:0:110}"
rm -f /home/op/.ssh/known_hosts
[ "$had_ssh_dir" = no ] && rmdir /home/op/.ssh 2>/dev/null
# And the state this suite made is gone, or doctor reports it as the host's.
if [ -d /home/op/.ssh ] && runuser -u faramir-exec -- test -r /home/op/.ssh 2>/dev/null; then
  bad "this suite left /home/op/.ssh readable by the executor"
else
  ok "and the directory it needed to ask that is gone again"
fi

# --------------------------------------------------------------------------
head_ "6. a value injected here, printed there, comes back redacted"

out=$(runuser -u op -- /usr/local/bin/faramir run --quiet -t 25 --env DB=secret://db/password -- \
  /bin/sh -c "ssh -o BatchMode=yes -o ConnectTimeout=8 deploy@$HOST \"echo REMOTE=\$DB\"" 2>&1)
if grep -qF "$SECRET" <<<"$out"; then
  bad "the value came back from the managed host in plaintext: ${out:0:110}"
elif grep -q 'REMOTE=«SECRET:db/password»' <<<"$out"; then
  ok "the remote echoed it and it came back as its token"
else
  bad "inconclusive: ${out:0:150}"
fi
# It really did cross the wire, so what was redacted is the return path.
out=$(runuser -u op -- /usr/local/bin/faramir run --quiet -t 25 --env DB=secret://db/password -- \
  /bin/sh -c "ssh -o BatchMode=yes -o ConnectTimeout=8 deploy@$HOST \"printf %s \\\"\$DB\\\" | wc -c\"" 2>&1)
[ "$(tail -1 <<<"$out" | tr -d ' \r')" = "${#SECRET}" ] \
  && ok "and the managed host received all ${#SECRET} bytes of it, so the wire carried the value" \
  || bad "the remote did not receive the value: ${out:0:110}"

# --------------------------------------------------------------------------
head_ "7. several at once"
#
# Two descriptors per relayed connection, and a playbook authenticates to as many
# hosts at once as -f allows.

# As many as the broker will run at once: more than that is refused busy, which
# is the concurrency gate doing its job and says nothing about the relay.
n=$(sed -n 's/^max_concurrency *= *\([0-9]*\).*/\1/p' /etc/faramir/config.toml | head -1)
n=${n:-4}
tmp=$(mktemp -d)
for i in $(seq "$n"); do
  ( sshb deploy@$HOST /usr/bin/id -un > "$tmp/$i" 2>&1 ) &
done
wait
good=$(grep -l '^deploy$' "$tmp"/* 2>/dev/null | wc -l)
[ "$good" -eq "$n" ] && ok "$n concurrent brokered ssh connections all authenticated" \
  || bad "only $good of $n succeeded: $(head -2 "$tmp"/* 2>/dev/null | head -4 | tr '\n' ' ')"
rm -rf "$tmp"
brokered /usr/bin/ssh-add -l | grep -q SHA256 && ok "and the agent still holds its key" \
  || bad "the agent lost its key under concurrency"

# --------------------------------------------------------------------------
head_ "8. agent forwarding relocates the signing capability"
#
# Not a defect: -A is the command's own choice, and a brokered command can
# already sign anything.  Worth stating, because while that connection is open
# the managed host can sign with the broker's key too, which is a wider reach
# than "a brokered command can use it".

out=$(brokered /usr/bin/ssh -A -o BatchMode=yes -o ConnectTimeout=8 deploy@$HOST \
  'ssh-add -l 2>&1 | head -1')
if grep -q SHA256 <<<"$out"; then
  ok "with -A the managed host can use the key too, for the life of the connection"
else
  ok "with -A the managed host got no usable agent: $(head -1 <<<"$out" | cut -c1-60)"
fi
# What it must not get either way is the key itself.
grep -qi 'PRIVATE KEY' <<<"$out" && bad "the key crossed to the managed host" \
  || ok "and the key itself does not cross the wire"

# --------------------------------------------------------------------------
head_ "9. a prompt the command reads from its terminal"
#
# docs/operating.md: "Interactive prompts fail rather than hang. Stdin is
# /dev/null."  Stdin is, and a command reading stdin does end.  But the child is
# given the PTY as its controlling terminal, so /dev/tty is open, and every
# credential prompt worth the name reads /dev/tty precisely so a pipe cannot
# feed it: ssh-add, sudo, gpg, ssh's own passphrase prompt.

out=$(runuser -u op -- /usr/local/bin/faramir run --quiet -t 6 -- \
  /bin/sh -c 'head -1; echo STDIN-ENDED' 2>&1)
grep -q STDIN-ENDED <<<"$out" && ok "a command reading stdin gets EOF and ends" \
  || bad "even stdin blocked: ${out:0:110}"

start=$(date +%s)
out=$(runuser -u op -- /usr/local/bin/faramir run --quiet -t 6 -- \
  /bin/sh -c 'printf "passphrase: " > /dev/tty; head -1 /dev/tty' 2>&1)
elapsed=$(( $(date +%s) - start ))
if grep -qi 'timed out' <<<"$out"; then
  bad "a prompt on /dev/tty hung for the whole ${elapsed}s timeout instead of failing"
else
  ok "a prompt on /dev/tty ended in ${elapsed}s without waiting out the timeout"
fi

# The real case, and the reason it matters: ssh-add -x is an ordinary thing to
# try, and it holds a concurrency slot for the whole timeout.
start=$(date +%s)
out=$(runuser -u op -- /usr/local/bin/faramir run --quiet -t 6 -- /usr/bin/ssh-add -x 2>&1)
elapsed=$(( $(date +%s) - start ))
grep -qi 'timed out' <<<"$out" \
  && bad "ssh-add -x hung for ${elapsed}s rather than failing on a prompt it cannot answer" \
  || ok "ssh-add -x ended in ${elapsed}s"

# What that costs: [server] max_concurrency slots, held for [exec]
# default_timeout_sec, by commands nobody meant to run.
slots=$(sed -n 's/^max_concurrency *= *\([0-9]*\).*/\1/p' /etc/faramir/config.toml | head -1)
slots=${slots:-4}
for _ in $(seq "$slots"); do
  runuser -u op -- /usr/local/bin/faramir run --quiet -t 12 -- /usr/bin/ssh-add -x >/dev/null 2>&1 &
done
# A fixed wait rather than a waitfor, because what holds a slot is the executor
# on the broker's side and not a process of ssh-add's own: the only observable
# for "the slots are taken" is the busy refusal this is about to ask for.  Long
# enough that all of them have started, short enough that none of the 12s runs
# above has ended.
sleep 4
out=$(runuser -u op -- /usr/local/bin/faramir run --quiet -t 8 -- /bin/echo works 2>&1)
if grep -q 'busy' <<<"$out"; then
  bad "$slots accidental prompts refuse every other brokered command with 'busy'"
else
  ok "other commands still run while $slots prompts are outstanding"
fi
wait

# --------------------------------------------------------------------------
head_ "10. the audit log"

records=$(grep -c '"op":"exec"' $LOG)
[ "$records" -gt 0 ] && ok "$records exec record(s) written" || bad "nothing was recorded"
grep -qF "$SECRET" $LOG && bad "the audit log holds the plaintext value" \
  || ok "no plaintext value in the audit log"
grep -q "$HOST" $LOG && ok "the brokered ssh is recorded with its argv" \
  || bad "no record names the managed host"
# The key never passes through a record, argv or output.
grep -q 'PRIVATE KEY' $LOG && bad "the log holds key material" || ok "and no key material"
# A busy refusal is legible as a refusal rather than as a blank row.  Whether
# the run produced one at all is up to how the concurrency gate happened to fall,
# so say when it did not: an assertion that quietly does not run reads in the
# counts as one that was never written.
busy_id=$(jq -r 'select(.refused=="busy") | .log_id' $LOG 2>/dev/null | tail -1)
if [ -n "$busy_id" ]; then
  faramir logs --color never "$busy_id" | grep -q busy \
    && ok "a busy refusal reads as busy in faramir logs" \
    || bad "a busy refusal renders with no outcome: $(faramir logs --color never "$busy_id" | head -1)"
else
  note "nothing hit the concurrency gate this run, so how a busy refusal reads went untested"
fi

# --------------------------------------------------------------------------
summary
