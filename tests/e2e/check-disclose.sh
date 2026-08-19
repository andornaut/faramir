#!/bin/bash
# What the broker tells the account it exists to keep values from.
#
# Every other suite asks whether a value escapes. This one asks what the agent
# is told when nothing escapes: the names, the counts, the paths, the errors and
# the refusals. Those are the answers an agent gets to keep, and each is a
# choice about what a compromised one learns.
#
# The sharpest of them is the list of refs the redactor refused. Those are
# exactly the values that would arrive in plaintext if they ever reached output,
# so the protocol keeps that list behind `broker --check` and out of every
# agent-facing answer. Whether it stays there is the centre of this suite.
#
# Run as root in the e2e container; every probe runs as op.
set -u
SECRET='hunter2-correct-horse-battery'
TOKEN_API='tok_live_0PENSESAME_9911'
PROJECT=/home/op/project
. "$(dirname "$0")/lib.sh" || { echo "e2e: lib.sh is missing beside $0" >&2; exit 2; }

asop() { runuser -u op -- /usr/local/bin/faramir "$@" 2>&1; }
# mcp sends one tools/call and prints the result line.
mcp() { # tool, arguments-json
  printf '%s\n%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}' \
    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}" \
  | (cd $PROJECT && timeout 25 runuser -u op -- /usr/local/bin/faramir mcp 2>/dev/null) | tail -1
}
# carries fails when a haystack holds any value or key material.
carries() { # label, text
  local label=$1 text=$2
  if grep -qF "$SECRET" <<<"$text"; then bad "$label carries a managed value"; return; fi
  if grep -qF "$TOKEN_API" <<<"$text"; then bad "$label carries another managed value"; return; fi
  if grep -qE 'AGE-SECRET-KEY|BEGIN OPENSSH PRIVATE KEY|PRIVATE KEY' <<<"$text"; then
    bad "$label carries key material"; return
  fi
  ok "$label carries no value and no key material"
}

echo "probing as op; $(asop refs | wc -l) ref(s) served"

# --------------------------------------------------------------------------
head_ "1. what the agent is told"

refs=$(asop refs)
grep -q '^faramir://' <<<"$refs" && ok "refs answers with refs" || bad "no refs: ${refs:0:80}"
carries "refs" "$refs"
[ "$(grep -cv '^faramir://' <<<"$refs")" -eq 0 ] \
  && ok "and with nothing else on any line" || bad "a line is not a ref: $(grep -v '^faramir://' <<<"$refs" | head -1)"

st=$(asop status)
jq -e . <<<"$st" >/dev/null 2>&1 && ok "status answers with JSON" || bad "status is not JSON: ${st:0:80}"
carries "status" "$st"
for key in version secrets ssh sudo; do
  jq -e --arg k "$key" 'has($k)' <<<"$st" >/dev/null && ok "  status reports $key" || bad "  status omits $key"
done

# --------------------------------------------------------------------------
head_ "2. what it is not told"
#
# The refs the redactor refused name exactly the values that are never
# tokenised, so an agent that learned the list would learn which values it could
# print without them being caught.

refused=$(/usr/local/bin/faramir broker --check 2>/dev/null | jq -r '.secrets.not_redactable | keys[]' 2>/dev/null)
if [ -z "$refused" ]; then
  bad "this host has no refused ref, so the withholding cannot be tested"
else
  ok "the operator's own view names $(wc -w <<<"$refused") refused ref(s)"
  for ref in $refused; do
    grep -q "$ref" <<<"$st"   && bad "status names the refused ref $ref"   || ok "status does not name $ref"
    grep -q "$ref" <<<"$refs" && bad "refs names the refused ref $ref" || ok "refs does not name $ref"
  done
fi

# And the agent cannot simply run the operator's view itself: it may execute the
# binary, but the keeper socket is closed to it, so it decrypts nothing.
own=$(asop broker --check)
if jq -e '.secrets.not_redactable | length > 0' <<<"$(sed -n '/^{/,$p' <<<"$own")" >/dev/null 2>&1; then
  bad "the agent ran broker --check and got the refused list"
else
  ok "the agent may run broker --check and learns no value set from it"
fi
grep -q 'permission denied' <<<"$own" && ok "  because the keeper socket is closed to it" \
  || bad "  for some other reason: $(head -1 <<<"$own" | cut -c1-90)"
carries "the agent's own broker --check" "$own"

# --------------------------------------------------------------------------
head_ "3. asking for a refused ref"
#
# The list is withheld, and a request for one ref answers for that ref. The
# message is written for whoever reads the agent's transcript, and says what to
# fix; it also confirms the ref exists and is not redactable.

for ref in $refused; do
  out=$(asop run --quiet -t 15 -C $PROJECT --env P="faramir://$ref" -- /bin/sh -c 'echo $P')
  grep -q 'unknown_secret' <<<"$out" && ok "a refused ref is not injectable ($ref)" \
    || bad "a refused ref was injected: ${out:0:90}"
  carries "the refusal for $ref" "$out"
  # What it discloses: that this ref exists and why it was refused.
  if grep -qi 'refused at load\|cannot be redacted' <<<"$out"; then
    ok "  and the refusal says why, which also confirms the ref exists"
  else
    ok "  and the refusal is indistinguishable from a ref that does not exist"
  fi
done
# A ref nobody has: the two answers are worth comparing, one being an oracle.
nothing=$(asop run --quiet -t 15 -C $PROJECT --env P=faramir://no/such/ref -- /bin/true)
grep -q 'unknown_secret' <<<"$nothing" && ok "and a ref that does not exist is also unknown_secret" \
  || bad "an absent ref answered differently: ${nothing:0:90}"

# --------------------------------------------------------------------------
head_ "4. every refusal the agent can provoke"

probe() { # label, then argv for faramir run
  local label=$1; shift
  local out; out=$(asop run --quiet -t 15 "$@")
  carries "the $label refusal" "$out"
}
probe "unknown ref"     -C $PROJECT --env X=faramir://no/such -- /bin/true
probe "no such program" -C $PROJECT -- /bin/nosuchprogram
probe "cwd is a file"   -C /etc/hostname -- /bin/true
probe "timeout"         -C $PROJECT -t 1 -- /bin/sleep 5
# A value inside the caller's own cwd, which the refusal echoes back.
d=$(runuser -u op -- mktemp -d); runuser -u op -- mkdir -p "$d/$SECRET"
out=$(asop run --quiet -t 15 -C "$d/$SECRET/missing" -- /bin/true)
carries "a refusal naming a cwd that holds a value" "$out"
grep -q '«SECRET:' <<<"$out" && ok "  and the value in it came back as a token" \
  || bad "  the value was neither redacted nor present: ${out:0:90}"
rm -rf "$d"

# --------------------------------------------------------------------------
head_ "5. the same answers through MCP"

out=$(mcp faramir_refs '{}')
grep -q 'faramir://' <<<"$out" && ok "faramir_refs answers with refs" || bad "no refs: ${out:0:110}"
carries "faramir_refs" "$out"
for ref in $refused; do
  grep -q "$ref" <<<"$out" && bad "faramir_refs names the refused ref $ref" \
    || ok "and does not name $ref"
done

# There is no status tool: what it answered was which config files loaded, in
# what order, and what failed to load, and no agent acts on any of it. Dropping
# it narrowed what an agent is told, so being refused it is the assertion.
out=$(mcp faramir_status '{}')
grep -qi 'unknown tool' <<<"$out" && ok "no status tool is offered to the agent" \
  || bad "faramir_status answered: ${out:0:110}"
carries "the refusal of faramir_status" "$out"
tools=$(printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | (cd $PROJECT && timeout 25 runuser -u op -- /usr/local/bin/faramir mcp 2>/dev/null) | tail -1)
grep -q 'faramir_run' <<<"$tools" || bad "tools/list answered nothing, so the check below has no subject"
grep -q 'faramir_status' <<<"$tools" && bad "faramir_status is still listed" \
  || ok "and it is not in the tool list either"

# An MCP error is agent-visible text like any other.
out=$(mcp faramir_run '{"cmd":["/bin/nosuchprogram"],"cwd":"'$PROJECT'"}')
carries "an MCP run error" "$out"
out=$(mcp faramir_run '{"cmd":["/bin/sh","-c","echo $P"],"cwd":"'$PROJECT'","env_refs":{"P":"faramir://db/password"}}')
carries "an MCP run that printed a value" "$out"
grep -q '«SECRET:db/password»' <<<"$out" && ok "which came back as its token" \
  || bad "no token in the MCP result: ${out:0:130}"

# --------------------------------------------------------------------------
head_ "6. the id the agent is given is one it cannot read"

out=$(asop run --quiet -t 15 -C $PROJECT --env X=faramir://no/such -- /bin/true)
id=$(sed -n 's/.*log_id=\([^ ]*\).*/\1/p' <<<"$out" | head -1)
[ -n "$id" ] && ok "a refusal cites a log_id ($id)" || bad "no log_id cited"
out=$(asop logs "$id")
grep -qi 'must run as root' <<<"$out" && ok "and the agent cannot read the record it names" \
  || bad "the agent read the audit log: ${out:0:90}"
runuser -u op -- head -c1 /var/log/faramir/audit.log >/dev/null 2>&1 \
  && bad "nor the file directly" || ok "nor the file directly"

# --------------------------------------------------------------------------
head_ "7. a wrong invocation stays off stdout"
#
# Only the real binary can answer this: cobra sends usage to stderr while
# nothing has set its out writer, so an in-process test that captures stdout by
# setting one pulls the usage block into its own capture and cannot tell a
# correct routing from a wrong one. What rests on it is every caller that pipes
# stdout into a parser: `--json`, and `faramir logs`.

out=$(runuser -u op -- /usr/local/bin/faramir run --not-a-flag 2>/dev/null)
code=$?
[ $code -eq 2 ] && ok "a bad flag is a usage error, exit 2" || bad "a bad flag: exit $code"
[ -z "$out" ] && ok "and wrote nothing to stdout, so a parser reading it stays clean" \
  || bad "a usage error reached stdout: ${out:0:120}"
err=$(runuser -u op -- /usr/local/bin/faramir run --not-a-flag 2>&1 >/dev/null)
grep -q 'not-a-flag' <<<"$err" && ok "and named the flag on stderr" \
  || bad "stderr does not name the flag: ${err:0:120}"

# --------------------------------------------------------------------------
head_ "8. an error from below reaches the agent as text"
#
# A managed file that will not load puts sops's own words into an error the
# broker reports. That text is written by a program reading ciphertext, so it
# is the one place arbitrary bytes from the store could travel outward.

printf 'not a sops file at all\n' > /etc/faramir/secrets/broken.sops.yml
chown root:faramir-keeper /etc/faramir/secrets/broken.sops.yml
chmod 0640 /etc/faramir/secrets/broken.sops.yml
# The store is re-read at most every refresh_sec, so the failure reaches status
# on a later pass rather than this one. The wait has to clear that interval
# with margin: a shorter one gives up while the broker is still serving the
# value set it loaded before the file appeared, and then every suite after this
# one runs against a broker refusing `no_secrets`.
reportsLoadError() { jq -e '.secrets.errors[]?' <<<"$(asop status)" >/dev/null 2>&1; }
waitfor 40 reportsLoadError
st=$(asop status)
carries "status with a file that will not load" "$st"
errs=$(jq -r '.secrets.errors[]?' <<<"$st" 2>/dev/null)
# Whether the broker passes the loader's own words through to the agent is not
# this suite's claim to make; that they carry no value is. Recorded either way,
# so that a change in what the agent is told is visible here.
if [ -n "$errs" ]; then
  note "status reports the load failure to the agent"
  carries "the load error text" "$errs"
  grep -q 'broken.sops.yml' <<<"$errs" && note "  and names the file that failed" \
    || note "  without naming the file"
else
  note "status reports no error text to the agent"
fi
# And a brokered command is refused rather than run against a partial value set.
out=$(asop run --quiet -t 15 -C $PROJECT -- /bin/echo hi)
grep -q 'no_secrets' <<<"$out" && ok "and a brokered command is refused while a file went unread" \
  || bad "a command ran against a partial value set: ${out:0:90}"
carries "that refusal" "$out"
rm -f /etc/faramir/secrets/broken.sops.yml
# Waiting on the error going away rather than on refs answering: that
# answers while the store still holds the failure, and every suite after this
# one runs against a broker that refuses to inject.
recovered() { [ "$(jq -r '.secrets.errors | length' <<<"$(asop status)" 2>/dev/null)" = 0 ]; }
waitfor 40 recovered && ok "the host recovers when the file is removed" \
  || bad "the host still reports the file 20s after it went away"

# --------------------------------------------------------------------------
summary
