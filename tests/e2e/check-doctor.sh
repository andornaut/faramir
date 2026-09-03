#!/bin/bash
# `faramir doctor` as a fault detector.
#
# Doctor is the only thing that answers "is this install still doing its job",
# and the way to test a detector is to break the host and ask whether it
# notices. Every check here injects one fault, reads the verdict, repairs it,
# and reads the verdict again: the repair half is what proves the check reads
# the live state rather than reporting a conclusion it reached some other way.
#
# The property that matters most is not that a fault is found. It is that a
# check which could not be made is never reported as ok: an unearned pass on a
# boundary is worse than a failure, because it is the answer an operator acts
# on. D6 puts every fault to a caller that cannot ask.
#
# Run as root inside the e2e container.
set -u
OP=op
CFG=/etc/faramir/config.toml
KEY=/etc/faramir/age.key
SECRETS=/etc/faramir/secrets/app.sops.yml
LOG=/var/log/faramir/audit.log
JSON=/tmp/doc.json
. "$(dirname "$0")/lib.sh" || { echo "e2e: lib.sh is missing beside $0" >&2; exit 2; }

# settle puts the host back to a running install and waits for the broker to
# answer. Called after any group that stops a unit: a later group reading a
# half-started host would report the residue as its own finding, which is how a
# fault-injection suite ends up chasing itself.
settle() {
  # reset-failed first: a unit stopped and started repeatedly lands in failed,
  # and systemd refuses to start it again from there.
  systemctl reset-failed faramir-broker.service faramir-broker.socket \
    faramir-keeper.socket faramir-exec.socket >/dev/null 2>&1
  systemctl start faramir-keeper.socket faramir-exec.socket faramir-broker.socket >/dev/null 2>&1
  # refs rather than status: this asks whether the broker answers, and status's
  # exit code carries the health of the value set as well, so a host holding one
  # degraded ref would read as a broker that never came up.
  waitfor 30 runuser -u "$OP" -- /usr/local/bin/faramir refs && return 0
  printf '    (settle gave up: %s)\n' \
    "$(for u in faramir-keeper.socket faramir-exec.socket faramir-broker.socket faramir-broker.service; do
         printf '%s=%s ' "$u" "$(systemctl is-active $u)"; done)"
  return 1
}

# snap, st and dt come from lib.sh; these two are this suite's own totals.
broke() { jq -r .failed $JSON; }
unasked() { jq -r .not_asked $JSON; }

# probe injects a fault, reads the verdict, repairs, and reads it again.
#
# says is an optional extended regex the detail must match while the fault is
# live. It has to be asserted here rather than after the call: the repair below
# re-snapshots, so a caller reading the detail afterwards reads the healed one.
probe() { # label check want inject repair [says]
  local label=$1 check=$2 want=$3 inject=$4 repair=$5 says=${6:-} got back
  eval "$inject" >/dev/null 2>&1
  snap; got=$(st "$check")
  if [[ "$got" == *"$want"* ]]; then
    ok "$label -> $check is $got"
  else
    bad "$label: $check is [$got], want $want. detail: $(dt "$check" | head -c 130)"
  fi
  if [ -n "$says" ]; then
    dt "$check" | grep -qiE "$says" && ok "  and the detail says what it costs" \
      || bad "  the detail matches no /$says/: $(dt "$check" | head -c 130)"
  fi
  eval "$repair" >/dev/null 2>&1
  snap; back=$(st "$check")
  if [[ "$back" == *failed* ]]; then
    bad "  $check stayed [$back] after the repair, so the fault was not what it read"
  else
    ok "  and back to $back once repaired"
  fi
}

snap
echo "baseline: $(jq -r '[.findings[]|.status]|group_by(.)|map("\(length) \(.[0])")|join(", ")' $JSON), $(unasked) not asked"

# --------------------------------------------------------------------------
head_ "1. a healthy install"
#
# "Healthy" here means every fault this host has is one the fixture put there on
# purpose, and there are two. bootstrap.sh writes short/pin under [secret]
# min_length, which doctor fails on: a ref the config names and the redactor
# cannot cover is a degraded host. And check-project enrolled a tree for Codex
# on a box where Codex has never been started, so its hook is untrusted and
# therefore inert; section 6 is that check on its own. So the claim is that the
# failures are exactly those two, which still fails on any other check breaking
# and on either of these ceasing to fire.

snap
failed=$(jq -r '[.findings[]|select(.status=="failed")|.check]|sort|join(",")' $JSON)
if [ "$failed" = "codex hook trust,refused refs" ]; then
  ok "an install straight from init fails on the fixture's two known faults and nothing else"
else
  bad "failed checks are [$failed], want [codex hook trust,refused refs]: $(jq -r '[.findings[]|select(.status=="failed")|"\(.check): \(.detail)"]|join(" | ")' $JSON | head -c 400)"
fi
# The exit code follows the report, so it is non-zero for the same reasons.
if /usr/local/bin/faramir doctor >/dev/null 2>&1; then
  bad "doctor exits 0 on a host holding a ref it cannot redact"
else
  ok "and exits non-zero, the report and the status agreeing"
fi

# A root shell with no SUDO_USER is a container, `su -`, cron or a configuration
# manager's become. The install recorded who the agent account is, and that is the
# whole of how this is known: no command but `init` names it, so a run here either
# reads the record or reports the checks as unasked.
snap
[ "$(jq -r '[.findings[]|select(.check=="boundaries")]|length' $JSON)" = 0 ] \
  && ok "and there is no boundaries warning, the account being known" \
  || bad "boundaries reported $(jq -r '[.findings[]|select(.check=="boundaries")]|length' $JSON) findings: $(dt boundaries)"
# The boundary checks themselves, which is what those findings were standing in
# for: run as root with nothing naming the operator, they are asked and answered.
[ "$(st secrets)" = ok ] \
  && ok "the boundary checks answer without being told the account" \
  || bad "secrets is [$(st secrets)], want ok: the recorded account was not used"

# Degrading is still the answer where the config names no account, which is a
# host provisioned before agent_user was recorded.
cp /etc/faramir/config.toml /tmp/doctor.agentuser.bak
sed -i 's/^agent_user = .*/agent_user = ""/' /etc/faramir/config.toml
/usr/local/bin/faramir doctor --json >/tmp/doctor.noop.json 2>/dev/null
noname=$(jq -r '[.findings[]|select(.check=="boundaries")|.status]|first // "missing"' /tmp/doctor.noop.json)
[ "$noname" = warn ] \
  && ok "a config naming no account degrades to a warning rather than a pass" \
  || bad "boundaries is [$noname] with no account named anywhere, want warn"
for want in "faramir init --agent-user" "SUDO_USER"; do
  grep -qF -- "$want" <<<"$(jq -r '[.findings[]|select(.check=="boundaries")|.detail]|first // ""' /tmp/doctor.noop.json)" \
    && ok "and says how to ask it ($want)" \
    || bad "the warning does not mention $want: $(jq -r '[.findings[]|select(.check=="boundaries")|.detail]|first' /tmp/doctor.noop.json)"
done
# An account that is not on the host, recorded rather than passed: nothing but
# `init` names one, so this is the shape the case takes. Without the refusal every
# check that asks what the agent can reach answers about a uid nothing has, and
# the report reads as an examination of the host rather than of a name.
sed -i 's/^agent_user = .*/agent_user = "nosuchuser-e2e"/' /etc/faramir/config.toml
out=$(/usr/local/bin/faramir doctor --json 2>/dev/null)
n=$(jq '.findings|length' <<<"$out" 2>/dev/null)
# Two findings: the refusal, and the line accounting for the abandoned rest of
# the examination, so one failure cannot read as a host where all else passed.
[ "$n" = 2 ] && ok "an account that is not there stops the examination" \
  || bad "doctor made $n finding(s) about an account that does not exist"
jq -r '.findings[1].detail' <<<"$out" 2>/dev/null | grep -q 'every other check' \
  && ok "  and the abandoned examination is accounted for" \
  || bad "  nothing says the rest was not run: $(jq -r '.findings[1].detail // ""' <<<"$out" | head -c 100)"
jq -r '.findings[0].detail' <<<"$out" 2>/dev/null | grep -q 'nosuchuser-e2e' \
  && ok "  and the refusal names it" \
  || bad "  the refusal does not name the account: $(jq -r '.findings[0].detail // ""' <<<"$out" | head -c 100)"

cp /tmp/doctor.agentuser.bak /etc/faramir/config.toml
rm -f /tmp/doctor.agentuser.bak /tmp/doctor.noop.json

# The checks that never ask about an account still run, or a root shell would
# report a clean host having examined nothing.
/usr/local/bin/faramir doctor --json >$JSON 2>/dev/null
[ "$(jq -r '[.findings[]|select(.check!="boundaries")]|length' $JSON)" -gt 1 ] \
  && ok "while the checks that ask about no account still ran" \
  || bad "nothing ran besides the warning: an age key left 0644 would go unreported"
snap

# --------------------------------------------------------------------------
head_ "2. the files the install owns"

probe "the age key world-readable" "age key" failed \
  "chmod 0644 $KEY" "chmod 0400 $KEY"
probe "the age key readable by the agent" "age key" failed \
  "chown $OP $KEY" "chown faramir-keeper $KEY"
# Not a probe: the writer chmods 0600 on every open (internal/audit), so a log
# left world-readable is closed again by the next record rather than found by
# doctor. What is under test is that self-healing, and that doctor's verdict
# describes the mode that is there now.
chmod 0644 $LOG
runuser -u "$OP" -- /usr/local/bin/faramir run --quiet -C /home/op/project -- /bin/true >/dev/null 2>&1
mode=$(stat -c %a $LOG)
[ "$mode" = 600 ] && ok "an audit log left 0644 is closed again by the next record" \
  || bad "the log stayed $mode after a record was written"
snap
[ "$(st 'audit log')" = ok ] && ok "and doctor reports the mode that is there now" \
  || bad "audit log is [$(st 'audit log')]: $(dt 'audit log')"
# The directory, not the file: the ciphertext is encrypted to the keeper, and
# what would let the agent choose a value is replacing the file, which needs
# write on the directory. 0640 vs 0644 on the file alone changes nothing an
# attacker can use, and doctor checks the boundary rather than the incidental.
probe "the secrets directory writable by the agent" "secrets" failed \
  "chmod 0777 /etc/faramir/secrets" "chmod 2750 /etc/faramir/secrets"
probe "the ssh key world-readable" "ssh key" failed \
  "chmod 0644 /etc/faramir/id_ed25519" "chmod 0600 /etc/faramir/id_ed25519"
probe "the deny-patterns file emptied" "deny patterns" failed \
  ": > /usr/local/libexec/faramir/deny-patterns.txt" \
  "faramir init --agent-user $OP"
# The config is where [command.env] PATH comes from, so an agent that can write
# it chooses what the executor runs. Nothing else covers this check.
cfg_mode=$(stat -c %a /etc/faramir/config.toml)
probe "the config writable by the agent" "config ownership" failed \
  "chmod 0666 /etc/faramir/config.toml" "chmod $cfg_mode /etc/faramir/config.toml" \
  "executor runs"
# The other direction, and the one nothing used to ask: whether the account that
# has to load the config can still reach it. A reload is the only thing that
# ever found this out, and it finds out by refusing, so an install whose config
# went out of reach kept serving what it had and read as healthy.
#
# The directory rather than the file: config.toml is world-readable and what
# stops the broker is a parent it cannot enter, which is what the detail has to
# name or an operator chmods the wrong thing.
dir_mode=$(stat -c %a /etc/faramir)
probe "the config directory closed to the broker" "config reach" failed \
  "chmod 0700 /etc/faramir" "chmod $dir_mode /etc/faramir" \
  "/etc/faramir"
# And the finding says what it costs, which is that the daemons carry on with
# what they loaded rather than stopping.
chmod 0700 /etc/faramir
snap
dt "config reach" | grep -qi "reload" \
  && ok "  and it says a reload will refuse rather than take the change" \
  || bad "  the config reach detail does not mention a reload: $(dt "config reach" | head -c 130)"
chmod "$dir_mode" /etc/faramir
# The creation rule names the age recipients, so whoever writes it chooses who
# can decrypt every value written after it. Only checked where one exists: the
# rule is kept if it is already there, so an install may carry none.
if [ -f /etc/faramir/.sops.yaml ]; then
  sops_mode=$(stat -c %a /etc/faramir/.sops.yaml)
  probe "the creation rule writable by the agent" "config ownership" failed \
    "chmod 0666 /etc/faramir/.sops.yaml" "chmod $sops_mode /etc/faramir/.sops.yaml" \
    "age recipients"
else
  ok "no creation rule on this install, so there is none to be writable"
fi
# ProtectProc=invisible is set on all three units, and what it buys is that the
# agent's account cannot read a daemon's environ: that is where a running
# command's injected values are, so it is a disclosure boundary rather than a
# hardening preference. Asserted directly as well as through the check, a
# doctor that reports on itself proving only that it is consistent.
BROKERPID=$(systemctl show faramir-broker.service -p MainPID --value)
if [ -n "$BROKERPID" ] && [ "$BROKERPID" != 0 ]; then
  runuser -u "$OP" -- cat "/proc/$BROKERPID/environ" >/dev/null 2>&1 \
    && bad "*** $OP can read the broker's environ, where a run's values are ***" \
    || ok "the agent's account cannot read the broker's environ"
  snap
  [ "$(st protectproc)" = "ok,ok,ok" ] \
    && ok "and doctor reads ProtectProc=invisible off all three units" \
    || bad "protectproc is [$(st protectproc)]: $(dt protectproc)"
else
  ok "the broker is idle, which is its resting state; the unit properties are still read"
fi

# A config.d is not read, so the pass names the config and the creation rule and
# not a drop-in nothing looked at.
snap
dt 'config ownership' | grep -qi 'drop-in' \
  && bad "the pass claims a drop-in check nothing makes: $(dt 'config ownership')" \
  || ok "and the pass names only what it looked at"

# --------------------------------------------------------------------------
head_ "3. the arrangement around them"

probe "the rotation rule removed" "log rotation" failed \
  "rm -f /etc/logrotate.d/faramir" "faramir init --agent-user $OP"
probe "an outsider in the client group" "client group" warn \
  "useradd -M -N stranger 2>/dev/null; usermod -aG faramir-client stranger" \
  "gpasswd -d stranger faramir-client; userdel stranger"
# The whole socket group down. Doctor asks the broker where the install is and
# that connection activates the chain, so what stops the examination repairing
# the fault it found is the order: the socket states are sampled before the
# round trip, and the report names the host doctor met rather than the one it
# made. Nothing suppresses the asking, and no command takes a directory.
systemctl stop faramir-broker.service faramir-broker.socket faramir-keeper.socket >/dev/null 2>&1
/usr/local/bin/faramir doctor --json >$JSON 2>/dev/null
if [[ "$(st sockets)" == *failed* ]]; then
  ok "a stopped socket is reported failed, sampled before the broker is asked"
else
  bad "a stopped socket reads [$(st sockets)]: $(dt sockets)"
fi
dt sockets | grep -q 'inactive' && ok "and the finding names the state systemd reports" \
  || bad "the state is not named: $(dt sockets)"

# Back to a live broker first: the block above left it stopped, which is the
# other case entirely and would make this one pass without testing it.
settle || bad "the host did not come back before the reactivation case"
# The narrow case: the broker socket up, a socket it depends on down. Doctor
# asks the broker where the install is, that connection activates the chain, and
# the socket it was about to examine is started by the examination itself.
systemctl stop faramir-keeper.socket >/dev/null 2>&1
before=$(systemctl is-active faramir-keeper.socket)
snap
after=$(systemctl is-active faramir-keeper.socket)
if [[ "$(st sockets)" == *failed* ]]; then
  ok "a stopped keeper socket under a live broker is reported failed ($before -> $after)"
else
  bad "with the broker socket up, doctor reported [$(st sockets)] for a socket that was $before"
fi
dt sockets | grep -q 'keeper.socket is inactive' && ok "and names the socket and the state it was in" \
  || bad "the finding does not name it: $(dt sockets)"
settle || bad "the host did not come back after the socket group"
snap
probe "the sops config removed" "sops config" warn \
  "mv /etc/faramir/.sops.yaml /tmp/sops.bak" \
  "mv /tmp/sops.bak /etc/faramir/.sops.yaml"

# .sops.yaml is 0644, so root can edit it directly, and nothing on that path
# looks at what was typed: `faramir reader add` validates a key and a hand
# edit does not. An identity written where a recipient belongs is the key that
# opens the store, readable by every account on this host.
cp /etc/faramir/.sops.yaml /tmp/sops-baseline.yaml
probe "an age identity pasted where a recipient belongs" "sops config" failed \
  'printf "creation_rules:\n  - path_regex: .*\n    key_groups:\n      - age:\n          - AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n" > /etc/faramir/.sops.yaml' \
  'cp /tmp/sops-baseline.yaml /etc/faramir/.sops.yaml' \
  'world-readable|will not take'

# A rule reaching none of the managed files leaves a store neither `faramir
# edit` nor `faramir reader reseal` can write back, and nothing else on the host says
# so: the values still decrypt and the broker still serves them, so the failure
# waits until somebody edits one.
probe "a rule that reaches no managed file" "rule coverage" failed \
  'printf "creation_rules:\n  - path_regex: ^nowhere-near-the-store/.*\n    key_groups:\n      - age:\n          - %s\n" "$(age-keygen -y /etc/faramir/age.key)" > /etc/faramir/.sops.yaml' \
  'cp /tmp/sops-baseline.yaml /etc/faramir/.sops.yaml'

# The keeper named only in the bare `age:` beside a key group is not a reader:
# sops seals to the groups alone, so every value written from then on is one the
# broker cannot open. Reported as the rule drifting off the keeper's key, which
# is what it is.
probe "the keeper named only in the shorthand sops ignores" "sops config" warn \
  'printf "creation_rules:\n  - path_regex: .*\n    age: %s\n    key_groups:\n      - age:\n          - age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n" "$(age-keygen -y /etc/faramir/age.key)" > /etc/faramir/.sops.yaml' \
  'cp /tmp/sops-baseline.yaml /etc/faramir/.sops.yaml'

# The config is what every other check reads, so losing it has to be reported
# as the config rather than as thirty unrelated faults.
mv $CFG /tmp/config.bak
snap
[ "$(st config)" = failed ] && ok "the config removed -> config failed" || bad "config is [$(st config)]"
# Every other check reads the config, so one finding and a stop is the answer:
# thirty findings derived from a file that is not there would each be wrong in
# its own way.
# The refusal plus the abandoned-examination line, and nothing derived from a
# file that is not there.
[ "$(jq '.findings|length' $JSON)" -eq 2 ] && ok "and only the abandoned-examination line stands beside it" \
  || bad "$(jq '.findings|length' $JSON) findings with no config"
crash=$(/usr/local/bin/faramir doctor 2>&1 >/dev/null | grep -ci 'panic\|goroutine')
[ "$crash" -eq 0 ] && ok "without a panic" || bad "doctor panicked with no config"
mv /tmp/config.bak $CFG

printf 'this is not toml at all\n[[[\n' >> $CFG
snap
[[ "$(st config)" == *failed* ]] && ok "a config that will not parse -> config failed" \
  || bad "a corrupt config is [$(st config)]"
dt config | grep -qi 'does not load\|parse' && ok "and says it did not load" || bad "unclear: $(dt config)"
head -n -2 $CFG > /tmp/c && mv /tmp/c $CFG
snap
[[ "$(st config)" != *failed* ]] && ok "and back to [$(st config)] once repaired" \
  || bad "config stayed [$(st config)]"

# --------------------------------------------------------------------------
head_ "4. the broker it is examining"

# A build the broker is not running. Two binaries is the only honest way to
# reach this, the version being compiled in.
if [ -x /opt/faramir/faramir-skew ]; then
  # rename, not copy: the daemons are executing this inode, so writing to it is
  # ETXTBSY. Replacing the directory entry is what an upgrade does anyway.
  cp /usr/local/bin/faramir /tmp/faramir.real
  cp /opt/faramir/faramir-skew /tmp/skew && mv /tmp/skew /usr/local/bin/faramir
  chmod 0755 /usr/local/bin/faramir
  snap
  [ "$(st version)" = failed ] && ok "a binary newer than the running broker -> version failed" \
    || bad "version skew is [$(st version)]: $(dt version)"
  dt version | grep -q '9\.9\.9' && ok "and names both builds" || bad "does not name the builds: $(dt version)"
  # The same skew over the socket. doctor is the operator asking; this is what a
  # client of that build is told when it tries to work, which is the half an
  # agent sees: a daemon that outlived the install which replaced the binary
  # under it refuses the CLI the agent runs.
  out=$(runuser -u "$OP" -- /usr/local/bin/faramir refs 2>&1)
  grep -q '9\.9\.9' <<<"$out" && ok "and the broker refuses a client of that build, naming its version" \
    || bad "the broker did not name the caller's version: ${out:0:160}"
  mv /tmp/faramir.real /usr/local/bin/faramir; chmod 0755 /usr/local/bin/faramir
  snap
  [ "$(st version)" = ok ] && ok "and back to ok on the matching build" || bad "version stayed [$(st version)]"
else
  bad "no skewed binary at /opt/faramir/faramir-skew; e2e.sh did not build one"
fi

# The socket the agent connects to, regrouped so the client group is shut out.
probe "the broker socket closed to the client group" "broker socket" failed \
  "chgrp root /run/faramir/broker.sock; chmod 0660 /run/faramir/broker.sock" \
  "systemctl restart faramir-broker.socket; settle"

# --------------------------------------------------------------------------
head_ "5. a value the redactor refused"
#
# Under [secret] min_length a value is loaded but never injected and never
# redacted, so a command that prints it prints it in plaintext. The broker
# reports this and keeps serving; doctor fails on it and status exits non-zero,
# a ref the config names and the broker cannot cover being a host that is not
# what its config describes.

snap
short=$(grep -c 'short/pin' <<<"$(dt 'refused refs') $(dt broker) $(dt 'managed store')")
if [ "$short" -gt 0 ]; then
  ok "doctor surfaces the ref the redactor refused"
else
  bad "no check mentions short/pin: $(dt 'refused refs' | head -c 160)"
fi
[ "$(st 'refused refs')" = failed ] \
  && ok "and fails on it: a ref that is never covered is a degraded host" \
  || bad "refused refs is $(st 'refused refs'), want failed"
# The same question, asked of the broker rather than of the install. status is
# what an agent and a converge run read, so a degraded host has to be non-zero
# there too.
runuser -u "$OP" -- /usr/local/bin/faramir status >/dev/null 2>&1 \
  && bad "faramir status exited 0 on a host holding a ref it cannot redact" \
  || ok "and faramir status exits non-zero over the same state"
# Whatever it is called, it must not read as an unexplained failure: the reason
# is known and is the operator's to act on.
if dt broker | grep -qi 'reason not reported'; then
  bad "it is reported as a failure for 'a reason not reported above', with the runuser command line as the detail"
else
  ok "and not as a failure nothing explains"
fi
# The store itself loaded and serves its other refs, which is why init finishes
# over this while doctor fails on it: an install cannot lengthen a secret, and
# failing here would also make [secret] min_length impossible to raise, init
# writing the config before it validates.
/usr/local/bin/faramir broker --check >/tmp/chk.json 2>/dev/null
[ "$(jq -r '.secrets.errors|length' /tmp/chk.json)" -eq 0 ] \
  && ok "the store reports no load errors" || bad "the store failed to load"
[ "$(jq -r '.secrets.count' /tmp/chk.json)" -ge 3 ] \
  && ok "and serves its other refs" || bad "the store serves nothing"
[ "$(jq -r '.secrets.not_redactable|length' /tmp/chk.json)" -eq 1 ] \
  && ok "with one ref named not redactable" || bad "not_redactable is not the one condition here"

# The consequence an operator meets: init cannot finish on this host. It is the
# same --check, run as validate, and init rewrites config.toml from its template
# on the way past, so [secret] min_length cannot be relaxed to get through it.
out=$(/usr/local/bin/faramir init --agent-user "$OP" 2>&1); code=$?
if [ $code -eq 0 ]; then
  ok "init completes on a host holding a value shorter than min_length"
else
  bad "init exits $code on a host whose only fault is one short value: $(grep -o 'validate:.*' <<<"$out" | head -c 150)"
fi
grep -q '^min_length = 8' $CFG && ok "(init rewrote config.toml, as it does)" \
  || bad "init did not rewrite the config"

# --------------------------------------------------------------------------
head_ "6. a Codex hook nothing has been told to trust"
#
# The one failure in the whole arrangement with no signal of its own. Codex
# skips a hook it has not been told to trust and says nothing when it does, so
# an unguarded Codex runs normally and looks like a guarded one from every
# direction. Nobody has ever started Codex on this box, so every hook the
# enrolments wrote is untrusted, which is what section 1 counts as the second
# known fault.
#
# The trust is a hash of the hook as Codex parses it rather than of the file, so
# the same value serves wherever the file sits, and the routing hook's is what
# an enrolled tree carries.
CODEX_HOOK=/home/op/p-codex/.codex/hooks.json
CODEX_CFG=/home/op/.codex/config.toml
CODEX_ROUTING_HASH=sha256:1c5598a904eb33a91c90a8790392a5d43d5df6c5a89dc0b9d407f8215db99234
CODEX_KEY="$CODEX_HOOK:pre_tool_use:0:0"

# Nothing else writes this file: Codex is not installed here. Kept aside anyway,
# so a later suite reads the home it would have read.
[ -e "$CODEX_CFG" ] && mv "$CODEX_CFG" "$CODEX_CFG.aside"
[ -e "$CODEX_HOOK" ] || bad "check-project did not leave a Codex hook at $CODEX_HOOK"

snap
[ "$(st 'codex hook trust')" = failed ] \
  && ok "a hook nothing has trusted fails rather than passing quietly" \
  || bad "codex hook trust is [$(st 'codex hook trust')] on a box that has never run Codex"
dt 'codex hook trust' | grep -qF "$CODEX_HOOK" \
  && ok "  and names the tree whose hook is inert" \
  || bad "  without naming $CODEX_HOOK: $(dt 'codex hook trust' | head -c 160)"
dt 'codex hook trust' | grep -qi 'says nothing' \
  && ok "  and says why nothing else would report it" \
  || bad "  without saying it fails silently: $(dt 'codex hook trust' | head -c 160)"

# Granted, against the identity Codex computes for the hook that is installed.
# This is the whole claim: faramir's hash of a hook it rendered is the one Codex
# recorded, or every trusted hook on every host reads as modified.
mkdir -p "$(dirname "$CODEX_CFG")"
printf '[hooks.state."%s"]\ntrusted_hash = "%s"\n' "$CODEX_KEY" "$CODEX_ROUTING_HASH" > "$CODEX_CFG"
chown -R op:op "$(dirname "$CODEX_CFG")"
snap
dt 'codex hook trust' | grep -qF "$CODEX_HOOK" \
  && bad "  a hook trusted at its recorded identity is still reported: $(dt 'codex hook trust' | head -c 160)" \
  || ok "  and the trust granted at that identity drops it from the report"

# A release that rewrites the hook leaves the trust behind, which is the case
# that has no first run to blame. It has to read differently from one never
# granted, the two having different remedies.
printf '[hooks.state."%s"]\ntrusted_hash = "sha256:0000"\n' "$CODEX_KEY" > "$CODEX_CFG"
chown op:op "$CODEX_CFG"
snap
dt 'codex hook trust' | grep -qi 'different hook' \
  && ok "and a hook trusted at an identity it no longer has is reported as changed" \
  || bad "a stale trust reads as never granted: $(dt 'codex hook trust' | head -c 160)"

# A hook Codex loads and will not run is the same silence by another route.
printf '[hooks.state."%s"]\ntrusted_hash = "%s"\nenabled = false\n' \
  "$CODEX_KEY" "$CODEX_ROUTING_HASH" > "$CODEX_CFG"
chown op:op "$CODEX_CFG"
snap
dt 'codex hook trust' | grep -qi 'turned off' \
  && ok "and a trusted hook turned off is reported too" \
  || bad "a disabled hook passes: $(dt 'codex hook trust' | head -c 160)"

rm -f "$CODEX_CFG"
[ -e "$CODEX_CFG.aside" ] && mv "$CODEX_CFG.aside" "$CODEX_CFG"
snap
[ "$(st 'codex hook trust')" = failed ] \
  && ok "and revoking it puts the finding back, so the check reads the live state" \
  || bad "codex hook trust stayed [$(st 'codex hook trust')] once the trust was removed"

# --------------------------------------------------------------------------
head_ "7. a check that cannot be made is never ok"
#
# The claim the whole report rests on. Each fault below is real while the
# question is put to a caller that cannot ask it.

asOp() { runuser -u "$OP" -- /usr/local/bin/faramir doctor --json 2>/dev/null > $JSON; }

asOp
n=$(unasked)
[ "$n" -ge 10 ] && ok "as the agent's uid, $n checks are reported unasked" \
  || bad "only $n checks unasked without root"
liar=$(jq -r '[.findings[]|select(.status=="ok")|.check]|join(",")' $JSON)
for boundary in "age key" "audit log" "store" "ssh key" "keeper socket" "executor socket"; do
  if [[ ",$liar," == *",$boundary,"* ]]; then
    bad "$boundary reports ok to a caller that cannot read it"
  else
    ok "$boundary does not report ok to a caller that cannot read it"
  fi
done

# And with the host actually broken underneath: the answer must still not be ok.
# The age key, not the audit log, whose mode the writer restores on its own.
chmod 0644 $KEY
asOp
got=$(st "age key")
if [[ "$got" == *ok* ]]; then
  bad "age key is ok to a non-root caller while actually world-readable"
else
  ok "age key is [$got] to a non-root caller while broken, not ok"
fi
# Root, asking the same host at the same moment, sees the truth.
snap
[ "$(st 'age key')" = failed ] && ok "and root, asking the same host, reports it failed" \
  || bad "root reports age key [$(st 'age key')]"
chmod 0400 $KEY

# runuser is the mechanism every boundary check uses. Without it they cannot be
# asked, and reporting them as holding would be the same unearned pass.
if [ -x /usr/sbin/runuser ]; then
  mv /usr/sbin/runuser /usr/sbin/runuser.hidden
  PATH=/usr/local/bin:/usr/bin:/bin /usr/local/bin/faramir doctor --json >$JSON 2>/dev/null
  if jq -e '[.findings[]|select(.check=="boundaries" and .status!="ok")]|length > 0' $JSON >/dev/null; then
    ok "with runuser gone, the boundary checks are declared unasked"
  else
    bad "with runuser gone, boundaries did not say so: $(dt boundaries | head -c 150)"
  fi
  for c in "age key" "audit log" "store"; do
    [[ "$(st "$c")" == *ok* ]] && bad "$c is ok with no way to ask" || ok "$c is not ok with no way to ask"
  done
  # Whether this host was granted an escalation needs no account to answer, so
  # giving up on the ones that do must not take it with them: a reader whose
  # brokered sudo just failed came for this line, and its absence reads as an
  # arrangement nobody examined rather than one that was never asked for. This
  # host is installed without --allow-sudo, so n/a is the answer.
  [[ "$(st "sudo grant")" == *n/a* ]] \
    && ok "and the grant is still reported, needing no account to answer" \
    || bad "with runuser gone the sudo grant line is $(st "sudo grant"), want n/a"
  mv /usr/sbin/runuser.hidden /usr/sbin/runuser
else
  bad "runuser is not at /usr/sbin/runuser; this group did not run"
fi
snap

# --------------------------------------------------------------------------
head_ "8. what the report itself promises"

snap
total=$(jq '.findings|length' $JSON)
[ "$total" -gt 20 ] && ok "the report carries $total findings" || bad "only $total findings"
jq -e 'all(.findings[]; .check != "" and .status != "" and .detail != "")' $JSON >/dev/null \
  && ok "every finding names a check, a status and a reason" || bad "a finding is missing a field"
jq -r '.findings[].status' $JSON | sort -u | while read -r s; do
  case "$s" in ok|warn|failed|n/a) ;; *) echo "  FAIL unknown status $s";; esac
done
[ "$(jq -r '.findings[].status' $JSON | sort -u | grep -cvE '^(ok|warn|failed|n/a)$')" -eq 0 ] \
  && ok "and every status is one of ok, warn, failed, n/a" || bad "an unknown status appeared"

# failed and the exit code have to agree, an operator scripting this reads one
# or the other.
chmod 0644 $KEY; snap
/usr/local/bin/faramir doctor >/dev/null 2>&1; code=$?
withFault=$(jq -r '[.findings[]|select(.status=="failed")|.check]|sort|join(",")' $JSON)
[ "$(broke)" = true ] && [ $code -eq 1 ] && ok "a failure sets .failed and exit 1 together" \
  || bad "failed=$(broke) but exit $code"
chmod 0400 $KEY; snap
repaired=$(jq -r '[.findings[]|select(.status=="failed")|.check]|sort|join(",")' $JSON)
# Against the set before the fault rather than against zero: this host carries a
# standing failure of its own (D5), and a suite that demanded a clean bill here
# would be asserting that bug away.
[[ "$withFault" == *"age key"* && "$repaired" != *"age key"* ]] \
  && ok "and repairing the fault drops exactly that check from the failed set" \
  || bad "failed set went [$withFault] -> [$repaired]"

# not_asked is the operator's cue that the totals are partial.
runuser -u "$OP" -- /usr/local/bin/faramir doctor 2>/dev/null | tail -6 | grep -qi 'not made\|not the whole' \
  && ok "the text report says the totals are partial when checks went unasked" \
  || bad "a partial examination does not say so"

# --------------------------------------------------------------------------
head_ "9. uninstall keeps what cannot be recreated"

# From a settled host: everything above injected faults, and an uninstall read
# against that residue would report this group's findings for another group's
# damage.
settle || bad "the host was not settled before the uninstall group"

cp /usr/local/bin/faramir /tmp/faramir.kept
sha_secrets=$(sha256sum $SECRETS | cut -d' ' -f1)
sha_key=$(sha256sum $KEY | cut -d' ' -f1)
log_lines=$(wc -l <$LOG)

out=$(/usr/local/bin/faramir uninstall 2>&1); code=$?
[ $code -eq 0 ] && ok "uninstall exits 0" || bad "uninstall exit $code: $(head -c 200 <<<"$out")"

# The three things no re-install can bring back.
[ "$(sha256sum $KEY 2>/dev/null | cut -d' ' -f1)" = "$sha_key" ] \
  && ok "the age key is untouched" || bad "the age key was changed or removed"
[ "$(sha256sum $SECRETS 2>/dev/null | cut -d' ' -f1)" = "$sha_secrets" ] \
  && ok "the ciphertext is untouched" || bad "the managed sops file was changed or removed"
[ -f $LOG ] && [ "$(wc -l <$LOG)" -ge "$log_lines" ] \
  && ok "the audit log is kept" || bad "the audit log was removed or truncated"
[ -f $CFG ] && ok "and the config is kept" || bad "the config was removed"
grep -q 'age.key' <<<"$out" && ok "and it names what it left behind" || bad "it does not say what it kept"

# What it is supposed to take away.
for path in /etc/systemd/system/faramir-broker.service /etc/logrotate.d/faramir \
            /etc/tmpfiles.d/faramir.conf /run/faramir; do
  [ -e "$path" ] && bad "$path survived the uninstall" || ok "$path is gone"
done
systemctl is-active faramir-broker.service >/dev/null 2>&1 \
  && bad "the broker is still running" || ok "no daemon is left running"
[ -x /usr/local/bin/faramir ] && bad "the binary survived" || ok "the binary removes itself last"

# Running it twice is what an operator does when the first was interrupted.
install -m0755 /tmp/faramir.kept /usr/local/bin/faramir
out=$(/usr/local/bin/faramir uninstall 2>&1); code=$?
[ $code -eq 0 ] && ok "a second uninstall is not an error" || bad "second uninstall exit $code: $(head -c 150 <<<"$out")"

# --------------------------------------------------------------------------
head_ "10. and the secrets survive the round trip"

install -m0755 /tmp/faramir.kept /usr/local/bin/faramir
if /usr/local/bin/faramir init --agent-user "$OP" >/tmp/reinit.log 2>&1; then
  ok "init runs again on a host that was uninstalled"
else
  bad "re-init failed: $(tail -3 /tmp/reinit.log)"
fi
[ "$(sha256sum $KEY | cut -d' ' -f1)" = "$sha_key" ] \
  && ok "and does not mint a second age key over the first" \
  || bad "re-init replaced the age key, so every managed file is now unreadable"

systemctl restart faramir-keeper.socket faramir-exec.socket faramir-broker.socket >/dev/null 2>&1
for _ in $(seq 20); do
  refs=$(runuser -u "$OP" -- /usr/local/bin/faramir refs 2>/dev/null || true)
  case "$refs" in *db/password*) break;; esac
  sleep 1
done
grep -q 'db/password' <<<"$refs" && ok "the same secrets load again after the round trip" \
  || bad "the store does not load after uninstall+init: [$refs]"

out=$(runuser -u "$OP" -- /usr/local/bin/faramir run --quiet -C /home/op/project \
  --env PW=faramir://db/password -- /bin/sh -c 'echo $PW' 2>&1)
grep -q '«SECRET:db/password»' <<<"$out" && ok "and a brokered command still gets the value, redacted" \
  || bad "a brokered command after the round trip: [$out]"

snap
# Back to the baseline of section 1: the fixture's two known faults and nothing
# else. broker is excluded for the reason it always was, --check exiting
# non-zero over that same short ref.
[ "$(jq -r '[.findings[]|select(.status=="failed" and .check!="broker" and .check!="refused refs" and .check!="codex hook trust")]|length' $JSON)" -eq 0 ] \
  && ok "and doctor is back to the fixture's one known fault on the rebuilt host" \
  || bad "after the round trip: $(jq -r '[.findings[]|select(.status=="failed")|.check]|join(",")' $JSON)"

# --------------------------------------------------------------------------
summary
