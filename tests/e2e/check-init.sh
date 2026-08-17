#!/bin/bash
# Functional test of `faramir init` against docs/layout.md, run as root inside a
# throwaway container.  The oracle is the documentation, not what the code
# happened to produce.
set -u
. "$(dirname "$0")/lib.sh" || { echo "e2e: lib.sh is missing beside $0" >&2; exit 2; }

# mode PATH MODE OWNER:GROUP -- as docs/layout.md states it.
mode() {
  local path=$1 want_mode=$2 want_own=$3
  if [ ! -e "$path" ]; then bad "$path is missing"; return; fi
  local got_mode got_own
  got_mode=$(stat -c '%a' "$path")
  got_own=$(stat -c '%U:%G' "$path")
  # Documented modes carry a leading zero; stat does not print one.
  want_mode=$(printf '%d' "0$want_mode" | xargs -I{} printf '%o' {})
  if [ "$got_mode" != "$want_mode" ]; then
    bad "$path is mode $got_mode, want $want_mode"; return
  fi
  if [ -n "$want_own" ] && [ "$got_own" != "$want_own" ]; then
    bad "$path is $got_own, want $want_own"; return
  fi
  ok "$path $got_mode $got_own"
}

absent() {
  if [ -e "$1" ]; then bad "$1 exists and should not"; else ok "$1 absent"; fi
}

# canread ACCOUNT PATH -- asserts the account CANNOT read it.  runuser is what
# doctor uses for the same question.
refused() {
  local account=$1 path=$2
  if runuser -u "$account" -- test -r "$path" 2>/dev/null; then
    bad "$account CAN read $path"
  else
    ok "$account cannot read $path"
  fi
}

granted() {
  local account=$1 path=$2
  if runuser -u "$account" -- test -r "$path" 2>/dev/null; then
    ok "$account can read $path"
  else
    bad "$account cannot read $path and should be able to"
  fi
}

inGroup() {
  if id -nG "$1" | tr ' ' '\n' | grep -qx "$2"; then
    ok "$1 is in $2"
  else
    bad "$1 is not in $2"
  fi
}

notInGroup() {
  if id -nG "$1" | tr ' ' '\n' | grep -qx "$2"; then
    bad "$1 is in $2 and must not be"
  else
    ok "$1 is not in $2"
  fi
}

head_ "accounts and groups"
for account in faramir-broker faramir-keeper faramir-exec; do
  if id "$account" >/dev/null 2>&1; then ok "$account exists"; else bad "$account missing"; fi
done
inGroup op dev
inGroup faramir-keeper faramir-keeper
# The split the whole design rests on: only the keeper reads the ciphertext.
notInGroup faramir-broker faramir-keeper
notInGroup faramir-exec faramir-keeper
notInGroup op faramir-keeper

head_ "installed files (docs/layout.md)"
mode /usr/local/bin/faramir            0755 root:root
mode /usr/local/libexec/faramir        0755 root:root
mode /usr/local/share/doc/faramir      0755 root:root
mode /etc/tmpfiles.d/faramir.conf      0644 root:root
mode /etc/logrotate.d/faramir          0644 root:root
for unit in broker keeper exec; do
  mode "/etc/systemd/system/faramir-$unit.service" 0644 root:root
  mode "/etc/systemd/system/faramir-$unit.socket"  0644 root:root
done

head_ "the config directory"
mode /etc/faramir/config.toml  0644 root:root
mode /etc/faramir/config.d     0755 root:root
mode /etc/faramir/.sops.yaml   0644 root:root
mode /etc/faramir/secrets      2750 root:faramir-keeper
mode /etc/faramir/age.key      0400 faramir-keeper:faramir-keeper
mode /etc/faramir/id_ed25519   0600 faramir-broker:faramir-broker
mode /etc/faramir/id_ed25519.pub 0644 faramir-broker:faramir-broker
mode /var/log/faramir          0750 faramir-broker:faramir-broker

head_ "what each account can reach"
# The age key decrypts every managed file, retroactively.
refused faramir-exec   /etc/faramir/age.key
refused faramir-broker /etc/faramir/age.key
refused op             /etc/faramir/age.key
granted faramir-keeper /etc/faramir/age.key
# The ciphertext.
refused faramir-exec   /etc/faramir/secrets
refused op             /etc/faramir/secrets
# The key the broker lends through the agent, which it must never hand over.
refused faramir-exec   /etc/faramir/id_ed25519
refused op             /etc/faramir/id_ed25519
granted faramir-broker /etc/faramir/id_ed25519

head_ "no sudo grant unless asked for"
absent /etc/sudoers.d/faramir
absent /etc/pam.d/faramir-sudo

head_ "the agents init writes deny rules for"
#
# `--agent auto` is the default, and what it asks is which agents this home
# carries.  Read through --dry-run, which answers without writing: this suite
# runs before anything has enrolled, and every suite after it examines this
# account.

agentStep() {
  /usr/local/bin/faramir init --agent-user op --dry-run --json "$@" 2>/dev/null \
    | jq -r '[.steps[]|select(.step=="agent config")|.detail]|join(" ")'
}
out=$(agentStep)
grep -q 'no coding agent found in /home/op' <<<"$out" \
  && ok "a home carrying no agent gets no deny rules, and is told so" \
  || bad "auto found something in a home with no agent in it: $out"
grep -q 'antigravity, claude, kilocode, opencode, pi' <<<"$out" \
  && ok "and the message names all five it could be told to write for" \
  || bad "the message does not name the five: $out"

# The marker is made and removed here: init asks the home, so a directory left
# behind would answer for every suite after this one.
#
# The claim is the pair.  Nothing in the report names what auto found, and the
# message for finding nothing lists every known agent by name, so matching a
# name in it would pass whether or not the marker was read.  What says the
# marker was read is that the same command stops saying it found nothing.
install -d -o op -g op /home/op/.claude
out=$(agentStep)
rm -rf /home/op/.claude
grep -q 'no coding agent found' <<<"$out" \
  && bad "a home carrying .claude was still read as carrying no agent: $out" \
  || ok "and the same home with .claude in it is not: the marker is what auto reads"
absent /home/op/.claude

# Naming an agent configures it whether or not the home shows any sign of it,
# which is what makes auto safe as the default: it only ever adds.  The step
# carries no detail when it has rules to write, so what says the name was taken
# is that the nothing-to-write message is gone.
out=$(agentStep --agent pi)
grep -q 'no coding agent found' <<<"$out" \
  && bad "naming pi in a bare home still reported nothing to write for: $out" \
  || ok "and naming an agent writes for it whether or not the home shows a sign of it"

# A dry run answers and writes nothing, which is what makes the three checks
# above safe to run against the account every later suite depends on.
before=$(find /home/op -maxdepth 2 -name 'settings.json' -o -maxdepth 2 -name 'faramir.toml' 2>/dev/null | sort)
/usr/local/bin/faramir init --agent-user op --dry-run --agent claude --agent opencode >/dev/null 2>&1
[ "$before" = "$(find /home/op -maxdepth 2 -name 'settings.json' -o -maxdepth 2 -name 'faramir.toml' 2>/dev/null | sort)" ] \
  && ok "and a dry run wrote nothing into the home while answering" \
  || bad "a dry run wrote into the operator's home"

summary
