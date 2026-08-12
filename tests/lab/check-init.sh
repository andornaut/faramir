#!/bin/bash
# Functional test of `faramir init` against docs/layout.md, run as root inside a
# throwaway container.  The oracle is the documentation, not what the code
# happened to produce.
set -u
PASS=0; FAIL=0

ok()   { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; }
head_() { printf '\n== %s\n' "$1"; }

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

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
