#!/usr/bin/env bash
# Verify a faramir install: the accounts, the modes, and the boundaries they
# are there to enforce.
#
# Run as the operator, not under sudo: several checks are negative ones that
# only mean something from an unprivileged shell. It sudos for the few reads
# that need root, so expect one password prompt.
#
# Read-only except for one no-op edit, which runs /bin/true as the editor and
# must report "unchanged" without rewriting anything.
#
#   tests/verify-install.sh [CONFIG_DIR]

set -uo pipefail

CONFIG_DIR=${1:-$HOME/.faramir}
SECRETS_DIR=$CONFIG_DIR/secrets
STORE_GROUP=faramir-keeper
CLIENT_GROUP=dev
OPERATOR=$(id -un)

pass=0
fail=0

ok() { printf '  \033[32mok\033[0m      %s\n' "$1"; pass=$((pass + 1)); }
no() { printf '  \033[31mFAIL\033[0m    %s\n' "$1"; fail=$((fail + 1)); }
note() { printf '  --      %s\n' "$1"; }
section() { printf '\n%s\n' "$1"; }

# check DESCRIPTION EXPECTED ACTUAL
check() {
  if [ "$2" = "$3" ]; then ok "$1 ($3)"; else no "$1: want '$2', got '$3'"; fi
}

owner_of() { sudo stat -c '%U:%G' "$1" 2>/dev/null; }
mode_of() { sudo stat -c '%a' "$1" 2>/dev/null; }

# Membership through id, not the group file: the store group is the keeper's
# primary group, and a primary membership is on the passwd entry rather than in
# the member list getent prints.
in_group() { id -nG "$1" 2>/dev/null | tr ' ' '\n' | grep -qx "$2"; }

section "Groups"
if getent group "$STORE_GROUP" >/dev/null; then
  ok "$STORE_GROUP exists"
  if in_group faramir-keeper "$STORE_GROUP"; then
    ok "faramir-keeper is in $STORE_GROUP"
  else
    no "faramir-keeper is NOT in $STORE_GROUP; it cannot decrypt or fingerprint the store"
  fi
  # The whole point: nothing that holds plaintext, runs a brokered command, or
  # belongs to a human may reach the ciphertext.  The broker is in this list
  # because it holds every decrypted value already, so read here would only
  # extend it to files no [secrets] list names.
  for who in "$OPERATOR" faramir-exec faramir-broker; do
    if in_group "$who" "$STORE_GROUP"; then
      no "$who IS in $STORE_GROUP; it can read and replace the store"
    else
      ok "$who is not in $STORE_GROUP"
    fi
  done
else
  no "$STORE_GROUP does not exist; faramir init has not run on this host"
fi

# An install that predates the store group moving onto the keeper leaves this
# behind, owning nothing.  A gid nobody uses is one a host will hand to
# something else.
if [ "$STORE_GROUP" != faramir-secrets ] && getent group faramir-secrets >/dev/null; then
  note "faramir-secrets still exists and now owns nothing; remove it with 'sudo groupdel faramir-secrets'"
fi

if id -nG "$OPERATOR" | tr ' ' '\n' | grep -qx "$CLIENT_GROUP"; then
  ok "$OPERATOR is in $CLIENT_GROUP (needed to reach the broker socket)"
else
  no "$OPERATOR is not in $CLIENT_GROUP; faramir status will be denied"
fi

section "Store"
check "store directory ownership" "root:$STORE_GROUP" "$(owner_of "$SECRETS_DIR")"
check "store directory mode" "2750" "$(mode_of "$SECRETS_DIR")"

while IFS= read -r f; do
  [ -n "$f" ] || continue
  check "$(basename "$f") ownership" "root:$STORE_GROUP" "$(owner_of "$f")"
  check "$(basename "$f") mode" "640" "$(mode_of "$f")"
done < <(sudo find "$SECRETS_DIR" -maxdepth 1 -type f -name '*.sops.y*ml' 2>/dev/null)

# Negative: this must fail from an unprivileged shell.
if ls "$SECRETS_DIR" >/dev/null 2>&1; then
  no "$OPERATOR can list the store; the split is not in effect"
else
  ok "$OPERATOR cannot list the store"
fi

section "Config"
for p in "$CONFIG_DIR" "$CONFIG_DIR/config.d" "$CONFIG_DIR/config.toml"; do
  check "$(basename "$p") ownership" "root:root" "$(owner_of "$p")"
done

# Every drop-in too: a root-owned directory stops one being created, and does
# nothing about writing to one that is already there.
while IFS= read -r d; do
  [ -n "$d" ] || continue
  check "config.d/$(basename "$d") ownership" "root:root" "$(owner_of "$d")"
done < <(sudo find "$CONFIG_DIR/config.d" -maxdepth 1 -type f -name '*.toml' 2>/dev/null)

# Negative: the file [exec.base_env] lives in must not be writable by the
# account an agent runs as.
if [ -w "$CONFIG_DIR/config.toml" ]; then
  no "$OPERATOR can write config.toml, which is where [exec.base_env] PATH lives"
else
  ok "$OPERATOR cannot write config.toml"
fi

# Negative: a writable config.d is the PATH-injection path into [exec.base_env].
probe=$CONFIG_DIR/config.d/.write-probe
if (: >"$probe") 2>/dev/null; then
  rm -f "$probe"
  no "$OPERATOR can write config.d; a drop-in there chooses what the executor runs"
else
  ok "$OPERATOR cannot write config.d"
fi

section "Age key"
check "age key ownership" "faramir-keeper:faramir-keeper" "$(owner_of "$CONFIG_DIR/age.key")"
check "age key mode" "400" "$(mode_of "$CONFIG_DIR/age.key")"

section "Broker"
if status=$(faramir status 2>&1); then
  count=$(printf '%s' "$status" | python3 -c 'import json,sys; print(json.load(sys.stdin)["secrets"]["count"])' 2>/dev/null)
  errs=$(printf '%s' "$status" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["secrets"]["errors"]))' 2>/dev/null)
  if [ "${count:-0}" -gt 0 ]; then ok "broker loaded $count secret(s)"; else no "broker loaded no secrets"; fi
  check "decryption errors" "0" "${errs:-unknown}"
  refs=$(faramir list-secrets 2>/dev/null | grep -c '^secret://')
  check "refs listed" "${count:-0}" "$refs"
else
  no "faramir status failed: $status"
  note "if this says permission denied, your shell predates $CLIENT_GROUP: run 'newgrp $CLIENT_GROUP'"
fi

section "Deny rules"
patterns=/usr/local/libexec/faramir/deny-patterns.txt
if sudo test -r "$patterns"; then
  # The paths are interpolated through regexQuote, so a literal dot arrives as
  # "\.". Matched as a fixed string against that escaped form.
  quoted=${CONFIG_DIR//./\\.}
  if sudo grep -qF -- "$quoted" "$patterns"; then
    ok "patterns name this install's config directory"
  else
    no "patterns do not name $CONFIG_DIR; they were copied, not rendered"
  fi
  for token in 'sops/age' 'keys.txt'; do
    if sudo grep -q -- "$token" "$patterns"; then ok "patterns cover $token"; else no "patterns do not cover $token"; fi
  done
else
  no "$patterns is missing"
fi

section "Edit round trip"
store_file=$(sudo find "$SECRETS_DIR" -maxdepth 1 -type f -name '*.sops.y*ml' 2>/dev/null | head -1)
if [ -n "$store_file" ]; then
  before=$(sudo stat -c '%Y:%s' "$store_file")
  # /bin/true leaves the plaintext alone, so a correct implementation decrypts,
  # sees no change, and rewrites nothing.
  out=$(sudo faramir edit -editor /bin/true "$(basename "$store_file")" 2>&1)
  after=$(sudo stat -c '%Y:%s' "$store_file")
  case "$out" in
    *unchanged*) ok "no-op edit reported unchanged" ;;
    *) no "no-op edit said: $out" ;;
  esac
  check "store untouched by a no-op edit" "$before" "$after"
else
  note "no managed sops file found under $SECRETS_DIR"
fi

section "Is your personal age key a recipient?"
key=$HOME/.config/sops/age/keys.txt
if [ -r "$key" ] && [ -n "$store_file" ]; then
  mine=$(age-keygen -y "$key" 2>/dev/null)
  if [ -n "$mine" ] && sudo grep -q -- "$mine" "$store_file"; then
    note "YES: your key decrypts the store, so retiring it is what closes the gap"
    note "     (public key only shown): $mine"
  else
    note "NO: the store does not list your key, so retiring it changes nothing here"
    note "    it may still open other sops files, and the agent can read it"
  fi
else
  note "no key at $key, or no store file to compare against"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
