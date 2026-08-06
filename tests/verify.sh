#!/usr/bin/env bash
# Phase 7 -- verification matrix, run against a REAL deployment.
#
# The unit and end-to-end suites (make test) cover the broker's behaviour in a
# temp directory.  This script covers the parts that only exist once the thing
# is actually installed: uid separation, ProtectProc, socket permissions.
#
#   sudo tests/verify.sh
#
# Tests 10 and 11 are EXPECTED TO LEAK.  They are the boundary of the threat
# model, not defects.  If they ever stop leaking, the README is wrong.
set -uo pipefail

AGENT_USER="${AGENT_USER:-agent}"
BROKER_USER="${BROKER_USER:-faramir-broker}"
KEEPER_USER="${KEEPER_USER:-faramir-keeper}"
AGE_KEY="${AGE_KEY:-/etc/faramir/age.key}"
KEEPER_SOCKET="${KEEPER_SOCKET:-/run/faramir/keeper.sock}"
SOCKET="${FARAMIR_SOCKET:-/run/faramir/broker.sock}"
RAW_LOG="${RAW_LOG:-/var/log/faramir/raw.log}"
PW_REF="${PW_REF:-secret://home/router/admin}"
PLAYBOOK="${PLAYBOOK:-site.yml}"

pass=0 fail=0 skip=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$*"; pass=$((pass+1)); }
no()   { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fail=$((fail+1)); }
skipt(){ printf '  \033[33mSKIP\033[0m  %s\n' "$*"; skip=$((skip+1)); }
head_() { printf '\n\033[1m%s\033[0m\n' "$*"; }

as_agent() { sudo -u "$AGENT_USER" "$@" 2>&1; }
as_broker() { sudo -u "$BROKER_USER" "$@" 2>&1; }
srun() { sudo -u "$AGENT_USER" faramir run --quiet "$@" 2>&1; }

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
id -u "$AGENT_USER" >/dev/null 2>&1 || { echo "no such user: $AGENT_USER" >&2; exit 1; }

head_ "1-2  uid separation"

# Note: capture first, then grep.  With `pipefail`, piping a failing command
# into a succeeding grep still reports failure, which silently inverts results.
out="$(as_agent cat "$AGE_KEY")"
if grep -qi 'permission denied' <<<"$out"; then
  ok "1  agent cannot read ${AGE_KEY}"
else
  no "1  agent CAN read the age key -- phase 1 is broken, stop here"
fi

# The point of the keeper: the uid that runs every brokered command must not be
# able to read the key either, by any route.
out="$(as_broker cat "$AGE_KEY")"
if grep -qi 'permission denied' <<<"$out"; then
  ok "1b ${BROKER_USER} cannot read the age key (the keeper holds it)"
else
  no "1b ${BROKER_USER} CAN read the age key -- so can every brokered command"
fi

owner="$(stat -c '%a %U' "$AGE_KEY" 2>/dev/null || echo missing)"
if [[ $owner == "400 ${KEEPER_USER}" ]]; then
  ok "1c age key is 0400 ${KEEPER_USER}"
else
  no "1c age key is '${owner}', expected '400 ${KEEPER_USER}'"
fi

out="$(as_agent test -w "$KEEPER_SOCKET" && echo writable)"
if [[ $out == writable ]]; then
  no "1d agent can reach the keeper socket ${KEEPER_SOCKET}"
else
  ok "1d agent cannot reach the keeper socket"
fi

# A brokered command runs as ${BROKER_USER}; the credential directory is the
# route that used to work regardless of any allowlist flag.
out="$(srun -- bash -lc 'cat /run/credentials/*/age_key 2>&1 | head -1')"
if grep -qiE 'no such file|permission denied|AGE-KEY' <<<"$out" || [[ -z ${out// /} ]]; then
  ok "1e brokered command cannot read a systemd credential holding the key"
else
  no "1e brokered command read something from /run/credentials: $out"
fi

out="$(srun -- bash -lc 'echo "[${SOPS_AGE_KEY:-unset}]"')"
if grep -q '\[unset\]' <<<"$out"; then
  ok "1f no brokered command receives SOPS_AGE_KEY"
else
  no "1f SOPS_AGE_KEY is present in a child environment: $out"
fi

BROKER_PID="$(pgrep -u "$BROKER_USER" -f '[f]aramir-broker' | head -1)"
if [[ -z $BROKER_PID ]]; then
  skipt "2  broker is not running"
else
  out="$(as_agent cat "/proc/${BROKER_PID}/environ")"
  if grep -qiE 'no such file|permission denied' <<<"$out"; then
    ok "2  agent cannot read the broker's environ (ProtectProc)"
  else
    no "2  agent CAN read /proc/${BROKER_PID}/environ -- ProtectProc is not working"
  fi
fi

if as_agent test -w "$SOCKET"; then
  ok "2b agent can write to $SOCKET (devwork group access works)"
else
  no "2b agent cannot reach $SOCKET"
fi

head_ "3-5  redaction of injected values"

out="$(srun --env "ROUTER_PW=${PW_REF}" -- printenv ROUTER_PW)"
if grep -q 'SECRET:' <<<"$out"; then
  ok "3  printenv shows a token: $(tr -d '\n' <<<"$out")"
else
  no "3  printenv did not produce a token: $out"
fi

out="$(srun --env "ROUTER_PW=${PW_REF}" -- bash -lc 'printenv ROUTER_PW | base64')"
if grep -q 'SECRET:' <<<"$out"; then ok "4  wrapped base64 redacted"; else no "4  base64 leaked: $out"; fi

out="$(srun --env "ROUTER_PW=${PW_REF}" -- bash -lc 'printenv ROUTER_PW | base64 -w0')"
if grep -q 'SECRET:' <<<"$out"; then ok "5  unwrapped base64 redacted"; else no "5  base64 -w0 leaked: $out"; fi

head_ "6-7  redaction of values the broker never injected"

if [[ -f "/srv/ansible-ctrl/${PLAYBOOK}" ]]; then
  out="$(srun -- ansible-playbook "$PLAYBOOK" -vvv)"
  if grep -q 'SECRET:' <<<"$out" || ! grep -qi 'password\|token' <<<"$out"; then
    ok "6  ansible-playbook -vvv produced no plaintext"
  else
    no "6  inspect the output of ansible-playbook -vvv by hand"
  fi
  out="$(srun -- ansible-playbook "$PLAYBOOK")"
  if grep -q 'SECRET:' <<<"$out"; then
    ok "7  a playbook printing a vault var is redacted"
  else
    skipt "7  no redaction seen -- does $PLAYBOOK print a vault var?"
  fi
else
  skipt "6  /srv/ansible-ctrl/${PLAYBOOK} not found"
  skipt "7  /srv/ansible-ctrl/${PLAYBOOK} not found"
fi

head_ "8  allowlist"

out="$(srun -- cat /etc/passwd)"
if grep -q 'denied' <<<"$out"; then
  ok "8  non-allowlisted command denied"
else
  no "8  'cat /etc/passwd' was not denied: $out"
fi

head_ "9  audit log"

if [[ -f $RAW_LOG ]]; then
  mode="$(stat -c '%a %U' "$RAW_LOG")"
  if [[ $mode == "600 ${BROKER_USER}" ]]; then
    ok "9a raw log is 0600 ${BROKER_USER}"
  else
    no "9a raw log is '$mode', expected '600 ${BROKER_USER}'"
  fi
  out="$(as_agent cat "$RAW_LOG")"
  if grep -qi 'permission denied' <<<"$out"; then
    ok "9b agent cannot read the raw log"
  else
    no "9b agent CAN read the raw log"
  fi
  if [[ -s $RAW_LOG ]]; then ok "9c raw log has content"; else no "9c raw log is empty"; fi
else
  skipt "9  $RAW_LOG does not exist yet"
fi

head_ "10-11  documented leaks (these SHOULD leak)"

out="$(srun --env "ROUTER_PW=${PW_REF}" -- bash -lc 'printenv ROUTER_PW | rev')"
if grep -q 'SECRET:' <<<"$out"; then
  no "10 reversed value was redacted -- unexpected; the README says it leaks"
else
  ok "10 reversed value leaks, as documented (adversarial exfiltration is out of scope)"
fi

out="$(srun --env "ROUTER_PW=${PW_REF}" -- bash -lc 'printenv ROUTER_PW | cut -c1-4')"
if grep -q 'SECRET:' <<<"$out"; then
  no "11 partial value was redacted -- unexpected; the README says it leaks"
else
  ok "11 partial value leaks, as documented"
fi

head_ "extra  the acceptance invariant"

if [[ -f /home/${AGENT_USER}/work/ansible-ctrl/CLAUDE.md ]]; then
  printf '  \033[33mNOTE\033[0m  CLAUDE.md exists. Delete it and re-run 1, 2 and 8:\n'
  printf '        nothing about what is *reachable* may change.\n'
fi

printf '\n\033[1m%d passed, %d failed, %d skipped\033[0m\n' "$pass" "$fail" "$skip"
[[ $fail -eq 0 ]]
