#!/usr/bin/env bash
# The verification matrix, run against a REAL deployment.
#
# The unit and end-to-end suites (make test) cover the broker's behaviour in a
# temp directory.  This script covers the parts that only exist once the thing
# is actually installed: uid separation, ProtectProc, socket permissions.
#
#   sudo tests/verify.sh
#
# Checks 10 and 11 are demonstrations, not assertions: a transformed value is
# one the redactor never claimed to catch, so there is nothing there to pass or
# fail.  They print what actually reaches the caller, because that boundary is
# easier to believe once seen.
set -uo pipefail

# The account the coding agent runs as, which is the operator's own: there is no
# separate uid for it.  The checks below that used to prove what an "agent"
# account could not reach now prove what the *operator* cannot reach, which is
# the boundary that survives.
OPERATOR="${OPERATOR:-${SUDO_USER:-$(id -un)}}"
BROKER_USER="${BROKER_USER:-faramir-broker}"
KEEPER_USER="${KEEPER_USER:-faramir-keeper}"
EXEC_USER="${EXEC_USER:-faramir-exec}"
AGE_KEY="${AGE_KEY:-/etc/faramir/age.key}"
KEEPER_SOCKET="${KEEPER_SOCKET:-/run/faramir/keeper.sock}"
EXEC_SOCKET="${EXEC_SOCKET:-/run/faramir/exec.sock}"
# A brokered command runs where its caller was, so the tree under test is
# wherever this is run from unless told otherwise.
TREE="${TREE:-$PWD}"
SOCKET="${FARAMIR_SOCKET:-/run/faramir/broker.sock}"
AUDIT_LOG="${AUDIT_LOG:-/var/log/faramir/audit.log}"
PW_REF="${PW_REF:-secret://home/router/admin}"
PLAYBOOK="${PLAYBOOK:-site.yml}"

pass=0 fail=0 skip=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$*"; pass=$((pass+1)); }
no()   { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fail=$((fail+1)); }
skipt(){ printf '  \033[33mSKIP\033[0m  %s\n' "$*"; skip=$((skip+1)); }
head_() { printf '\n\033[1m%s\033[0m\n' "$*"; }

as_operator() { sudo -u "$OPERATOR" "$@" 2>&1; }
as_broker() { sudo -u "$BROKER_USER" "$@" 2>&1; }
as_exec() { sudo -u "$EXEC_USER" "$@" 2>&1; }
# --socket explicitly: sudo does not carry FARAMIR_SOCKET across, so a
# non-default SOCKET would otherwise be honoured by the checks above and
# silently ignored by every brokered one.
srun() { sudo -u "$OPERATOR" faramir run --socket "$SOCKET" --quiet "$@" 2>&1; }

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
id -u "$OPERATOR" >/dev/null 2>&1 || { echo "no such user: $OPERATOR" >&2; exit 1; }

head_ "1-2  uid separation"

# Note: capture first, then grep.  With `pipefail`, piping a failing command
# into a succeeding grep still reports failure, which silently inverts results.
out="$(as_operator cat "$AGE_KEY")"
if grep -qi 'permission denied' <<<"$out"; then
  ok "1  ${OPERATOR} cannot read ${AGE_KEY}"
else
  no "1  ${OPERATOR} CAN read the age key -- phase 1 is broken, stop here"
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

out="$(as_operator test -w "$KEEPER_SOCKET" && echo writable)"
if [[ $out == writable ]]; then
  no "1d ${OPERATOR} can reach the keeper socket ${KEEPER_SOCKET}"
else
  ok "1d ${OPERATOR} cannot reach the keeper socket"
fi

# The keeper holds the key through LoadCredential=, so the credential
# directory is the one place a brokered command might still find it.
out="$(srun -- bash -lc 'cat /run/credentials/*/age_key 2>&1 | head -1')"
if grep -qiE 'no such file|permission denied|AGE-KEY' <<<"$out" || [[ -z ${out// /} ]]; then
  ok "1e brokered command cannot read a systemd credential holding the key"
else
  no "1e brokered command read something from /run/credentials: $out"
fi

# shellcheck disable=SC2016  # the brokered shell expands this, not us
out="$(srun -- bash -lc 'echo "[${SOPS_AGE_KEY:-unset}]"')"
if grep -q '\[unset\]' <<<"$out"; then
  ok "1f no brokered command receives SOPS_AGE_KEY"
else
  no "1f SOPS_AGE_KEY is present in a child environment: $out"
fi

head_ "1g-1k  what a brokered command runs as"

out="$(srun -- bash -lc 'id -un')"
if grep -qw "$EXEC_USER" <<<"$out"; then
  ok "1g brokered commands run as ${EXEC_USER}"
else
  no "1g brokered commands run as '$(tr -d '\n' <<<"$out")', expected ${EXEC_USER}"
fi

out="$(as_exec cat "$AUDIT_LOG")"
if grep -qiE 'permission denied|no such file' <<<"$out"; then
  ok "1h ${EXEC_USER} cannot read the audit log"
else
  no "1h ${EXEC_USER} CAN read the audit log, so it can also truncate it"
fi

# Commands run in the agent's tree and are meant to write it: ansible drops
# .retry files and fact caches there.  What matters is that dev buys the
# executor that and nothing else, which 1h, 1i2, 1j and 1m check.
out="$(srun -- bash -lc "touch ${TREE}/.verify-write && echo wrote")"
if grep -q wrote <<<"$out"; then
  ok "1i brokered commands can write the working tree"
  rm -f "${TREE}/.verify-write"
else
  no "1i a brokered command cannot write ${TREE}: $out"
fi

# The executor uid is in dev, so it must NOT thereby reach the key.
out="$(as_exec cat "$AGE_KEY")"
if grep -qi 'permission denied' <<<"$out"; then
  ok "1i2 ${EXEC_USER} cannot read the age key"
else
  no "1i2 ${EXEC_USER} CAN read the age key -- dev must not grant this"
fi

out="$(as_exec test -w "$KEEPER_SOCKET" && echo writable)"
if [[ $out == writable ]]; then
  no "1j ${EXEC_USER} can reach the keeper socket"
else
  ok "1j ${EXEC_USER} cannot reach the keeper socket"
fi

out="$(as_exec test -w "$EXEC_SOCKET" && echo writable)"
if [[ $out == writable ]]; then
  no "1k ${EXEC_USER} can reach the executor socket and run unlogged commands"
else
  ok "1k ${EXEC_USER} cannot reach the executor socket"
fi

# Only meaningful when [ssh] keys is configured; otherwise the keys are
# deliberately in the executor's own home and this has nothing to check.
SSH_AGENT_SOCKET="${SSH_AGENT_SOCKET:-/run/faramir/ssh-agent.sock}"
if [[ -S $SSH_AGENT_SOCKET ]]; then
  out="$(srun -- bash -lc 'ssh-add -l')"
  if grep -qE 'SHA256|no identities' <<<"$out"; then
    ok "1l brokered commands can use the ssh-agent"
  else
    no "1l brokered commands cannot reach the ssh-agent: $out"
  fi
  # ssh-agent's own socket is the broker's; the executor reaches the keys only
  # through the relay, which checks SO_PEERCRED.  Connecting to a unix socket
  # needs write, not read: -r would pass a socket left 0620 that the executor
  # could in fact use.
  if as_exec test -w "${SSH_AGENT_SOCKET}.private"; then
    no "1n ${EXEC_USER} can reach ssh-agent's own socket, bypassing the relay"
  else
    ok "1n ${EXEC_USER} cannot reach ssh-agent's own socket"
  fi
  # The relay forwards list and sign only.  A brokered command that could send
  # the rest of the agent protocol would empty the broker's agent, and every
  # managed host would then refuse it until the broker restarted.
  # An agent holding nothing has nothing to lose: [ssh] keys can be configured
  # and still load no key (a passphrase, a missing file), which the broker logs
  # and carries on from.
  before="$(srun -- bash -lc 'ssh-add -l')"
  if grep -q 'SHA256' <<<"$before"; then
    srun -- bash -lc 'ssh-add -D' >/dev/null 2>&1
    if [[ "$(srun -- bash -lc 'ssh-add -l')" == "$before" ]]; then
      ok "1o brokered commands cannot empty the ssh-agent"
    else
      no "1o a brokered command changed what the ssh-agent holds; the relay forwards too much (restart the broker to reload the keys)"
    fi
  else
    skipt "1o the agent holds no identities; nothing to empty"
  fi
  leaked=0
  while read -r key; do
    [[ -n $key ]] || continue
    if ! grep -qi 'permission denied' <<<"$(as_exec cat "$key")"; then
      no "1m ${EXEC_USER} CAN read ${key}; the agent buys nothing"
      leaked=1
    fi
  done < <(sudo -u "$BROKER_USER" find "$(getent passwd "$BROKER_USER" | cut -d: -f6)/.ssh" \
             -name 'id_*' ! -name '*.pub' 2>/dev/null)
  [[ $leaked -eq 0 ]] && ok "1m ${EXEC_USER} cannot read any broker-held SSH key"
else
  skipt "1l no ssh-agent socket; [ssh] keys is empty"
  skipt "1m no ssh-agent socket; [ssh] keys is empty"
  skipt "1n no ssh-agent socket; [ssh] keys is empty"
  skipt "1o no ssh-agent socket; [ssh] keys is empty"
fi

BROKER_PID="$(pgrep -u "$BROKER_USER" -f '[f]aramir-broker' | head -1)"
if [[ -z $BROKER_PID ]]; then
  skipt "2  broker is not running"
else
  out="$(as_operator cat "/proc/${BROKER_PID}/environ")"
  if grep -qiE 'no such file|permission denied' <<<"$out"; then
    ok "2  ${OPERATOR} cannot read the broker's environ (ProtectProc)"
  else
    no "2  ${OPERATOR} CAN read /proc/${BROKER_PID}/environ -- ProtectProc is not working"
  fi
fi

if as_operator test -w "$SOCKET"; then
  ok "2b agent can write to $SOCKET (dev group access works)"
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

if [[ -f "${TREE}/${PLAYBOOK}" ]]; then
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
  skipt "6  ${TREE}/${PLAYBOOK} not found"
  skipt "7  ${TREE}/${PLAYBOOK} not found"
fi

head_ "8  what still bounds a command"

# There is no allowlist any more, so there is nothing here that refuses a
# program by name.  What is left is worth checking because an operator will hit
# it: a bare command name is looked up on [exec.base_env] PATH, which is the
# PATH the child gets, and the error has to say so.
out="$(srun -- definitely-not-installed-xyzzy)"
if grep -q 'base_env' <<<"$out"; then
  ok "8  an unresolvable program names [exec.base_env] PATH in the error"
else
  no "8  unhelpful error for an unresolvable program: $out"
fi

# The flip side, and the reason the allowlist went: a program outside the
# system directories has to work.  This is the venv/pipx/working-tree case.
probe="${TREE}/.verify-probe.sh"
printf '#!/bin/sh\necho PROBE_OK\n' >"$probe" && chmod 0755 "$probe"
out="$(srun -- "$probe")"
if grep -q 'PROBE_OK' <<<"$out"; then
  ok "8b a program outside the system directories runs"
else
  no "8b could not run ${probe}: $out"
fi
rm -f "$probe"

head_ "9  audit log"

if [[ -f $AUDIT_LOG ]]; then
  mode="$(stat -c '%a %U' "$AUDIT_LOG")"
  if [[ $mode == "600 ${BROKER_USER}" ]]; then
    ok "9a audit log is 0600 ${BROKER_USER}"
  else
    no "9a audit log is '$mode', expected '600 ${BROKER_USER}'"
  fi
  out="$(as_operator cat "$AUDIT_LOG")"
  if grep -qi 'permission denied' <<<"$out"; then
    ok "9b ${OPERATOR} cannot read the audit log"
  else
    no "9b ${OPERATOR} CAN read the audit log"
  fi
  if [[ -s $AUDIT_LOG ]]; then ok "9c audit log has content"; else no "9c audit log is empty"; fi

  # The log holds what the agent saw, so it must hold tokens and no values.
  # Run one command that injects a secret, then look for the value on disk.
  srun --env "ROUTER_PW=${PW_REF}" -- printenv ROUTER_PW >/dev/null 2>&1
  if grep -q 'SECRET:' "$AUDIT_LOG"; then
    ok "9d the audit log records redacted output"
  else
    no "9d no token in the audit log; is anything being recorded?"
  fi
  # PW_PLAINTEXT is only for this check, and only an operator can supply it:
  # nothing here can obtain the value on its own, which is the whole point.
  if [[ -n ${PW_PLAINTEXT:-} ]]; then
    if grep -qF -- "$PW_PLAINTEXT" "$AUDIT_LOG"; then
      no "9e PLAINTEXT IN THE AUDIT LOG: the value reached disk unredacted"
    else
      ok "9e the injected value does not appear in the audit log"
    fi
  else
    skipt "9e set PW_PLAINTEXT=<the value of ${PW_REF}> to check the log for it"
  fi
else
  skipt "9  $AUDIT_LOG does not exist yet"
fi

head_ "10-11  the boundary, demonstrated (not assertions)"

# Deliberately not pass/fail.  A transformed value is one the redactor does not
# claim to catch, so "it was not caught" asserts nothing, and asserting it would
# turn any future improvement into a red test.  It is shown because operators
# do not believe this until they watch it happen.
for transform in rev 'cut -c1-4'; do
  out="$(srun --env "ROUTER_PW=${PW_REF}" -- bash -lc "printenv ROUTER_PW | ${transform}")"
  if grep -q 'SECRET:' <<<"$out"; then
    printf '  \033[33mNOTE\033[0m  %s was caught; redaction now covers more than the README claims\n' "$transform"
  else
    printf '  \033[33mNOTE\033[0m  %s reaches the caller transformed, as documented: %s\n' \
      "$transform" "$(tr -d '\n' <<<"$out" | cut -c1-40)"
  fi
done
printf '        Adversarial exfiltration is out of scope. See the README.\n'

head_ "12  the redactor outside a brokered command"

# What covers a session that is not the broker's child: the same value set,
# reached through the socket, so a caller that holds no values gets the same
# tokens a brokered command's output gets.
# As the operator, like every other brokered check: this script runs as root,
# and root is not in the dev group the broker's socket is restricted to, so the
# connect fails, the CLI warns on stderr, and 2>&1 folds that warning into the
# comparison.  A correct deployment would report a failure.
out="$(printf 'nothing secret here\n' | as_operator faramir redact --socket "$SOCKET")"
if [[ $out == "nothing secret here" ]]; then
  ok "12a faramir redact passes ordinary text through unchanged"
else
  no "12a faramir redact altered text with no secret in it: $out"
fi

# The wrapper the hook rewrites a command into.  A wrapper that swallowed the
# child's status would make every failure read as a success.
faramir redact --socket "$SOCKET" -- bash -lc 'exit 33' >/dev/null 2>&1
code=$?
if [[ $code -eq 33 ]]; then
  ok "12b faramir redact -- preserves the child's exit code"
else
  no "12b faramir redact -- lost the child's exit code"
fi

# The rewrite itself: the guard has to answer with updatedInput, or every
# command an agent runs is covered by the deny list alone.
GUARD="${GUARD:-/usr/local/libexec/faramir/faramir-guard}"
if [[ -x $GUARD ]]; then
  out="$(printf '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}' | "$GUARD" 2>&1)"
  if grep -q 'updatedInput' <<<"$out" && grep -q 'redact' <<<"$out"; then
    ok "12c the hook rewrites an allowed command through the redactor"
  else
    no "12c the hook did not rewrite an allowed command: $out"
  fi
else
  skipt "12c ${GUARD} not installed"
fi

# Operator mode is the session that can read everything, so it is the one where
# an accidental read is most likely to reach a transcript.
OPERATOR_HOME="$(getent passwd "$OPERATOR" | cut -d: -f6)" || OPERATOR_HOME=""
if [[ -n $OPERATOR_HOME && -f ${OPERATOR_HOME}/.claude/settings.json ]]; then
  if grep -q faramir-guard "${OPERATOR_HOME}/.claude/settings.json"; then
    ok "12d the operator's own session registers the hook"
  else
    no "12d ${OPERATOR_HOME}/.claude/settings.json does not register faramir-guard"
  fi
else
  skipt "12d no settings.json in the operator's home"
fi

head_ "extra  the acceptance invariant"

if [[ -f ${TREE}/CLAUDE.md ]]; then
  printf '  \033[33mNOTE\033[0m  CLAUDE.md exists. Delete it and re-run 1, 2 and 8:\n'
  printf '        nothing about what is *reachable* may change.\n'
fi

printf '\n\033[1m%d passed, %d failed, %d skipped\033[0m\n' "$pass" "$fail" "$skip"
[[ $fail -eq 0 ]]
