# shellcheck shell=bash
# Sourced by every check-*.sh.  e2e.sh copies it in beside the suite it runs.
#
# What is here is what every suite reports through, and nothing else: a helper
# one suite needs belongs in that suite, where its reader will find it.

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; }
# note records what the suite saw without claiming it.  A branch reported with
# ok on both sides is an assertion that cannot fail, and it counts toward the
# passes as though it were one; write the observation with note instead.
note() { printf '  --   %s\n' "$1"; }
head_() { printf '\n== %s\n' "$1"; }

# summary ends a suite with its counts and the exit status they imply.  The
# name comes from the file, so it cannot drift from the name e2e.sh and the
# README use for the same suite.
summary() {
  local name=${0##*/}
  name=${name#check-}
  printf '\n== %s: %d passed, %d failed\n' "${name%.sh}" "$PASS" "$FAIL"
  [ "$FAIL" -eq 0 ]
}

# waitfor SECONDS COMMAND... runs COMMAND once a second until it succeeds, and
# returns 1 if it never does.  Use it wherever a suite would otherwise sleep for
# as long as the slowest case is thought to take: a fixed sleep is slower than
# the usual case and still too short for the unusual one, and when it is too
# short what reports the failure is the assertion after it, which then reads as
# a fault in what was being tested.
waitfor() {
  local secs=$1; shift
  for _ in $(seq "$secs"); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
