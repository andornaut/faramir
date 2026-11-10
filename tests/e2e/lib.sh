# shellcheck shell=bash
# Sourced by every check-*.sh. e2e.sh copies it in beside the suite it runs.
#
# What is here is what every suite reports through, and nothing else: a helper
# one suite needs belongs in that suite, where its reader will find it.

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; }
# note records what the suite saw without claiming it. A branch reported with
# ok on both sides is an assertion that cannot fail, and it counts toward the
# passes as though it were one; write the observation with note instead.
note() { printf '  --   %s\n' "$1"; }
head_() { printf '\n== %s\n' "$1"; }

# summary ends a suite with its counts and the exit status they imply. The
# name comes from the file, so it cannot drift from the name e2e.sh and the
# README use for the same suite.
summary() {
  local name=${0##*/}
  name=${name#check-}
  printf '\n== %s: %d passed, %d failed\n' "${name%.sh}" "$PASS" "$FAIL"
  [ "$FAIL" -eq 0 ]
}

# snap runs doctor as root into $JSON, which each suite that uses it points at
# a file of its own; st and dt read one check's statuses and details out of it,
# joined: several findings share one name (the three sockets), and a suite that
# read only the first would miss the one that broke.
snap() { /usr/local/bin/faramir doctor --json >"$JSON" 2>/dev/null; }
st() { jq -r --arg c "$1" '[.findings[]|select(.check==$c)|.status]|join(",")' "$JSON"; }
dt() { jq -r --arg c "$1" '[.findings[]|select(.check==$c)|.detail]|join(" ")' "$JSON"; }

# waitfor SECONDS COMMAND... runs COMMAND once a second until it succeeds, and
# returns 1 if it never does. Use it wherever a suite would otherwise sleep for
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

# broker_document USER OP accepts a single successful metadata response, including
# exit 1 for degraded state. A refusal, missing response or mismatched status is
# not readiness. Capture the status explicitly so callers may enable pipefail.
broker_document() {
  local response code=0
  response=$(runuser -u "$1" -- /usr/local/bin/faramir "$2" --json 2>/dev/null) || code=$?
  case "$code" in 0|1) ;; *) return 1 ;; esac
  jq -cse --argjson code "$code" '
    if length == 1 and
      (.[0] | type == "object" and .error == null and .exit_code == $code)
    then .[0] else empty end
  ' <<<"$response"
}

refs_document() {
  local response
  response=$(broker_document "$1" refs) || return 1
  jq -ce 'select((.refs | type) == "array" and all(.refs[]; type == "string"))' <<<"$response"
}

# answers USER asks whether the broker answered, even when refs exits 1 for a
# degraded store. Membership predicates additionally wait for the expected state.
answers() { refs_document "$1" >/dev/null; }

ref_served() {
  local response
  response=$(refs_document "$1") || return 1
  jq -e --arg ref "$2" '.refs | index($ref) != null' <<<"$response" >/dev/null
}

ref_not_served() {
  local response
  response=$(refs_document "$1") || return 1
  jq -e --arg ref "$2" '.refs | index($ref) == null' <<<"$response" >/dev/null
}
