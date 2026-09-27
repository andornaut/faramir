#!/usr/bin/env bash
# Runs every fuzz target for FUZZTIME each, inside the container run.sh starts,
# and copies any crasher a target writes to /out under the path it has in the
# checkout.
#
#   FARAMIR_TEST_OUT=bin tests/go/run.sh tests/go/fuzz.sh 30s
#
# -run='^$' so only the fuzzing happens, and one target at a time because
# `-fuzz` takes a single pattern.
set -euo pipefail

fuzztime=${1:?usage: fuzz.sh FUZZTIME}
[ -d /out ] || { echo "fuzz.sh: /out is not mounted; set FARAMIR_TEST_OUT" >&2; exit 2; }

# Anything under testdata/fuzz newer than this is a crasher this run wrote.
stamp=$(mktemp)
status=0
while IFS=: read -r file target; do
  # ./ whatever grep printed: go test reads a bare internal/x as an import path.
  pkg=./$(dirname "${file#./}")
  printf '%s %s (%s)\n' "$pkg" "$target" "$fuzztime"
  # The last two lines on a pass, and everything on a failure, which is where
  # the reason is.
  if log=$(go test "$pkg" -run='^$' -fuzz="^$target\$" -fuzztime="$fuzztime" </dev/null 2>&1); then
    tail -2 <<<"$log"
  else
    printf '%s\n' "$log"
    status=1
  fi
done < <(grep -rHo '^func Fuzz[A-Za-z0-9_]*' --include='*_test.go' . | sed 's/:func /:/')

# A crasher is a regression seed worth committing, and the checkout here is a
# copy, so it is only kept if it leaves through /out.
find . -path '*/testdata/fuzz/*' -type f -newer "$stamp" -print0 \
  | while IFS= read -r -d '' crasher; do
      mkdir -p "/out/$(dirname "$crasher")"
      cp "$crasher" "/out/$crasher"
      echo "crasher: $crasher" >&2
    done
exit "$status"
