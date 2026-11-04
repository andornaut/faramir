#!/usr/bin/env bash
# Runs a command, by default the Go suite, in a container that can write to
# nothing on the host: the checkout is mounted read-only and copied into a
# tmpfs, the module and build caches are Docker volumes, and the tests run as
# uid 19001, which owns nothing on the host.
#
#   tests/go/run.sh                      go test -v ./...
#   tests/go/run.sh go test ./internal/guard
#
# FARAMIR_TEST_OUT names a host directory that what a run writes to /out is
# copied into, by `docker cp` as the caller once the container stops: the one
# place a run can leave a file, a coverage profile or a fuzz crasher. The copy
# happens whatever the command's status, since a failing fuzz run is the one
# that wrote a crasher.
#
# Privileged for the cgroup filesystem alone, which the executor tests need
# writable and Docker mounts read-only otherwise. The tests themselves run as an
# unprivileged account, so the privilege is the setup's and not theirs.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
image=faramir-go-test
sops=$root/tests/e2e/sops

[ -x "$sops" ] || {
  echo "tests/go: $sops is missing; tests/e2e/e2e.sh fetch downloads it" >&2
  exit 1
}
[ $# -gt 0 ] || set -- go test -v ./...

docker build -q -t "$image" "$here" >/dev/null
args=(--privileged --cgroupns=private -e CGO_ENABLED="${CGO_ENABLED:-0}"
  --mount "type=bind,source=$root,target=/src,readonly"
  --mount "type=bind,source=$sops,target=/usr/local/bin/sops,readonly"
  -v faramir-go-mod:/go/pkg/mod -v faramir-go-cache:/cache
  --tmpfs "/work:exec,size=4g" --tmpfs "/tmp:exec,size=4g")

# No --name: two sessions running this at once must not collide.
[ -n "${FARAMIR_TEST_OUT:-}" ] || exec docker run --rm "${args[@]}" "$image" "$@"

# A container kept after it stops, so /out can be copied from it, and named
# after this process so concurrent runs do not collide.
name=faramir-go-test-$$
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
mkdir -p "$FARAMIR_TEST_OUT"
status=0
docker run --name "$name" -e FARAMIR_OUT=1 "${args[@]}" "$image" "$@" || status=$?
docker cp -q "$name":/out/. "$FARAMIR_TEST_OUT" || { [ "$status" -ne 0 ] || status=1; }
exit "$status"
