#!/usr/bin/env bash
# Runs a command, by default the Go suite, in a container that can write to
# nothing on the host: the checkout is mounted read-only and copied into a
# tmpfs, and the module and build caches are Docker volumes.
#
#   tests/go/run.sh                      go test -v ./...
#   tests/go/run.sh go test ./internal/guard
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
# No --name: two sessions running this at once must not collide.
exec docker run --rm --privileged --cgroupns=private -e CGO_ENABLED="${CGO_ENABLED:-0}" \
  -v "$root":/src:ro -v "$sops":/usr/local/bin/sops:ro \
  -v faramir-go-mod:/go/pkg/mod -v faramir-go-cache:/cache \
  --tmpfs /work:exec,size=4g --tmpfs /tmp:exec,size=4g \
  "$image" "$@"
